"""Durable ownership of one EVEDEX portfolio and its per-trade venue requests.

A PREPARED record is committed before a request can reach the venue. A crash in
that interval is ambiguous. Reopening the database never grants a retry.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import uuid
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

_EFFECT_KINDS = {
    "CANCEL_ENTRY",
    "LEVERAGE",
    "ENTRY",
    "STOP",
    "TAKE",
    "CANCEL_STOP",
    "CANCEL_TAKE",
    "CLOSE",
    "PARTIAL_CLOSE",
}
_OPEN = ("RESERVED", "OPEN")
_SECRET_FIELD = re.compile(
    r"signature|privatekey|apikey|authorization|passphrase|password|bearer|token|wallet"
)


class PortfolioJournalError(RuntimeError):
    """An ownership, durability or attribution check refused an operation."""


class PortfolioAdmissionRefused(PortfolioJournalError):
    """A known pre-dispatch portfolio limit prevented opening a new position."""


def _timestamp() -> str:
    return datetime.now(UTC).isoformat()


def _identifier(value: str, name: str) -> str:
    if (
        not isinstance(value, str)
        or not 0 < len(value) <= 240
        or not value.isascii()
        or not value.isprintable()
    ):
        raise PortfolioJournalError(f"invalid {name}")
    return value


def _amount(value: Decimal, *, positive: bool = True) -> str:
    if not isinstance(value, Decimal) or not value.is_finite() or (positive and value <= 0):
        raise PortfolioJournalError("invalid finite monetary value")
    return str(value)


def _encode_request(request: Mapping[str, Any]) -> str:
    # Record economic parameters and client IDs. Signed wire packets belong to the transport.
    def clean(value: Any) -> Any:
        if isinstance(value, Mapping):
            if any(not isinstance(k, str) or _SECRET_FIELD.search(k.replace("_", "").lower()) for k in value):
                raise PortfolioJournalError("private fields cannot be journaled")
            return {k: clean(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [clean(v) for v in value]
        if isinstance(value, Decimal):
            return _amount(value, positive=False)
        return value

    if not isinstance(request, Mapping):
        raise PortfolioJournalError("expected an economic request object")
    data = json.dumps(clean(request), allow_nan=False, sort_keys=True, separators=(",", ":"))
    if len(data.encode("utf-8")) > 16_384:
        raise PortfolioJournalError("economic request too large")
    return data


_SCHEMA = """
CREATE TABLE IF NOT EXISTS portfolio (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    account_id TEXT NOT NULL, symbols TEXT NOT NULL, max_positions INTEGER NOT NULL, store_id TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS trades (
    trade_id TEXT PRIMARY KEY NOT NULL, decision_id TEXT UNIQUE NOT NULL, symbol TEXT NOT NULL,
    side TEXT NOT NULL, approved_quantity TEXT NOT NULL, leverage INTEGER NOT NULL, stop TEXT NOT NULL,
    take TEXT NOT NULL, worst_case_loss TEXT NOT NULL, notional TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('RESERVED','OPEN','CLOSED','REFUSED')),
    entry_order_id TEXT UNIQUE, quantity TEXT, price TEXT,
    exit_origin TEXT, net_pnl TEXT, pnl_basis TEXT, created_at TEXT NOT NULL, finished_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS live_symbol ON trades(symbol) WHERE state IN ('RESERVED','OPEN');
CREATE TABLE IF NOT EXISTS effects (
    effect_id TEXT PRIMARY KEY NOT NULL, trade_id TEXT NOT NULL REFERENCES trades(trade_id),
    kind TEXT NOT NULL, operation_key TEXT NOT NULL, request TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('PREPARED','UNKNOWN','ACCEPTED','REJECTED')),
    venue_id TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
    UNIQUE(trade_id,kind,operation_key)
);
CREATE TABLE IF NOT EXISTS attached_protection (
    venue_id TEXT PRIMARY KEY NOT NULL, trade_id TEXT NOT NULL REFERENCES trades(trade_id),
    entry_order_id TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('STOP','TAKE')), price TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reductions (
    close_order_id TEXT PRIMARY KEY NOT NULL, trade_id TEXT NOT NULL REFERENCES trades(trade_id),
    quantity TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS pilot (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1), started_at TEXT NOT NULL, baseline TEXT NOT NULL,
    observed_at TEXT NOT NULL, funding_balance TEXT NOT NULL, conservative_equity TEXT NOT NULL,
    external_flow TEXT NOT NULL, account_result TEXT NOT NULL, adverse_loss TEXT NOT NULL,
    open_positions INTEGER NOT NULL, stopped INTEGER NOT NULL CHECK(stopped IN (0,1)),
    entry_deadline_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    sequence INTEGER PRIMARY KEY, previous_digest TEXT NOT NULL, digest TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL, event TEXT NOT NULL, payload TEXT NOT NULL
);
"""


class PortfolioJournal:
    """Single-machine, single-writer portfolio store shared by all runner sessions."""

    def __init__(self, path: Path, *, account_id: str, symbols: Sequence[str], max_positions: int = 10):
        self.account_id = _identifier(account_id, "account ID")
        self.symbols = frozenset(symbols)
        if (
            not self.symbols
            or len(self.symbols) != len(symbols)
            or len(self.symbols) > 23
            or any(not re.fullmatch(r"[A-Z0-9]{2,32}", s) for s in self.symbols)
        ):
            raise PortfolioJournalError("invalid portfolio instrument universe")
        if type(max_positions) is not int or not 1 <= max_positions <= 10:
            raise PortfolioJournalError("portfolio position limit must be between 1 and 10")
        self.max_positions = max_positions
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # SQLite's OS lock is released if the writer dies, independently of the journal connection.
        self._owner = sqlite3.connect(str(self.path) + ".owner", timeout=0, isolation_level=None)
        self._db: sqlite3.Connection | None = None
        try:
            try:
                self._owner.execute("BEGIN EXCLUSIVE")
            except sqlite3.OperationalError as exc:
                raise PortfolioJournalError("portfolio already owned or owner storage unavailable") from exc
            self._owner.execute("CREATE TABLE IF NOT EXISTS binding (id TEXT PRIMARY KEY NOT NULL)")
            binding = self._owner.execute("SELECT id FROM binding").fetchone()
            if binding and not self.path.is_file():
                raise PortfolioJournalError("bound portfolio journal missing")
            self._db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
            self._db.row_factory = sqlite3.Row
            self._db.execute("PRAGMA foreign_keys=ON")
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=FULL")
            version = self._db.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 1):
                raise PortfolioJournalError("unsupported portfolio journal version")
            if binding and version != 1:
                raise PortfolioJournalError("bound portfolio journal invalid")
            self._db.executescript(_SCHEMA)
            universe = json.dumps(sorted(self.symbols), separators=(",", ":"))
            with self._write() as db:
                row = db.execute("SELECT * FROM portfolio WHERE singleton=1").fetchone()
                if binding and (row is None or row["store_id"] != binding[0]):
                    raise PortfolioJournalError("bound portfolio journal was replaced")
                if row is None:
                    store_id = uuid.uuid4().hex
                    db.execute(
                        "INSERT INTO portfolio VALUES(1,?,?,?,?)",
                        (self.account_id, universe, max_positions, store_id),
                    )
                    self._event(
                        db, "PORTFOLIO_CREATED", {"symbols": sorted(self.symbols), "limit": max_positions}
                    )
                elif (row["account_id"], row["symbols"], row["max_positions"]) != (
                    self.account_id,
                    universe,
                    max_positions,
                ):
                    raise PortfolioJournalError("journal is bound to another account or portfolio mandate")
                db.execute("PRAGMA user_version=1")
            if not binding:
                store_id = self._db.execute("SELECT store_id FROM portfolio WHERE singleton=1").fetchone()[0]
                self._owner.execute("INSERT INTO binding VALUES(?)", (store_id,))
                self._owner.commit()
                self._owner.execute("BEGIN EXCLUSIVE")
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        try:
            if self._db is not None:
                self._db.close()
                self._db = None
        finally:
            self._owner.close()

    def __enter__(self) -> PortfolioJournal:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def _connection(self) -> sqlite3.Connection:
        if self._db is None:
            raise PortfolioJournalError("portfolio journal is closed")
        return self._db

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        db = self._connection()
        db.execute("BEGIN IMMEDIATE")
        try:
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise

    @staticmethod
    def _event(db: sqlite3.Connection, event: str, payload: Mapping[str, Any]) -> None:
        data = _encode_request(payload)
        prior = db.execute("SELECT digest FROM events ORDER BY sequence DESC LIMIT 1").fetchone()
        previous = prior[0] if prior else "0" * 64
        now = _timestamp()
        record = json.dumps([previous, now, event, data], separators=(",", ":")).encode()
        db.execute(
            "INSERT INTO events(previous_digest,digest,created_at,event,payload) VALUES(?,?,?,?,?)",
            (previous, hashlib.sha256(record).hexdigest(), now, event, data),
        )

    def trade(self, trade_id: str) -> dict[str, Any] | None:
        row = self._connection().execute("SELECT * FROM trades WHERE trade_id=?", (trade_id,)).fetchone()
        return dict(row) if row else None

    def active_trade(self, symbol: str) -> dict[str, Any] | None:
        row = (
            self._connection()
            .execute("SELECT * FROM trades WHERE symbol=? AND state IN ('RESERVED','OPEN')", (symbol,))
            .fetchone()
        )
        return dict(row) if row else None

    def active_trades(self) -> list[dict[str, Any]]:
        return [
            dict(row)
            for row in self._connection().execute(
                "SELECT * FROM trades WHERE state IN ('RESERVED','OPEN') ORDER BY created_at,trade_id"
            )
        ]

    @staticmethod
    def _effect(row: sqlite3.Row) -> dict[str, Any]:
        return {**dict(row), "request": json.loads(row["request"])}

    def effects(self, trade_id: str) -> list[dict[str, Any]]:
        return [
            self._effect(row)
            for row in self._connection().execute(
                "SELECT * FROM effects WHERE trade_id=? ORDER BY rowid", (trade_id,)
            )
        ]

    def unresolved_effects(self) -> list[dict[str, Any]]:
        return [
            self._effect(row)
            for row in self._connection().execute(
                "SELECT * FROM effects WHERE status IN ('PREPARED','UNKNOWN') ORDER BY rowid"
            )
        ]

    def reserve_entry(
        self,
        *,
        trade_id: str,
        decision_id: str,
        symbol: str,
        side: str,
        quantity: Decimal,
        leverage: int,
        stop: Decimal,
        take: Decimal,
        worst_case_loss: Decimal,
        notional: Decimal,
        equity: Decimal,
    ) -> None:
        _identifier(trade_id, "trade ID")
        _identifier(decision_id, "risk decision ID")
        if symbol not in self.symbols or side not in {"LONG", "SHORT"}:
            raise PortfolioJournalError("unapproved symbol or side")
        if type(leverage) is not int or not 1 <= leverage <= 30:
            raise PortfolioJournalError("invalid approved leverage")
        qty, sl, tp = _amount(quantity), _amount(stop), _amount(take)
        if (side == "LONG" and stop >= take) or (side == "SHORT" and take >= stop):
            raise PortfolioJournalError("invalid protective prices")
        approved_loss, approved_notional = _amount(worst_case_loss), _amount(notional)
        _amount(equity)
        if worst_case_loss > Decimal("0.25") or notional > Decimal("25"):
            raise PortfolioAdmissionRefused("entry exceeds the pilot's loss or notional limit")
        with self._write() as db:
            if (
                self.unresolved_effects()
                or db.execute("SELECT 1 FROM trades WHERE state='RESERVED' LIMIT 1").fetchone()
            ):
                raise PortfolioJournalError("earlier portfolio operation requires reconciliation")
            pilot = self.pilot_status()
            now = datetime.now(UTC)
            if (
                not pilot
                or pilot["stopped"]
                or not timedelta(0)
                <= now - datetime.fromisoformat(pilot["observed_at"])
                <= timedelta(seconds=60)
            ):
                raise PortfolioAdmissionRefused("pilot stopped or fresh verified performance unavailable")
            if now >= datetime.fromisoformat(pilot["entry_deadline_utc"]):
                raise PortfolioAdmissionRefused("pilot entry window ended")
            at_risk = sum((Decimal(row["worst_case_loss"]) for row in self.active_trades()), Decimal(0))
            equity = min(equity, Decimal(pilot["conservative_equity"]))
            capital = min(Decimal(100), equity)
            current_loss = max(
                Decimal(0), Decimal(pilot["baseline"]) + Decimal(pilot["external_flow"]) - equity
            )
            if (
                worst_case_loss > capital * Decimal("0.0025")
                or at_risk + worst_case_loss > capital * Decimal("0.01")
                or current_loss + at_risk + worst_case_loss > Decimal(5)
            ):
                raise PortfolioAdmissionRefused("portfolio or session loss budget exhausted")
            attempts = db.execute(
                "SELECT count(*) FROM trades WHERE state!='REFUSED' AND created_at>=?",
                (now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat(),),
            ).fetchone()[0]
            if attempts >= 12:
                raise PortfolioAdmissionRefused("daily portfolio entry limit reached")
            if len(self.active_trades()) >= self.max_positions:
                raise PortfolioAdmissionRefused("portfolio has no free slot")
            try:
                db.execute(
                    """INSERT INTO trades(trade_id,decision_id,symbol,side,approved_quantity,leverage,
                              stop,take,worst_case_loss,notional,state,created_at)
                              VALUES(?,?,?,?,?,?,?,?,?,?,'RESERVED',?)""",
                    (
                        trade_id,
                        decision_id,
                        symbol,
                        side,
                        qty,
                        leverage,
                        sl,
                        tp,
                        approved_loss,
                        approved_notional,
                        _timestamp(),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise PortfolioJournalError("duplicate trade, decision or occupied symbol") from exc
            self._event(
                db,
                "ENTRY_RESERVED",
                {
                    "trade_id": trade_id,
                    "decision_id": decision_id,
                    "symbol": symbol,
                    "side": side,
                    "quantity": qty,
                    "leverage": leverage,
                    "stop": sl,
                    "take": tp,
                    "worst_case_loss": approved_loss,
                    "notional": approved_notional,
                },
            )

    def prepare_effect(self, *, trade_id: str, kind: str, operation_key: str, request: dict) -> str:
        _identifier(operation_key, "operation key")
        kind = kind.upper()
        if kind not in _EFFECT_KINDS:
            raise PortfolioJournalError("unknown effect kind")
        data = _encode_request(request)
        identity = json.dumps(
            [self.account_id, trade_id, kind, operation_key], separators=(",", ":")
        ).encode()
        effect_id = hashlib.sha256(identity).hexdigest()
        with self._write() as db:
            trade = self.trade(trade_id)
            if not trade or trade["state"] not in _OPEN:
                raise PortfolioJournalError("effect has no active trade owner")
            if kind in {"ENTRY", "LEVERAGE"}:
                if trade["state"] != "RESERVED" or self.unresolved_effects():
                    raise PortfolioJournalError("entry has already started or needs reconciliation")
                filled = db.execute(
                    """SELECT 1 FROM effects WHERE trade_id=? AND kind='ENTRY'
                                         AND status!='REJECTED'""",
                    (trade_id,),
                ).fetchone()
                if filled:
                    raise PortfolioJournalError("an entry attempt already owns this trade")
            elif db.execute(
                """SELECT 1 FROM effects WHERE trade_id=? AND kind=?
                               AND status IN ('PREPARED','UNKNOWN')""",
                (trade_id, kind),
            ).fetchone():
                raise PortfolioJournalError("previous effect of this kind requires reconciliation")
            now = _timestamp()
            try:
                db.execute(
                    "INSERT INTO effects VALUES(?,?,?,?,?,'PREPARED',NULL,?,?)",
                    (effect_id, trade_id, kind, operation_key, data, now, now),
                )
            except sqlite3.IntegrityError as exc:
                raise PortfolioJournalError("operation already recorded; inspect its venue outcome") from exc
            self._event(
                db,
                "EFFECT_PREPARED",
                {
                    "effect_id": effect_id,
                    "trade_id": trade_id,
                    "kind": kind,
                    "operation_key": operation_key,
                    "request": json.loads(data),
                },
            )
        return effect_id

    def finish_effect(self, effect_id: str, status: str, venue_id: str | None = None) -> None:
        status = status.upper()
        if status not in {"ACCEPTED", "REJECTED", "UNKNOWN"}:
            raise PortfolioJournalError("unknown venue disposition")
        if venue_id is not None:
            _identifier(venue_id, "venue ID")
        with self._write() as db:
            row = db.execute("SELECT * FROM effects WHERE effect_id=?", (effect_id,)).fetchone()
            if not row:
                raise PortfolioJournalError("unknown effect ID")
            if (
                status == "ACCEPTED"
                and row["kind"]
                in {"ENTRY", "CANCEL_ENTRY", "CLOSE", "PARTIAL_CLOSE", "CANCEL_STOP", "CANCEL_TAKE"}
                and (not venue_id or json.loads(row["request"]).get("id") != venue_id)
            ):
                raise PortfolioJournalError("accepted effect does not match its planned venue ID")
            if row["status"] == status and row["venue_id"] == venue_id:
                return
            if row["status"] != "PREPARED":
                raise PortfolioJournalError(
                    "effect has a recorded disposition; explicit reconciliation required"
                )
            db.execute(
                "UPDATE effects SET status=?,venue_id=?,updated_at=? WHERE effect_id=?",
                (status, venue_id, _timestamp(), effect_id),
            )
            self._event(db, "EFFECT_RESULT", {"effect_id": effect_id, "status": status, "venue_id": venue_id})

    def opened(self, trade_id: str, *, entry_order_id: str, quantity: Decimal, price: Decimal) -> None:
        _identifier(entry_order_id, "entry order ID")
        qty, px = _amount(quantity), _amount(price)
        with self._write() as db:
            trade = self.trade(trade_id)
            if (
                trade
                and trade["state"] == "OPEN"
                and trade["entry_order_id"] == entry_order_id
                and (Decimal(trade["quantity"]), Decimal(trade["price"])) == (quantity, price)
            ):
                return
            if not trade or trade["state"] != "RESERVED" or quantity > Decimal(trade["approved_quantity"]):
                raise PortfolioJournalError("entry fill exceeds or lacks a reservation")
            if not db.execute(
                """SELECT 1 FROM effects WHERE trade_id=? AND kind='ENTRY'
                                 AND status='ACCEPTED' AND venue_id=?""",
                (trade_id, entry_order_id),
            ).fetchone():
                raise PortfolioJournalError("entry fill lacks an accepted owned order")
            db.execute(
                "UPDATE trades SET state='OPEN',entry_order_id=?,quantity=?,price=? WHERE trade_id=?",
                (entry_order_id, qty, px, trade_id),
            )
            self._event(
                db,
                "ENTRY_FILLED",
                {"trade_id": trade_id, "order_id": entry_order_id, "quantity": qty, "price": px},
            )

    def release_refused(self, trade_id: str) -> None:
        with self._write() as db:
            trade = self.trade(trade_id)
            if (
                not trade
                or trade["state"] != "RESERVED"
                or db.execute(
                    """SELECT 1 FROM effects WHERE trade_id=? AND (status IN ('UNKNOWN','PREPARED')
                   OR (kind='ENTRY' AND status='ACCEPTED'))""",
                    (trade_id,),
                ).fetchone()
            ):
                raise PortfolioJournalError("reservation cannot be released while entry is possible")
            db.execute(
                "UPDATE trades SET state='REFUSED',finished_at=? WHERE trade_id=?", (_timestamp(), trade_id)
            )
            self._event(db, "ENTRY_REFUSED", {"trade_id": trade_id})

    def closed(
        self,
        trade_id: str,
        *,
        exit_origin: str = "unknown",
        net_pnl: Decimal | None = None,
        pnl_basis: str = "unknown",
    ) -> None:
        if exit_origin not in {"system", "operator", "unknown"} or pnl_basis not in {
            "execution_fills",
            "account_change",
            "price_estimate",
            "unknown",
        }:
            raise PortfolioJournalError("unsupported closure provenance")
        if pnl_basis == "execution_fills" and net_pnl is None:
            raise PortfolioJournalError("attributed fills require a reconciled net result")
        pnl = _amount(net_pnl, positive=False) if net_pnl is not None else None
        with self._write() as db:
            trade = self.trade(trade_id)
            if (
                not trade
                or trade["state"] != "OPEN"
                or db.execute(
                    "SELECT 1 FROM effects WHERE trade_id=? AND status IN ('UNKNOWN','PREPARED')", (trade_id,)
                ).fetchone()
            ):
                raise PortfolioJournalError("trade cannot settle with unresolved venue effects")
            db.execute(
                "UPDATE trades SET state='CLOSED',exit_origin=?,net_pnl=?,pnl_basis=?,finished_at=? "
                "WHERE trade_id=?",
                (exit_origin, pnl, pnl_basis, _timestamp(), trade_id),
            )
            self._event(
                db,
                "TRADE_CLOSED",
                {"trade_id": trade_id, "exit_origin": exit_origin, "net_pnl": pnl, "pnl_basis": pnl_basis},
            )

    def pilot_status(self) -> dict[str, Any] | None:
        row = self._connection().execute("SELECT * FROM pilot WHERE singleton=1").fetchone()
        return dict(row) if row else None

    def record_observation(
        self,
        *,
        observed_at: datetime,
        funding: Decimal,
        conservative_equity: Decimal,
        external_flow: Decimal,
        positions: int,
        entry_deadline_utc: datetime,
        read_digests: Sequence[str],
        baseline_at: str | None,
    ) -> dict[str, Any]:
        if (
            observed_at.tzinfo is None
            or entry_deadline_utc.tzinfo is None
            or type(positions) is not int
            or positions < 0
            or not read_digests
            or any(not re.fullmatch(r"[a-f0-9]{64}", s) for s in read_digests)
        ):
            raise PortfolioJournalError("invalid portfolio observation")
        funding_text = _amount(funding, positive=False)
        equity_text = _amount(conservative_equity, positive=False)
        flow = _amount(external_flow, positive=False)
        if conservative_equity > funding:
            raise PortfolioJournalError("invalid conservative equity")
        when = observed_at.astimezone(UTC).isoformat()
        deadline = entry_deadline_utc.astimezone(UTC).isoformat()
        with self._write() as db:
            previous = self.pilot_status()
            if previous is None:
                if (
                    baseline_at is not None
                    or positions
                    or external_flow
                    or conservative_equity != funding
                    or funding < 100
                ):
                    raise PortfolioJournalError("pilot requires a flat verified baseline")
                started, baseline = when, funding
            else:
                if (
                    previous["started_at"] != baseline_at
                    or previous["entry_deadline_utc"] != deadline
                    or previous["observed_at"] > when
                ):
                    raise PortfolioJournalError("pilot identity, window or chronology changed")
                started, baseline = previous["started_at"], Decimal(previous["baseline"])
            result = funding - external_flow - baseline
            loss = max(Decimal(0), baseline + external_flow - conservative_equity)
            stopped = int(loss >= 5 or bool(previous and previous["stopped"]))
            db.execute(
                """INSERT INTO pilot VALUES(1,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(singleton) DO UPDATE SET observed_at=excluded.observed_at,
                   funding_balance=excluded.funding_balance, conservative_equity=excluded.conservative_equity,
                   external_flow=excluded.external_flow, account_result=excluded.account_result,
                   adverse_loss=excluded.adverse_loss, open_positions=excluded.open_positions,
                   stopped=excluded.stopped""",
                (
                    started,
                    str(baseline),
                    when,
                    funding_text,
                    equity_text,
                    flow,
                    str(result),
                    str(loss),
                    positions,
                    stopped,
                    deadline,
                ),
            )
            self._event(
                db,
                "ACCOUNT_OBSERVED",
                {
                    "at": when,
                    "funding": funding_text,
                    "equity_lower_bound": equity_text,
                    "net_transfers": flow,
                    "positions": positions,
                    "stopped": stopped,
                    "source_read_count": len(read_digests),
                    "source_sha256": hashlib.sha256("".join(read_digests).encode("ascii")).hexdigest(),
                },
            )
            return dict(db.execute("SELECT * FROM pilot WHERE singleton=1").fetchone())

    def _accepted_order(self, trade_id: str, kind: str, venue_id: str) -> bool:
        return any(
            e["kind"] == kind
            and e["status"] == "ACCEPTED"
            and e["venue_id"] == venue_id
            and e["request"].get("id") == venue_id
            for e in self.effects(trade_id)
        )

    def reconcile_effect(self, effect_id: str, *, venue_id: str) -> None:
        """Record the broker's exact-ID venue readback of a previously ambiguous owned order."""
        _identifier(venue_id, "venue ID")
        with self._write() as db:
            row = db.execute("SELECT * FROM effects WHERE effect_id=?", (effect_id,)).fetchone()
            if (
                not row
                or row["kind"] not in {"ENTRY", "CANCEL_ENTRY", "CLOSE", "PARTIAL_CLOSE"}
                or json.loads(row["request"]).get("id") != venue_id
                or row["venue_id"] not in (None, venue_id)
                or row["status"] == "REJECTED"
            ):
                raise PortfolioJournalError("reconciliation lacks the exact owned order")
            if row["status"] == "ACCEPTED":
                return
            db.execute(
                "UPDATE effects SET status='ACCEPTED',venue_id=?,updated_at=? WHERE effect_id=?",
                (venue_id, _timestamp(), effect_id),
            )
            self._event(db, "EFFECT_RECONCILED", {"effect_id": effect_id, "venue_id": venue_id})

    def no_fill(self, trade_id: str, *, entry_order_id: str) -> None:
        """Release a canceled/expired entry only after the broker verified a zero terminal fill."""
        with self._write() as db:
            trade = self.trade(trade_id)
            if (
                not trade
                or trade["state"] not in {"RESERVED", "REFUSED"}
                or not self._accepted_order(trade_id, "ENTRY", entry_order_id)
                or any(e["status"] in {"UNKNOWN", "PREPARED"} for e in self.effects(trade_id))
            ):
                raise PortfolioJournalError("cannot release an unverified entry")
            if trade["state"] == "REFUSED":
                return
            db.execute(
                "UPDATE trades SET state='REFUSED',entry_order_id=?,finished_at=? WHERE trade_id=?",
                (entry_order_id, _timestamp(), trade_id),
            )
            self._event(db, "ENTRY_TERMINAL_ZERO_FILL", {"trade_id": trade_id, "order_id": entry_order_id})

    def reduced(self, trade_id: str, *, close_order_id: str, quantity: Decimal) -> None:
        """Apply a positive verified reduction once per owned partial-close order."""
        _amount(quantity)
        with self._write() as db:
            prev = db.execute("SELECT * FROM reductions WHERE close_order_id=?", (close_order_id,)).fetchone()
            if prev:
                if prev["trade_id"] == trade_id and Decimal(prev["quantity"]) == quantity:
                    return
                raise PortfolioJournalError("conflicting quantity for an applied reduction")
            trade = self.trade(trade_id)
            if (
                not trade
                or trade["state"] != "OPEN"
                or quantity >= Decimal(trade["quantity"])
                or not self._accepted_order(trade_id, "PARTIAL_CLOSE", close_order_id)
            ):
                raise PortfolioJournalError("unowned or invalid reduction")
            db.execute("INSERT INTO reductions VALUES(?,?,?)", (close_order_id, trade_id, str(quantity)))
            db.execute(
                "UPDATE trades SET quantity=? WHERE trade_id=?",
                (str(Decimal(trade["quantity"]) - quantity), trade_id),
            )
            self._event(
                db,
                "QUANTITY_REDUCED",
                {"trade_id": trade_id, "order_id": close_order_id, "quantity": quantity},
            )

    def attached(self, trade_id: str) -> list[dict[str, Any]]:
        rows = self._connection().execute(
            "SELECT * FROM attached_protection WHERE trade_id=? ORDER BY venue_id", (trade_id,)
        )
        return [dict(r) for r in rows]

    def record_attached(
        self,
        trade_id: str,
        *,
        entry_order_id: str,
        venue_id: str,
        kind: str,
        price: Decimal,
    ) -> None:
        """Persist native child IDs read back from this trade's exact, acknowledged parent order."""
        _identifier(venue_id, "protection ID")
        px = _amount(price)
        if kind not in {"STOP", "TAKE"} or venue_id == entry_order_id:
            raise PortfolioJournalError("invalid attached protection")
        with self._write() as db:
            trade = self.trade(trade_id)
            if (
                not trade
                or trade["state"] not in _OPEN
                or not self._accepted_order(trade_id, "ENTRY", entry_order_id)
                or Decimal(trade["stop" if kind == "STOP" else "take"]) != price
            ):
                raise PortfolioJournalError("attached child does not match its approved entry")
            prior = db.execute("SELECT * FROM attached_protection WHERE venue_id=?", (venue_id,)).fetchone()
            if prior:
                if (prior["trade_id"], prior["entry_order_id"], prior["kind"], Decimal(prior["price"])) != (
                    trade_id,
                    entry_order_id,
                    kind,
                    price,
                ):
                    raise PortfolioJournalError("conflicting attachment identity")
                return
            db.execute(
                "INSERT INTO attached_protection VALUES(?,?,?,?,?)",
                (venue_id, trade_id, entry_order_id, kind, px),
            )
            self._event(
                db,
                "ATTACHED_PROTECTION_VERIFIED",
                {
                    "trade_id": trade_id,
                    "entry_order_id": entry_order_id,
                    "venue_id": venue_id,
                    "kind": kind,
                    "price": px,
                },
            )
