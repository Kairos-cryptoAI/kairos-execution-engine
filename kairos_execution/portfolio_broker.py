"""Account-owned EVEDEX portfolio execution. A Risk decision authorizes one bounded entry."""

from __future__ import annotations

import asyncio
import hashlib
import re
import subprocess  # nosec B404 - catches a timeout in detached-owner signature verification
import time
from collections.abc import Awaitable, Callable
from datetime import datetime
from decimal import Decimal
from functools import partial
from typing import Any

from kairos_core.contracts import RiskTradeDecisionV1

from .native_protection import EVEDEX_NATIVE_PROTECTION_UNAVAILABLE, reducing_side
from .one_canary_account import EvedexCanaryAccountSource
from .portfolio_evedex import (
    Book,
    Evedex,
    EvedexError,
    Instrument,
    OrderSigner,
    Position,
    Rejected,
    Unknown,
    dec,
    new_order_id,
    plain,
)
from .portfolio_journal import PortfolioAdmissionRefused, PortfolioJournal, RefusalReason
from .portfolio_performance import observe_pilot
from .portfolio_profile import PortfolioProfile, verify_profile
from .portfolio_targets import (
    TargetEvidenceError,
    partial_target_spec,
    sized_targets,
    target_fills,
    target_matches,
)
from .prod_universe import PROD_SYMBOL_MAP

PORTFOLIO_API_VERSION = 1
LIVE_ACCOUNT_SOURCE = "evedex-prod-runner-session"
TERMINAL = {"FILLED", "CANCELLED", "CANCELED", "REJECTED", "EXPIRED"}


class EntryExpired(EvedexError):
    """This approval no longer authorizes an executable entry."""


class CloseUnfilled(EvedexError):
    """An exact close was canceled, rejected or expired without reducing the position."""


class SettlementPending(EvedexError):
    """The owned close is terminal and flat, but its indexed position history is pending."""

    def __init__(self, symbol: str) -> None:
        self.symbol = symbol
        super().__init__(f"waiting for EVEDEX to publish the closed {symbol} position generation")


class NeedsOperator(EvedexError):
    """Venue facts or local ownership cannot safely authorize the next action."""


class ProtectionEvidenceError(NeedsOperator):
    """A fixed, non-sensitive reason the venue did not establish protection ownership."""


class PositionIdentityError(NeedsOperator):
    """The current exposure cannot be reduced on the original entry's authority."""


class _PositionCover(dict[str, Any]):
    """One read's corroborated position-level cover. It conveys no mutation authority."""

    def __init__(self, trade_id: str, row: dict[str, Any]):
        super().__init__(row)
        self.trade_id = trade_id


def account_id_for(wallet_address: str) -> str:
    return "evedex-prod-" + hashlib.sha256(wallet_address.lower().encode()).hexdigest()[:20]


def row_price(row: dict[str, Any]) -> Decimal | None:
    try:
        price = dec(row.get("price"))
    except (ArithmeticError, ValueError):
        return None
    return price if price > 0 else None


def wrong_protection_side(exc: Rejected) -> bool:
    return (
        bool(re.fullmatch(r"(stop_loss|take_profit)_price_(above|below)_(last|order)_price_error", exc.label))
        or "price should be" in exc.body.lower()
    )


def _venue_refusal(exc: Rejected) -> RefusalReason:
    # The response body can contain a request or account details. Only publish reviewed categories.
    if exc.label == "invalid_signature_error":
        return RefusalReason.SIGNING
    if exc.label == "invalid_order_leverage_error":
        return RefusalReason.LEVERAGE
    if wrong_protection_side(exc):
        return RefusalReason.PROTECTION_PRICE
    return RefusalReason.OTHER


def _side(trade: dict) -> str:
    return {"LONG": "BUY", "SHORT": "SELL"}[trade["side"]]


def _exit_side(trade: dict) -> str:
    return reducing_side(_side(trade))


def _now() -> int:
    return time.time_ns() // 1_000_000


class PortfolioBroker:
    mode = "live"
    account_source = LIVE_ACCOUNT_SOURCE

    def __init__(
        self,
        api: Evedex,
        store: Any,
        config: Any,
        wallet_key: str,
        settle_seconds: float = 1.0,
        cache_seconds: float = 3.0,
        *,
        journal: PortfolioJournal,
        profile: PortfolioProfile,
        account_source_reader: EvedexCanaryAccountSource,
    ):
        self._profile = verify_profile(profile)
        self._signer = OrderSigner(wallet_key, self._profile.chain_id)
        self.account_id = account_id_for(self._signer.address)
        wallet_hash = hashlib.sha256(self._signer.address.lower().encode("ascii")).hexdigest()
        if (
            wallet_hash != profile.signer_wallet_sha256
            or self.account_id != profile.account_id
            or journal.account_id != profile.account_id
            or journal.symbols != frozenset(profile.symbols)
            or journal.max_positions != profile.max_positions
            or journal.path.resolve() != profile.journal_path
            or store.directory.resolve() != profile.runner_runtime_dir
        ):
            raise NeedsOperator("owner profile does not match wallet, journal, runtime or portfolio scope")
        self._api, self._journal = api, journal
        self._source_reader, self._store = account_source_reader, store
        self._last_observation = 0.0
        self._admission_observed_at = 0.0
        self._settle_seconds = settle_seconds
        self._lock = asyncio.Lock()
        # Only immutable terminal entry facts are cached. Active children, the live position,
        # generation fills and closure are checked on every use of position-level cover.
        self._position_entries: dict[str, tuple[int, Decimal, Decimal, str]] = {}

    @property
    def native_protection_unavailable(self) -> str | None:
        return getattr(self._api, "native_protection_unavailable", EVEDEX_NATIVE_PROTECTION_UNAVAILABLE)

    def protection_unavailable_for(self, instrument: str) -> str | None:
        check = getattr(self._api, "protection_unavailable_for", None)
        return check(instrument) if check is not None else self.native_protection_unavailable

    def native_ladder_qualified_for(self, instrument: str) -> bool:
        check = getattr(self._api, "native_ladder_qualified_for", None)
        return check is not None and check(instrument) is True

    def native_stop_move_qualified_for(self, instrument: str) -> bool:
        check = getattr(self._api, "native_stop_move_qualified_for", None)
        return check is not None and check(instrument) is True

    def pilot_status(self) -> dict[str, Any] | None:
        return self._journal.pilot_status()

    def release(self) -> None:
        self._journal.close()

    async def _observe(self) -> None:
        await observe_pilot(
            self._journal,
            self._source_reader,
            expected_remote_account_id=self._profile.remote_account_id,
            entry_deadline_utc=self._profile.entry_deadline_utc,
        )
        self._last_observation = time.monotonic()

    @property
    def entry_deadline_utc(self) -> datetime:
        return self._profile.entry_deadline_utc

    async def refresh_performance(self, force: bool = False) -> None:
        if not force and time.monotonic() - self._last_observation < 60:
            return
        try:
            await self._observe()
        except (RuntimeError, ValueError, OSError) as exc:
            self._store.journal("portfolio_observation_unavailable", error=type(exc).__name__)
            self._last_observation = time.monotonic()

    async def prepare_admission(self, own: set[str]) -> Decimal:
        issues, _ = await self._inspect(own, check_protected=True)
        if issues:
            raise NeedsOperator(", ".join(issues))
        await self._observe()
        self._admission_observed_at = time.monotonic()
        status = self._journal.pilot_status()
        if not status:
            raise NeedsOperator("portfolio funding observation is unavailable")
        return dec(status["funding_balance"])

    def _entry_stopped(self) -> bool:
        return bool(self._store.state.get("halted") or self._store.flag("STOP") or self._store.flag("CLOSE"))

    async def _venue_clock(self) -> Callable[[], int]:
        # Bracket the documented server ping. Advance its conservative upper bound by monotonic elapsed
        # time, so an approved entry cannot gain time when the host clock trails the venue or steps back.
        sent = _now()
        start = time.monotonic_ns()
        observed = await self._api.server_time_ms()
        end = time.monotonic_ns()
        received = _now()
        latency = (end - start + 999_999) // 1_000_000
        if (
            type(observed) is not int
            or latency > 2_000
            or received < sent
            or observed - received > 2_000
            or sent - observed > 2_000
        ):
            raise EntryExpired("EVEDEX clock exceeds the bounded clock or latency policy")
        upper = max(received, observed + latency)
        if upper - received > 2_000:
            raise EntryExpired("EVEDEX clock uncertainty exceeds two seconds")
        return lambda: max(_now(), upper + (time.monotonic_ns() - end) // 1_000_000)

    async def _identity(self) -> None:
        account = await self._api.me()
        if str(account.get("exchangeId", "")) != self._profile.remote_account_id:
            raise NeedsOperator("API account does not match the signed owner profile")

    async def equity(self) -> Decimal:
        return (await self._api.balance())[0]

    async def available(self) -> Decimal:
        return (await self._api.balance())[1]

    async def account_reads(self) -> tuple[Decimal, Decimal, list[Position], list[dict[str, Any]]]:
        await self._identity()
        (balance, available), positions, orders = await asyncio.gather(
            self._api.balance(), self._api.positions(), self._api.open_orders()
        )
        return balance, available, positions, orders

    async def position(self, instrument: str, max_age: float = 0.0) -> Position | None:
        found = [p for p in await self._api.positions() if p.instrument == instrument]
        if len(found) > 1:
            raise NeedsOperator("ambiguous venue positions in one instrument")
        return found[0] if found else None

    def _owned(self, trade: dict, *, allow_closed: bool = False) -> dict:
        item = self._journal.trade(trade.get("risk_trade_id", ""))
        if (
            not item
            or (item["state"] != "OPEN" and not (allow_closed and item["state"] == "CLOSED"))
            or (item["symbol"], item["side"], item["entry_order_id"])
            != (trade.get("symbol"), trade.get("side"), trade.get("id"))
            or item["decision_id"] != trade.get("risk_decision_id")
        ):
            raise NeedsOperator("trade does not match the durable Risk and order identities")
        return item

    def _owned_protection(self, item: dict, row: dict) -> bool:
        if row.get("instrument") != item["symbol"] or row.get("type") not in {"stop-loss", "take-profit"}:
            return False
        if not isinstance(row.get("id"), str) or not row["id"]:
            return False
        parent = row.get("order")
        if parent and parent != item.get("entry_order_id"):
            return False
        if row.get("side") != _exit_side(item):
            return False
        if dec(row.get("quantity")) != 0:
            return any(target_matches(item, e, row) for e in self._journal.effects(item["trade_id"]))
        kind = "STOP" if row["type"] == "stop-loss" else "TAKE"
        price = row_price(row)
        initial_price = dec(item["stop"] if kind == "STOP" else item["take"])
        if parent == item.get("entry_order_id") and parent and price == initial_price:
            return True
        if any(
            a["kind"] == kind and a["venue_id"] == row["id"] and dec(a["price"]) == price
            for a in self._journal.attached(item["trade_id"])
        ):
            return True
        return any(
            e["kind"] == kind
            and e["status"] == "ACCEPTED"
            and e["venue_id"] == row["id"]
            and dec(e["request"]["price"]) == price
            for e in self._journal.effects(item["trade_id"])
        )

    async def _protection_rows(
        self,
        item: dict,
        rows: list[dict[str, Any]] | None = None,
        position: Position | None = None,
        *,
        clear_waiting: bool = False,
    ) -> list[dict[str, Any]]:
        if rows is None:
            rows = await self._api.active_tpsl(item["symbol"])
        if clear_waiting and any(r.get("status") == "waitOrder" for r in rows):
            rows = await self._clear_waiting_requests(item, rows)
            position = None  # cancellation can change the position's own protection projection
        if all(r.get("order") or self._owned_protection(item, r) for r in rows):
            return rows
        if item.get("entry_order_id") in self._position_entries:
            observed, diagnostic = await self._position_cover(item, rows, position)
            if not diagnostic:
                return observed
        parent = await self._api.order_with_protections(item["symbol"], item["entry_order_id"])
        empty_parent = self._bind_attached(item, rows, parent)
        if all(self._owned_protection(item, r) for r in rows):
            return rows

        # A complete pair at the signed prices can precede its parent projection. Geometry
        # permits one bounded read only. A foreign ID never becomes our protection on this basis.
        def active_pair(rows: list[dict[str, Any]]) -> bool:
            expected = {"stop-loss": dec(item["stop"]), "take-profit": dec(item["take"])}
            return (
                len(rows) == 2
                and {r.get("type") for r in rows} == set(expected)
                and len({r.get("id") for r in rows if isinstance(r.get("id"), str) and r["id"]}) == 2
                and all(
                    r.get("instrument") == item["symbol"]
                    and r.get("side") == _exit_side(item)
                    and r.get("status") == "active"
                    and dec(r.get("quantity")) == 0
                    and row_price(r) == expected[r["type"]]
                    and r.get("order") in (None, item["entry_order_id"])
                    for r in rows
                )
            )

        if active_pair(rows):
            if empty_parent:
                observed, diagnostic = await self._position_cover(item, rows, position)
                if not diagnostic:
                    return observed
                if diagnostic not in {
                    "protection parent is empty and the position lists no protection IDs",
                    "position and active API protection IDs differ or are ambiguous",
                }:
                    raise ProtectionEvidenceError(diagnostic)
            original_ids = {r["id"] for r in rows}
            try:
                async with asyncio.timeout(1):
                    await asyncio.sleep(min(self._settle_seconds, 0.1))
                    refreshed, parent, fresh_position = await asyncio.gather(
                        self._api.active_tpsl(item["symbol"]),
                        self._api.order_with_protections(item["symbol"], item["entry_order_id"]),
                        self.position(item["symbol"]),
                    )
                    if not active_pair(refreshed) or {r["id"] for r in refreshed} != original_ids:
                        raise ProtectionEvidenceError(
                            "active protection pair changed during ownership verification"
                        )
                    empty_parent = self._bind_attached(item, refreshed, parent)
                    rows = refreshed
                    if empty_parent and any(not self._owned_protection(item, r) for r in rows):
                        observed, diagnostic = await self._position_cover(item, rows, fresh_position)
                        if diagnostic:
                            raise ProtectionEvidenceError(diagnostic)
                        return observed
            except TimeoutError as exc:
                raise ProtectionEvidenceError("parent protection evidence refresh timed out") from exc
        if empty_parent and any(not self._owned_protection(item, r) for r in rows):
            observed, diagnostic = await self._position_cover(item, rows)
            if diagnostic:
                raise ProtectionEvidenceError(diagnostic)
            return observed
        if any(not self._owned_protection(item, r) for r in rows):
            raise ProtectionEvidenceError("venue did not link active protection IDs to the owned entry")
        return rows

    def _bind_attached(self, item: dict, rows: list[dict[str, Any]], parent: dict | None) -> bool:
        order_id = item["entry_order_id"]
        if parent is None:
            return False
        if str(parent.get("user", "")) != self._profile.remote_account_id:
            raise ProtectionEvidenceError("protection parent does not belong to the authenticated account")
        entry = next(
            e
            for e in self._journal.effects(item["trade_id"])
            if e["kind"] == "ENTRY" and e["venue_id"] == order_id
        )
        self._entry_record(parent, item, order_id, dec(entry["request"]["price"]))
        children = parent.get("tpslList")
        if not isinstance(children, list) or any(not isinstance(c, dict) for c in children):
            raise ProtectionEvidenceError("exact parent order has no verifiable TP/SL projection")
        for child in children:
            kind = child.get("type")
            if kind not in {"stop-loss", "take-profit"}:
                continue
            px = dec(item["stop"] if kind == "stop-loss" else item["take"])
            if (
                child.get("instrument") != item["symbol"]
                or child.get("side") != _exit_side(item)
                or row_price(child) != px
                or dec(child.get("quantity")) != 0
            ):
                continue
            matches = [
                r
                for r in rows
                if r.get("id") == child.get("id")
                and r.get("type") == kind
                and r.get("side") == _exit_side(item)
                and r.get("instrument") == item["symbol"]
                and row_price(r) == px
                and dec(r.get("quantity")) == 0
            ]
            if len(matches) == 1 and isinstance(child.get("id"), str) and child["id"]:
                self._journal.record_attached(
                    item["trade_id"],
                    entry_order_id=order_id,
                    venue_id=child["id"],
                    kind="STOP" if kind == "stop-loss" else "TAKE",
                    price=px,
                )
        return not children

    async def _position_cover(
        self, item: dict, rows: list[dict[str, Any]], position: Position | None = None
    ) -> tuple[list[dict[str, Any]], str | None]:
        """Confirm coverage on the authenticated, currently owned position, never authorship."""
        if all(self._owned_protection(item, row) for row in rows):
            return rows, None
        if item["state"] != "OPEN":
            return rows, "position-level protection requires a reconciled terminal entry fill"
        position = position or await self.position(item["symbol"])
        if position is not None and position.venue_id is None and position.user is None:
            return rows, "protection parent is empty and the position lists no protection IDs"
        if (
            position is None
            or not self._match_position(item, position)
            or position.user != self._profile.remote_account_id
            or not isinstance(position.venue_id, str)
            or not position.venue_id
        ):
            raise PositionIdentityError(
                "protection parent is empty and the authenticated open position does not match"
            )
        if not position.protections:
            return rows, "protection parent is empty and the position lists no protection IDs"
        children = {c.get("id"): c for c in position.protections if isinstance(c.get("id"), str) and c["id"]}
        active_ids = {r.get("id") for r in rows}
        if (
            len(children) != len(position.protections)
            or len(active_ids) != len(rows)
            or set(children) != active_ids
        ):
            return rows, "position and active API protection IDs differ or are ambiguous"
        covered: list[dict[str, Any]] = []
        initial = {"stop-loss": dec(item["stop"]), "take-profit": dec(item["take"])}
        for row in rows:
            child = children[row["id"]]
            kind = row.get("type")
            if self._owned_protection(item, row):
                covered.append(row)
            elif (
                kind in initial
                and sum(r.get("type") == kind and row_price(r) == initial[kind] for r in rows) == 1
                and all(
                    r.get("instrument") == item["symbol"]
                    and r.get("type") == kind
                    and r.get("side") == _exit_side(item)
                    and r.get("status") == "active"
                    and r.get("order") in (None, item["entry_order_id"])
                    and not r.get("triggerOrder")
                    and dec(r.get("quantity")) == 0
                    and row_price(r) == initial[kind]
                    for r in (row, child)
                )
            ):
                covered.append(_PositionCover(item["trade_id"], row))
            else:
                return rows, "position protection does not match the initial full-size active pair"
        stop = self._tightest_stop(item)
        if not (
            any(self._valid_protection(item, r, "stop-loss", stop) for r in covered)
            and any(self._valid_protection(item, r, "take-profit", initial["take-profit"]) for r in covered)
        ):
            return rows, "position lacks the complete active stop and take at the entry levels"
        await self._require_position_generation(item, position)
        return covered, None

    async def _require_position_generation(self, item: dict, position: Position) -> None:
        if (
            not self._match_position(item, position)
            or not position.venue_id
            or position.user != self._profile.remote_account_id
        ):
            raise PositionIdentityError("authenticated position identity does not match the owned fill")
        effects = self._journal.effects(item["trade_id"])
        entry = next(
            e
            for e in effects
            if e["kind"] == "ENTRY" and e["status"] == "ACCEPTED" and e["venue_id"] == item["entry_order_id"]
        )
        key = item["entry_order_id"]
        cached = self._position_entries.get(key)
        if cached is None:
            detail = await self._api.order(key)
            status, filled = self._entry_record(detail, item, key, dec(entry["request"]["price"]))
            versions = detail.get("positionVersions") if detail else None
            if (
                not detail
                or str(detail.get("user", "")) != position.user
                or status not in TERMINAL
                or not isinstance(versions, list)
                or len(versions) != 1
                or type(versions[0]) is not int
                or versions[0] < 0
            ):
                raise PositionIdentityError("entry does not identify a unique matching position generation")
            cached = (versions[0], filled, dec(detail.get("filledAvgPrice")), position.venue_id)
        version, filled, average, venue_id = cached
        if venue_id != position.venue_id or filled < position.quantity or average != position.avg_price:
            raise PositionIdentityError("entry does not identify a unique matching position generation")
        closed, orders = await asyncio.gather(
            self._api.position_version_closed(item["symbol"], version),
            self._api.position_version_orders(item["symbol"], version),
        )
        if closed:
            raise PositionIdentityError("entry position generation is already closed")
        # Prove that only our entry and acknowledged reductions compose this generation.
        # The live position has no version field, and its current economics alone can repeat.
        reductions = self._owned_reductions(item, effects)
        self._validate_generation_balance(item, orders, entry, filled, average, reductions, position.quantity)
        self._position_entries[item["entry_order_id"]] = cached

    def _owned_reductions(self, item: dict, effects: list[dict]) -> dict[str, Decimal]:
        reductions = {
            e["venue_id"]: dec(e["request"]["quantity"])
            for e in effects
            if e["status"] == "ACCEPTED" and e["kind"] == "PARTIAL_CLOSE"
        }
        reductions.update(
            {oid: dec(qty) for oid, qty, _ in self._journal.native_target_fills(item["trade_id"]).values()}
        )
        return reductions

    def _validate_generation_balance(
        self,
        item: dict,
        orders: list[dict],
        entry: dict,
        filled: Decimal,
        average: Decimal,
        reductions: dict[str, Decimal],
        remaining: Decimal,
    ) -> None:
        expected_fills = {item["entry_order_id"]: filled, **reductions}
        actual_fills = {}
        seen_orders: set[str] = set()
        for order in orders:
            key = order.get("id")
            if (
                not isinstance(key, str)
                or not key
                or key in seen_orders
                or order.get("instrument") != item["symbol"]
                or str(order.get("user", "")) != self._profile.remote_account_id
            ):
                raise PositionIdentityError("position generation order list is ambiguous")
            seen_orders.add(key)
            amount = dec(order.get("quantity")) - dec(order.get("unFilledQuantity"))
            if key == item["entry_order_id"]:
                self._entry_record(order, item, key, dec(entry["request"]["price"]))
                if dec(order.get("filledAvgPrice")) != average:
                    raise PositionIdentityError(
                        "generation entry average price conflicts with its exact fill"
                    )
            if key in reductions and (
                order.get("side") != _exit_side(item)
                or order.get("status") != "FILLED"
                or dec(order.get("unFilledQuantity")) != 0
                or dec(order.get("filledAvgPrice")) <= 0
            ):
                raise PositionIdentityError("generation reduction conflicts with its acknowledged fill")
            if amount != 0:
                actual_fills[key] = amount
        if actual_fills != expected_fills or filled - sum(reductions.values()) != remaining:
            raise PositionIdentityError(
                "position generation contains fills outside the owned entry and reductions"
            )

    def _usable_protection(self, item: dict, row: dict) -> bool:
        return (
            isinstance(row, _PositionCover) and row.trade_id == item["trade_id"]
        ) or self._owned_protection(item, row)

    def _valid_protection(self, item: dict, row: dict, kind: str, price: Decimal) -> bool:
        return (
            self._usable_protection(item, row)
            and row["type"] == kind
            and row.get("side") == _exit_side(item)
            and row_price(row) == price
            and dec(row.get("quantity")) == 0
            and row.get("status") in {"active", "process"}
        )

    @staticmethod
    def _match_position(item: dict, position: Position) -> bool:
        return (
            item["state"] == "OPEN"
            and position.instrument == item["symbol"]
            and position.side == _side(item)
            and dec(item["quantity"]) == position.quantity > 0
            and position.avg_price == dec(item["price"])
        )

    async def _inspect(self, own: set[str], *, check_protected: bool) -> tuple[list[str], list[Position]]:
        _, positions, open_orders, protections = await asyncio.gather(
            self._identity(),
            self._api.positions(),
            self._api.open_orders(),
            self._api.active_tpsl(),
        )
        tracked = {t["symbol"]: t for t in self._journal.active_trades()}
        issues = []
        if set(tracked) != own or any(t["state"] != "OPEN" for t in tracked.values()):
            issues.append("runner and execution ownership require reconciliation")
        unresolved = self._journal.unresolved_effects()
        if unresolved:
            issues.append("a venue request has an unresolved outcome")
        seen: set[str] = set()
        for pos in positions:
            item = tracked.get(pos.instrument)
            if (
                item
                and not self._match_position(item, pos)
                and self._journal.native_target_plan(item["trade_id"])
            ):
                await self._reconcile_native_targets(item, pos)
            if not item or pos.instrument in seen or not self._match_position(item, pos):
                issues.append(f"unowned or mismatched position in {pos.instrument}")
            seen.add(pos.instrument)
        # Entries fill immediately or their known GTC remainder is cancelled before admitting another.
        if open_orders:
            issues.append("an unclosed entry or foreign order is resting")
        projected = []
        for symbol in {r.get("instrument") for r in protections}:
            scope = [r for r in protections if r.get("instrument") == symbol]
            item = tracked.get(symbol)
            if item and symbol in seen and any(not self._owned_protection(item, r) for r in scope):
                try:
                    scope = await self._protection_rows(
                        item, scope, next(p for p in positions if p.instrument == symbol)
                    )
                except ProtectionEvidenceError as exc:
                    issues.append(str(exc))
            if not item or any(not self._usable_protection(item, r) for r in scope):
                issues.append("unowned venue protection")
            projected.extend(scope)
        if check_protected and any(self.protection_unavailable_for(symbol) for symbol in tracked):
            issues.append(EVEDEX_NATIVE_PROTECTION_UNAVAILABLE)
        elif check_protected:
            for symbol, item in tracked.items():
                stop = self._tightest_stop(item)
                waiting_for_ack = issues == ["a venue request has an unresolved outcome"] and all(
                    e["trade_id"] == item["trade_id"] and e["kind"] == "CLOSE" for e in unresolved
                )
                if symbol not in seen and (not issues or waiting_for_ack) and self._full_close(item):
                    # Even when the index has just caught up, the runner still owns this slot.
                    await self._verify_terminal_close(item)
                    raise SettlementPending(symbol)
                if (
                    symbol not in seen
                    or not any(
                        self._valid_protection(item, r, "stop-loss", stop)
                        for r in projected
                        if r.get("instrument") == symbol
                    )
                    or not any(
                        self._valid_protection(item, r, "take-profit", dec(item["take"]))
                        for r in projected
                        if r.get("instrument") == symbol
                    )
                ):
                    issues.append(f"{symbol} awaits its confirmed stop and take or flatness reconciliation")
        return issues, positions

    async def foreign_exposure(self, own: set[str]) -> list[str]:
        issues, _ = await self._inspect(own, check_protected=True)
        return issues

    async def reconcile_start(self, trades: list[dict], pending: dict | None) -> None:
        await self._identity()
        if isinstance(self._api, Evedex):
            try:
                await self._api.verify_native_protection(self._profile)
            except (
                OSError,
                ArithmeticError,
                ValueError,
                KeyError,
                TypeError,
                EvedexError,
                subprocess.TimeoutExpired,
            ) as exc:
                self._store.journal("native_protection_qualification_refused", error=type(exc).__name__)
        # Reconcile old GTC acknowledgements before inspecting runner state. Never place the entry again.
        for item in self._journal.active_trades():
            if item["state"] == "OPEN":
                await self._recover_exit(item)
                continue
            entries = [
                e
                for e in self._journal.effects(item["trade_id"])
                if e["kind"] == "ENTRY" and e["status"] != "REJECTED"
            ]
            if len(entries) == 1:
                request = entries[0]["request"]
                await self._confirm_entry(item, request["id"], dec(request["price"]))
        if pending:
            raise NeedsOperator("pending runner entry requires order-specific reconciliation")
        active = set()
        for trade in trades:
            item = self._owned(trade, allow_closed=True)
            if item["state"] == "OPEN":
                active.add(item["symbol"])
                position = await self._owned_position(item)
                if position:
                    await self._maintain_protection(item, trade, position)
                if trade.get("quantity") is not None and dec(trade["quantity"]) != dec(item["quantity"]):
                    # Only a confirmed reduce-only fill is allowed to alter the journal quantity.
                    trade["quantity"] = item["quantity"]
        for item in self._journal.active_trades():
            if item["symbol"] not in active and item["state"] == "OPEN":
                await self._settle_orphan(item)
        issues, _ = await self._inspect(active, check_protected=False)
        if issues:
            raise NeedsOperator(", ".join(issues))
        await self._observe()

    async def _settle_orphan(self, item: dict) -> None:
        # The crash occurred before the runner committed its management plan. Reduce this exact
        # exposure rather than guessing the plan, assuming a manual fill, or adopting another order.
        order_id, symbol = item["entry_order_id"], item["symbol"]
        entries = [
            e
            for e in self._journal.effects(item["trade_id"])
            if e["kind"] == "ENTRY" and e["status"] == "ACCEPTED" and e["venue_id"] == order_id
        ]
        if len(entries) != 1:
            raise NeedsOperator("orphan has no unique accepted original entry")
        order = await self._api.order(order_id)
        status, filled = self._entry_record(order, item, order_id, dec(entries[0]["request"]["price"]))
        if (
            status not in TERMINAL
            or filled < dec(item["quantity"])
            or not order
            or dec(order.get("filledAvgPrice")) != dec(item["price"])
        ):
            raise NeedsOperator("orphan position cannot be proved from its exact terminal entry")
        pending = await self._api.open_orders()
        protections = await self._protection_rows(item)
        if any(r.get("instrument") == symbol for r in pending) or any(
            not self._usable_protection(item, r) for r in protections
        ):
            raise NeedsOperator("orphan shares its instrument with an unowned order")
        position = await self._owned_position(item)
        if position:
            await self._close_quantity(item, position, position.quantity, origin="unknown")
        elif await self._completed_entry_bracket(item, order, filled, dec(item["price"])):
            # A process exit between recording the entry and its proven native close is recoverable.
            return
        await self.settle(
            {
                "id": order_id,
                "symbol": symbol,
                "side": item["side"],
                "risk_trade_id": item["trade_id"],
                "risk_decision_id": item["decision_id"],
            }
        )
        self._store.journal("portfolio_orphan_settled", trade_id=item["trade_id"], symbol=symbol)

    async def _recover_exit(self, item: dict) -> None:
        for effect in reversed(self._journal.effects(item["trade_id"])):
            if effect["kind"] not in {"CLOSE", "PARTIAL_CLOSE"} or effect["status"] == "REJECTED":
                continue
            r = effect["request"]
            if dec(item["quantity"]) == dec(r["before"]):
                try:
                    await self._confirm_close(item, r["id"], dec(r["before"]), dec(r["quantity"]))
                except CloseUnfilled:
                    pass  # This attempt is terminal; the caller will re-read the owned position.
            break

    def _full_close(self, item: dict) -> dict | None:
        closes = [
            e
            for e in self._journal.effects(item["trade_id"])
            if e["kind"] == "CLOSE" and e["status"] != "REJECTED"
        ]
        if len(closes) > 1:
            raise PositionIdentityError("multiple full closes claim the same generation")
        return closes[0] if closes else None

    async def reconcile_settlement(self, symbol: str) -> None:
        """Read-only retry for a previously observed terminal close, including a restart orphan."""
        async with self._lock:
            item = self._journal.active_trade(symbol)
            if not item or item["state"] != "OPEN":
                raise PositionIdentityError("pending settlement lost its owned journal entry")
            await self._verify_terminal_close(item)

    async def _verify_terminal_close(self, item: dict) -> None:
        """Distinguish a lagging history index from an unexplained disappearance of exposure."""
        symbol, trade_id, entry_id = item["symbol"], item["trade_id"], item["entry_order_id"]
        effects = self._journal.effects(trade_id)
        close = self._full_close(item)
        entries = [
            e
            for e in effects
            if e["kind"] == "ENTRY" and e["status"] == "ACCEPTED" and e["venue_id"] == entry_id
        ]
        if not close or len(entries) != 1:
            raise PositionIdentityError("flat generation lacks a unique owned entry and close")
        request = close["request"]
        close_id, version = request["id"], request.get("position_version")
        quantity = dec(item["quantity"])
        if (
            close_id == entry_id
            or close["venue_id"] not in (None, close_id)
            or dec(request["before"]) != quantity
            or dec(request["quantity"]) != quantity
            or quantity <= 0
            or any(e["status"] in {"UNKNOWN", "PREPARED"} and e != close for e in effects)
        ):
            raise PositionIdentityError("journaled close does not account for the remaining position")
        reductions = self._owned_reductions(item, effects)
        if close_id in reductions:
            raise PositionIdentityError("close order identity conflicts with a recorded reduction")
        reductions[close_id] = quantity
        native_fills = self._journal.native_target_fills(trade_id)
        plan = self._journal.native_target_plan(trade_id)
        bound = {r["venue_id"] for r in self._journal.attached(trade_id)}
        bound.update(
            e["venue_id"]
            for e in effects
            if e["kind"] in {"STOP", "TAKE", "PARTIAL_TAKE"} and e["status"] == "ACCEPTED"
        )
        if plan:
            bound.update(plan["full_ids"])
            if plan["version"] != version or plan["position_id"] != request.get("position_id"):
                raise PositionIdentityError("close and protection refer to different owned generations")

        async def snapshot():
            await self._identity()
            entry, exit_order, positions, resting, active = await asyncio.gather(
                self._api.order(entry_id),
                self._api.order(close_id),
                self._api.positions(),
                self._api.open_orders(),
                self._api.active_tpsl(symbol),
            )
            if (
                any(p.instrument == symbol for p in positions)
                or any(r.get("instrument") == symbol for r in resting)
                or active
            ):
                raise PositionIdentityError("settling instrument has a position or a resting order")
            if not entry or not exit_order:
                raise PositionIdentityError("terminal generation lacks its exact entry or close")
            versions = entry.get("positionVersions")
            if (
                not isinstance(versions, list)
                or len(versions) != 1
                or type(versions[0]) is not int
                or versions[0] < 0
                or (version is not None and versions != [version])
                or exit_order.get("positionVersions") != versions
                or type(exit_order["positionVersions"][0]) is not int
                or any(str(r.get("user", "")) != self._profile.remote_account_id for r in (entry, exit_order))
                or exit_order.get("id") != close_id
                or exit_order.get("instrument") != symbol
                or exit_order.get("side") != _exit_side(item)
                or exit_order.get("group") != "manually"
                or exit_order.get("status") != "FILLED"
                or dec(exit_order["quantity"]) != quantity
                or dec(exit_order["unFilledQuantity"]) != 0
                or dec(exit_order["filledAvgPrice"]) <= 0
            ):
                raise PositionIdentityError(
                    "terminal close differs from the journaled account, generation or quantity"
                )
            status, filled = self._entry_record(entry, item, entry_id, dec(entries[0]["request"]["price"]))
            if status not in TERMINAL or dec(entry["filledAvgPrice"]) != dec(item["price"]):
                raise PositionIdentityError("terminal generation entry conflicts with its original fill")
            orders = await self._api.position_version_orders(symbol, versions[0])
            self._validate_generation_balance(
                item, orders, entries[0], filled, dec(item["price"]), reductions, Decimal(0)
            )
            if bound:
                history = await self._api.target_history(symbol, bound)
                if set(history) != bound:
                    raise ProtectionEvidenceError("terminal generation is missing bound protection history")
                for key, row in history.items():
                    native = native_fills.get(key)
                    if (
                        row.get("id") != key
                        or row.get("instrument") != symbol
                        or row.get("side") != _exit_side(item)
                        or row.get("status") != ("done" if native else "cancelled")
                        or dec(row.get("triggeredQuantity") or 0) != (dec(native[1]) if native else 0)
                    ):
                        raise ProtectionEvidenceError("a bound protection has an unexplained terminal state")
            return versions[0], dec(exit_order["filledAvgPrice"])

        try:
            first = await snapshot()
            second = await snapshot()
        except (ArithmeticError, KeyError, TypeError, ValueError) as exc:
            raise PositionIdentityError(
                "terminal generation has malformed ownership or quantity evidence"
            ) from exc
        if first != second:
            raise PositionIdentityError("terminal generation changed between observations")
        if not await self._api.position_version_closed(symbol, second[0]):
            raise SettlementPending(symbol)

    async def position_open(self, trade: dict) -> bool:
        await self.refresh_performance()
        async with self._lock:
            item = self._owned(trade, allow_closed=True)
            position = await self._owned_position(item)
            if self._journal.native_target_plan(item["trade_id"]):
                trade["native_partial_targets"] = True
                trade["quantity"] = item["quantity"]
                trade["native_target_fills"] = list(
                    self._journal.native_target_fills(item["trade_id"]).values()
                )
            return bool(position and await self._maintain_protection(item, trade, position))

    def _tightest_stop(self, item: dict, runner_stop: Decimal | None = None) -> Decimal:
        prices = [dec(item["stop"])]
        if runner_stop is not None:
            prices.append(runner_stop)
        effects = self._journal.effects(item["trade_id"])
        cancelled = {
            e["request"]["id"] for e in effects if e["kind"] == "CANCEL_STOP" and e["status"] == "ACCEPTED"
        }
        prices.extend(
            dec(e["request"]["price"])
            for e in effects
            if e["kind"] == "STOP" and e["status"] == "ACCEPTED" and e["venue_id"] not in cancelled
        )
        return max(prices) if item["side"] == "LONG" else min(prices)

    async def _maintain_protection(self, item: dict, trade: dict, position: Position) -> bool:
        if self.protection_unavailable_for(item["symbol"]):
            # The caller already matched this live position. Keep it visible to the software
            # exits and explicit close path without adding or treating an unsafe trigger as cover.
            return True
        rows = await self._protection_rows(item, position=position, clear_waiting=True)
        scoped = {
            e["venue_id"]: e["request"]
            for e in self._journal.effects(item["trade_id"])
            if e["status"] == "ACCEPTED"
            and e["request"].get("wire_scope") == "position"
            and e["request"].get("position_id")
        }
        if scoped:
            fresh = await self._owned_position(item)
            if fresh is None:
                return False
            await self._require_position_generation(item, fresh)
            version = self._position_entries[item["entry_order_id"]][0]
            if any(r["position_id"] != fresh.venue_id or r["version"] != version for r in scoped.values()):
                raise PositionIdentityError("standalone protection belongs to another position generation")
            for row in rows:
                if (
                    row["id"] in scoped
                    and row.get("status") == "active"
                    and not any(
                        child.get("id") == row["id"]
                        and child.get("status") == "active"
                        and child.get("type") == row["type"]
                        and child.get("side") == row["side"]
                        and row_price(child) == row_price(row)
                        and dec(child["quantity"]) == dec(row["quantity"])
                        for child in fresh.protections
                    )
                ):
                    raise ProtectionEvidenceError("standalone protection is absent from the owned position")
        stop = self._tightest_stop(item, dec(trade["stop"]))
        if any(not self._usable_protection(item, r) for r in rows):
            raise NeedsOperator("foreign protection shares a managed instrument")
        if plan := self._journal.native_target_plan(item["trade_id"]):
            filled = self._journal.native_target_fills(item["trade_id"])
            placements = [e for e in self._journal.effects(item["trade_id"]) if e["kind"] == "PARTIAL_TAKE"]
            planned = {(r["price"], r["quantity"]) for r in plan["levels"]}
            accepted = {
                (e["request"]["price"], e["request"]["quantity"])
                for e in placements
                if e["status"] == "ACCEPTED"
            }
            if len(placements) != len(planned) or planned != accepted:
                raise ProtectionEvidenceError(
                    "native target placement stopped before all levels were confirmed"
                )
            pending = [e for e in placements if e["venue_id"] not in filled]
            if any(
                not any(target_matches(item, e, r) and r.get("status") == "active" for r in rows)
                for e in pending
            ):
                raise ProtectionEvidenceError("a pending native target is missing from the owned position")
        try:
            protected = await self._ensure_price(item, "stop-loss", stop, rows) and await self._ensure_price(
                item, "take-profit", dec(item["take"]), rows
            )
        except (EvedexError, ValueError, ArithmeticError, RuntimeError):
            protected = False
        if protected:
            trade["stop"] = plain(stop)
            return True
        current = await self._owned_position(item)
        if current:
            await self._close_quantity(item, current, current.quantity, origin="unknown")
        return False

    def _dispatch_refusal(self, expires_ms: int | None, now_ms: int) -> RefusalReason | None:
        if expires_ms is not None:
            if now_ms >= expires_ms:
                return RefusalReason.DEADLINE
            if self._entry_stopped():
                return RefusalReason.OPERATOR
        return None

    async def _effect(
        self,
        item: dict,
        kind: str,
        key: str,
        request: dict,
        call: Callable[[], Awaitable[Any]],
        *,
        expected_id: str | None = None,
        returned_id: bool = False,
        expires_ms: int | None = None,
        venue_now: Callable[[], int] = _now,
    ) -> Any:
        await self._identity()
        checked_at = venue_now()
        reason = self._dispatch_refusal(expires_ms, checked_at)
        if reason is not None:
            self._journal.release_refused(item["trade_id"], reason=reason)
            raise EntryExpired(reason.value)
        if expires_ms is not None:
            request = {**request, "expires_at_ms": expires_ms, "venue_checked_at_ms": checked_at}
        eid = self._journal.prepare_effect(
            trade_id=item["trade_id"], kind=kind, operation_key=key, request=request
        )
        reason = self._dispatch_refusal(expires_ms, venue_now())
        if reason is not None:
            self._journal.finish_effect(eid, "REJECTED", refusal=reason)
            self._journal.release_refused(item["trade_id"], reason=reason)
            raise EntryExpired(reason.value)
        try:
            response = await call()
            venue_id = expected_id
            if returned_id:
                venue_id = response.get("id") if isinstance(response, dict) else None
                if not isinstance(venue_id, str) or not venue_id or (expected_id and venue_id != expected_id):
                    raise NeedsOperator("venue did not acknowledge the exact request identity")
        except Rejected as exc:
            self._journal.finish_effect(eid, "REJECTED", refusal=_venue_refusal(exc), http_status=exc.status)
            raise
        except BaseException:
            self._journal.finish_effect(eid, "UNKNOWN", expected_id)
            raise
        self._journal.finish_effect(eid, "ACCEPTED", venue_id)
        return response

    def _admission(
        self,
        candidate: Any,
        quantity: Decimal,
        book: Book,
        instrument: Instrument,
        stop: Decimal,
        take: Decimal,
        leverage: int,
        decision: RiskTradeDecisionV1,
        venue_now: Callable[[], int],
    ) -> Decimal:
        if type(decision) is not RiskTradeDecisionV1:
            raise NeedsOperator("a validated LIVE Risk decision is required")
        # Recompute canonical digests even when a caller supplies a copied Pydantic model.
        decision = RiskTradeDecisionV1.model_validate(decision.model_dump(mode="python"))
        symbol = candidate.instrument
        now = venue_now()
        if (
            not decision.approved
            or decision.rejection_reasons
            or decision.account_id != self.account_id
            or decision.trading_mode.value != "LIVE"
            or decision.evedex_profile.value != "PROD"
            or PROD_SYMBOL_MAP.get(decision.intent.symbol) != symbol
            or symbol not in self._journal.symbols
            or instrument.name != symbol
            or decision.venue_symbol != symbol
            or not instrument.tradable
            or decision.intent.intent_id != candidate.id
            or decision.intent.side.value != candidate.side
            or stop != dec(decision.exit_plan.stop_price)
            or take != dec(decision.exit_plan.target_price)
            or type(leverage) is not int
            or leverage != decision.leverage
            or not 1 <= leverage <= min(30, instrument.max_leverage)
            or dec(decision.worst_case_loss_usd) > Decimal(self._profile.max_trade_loss_usd)
            or not 0 < quantity <= dec(decision.quantity)
            or quantity < instrument.min_quantity
        ):
            raise NeedsOperator("entry conflicts with the owner profile or Risk decision")
        if (
            decision.decided_at_ms > now
            or now >= min(decision.intent.entry_expires_ts_ms, decision.venue_quality.expires_at_ms)
            or not 0 <= now - book.time_ms <= 30_000
            or self._entry_stopped()
        ):
            raise EntryExpired("quote or Risk approval expired, or operator stopped entries")
        price = dec(decision.worst_entry_price)
        long = candidate.side == "LONG"
        if (
            min(instrument.price_step, instrument.quantity_step) <= 0
            or quantity % instrument.quantity_step
            or any(px % instrument.price_step or dec(plain(px)) != px for px in (price, stop, take))
            or dec(plain(quantity)) != quantity
            or price * quantity < instrument.min_volume
            or price * quantity > self._profile.max_notional_usd
        ):
            raise NeedsOperator("price or quantity no longer falls inside the approved execution bounds")
        if not (stop < book.ask <= price < take if long else take < price <= book.bid < stop):
            raise EntryExpired("latest quote outside the approved limit")
        return price

    async def _conservative_equity(self, positions: list[Position], venue_now: Callable[[], int]) -> Decimal:
        total, quotes = await asyncio.gather(
            self.equity(), asyncio.gather(*(self._api.book(p.instrument) for p in positions))
        )
        for pos, quote in zip(positions, quotes, strict=True):
            if not 0 <= venue_now() - quote.time_ms <= 30_000:
                raise EntryExpired("no fresh quote to value the open portfolio")
            delta = quote.bid - pos.avg_price if pos.side == "BUY" else pos.avg_price - quote.ask
            total += min(Decimal(0), pos.quantity * delta)
        return total

    async def enter(
        self,
        candidate: Any,
        quantity: Decimal,
        book: Book,
        instrument: Instrument,
        stop: Decimal,
        take: Decimal,
        leverage: int = 1,
        *,
        decision: RiskTradeDecisionV1,
        partial_targets: list[dict] | None = None,
    ) -> dict[str, Any] | None:
        async with self._lock:
            if reason := self.protection_unavailable_for(candidate.instrument):
                self._store.journal("entry_skipped", reason=reason)
                return None
            if partial_targets and not self.native_ladder_qualified_for(candidate.instrument):
                self._store.journal("entry_skipped", reason="native partial targets are unqualified")
                return None
            target_spec = partial_target_spec(partial_targets, instrument) if partial_targets else None
            active = {t["symbol"] for t in self._journal.active_trades()}
            issues, positions = await self._inspect(active, check_protected=True)
            if issues:
                raise NeedsOperator(", ".join(issues))
            observed_at, self._admission_observed_at = self._admission_observed_at, 0.0
            if not observed_at or time.monotonic() - observed_at >= 30:
                await self._observe()
            try:
                venue_now = await self._venue_clock()
                equity, book = await asyncio.gather(
                    self._conservative_equity(positions, venue_now), self._api.book(instrument.name)
                )
                price = self._admission(
                    candidate, quantity, book, instrument, stop, take, leverage, decision, venue_now
                )
            except EntryExpired as exc:
                self._store.journal("entry_skipped", reason=str(exc))
                return None
            if not decision.trade_id or not decision.decision_id:
                raise NeedsOperator("Risk omitted its canonical identifiers")
            try:
                self._journal.reserve_entry(
                    trade_id=decision.trade_id,
                    decision_id=decision.decision_id,
                    symbol=instrument.name,
                    side=candidate.side,
                    quantity=quantity,
                    leverage=leverage,
                    stop=stop,
                    take=take,
                    worst_case_loss=dec(decision.worst_case_loss_usd),
                    notional=quantity * price,
                    equity=equity,
                )
            except PortfolioAdmissionRefused as exc:
                self._store.journal("entry_skipped", reason=str(exc))
                return None
            item = self._journal.trade(decision.trade_id)
            if not item:
                raise NeedsOperator("reservation missing after commit")
            try:
                await self._effect(
                    item,
                    "LEVERAGE",
                    "initial",
                    {"leverage": leverage},
                    lambda: self._api.set_leverage(instrument.name, leverage),
                )
            except Rejected:
                self._journal.release_refused(decision.trade_id)
                return None
            deadline_ms = min(
                decision.intent.entry_expires_ts_ms,
                decision.venue_quality.expires_at_ms,
                int(self._profile.entry_deadline_utc.timestamp() * 1000),
            )
            if venue_now() >= deadline_ms:
                self._journal.release_refused(decision.trade_id, reason=RefusalReason.DEADLINE)
                return None
            order_id = new_order_id()
            attached = [
                {"type": kind, "side": _exit_side(item), "quantity": "0", "price": plain(px)}
                for kind, px in (("stop-loss", stop), ("take-profit", take))
            ]
            body = self._signer.bounded_entry(
                order_id=order_id,
                instrument=instrument.name,
                side=_side(item),
                quantity=quantity,
                price=price,
                leverage=leverage,
                protection=attached,
            )
            request = {
                "id": order_id,
                "symbol": instrument.name,
                "side": _side(item),
                "quantity": plain(quantity),
                "price": plain(price),
                "leverage": leverage,
                "stop": plain(stop),
                "take": plain(take),
            }
            if target_spec:
                request["partial_targets"] = target_spec
            try:
                await self._effect(
                    item,
                    "ENTRY",
                    "initial",
                    request,
                    lambda: self._api.post_limit_order(body),
                    expected_id=order_id,
                    returned_id=True,
                    expires_ms=deadline_ms,
                    venue_now=venue_now,
                )
            except EntryExpired:
                return None
            except (Unknown, NeedsOperator):
                if not any(
                    e["kind"] == "ENTRY" and e["status"] == "UNKNOWN"
                    for e in self._journal.effects(decision.trade_id)
                ):
                    raise
                # Read the exact original client order ID; a missing record never permits a resend.
            except Rejected:
                self._journal.release_refused(decision.trade_id)
                return None
            return await self._confirm_entry(item, order_id, price)

    @staticmethod
    def _entry_record(order: dict | None, item: dict, order_id: str, price: Decimal) -> tuple[str, Decimal]:
        if (
            not order
            or order.get("id") != order_id
            or order.get("instrument") != item["symbol"]
            or order.get("side") != _side(item)
            or order.get("type") != "LIMIT"
            or dec(order.get("limitPrice")) != price
            or dec(order.get("quantity")) != dec(item["approved_quantity"])
        ):
            raise NeedsOperator("exact owned entry and its signed geometry could not be reconciled")
        remaining = dec(order.get("unFilledQuantity"))
        supplied = dec(order["quantity"])
        status = str(order.get("status", "")).upper()
        if (
            not 0 <= remaining <= supplied
            or (status == "FILLED" and remaining != 0)
            or (status == "REJECTED" and remaining != supplied)
            or status not in TERMINAL | {"NEW", "PARTIALLY_FILLED"}
        ):
            raise NeedsOperator("entry has an inconsistent status or remaining quantity")
        return status, supplied - remaining

    async def _completed_entry_bracket(
        self, item: dict, record: dict, filled: Decimal, avg: Decimal
    ) -> dict[str, Any] | None:
        """An attached full bracket can close the position before the first open-position read."""
        symbol, order_id = item["symbol"], item["entry_order_id"]
        versions = record.get("positionVersions")
        if not (
            isinstance(versions, list)
            and len(versions) == 1
            and type(versions[0]) is int
            and versions[0] >= 0
            and str(record.get("user", "")) == self._profile.remote_account_id
            and avg > 0
            and hasattr(self._api, "protection_for_fill")
        ):
            return None
        version = versions[0]

        async def observation():
            if not await self._api.position_version_closed(symbol, version):
                return None
            rows, flat, active = await asyncio.gather(
                self._api.position_version_orders(symbol, version),
                self._flat_without_resting_order(symbol),
                self._api.active_tpsl(symbol),
            )
            if not flat or active or len(rows) != 2:
                return None
            entry = next((r for r in rows if r.get("id") == order_id), None)
            child = next((r for r in rows if r.get("id") and r["id"] != order_id), None)
            if not entry or not child or child.get("group") not in {"stop-loss", "take-profit"}:
                return None
            if any(
                str(r.get("user")) != self._profile.remote_account_id or r.get("instrument") != symbol
                for r in rows
            ):
                return None
            if any(
                record.get(k) != entry.get(k)
                for k in ("side", "status", "quantity", "unFilledQuantity", "filledAvgPrice")
            ):
                return None
            detail, trigger = await asyncio.gather(
                self._api.order(child["id"]),
                self._api.protection_for_fill(symbol, child["id"]),
            )
            if not detail or not trigger:
                return None
            kind = child["group"]
            px = dec(item["stop"] if kind == "stop-loss" else item["take"])
            if not (
                detail.get("id") == child["id"]
                and str(detail.get("user")) == self._profile.remote_account_id
                and detail.get("instrument") == symbol
                and detail.get("positionVersions") == [version]
                and detail.get("side") == _exit_side(item)
                and detail.get("status") == "FILLED"
                and detail.get("group") == kind
                and dec(detail["quantity"]) == filled
                and dec(detail["unFilledQuantity"]) == 0
                and dec(detail["filledAvgPrice"]) > 0
                and all(
                    detail.get(k) == child.get(k)
                    for k in ("side", "status", "quantity", "unFilledQuantity", "filledAvgPrice")
                )
                and trigger.get("status") == "done"
                and trigger.get("instrument") == symbol
                and trigger.get("side") == _exit_side(item)
                and trigger.get("type") == kind
                and dec(trigger["price"]) == px
                and dec(trigger["quantity"]) == 0
                and dec(trigger["triggeredQuantity"]) == filled
                and (trigger.get("id") == child["id"] or trigger.get("triggerOrder") == child["id"])
                and trigger.get("order") in (None, order_id)
                and trigger.get("triggerOrder") in (None, order_id, child["id"])
            ):
                return None
            if order_id not in (trigger.get("triggerOrder"), trigger.get("order")):
                parent = await self._api.order_with_protections(symbol, order_id)
                if not (
                    parent
                    and parent.get("id") == order_id
                    and str(parent.get("user")) == self._profile.remote_account_id
                    and any(
                        r.get("id") == trigger["id"]
                        and r.get("type") == kind
                        and r.get("side") == _exit_side(item)
                        and row_price(r) == px
                        and dec(r["quantity"]) == 0
                        for r in parent.get("tpslList", [])
                    )
                ):
                    return None
            return trigger["id"], child["id"], kind, dec(detail["filledAvgPrice"])

        first = await observation()
        if first is None or first != await observation():
            return None
        self._journal.opened(item["trade_id"], entry_order_id=order_id, quantity=filled, price=avg)
        self._journal.closed(item["trade_id"], exit_origin="system")
        self._position_entries.pop(order_id, None)
        self._store.journal(
            "portfolio_bracket_completed_at_entry",
            trade_id=item["trade_id"],
            symbol=symbol,
            generation=version,
            exit_trigger_id=first[0],
            exit_order_id=first[1],
        )
        return {
            "order_id": order_id,
            "trade_id": item["trade_id"],
            "price": avg,
            "quantity": filled,
            "protected": True,
            "closed_at_entry": "STOP" if first[2] == "stop-loss" else "TAKE",
            "exit_price": first[3],
        }

    async def _confirm_entry(self, item: dict, order_id: str, price: Decimal) -> dict[str, Any] | None:
        trade_id, symbol = item["trade_id"], item["symbol"]
        item = {**item, "entry_order_id": order_id}
        # A current owned nonterminal GTC is cancelled once. An absent projection never proves flatness.
        for _ in range(15):
            record = await self._api.order(order_id)
            if not record:
                await asyncio.sleep(self._settle_seconds)
                continue
            status, filled = self._entry_record(record, item, order_id, price)
            entry = next(e for e in self._journal.effects(trade_id) if e["kind"] == "ENTRY")
            if entry["status"] in {"PREPARED", "UNKNOWN"}:
                self._journal.reconcile_effect(entry["effect_id"], venue_id=order_id)
            if status not in TERMINAL:
                effects = self._journal.effects(trade_id)
                if not any(e["kind"] == "CANCEL_ENTRY" for e in effects):
                    try:
                        if filled:
                            pos = await self.position(symbol)
                            if pos and pos.side == _side(item) and pos.quantity == filled:
                                try:
                                    await self._ensure_entry_protection(item)
                                except ProtectionEvidenceError:
                                    # Position-only cover is not accepted for an unsettled GTC.
                                    # Cancel its remainder now and prove or close the terminal fill below.
                                    pass
                    finally:
                        # Even on a protection observation failure, stop the exact GTC remainder.
                        try:
                            await self._effect(
                                item,
                                "CANCEL_ENTRY",
                                order_id,
                                {"id": order_id},
                                lambda: self._api.cancel_order(order_id),
                                expected_id=order_id,
                            )
                        except Unknown:
                            pass  # the following exact-order read is the only allowed recovery
                await asyncio.sleep(self._settle_seconds)
                continue
            for cancel in self._journal.effects(trade_id):
                if cancel["kind"] == "CANCEL_ENTRY" and cancel["status"] in {"UNKNOWN", "PREPARED"}:
                    self._journal.reconcile_effect(cancel["effect_id"], venue_id=order_id)
            pos = await self.position(symbol)
            if not filled:
                if pos or any(o.get("instrument") == symbol for o in await self._api.open_orders()):
                    raise NeedsOperator("terminal zero-fill conflicts with venue exposure")
                await self._remove_leftovers(item)
                self._journal.no_fill(trade_id, entry_order_id=order_id)
                return None
            avg = dec(record.get("filledAvgPrice"))
            if pos is None and (completed := await self._completed_entry_bracket(item, record, filled, avg)):
                return completed
            if (
                pos is None
                or pos.side != _side(item)
                or pos.quantity != filled
                or pos.avg_price != avg
                or avg <= 0
                or (avg > price if item["side"] == "LONG" else avg < price)
            ):
                await asyncio.sleep(self._settle_seconds)
                continue
            self._journal.opened(trade_id, entry_order_id=order_id, quantity=filled, price=avg)
            opened = self._journal.trade(trade_id)
            if not opened:
                raise NeedsOperator("entry ownership was lost")
            item = opened
            stop, take = dec(item["stop"]), dec(item["take"])
            within_plan = stop < avg < take if item["side"] == "LONG" else take < avg < stop
            failure = "owned entry exceeded its geometry or protection could not be verified"
            try:
                protected = (
                    avg * filled <= self._profile.max_notional_usd
                    and within_plan
                    and await self._ensure_entry_protection(item, position=pos)
                )
            except ProtectionEvidenceError as exc:
                protected = False
                failure = str(exc)
            except PositionIdentityError:
                if completed := await self._completed_entry_bracket(item, record, filled, avg):
                    return completed
                raise
            except (EvedexError, ValueError, ArithmeticError, RuntimeError):
                protected = False
            if not protected:
                current = await self._owned_position(item)
                if current:
                    await self._close_quantity(item, current, current.quantity)
                    # The exact full close was confirmed before the runner received a trade.
                    # Settle only a clean instrument. Recovery owns any effects still in doubt.
                    try:
                        flat = await self._flat_without_resting_order(
                            symbol
                        ) and not await self._api.active_tpsl(symbol)
                    except (EvedexError, TimeoutError, ValueError) as exc:
                        raise NeedsOperator(
                            f"{failure}; emergency close filled, settlement read unavailable"
                        ) from exc
                    if flat and all(
                        e["status"] not in {"UNKNOWN", "PREPARED"} for e in self._journal.effects(trade_id)
                    ):
                        self._journal.closed(trade_id, exit_origin="system")
                        self._position_entries.pop(order_id, None)
                elif completed := await self._completed_entry_bracket(item, record, filled, avg):
                    return completed
                raise NeedsOperator(failure)
            if spec := entry["request"].get("partial_targets"):
                try:
                    await self._place_native_targets(item, pos, spec)
                except (EvedexError, ValueError, ArithmeticError) as exc:
                    if completed := await self._completed_entry_bracket(item, record, filled, avg):
                        return completed
                    raise ProtectionEvidenceError("native partial target plan needs reconciliation") from exc
            return {
                "quantity": filled,
                "price": avg,
                "order_id": order_id,
                "protected": True,
                "trade_id": trade_id,
                "native_partial_targets": bool(entry["request"].get("partial_targets")),
            }
        raise NeedsOperator("entry outcome needs order-specific reconciliation")

    async def _place_native_targets(self, item: dict, position: Position, spec: dict) -> None:
        # Only the complete fill, with its original full-size stop and final target, can arm levels.
        if not self.native_ladder_qualified_for(item["symbol"]):
            raise ProtectionEvidenceError("native partial targets are unqualified")
        await self._require_position_generation(item, position)
        version = self._position_entries[item["entry_order_id"]][0]
        levels = sized_targets(
            spec, item["side"], position.avg_price, dec(item["stop"]), dec(item["take"]), position.quantity
        )
        projection = await self._protection_rows(item, position=position)
        full_ids = []
        for kind, col in (("stop-loss", "stop"), ("take-profit", "take")):
            owned = [r["id"] for r in projection if self._valid_protection(item, r, kind, dec(item[col]))]
            if len(owned) != 1:
                raise ProtectionEvidenceError("native target plan requires its unique full-position bracket")
            full_ids.extend(owned)
        self._journal.bind_native_target_plan(
            item["trade_id"],
            {
                "entry_order_id": item["entry_order_id"],
                "position_id": position.venue_id,
                "version": version,
                "initial_quantity": plain(position.quantity),
                "levels": levels,
                "full_ids": full_ids,
            },
        )
        for level in levels:
            current = await self.position(item["symbol"])
            if current is None or current.venue_id != position.venue_id:
                raise ProtectionEvidenceError("position changed before native target placement")
            await self._require_position_generation(item, current)
            body = self._signer.tpsl(
                instrument=item["symbol"],
                kind="take-profit",
                side=_exit_side(item),
                quantity=dec(level["quantity"]),
                price=dec(level["price"]),
            )
            request = {
                **level,
                "order": item["entry_order_id"],
                "side": _exit_side(item),
                "version": version,
                "position_id": position.venue_id,
                "wire_scope": "position",
            }
            await self._effect(
                item,
                "PARTIAL_TAKE",
                level["price"],
                request,
                partial(self._api.post_partial_target, body, expected=current)
                if isinstance(self._api, Evedex)
                else partial(self._api.post_partial_target, body),
                returned_id=True,
            )
            # Confirm the new ID independently on both the active list and the exact same position.
            fresh = await self.position(item["symbol"])
            if fresh is None or fresh.venue_id != position.venue_id or not self._match_position(item, fresh):
                raise ProtectionEvidenceError("native target position changed before acknowledgement")
            await self._require_position_generation(item, fresh)
            rows = await self._protection_rows(item, position=fresh, clear_waiting=True)
            placements = [e for e in self._journal.effects(item["trade_id"]) if e["kind"] == "PARTIAL_TAKE"]
            if not all(
                sum(target_matches(item, e, row) and row.get("status") == "active" for row in records) == 1
                for e in placements
                for records in (rows, fresh.protections)
            ):
                raise ProtectionEvidenceError("native partial target lacks dual ownership confirmation")
            if not all(
                any(self._valid_protection(item, r, kind, dec(item[col])) for r in rows)
                for kind, col in (("stop-loss", "stop"), ("take-profit", "take"))
            ):
                raise ProtectionEvidenceError(
                    "full-size stop or final target disappeared during scale-out setup"
                )

    async def _reconcile_native_targets(self, item: dict, position: Position | None) -> None:
        plan = self._journal.native_target_plan(item["trade_id"])
        if not plan or item["state"] != "OPEN":
            return
        symbol, version = item["symbol"], plan["version"]
        remaining = position.quantity if position else Decimal(0)
        if position and (
            position.venue_id != plan["position_id"]
            or position.user != self._profile.remote_account_id
            or position.side != _side(item)
            or position.avg_price != dec(item["price"])
        ):
            raise PositionIdentityError("native targets belong to a different position generation")
        all_effects = self._journal.effects(item["trade_id"])
        effects = [e for e in all_effects if e["kind"] == "PARTIAL_TAKE"]
        cancelled = {
            e["request"]["id"]
            for e in all_effects
            if e["kind"] == "CANCEL_TAKE" and e["status"] == "ACCEPTED"
        }
        if any(e["status"] != "ACCEPTED" for e in effects):
            raise ProtectionEvidenceError("native target request still needs reconciliation")
        child_ids = {e["venue_id"] for e in effects}
        if len(child_ids) != len(effects):
            raise ProtectionEvidenceError("native target IDs are not unique")
        related_ids = (
            child_ids
            | set(plan["full_ids"])
            | {
                e["venue_id"]
                for e in all_effects
                if e["kind"] in {"STOP", "TAKE"} and e["status"] == "ACCEPTED"
            }
        )

        # A confirmed close only reduces ownership once, even when both levels fill between polls.
        async def snapshot():
            history, rows, closed = await asyncio.gather(
                self._api.target_history(symbol, related_ids),
                self._api.position_version_orders(symbol, version),
                self._api.position_version_closed(symbol, version),
            )
            if position is None and not closed and self._full_close(item):
                await self._verify_terminal_close(item)
                closed = True  # The indexed close arrived during the independent observations.
            if closed != (position is None):
                raise PositionIdentityError("native target position generation changed")
            if set(history) != related_ids:
                raise ProtectionEvidenceError("native trigger history is missing a bound sibling")
            # Version-list records do not always include positionVersions. Re-read each exact fill.
            details = await asyncio.gather(*(self._api.order(r["id"]) for r in rows))
            if any(
                not d
                or d["id"] != r["id"]
                or d.get("positionVersions") != [version]
                or any(
                    d.get(k) != r.get(k)
                    for k in ("instrument", "status", "side", "quantity", "unFilledQuantity")
                )
                for d, r in zip(details, rows, strict=True)
            ):
                raise PositionIdentityError("native target child lacks an exact generation order")
            fills = target_fills(
                item, plan, effects, history, details, self._profile.remote_account_id, remaining, cancelled
            )
            triggers = {
                key: tuple(
                    row.get(k)
                    for k in (
                        "status",
                        "side",
                        "price",
                        "quantity",
                        "triggerOrder",
                        "triggeredQuantity",
                        "updatedAt",
                    )
                )
                for key, row in history.items()
            }
            orders = {
                row["id"]: tuple(
                    row.get(k)
                    for k in (
                        "status",
                        "side",
                        "quantity",
                        "unFilledQuantity",
                        "filledAvgPrice",
                        "group",
                        "updatedAt",
                    )
                )
                for row in details
            }
            return fills, triggers, orders

        try:
            first = await snapshot()
            second = await snapshot()
        except (TargetEvidenceError, ValueError, ArithmeticError, KeyError, TypeError) as exc:
            raise ProtectionEvidenceError("cannot identify the terminal native target fill") from exc
        fresh = await self.position(symbol)
        if (
            first != second
            or ((fresh is None) != (position is None))
            or (
                fresh
                and (
                    fresh.venue_id != plan["position_id"]
                    or fresh.quantity != remaining
                    or fresh.user != self._profile.remote_account_id
                    or fresh.side != _side(item)
                )
            )
        ):
            raise PositionIdentityError("native target ownership changed between observations")
        self._journal.confirm_native_target_fills(item["trade_id"], second[0], remaining)
        updated = self._journal.trade(item["trade_id"])
        if updated is None:
            raise PositionIdentityError("missing owned journal entry after native fill")
        item["quantity"] = updated["quantity"]

    async def _ensure_entry_protection(self, item: dict, *, position: Position | None = None) -> bool:
        if self.protection_unavailable_for(item["symbol"]):
            return False
        # Attached and separately placed protection must refer to the same entry.
        rows = await self._protection_rows(item, position=position)
        if all(self._usable_protection(item, r) for r in rows) and all(
            any(self._valid_protection(item, r, kind, price) for r in rows)
            for kind, price in (("stop-loss", dec(item["stop"])), ("take-profit", dec(item["take"])))
        ):
            return True
        return await self._ensure_price(
            item, "stop-loss", dec(item["stop"]), rows
        ) and await self._ensure_price(item, "take-profit", dec(item["take"]))

    async def _ensure_price(
        self, item: dict, kind: str, price: Decimal, rows: list[dict[str, Any]] | None = None
    ) -> bool:
        if self.protection_unavailable_for(item["symbol"]):
            return False
        rows = rows if rows is not None else await self._protection_rows(item)
        if any(not self._usable_protection(item, r) for r in rows):
            raise NeedsOperator("an unowned protection shares this instrument")
        if any(self._valid_protection(item, r, kind, price) for r in rows):
            return True
        if (
            kind == "stop-loss"
            and price != dec(item["stop"])
            and not self.native_stop_move_qualified_for(item["symbol"])
        ):
            return False
        if item["state"] != "OPEN":
            return False  # cancel the GTC remainder and reconcile its terminal fill first
        current = await self._owned_position(item)
        if current is None:
            return False
        if (
            current.venue_id is not None
            or current.user is not None
            or item["entry_order_id"] in self._position_entries
        ):
            await self._require_position_generation(item, current)
        body = self._signer.tpsl(
            instrument=item["symbol"], kind=kind, side=_exit_side(item), quantity=Decimal(0), price=price
        )
        identity = self._position_entries.get(item["entry_order_id"])
        request = {
            "order": item["entry_order_id"],
            "price": plain(price),
            "side": _exit_side(item),
            "version": identity[0] if identity else None,
            "position_id": current.venue_id,
            "wire_scope": "position",
        }
        try:
            response = await self._effect(
                item,
                "STOP" if kind == "stop-loss" else "TAKE",
                plain(price),
                request,
                partial(self._api.post_tpsl, body, expected=current, entry_order_id=item["entry_order_id"])
                if isinstance(self._api, Evedex)
                else partial(self._api.post_tpsl, body),
                returned_id=True,
            )
        except Rejected:
            return False
        fresh, rows = await asyncio.gather(
            self.position(item["symbol"]), self._api.active_tpsl(item["symbol"])
        )
        if fresh is None or not self._match_position(item, fresh) or fresh.venue_id != current.venue_id:
            return False
        rows = await self._protection_rows(item, rows, fresh, clear_waiting=True)
        projections = [rows]
        if identity is not None:
            await self._require_position_generation(item, fresh)
            projections.append(list(fresh.protections))
        return all(
            sum(
                r["id"] == response["id"]
                and r.get("status") == "active"
                and self._valid_protection(item, r, kind, price)
                for r in projection
            )
            == 1
            for projection in projections
        )

    async def _clear_waiting_requests(self, item: dict, rows: list[dict]) -> list[dict]:
        # Only our individually acknowledged post-fill requests can be stranded waiting for an order.
        # An entry-attached trigger in waitOrder can still be armed by its unfinished GTC.
        effects = self._journal.effects(item["trade_id"])
        placements = {
            e["venue_id"]: e
            for e in effects
            if e["kind"] in {"PARTIAL_TAKE", "STOP", "TAKE"}
            and e["status"] == "ACCEPTED"
            and e["request"].get("order") == item["entry_order_id"]
        }
        candidates = {
            r["id"]
            for r in rows
            if r.get("status") == "waitOrder"
            and r.get("id") in placements
            and self._owned_protection(item, r)
        }
        if not candidates:
            return rows
        refreshed = await self._api.active_tpsl(item["symbol"])
        cancelled = {
            e["request"]["id"]
            for e in effects
            if e["kind"] in {"CANCEL_TAKE", "CANCEL_STOP"} and e["status"] == "ACCEPTED"
        }
        for row in refreshed:
            if (
                row.get("id") in candidates
                and row.get("status") == "waitOrder"
                and row["id"] not in cancelled
            ):
                await self._cancel_protection(item, row)
        after = await self._api.active_tpsl(item["symbol"])
        if any(r.get("id") in candidates and r.get("status") == "waitOrder" for r in after):
            raise ProtectionEvidenceError("acknowledged waiting protection has not cleared")
        return after

    async def _cancel_protection(self, item: dict, row: dict) -> None:
        if not self._owned_protection(item, row):
            raise NeedsOperator("protection is not attributed to this trade")
        key = row["id"]
        kind = "CANCEL_STOP" if row["type"] == "stop-loss" else "CANCEL_TAKE"
        await self._effect(
            item, kind, key, {"id": key}, lambda: self._api.cancel_tpsl(item["symbol"], key), expected_id=key
        )

    async def _owned_position(self, item: dict) -> Position | None:
        position = await self.position(item["symbol"])
        if (
            position is None or not self._match_position(item, position)
        ) and self._journal.native_target_plan(item["trade_id"]):
            await self._reconcile_native_targets(item, position)
        if position and not self._match_position(item, position):
            raise NeedsOperator("position quantity, side or price differs from the owned entry")
        return position

    async def ensure_stop(self, trade: dict) -> bool:
        async with self._lock:
            item = self._owned(trade, allow_closed=True)
            if not await self._owned_position(item):
                return True
            stop = dec(trade["stop"])
            outside = stop < dec(item["stop"]) if item["side"] == "LONG" else stop > dec(item["stop"])
            if outside:
                raise NeedsOperator("stop is outside the immutable Risk boundary")
            return await self._ensure_price(item, "stop-loss", stop)

    async def move_stop(self, trade: dict, stop: Decimal) -> bool:
        async with self._lock:
            item = self._owned(trade)
            if not await self._owned_position(item):
                return False
            if not self.native_stop_move_qualified_for(item["symbol"]):
                return False
            previous = dec(trade["stop"])
            stops = [
                r
                for r in await self._api.active_tpsl(item["symbol"])
                if self._owned_protection(item, r) and r["type"] == "stop-loss"
            ]
            known = [dec(item["stop"]), previous] + [dec(r["price"]) for r in stops]
            if not (stop > max(known) if item["side"] == "LONG" else stop < min(known)):
                raise ValueError("a stop may only move toward less risk")
            if not await self._ensure_price(item, "stop-loss", stop):
                current = await self._owned_position(item)
                if current:
                    await self._maintain_protection(item, trade, current)
                return False
            # A full-position replacement can cancel the old stop or reuse its
            # identity. Cancel only an old level still present after the move.
            active = {r["id"]: r for r in await self._api.active_tpsl(item["symbol"])}
            if not any(self._valid_protection(item, r, "stop-loss", stop) for r in active.values()):
                return False
            for row in stops:
                previous_row = active.get(row["id"])
                if previous_row is not None and row_price(previous_row) != stop:
                    await self._cancel_protection(item, previous_row)
            trade["stop"] = str(stop)
            return True

    async def _close_quantity(
        self, item: dict, pos: Position, quantity: Decimal, *, origin: str = "system"
    ) -> Decimal:
        if self._journal.native_target_plan(item["trade_id"]):
            if quantity != pos.quantity:
                raise NeedsOperator("native target plan is the sole owner of partial reductions")
            await self._require_position_generation(item, pos)
            for row in await self._protection_rows(item, position=pos):
                if dec(row.get("quantity")) > 0:
                    await self._cancel_protection(item, row)
            if any(dec(row.get("quantity")) > 0 for row in await self._api.active_tpsl(item["symbol"])):
                raise NeedsOperator("native partial targets are still resting before position close")
            remainder = await self._owned_position(item)
            if remainder is None:
                return Decimal(0)
            pos, quantity = remainder, remainder.quantity
        identity = {}
        if (
            pos.venue_id is not None
            or pos.user is not None
            or item["entry_order_id"] in self._position_entries
        ):
            await self._require_position_generation(item, pos)
            identity = {
                "position_version": self._position_entries[item["entry_order_id"]][0],
                "position_id": pos.venue_id,
            }
        full = quantity == pos.quantity
        if not 0 < quantity <= pos.quantity or dec(plain(quantity)) != quantity:
            raise NeedsOperator("close quantity is outside owned exposure")
        order_id = new_order_id()
        body = self._signer.close_order(
            order_id=order_id, instrument=item["symbol"], quantity=quantity, leverage=item["leverage"]
        )
        kind = "CLOSE" if full else "PARTIAL_CLOSE"
        try:
            await self._effect(
                item,
                kind,
                order_id,
                {
                    "id": order_id,
                    "quantity": plain(quantity),
                    "before": plain(pos.quantity),
                    "origin": origin,
                    **identity,
                },
                lambda: self._api.post_close(body),
                expected_id=order_id,
                returned_id=True,
            )
        except (Unknown, NeedsOperator):
            if not any(
                e["kind"] == kind and e["status"] == "UNKNOWN" and e["request"]["id"] == order_id
                for e in self._journal.effects(item["trade_id"])
            ):
                raise
        return await self._confirm_close(item, order_id, pos.quantity, quantity)

    async def _close_fill_matches(
        self, item: dict, effect: dict, order: dict | None, after: Position | None
    ) -> bool:
        request = effect["request"]
        quantity = dec(request["quantity"])
        remaining = dec(request["before"]) - quantity
        if not (
            order
            and order.get("id") == request["id"]
            and order.get("instrument") == item["symbol"]
            and order.get("side") == _exit_side(item)
            and order.get("status") == "FILLED"
            and dec(order.get("quantity")) == quantity
            and dec(order.get("unFilledQuantity")) == 0
            and dec(order.get("filledAvgPrice")) > 0
        ):
            return False
        if after is None:
            if remaining != 0:
                return False
        elif (
            remaining <= 0
            or after.side != _side(item)
            or after.avg_price != dec(item["price"])
            or after.quantity != remaining
        ):
            return False

        version = request.get("position_version")
        if version is None:
            if not isinstance(self._api, Evedex) and "positionVersions" not in order and "user" not in order:
                return True  # Adapter without exchange position identities.
            # Recover a close recorded by an older runner using the immutable entry receipt.
            entry = await self._api.order(item["entry_order_id"])
            versions = entry.get("positionVersions") if entry else None
            if not (
                entry
                and entry.get("id") == item["entry_order_id"]
                and entry.get("instrument") == item["symbol"]
                and str(entry.get("user", "")) == self._profile.remote_account_id
                and isinstance(versions, list)
                and len(versions) == 1
            ):
                return False
            version = versions[0]
        if (
            type(version) is not int
            or version < 0
            or str(order.get("user", "")) != self._profile.remote_account_id
            or order.get("positionVersions") != [version]
            or type(order["positionVersions"][0]) is not int
        ):
            return False
        if after is not None and (
            after.user != self._profile.remote_account_id
            or (request.get("position_id") is not None and after.venue_id != request["position_id"])
        ):
            return False
        # A matching symbol, average and size can belong to an identical replacement position.
        closed = await self._api.position_version_closed(item["symbol"], version)
        if remaining == 0 and not closed:
            await self._verify_terminal_close(item)
            return True
        return closed == (remaining == 0)

    async def _confirm_close(self, item: dict, order_id: str, before: Decimal, quantity: Decimal) -> Decimal:
        full = before == quantity
        kind = "CLOSE" if full else "PARTIAL_CLOSE"
        effect = next(
            e
            for e in self._journal.effects(item["trade_id"])
            if e["kind"] == kind and e["request"]["id"] == order_id
        )
        for _ in range(15):
            order, after = await asyncio.gather(self._api.order(order_id), self.position(item["symbol"]))
            request = effect["request"]
            if (
                order
                and order.get("status") in TERMINAL - {"FILLED"}
                and order.get("id") == order_id
                and order.get("instrument") == item["symbol"]
                and order.get("side") == _exit_side(item)
                and dec(order.get("quantity")) == dec(order.get("unFilledQuantity")) == quantity
                and after is not None
                and self._match_position(item, after)
                and after.quantity == before
                and after.venue_id == request.get("position_id", after.venue_id)
                and (after.user is None or after.user == self._profile.remote_account_id)
                and ("user" not in order or str(order["user"]) == self._profile.remote_account_id)
            ):
                self._journal.close_without_fill(
                    effect["effect_id"], order_id=order_id, venue_status=order["status"]
                )
                raise CloseUnfilled("terminal exit had zero filled quantity")
            if order and await self._close_fill_matches(item, effect, order, after):
                if effect["status"] in {"UNKNOWN", "PREPARED"}:
                    self._journal.reconcile_effect(effect["effect_id"], venue_id=order_id)
                if not full:
                    self._journal.reduced(item["trade_id"], close_order_id=order_id, quantity=quantity)
                return dec(order["filledAvgPrice"])
            await asyncio.sleep(self._settle_seconds)
        raise NeedsOperator("close cannot be confirmed against its exact order and position")

    async def partial_close(self, trade: dict, book: Book, quantity: Decimal) -> Decimal | None:
        async with self._lock:
            item = self._owned(trade)
            if self._journal.native_target_plan(item["trade_id"]):
                raise NeedsOperator("native target plan is the sole owner of partial exits")
            await self._recover_exit(item)
            item = self._owned(trade)
            pos = await self._owned_position(item)
            if pos and trade.get("quantity") is not None and dec(trade["quantity"]) != pos.quantity:
                trade["quantity"] = plain(pos.quantity)
                return None  # Recompute the target against the recovered reduction on the next poll.
            if not pos or quantity >= pos.quantity:
                return None
            try:
                price = await self._close_quantity(item, pos, quantity)
            except CloseUnfilled:
                return None
            trade["quantity"] = plain(pos.quantity - quantity)
            return price

    async def close(self, trade: dict, book: Book, reason: str) -> None:
        async with self._lock:
            item = self._owned(trade, allow_closed=True)
            if item["state"] == "OPEN":
                await self._recover_exit(item)
                item = self._owned(trade, allow_closed=True)
            pos = await self._owned_position(item)
            if pos:
                await self._close_quantity(
                    item, pos, pos.quantity, origin="operator" if reason == "OPERATOR_CLOSE" else "system"
                )

    async def _remove_leftovers(self, item: dict) -> None:
        rows = await self._protection_rows(item)
        if any(not self._owned_protection(item, r) for r in rows):
            raise NeedsOperator("foreign protection remains on the settled instrument")
        for row in rows:
            await self._cancel_protection(item, row)
        if await self._api.active_tpsl(item["symbol"]):
            raise NeedsOperator("venue still reports protective orders on the settled instrument")

    async def _flat_without_resting_order(self, symbol: str) -> bool:
        return await self.position(symbol) is None and not any(
            order.get("instrument") == symbol for order in await self._api.open_orders()
        )

    async def settle(self, trade: dict) -> dict[str, Any]:
        async with self._lock:
            await self._identity()
            item = self._owned(trade, allow_closed=True)
            if item["state"] != "CLOSED":
                if not await self._flat_without_resting_order(item["symbol"]):
                    raise NeedsOperator("cannot settle a position or resting order")
                if self._journal.native_target_plan(item["trade_id"]):
                    await self._reconcile_native_targets(item, None)
                await self._remove_leftovers(item)
                origin = "unknown"
                for effect in self._journal.effects(item["trade_id"]):
                    if effect["kind"] != "CLOSE" or effect["status"] != "ACCEPTED":
                        continue
                    record = await self._api.order(effect["venue_id"])
                    if not await self._close_fill_matches(item, effect, record, None):
                        raise PositionIdentityError("journaled full close conflicts with settlement evidence")
                    origin = effect["request"].get("origin", "unknown")
                self._journal.closed(item["trade_id"], exit_origin=origin)
                settled = self._journal.trade(item["trade_id"])
                if not settled:
                    raise NeedsOperator("settlement was not retained")
                item = settled
            self._position_entries.pop(item["entry_order_id"], None)
            return {
                "exit_origin": item["exit_origin"],
                "pnl_basis": item["pnl_basis"],
                "net_pnl": item["net_pnl"],
            }
