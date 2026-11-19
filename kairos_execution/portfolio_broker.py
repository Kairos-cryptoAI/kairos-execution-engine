"""Account-owned EVEDEX portfolio execution. A Risk decision authorizes one bounded entry."""

from __future__ import annotations

import asyncio
import hashlib
import re
import time
from collections.abc import Awaitable, Callable
from datetime import datetime
from decimal import Decimal
from typing import Any

from kairos_core.contracts import RiskTradeDecisionV1

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
from .portfolio_journal import PortfolioAdmissionRefused, PortfolioJournal
from .portfolio_performance import observe_pilot
from .portfolio_profile import PortfolioProfile, verify_profile
from .prod_universe import PROD_SYMBOL_MAP

PORTFOLIO_API_VERSION = 1
LIVE_ACCOUNT_SOURCE = "evedex-prod-runner-session"
TERMINAL = {"FILLED", "CANCELLED", "CANCELED", "REJECTED", "EXPIRED"}


class EntryExpired(EvedexError):
    """This approval no longer authorizes an executable entry."""


class NeedsOperator(EvedexError):
    """Venue facts or local ownership cannot safely authorize the next action."""


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


def _side(trade: dict) -> str:
    return {"LONG": "BUY", "SHORT": "SELL"}[trade["side"]]


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
        balance, available = await self._api.balance()
        return balance, available, await self._api.positions(), await self._api.open_orders()

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
        if row.get("side") != _side(item) or dec(row.get("quantity")) != 0:
            return False
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

    async def _protection_rows(self, item: dict) -> list[dict[str, Any]]:
        rows = await self._api.active_tpsl(item["symbol"])
        if not any(not r.get("order") and not self._owned_protection(item, r) for r in rows):
            return rows
        order_id = item["entry_order_id"]
        parent = await self._api.order_with_protections(item["symbol"], order_id)
        if not parent or str(parent.get("user", "")) != self._profile.remote_account_id:
            raise NeedsOperator("exact parent order and its authenticated account could not be verified")
        entry = next(
            e
            for e in self._journal.effects(item["trade_id"])
            if e["kind"] == "ENTRY" and e["venue_id"] == order_id
        )
        self._entry_record(parent, item, order_id, dec(entry["request"]["price"]))
        children = parent.get("tpslList")
        if not isinstance(children, list) or any(not isinstance(c, dict) for c in children):
            raise NeedsOperator("exact parent order has no verifiable TP/SL projection")
        for child in children:
            kind = child.get("type")
            if kind not in {"stop-loss", "take-profit"}:
                continue
            px = dec(item["stop"] if kind == "stop-loss" else item["take"])
            if (
                child.get("instrument") != item["symbol"]
                or child.get("side") != _side(item)
                or row_price(child) != px
                or dec(child.get("quantity")) != 0
            ):
                continue
            matches = [
                r
                for r in rows
                if r.get("id") == child.get("id")
                and r.get("type") == kind
                and r.get("side") == _side(item)
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
        return rows

    def _valid_protection(self, item: dict, row: dict, kind: str, price: Decimal) -> bool:
        return (
            self._owned_protection(item, row)
            and row["type"] == kind
            and row.get("side") == _side(item)
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
        if self._journal.unresolved_effects():
            issues.append("a venue request has an unresolved outcome")
        seen: set[str] = set()
        for pos in positions:
            item = tracked.get(pos.instrument)
            if not item or pos.instrument in seen or not self._match_position(item, pos):
                issues.append(f"unowned or mismatched position in {pos.instrument}")
            seen.add(pos.instrument)
        # Entries fill immediately or their known GTC remainder is cancelled before admitting another.
        if open_orders:
            issues.append("an unclosed entry or foreign order is resting")
        for row in protections:
            item = tracked.get(row.get("instrument", ""))
            if not item or not self._owned_protection(item, row):
                issues.append("unowned venue protection")
        if check_protected:
            for symbol, item in tracked.items():
                stop = self._tightest_stop(item)
                if (
                    symbol not in seen
                    or not any(self._valid_protection(item, r, "stop-loss", stop) for r in protections)
                    or not any(
                        self._valid_protection(item, r, "take-profit", dec(item["take"])) for r in protections
                    )
                ):
                    issues.append(f"{symbol} awaits its confirmed stop and take or flatness reconciliation")
        return issues, positions

    async def foreign_exposure(self, own: set[str]) -> list[str]:
        issues, _ = await self._inspect(own, check_protected=True)
        return issues

    async def reconcile_start(self, trades: list[dict], pending: dict | None) -> None:
        await self._identity()
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
            not self._owned_protection(item, r) for r in protections
        ):
            raise NeedsOperator("orphan shares its instrument with an unowned order")
        position = await self._owned_position(item)
        if position:
            await self._close_quantity(item, position, position.quantity, origin="unknown")
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
                await self._confirm_close(item, r["id"], dec(r["before"]), dec(r["quantity"]))
            break

    async def position_open(self, trade: dict) -> bool:
        await self.refresh_performance()
        async with self._lock:
            item = self._owned(trade, allow_closed=True)
            position = await self._owned_position(item)
            return bool(position and await self._maintain_protection(item, trade, position))

    def _tightest_stop(self, item: dict, runner_stop: Decimal | None = None) -> Decimal:
        prices = [dec(item["stop"])]
        if runner_stop is not None:
            prices.append(runner_stop)
        prices.extend(
            dec(e["request"]["price"])
            for e in self._journal.effects(item["trade_id"])
            if e["kind"] == "STOP" and e["status"] == "ACCEPTED"
        )
        return max(prices) if item["side"] == "LONG" else min(prices)

    async def _maintain_protection(self, item: dict, trade: dict, position: Position) -> bool:
        stop = self._tightest_stop(item, dec(trade["stop"]))
        rows = await self._protection_rows(item)
        if any(not self._owned_protection(item, r) for r in rows):
            raise NeedsOperator("foreign protection shares a managed instrument")
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
        if expires_ms is not None and (venue_now() >= expires_ms or self._entry_stopped()):
            self._journal.release_refused(item["trade_id"])
            raise EntryExpired("entry deadline or operator stop before dispatch")
        eid = self._journal.prepare_effect(
            trade_id=item["trade_id"], kind=kind, operation_key=key, request=request
        )
        if expires_ms is not None and (venue_now() >= expires_ms or self._entry_stopped()):
            self._journal.finish_effect(eid, "REJECTED")
            self._journal.release_refused(item["trade_id"])
            raise EntryExpired("entry expired while recording the venue request")
        try:
            response = await call()
            venue_id = expected_id
            if returned_id:
                venue_id = response.get("id") if isinstance(response, dict) else None
                if not isinstance(venue_id, str) or not venue_id or (expected_id and venue_id != expected_id):
                    raise NeedsOperator("venue did not acknowledge the exact request identity")
        except Rejected:
            self._journal.finish_effect(eid, "REJECTED")
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
    ) -> dict[str, Any] | None:
        async with self._lock:
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
                self._journal.release_refused(decision.trade_id)
                return None
            order_id = new_order_id()
            attached = [
                {"type": kind, "side": _side(item), "quantity": "0", "price": plain(px)}
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
                                await self._ensure_entry_protection(item)
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
            try:
                protected = (
                    avg * filled <= self._profile.max_notional_usd
                    and within_plan
                    and await self._ensure_entry_protection(item)
                )
            except (EvedexError, ValueError, ArithmeticError, RuntimeError):
                protected = False
            if not protected:
                current = await self._owned_position(item)
                if current:
                    await self._close_quantity(item, current, current.quantity)
                raise NeedsOperator("owned entry exceeded its geometry or protection could not be verified")
            return {
                "quantity": filled,
                "price": avg,
                "order_id": order_id,
                "protected": True,
                "trade_id": trade_id,
            }
        raise NeedsOperator("entry outcome needs order-specific reconciliation")

    async def _ensure_entry_protection(self, item: dict) -> bool:
        # Attached and separately placed protection must refer to the same entry.
        return await self._ensure_price(item, "stop-loss", dec(item["stop"])) and await self._ensure_price(
            item, "take-profit", dec(item["take"])
        )

    async def _ensure_price(
        self, item: dict, kind: str, price: Decimal, rows: list[dict[str, Any]] | None = None
    ) -> bool:
        rows = rows if rows is not None else await self._protection_rows(item)
        if any(not self._owned_protection(item, r) for r in rows):
            raise NeedsOperator("an unowned protection shares this instrument")
        if any(self._valid_protection(item, r, kind, price) for r in rows):
            return True
        body = self._signer.tpsl(
            instrument=item["symbol"], kind=kind, side=_side(item), quantity=Decimal(0), price=price
        )
        body["order"] = item["entry_order_id"]
        try:
            await self._effect(
                item,
                "STOP" if kind == "stop-loss" else "TAKE",
                plain(price),
                {"order": item["entry_order_id"], "price": plain(price), "side": _side(item)},
                lambda: self._api.post_tpsl(body),
                returned_id=True,
            )
        except Rejected:
            return False
        return any(
            self._valid_protection(item, r, kind, price) for r in await self._api.active_tpsl(item["symbol"])
        )

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
                return False
            for row in stops:
                if row_price(row) != stop:
                    await self._cancel_protection(item, row)
            trade["stop"] = str(stop)
            return True

    async def _close_quantity(
        self, item: dict, pos: Position, quantity: Decimal, *, origin: str = "system"
    ) -> Decimal:
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
                f"{pos.quantity}:{quantity}",
                {
                    "id": order_id,
                    "quantity": plain(quantity),
                    "before": plain(pos.quantity),
                    "origin": origin,
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

    async def _confirm_close(self, item: dict, order_id: str, before: Decimal, quantity: Decimal) -> Decimal:
        full = before == quantity
        kind = "CLOSE" if full else "PARTIAL_CLOSE"
        for _ in range(15):
            order = await self._api.order(order_id)
            after = await self.position(item["symbol"])
            if (
                order
                and order.get("id") == order_id
                and order.get("instrument") == item["symbol"]
                and order.get("side") == ("SELL" if _side(item) == "BUY" else "BUY")
                and order.get("status") == "FILLED"
                and dec(order.get("quantity")) == quantity
                and dec(order.get("unFilledQuantity")) == 0
                and dec(order.get("filledAvgPrice")) > 0
            ):
                remaining_matches = (full and after is None) or (
                    not full
                    and after
                    and after.side == _side(item)
                    and after.avg_price == dec(item["price"])
                    and after.quantity == before - quantity
                )
                if remaining_matches:
                    effect = next(
                        e
                        for e in self._journal.effects(item["trade_id"])
                        if e["kind"] == kind and e["request"]["id"] == order_id
                    )
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
            pos = await self._owned_position(item)
            if not pos or quantity >= pos.quantity:
                return None
            price = await self._close_quantity(item, pos, quantity)
            trade["quantity"] = plain(pos.quantity - quantity)
            return price

    async def close(self, trade: dict, book: Book, reason: str) -> None:
        async with self._lock:
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

    async def settle(self, trade: dict) -> dict[str, Any]:
        async with self._lock:
            await self._identity()
            item = self._owned(trade, allow_closed=True)
            if item["state"] != "CLOSED":
                if await self.position(item["symbol"]) is not None or any(
                    o.get("instrument") == item["symbol"] for o in await self._api.open_orders()
                ):
                    raise NeedsOperator("cannot settle a position or resting order")
                await self._remove_leftovers(item)
                origin = "unknown"
                for effect in self._journal.effects(item["trade_id"]):
                    if effect["kind"] != "CLOSE" or effect["status"] != "ACCEPTED":
                        continue
                    record = await self._api.order(effect["venue_id"])
                    if (
                        record
                        and record.get("id") == effect["venue_id"]
                        and record.get("status") == "FILLED"
                        and record.get("instrument") == item["symbol"]
                        and record.get("side") == ("SELL" if _side(item) == "BUY" else "BUY")
                        and dec(record.get("quantity")) == dec(item["quantity"])
                        and dec(record.get("unFilledQuantity")) == 0
                    ):
                        origin = effect["request"].get("origin", "unknown")
                self._journal.closed(item["trade_id"], exit_origin=origin)
                settled = self._journal.trade(item["trade_id"])
                if not settled:
                    raise NeedsOperator("settlement was not retained")
                item = settled
            return {
                "exit_origin": item["exit_origin"],
                "pnl_basis": item["pnl_basis"],
                "net_pnl": item["net_pnl"],
            }
