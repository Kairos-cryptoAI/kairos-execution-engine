"""Crash-safe PAPER execution for strict ``RiskTradeDecisionV1`` messages."""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import ROUND_CEILING, Decimal, InvalidOperation
from typing import Any

from kairos_core.contracts import (
    AccountSnapshotV2,
    OpenOrderSnapshotV2,
    PositionSnapshotV2,
    RiskTradeDecisionV1,
    TradeExecutionEventV1,
    canonical_sha256,
)
from kairos_core.enums import (
    CandidateReviewTier,
    EntryPolicy,
    EvedexProfile,
    OrderRole,
    OrderSide,
    OrderStatus,
    OrderType,
    ReasoningEffort,
    ReviewDecision,
    Side,
    TradeExecutionEventType,
    TradeExitReason,
    TradeLifecycleState,
    TradingMode,
)
from kairos_persistence import (
    EffectPreparation,
    EffectStatus,
    EffectType,
    ExecutionEffect,
    ExecutionJournalRepository,
    ExecutionMutationBudgetRepository,
    ExecutionRuntimeHealth,
    ExecutionRuntimeHealthRepository,
    NewTrade,
    TradeLifecycleRepository,
    TradeMutationResult,
    TradeRecord,
    TradeState,
)

from .adapters.evedex_sidecar import EvedexSidecarAdapter
from .config import ExecSettings
from .state_machine import client_order_id

_CANARY_SOURCE = "kairos-paper-canary"
_CANARY_RULE_DOMAIN = "evedex-dev-instrument-rule.v1"
_CANARY_RULE_DECIMAL_FIELDS = (
    "venue_lot_size",
    "venue_price_increment",
    "venue_quantity_increment",
    "venue_multiplier",
    "venue_min_volume_usd",
    "venue_min_price",
    "venue_max_price",
    "venue_min_quantity",
    "venue_max_quantity",
)
_CANARY_METADATA_KEYS = frozenset(
    {
        "account_id",
        "alpha_claim",
        "canary_entry_order",
        "canary_quantity",
        "entry_policy",
        "instrument_rules_sha256",
        "purpose",
        *_CANARY_RULE_DECIMAL_FIELDS,
        "venue_market_state",
        "venue_symbol",
        "venue_trading",
        "venue_updated_at_ms",
    }
)


class PaperExecutionSafetyError(RuntimeError):
    """PAPER could not prove that venue and durable state are safe."""


@dataclass(frozen=True, slots=True)
class PaperExecutionResult:
    events: tuple[TradeExecutionEventV1, ...]


@dataclass(frozen=True, slots=True)
class _VenueTriggeredExit:
    role: OrderRole
    reason: TradeExitReason
    target_state: TradeState
    protection_id: str
    trigger_order_id: str
    trigger_order: dict[str, Any]
    filled_quantity: float
    average_price: float
    fee_usd: float


class PaperExecutionEngine:
    """One-stop/one-target/one-timeout lifecycle with durable effects."""

    _MAX_ENTRY_ELIGIBILITY_WAIT_S = 2.0
    _EFFECT_AMBIGUITY_GRACE = timedelta(minutes=2)
    _VENUE_TIMESTAMP_SKEW = timedelta(seconds=2)
    _IOC_SETTLE_ATTEMPTS = 4
    _IOC_SETTLE_POLL_S = 0.05

    def __init__(
        self,
        adapter: EvedexSidecarAdapter,
        trades: TradeLifecycleRepository,
        effects: ExecutionJournalRepository,
        settings: ExecSettings,
        *,
        clock: Callable[[], datetime] | None = None,
        sleeper: Callable[[float], Awaitable[None]] | None = None,
        mutation_budget: ExecutionMutationBudgetRepository | None = None,
        runtime_health: ExecutionRuntimeHealthRepository | None = None,
    ) -> None:
        if settings.trading_mode is not TradingMode.PAPER:
            raise ValueError("PaperExecutionEngine requires TradingMode.PAPER")
        self.adapter = adapter
        self.trades = trades
        self.effects = effects
        self.mutation_budget = mutation_budget or ExecutionMutationBudgetRepository(trades.pool)
        self.runtime_health = runtime_health or ExecutionRuntimeHealthRepository(trades.pool)
        self.settings = settings
        self.clock = clock or (lambda: datetime.now(UTC))
        self._sleep = sleeper or asyncio.sleep
        self._recovery_blockers: tuple[str, ...] = ("startup recovery has not run",)
        self._recovered_events: list[TradeExecutionEventV1] = []
        self._operational_telemetry: dict[str, str] = {}
        self._last_sidecar_health: dict[str, Any] = {}
        self._lifecycle_lock = asyncio.Lock()

    @property
    def recovery_blocked(self) -> bool:
        return bool(self._recovery_blockers)

    @property
    def recovery_blockers(self) -> tuple[str, ...]:
        return self._recovery_blockers

    @property
    def operational_telemetry(self) -> tuple[tuple[str, str], ...]:
        """Secret-free health values for structured logs and metric exporters."""
        return tuple(sorted(self._operational_telemetry.items()))

    async def initialize_recovery(self) -> tuple[str, ...]:
        """Serialize startup/reconnect recovery with local lifecycle work."""
        async with self._lifecycle_lock:
            async with self.trades.account_lock(**self._remote_account_scope):
                return await self._initialize_recovery_unlocked()

    async def _initialize_recovery_unlocked(self) -> tuple[str, ...]:
        """Block entries, preflight DEV, then reconcile all known durable state."""
        environment = self._environment
        account_id = self.settings.account_id
        recovery = await self.trades.begin_recovery(
            environment=environment,
            account_id=account_id,
            exchange=self.adapter.name,
        )
        blockers: list[str] = []
        try:
            await self._observe_health(await self.adapter.preflight())
            await self.adapter.fetch_paper_state()
        except Exception as exc:
            blockers.append(f"venue preflight failed: {type(exc).__name__}: {exc}")
            self._recovery_blockers = tuple(blockers)
            return self._recovery_blockers

        try:
            await self._audit_scoped_public_facts()
        except Exception as exc:
            blockers.append(f"public lifecycle audit failed: {type(exc).__name__}: {exc}")
            self._recovery_blockers = tuple(blockers)
            return self._recovery_blockers

        recovery_effects = await self.effects.recovery_required(
            exchange=self.adapter.name,
            environment=environment,
            account_id=account_id,
        )
        eligible_effect_keys = {effect.effect_key for effect in recovery_effects}
        for effect in recovery_effects:
            try:
                if effect.trade_id is None:
                    await self._recover_effect_locked(effect)
                else:
                    # Lock ordering is always trade -> effect, matching normal
                    # decision redelivery and avoiding cross-process deadlock.
                    async with self.trades.trade_lock(effect.trade_id):
                        await self._recover_effect_locked(effect)
            except Exception as exc:
                blockers.append(f"{effect.effect_key}: {type(exc).__name__}: {exc}")
        for trade in await self.trades.recovery_required(environment=environment, account_id=account_id):
            try:
                async with self.trades.trade_lock(trade.trade_id):
                    current_trade = await self.trades.get(trade.trade_id)
                    if current_trade is not None and current_trade.state not in {
                        TradeState.FLAT,
                        TradeState.CANCELLED,
                    }:
                        unripe = await self._unripe_effects(
                            current_trade,
                            eligible_effect_keys=eligible_effect_keys,
                        )
                        if unripe:
                            raise PaperExecutionSafetyError(
                                "ambiguous venue effect is still inside its two-minute grace: "
                                + ",".join(unripe)
                            )
                        locked_venue = await self.adapter.fetch_paper_state()
                        self._recovered_events.extend(
                            await self._reconcile_trade(current_trade, locked_venue, ())
                        )
            except Exception as exc:
                blockers.append(f"{trade.trade_id}: {type(exc).__name__}: {exc}")
        if not blockers:
            try:
                final_venue = await self.adapter.fetch_paper_state()
                current_trades = await self.trades.recovery_required(
                    environment=environment,
                    account_id=account_id,
                )
                blockers.extend(self._authoritative_account_blockers(final_venue, current_trades))
            except Exception as exc:
                blockers.append(f"account-wide recovery: {type(exc).__name__}: {exc}")
        if not blockers:
            await self.trades.complete_recovery(
                environment=environment,
                account_id=account_id,
                exchange=self.adapter.name,
                expected_epoch=recovery.recovery_epoch,
                detail="SDK preflight, effects, positions, orders and TP/SL reconciled",
            )
        self._recovery_blockers = tuple(blockers)
        return self._recovery_blockers

    async def _audit_scoped_public_facts(self) -> None:
        """Require one atomic public fact for creation and every FSM transition."""

        scoped = await self.trades.list_trades_for_scope(
            environment=self._environment,
            account_id=self.settings.account_id,
            exchange=self.adapter.name,
            include_terminal=True,
        )
        for trade in scoped:
            facts = await self.trades.list_execution_events(trade.trade_id)
            expected_count = trade.state_version + 1
            if len(facts) != expected_count:
                raise PaperExecutionSafetyError(
                    f"trade {trade.trade_id} has {len(facts)} public facts for "
                    f"{expected_count} durable lifecycle versions"
                )
            if [fact.event_seq for fact in facts] != list(range(1, expected_count + 1)):
                raise PaperExecutionSafetyError(
                    f"trade {trade.trade_id} public lifecycle sequence is not contiguous"
                )
            first = facts[0]
            if (
                first.event_type is not TradeExecutionEventType.DECISION_RECEIVED
                or first.lifecycle_state is not TradeLifecycleState.RECEIVED
            ):
                raise PaperExecutionSafetyError(
                    f"trade {trade.trade_id} lacks the atomic DECISION_RECEIVED creation fact"
                )
            expected_state = TradeLifecycleState(trade.state.value)
            if facts[-1].lifecycle_state is not expected_state:
                raise PaperExecutionSafetyError(
                    f"trade {trade.trade_id} public state does not match durable {trade.state.value}"
                )

    async def block_entries(self, detail: str) -> None:
        """Serialize persistent safety revocation with local lifecycle work."""
        async with self._lifecycle_lock:
            async with self.trades.account_lock(**self._remote_account_scope):
                await self._block_entries_unlocked(detail)

    async def _block_entries_unlocked(self, detail: str) -> None:
        """Persistently revoke entry authority after any ambiguous PAPER state."""
        message = detail.strip()[:2_000] or "authoritative PAPER reconciliation required"
        await self.trades.begin_recovery(
            environment=self._environment,
            account_id=self.settings.account_id,
            exchange=self.adapter.name,
        )
        self._recovery_blockers = (message,)

    async def handle(self, decision: RiskTradeDecisionV1) -> PaperExecutionResult:
        """Serialize entry and reconciliation work within this service process."""
        trade_id = self._required_text(decision.trade_id, "trade_id")
        async with self._lifecycle_lock:
            async with self.trades.account_lock(**self._remote_account_scope):
                # The database session lock is the STOP/TP/timeout race boundary
                # across multiple PAPER engine instances.
                async with self.trades.trade_lock(trade_id):
                    return await self._handle_once(decision)

    async def _handle_once(self, decision: RiskTradeDecisionV1) -> PaperExecutionResult:
        """Submit one approved NEXT_BAR_MARKET decision and arm SL before TP."""
        self._validate_decision(decision)
        if not decision.approved:
            return PaperExecutionResult(events=())
        if self.recovery_blocked or not await self.trades.entries_allowed(
            environment=self._environment,
            account_id=self.settings.account_id,
            exchange=self.adapter.name,
        ):
            raise PaperExecutionSafetyError(
                "new PAPER entries are blocked until authoritative startup recovery completes"
            )

        now = self.clock().astimezone(UTC)
        now_ms = int(now.timestamp() * 1000)
        if now_ms < decision.intent.entry_eligible_ts_ms:
            wait_s = (decision.intent.entry_eligible_ts_ms - now_ms) / 1000
            if wait_s <= self._MAX_ENTRY_ELIGIBILITY_WAIT_S:
                await self._sleep(wait_s)
                now = self.clock().astimezone(UTC)
                now_ms = int(now.timestamp() * 1000)
            if now_ms < decision.intent.entry_eligible_ts_ms:
                raise PaperExecutionSafetyError(
                    "NEXT_BAR_MARKET eligibility is beyond the bounded local clock-skew wait"
                )

        # A delayed bus delivery must fail before creating durable venue intent.
        # Risk proved book/basis/depth only until this exact timestamp.
        if now_ms <= decision.intent.entry_expires_ts_ms:
            self._assert_fresh_entry_market(decision, now_ms)

        trade_id = self._required_text(decision.trade_id, "trade_id")
        entry_client_id = self._client_id(trade_id, OrderRole.ENTRY, decision.decided_at_ms)
        new_trade = NewTrade(
            trade_id=trade_id,
            strategy_intent_id=self._required_text(decision.intent.intent_id, "intent_id"),
            risk_decision_id=self._required_text(decision.decision_id, "decision_id"),
            risk_decision_payload=decision.to_payload(),
            strategy_id=decision.intent.strategy_id,
            strategy_revision=decision.intent.strategy_revision,
            trading_mode=decision.trading_mode.value,
            environment=self._environment,
            profile=decision.evedex_profile.value,
            exchange=self.adapter.name,
            account_id=decision.account_id,
            symbol=decision.intent.symbol,
            venue_symbol=decision.venue_symbol,
            side=self._order_side(decision).value,
            quantity=decision.quantity,
            leverage=decision.leverage,
            stop_price=decision.exit_plan.stop_price,
            target_price=decision.exit_plan.target_price,
            entry_eligible_at=self._from_ms(decision.intent.entry_eligible_ts_ms),
            entry_expires_at=self._from_ms(decision.intent.entry_expires_ts_ms),
            max_holding_ms=decision.exit_plan.max_holding_ms,
            entry_client_order_id=entry_client_id,
        )
        creation, created = await self._create_trade_with_event(decision, new_trade)
        trade = creation.trade
        if trade.state is not TradeState.RECEIVED:
            # Redelivery never repeats a venue effect. Reconciliation owns any
            # non-initial trade and will emit missing facts from durable state.
            return PaperExecutionResult(events=tuple(await self._reconcile_redelivery_locked(trade)))

        events = [creation.event] if created else []
        if now_ms > decision.intent.entry_expires_ts_ms:
            trade, event = await self._transition_with_event(
                decision,
                trade,
                TradeState.CANCELLED,
                journal_event_type="DECISION_EXPIRED_BEFORE_SUBMISSION",
                public_event_type=TradeExecutionEventType.ENTRY_CANCELLED,
                lifecycle_state=TradeLifecycleState.CANCELLED,
                order_role=OrderRole.ENTRY,
                client_order_id=entry_client_id,
                requested_quantity=decision.quantity,
                details=(("reason", "entry_deadline_expired"),),
            )
            events.append(event)
            return PaperExecutionResult(events=tuple(events))
        trade, entry_pending = await self._transition_with_event(
            decision,
            trade,
            TradeState.ENTRY_PENDING,
            journal_event_type="ENTRY_EFFECT_READY",
            public_event_type=TradeExecutionEventType.RECONCILIATION,
            lifecycle_state=TradeLifecycleState.ENTRY_PENDING,
            order_role=OrderRole.ENTRY,
            client_order_id=entry_client_id,
            requested_quantity=decision.quantity,
            details=(("reason", "entry_effect_ready"),),
        )
        events.append(entry_pending)
        entry_effect = self._effect_id(trade_id, OrderRole.ENTRY, "place")
        preparation = await self._prepare_entry_effect(
            decision,
            trade,
            effect_id=entry_effect,
            client_order_id=entry_client_id,
        )
        try:
            response = await self._entry_effect(
                decision,
                trade,
                effect_id=entry_effect,
                client_order_id=entry_client_id,
                preparation=preparation,
            )
            exchange_order_id, status, filled, average_price = self._validate_entry_response(
                response,
                decision=decision,
                client_order_id=entry_client_id,
            )
            if filled <= 0 and status not in {"CANCELED", "REJECTED", "EXPIRED", "REPLACED"}:
                # EVEDEX may ACK an IOC LIMIT as NEW before its REST projections
                # converge. Do not return an unattended, potentially fillable
                # order: settle it synchronously, then cancel and prove no
                # exposure, or fail into account recovery.
                response = await self._settle_or_cancel_ioc_entry(decision, trade, response)
                exchange_order_id, status, filled, average_price = self._validate_entry_response(
                    response,
                    decision=decision,
                    client_order_id=entry_client_id,
                )
        except Exception as exc:
            # The mutation may have reached EVEDEX even when its ACK is
            # malformed or the NDJSON boundary failed. Exposure is checked
            # immediately; any observed fill is closed, never left waiting for
            # the ambiguity grace without protection.
            await self._block_entries_unlocked(
                f"ambiguous entry ACK requires recovery: {type(exc).__name__}: {exc}"
            )
            venue = await self.adapter.fetch_paper_state()
            exposed = self._position_quantity(venue, trade.symbol)
            if exposed <= 0:
                raise
            trade, failed = await self._transition_with_event(
                decision,
                trade,
                TradeState.PROTECTING,
                journal_event_type="AMBIGUOUS_ENTRY_ACK_WITH_EXPOSURE",
                public_event_type=TradeExecutionEventType.FAILED,
                lifecycle_state=TradeLifecycleState.PROTECTING,
                event_payload={"observed_quantity_hex": float(exposed).hex()},
                transition_filled_quantity=min(exposed, trade.quantity),
                first_fill_at=self._from_ms(decision.intent.entry_eligible_ts_ms),
                entry_exchange_order_id=entry_client_id,
                effect_id=entry_effect,
                order_role=OrderRole.ENTRY,
                client_order_id=entry_client_id,
                requested_quantity=decision.quantity,
                public_filled_quantity=min(exposed, trade.quantity),
                position_quantity=exposed,
                details=(("reason", "ambiguous_entry_ack_with_exposure"),),
            )
            events.append(failed)
            events.extend(
                await self._emergency_close(
                    decision,
                    trade,
                    f"ambiguous entry ACK: {type(exc).__name__}",
                )
            )
            return PaperExecutionResult(events=tuple(events))
        if filled <= 0 and status in {"CANCELED", "REJECTED", "EXPIRED", "REPLACED"}:
            trade, event = await self._transition_with_event(
                decision,
                trade,
                TradeState.CANCELLED,
                journal_event_type="ENTRY_TERMINAL_WITHOUT_FILL",
                public_event_type=TradeExecutionEventType.ENTRY_CANCELLED,
                lifecycle_state=TradeLifecycleState.CANCELLED,
                entry_exchange_order_id=exchange_order_id,
                order_role=OrderRole.ENTRY,
                client_order_id=entry_client_id,
                exchange_order_id=exchange_order_id,
                requested_quantity=decision.quantity,
            )
            events.append(event)
            return PaperExecutionResult(events=tuple(events))
        if filled <= 0:
            trade, event = await self._transition_with_event(
                decision,
                trade,
                TradeState.ENTRY_PENDING,
                journal_event_type="ENTRY_ACKNOWLEDGED_PENDING_FILL",
                public_event_type=TradeExecutionEventType.VENUE_ACK,
                lifecycle_state=TradeLifecycleState.ENTRY_PENDING,
                entry_exchange_order_id=exchange_order_id,
                order_role=OrderRole.ENTRY,
                client_order_id=entry_client_id,
                exchange_order_id=exchange_order_id,
                requested_quantity=decision.quantity,
            )
            events.append(event)
            return PaperExecutionResult(events=tuple(events))

        observed_at = self.clock().astimezone(UTC)
        fill_at = self._response_time(
            response,
            fallback=observed_at,
            observed_at=observed_at,
            not_before=self._from_ms(decision.intent.entry_eligible_ts_ms),
        )
        event_type = (
            TradeExecutionEventType.ENTRY_FILLED
            if math.isclose(filled, decision.quantity, rel_tol=1e-9)
            else TradeExecutionEventType.ENTRY_PARTIAL_FILL
        )
        trade, event = await self._transition_with_event(
            decision,
            trade,
            TradeState.PROTECTING,
            journal_event_type="FIRST_NONZERO_FILL",
            public_event_type=event_type,
            lifecycle_state=TradeLifecycleState.PROTECTING,
            transition_filled_quantity=filled,
            first_fill_at=fill_at,
            entry_exchange_order_id=exchange_order_id,
            order_role=OrderRole.ENTRY,
            client_order_id=entry_client_id,
            exchange_order_id=exchange_order_id,
            requested_quantity=decision.quantity,
            public_filled_quantity=filled,
            position_quantity=filled,
            average_price=average_price,
            details=self._execution_shortfall_details(decision, average_price),
        )
        events.append(event)
        protection_events = await self._protect(decision, trade)
        events.extend(protection_events)
        return PaperExecutionResult(events=tuple(events))

    async def _settle_or_cancel_ioc_entry(
        self,
        decision: RiskTradeDecisionV1,
        trade: TradeRecord,
        acknowledged: dict[str, Any],
    ) -> dict[str, Any]:
        """Bound an asynchronous IOC ACK without leaving naked exposure."""
        fill_projection_seen = False
        for attempt in range(self._IOC_SETTLE_ATTEMPTS):
            venue = await self.adapter.fetch_paper_state()
            settled, observed_fill = self._settled_entry_projection(decision, trade, venue)
            fill_projection_seen = fill_projection_seen or observed_fill
            if settled is not None:
                return settled
            if attempt + 1 < self._IOC_SETTLE_ATTEMPTS:
                await self._sleep(self._IOC_SETTLE_POLL_S)

        # A FILLED/PARTIALLY_FILLED history record is authoritative exposure
        # evidence even while the positions projection is lagging. Cancelling
        # that already-filled IOC cannot make the account flat and can obscure
        # the lineage, so fail into immediate compensation/recovery instead.
        if fill_projection_seen:
            raise PaperExecutionSafetyError(
                "IOC fill projection did not converge to an authoritative position"
            )

        cancel_ack = await self._cancel_entry_effect(trade)
        if self._required_text(cancel_ack.get("id"), "entry cancel order ID") != trade.entry_client_order_id:
            raise PaperExecutionSafetyError("entry cancel ACK changed the deterministic order ID")
        cancel_status = str(cancel_ack.get("status", "")).upper().replace("CANCELLED", "CANCELED")
        if cancel_status != "CANCELED":
            raise PaperExecutionSafetyError("entry cancel ACK is not terminal CANCELED")

        last_venue: dict[str, Any] | None = None
        for attempt in range(self._IOC_SETTLE_ATTEMPTS):
            last_venue = await self.adapter.fetch_paper_state()
            settled, observed_fill = self._settled_entry_projection(decision, trade, last_venue)
            if settled is not None:
                return settled
            if observed_fill:
                raise PaperExecutionSafetyError("IOC fill appeared while proving authoritative cancellation")
            if self._find_order(last_venue, trade.entry_client_order_id) is not None:
                if attempt + 1 < self._IOC_SETTLE_ATTEMPTS:
                    await self._sleep(self._IOC_SETTLE_POLL_S)
                    continue
                raise PaperExecutionSafetyError("IOC entry remains open after authoritative cancel")
            if attempt + 1 < self._IOC_SETTLE_ATTEMPTS:
                await self._sleep(self._IOC_SETTLE_POLL_S)

        if last_venue is None or self._position_quantity_for_trade(last_venue, trade) > 0:
            raise PaperExecutionSafetyError("IOC cancel could not prove an exposure-free account")
        # The original ACK proves the exact order geometry; the cancel ACK and
        # repeated authoritative no-order/no-position reads prove its terminal
        # outcome even when order-history projection lags.
        return {**acknowledged, "status": "CANCELED"}

    def _settled_entry_projection(
        self,
        decision: RiskTradeDecisionV1,
        trade: TradeRecord,
        venue: dict[str, Any],
    ) -> tuple[dict[str, Any] | None, bool]:
        position_quantity = self._position_quantity_for_trade(venue, trade)
        candidates_by_payload: dict[str, dict[str, Any]] = {}
        for candidate in (
            self._find_order(venue, trade.entry_client_order_id),
            self._find_historical_order(venue, trade.entry_client_order_id),
        ):
            if candidate is not None:
                encoded = json.dumps(candidate, sort_keys=True, separators=(",", ":"), default=str)
                candidates_by_payload[encoded] = candidate
        candidates = list(candidates_by_payload.values())
        validated: list[tuple[dict[str, Any], str, float]] = []
        for candidate in candidates:
            _, status, filled, _ = self._validate_entry_response(
                candidate,
                decision=decision,
                client_order_id=trade.entry_client_order_id,
            )
            validated.append((candidate, status, filled))
        if position_quantity > 0:
            matching = [
                candidate
                for candidate, _, filled in validated
                if filled + max(1e-12, trade.quantity * 1e-9) >= position_quantity
            ]
            if len(matching) != 1:
                raise PaperExecutionSafetyError("IOC exposure lacks one exact entry-order fill projection")
            return matching[0], True
        observed_fill = any(filled > 0 for _, _, filled in validated)
        terminal = [
            candidate
            for candidate, status, filled in validated
            if filled <= 0 and status in {"CANCELED", "REJECTED", "EXPIRED", "REPLACED"}
        ]
        if len(terminal) > 1:
            first = json.dumps(terminal[0], sort_keys=True, separators=(",", ":"), default=str)
            if any(
                json.dumps(item, sort_keys=True, separators=(",", ":"), default=str) != first
                for item in terminal[1:]
            ):
                raise PaperExecutionSafetyError("IOC terminal projections conflict")
        return (None if not terminal else terminal[0]), observed_fill

    async def _reconcile_redelivery_locked(self, trade: TradeRecord) -> list[TradeExecutionEventV1]:
        """Recover one redelivered trade while its cross-process lock is held."""
        await self._observe_health(await self.adapter.preflight())
        venue = await self.adapter.fetch_paper_state()
        current_trade = await self.trades.get(trade.trade_id)
        if current_trade is None:
            raise PaperExecutionSafetyError("redelivered decision lost its durable trade")
        if current_trade.state in {TradeState.FLAT, TradeState.CANCELLED}:
            emitted = self._recovered_events
            self._recovered_events = []
            return [*emitted, *(await self._recover_terminal_public_fact(current_trade))]
        gap_events = await self._recover_pre_mutation_gap(current_trade, venue)
        current_trade = await self.trades.get(trade.trade_id)
        if current_trade is None:
            raise PaperExecutionSafetyError("trade disappeared during redelivery recovery")
        if current_trade.state in {TradeState.FLAT, TradeState.CANCELLED}:
            return [*gap_events, *(await self._recover_terminal_public_fact(current_trade))]
        recovery_effects = await self.effects.recovery_required(
            exchange=self.adapter.name,
            environment=self._environment,
            account_id=self.settings.account_id,
        )
        eligible_effect_keys = {effect.effect_key for effect in recovery_effects}
        for effect in recovery_effects:
            if effect.trade_id != trade.trade_id:
                continue
            await self._recover_effect_locked(effect)
        current_trade = await self.trades.get(trade.trade_id)
        if current_trade is not None:
            unripe = await self._unripe_effects(
                current_trade,
                eligible_effect_keys=eligible_effect_keys,
            )
            if unripe:
                raise PaperExecutionSafetyError(
                    "redelivered trade has an in-flight ambiguous venue effect: " + ",".join(unripe)
                )
        venue = await self.adapter.fetch_paper_state()
        sidecar_events: list[dict[str, Any]] = list(await self.adapter.drain_events(limit=1000))
        current_trade = await self.trades.get(trade.trade_id)
        emitted = [*gap_events, *self._recovered_events]
        self._recovered_events = []
        if current_trade is None:
            return emitted
        if current_trade.state in {TradeState.FLAT, TradeState.CANCELLED}:
            emitted.extend(await self._recover_terminal_public_fact(current_trade))
            return emitted
        emitted.extend(await self._reconcile_trade(current_trade, venue, tuple(sidecar_events)))
        return emitted

    async def _recover_pre_mutation_gap(
        self,
        trade: TradeRecord,
        venue: dict[str, Any],
    ) -> list[TradeExecutionEventV1]:
        """Close crash windows that provably precede any venue mutation."""
        decision = self._decision_for_trade(trade)
        events: list[TradeExecutionEventV1] = []
        if trade.state is TradeState.RECEIVED:
            trade, cancelled = await self._transition_with_event(
                decision,
                trade,
                TradeState.CANCELLED,
                journal_event_type="RECOVERED_CRASH_BEFORE_ENTRY_TRANSITION",
                public_event_type=TradeExecutionEventType.ENTRY_CANCELLED,
                lifecycle_state=TradeLifecycleState.CANCELLED,
                order_role=OrderRole.ENTRY,
                client_order_id=trade.entry_client_order_id,
                requested_quantity=trade.quantity,
                details=(("reason", "crash_before_entry_transition"),),
            )
            events.append(cancelled)
            return events
        if trade.state is not TradeState.ENTRY_PENDING:
            return events
        placement_id = self._effect_id(trade.trade_id, OrderRole.ENTRY, "place")
        placement = await self.effects.get(placement_id)
        if placement is not None:
            # PREPARED is authoritative internal effect-journal state, not a
            # domain lifecycle fact. Recovery below reconciles the effect and
            # publishes only the resulting venue/lifecycle observation.
            return events
        # Every adapter mutation is ordered strictly after a durable PREPARED
        # journal row. Its absence therefore proves Kairos never called EVEDEX.
        if (
            self._find_order(venue, trade.entry_client_order_id) is not None
            or self._find_historical_order(venue, trade.entry_client_order_id) is not None
            or self._position_quantity_for_trade(venue, trade) > 0
        ):
            raise PaperExecutionSafetyError(
                "venue exposure exists without the mandatory PREPARED entry effect"
            )
        trade, cancelled = await self._transition_with_event(
            decision,
            trade,
            TradeState.CANCELLED,
            journal_event_type="RECOVERED_CRASH_BEFORE_ENTRY_EFFECT_PREPARE",
            public_event_type=TradeExecutionEventType.ENTRY_CANCELLED,
            lifecycle_state=TradeLifecycleState.CANCELLED,
            order_role=OrderRole.ENTRY,
            client_order_id=trade.entry_client_order_id,
            requested_quantity=trade.quantity,
            details=(("reason", "crash_before_durable_effect_prepare"),),
        )
        events.append(cancelled)
        return events

    async def _recover_terminal_public_fact(
        self,
        trade: TradeRecord,
    ) -> list[TradeExecutionEventV1]:
        """Audit terminal state; atomic transitions make repair unnecessary."""
        facts = await self.trades.list_execution_events(trade.trade_id)
        if trade.state is TradeState.CANCELLED:
            if any(
                fact.event_type is TradeExecutionEventType.ENTRY_CANCELLED
                and fact.lifecycle_state is TradeLifecycleState.CANCELLED
                for fact in facts
            ):
                return []
            raise PaperExecutionSafetyError("terminal CANCELLED trade lacks its atomic public lifecycle fact")
        if trade.state is not TradeState.FLAT:
            return []
        if any(
            fact.lifecycle_state is TradeLifecycleState.FLAT
            and fact.event_type
            in {TradeExecutionEventType.EXIT_FILLED, TradeExecutionEventType.EMERGENCY_CLOSE}
            for fact in facts
        ):
            return []
        raise PaperExecutionSafetyError("terminal FLAT trade lacks its atomic public lifecycle fact")

    async def reconcile_once(self) -> list[TradeExecutionEventV1]:
        """Serialize reconciliation against decision handling in this process."""
        async with self._lifecycle_lock:
            async with self.trades.account_lock(**self._remote_account_scope):
                try:
                    return await self._reconcile_once_unlocked()
                except Exception as exc:
                    await self._block_entries_unlocked(
                        f"authoritative reconciliation failed: {type(exc).__name__}: {exc}"
                    )
                    raise

    async def _reconcile_once_unlocked(self) -> list[TradeExecutionEventV1]:
        """Reconcile sidecar events, entry expiry, fill protection and timeout."""
        if self.recovery_blocked:
            return []
        if not await self.trades.entries_allowed(
            environment=self._environment,
            account_id=self.settings.account_id,
            exchange=self.adapter.name,
        ):
            self._recovery_blockers = ("durable account recovery is active",)
            return []
        eligible_recovery_effects = await self.effects.recovery_required(
            exchange=self.adapter.name,
            environment=self._environment,
            account_id=self.settings.account_id,
        )
        if eligible_recovery_effects:
            raise PaperExecutionSafetyError("execution journal requires a durable account recovery epoch")
        await self._observe_health(await self.adapter.preflight())
        sidecar_events: list[dict[str, Any]] = list(await self.adapter.drain_events(limit=1000))
        emitted = self._recovered_events
        self._recovered_events = []
        for trade in await self.trades.recovery_required(
            environment=self._environment,
            account_id=self.settings.account_id,
        ):
            async with self.trades.trade_lock(trade.trade_id):
                current_trade = await self.trades.get(trade.trade_id)
                if current_trade is None or current_trade.state in {
                    TradeState.FLAT,
                    TradeState.CANCELLED,
                }:
                    continue
                unripe = await self._unripe_effects(
                    current_trade,
                    eligible_effect_keys=set(),
                )
                if unripe:
                    raise PaperExecutionSafetyError(
                        "venue effect is still inside its two-minute ambiguity grace: " + ",".join(unripe)
                    )
                locked_venue = await self.adapter.fetch_paper_state()
                sidecar_events.extend(await self.adapter.drain_events(limit=1000))
                emitted.extend(
                    await self._reconcile_trade(current_trade, locked_venue, tuple(sidecar_events))
                )
        return emitted

    async def account_snapshot(self) -> AccountSnapshotV2:
        """Serialize account lineage reads with local lifecycle mutations."""
        async with self._lifecycle_lock:
            async with self.trades.account_lock(**self._remote_account_scope):
                return await self._account_snapshot_unlocked()

    async def _account_snapshot_unlocked(self) -> AccountSnapshotV2:
        """Join authoritative venue state with durable strategy/trade lineage."""
        captured = self.clock().astimezone(UTC)
        captured_ms = int(captured.timestamp() * 1000)
        await self._observe_health(await self.adapter.preflight())
        venue = await self.adapter.fetch_paper_state()
        account = self._object(venue.get("account"), "account")
        remote_identities = {
            str(account[key]) for key in ("id", "exchangeId", "user") if account.get(key) is not None
        }
        if self.settings.evedex_dev_expected_account_id not in remote_identities:
            raise PaperExecutionSafetyError("account snapshot identity differs from PAPER preflight")
        if account.get("marginCall") is not False:
            raise PaperExecutionSafetyError("EVEDEX PAPER account is in margin call or lacks its flag")
        balance = self._object(venue.get("balance"), "balance")
        funding = self._object(balance.get("funding"), "funding")
        venue_positions = self._list(venue.get("positions"))
        negative_unpnl = sum(
            max(0.0, -self._required_position_unrealized(item))
            for item in venue_positions
            if self._required_nonnegative_number(item, "quantity") > 0
        )
        equity = max(0.0, self._finite(funding.get("balance")) - negative_unpnl)
        available = max(0.0, self._finite(balance.get("availableBalance")) - negative_unpnl)
        if equity <= 0:
            raise PaperExecutionSafetyError("reconciled PAPER equity is not positive")
        durable_trades = await self.trades.recovery_required(
            environment=self._environment,
            account_id=self.settings.account_id,
        )
        by_venue_symbol = {
            self.settings.evedex_dev_symbol_map[trade.symbol]: trade for trade in durable_trades
        }
        by_entry_id = {trade.entry_client_order_id: trade for trade in durable_trades}
        owned_tpsl_ids = {
            order_id
            for trade in durable_trades
            for order_id in (trade.stop_exchange_order_id, trade.target_exchange_order_id)
            if order_id is not None
        }
        details = self._authoritative_account_blockers(venue, durable_trades)
        positions: list[PositionSnapshotV2] = []
        total_open_risk = 0.0
        unrealized = 0.0
        instrument_metrics = {
            str(item.get("name", "")).upper(): item for item in self._list(venue.get("instruments"))
        }
        for item in venue_positions:
            quantity = self._required_nonnegative_number(item, "quantity")
            if quantity <= 0:
                continue
            venue_symbol = str(item.get("instrument", "")).upper()
            trade = by_venue_symbol.get(venue_symbol)
            if trade is None:
                details.append(f"unowned venue position {venue_symbol}")
                continue
            if trade.first_fill_at is None or trade.timeout_at is None:
                details.append(f"trade {trade.trade_id} position has no durable first-fill clock")
                continue
            decision = RiskTradeDecisionV1.model_validate(trade.risk_decision_payload)
            raw_side = str(item.get("side", "")).upper()
            if raw_side not in {"BUY", "SELL"}:
                details.append(f"trade {trade.trade_id} venue side is malformed")
                continue
            entry = self._positive(item.get("avgPrice"), "position entry")
            metrics = instrument_metrics.get(venue_symbol)
            if metrics is None:
                details.append(f"position {venue_symbol} lacks authoritative instrument metrics")
                continue
            mark = self._positive(metrics.get("markPrice"), "position mark")
            signed_quantity = quantity if raw_side == "BUY" else -quantity
            position_unrealized = self._required_position_unrealized(item)
            leverage = self._positive(item.get("leverage"), "position leverage")
            if not math.isclose(
                leverage,
                trade.leverage,
                rel_tol=1e-9,
                abs_tol=max(1e-12, trade.leverage * 1e-9),
            ):
                details.append(f"trade {trade.trade_id} venue leverage differs from approval")
                continue
            unrealized += position_unrealized
            total_open_risk += quantity * abs(entry - trade.stop_price)
            positions.append(
                PositionSnapshotV2(
                    venue_symbol=venue_symbol,
                    side=Side.LONG if raw_side == "BUY" else Side.SHORT,
                    signed_quantity=signed_quantity,
                    entry_price=entry,
                    mark_price=mark,
                    leverage=leverage,
                    liquidation_price=self._positive_optional(item.get("liquidationPrice")),
                    unrealized_pnl_usd=position_unrealized,
                    strategy_id=trade.strategy_id,
                    strategy_revision=trade.strategy_revision,
                    intent_id=trade.strategy_intent_id,
                    risk_decision_id=trade.risk_decision_id,
                    trade_id=trade.trade_id,
                    lifecycle_state=TradeLifecycleState(trade.state.value),
                    entry_client_order_id=trade.entry_client_order_id,
                    stop_client_order_id=trade.stop_client_order_id,
                    target_client_order_id=trade.target_client_order_id,
                    first_fill_at_ms=int(trade.first_fill_at.timestamp() * 1000),
                    timeout_at_ms=int(trade.timeout_at.timestamp() * 1000),
                    exit_plan=decision.exit_plan,
                )
            )
        open_orders: list[OpenOrderSnapshotV2] = []
        for item in self._list(venue.get("orders")):
            client_id = str(item.get("id", ""))
            trade = by_entry_id.get(client_id)
            if trade is None:
                details.append(f"unowned open venue order {client_id or '<missing-id>'}")
                continue
            decision = RiskTradeDecisionV1.model_validate(trade.risk_decision_payload)
            status_raw = str(item.get("status", "NEW")).upper().replace("CANCELLED", "CANCELED")
            try:
                status = OrderStatus(status_raw)
            except ValueError:
                details.append(f"order {client_id} has unknown status {status_raw}")
                continue
            if status not in {OrderStatus.NEW, OrderStatus.PARTIALLY_FILLED}:
                continue
            quantity = self._required_nonnegative_number(item, "quantity")
            remaining = self._required_nonnegative_number(item, "unFilledQuantity")
            open_orders.append(
                OpenOrderSnapshotV2(
                    venue_symbol=decision.venue_symbol,
                    client_order_id=client_id,
                    exchange_order_id=client_id,
                    order_role=OrderRole.ENTRY,
                    side=OrderSide(trade.side),
                    order_type=(
                        OrderType.MARKET
                        if str(item.get("type", "MARKET")).upper() == "MARKET"
                        else OrderType.LIMIT
                    ),
                    status=status,
                    quantity=quantity,
                    filled_quantity=max(0.0, quantity - remaining),
                    price=self._positive_optional(item.get("limitPrice")),
                    reduce_only=False,
                    strategy_id=trade.strategy_id,
                    strategy_revision=trade.strategy_revision,
                    intent_id=trade.strategy_intent_id,
                    risk_decision_id=trade.risk_decision_id,
                    trade_id=trade.trade_id,
                    created_at_ms=self._timestamp_ms(item.get("createdAt"), captured_ms),
                    updated_at_ms=self._timestamp_ms(item.get("updatedAt"), captured_ms),
                )
            )
        for item in self._list(venue.get("tpsl")):
            if self._is_live_tpsl(item) and str(item.get("id", "")) not in owned_tpsl_ids:
                details.append(f"unowned live TP/SL {item.get('id', '<missing-id>')}")
        margin_used = sum(
            self._required_nonnegative_number(item, "initialMargin")
            for item in self._list(balance.get("positions"))
        )
        if self.recovery_blocked:
            details.extend(self.recovery_blockers)
        if details:
            detail = "; ".join(dict.fromkeys(details))[:2_000]
            await self._block_entries_unlocked(detail)
            raise PaperExecutionSafetyError(detail)
        # Day-start/peak state advances only after every account, balance,
        # lineage and protection invariant above has passed.
        equity_state = await self.trades.record_equity(
            environment=self._environment,
            account_id=self.settings.account_id,
            exchange=self.adapter.name,
            captured_at=captured,
            equity_usd=equity,
        )
        detail = "SDK account, balance summaries, lifecycle lineage, effects and protection reconciled"
        return AccountSnapshotV2(
            source=self.settings.service_name,
            trading_mode=TradingMode.PAPER,
            evedex_profile=EvedexProfile.DEV,
            account_id=self.settings.account_id,
            equity_usd=equity,
            available_balance_usd=available,
            margin_used_usd=margin_used,
            durable_day_start_equity_usd=equity_state.day_start_equity_usd,
            durable_peak_equity_usd=equity_state.peak_equity_usd,
            unrealized_pnl_usd=unrealized,
            total_open_risk_usd=total_open_risk,
            positions=tuple(positions),
            open_orders=tuple(open_orders),
            captured_at_ms=captured_ms,
            reconciliation_seq=equity_state.reconciliation_seq,
            reconciled=True,
            reconciliation_detail=detail[:2048],
        )

    def _authoritative_account_blockers(
        self,
        venue: dict[str, Any],
        durable_trades: list[TradeRecord],
        *,
        ignore_trade_id: str | None = None,
    ) -> list[str]:
        """Validate account-wide ownership and SDK balance projections."""
        blockers: list[str] = []
        account = self._object(venue.get("account"), "account")
        identities = {
            str(account[key]) for key in ("id", "exchangeId", "user") if account.get(key) is not None
        }
        if self.settings.evedex_dev_expected_account_id not in identities:
            blockers.append("authenticated account identity differs from the dedicated DEV account")
        if account.get("marginCall") is not False:
            blockers.append("authenticated DEV account is in margin call or lacks its flag")

        included = [trade for trade in durable_trades if trade.trade_id != ignore_trade_id]
        by_symbol: dict[str, TradeRecord] = {}
        by_entry: dict[str, TradeRecord] = {}
        protection: dict[str, tuple[TradeRecord, OrderRole, str, float]] = {}
        for trade in included:
            venue_symbol = self.settings.evedex_dev_symbol_map.get(trade.symbol)
            if venue_symbol is None:
                blockers.append(f"trade {trade.trade_id} has a symbol outside the DEV allowlist")
                continue
            if venue_symbol in by_symbol:
                blockers.append(f"multiple nonterminal trades own {venue_symbol}")
            by_symbol[venue_symbol] = trade
            if trade.entry_client_order_id in by_entry:
                blockers.append("duplicate deterministic entry IDs in durable state")
            by_entry[trade.entry_client_order_id] = trade
            for exchange_id, role, tpsl_type, price in (
                (trade.stop_exchange_order_id, OrderRole.STOP_LOSS, "STOP_LOSS", trade.stop_price),
                (
                    trade.target_exchange_order_id,
                    OrderRole.TAKE_PROFIT,
                    "TAKE_PROFIT",
                    trade.target_price,
                ),
            ):
                if exchange_id is not None:
                    if exchange_id in protection:
                        blockers.append("duplicate TP/SL exchange identity in durable state")
                    protection[exchange_id] = (trade, role, tpsl_type, price)

        actual_positions: dict[tuple[str, str], float] = {}
        for item in self._list(venue.get("positions")):
            quantity = self._required_nonnegative_number(item, "quantity")
            if quantity <= 0:
                continue
            venue_symbol = str(item.get("instrument", "")).upper()
            side = str(item.get("side", "")).upper()
            if side not in {"BUY", "SELL"}:
                blockers.append(f"position {venue_symbol} has malformed side")
                continue
            key = (venue_symbol, side)
            actual_positions[key] = actual_positions.get(key, 0.0) + quantity
            position_owner = by_symbol.get(venue_symbol)
            if position_owner is None:
                blockers.append(f"unowned venue position {venue_symbol}")
                continue
            if side != position_owner.side:
                blockers.append(f"position {venue_symbol} side differs from durable lineage")
            if quantity > position_owner.quantity + max(1e-12, position_owner.quantity * 1e-9):
                blockers.append(f"position {venue_symbol} exceeds approved quantity")
            leverage = self._positive(item.get("leverage"), "position leverage")
            if not math.isclose(
                leverage,
                position_owner.leverage,
                rel_tol=1e-9,
                abs_tol=max(1e-12, position_owner.leverage * 1e-9),
            ):
                blockers.append(f"position {venue_symbol} leverage differs from durable approval")
            if position_owner.state is TradeState.ENTRY_PENDING:
                blockers.append(f"trade {position_owner.trade_id} has an unreconciled entry fill")
            elif position_owner.state in {TradeState.PROTECTING, TradeState.ACTIVE} and not math.isclose(
                quantity,
                position_owner.filled_quantity,
                rel_tol=1e-9,
                abs_tol=max(1e-12, position_owner.quantity * 1e-9),
            ):
                blockers.append(f"position {venue_symbol} differs from durable cumulative filled quantity")

        actual_orders: dict[tuple[str, str], float] = {}
        for item in self._list(venue.get("orders")):
            client_id = str(item.get("id", ""))
            order_owner = by_entry.get(client_id)
            venue_symbol = str(item.get("instrument", "")).upper()
            side = str(item.get("side", "")).upper()
            remaining = self._required_nonnegative_number(item, "unFilledQuantity")
            if remaining > 0:
                key = (venue_symbol, side)
                actual_orders[key] = actual_orders.get(key, 0.0) + remaining
            if order_owner is None:
                blockers.append(f"unowned open venue order {client_id or '<missing-id>'}")
                continue
            self._validate_entry_response(
                item,
                decision=self._decision_for_trade(order_owner),
                client_order_id=order_owner.entry_client_order_id,
            )
            if order_owner.state not in {
                TradeState.ENTRY_PENDING,
                TradeState.PROTECTING,
                TradeState.ACTIVE,
            }:
                blockers.append(f"terminal/closing trade {order_owner.trade_id} retains an entry order")

        tpsl_records = {
            self._required_text(item.get("id"), "TP/SL exchange ID"): item
            for item in self._list(venue.get("tpsl"))
        }
        for tpsl_id, item in tpsl_records.items():
            self._assert_known_tpsl_status(item)
            if not self._is_live_tpsl(item):
                continue
            lineage = protection.get(tpsl_id)
            if lineage is None:
                blockers.append(f"unowned live TP/SL {tpsl_id}")
                continue
            trade, _, tpsl_type, price = lineage
            self._validate_tpsl_record(
                item,
                venue_symbol=self.settings.evedex_dev_symbol_map[trade.symbol],
                side=trade.side,
                tpsl_type=tpsl_type,
                price=price,
                parent_order_id=trade.entry_client_order_id,
                require_live=True,
                require_parent=False,
            )

        for trade in included:
            position_open = self.settings.evedex_dev_symbol_map[trade.symbol] in {
                symbol for symbol, _ in actual_positions
            }
            if trade.state is TradeState.ACTIVE and not position_open:
                blockers.append(f"ACTIVE trade {trade.trade_id} lacks its venue position")
            if trade.state in {TradeState.PROTECTING, TradeState.ACTIVE} and position_open:
                stop = tpsl_records.get(trade.stop_exchange_order_id or "")
                if stop is None or not self._is_live_tpsl(stop):
                    blockers.append(f"trade {trade.trade_id} has unprotected exposure")
            if trade.state is TradeState.ACTIVE and position_open:
                target = tpsl_records.get(trade.target_exchange_order_id or "")
                if target is None or not self._is_live_tpsl(target):
                    blockers.append(f"ACTIVE trade {trade.trade_id} lacks its target")

        balance = self._object(venue.get("balance"), "balance")
        summary_positions = self._balance_projection(
            self._list(balance.get("positions")), quantity_field="volume"
        )
        summary_orders = self._balance_projection(
            self._list(balance.get("openOrders")), quantity_field="unFilledVolume"
        )
        if not self._projections_match(summary_positions, actual_positions):
            blockers.append("balance.positions differs from fetched positions")
        if not self._projections_match(summary_orders, actual_orders):
            blockers.append("balance.openOrders differs from fetched open orders")
        return blockers

    @classmethod
    def _balance_projection(
        cls, rows: list[dict[str, Any]], *, quantity_field: str
    ) -> dict[tuple[str, str], float]:
        projection: dict[tuple[str, str], float] = {}
        for row in rows:
            quantity = cls._required_nonnegative_number(row, quantity_field)
            if quantity <= 0:
                continue
            symbol = str(row.get("instrument", "")).upper()
            side = str(row.get("side", "")).upper()
            if not symbol or side not in {"BUY", "SELL"}:
                raise PaperExecutionSafetyError("balance projection has malformed instrument/side")
            key = (symbol, side)
            projection[key] = projection.get(key, 0.0) + quantity
        return projection

    @staticmethod
    def _projections_match(left: dict[tuple[str, str], float], right: dict[tuple[str, str], float]) -> bool:
        return left.keys() == right.keys() and all(
            math.isclose(left[key], right[key], rel_tol=1e-9, abs_tol=1e-12) for key in left
        )

    async def _protect(
        self, decision: RiskTradeDecisionV1, trade: TradeRecord
    ) -> list[TradeExecutionEventV1]:
        events: list[TradeExecutionEventV1] = []
        stop_client_id = self._client_id(trade.trade_id, OrderRole.STOP_LOSS, decision.decided_at_ms)
        stop_effect = self._effect_id(trade.trade_id, OrderRole.STOP_LOSS, "create")
        try:
            stop = await self._tpsl_effect(
                trade,
                effect_id=stop_effect,
                client_order_id=stop_client_id,
                role=OrderRole.STOP_LOSS,
                price=trade.stop_price,
            )
            stop_id = self._required_text(stop.get("id"), "stop exchange ID")
            # Persist server lineage immediately after the durable effect is
            # confirmed. A transient follow-up read must still leave enough
            # information to cancel the protection after an emergency close.
            trade, stop_created = await self._transition_with_event(
                decision,
                trade,
                TradeState.PROTECTING,
                journal_event_type="STOP_EFFECT_CONFIRMED_PENDING_RECONCILIATION",
                public_event_type=TradeExecutionEventType.STOP_CREATED,
                lifecycle_state=TradeLifecycleState.PROTECTING,
                stop_client_order_id=stop_client_id,
                stop_exchange_order_id=stop_id,
                effect_id=stop_effect,
                order_role=OrderRole.STOP_LOSS,
                client_order_id=stop_client_id,
                exchange_order_id=stop_id,
                requested_quantity=trade.filled_quantity,
                position_quantity=trade.filled_quantity,
                details=(("reason", "pending_authoritative_reconciliation"),),
            )
            events.append(stop_created)
            reconciled_stop = await self.adapter.find_tpsl_record(
                symbol=trade.symbol,
                tpsl_id=stop_id,
                tpsl_type="stop-loss",
                price=trade.stop_price,
                parent_order_id=None,
            )
            if reconciled_stop is None:
                raise PaperExecutionSafetyError("created stop was not authoritatively reconciled")
            self._validate_tpsl_record(
                reconciled_stop,
                venue_symbol=decision.venue_symbol,
                side=trade.side,
                tpsl_type="STOP_LOSS",
                price=trade.stop_price,
                parent_order_id=trade.entry_client_order_id,
                require_live=True,
                require_parent=False,
            )
            await self.effects.reconcile(
                stop_effect,
                exchange_effect_id=stop_id,
                response_payload=reconciled_stop,
            )
            trade, stop_reconciled = await self._transition_with_event(
                decision,
                trade,
                TradeState.PROTECTING,
                journal_event_type="STOP_RECONCILED",
                public_event_type=TradeExecutionEventType.STOP_RECONCILED,
                lifecycle_state=TradeLifecycleState.PROTECTING,
                stop_client_order_id=stop_client_id,
                stop_exchange_order_id=stop_id,
                effect_id=stop_effect,
                order_role=OrderRole.STOP_LOSS,
                client_order_id=stop_client_id,
                exchange_order_id=stop_id,
                requested_quantity=trade.filled_quantity,
                position_quantity=trade.filled_quantity,
            )
            events.append(stop_reconciled)
        except Exception as exc:
            events.extend(await self._emergency_close(decision, trade, f"stop failed: {type(exc).__name__}"))
            return events

        target_client_id = self._client_id(trade.trade_id, OrderRole.TAKE_PROFIT, decision.decided_at_ms)
        target_effect = self._effect_id(trade.trade_id, OrderRole.TAKE_PROFIT, "create")
        try:
            target = await self._tpsl_effect(
                trade,
                effect_id=target_effect,
                client_order_id=target_client_id,
                role=OrderRole.TAKE_PROFIT,
                price=trade.target_price,
            )
            target_id = self._required_text(target.get("id"), "target exchange ID")
            trade, target_created = await self._transition_with_event(
                decision,
                trade,
                TradeState.PROTECTING,
                journal_event_type="TARGET_EFFECT_CONFIRMED_PENDING_RECONCILIATION",
                public_event_type=TradeExecutionEventType.TARGET_CREATED,
                lifecycle_state=TradeLifecycleState.PROTECTING,
                target_client_order_id=target_client_id,
                target_exchange_order_id=target_id,
                effect_id=target_effect,
                order_role=OrderRole.TAKE_PROFIT,
                client_order_id=target_client_id,
                exchange_order_id=target_id,
                requested_quantity=trade.filled_quantity,
                position_quantity=trade.filled_quantity,
                details=(("reason", "pending_authoritative_reconciliation"),),
            )
            events.append(target_created)
            reconciled_target = await self.adapter.find_tpsl_record(
                symbol=trade.symbol,
                tpsl_id=target_id,
                tpsl_type="take-profit",
                price=trade.target_price,
                parent_order_id=None,
            )
            if reconciled_target is None:
                raise PaperExecutionSafetyError("created target was not authoritatively reconciled")
            self._validate_tpsl_record(
                reconciled_target,
                venue_symbol=decision.venue_symbol,
                side=trade.side,
                tpsl_type="TAKE_PROFIT",
                price=trade.target_price,
                parent_order_id=trade.entry_client_order_id,
                require_live=True,
                require_parent=False,
            )
            await self.effects.reconcile(
                target_effect,
                exchange_effect_id=target_id,
                response_payload=reconciled_target,
            )
            trade, target_reconciled = await self._transition_with_event(
                decision,
                trade,
                TradeState.ACTIVE,
                journal_event_type="TARGET_RECONCILED_POSITION_ACTIVE",
                public_event_type=TradeExecutionEventType.TARGET_RECONCILED,
                lifecycle_state=TradeLifecycleState.ACTIVE,
                target_client_order_id=target_client_id,
                target_exchange_order_id=target_id,
                effect_id=target_effect,
                order_role=OrderRole.TAKE_PROFIT,
                client_order_id=target_client_id,
                exchange_order_id=target_id,
                requested_quantity=trade.filled_quantity,
                position_quantity=trade.filled_quantity,
            )
            events.append(target_reconciled)
        except Exception as exc:
            events.extend(
                await self._emergency_close(decision, trade, f"target failed: {type(exc).__name__}")
            )
        return events

    async def _emergency_close(
        self, decision: RiskTradeDecisionV1, trade: TradeRecord, reason: str
    ) -> list[TradeExecutionEventV1]:
        trade, close_quantity, events = await self._cancel_entry_and_measure_position(decision, trade)
        if trade.state is not TradeState.EXITING_EMERGENCY:
            close_client_id = self._fresh_close_client_id(trade.trade_id, OrderRole.EMERGENCY_EXIT)
            trade, triggered = await self._transition_with_event(
                decision,
                trade,
                TradeState.EXITING_EMERGENCY,
                journal_event_type="EMERGENCY_CLOSE_REQUIRED",
                public_event_type=TradeExecutionEventType.EXIT_TRIGGERED,
                lifecycle_state=TradeLifecycleState.EXITING_EMERGENCY,
                event_payload={"reason": reason},
                close_client_order_id=close_client_id,
                effect_id=self._effect_id(trade.trade_id, OrderRole.EMERGENCY_EXIT, "close"),
                order_role=OrderRole.EMERGENCY_EXIT,
                client_order_id=close_client_id,
                requested_quantity=close_quantity,
                exit_reason=TradeExitReason.EMERGENCY,
                details=(("reason", reason),),
            )
            events.append(triggered)
        close_client_id = self._required_text(
            trade.close_client_order_id, "durable emergency close client ID"
        )
        effect_id = self._effect_id(trade.trade_id, OrderRole.EMERGENCY_EXIT, "close")
        response: dict[str, Any] = {}
        if close_quantity > 0:
            response = await self._close_effect(
                trade,
                effect_id=effect_id,
                client_order_id=close_client_id,
                leverage=decision.leverage,
                effect_type=EffectType.EMERGENCY_CLOSE,
                role=OrderRole.EMERGENCY_EXIT,
                quantity=close_quantity,
            )
        venue = await self.adapter.fetch_paper_state()
        if (
            self._position_quantity(venue, trade.symbol) > 0
            or self._find_order(venue, trade.entry_client_order_id) is not None
        ):
            _failed_trade, _failed = await self._transition_with_event(
                decision,
                trade,
                TradeState.FAILED_BLOCKED,
                journal_event_type="EMERGENCY_CLOSE_NOT_FLAT",
                public_event_type=TradeExecutionEventType.FAILED,
                lifecycle_state=TradeLifecycleState.FAILED_BLOCKED,
                event_payload={"reason": reason},
                close_client_order_id=close_client_id,
                close_exchange_order_id=str(response.get("id", close_client_id)),
                effect_id=effect_id if close_quantity > 0 else None,
                order_role=OrderRole.EMERGENCY_EXIT,
                client_order_id=close_client_id,
                exchange_order_id=str(response.get("id", close_client_id)),
                requested_quantity=close_quantity,
                position_quantity=self._position_quantity(venue, trade.symbol),
                exit_reason=TradeExitReason.EMERGENCY,
                details=(("reason", reason),),
            )
            raise PaperExecutionSafetyError("emergency close did not reconcile entry and position to FLAT")
        if close_quantity > 0:
            await self._assert_manual_close_won(
                trade,
                role=OrderRole.EMERGENCY_EXIT,
                response=response,
            )
        # Cleanup is part of reaching FLAT. Keeping EXITING_EMERGENCY durable
        # until every protection is proven terminal makes restart recovery
        # retry cleanup instead of forgetting an orphan TP/SL.
        await self._cancel_remaining_protection(trade)
        trade, closed = await self._transition_with_event(
            decision,
            trade,
            TradeState.FLAT,
            journal_event_type="EMERGENCY_CLOSE_RECONCILED_FLAT",
            public_event_type=TradeExecutionEventType.EMERGENCY_CLOSE,
            lifecycle_state=TradeLifecycleState.FLAT,
            close_client_order_id=close_client_id,
            close_exchange_order_id=str(response.get("id", close_client_id)),
            effect_id=effect_id if close_quantity > 0 else None,
            order_role=OrderRole.EMERGENCY_EXIT,
            client_order_id=close_client_id,
            exchange_order_id=str(response.get("id", close_client_id)),
            requested_quantity=close_quantity,
            public_filled_quantity=close_quantity,
            position_quantity=0,
            exit_reason=TradeExitReason.EMERGENCY,
            details=(("reason", reason),),
        )
        return [*events, closed]

    async def _prepare_entry_effect(
        self,
        decision: RiskTradeDecisionV1,
        trade: TradeRecord,
        *,
        effect_id: str,
        client_order_id: str,
    ) -> EffectPreparation:
        self._assert_fresh_entry_market(decision, int(self.clock().astimezone(UTC).timestamp() * 1000))
        request = {
            "trade_id": trade.trade_id,
            "intent_id": trade.strategy_intent_id,
            "client_order_id": client_order_id,
            "venue_symbol": decision.venue_symbol,
            "side": trade.side,
            "quantity_hex": float(decision.quantity).hex(),
            "limit_price_hex": float(decision.worst_entry_price).hex(),
            "leverage_hex": float(decision.leverage).hex(),
        }
        await self._assert_entry_admission(trade)
        return await self.effects.prepare(
            effect_key=effect_id,
            effect_type=EffectType.PLACE_ORDER,
            exchange=self.adapter.name,
            symbol=trade.symbol,
            client_order_id=client_order_id,
            request_payload=request,
            environment=trade.environment,
            account_id=trade.account_id,
            trade_id=trade.trade_id,
            order_role=OrderRole.ENTRY.value,
            recovery_delay=self._EFFECT_AMBIGUITY_GRACE,
        )

    async def _entry_effect(
        self,
        decision: RiskTradeDecisionV1,
        trade: TradeRecord,
        *,
        effect_id: str,
        client_order_id: str,
        preparation: EffectPreparation,
    ) -> dict[str, Any]:
        if preparation.effect.effect_key != effect_id:
            raise PaperExecutionSafetyError("prepared entry effect identity changed before mutation")
        cached = self._cached_effect(preparation.effect)
        if cached is not None:
            self._validate_entry_response(
                cached,
                decision=decision,
                client_order_id=client_order_id,
            )
            return cached
        if not preparation.created:
            raise PaperExecutionSafetyError("prepared entry requires authoritative recovery")
        # Do not let database latency turn an otherwise valid decision into a
        # mutation backed by stale EVEDEX book/basis/depth measurements.
        if not await self.trades.entries_allowed(
            environment=self._environment,
            account_id=self.settings.account_id,
            exchange=self.adapter.name,
        ):
            raise PaperExecutionSafetyError("durable account recovery revoked entry authority")
        # Re-run authenticated account/rule admission after PREPARED so a
        # rules/account change during the database write cannot reach EVEDEX.
        await self._assert_entry_admission(trade)
        self._assert_live_entry_book(
            decision,
            await self.adapter.fetch_depth(symbol=trade.symbol, max_level=100),
        )
        self._assert_fresh_entry_market(decision, int(self.clock().astimezone(UTC).timestamp() * 1000))
        await self._reserve_mutation(
            effect_id,
            operation="place_limit",
            compensation=False,
            require_entry_headroom=True,
        )
        response = await self.adapter.place_limit(
            effect_id=effect_id,
            client_order_id=client_order_id,
            symbol=trade.symbol,
            side=self._order_side(decision),
            quantity=decision.quantity,
            limit_price=decision.worst_entry_price,
            leverage=decision.leverage,
            post_only=False,
        )
        exchange_order_id, _, _, _ = self._validate_entry_response(
            response,
            decision=decision,
            client_order_id=client_order_id,
        )
        await self.effects.confirm(
            effect_id,
            exchange_effect_id=exchange_order_id,
            response_payload=response,
        )
        return response

    async def _assert_entry_admission(self, trade: TradeRecord) -> None:
        if not await self.trades.entries_allowed(
            environment=self._environment,
            account_id=self.settings.account_id,
            exchange=self.adapter.name,
        ):
            raise PaperExecutionSafetyError("durable account recovery revoked entry authority")
        await self._observe_health(await self.adapter.preflight(), require_entry=True)
        venue = await self.adapter.fetch_paper_state()
        durable = await self.trades.recovery_required(
            environment=self._environment,
            account_id=self.settings.account_id,
        )
        others = [candidate for candidate in durable if candidate.trade_id != trade.trade_id]
        blockers = self._authoritative_account_blockers(
            venue,
            durable,
            ignore_trade_id=trade.trade_id,
        )
        self._assert_technical_canary_instrument(self._decision_for_trade(trade), venue)
        if others:
            blockers.append("PAPER canary permits only one nonterminal trade globally")
        if blockers:
            raise PaperExecutionSafetyError("entry admission is not clean: " + "; ".join(blockers))

    def _assert_technical_canary_instrument(
        self, decision: RiskTradeDecisionV1, venue: dict[str, Any]
    ) -> None:
        """Recompute the fresh SDK rule and compare it byte-semantically.

        Risk binds the public DEV instrument rule into the immutable intent.
        Execution deliberately repeats that validation against the last
        authenticated SDK account projection.  A venue rule change invalidates
        the canary; quantity or exits are never rounded or rewritten here.
        """
        if not math.isclose(decision.leverage, 1.0, rel_tol=0.0, abs_tol=1e-12):
            raise PaperExecutionSafetyError("technical canary requires exactly 1x leverage")
        matches = [
            item
            for item in self._list(venue.get("instruments"))
            if str(item.get("name", "")).upper() == decision.venue_symbol.upper()
        ]
        if len(matches) != 1:
            raise PaperExecutionSafetyError("DEV instrument metadata is missing or duplicated")
        instrument = matches[0]
        if str(instrument.get("trading", "")).casefold() != "all":
            raise PaperExecutionSafetyError("technical canary instrument is not trading=all")
        if str(instrument.get("visibility", "")).casefold() != "all":
            raise PaperExecutionSafetyError("technical canary instrument is not visibility=all")
        if str(instrument.get("marketState", "")).upper() != "OPEN":
            raise PaperExecutionSafetyError("technical canary instrument marketState is not OPEN")
        current_decimals = {
            "venue_lot_size": self._positive_decimal(instrument.get("lotSize"), "lotSize"),
            "venue_price_increment": self._positive_decimal(
                instrument.get("priceIncrement"), "priceIncrement"
            ),
            "venue_quantity_increment": self._positive_decimal(
                instrument.get("quantityIncrement"), "quantityIncrement"
            ),
            "venue_multiplier": self._positive_decimal(instrument.get("multiplier"), "multiplier"),
            "venue_min_volume_usd": self._positive_decimal(instrument.get("minVolume"), "minVolume"),
            "venue_min_price": self._positive_decimal(instrument.get("minPrice"), "minPrice"),
            "venue_max_price": self._positive_decimal(instrument.get("maxPrice"), "maxPrice"),
            "venue_min_quantity": self._positive_decimal(instrument.get("minQuantity"), "minQuantity"),
            "venue_max_quantity": self._positive_decimal(instrument.get("maxQuantity"), "maxQuantity"),
        }
        current_rule: dict[str, object] = {
            "domain": _CANARY_RULE_DOMAIN,
            **{key: self._canonical_decimal(value) for key, value in current_decimals.items()},
            "venue_market_state": "OPEN",
            "venue_symbol": decision.venue_symbol,
            "venue_trading": "all",
            "venue_updated_at_ms": self._iso_timestamp_ms(
                instrument.get("updatedAt"), "instrument updatedAt"
            ),
        }
        metadata = dict(decision.intent.metadata)
        bound_rule: dict[str, object] = {
            "domain": _CANARY_RULE_DOMAIN,
            **{key: metadata[key] for key in _CANARY_RULE_DECIMAL_FIELDS},
            "venue_market_state": metadata["venue_market_state"],
            "venue_symbol": metadata["venue_symbol"],
            "venue_trading": metadata["venue_trading"],
            "venue_updated_at_ms": int(metadata["venue_updated_at_ms"]),
        }
        if current_rule != bound_rule:
            raise PaperExecutionSafetyError(
                "fresh EVEDEX DEV instrument rule differs from the Risk-bound canary rule"
            )
        current_hash = canonical_sha256(current_rule)
        if current_hash != metadata["instrument_rules_sha256"]:
            raise PaperExecutionSafetyError("fresh EVEDEX DEV instrument rule hash changed")

        price_increment = current_decimals["venue_price_increment"]
        quantity_increment = current_decimals["venue_quantity_increment"]
        min_quantity = current_decimals["venue_min_quantity"]
        max_quantity = current_decimals["venue_max_quantity"]
        min_volume = current_decimals["venue_min_volume_usd"]
        min_price = current_decimals["venue_min_price"]
        max_price = current_decimals["venue_max_price"]
        if current_decimals["venue_lot_size"] != 1 or current_decimals["venue_multiplier"] != 1:
            raise PaperExecutionSafetyError("technical canary supports only lotSize=1 and multiplier=1")
        if min_price >= max_price or min_quantity > max_quantity:
            raise PaperExecutionSafetyError("DEV instrument price/quantity bounds are incoherent")
        if min_price % price_increment != 0 or max_price % price_increment != 0:
            raise PaperExecutionSafetyError("DEV price bounds are not priceIncrement-quantized")
        entry_price = Decimal(str(decision.worst_entry_price))
        quantity = Decimal(str(decision.quantity))
        protected_prices = {
            "entry": entry_price,
            "stop": Decimal(str(decision.exit_plan.stop_price)),
            "target": Decimal(str(decision.exit_plan.target_price)),
        }
        for role, price in protected_prices.items():
            if price < min_price or price > max_price:
                raise PaperExecutionSafetyError(f"canary {role} price is outside DEV instrument bounds")
            if price % price_increment != 0:
                raise PaperExecutionSafetyError(f"canary {role} price is not priceIncrement-quantized")
        if min_quantity % quantity_increment != 0:
            raise PaperExecutionSafetyError("DEV quantity bounds are not increment-quantized")
        volume_quantity = (min_volume / entry_price / quantity_increment).to_integral_value(
            rounding=ROUND_CEILING
        ) * quantity_increment
        effective_minimum = max(min_quantity, volume_quantity)
        if quantity != effective_minimum or quantity % quantity_increment != 0:
            raise PaperExecutionSafetyError(
                "canary decision quantity is not the current effective DEV minimum"
            )
        if quantity > max_quantity:
            raise PaperExecutionSafetyError("canary decision quantity exceeds maxQuantity")
        self._operational_telemetry["evedex_canary_instrument_rules_sha256"] = current_hash
        self._operational_telemetry["evedex_canary_effective_min_quantity"] = self._canonical_decimal(
            effective_minimum
        )
        self._operational_telemetry["evedex_canary_instrument_updated_at_ms"] = str(
            current_rule["venue_updated_at_ms"]
        )

    def _assert_live_entry_book(
        self,
        decision: RiskTradeDecisionV1,
        depth: dict[str, Any],
    ) -> None:
        """Prove the canary IOC cap, executable depth and effective minimum now."""

        now_ms = int(self.clock().astimezone(UTC).timestamp() * 1000)
        timestamp = depth.get("t")
        if isinstance(timestamp, bool) or not isinstance(timestamp, int):
            raise PaperExecutionSafetyError("EVEDEX depth timestamp is malformed")
        if timestamp < decision.venue_quality.book_timestamp_ms:
            raise PaperExecutionSafetyError("EVEDEX depth projection predates the Risk-bound book")
        age_ms = now_ms - timestamp
        if age_ms < -2_000 or age_ms > 5_000:
            raise PaperExecutionSafetyError("EVEDEX depth is stale or has excessive timestamp skew")

        def levels(field: str) -> list[tuple[Decimal, Decimal]]:
            rows = self._list(depth.get(field))
            if not rows:
                raise PaperExecutionSafetyError(f"EVEDEX depth has no {field}")
            parsed: list[tuple[Decimal, Decimal]] = []
            for row in rows:
                parsed.append(
                    (
                        self._positive_decimal(row.get("price"), f"depth {field} price"),
                        self._positive_decimal(row.get("quantity"), f"depth {field} quantity"),
                    )
                )
            return parsed

        asks = levels("asks")
        bids = levels("bids")
        best_ask = min(price for price, _quantity in asks)
        best_bid = max(price for price, _quantity in bids)
        if best_bid >= best_ask:
            raise PaperExecutionSafetyError("EVEDEX depth is crossed")
        cap = Decimal(str(decision.worst_entry_price))
        if decision.intent.side is Side.LONG:
            marketable_price = best_ask
            executable = [(price, quantity) for price, quantity in asks if price <= cap]
            if cap < best_ask:
                raise PaperExecutionSafetyError("canary IOC BUY cap is no longer marketable")
        else:
            marketable_price = best_bid
            executable = [(price, quantity) for price, quantity in bids if price >= cap]
            if cap > best_bid:
                raise PaperExecutionSafetyError("canary IOC SELL cap is no longer marketable")
        executable_depth = sum(
            (price * quantity for price, quantity in executable),
            start=Decimal(0),
        )
        required_depth = Decimal(
            str(max(decision.notional_usd, decision.venue_quality.assessed_notional_usd))
        )
        if executable_depth < required_depth:
            raise PaperExecutionSafetyError("canary IOC has insufficient current executable depth")

        metadata = dict(decision.intent.metadata)
        increment = self._positive_decimal(metadata["venue_quantity_increment"], "venue_quantity_increment")
        min_quantity = self._positive_decimal(metadata["venue_min_quantity"], "venue_min_quantity")
        min_volume = self._positive_decimal(metadata["venue_min_volume_usd"], "venue_min_volume_usd")
        volume_quantity = (min_volume / marketable_price / increment).to_integral_value(
            rounding=ROUND_CEILING
        ) * increment
        current_effective_minimum = max(min_quantity, volume_quantity)
        if Decimal(str(decision.quantity)) != current_effective_minimum:
            raise PaperExecutionSafetyError(
                "canary quantity is not the effective minimum at the current marketable IOC price"
            )
        self._operational_telemetry["evedex_entry_book_age_ms"] = str(max(0, age_ms))
        self._operational_telemetry["evedex_entry_executable_depth_usd"] = self._canonical_decimal(
            executable_depth
        )
        self._operational_telemetry["evedex_entry_marketable_price"] = self._canonical_decimal(
            marketable_price
        )

    async def _tpsl_effect(
        self,
        trade: TradeRecord,
        *,
        effect_id: str,
        client_order_id: str,
        role: OrderRole,
        price: float,
    ) -> dict[str, Any]:
        tpsl_type = "STOP_LOSS" if role is OrderRole.STOP_LOSS else "TAKE_PROFIT"
        effect_type = EffectType.PROTECTIVE_STOP if role is OrderRole.STOP_LOSS else EffectType.TAKE_PROFIT
        request = {
            "trade_id": trade.trade_id,
            "client_order_id": client_order_id,
            "parent_order_id": trade.entry_client_order_id,
            "venue_symbol": self.settings.evedex_dev_symbol_map[trade.symbol],
            "side": trade.side,
            "tpsl_type": tpsl_type,
            "quantity_hex": float(0).hex(),
            "price_hex": float(price).hex(),
        }
        preparation = await self.effects.prepare(
            effect_key=effect_id,
            effect_type=effect_type,
            exchange=self.adapter.name,
            symbol=trade.symbol,
            client_order_id=client_order_id,
            request_payload=request,
            environment=trade.environment,
            account_id=trade.account_id,
            trade_id=trade.trade_id,
            order_role=role.value,
            recovery_delay=self._EFFECT_AMBIGUITY_GRACE,
        )
        cached = self._cached_effect(preparation.effect)
        if cached is not None:
            return cached
        if not preparation.created:
            raise PaperExecutionSafetyError(f"prepared {role.value} requires authoritative recovery")
        await self._reserve_mutation(
            effect_id,
            operation="create_tpsl",
            compensation=False,
        )
        response = await self.adapter.create_tpsl(
            effect_id=effect_id,
            symbol=trade.symbol,
            side=OrderSide(trade.side),
            tpsl_type=tpsl_type,
            quantity=0,
            price=price,
            parent_order_id=trade.entry_client_order_id,
        )
        await self.effects.confirm(
            effect_id,
            exchange_effect_id=self._required_text(response.get("id"), "TP/SL exchange ID"),
            response_payload=response,
        )
        return response

    async def _close_effect(
        self,
        trade: TradeRecord,
        *,
        effect_id: str,
        client_order_id: str,
        leverage: float,
        effect_type: EffectType,
        role: OrderRole,
        quantity: float,
    ) -> dict[str, Any]:
        if not math.isfinite(quantity) or quantity <= 0:
            raise PaperExecutionSafetyError("close effect quantity must be positive")
        request = {
            "trade_id": trade.trade_id,
            "client_order_id": client_order_id,
            "venue_symbol": self.settings.evedex_dev_symbol_map[trade.symbol],
            "quantity_hex": float(quantity).hex(),
            "leverage_hex": float(leverage).hex(),
        }
        preparation = await self.effects.prepare(
            effect_key=effect_id,
            effect_type=effect_type,
            exchange=self.adapter.name,
            symbol=trade.symbol,
            client_order_id=client_order_id,
            request_payload=request,
            environment=trade.environment,
            account_id=trade.account_id,
            trade_id=trade.trade_id,
            order_role=role.value,
            recovery_delay=self._EFFECT_AMBIGUITY_GRACE,
        )
        cached = self._cached_effect(preparation.effect)
        if cached is not None:
            self._validate_close_response(
                cached,
                client_order_id=client_order_id,
                requested_quantity=quantity,
            )
            return cached
        if not preparation.created:
            raise PaperExecutionSafetyError("prepared close requires authoritative recovery")
        await self._reserve_mutation(
            effect_id,
            operation="close_position",
            compensation=True,
        )
        response = await self.adapter.paper_close_position(
            effect_id=effect_id,
            client_order_id=client_order_id,
            symbol=trade.symbol,
            quantity=quantity,
            leverage=leverage,
        )
        exchange_order_id, _, _, _ = self._validate_close_response(
            response,
            client_order_id=client_order_id,
            requested_quantity=quantity,
        )
        await self.effects.confirm(
            effect_id,
            exchange_effect_id=exchange_order_id,
            response_payload=response,
        )
        return response

    async def _recover_effect_locked(self, effect: ExecutionEffect) -> None:
        """Re-check one recovery candidate under its cross-process effect lock."""
        async with self.effects.recovery_lock(effect.effect_key):
            current_effect = await self.effects.get(effect.effect_key)
            if current_effect is not None and current_effect.status in {
                EffectStatus.PREPARED,
                EffectStatus.FAILED,
            }:
                venue = await self.adapter.fetch_paper_state()
                await self._reconcile_effect(current_effect, venue)

    async def _unripe_effects(
        self,
        trade: TradeRecord,
        *,
        eligible_effect_keys: set[str],
    ) -> list[str]:
        """Return ambiguous effects that have not completed the venue grace window."""
        identities = (
            (OrderRole.ENTRY, "place"),
            (OrderRole.ENTRY, "cancel"),
            (OrderRole.STOP_LOSS, "create"),
            (OrderRole.STOP_LOSS, "cancel"),
            (OrderRole.TAKE_PROFIT, "create"),
            (OrderRole.TAKE_PROFIT, "cancel"),
            (OrderRole.TIMEOUT_EXIT, "close"),
            (OrderRole.EMERGENCY_EXIT, "close"),
        )
        unripe: list[str] = []
        for role, operation in identities:
            effect_key = self._effect_id(trade.trade_id, role, operation)
            effect = await self.effects.get(effect_key)
            if (
                effect is not None
                and effect.status in {EffectStatus.PREPARED, EffectStatus.FAILED}
                and effect_key not in eligible_effect_keys
            ):
                unripe.append(effect_key)
        return unripe

    async def _reconcile_effect(self, effect: ExecutionEffect, venue: dict[str, Any]) -> None:
        if effect.status is EffectStatus.FAILED:
            raise PaperExecutionSafetyError(effect.error or "effect is FAILED")
        if effect.effect_type is EffectType.PLACE_ORDER:
            active = self._find_order(venue, effect.client_order_id)
            historical = self._find_historical_order(venue, effect.client_order_id or "")
            quantity = self._position_quantity(venue, effect.symbol)
            if active is not None:
                await self._validate_recovered_entry_effect(effect, active)
                await self.effects.reconcile(
                    effect.effect_key,
                    exchange_effect_id=str(active.get("id", effect.client_order_id)),
                    response_payload=active,
                )
                return
            if historical is not None:
                await self._validate_recovered_entry_effect(effect, historical)
                await self.effects.reconcile(
                    effect.effect_key,
                    exchange_effect_id=str(historical.get("id", effect.client_order_id)),
                    response_payload=historical,
                )
                return
            if quantity <= 0:
                await self.effects.reconcile(
                    effect.effect_key,
                    exchange_effect_id=effect.client_order_id,
                    response_payload={"status": "CANCELED", "reconciled_absent_and_flat": True},
                )
                return
            raise PaperExecutionSafetyError("entry effect is absent but the position is non-flat")
        if effect.effect_type in {EffectType.PROTECTIVE_STOP, EffectType.TAKE_PROFIT}:
            request = effect.request_payload
            record = self._find_tpsl(
                venue,
                tpsl_type=str(request["tpsl_type"]),
                price=float.fromhex(str(request["price_hex"])),
                parent_order_id=str(request["parent_order_id"]),
            )
            if record is not None:
                position_open = self._position_quantity(venue, effect.symbol) > 0
                self._validate_tpsl_record(
                    record,
                    venue_symbol=self._required_text(request.get("venue_symbol"), "venue symbol"),
                    side=self._required_text(request.get("side"), "TP/SL side"),
                    tpsl_type=self._required_text(request.get("tpsl_type"), "TP/SL type"),
                    price=float.fromhex(str(request["price_hex"])),
                    parent_order_id=self._required_text(
                        request.get("parent_order_id"), "TP/SL parent order ID"
                    ),
                    require_live=position_open,
                )
                await self.effects.reconcile(
                    effect.effect_key,
                    exchange_effect_id=str(record["id"]),
                    response_payload=record,
                )
                if not position_open:
                    if effect.trade_id is None:
                        raise PaperExecutionSafetyError("orphan TP/SL recovery lacks durable trade lineage")
                    trade = await self.trades.get(effect.trade_id)
                    if trade is None:
                        raise PaperExecutionSafetyError("orphan TP/SL recovery references a missing trade")
                    await self._cancel_remaining_protection(trade)
                return
            if self._position_quantity(venue, effect.symbol) <= 0:
                raise PaperExecutionSafetyError(
                    "ambiguous TP/SL create is absent while flat; cancellation cannot be proven"
                )
            raise PaperExecutionSafetyError("prepared TP/SL is absent while position remains open")
        if effect.effect_type is EffectType.CANCEL_ORDER:
            if self._find_order(venue, effect.client_order_id) is None:
                await self.effects.reconcile(
                    effect.effect_key,
                    exchange_effect_id=effect.client_order_id,
                    response_payload={"active": False},
                )
                return
            raise PaperExecutionSafetyError("cancel effect has not removed the entry order")
        if effect.effect_type is EffectType.CANCEL_TPSL:
            tpsl_id = self._required_text(effect.request_payload.get("tpsl_id"), "TP/SL ID")
            record = self._find_tpsl_by_id(venue, tpsl_id)
            if record is not None:
                self._assert_known_tpsl_status(record)
            if record is None or not self._is_live_tpsl(record):
                await self.effects.reconcile(
                    effect.effect_key,
                    exchange_effect_id=tpsl_id,
                    response_payload={"active": False},
                )
                return
            raise PaperExecutionSafetyError("cancel TP/SL effect remains live")
        if effect.effect_type in {
            EffectType.CLOSE_POSITION,
            EffectType.TIMEOUT_CLOSE,
            EffectType.EMERGENCY_CLOSE,
        }:
            if self._position_quantity(venue, effect.symbol) <= 0:
                await self.effects.reconcile(
                    effect.effect_key,
                    exchange_effect_id=effect.client_order_id,
                    response_payload={"position_flat": True},
                )
                return
            raise PaperExecutionSafetyError("prepared exit has not reached a flat position")
        raise PaperExecutionSafetyError(f"{effect.effect_type.value} has no PAPER recovery rule")

    async def _validate_recovered_entry_effect(self, effect: ExecutionEffect, record: dict[str, Any]) -> None:
        if effect.trade_id is None or effect.client_order_id is None:
            raise PaperExecutionSafetyError("entry recovery lacks durable trade/order lineage")
        trade = await self.trades.get(effect.trade_id)
        if trade is None:
            raise PaperExecutionSafetyError("entry recovery references a missing durable trade")
        self._validate_entry_response(
            record,
            decision=self._decision_for_trade(trade),
            client_order_id=effect.client_order_id,
        )

    async def _reconcile_trade(
        self,
        trade: TradeRecord,
        venue: dict[str, Any],
        sidecar_events: tuple[dict[str, Any], ...],
    ) -> list[TradeExecutionEventV1]:
        """Converge one trade from authoritative state without guessing effects."""
        decision = self._decision_for_trade(trade)
        now = self.clock().astimezone(UTC)
        position_quantity = self._position_quantity_for_trade(venue, trade)
        entry = self._find_order(venue, trade.entry_client_order_id)
        events: list[TradeExecutionEventV1] = []
        if trade.state in {TradeState.RECEIVED, TradeState.ENTRY_PENDING}:
            events.extend(await self._recover_pre_mutation_gap(trade, venue))
            current = await self.trades.get(trade.trade_id)
            if current is None:
                raise PaperExecutionSafetyError("trade disappeared during lifecycle gap recovery")
            trade = current
            if trade.state in {TradeState.CANCELLED, TradeState.FLAT}:
                return events
        if entry is not None:
            self._validate_entry_response(
                entry,
                decision=decision,
                client_order_id=trade.entry_client_order_id,
            )

        if position_quantity > trade.quantity + max(1e-12, trade.quantity * 1e-9):
            if trade.state is TradeState.ENTRY_PENDING:
                trade, failed = await self._transition_with_event(
                    decision,
                    trade,
                    TradeState.PROTECTING,
                    journal_event_type="AUTHORITATIVE_POSITION_EXCEEDS_APPROVED_QUANTITY",
                    public_event_type=TradeExecutionEventType.FAILED,
                    lifecycle_state=TradeLifecycleState.PROTECTING,
                    event_payload={"observed_quantity_hex": float(position_quantity).hex()},
                    transition_filled_quantity=trade.quantity,
                    first_fill_at=trade.entry_eligible_at,
                    entry_exchange_order_id=trade.entry_client_order_id,
                    order_role=OrderRole.ENTRY,
                    client_order_id=trade.entry_client_order_id,
                    requested_quantity=trade.quantity,
                    public_filled_quantity=trade.quantity,
                    position_quantity=position_quantity,
                    details=(("reason", "authoritative_position_exceeds_approval"),),
                )
                events.append(failed)
            if trade.state in {TradeState.PROTECTING, TradeState.ACTIVE}:
                return await self._emergency_close(
                    decision,
                    trade,
                    "authoritative position exceeds approved quantity",
                )
            raise PaperExecutionSafetyError("authoritative position exceeds approved quantity")

        if trade.state is TradeState.ENTRY_PENDING:
            if position_quantity > 0:
                observed_fill = position_quantity
                fill_source = entry or self._find_historical_order(venue, trade.entry_client_order_id) or {}
                if fill_source:
                    self._validate_entry_response(
                        fill_source,
                        decision=decision,
                        client_order_id=trade.entry_client_order_id,
                    )
                average_price = self._positive_optional(fill_source.get("filledAvgPrice"))
                detail = self._execution_shortfall_details(decision, average_price)
                public_type = (
                    TradeExecutionEventType.ENTRY_FILLED
                    if math.isclose(observed_fill, trade.quantity, rel_tol=1e-9)
                    else TradeExecutionEventType.ENTRY_PARTIAL_FILL
                )
                trade, fill_event = await self._transition_with_event(
                    decision,
                    trade,
                    TradeState.PROTECTING,
                    journal_event_type="RECONCILED_FIRST_NONZERO_FILL",
                    public_event_type=public_type,
                    lifecycle_state=TradeLifecycleState.PROTECTING,
                    transition_filled_quantity=observed_fill,
                    first_fill_at=self._response_time(
                        fill_source,
                        fallback=trade.entry_eligible_at,
                        observed_at=now,
                        not_before=trade.entry_eligible_at,
                    ),
                    entry_exchange_order_id=str(fill_source.get("id", trade.entry_client_order_id)),
                    order_role=OrderRole.ENTRY,
                    client_order_id=trade.entry_client_order_id,
                    exchange_order_id=str(fill_source.get("id", trade.entry_client_order_id)),
                    requested_quantity=trade.quantity,
                    public_filled_quantity=observed_fill,
                    position_quantity=observed_fill,
                    average_price=average_price,
                    details=detail,
                )
                events.append(fill_event)
                events.extend(await self._protect(decision, trade))
                return events
            if entry is not None and now >= trade.entry_expires_at:
                await self._cancel_entry_effect(trade)
                venue = await self.adapter.fetch_paper_state()
                if self._find_order(venue, trade.entry_client_order_id) is not None:
                    raise PaperExecutionSafetyError("expired entry remains open after cancel")
                position_quantity = self._position_quantity(venue, trade.symbol)
                if position_quantity > 0:
                    return await self._reconcile_trade(trade, venue, sidecar_events)
                entry = None
            if entry is None:
                placement = await self.effects.get(self._effect_id(trade.trade_id, OrderRole.ENTRY, "place"))
                if (
                    placement is not None
                    and placement.response_payload is not None
                    and placement.response_payload.get("reconciled_absent_and_flat") is True
                ):
                    trade, cancelled = await self._transition_with_event(
                        decision,
                        trade,
                        TradeState.CANCELLED,
                        journal_event_type="ENTRY_EFFECT_RECONCILED_ABSENT_AND_FLAT",
                        public_event_type=TradeExecutionEventType.ENTRY_CANCELLED,
                        lifecycle_state=TradeLifecycleState.CANCELLED,
                        order_role=OrderRole.ENTRY,
                        client_order_id=trade.entry_client_order_id,
                        exchange_order_id=trade.entry_exchange_order_id,
                        requested_quantity=trade.quantity,
                        position_quantity=0,
                        details=(("reason", "prepared_entry_reconciled_absent_and_flat"),),
                    )
                    events.append(cancelled)
                    return events
                historical = self._find_historical_order(venue, trade.entry_client_order_id)
                if historical is None:
                    # Open-order absence is not terminal proof. The accepted
                    # IOC may be between venue projections and can still fill;
                    # keep it in recovery until exact order history appears.
                    await self.trades.mark_reconciled(
                        trade.trade_id,
                        "entry absent from open projection; awaiting exact terminal history",
                    )
                    return events
                _, historical_status, historical_fill, _ = self._validate_entry_response(
                    historical,
                    decision=decision,
                    client_order_id=trade.entry_client_order_id,
                )
                if historical_fill > 0:
                    raise PaperExecutionSafetyError(
                        "entry history reports a fill while authoritative position is flat"
                    )
                if historical_status not in {"CANCELED", "REJECTED", "EXPIRED", "REPLACED"}:
                    raise PaperExecutionSafetyError(
                        "entry is absent from open orders without an exact terminal outcome"
                    )
                trade, cancelled = await self._transition_with_event(
                    decision,
                    trade,
                    TradeState.CANCELLED,
                    journal_event_type="ENTRY_TERMINAL_HISTORY_AND_AUTHORITATIVELY_FLAT",
                    public_event_type=TradeExecutionEventType.ENTRY_CANCELLED,
                    lifecycle_state=TradeLifecycleState.CANCELLED,
                    order_role=OrderRole.ENTRY,
                    client_order_id=trade.entry_client_order_id,
                    exchange_order_id=trade.entry_exchange_order_id,
                    requested_quantity=trade.quantity,
                    position_quantity=0,
                    details=(("reason", "terminal_entry_history_and_flat"),),
                )
                events.append(cancelled)
                return events
            await self.trades.mark_reconciled(trade.trade_id, "entry pending before deterministic expiry")
            return events

        if trade.state is TradeState.PROTECTING:
            if position_quantity <= 0:
                triggered_exit = self._classify_flat_exit(trade, venue, sidecar_events)
                close_client_id = (
                    trade.stop_client_order_id
                    if triggered_exit.role is OrderRole.STOP_LOSS
                    else trade.target_client_order_id
                )
                trade, triggered = await self._transition_venue_exit(
                    decision, trade, triggered_exit, close_client_id
                )
                return [
                    triggered,
                    *(
                        await self._finish_venue_exit(
                            decision,
                            trade,
                            triggered_exit.role,
                            triggered_exit.reason,
                            attribution=triggered_exit,
                        )
                    ),
                ]
            trade, fill_events = await self._record_cumulative_fill(
                decision,
                trade,
                venue,
                position_quantity,
            )
            events.extend(fill_events)
            events.extend(await self._protect(decision, trade))
            return events

        if trade.state is TradeState.ACTIVE:
            if position_quantity > 0:
                trade, fill_events = await self._record_cumulative_fill(
                    decision,
                    trade,
                    venue,
                    position_quantity,
                )
                events.extend(fill_events)
            if entry is not None and now >= trade.entry_expires_at:
                await self._cancel_entry_effect(trade)
                venue = await self.adapter.fetch_paper_state()
                if self._find_order(venue, trade.entry_client_order_id) is not None:
                    raise PaperExecutionSafetyError("partial entry remainder survived expiry cancel")
                position_quantity = self._position_quantity_for_trade(venue, trade)
                if position_quantity > 0:
                    trade, fill_events = await self._record_cumulative_fill(
                        decision,
                        trade,
                        venue,
                        position_quantity,
                    )
                    events.extend(fill_events)
            if position_quantity <= 0:
                triggered_exit = self._classify_flat_exit(trade, venue, sidecar_events)
                close_client_id = (
                    trade.stop_client_order_id
                    if triggered_exit.role is OrderRole.STOP_LOSS
                    else trade.target_client_order_id
                )
                trade, triggered = await self._transition_venue_exit(
                    decision, trade, triggered_exit, close_client_id
                )
                return [
                    triggered,
                    *(
                        await self._finish_venue_exit(
                            decision,
                            trade,
                            triggered_exit.role,
                            triggered_exit.reason,
                            attribution=triggered_exit,
                        )
                    ),
                ]
            stop = self._find_tpsl_by_id(venue, trade.stop_exchange_order_id)
            target = self._find_tpsl_by_id(venue, trade.target_exchange_order_id)
            for record, role, tpsl_type, price in (
                (stop, OrderRole.STOP_LOSS, "STOP_LOSS", trade.stop_price),
                (target, OrderRole.TAKE_PROFIT, "TAKE_PROFIT", trade.target_price),
            ):
                if record is None:
                    raise PaperExecutionSafetyError(f"ACTIVE trade lacks a live reconciled {role.value}")
                self._validate_tpsl_record(
                    record,
                    venue_symbol=decision.venue_symbol,
                    side=trade.side,
                    tpsl_type=tpsl_type,
                    price=price,
                    parent_order_id=trade.entry_client_order_id,
                    require_live=True,
                    require_parent=False,
                )
            if trade.timeout_at is None:
                raise PaperExecutionSafetyError("ACTIVE trade has no durable timeout clock")
            if now >= trade.timeout_at:
                return [*events, *(await self._timeout_close(decision, trade))]
            await self.trades.mark_reconciled(
                trade.trade_id, "position, entry expiry, stop, target and timeout reconciled"
            )
            return events

        exit_facts = {
            TradeState.EXITING_STOP: (OrderRole.STOP_LOSS, TradeExitReason.STOP),
            TradeState.EXITING_TARGET: (OrderRole.TAKE_PROFIT, TradeExitReason.TARGET),
            TradeState.EXITING_TIMEOUT: (OrderRole.TIMEOUT_EXIT, TradeExitReason.TIMEOUT),
            TradeState.EXITING_EMERGENCY: (OrderRole.EMERGENCY_EXIT, TradeExitReason.EMERGENCY),
        }
        if trade.state in exit_facts:
            role, reason = exit_facts[trade.state]
            if position_quantity <= 0:
                return await self._finish_venue_exit(
                    decision,
                    trade,
                    role,
                    reason,
                    sidecar_events=sidecar_events,
                )
            if trade.state in {TradeState.EXITING_TIMEOUT, TradeState.EXITING_EMERGENCY}:
                return await self._resume_close_exit(decision, trade, role, reason)
            await self.trades.mark_reconciled(trade.trade_id, "venue-triggered exit is still settling")
            return events
        if trade.state is TradeState.FAILED_BLOCKED:
            raise PaperExecutionSafetyError("trade requires operator recovery")
        return events

    async def _record_cumulative_fill(
        self,
        decision: RiskTradeDecisionV1,
        trade: TradeRecord,
        venue: dict[str, Any],
        position_quantity: float,
    ) -> tuple[TradeRecord, list[TradeExecutionEventV1]]:
        """Advance durable filled quantity when an entry remainder fills later."""
        tolerance = max(1e-12, trade.quantity * 1e-9)
        if position_quantity < trade.filled_quantity - tolerance:
            raise PaperExecutionSafetyError(
                "position quantity decreased without a uniquely attributable exit"
            )
        if position_quantity <= trade.filled_quantity + tolerance:
            return trade, []
        fill_source = self._find_order(venue, trade.entry_client_order_id) or self._find_historical_order(
            venue, trade.entry_client_order_id
        )
        average_price = None
        if fill_source is not None:
            _, _, _, average_price = self._validate_entry_response(
                fill_source,
                decision=decision,
                client_order_id=trade.entry_client_order_id,
            )
        public_type = (
            TradeExecutionEventType.ENTRY_FILLED
            if math.isclose(position_quantity, trade.quantity, rel_tol=1e-9)
            else TradeExecutionEventType.ENTRY_PARTIAL_FILL
        )
        trade, event = await self._transition_with_event(
            decision,
            trade,
            trade.state,
            journal_event_type="RECONCILED_CUMULATIVE_ENTRY_FILL",
            public_event_type=public_type,
            lifecycle_state=TradeLifecycleState(trade.state.value),
            event_payload={"position_quantity_hex": float(position_quantity).hex()},
            transition_filled_quantity=position_quantity,
            order_role=OrderRole.ENTRY,
            client_order_id=trade.entry_client_order_id,
            exchange_order_id=trade.entry_exchange_order_id,
            requested_quantity=trade.quantity,
            public_filled_quantity=position_quantity,
            position_quantity=position_quantity,
            average_price=average_price,
            details=self._execution_shortfall_details(decision, average_price),
        )
        return trade, [event]

    async def _cancel_entry_effect(self, trade: TradeRecord) -> dict[str, Any]:
        effect_id = self._effect_id(trade.trade_id, OrderRole.ENTRY, "cancel")
        request = {
            "trade_id": trade.trade_id,
            "client_order_id": trade.entry_client_order_id,
            "venue_symbol": self.settings.evedex_dev_symbol_map[trade.symbol],
        }
        preparation = await self.effects.prepare(
            effect_key=effect_id,
            effect_type=EffectType.CANCEL_ORDER,
            exchange=self.adapter.name,
            symbol=trade.symbol,
            client_order_id=trade.entry_client_order_id,
            request_payload=request,
            environment=trade.environment,
            account_id=trade.account_id,
            trade_id=trade.trade_id,
            order_role=OrderRole.ENTRY.value,
            recovery_delay=self._EFFECT_AMBIGUITY_GRACE,
        )
        cached = self._cached_effect(preparation.effect)
        if cached is not None:
            return cached
        if not preparation.created:
            raise PaperExecutionSafetyError("prepared entry cancel requires authoritative recovery")
        await self._reserve_mutation(
            effect_id,
            operation="cancel_order",
            compensation=True,
        )
        response = await self.adapter.paper_cancel_order(
            effect_id=effect_id,
            symbol=trade.symbol,
            client_order_id=trade.entry_client_order_id,
        )
        await self.effects.confirm(
            effect_id,
            exchange_effect_id=trade.entry_client_order_id,
            response_payload=response,
        )
        return response

    async def _timeout_close(
        self, decision: RiskTradeDecisionV1, trade: TradeRecord
    ) -> list[TradeExecutionEventV1]:
        close_client_id = self._fresh_close_client_id(trade.trade_id, OrderRole.TIMEOUT_EXIT)
        trade, triggered = await self._transition_with_event(
            decision,
            trade,
            TradeState.EXITING_TIMEOUT,
            journal_event_type="TIMEOUT_WON_EXIT_RACE",
            public_event_type=TradeExecutionEventType.EXIT_TRIGGERED,
            lifecycle_state=TradeLifecycleState.EXITING_TIMEOUT,
            close_client_order_id=close_client_id,
            effect_id=self._effect_id(trade.trade_id, OrderRole.TIMEOUT_EXIT, "close"),
            order_role=OrderRole.TIMEOUT_EXIT,
            client_order_id=close_client_id,
            requested_quantity=trade.filled_quantity,
            exit_reason=TradeExitReason.TIMEOUT,
        )
        return [
            triggered,
            *(
                await self._resume_close_exit(
                    decision, trade, OrderRole.TIMEOUT_EXIT, TradeExitReason.TIMEOUT
                )
            ),
        ]

    async def _transition_venue_exit(
        self,
        decision: RiskTradeDecisionV1,
        trade: TradeRecord,
        attribution: _VenueTriggeredExit,
        client_id: str | None,
    ) -> tuple[TradeRecord, TradeExecutionEventV1]:
        if client_id is None:
            raise PaperExecutionSafetyError("triggered TP/SL lacks deterministic client lineage")
        return await self._transition_with_event(
            decision,
            trade,
            attribution.target_state,
            journal_event_type=f"{attribution.reason.value}_TRIGGER_RECONCILED",
            public_event_type=TradeExecutionEventType.EXIT_TRIGGERED,
            lifecycle_state=TradeLifecycleState(attribution.target_state.value),
            close_client_order_id=client_id,
            close_exchange_order_id=attribution.trigger_order_id,
            order_role=attribution.role,
            client_order_id=client_id,
            exchange_order_id=attribution.trigger_order_id,
            requested_quantity=trade.filled_quantity,
            public_filled_quantity=attribution.filled_quantity,
            position_quantity=0,
            average_price=attribution.average_price,
            fee_usd=attribution.fee_usd,
            exit_reason=attribution.reason,
            details=(("evedex_protection_id", attribution.protection_id),),
        )

    async def _resume_close_exit(
        self,
        decision: RiskTradeDecisionV1,
        trade: TradeRecord,
        role: OrderRole,
        reason: TradeExitReason,
    ) -> list[TradeExecutionEventV1]:
        trade, close_quantity, events = await self._cancel_entry_and_measure_position(decision, trade)
        if close_quantity <= 0:
            return [*events, *(await self._finish_venue_exit(decision, trade, role, reason))]
        close_client_id = self._required_text(trade.close_client_order_id, "durable close client order ID")
        effect_type = (
            EffectType.TIMEOUT_CLOSE if role is OrderRole.TIMEOUT_EXIT else EffectType.EMERGENCY_CLOSE
        )
        response = await self._close_effect(
            trade,
            effect_id=self._effect_id(trade.trade_id, role, "close"),
            client_order_id=close_client_id,
            leverage=decision.leverage,
            effect_type=effect_type,
            role=role,
            quantity=close_quantity,
        )
        venue = await self.adapter.fetch_paper_state()
        if (
            self._position_quantity(venue, trade.symbol) > 0
            or self._find_order(venue, trade.entry_client_order_id) is not None
        ):
            _failed_trade, failed = await self._transition_with_event(
                decision,
                trade,
                TradeState.FAILED_BLOCKED,
                journal_event_type=f"{reason.value}_CLOSE_NOT_FLAT",
                public_event_type=TradeExecutionEventType.FAILED,
                lifecycle_state=TradeLifecycleState.FAILED_BLOCKED,
                close_client_order_id=close_client_id,
                close_exchange_order_id=str(response.get("id", close_client_id)),
                effect_id=self._effect_id(trade.trade_id, role, "close"),
                order_role=role,
                client_order_id=close_client_id,
                exchange_order_id=str(response.get("id", close_client_id)),
                requested_quantity=close_quantity,
                position_quantity=self._position_quantity(venue, trade.symbol),
                exit_reason=reason,
                details=(("reason", f"{reason.value.lower()}_close_not_flat"),),
            )
            raise PaperExecutionSafetyError(
                f"{reason.value} close did not reconcile entry and position to FLAT; "
                f"failure fact {failed.event_id} is durable"
            )
        latest = await self.trades.get(trade.trade_id)
        if latest is None:
            raise PaperExecutionSafetyError("trade disappeared during close reconciliation")
        return [
            *events,
            *(await self._finish_venue_exit(decision, latest, role, reason, response=response)),
        ]

    async def _cancel_entry_and_measure_position(
        self,
        decision: RiskTradeDecisionV1,
        trade: TradeRecord,
    ) -> tuple[TradeRecord, float, list[TradeExecutionEventV1]]:
        """Cancel a fillable remainder before closing the net DEV position."""
        events: list[TradeExecutionEventV1] = []
        venue = await self.adapter.fetch_paper_state()
        if self._find_order(venue, trade.entry_client_order_id) is not None:
            await self._cancel_entry_effect(trade)
            venue = await self.adapter.fetch_paper_state()
            if self._find_order(venue, trade.entry_client_order_id) is not None:
                raise PaperExecutionSafetyError("entry remainder remains open before position close")
        position_quantity = self._position_quantity_for_trade(venue, trade)
        tolerance = max(1e-12, trade.quantity * 1e-9)
        if (
            position_quantity > trade.filled_quantity + tolerance
            and position_quantity <= trade.quantity + tolerance
            and trade.state in {TradeState.PROTECTING, TradeState.ACTIVE}
        ):
            public_type = (
                TradeExecutionEventType.ENTRY_FILLED
                if math.isclose(position_quantity, trade.quantity, rel_tol=1e-9)
                else TradeExecutionEventType.ENTRY_PARTIAL_FILL
            )
            trade, fill_event = await self._transition_with_event(
                decision,
                trade,
                trade.state,
                journal_event_type="CUMULATIVE_FILL_RECONCILED_BEFORE_CLOSE",
                public_event_type=public_type,
                lifecycle_state=TradeLifecycleState(trade.state.value),
                event_payload={"position_quantity_hex": float(position_quantity).hex()},
                transition_filled_quantity=min(position_quantity, trade.quantity),
                order_role=OrderRole.ENTRY,
                client_order_id=trade.entry_client_order_id,
                exchange_order_id=trade.entry_exchange_order_id,
                requested_quantity=trade.quantity,
                public_filled_quantity=min(position_quantity, trade.quantity),
                position_quantity=position_quantity,
                details=(("reason", "cumulative_fill_reconciled_before_close"),),
            )
            events.append(fill_event)
        return trade, position_quantity, events

    async def _finish_venue_exit(
        self,
        decision: RiskTradeDecisionV1,
        trade: TradeRecord,
        role: OrderRole,
        reason: TradeExitReason,
        *,
        response: dict[str, Any] | None = None,
        attribution: _VenueTriggeredExit | None = None,
        sidecar_events: tuple[dict[str, Any], ...] = (),
    ) -> list[TradeExecutionEventV1]:
        close_client_id = (
            trade.stop_client_order_id
            if role is OrderRole.STOP_LOSS
            else trade.target_client_order_id
            if role is OrderRole.TAKE_PROFIT
            else self._required_text(trade.close_client_order_id, "durable close client order ID")
        )
        if close_client_id is None:
            raise PaperExecutionSafetyError("exit role lacks deterministic client lineage")
        if role in {OrderRole.TIMEOUT_EXIT, OrderRole.EMERGENCY_EXIT}:
            await self._assert_manual_close_won(trade, role=role, response=response)
        if role in {OrderRole.STOP_LOSS, OrderRole.TAKE_PROFIT}:
            if attribution is None:
                venue = await self.adapter.fetch_paper_state()
                attribution = self._classify_flat_exit(trade, venue, sidecar_events)
            if attribution.role is not role or attribution.reason is not reason:
                raise PaperExecutionSafetyError("durable exit role differs from authoritative trigger")
            response = attribution.trigger_order
            exchange_id = attribution.trigger_order_id
        else:
            exchange_id = str((response or {}).get("id", close_client_id))
        completed_protection = role if role in {OrderRole.STOP_LOSS, OrderRole.TAKE_PROFIT} else None
        await self._cancel_remaining_protection(trade, completed_role=completed_protection)
        if trade.state is TradeState.FLAT:
            await self._recover_terminal_public_fact(trade)
            return []
        trade, completed = await self._transition_with_event(
            decision,
            trade,
            TradeState.FLAT,
            journal_event_type=f"{reason.value}_EXIT_RECONCILED_FLAT",
            public_event_type=(
                TradeExecutionEventType.EMERGENCY_CLOSE
                if reason is TradeExitReason.EMERGENCY
                else TradeExecutionEventType.EXIT_FILLED
            ),
            lifecycle_state=TradeLifecycleState.FLAT,
            close_client_order_id=close_client_id,
            close_exchange_order_id=exchange_id,
            order_role=role,
            client_order_id=close_client_id,
            exchange_order_id=exchange_id,
            requested_quantity=trade.filled_quantity,
            public_filled_quantity=trade.filled_quantity,
            position_quantity=0,
            average_price=(
                attribution.average_price
                if attribution is not None
                else self._positive_optional((response or {}).get("filledAvgPrice"))
            ),
            fee_usd=(
                attribution.fee_usd
                if attribution is not None
                else self._order_fee_usd(response or {}, required=False)
            ),
            exit_reason=reason,
            details=(() if attribution is None else (("evedex_protection_id", attribution.protection_id),)),
        )
        return [completed]

    async def _assert_manual_close_won(
        self,
        trade: TradeRecord,
        *,
        role: OrderRole,
        response: dict[str, Any] | None,
    ) -> None:
        """Prove a close fill, and reject a simultaneous TP/SL winner."""
        effect = await self.effects.get(self._effect_id(trade.trade_id, role, "close"))
        if effect is None:
            raise PaperExecutionSafetyError("flat position lacks a durable close effect")
        requested = float.fromhex(
            self._required_text(effect.request_payload.get("quantity_hex"), "close quantity")
        )
        close_client_id = self._required_text(trade.close_client_order_id, "durable close client order ID")
        venue = await self.adapter.fetch_paper_state()
        historical = self._find_historical_order(venue, close_client_id)
        close_record = historical or response or effect.response_payload
        if close_record is None:
            raise PaperExecutionSafetyError("flat position lacks exact close-order fill proof")
        _, status, filled, _ = self._validate_close_response(
            close_record,
            client_order_id=close_client_id,
            requested_quantity=requested,
        )
        tolerance = max(1e-12, requested * 1e-9)
        if status != "FILLED" or not math.isclose(filled, requested, rel_tol=1e-9, abs_tol=tolerance):
            raise PaperExecutionSafetyError("manual close did not authoritatively fill its full quantity")
        triggered_exit = self._proven_venue_trigger(trade, venue, ())
        if triggered_exit is not None:
            raise PaperExecutionSafetyError("manual close and TP/SL have competing terminal venue evidence")

    async def _cancel_remaining_protection(
        self,
        trade: TradeRecord,
        *,
        completed_role: OrderRole | None = None,
    ) -> None:
        venue = await self.adapter.fetch_paper_state()
        decision = self._decision_for_trade(trade)
        for role, persisted_id, persisted_client_id, tpsl_type, price in (
            (
                OrderRole.STOP_LOSS,
                trade.stop_exchange_order_id,
                trade.stop_client_order_id,
                "STOP_LOSS",
                trade.stop_price,
            ),
            (
                OrderRole.TAKE_PROFIT,
                trade.target_exchange_order_id,
                trade.target_client_order_id,
                "TAKE_PROFIT",
                trade.target_price,
            ),
        ):
            create_effect = await self.effects.get(self._effect_id(trade.trade_id, role, "create"))
            if create_effect is not None and (
                create_effect.trade_id != trade.trade_id
                or create_effect.account_id != trade.account_id
                or create_effect.environment != trade.environment
                or create_effect.order_role != role.value
            ):
                raise PaperExecutionSafetyError("TP/SL effect lineage is inconsistent")
            response_id = None
            if create_effect is not None and create_effect.response_payload is not None:
                raw_response_id = create_effect.response_payload.get("id")
                if raw_response_id is not None and str(raw_response_id).strip():
                    response_id = str(raw_response_id)
            geometry_record = self._find_tpsl(
                venue,
                tpsl_type=tpsl_type,
                price=price,
                parent_order_id=trade.entry_client_order_id,
            )
            if geometry_record is not None:
                self._validate_tpsl_record(
                    geometry_record,
                    venue_symbol=self.settings.evedex_dev_symbol_map[trade.symbol],
                    side=trade.side,
                    tpsl_type=tpsl_type,
                    price=price,
                    parent_order_id=trade.entry_client_order_id,
                    require_live=False,
                )
            geometry_id = (
                None
                if geometry_record is None
                else self._required_text(geometry_record.get("id"), "TP/SL exchange ID")
            )
            if (
                create_effect is not None
                and geometry_record is not None
                and create_effect.status in {EffectStatus.PREPARED, EffectStatus.FAILED}
            ):
                create_effect = await self.effects.reconcile(
                    create_effect.effect_key,
                    exchange_effect_id=geometry_id,
                    response_payload=geometry_record,
                )
            candidate_ids = {
                value
                for value in (
                    persisted_id,
                    None if create_effect is None else create_effect.exchange_effect_id,
                    response_id,
                    geometry_id,
                )
                if value is not None
            }
            if len(candidate_ids) > 1:
                raise PaperExecutionSafetyError("TP/SL cleanup found conflicting exchange identities")
            if not candidate_ids:
                if create_effect is not None:
                    raise PaperExecutionSafetyError(
                        "TP/SL create outcome is ambiguous and cancellation cannot be proven"
                    )
                continue
            tpsl_id = next(iter(candidate_ids))
            record = self._find_tpsl_by_id(venue, tpsl_id)
            if record is not None:
                self._validate_tpsl_record(
                    record,
                    venue_symbol=self.settings.evedex_dev_symbol_map[trade.symbol],
                    side=trade.side,
                    tpsl_type=tpsl_type,
                    price=price,
                    parent_order_id=trade.entry_client_order_id,
                    require_live=False,
                    require_parent=(
                        create_effect is None
                        or create_effect.status in {EffectStatus.PREPARED, EffectStatus.FAILED}
                    ),
                )
            if record is not None and not self._is_live_tpsl(record):
                continue
            # The just-triggered STOP/TARGET may already be absent from the
            # list; its terminal attribution was proven before this cleanup.
            if record is None and role is completed_role:
                continue
            if (
                record is None
                and create_effect is not None
                and create_effect.status is EffectStatus.RECONCILED
            ):
                # This protection was previously observed authoritatively. Its
                # later absence from the complete TP/SL list is terminal proof,
                # unlike a merely confirmed create whose follow-up read missed.
                continue
            client_id = persisted_client_id or (
                None if create_effect is None else create_effect.client_order_id
            )
            if client_id is None:
                client_id = self._client_id(trade.trade_id, role, decision.decided_at_ms)
            effect_id = self._effect_id(trade.trade_id, role, "cancel")
            request = {
                "trade_id": trade.trade_id,
                "client_order_id": client_id,
                "tpsl_id": tpsl_id,
                "venue_symbol": self.settings.evedex_dev_symbol_map[trade.symbol],
            }
            preparation = await self.effects.prepare(
                effect_key=effect_id,
                effect_type=EffectType.CANCEL_TPSL,
                exchange=self.adapter.name,
                symbol=trade.symbol,
                client_order_id=client_id,
                request_payload=request,
                environment=trade.environment,
                account_id=trade.account_id,
                trade_id=trade.trade_id,
                order_role=role.value,
                recovery_delay=self._EFFECT_AMBIGUITY_GRACE,
            )
            if self._cached_effect(preparation.effect) is not None:
                verified = await self.adapter.fetch_paper_state()
                if self._is_live_tpsl(self._find_tpsl_by_id(verified, tpsl_id)):
                    raise PaperExecutionSafetyError(
                        "confirmed TP/SL cancellation remains live authoritatively"
                    )
                continue
            if not preparation.created:
                raise PaperExecutionSafetyError("prepared TP/SL cancel requires recovery")
            await self._reserve_mutation(
                effect_id,
                operation="cancel_tpsl",
                compensation=True,
            )
            response = await self.adapter.cancel_tpsl(
                effect_id=effect_id,
                symbol=trade.symbol,
                tpsl_id=tpsl_id,
            )
            await self.effects.confirm(
                effect_id,
                exchange_effect_id=tpsl_id,
                response_payload=response,
            )
            verified = await self.adapter.fetch_paper_state()
            verified_record = self._find_tpsl_by_id(verified, tpsl_id)
            if self._is_live_tpsl(verified_record):
                raise PaperExecutionSafetyError("TP/SL cancellation did not reconcile to terminal")

    def _classify_flat_exit(
        self,
        trade: TradeRecord,
        venue: dict[str, Any],
        sidecar_events: tuple[dict[str, Any], ...],
    ) -> _VenueTriggeredExit:
        result = self._proven_venue_trigger(trade, venue, sidecar_events)
        if result is None:
            raise PaperExecutionSafetyError(
                "flat position cannot be attributed uniquely to a filled STOP or TARGET order"
            )
        return result

    def _proven_venue_trigger(
        self,
        trade: TradeRecord,
        venue: dict[str, Any],
        sidecar_events: tuple[dict[str, Any], ...],
    ) -> _VenueTriggeredExit | None:
        event_records = [
            payload
            for event in sidecar_events
            if str(event.get("type", "")).upper() == "TPSL"
            for payload in self._event_objects(event.get("payload"))
        ]
        proven: list[_VenueTriggeredExit] = []
        for role, protection_id, tpsl_type, price, reason, target_state in (
            (
                OrderRole.STOP_LOSS,
                trade.stop_exchange_order_id,
                "STOP_LOSS",
                trade.stop_price,
                TradeExitReason.STOP,
                TradeState.EXITING_STOP,
            ),
            (
                OrderRole.TAKE_PROFIT,
                trade.target_exchange_order_id,
                "TAKE_PROFIT",
                trade.target_price,
                TradeExitReason.TARGET,
                TradeState.EXITING_TARGET,
            ),
        ):
            if protection_id is None:
                continue
            authoritative = self._find_tpsl_by_id(venue, protection_id)
            supplemental = [record for record in event_records if str(record.get("id")) == protection_id]
            records = [authoritative] if authoritative is not None else supplemental
            if not records:
                continue
            terminal_records: list[dict[str, Any]] = []
            for record in records:
                self._validate_tpsl_record(
                    record,
                    venue_symbol=self.settings.evedex_dev_symbol_map[trade.symbol],
                    side=trade.side,
                    tpsl_type=tpsl_type,
                    price=price,
                    parent_order_id=trade.entry_client_order_id,
                    require_live=False,
                    require_parent=False,
                )
                if self._is_terminal_tpsl(record):
                    terminal_records.append(record)
                elif record.get("triggerOrder") not in {None, ""}:
                    raise PaperExecutionSafetyError(
                        "non-triggered TP/SL unexpectedly references a generated exit order"
                    )
            if not terminal_records:
                continue
            trigger_ids = {
                self._required_text(record.get("triggerOrder"), "triggered TP/SL exit order ID")
                for record in terminal_records
            }
            if len(trigger_ids) != 1:
                raise PaperExecutionSafetyError("TP/SL trigger projections disagree on exit order ID")
            triggered_quantities = {
                self._positive(record.get("triggeredQuantity"), "TP/SL triggeredQuantity")
                for record in terminal_records
            }
            if len(triggered_quantities) != 1:
                raise PaperExecutionSafetyError("TP/SL trigger projections disagree on quantity")
            triggered_quantity = next(iter(triggered_quantities))
            tolerance = max(1e-12, trade.filled_quantity * 1e-9)
            if not math.isclose(
                triggered_quantity,
                trade.filled_quantity,
                rel_tol=1e-9,
                abs_tol=tolerance,
            ):
                raise PaperExecutionSafetyError(
                    "triggered TP/SL quantity differs from durable filled exposure"
                )
            for record in terminal_records:
                cancelled_reason = record.get("cancelledReason")
                if not isinstance(cancelled_reason, str) or cancelled_reason:
                    raise PaperExecutionSafetyError(
                        "triggered TP/SL has a cancellation reason or malformed reason"
                    )
            trigger_order_id = next(iter(trigger_ids))
            trigger_order = self._find_historical_order(venue, trigger_order_id)
            if trigger_order is None:
                raise PaperExecutionSafetyError(
                    "triggered TP/SL lacks its generated order in complete order history"
                )
            filled, average_price, fee_usd = self._validate_trigger_exit_order(
                trade,
                trigger_order,
                trigger_order_id=trigger_order_id,
                triggered_quantity=triggered_quantity,
            )
            proven.append(
                _VenueTriggeredExit(
                    role=role,
                    reason=reason,
                    target_state=target_state,
                    protection_id=protection_id,
                    trigger_order_id=trigger_order_id,
                    trigger_order=trigger_order,
                    filled_quantity=filled,
                    average_price=average_price,
                    fee_usd=fee_usd,
                )
            )
        if len(proven) > 1:
            raise PaperExecutionSafetyError("STOP and TARGET both have authoritative fill evidence")
        return None if not proven else proven[0]

    def _validate_trigger_exit_order(
        self,
        trade: TradeRecord,
        order: dict[str, Any],
        *,
        trigger_order_id: str,
        triggered_quantity: float,
    ) -> tuple[float, float, float]:
        if self._required_text(order.get("id"), "trigger order ID") != trigger_order_id:
            raise PaperExecutionSafetyError("trigger order history changed the generated order ID")
        expected_symbol = self.settings.evedex_dev_symbol_map[trade.symbol]
        if str(order.get("instrument", "")).upper() != expected_symbol.upper():
            raise PaperExecutionSafetyError("trigger order has the wrong DEV instrument")
        expected_side = "SELL" if trade.side == "BUY" else "BUY"
        if str(order.get("side", "")).upper() != expected_side:
            raise PaperExecutionSafetyError("trigger order has the wrong closing side")
        if str(order.get("type", "")).upper() != "MARKET":
            raise PaperExecutionSafetyError("generated TP/SL exit order is not MARKET")
        group = order.get("group")
        if group is not None and str(group).casefold().replace("_", "-") not in {
            "tpsl",
            "tp-sl",
        }:
            raise PaperExecutionSafetyError("generated TP/SL exit order has the wrong order group")
        status = str(order.get("status", "")).upper().replace("CANCELLED", "CANCELED")
        if status != "FILLED":
            raise PaperExecutionSafetyError("generated TP/SL exit order is not FILLED")
        quantity = self._required_nonnegative_number(order, "quantity")
        remaining = self._required_nonnegative_number(order, "unFilledQuantity")
        tolerance = max(1e-12, triggered_quantity * 1e-9)
        if not math.isclose(quantity, triggered_quantity, rel_tol=1e-9, abs_tol=tolerance):
            raise PaperExecutionSafetyError("trigger order quantity differs from TP/SL evidence")
        if not math.isclose(remaining, 0.0, abs_tol=tolerance):
            raise PaperExecutionSafetyError("trigger order retains unfilled quantity")
        average_price = self._positive(order.get("filledAvgPrice"), "trigger fill average price")
        return quantity, average_price, self._order_fee_usd(order, required=True)

    @staticmethod
    def _event_objects(value: Any) -> list[dict[str, Any]]:
        if isinstance(value, dict):
            if isinstance(value.get("list"), list):
                return [item for item in value["list"] if isinstance(item, dict)]
            return [value]
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        return []

    @staticmethod
    def _is_live_tpsl(value: dict[str, Any] | None) -> bool:
        return value is not None and str(value.get("status", "")).casefold() in {
            "waitorder",
            "active",
        }

    @staticmethod
    def _is_terminal_tpsl(value: dict[str, Any]) -> bool:
        return str(value.get("status", "")).casefold() in {
            "process",
            "triggered",
            "done",
        }

    @staticmethod
    def _assert_known_tpsl_status(value: dict[str, Any]) -> None:
        status = str(value.get("status", "")).casefold()
        if status not in {
            "waitorder",
            "active",
            "process",
            "triggered",
            "done",
            "cancelled",
        }:
            raise PaperExecutionSafetyError("EVEDEX TP/SL has an unknown lifecycle status")

    @staticmethod
    def _find_historical_order(venue: dict[str, Any], client_id: str) -> dict[str, Any] | None:
        matches = [
            item
            for item in PaperExecutionEngine._list(venue.get("order_history"))
            if str(item.get("id")) == client_id
        ]
        if len(matches) > 1:
            raise PaperExecutionSafetyError("venue returned duplicate deterministic order history")
        return None if not matches else matches[0]

    def _decision_for_trade(self, trade: TradeRecord) -> RiskTradeDecisionV1:
        decision = RiskTradeDecisionV1.model_validate(trade.risk_decision_payload)
        self._validate_decision(decision)
        if (
            decision.trade_id != trade.trade_id
            or decision.decision_id != trade.risk_decision_id
            or decision.intent.intent_id != trade.strategy_intent_id
            or decision.intent.symbol != trade.symbol
        ):
            raise PaperExecutionSafetyError("durable trade lineage differs from RiskTradeDecisionV1")
        return decision

    def _event_spec(
        self,
        decision: RiskTradeDecisionV1,
        trade: TradeRecord | NewTrade,
        event_type: TradeExecutionEventType,
        lifecycle_state: TradeLifecycleState,
        *,
        effect_id: str | None = None,
        order_role: OrderRole | None = None,
        client_order_id: str | None = None,
        exchange_order_id: str | None = None,
        requested_quantity: float = 0,
        filled_quantity: float = 0,
        position_quantity: float | None = None,
        average_price: float | None = None,
        fee_usd: float = 0,
        exit_reason: TradeExitReason | None = None,
        details: tuple[tuple[str, str], ...] = (),
        default_position_quantity: float = 0,
    ) -> tuple[str, Callable[[int], TradeExecutionEventV1]]:
        effective_position = default_position_quantity if position_quantity is None else position_quantity
        identity = {
            "event_type": event_type.value,
            "lifecycle_state": lifecycle_state.value,
            "effect_id": effect_id,
            "order_role": None if order_role is None else order_role.value,
            "client_order_id": client_order_id,
            "exchange_order_id": exchange_order_id,
            "requested_quantity_hex": float(requested_quantity).hex(),
            "filled_quantity_hex": float(filled_quantity).hex(),
            "position_quantity_hex": float(effective_position).hex(),
            "average_price_hex": None if average_price is None else float(average_price).hex(),
            "fee_usd_hex": float(fee_usd).hex(),
            "exit_reason": None if exit_reason is None else exit_reason.value,
            "fact_details": details,
        }
        fingerprint = hashlib.sha256(
            json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        fact_key = f"paper.v1:{event_type.value}:{fingerprint}"
        occurred_at_ms = int(self.clock().astimezone(UTC).timestamp() * 1000)
        event_details = tuple((*details, *self.operational_telemetry))

        def build(sequence: int) -> TradeExecutionEventV1:
            return TradeExecutionEventV1(
                source=self.settings.service_name,
                event_seq=sequence,
                occurred_at_ms=occurred_at_ms,
                event_type=event_type,
                lifecycle_state=lifecycle_state,
                trading_mode=TradingMode.PAPER,
                evedex_profile=EvedexProfile.DEV,
                account_id=trade.account_id,
                venue_symbol=decision.venue_symbol,
                strategy_id=trade.strategy_id,
                strategy_revision=trade.strategy_revision,
                intent_id=trade.strategy_intent_id,
                risk_decision_id=self._required_text(decision.decision_id, "decision_id"),
                trade_id=trade.trade_id,
                effect_id=effect_id,
                order_role=order_role,
                client_order_id=client_order_id,
                exchange_order_id=exchange_order_id,
                requested_quantity=requested_quantity,
                filled_quantity=filled_quantity,
                position_quantity=effective_position,
                average_price=average_price,
                fee_usd=fee_usd,
                exit_reason=exit_reason,
                details=event_details,
            )

        return fact_key, build

    async def _create_trade_with_event(
        self,
        decision: RiskTradeDecisionV1,
        new_trade: NewTrade,
    ) -> tuple[TradeMutationResult, bool]:
        """Atomically create RECEIVED and its mandatory public fact/outbox."""

        existed = await self.trades.get(new_trade.trade_id)
        fact_key, build = self._event_spec(
            decision,
            new_trade,
            TradeExecutionEventType.DECISION_RECEIVED,
            TradeLifecycleState.RECEIVED,
            position_quantity=0,
        )
        if existed is not None:
            stored = await self.trades.get_execution_event(new_trade.trade_id, fact_key=fact_key)
            if stored is not None:

                def replay_creation(_sequence: int) -> TradeExecutionEventV1:
                    return stored

                build = replay_creation
        result = await self.trades.create_with_execution_event(
            new_trade,
            fact_key=fact_key,
            build=build,
        )
        return result, existed is None

    async def _transition_with_event(
        self,
        decision: RiskTradeDecisionV1,
        trade: TradeRecord,
        target: TradeState,
        *,
        journal_event_type: str,
        public_event_type: TradeExecutionEventType,
        lifecycle_state: TradeLifecycleState,
        event_payload: dict[str, Any] | None = None,
        transition_filled_quantity: float | None = None,
        first_fill_at: datetime | None = None,
        entry_exchange_order_id: str | None = None,
        stop_client_order_id: str | None = None,
        stop_exchange_order_id: str | None = None,
        target_client_order_id: str | None = None,
        target_exchange_order_id: str | None = None,
        close_client_order_id: str | None = None,
        close_exchange_order_id: str | None = None,
        effect_id: str | None = None,
        order_role: OrderRole | None = None,
        client_order_id: str | None = None,
        exchange_order_id: str | None = None,
        requested_quantity: float = 0,
        public_filled_quantity: float = 0,
        position_quantity: float | None = None,
        average_price: float | None = None,
        fee_usd: float = 0,
        exit_reason: TradeExitReason | None = None,
        details: tuple[tuple[str, str], ...] = (),
    ) -> tuple[TradeRecord, TradeExecutionEventV1]:
        """Atomically mutate the FSM/internal journal and append one public fact."""

        default_position = (
            trade.filled_quantity if transition_filled_quantity is None else transition_filled_quantity
        )
        fact_key, build = self._event_spec(
            decision,
            trade,
            public_event_type,
            lifecycle_state,
            effect_id=effect_id,
            order_role=order_role,
            client_order_id=client_order_id,
            exchange_order_id=exchange_order_id,
            requested_quantity=requested_quantity,
            filled_quantity=public_filled_quantity,
            position_quantity=position_quantity,
            average_price=average_price,
            fee_usd=fee_usd,
            exit_reason=exit_reason,
            details=details,
            default_position_quantity=default_position,
        )
        stored = await self.trades.get_execution_event(trade.trade_id, fact_key=fact_key)
        if stored is not None:

            def replay_transition(_sequence: int) -> TradeExecutionEventV1:
                return stored

            build = replay_transition
        result = await self.trades.transition_with_execution_event(
            trade.trade_id,
            target,
            event_type=journal_event_type,
            fact_key=fact_key,
            build=build,
            event_payload=event_payload,
            filled_quantity=transition_filled_quantity,
            first_fill_at=first_fill_at,
            entry_exchange_order_id=entry_exchange_order_id,
            stop_client_order_id=stop_client_order_id,
            stop_exchange_order_id=stop_exchange_order_id,
            target_client_order_id=target_client_order_id,
            target_exchange_order_id=target_exchange_order_id,
            close_client_order_id=close_client_order_id,
            close_exchange_order_id=close_exchange_order_id,
        )
        return result.trade, result.event

    def _accept_health(self, health: dict[str, Any]) -> None:
        expected = {
            "profile": "DEV",
            "chain_id": 16182,
            "exchange_url": "https://trading-api.evedex.tech",
            "auth_url": "https://auth-api.evedex.tech",
            "sdk_version": "1.2.11",
        }
        if any(health.get(key) != value for key, value in expected.items()):
            raise PaperExecutionSafetyError("sidecar health differs from the pinned EVEDEX DEV profile")
        age = self._telemetry_integer(health, "auth_age_ms")
        capacity = self._telemetry_integer(health, "local_mutation_rate_limit_capacity")
        reserve = self._telemetry_integer(health, "local_mutation_rate_limit_reserve")
        window = self._telemetry_integer(health, "local_mutation_rate_limit_window_ms")
        compensation_reserve = self._telemetry_integer(health, "local_mutation_compensation_reserve")
        entry_min_reserve = self._telemetry_integer(health, "local_mutation_entry_min_reserve")
        if (
            capacity <= 0
            or reserve > capacity
            or compensation_reserve >= capacity
            or entry_min_reserve <= compensation_reserve + 2
            or entry_min_reserve > capacity
            or window <= 0
        ):
            raise PaperExecutionSafetyError("sidecar mutation reserve telemetry is inconsistent")
        expires = health.get("auth_expires_in_ms")
        expires_text = "unknown" if expires is None else str(self._nonnegative_integer(expires))
        venue_observable = health.get("venue_rate_limit_observable")
        if not isinstance(venue_observable, bool):
            raise PaperExecutionSafetyError("venue rate-limit observability flag is malformed")
        venue_reserve = health.get("venue_rate_limit_reserve")
        if venue_observable and venue_reserve is None:
            raise PaperExecutionSafetyError("observable venue rate limit lacks a reserve value")
        venue_text = "unknown" if venue_reserve is None else str(self._nonnegative_integer(venue_reserve))
        self._operational_telemetry = {
            "evedex_auth_age_ms": str(age),
            "evedex_auth_expires_in_ms": expires_text,
            "evedex_local_mutation_reserve": str(reserve),
            "evedex_local_mutation_capacity": str(capacity),
            "evedex_local_mutation_window_ms": str(window),
            "evedex_local_mutation_compensation_reserve": str(compensation_reserve),
            "evedex_local_mutation_entry_min_reserve": str(entry_min_reserve),
            "evedex_venue_rate_limit_observable": str(venue_observable).lower(),
            "evedex_venue_rate_limit_reserve": venue_text,
        }

    async def _observe_health(self, health: dict[str, Any], *, require_entry: bool = False) -> None:
        if require_entry:
            self._accept_entry_health(health)
        else:
            self._accept_health(health)
        self._last_sidecar_health = dict(health)
        previous = await self.runtime_health.latest(**self._remote_account_scope)
        durable_reserve = 30 if previous is None else previous.local_mutation_reserve
        await self._record_runtime_health(health, durable_reserve=durable_reserve)

    async def _record_runtime_health(self, health: dict[str, Any], *, durable_reserve: int) -> None:
        expires = health.get("auth_expires_in_ms")
        venue_reserve = health.get("venue_rate_limit_reserve")
        await self.runtime_health.record(
            ExecutionRuntimeHealth(
                environment=self._remote_account_scope["environment"],
                account_id=self._remote_account_scope["account_id"],
                exchange=self._remote_account_scope["exchange"],
                observed_at=self.clock().astimezone(UTC),
                auth_age_ms=self._telemetry_integer(health, "auth_age_ms"),
                auth_expires_in_ms=(None if expires is None else self._nonnegative_integer(expires)),
                # The shared runtime row is account-scoped, so its mutation
                # values come from the durable cross-process ledger. Sidecar
                # process-local values remain available in event details.
                local_mutation_reserve=durable_reserve,
                local_mutation_capacity=30,
                local_mutation_compensation_reserve=4,
                local_mutation_window_ms=60_000,
                venue_rate_limit_observable=bool(health["venue_rate_limit_observable"]),
                venue_rate_limit_reserve=(
                    None if venue_reserve is None else self._nonnegative_integer(venue_reserve)
                ),
            )
        )

    async def _reserve_mutation(
        self,
        effect_id: str,
        *,
        operation: str,
        compensation: bool,
        require_entry_headroom: bool = False,
    ) -> None:
        reservation = await self.mutation_budget.reserve(
            environment=self._remote_account_scope["environment"],
            account_id=self._remote_account_scope["account_id"],
            exchange=self._remote_account_scope["exchange"],
            effect_id=effect_id,
            operation=operation,
            compensation=compensation,
        )
        # Persist the authoritative cross-process reserve even when admission
        # is denied or this is a replay that must reconcile instead of call.
        self._operational_telemetry["evedex_durable_mutation_reserve"] = str(reservation.remaining)
        self._operational_telemetry["evedex_durable_mutation_capacity"] = "30"
        self._operational_telemetry["evedex_durable_mutation_window_ms"] = "60000"
        self._operational_telemetry["evedex_durable_mutation_compensation_reserve"] = "4"
        if self._last_sidecar_health:
            await self._record_runtime_health(
                self._last_sidecar_health,
                durable_reserve=reservation.remaining,
            )
        if reservation.replay:
            raise PaperExecutionSafetyError(
                "durable mutation reservation already exists; venue state must be reconciled"
            )
        if not reservation.granted:
            raise PaperExecutionSafetyError("durable EVEDEX mutation budget is exhausted")
        if require_entry_headroom and reservation.remaining < 6:
            raise PaperExecutionSafetyError(
                "durable mutation budget cannot fund mandatory STOP/TARGET plus compensation"
            )

    def _accept_entry_health(self, health: dict[str, Any]) -> None:
        self._accept_health(health)
        reserve = self._telemetry_integer(health, "local_mutation_rate_limit_reserve")
        minimum = self._telemetry_integer(health, "local_mutation_entry_min_reserve")
        if reserve < minimum:
            raise PaperExecutionSafetyError(
                "sidecar mutation reserve cannot fund entry plus mandatory STOP/TARGET"
            )

    @classmethod
    def _telemetry_integer(cls, health: dict[str, Any], field: str) -> int:
        if field not in health:
            raise PaperExecutionSafetyError(f"sidecar health lacks {field}")
        return cls._nonnegative_integer(health[field])

    @staticmethod
    def _nonnegative_integer(value: Any) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise PaperExecutionSafetyError("sidecar telemetry must be a non-negative integer")
        return value

    @staticmethod
    def _execution_shortfall_details(
        decision: RiskTradeDecisionV1, average_price: float | None
    ) -> tuple[tuple[str, str], ...]:
        if average_price is None:
            return (("execution_shortfall_bps", "unknown"),)
        direction = 1.0 if decision.intent.side is Side.LONG else -1.0
        shortfall_bps = (
            (average_price - decision.worst_entry_price) / decision.worst_entry_price * 10_000 * direction
        )
        if not math.isfinite(shortfall_bps):
            raise PaperExecutionSafetyError("execution shortfall is non-finite")
        return (
            ("decision_worst_entry_price", format(decision.worst_entry_price, ".12g")),
            ("execution_average_price", format(average_price, ".12g")),
            ("execution_shortfall_bps", format(shortfall_bps, ".12g")),
        )

    def _validate_decision(self, decision: RiskTradeDecisionV1) -> None:
        if decision.trading_mode is not TradingMode.PAPER:
            raise PaperExecutionSafetyError("PAPER consumer rejects non-PAPER decisions")
        if decision.evedex_profile is not EvedexProfile.DEV:
            raise PaperExecutionSafetyError("PAPER consumer rejects non-DEV decisions")
        if decision.account_id != self.settings.account_id:
            raise PaperExecutionSafetyError("risk decision targets a different PAPER account")
        expected_symbol = self.settings.evedex_dev_symbol_map.get(decision.intent.symbol)
        if expected_symbol != decision.venue_symbol:
            raise PaperExecutionSafetyError("risk decision venue symbol is outside the DEV allowlist")
        if decision.intent.entry_eligible_ts_ms > decision.venue_quality.expires_at_ms:
            raise PaperExecutionSafetyError(
                "venue quality expires before NEXT_BAR_MARKET entry becomes eligible"
            )
        self._assert_technical_canary_binding(decision)

    def _assert_technical_canary_binding(self, decision: RiskTradeDecisionV1) -> None:
        """Allow mutations only for the exact deterministic manual canary."""

        intent = decision.intent
        review = decision.review
        route = review.route
        if not decision.approved or decision.rejection_reasons:
            raise PaperExecutionSafetyError("PAPER mutations require an approved canary decision")
        if decision.entry_policy is not EntryPolicy.NEXT_BAR_MARKET:
            raise PaperExecutionSafetyError("technical canary requires NEXT_BAR_MARKET policy")
        if intent.strategy_id != "technical-canary" or intent.strategy_revision != "1":
            raise PaperExecutionSafetyError("PAPER mutations are restricted to technical-canary@1")
        if {intent.source, route.source, review.source} != {_CANARY_SOURCE}:
            raise PaperExecutionSafetyError("technical canary requires dedicated source lineage")
        if intent.message_id != intent.intent_id or review.message_id != review.review_id:
            raise PaperExecutionSafetyError("technical canary message identities are not canonical")
        if (
            route.correlation_id != intent.intent_id
            or route.causation_id != intent.message_id
            or review.correlation_id != intent.intent_id
            or review.causation_id != route.message_id
        ):
            raise PaperExecutionSafetyError("technical canary route/review lineage is invalid")
        if route.intent.model_dump(mode="json") != intent.model_dump(mode="json"):
            raise PaperExecutionSafetyError("technical canary route changed its immutable intent")
        if (
            review.decision is not ReviewDecision.ALLOW
            or review.reviewer != "DETERMINISTIC"
            or review.model_provenance is not None
            or review.reason_codes != ("TECHNICAL_CANARY_MANUAL_POLICY",)
            or review.priority != 0
            or route.review_tier is not CandidateReviewTier.NORMAL
            or route.requested_reasoning_effort is not ReasoningEffort.MEDIUM
            or route.conflict_rationale is not None
        ):
            raise PaperExecutionSafetyError("technical canary deterministic review policy is not exact")
        if (
            route.routed_at_ms != intent.decision_ts_ms
            or route.review_deadline_ms != intent.entry_expires_ts_ms
            or review.reviewed_at_ms != intent.entry_eligible_ts_ms
        ):
            raise PaperExecutionSafetyError("technical canary route/review timing is not exact")
        if intent.signal_strength != 0.0:
            raise PaperExecutionSafetyError("technical canary must not claim alpha confidence")

        metadata = dict(intent.metadata)
        if set(metadata) != _CANARY_METADATA_KEYS:
            raise PaperExecutionSafetyError("technical canary metadata set is not exact")
        if (
            metadata["account_id"] != decision.account_id
            or metadata["alpha_claim"] != "false"
            or metadata["canary_entry_order"] != "MARKETABLE_IOC_LIMIT"
            or metadata["entry_policy"] != EntryPolicy.NEXT_BAR_MARKET.value
            or metadata["purpose"] != "technical_execution_canary"
            or metadata["venue_symbol"] != decision.venue_symbol
            or metadata["venue_trading"] != "all"
            or metadata["venue_market_state"] != "OPEN"
        ):
            raise PaperExecutionSafetyError("technical canary fixed policy metadata is invalid")
        try:
            updated_at_ms = int(metadata["venue_updated_at_ms"])
        except ValueError as exc:
            raise PaperExecutionSafetyError("venue_updated_at_ms is invalid") from exc
        if str(updated_at_ms) != metadata["venue_updated_at_ms"] or updated_at_ms < 0:
            raise PaperExecutionSafetyError("venue_updated_at_ms is not canonical")
        decimals: dict[str, Decimal] = {}
        for field in _CANARY_RULE_DECIMAL_FIELDS:
            value = self._positive_decimal(metadata[field], field)
            if self._canonical_decimal(value) != metadata[field]:
                raise PaperExecutionSafetyError(f"{field} is not canonical")
            decimals[field] = value
        if decimals["venue_lot_size"] != 1 or decimals["venue_multiplier"] != 1:
            raise PaperExecutionSafetyError("technical canary supports only lotSize=1 and multiplier=1")
        if decimals["venue_min_price"] >= decimals["venue_max_price"]:
            raise PaperExecutionSafetyError("technical canary price bounds are invalid")
        if decimals["venue_min_quantity"] > decimals["venue_max_quantity"]:
            raise PaperExecutionSafetyError("technical canary quantity bounds are invalid")
        if (
            decimals["venue_min_price"] % decimals["venue_price_increment"] != 0
            or decimals["venue_max_price"] % decimals["venue_price_increment"] != 0
            or decimals["venue_min_quantity"] % decimals["venue_quantity_increment"] != 0
        ):
            raise PaperExecutionSafetyError("technical canary bound instrument increments are invalid")
        rule_payload: dict[str, object] = {
            "domain": _CANARY_RULE_DOMAIN,
            **{key: metadata[key] for key in _CANARY_RULE_DECIMAL_FIELDS},
            "venue_market_state": metadata["venue_market_state"],
            "venue_symbol": metadata["venue_symbol"],
            "venue_trading": metadata["venue_trading"],
            "venue_updated_at_ms": updated_at_ms,
        }
        rules_sha256 = canonical_sha256(rule_payload)
        if metadata["instrument_rules_sha256"] != rules_sha256:
            raise PaperExecutionSafetyError("technical canary instrument rule hash is invalid")

        evidence_by_kind: dict[str, list[Any]] = {}
        for evidence in intent.evidence:
            evidence_by_kind.setdefault(evidence.kind, []).append(evidence)
        if set(evidence_by_kind) != {"closed_bar", "venue_instrument"} or any(
            len(items) != 1 for items in evidence_by_kind.values()
        ):
            raise PaperExecutionSafetyError("technical canary requires exactly two evidence kinds")
        bar = evidence_by_kind["closed_bar"][0]
        instrument = evidence_by_kind["venue_instrument"][0]
        input_bars = intent.provenance.input_bar_sha256s
        if (
            len(input_bars) != 1
            or bar.content_sha256 != input_bars[0]
            or bar.observed_at_ms != intent.decision_ts_ms
            or not bar.reference.startswith(f"BINANCE_UM:{intent.symbol}:")
            or instrument.content_sha256 != rules_sha256
            or instrument.observed_at_ms != updated_at_ms
            or instrument.reference != f"EVEDEX_DEV:{decision.venue_symbol}:{updated_at_ms}"
            or review.evidence != intent.evidence
            or route.evidence_ids != tuple(sorted((input_bars[0], rules_sha256)))
        ):
            raise PaperExecutionSafetyError("technical canary evidence binding is invalid")

        bound_quantity = self._positive_decimal(metadata["canary_quantity"], "canary_quantity")
        if self._canonical_decimal(bound_quantity) != metadata["canary_quantity"]:
            raise PaperExecutionSafetyError("technical canary quantity is not canonical")
        quantity = Decimal(str(decision.quantity))
        if quantity != bound_quantity:
            raise PaperExecutionSafetyError("Risk decision changed the bound canary quantity")
        price = Decimal(str(decision.worst_entry_price))
        if price < decimals["venue_min_price"] or price > decimals["venue_max_price"]:
            raise PaperExecutionSafetyError("canary entry price is outside bound instrument limits")
        if price % decimals["venue_price_increment"] != 0:
            raise PaperExecutionSafetyError("canary entry price is not bound-price quantized")
        volume_minimum = (
            decimals["venue_min_volume_usd"] / price / decimals["venue_quantity_increment"]
        ).to_integral_value(rounding=ROUND_CEILING) * decimals["venue_quantity_increment"]
        effective_minimum = max(decimals["venue_min_quantity"], volume_minimum)
        if (
            bound_quantity != effective_minimum
            or bound_quantity > decimals["venue_max_quantity"]
            or bound_quantity % decimals["venue_quantity_increment"] != 0
        ):
            raise PaperExecutionSafetyError(
                "technical canary quantity is not the Risk-bound effective venue minimum"
            )

    @staticmethod
    def _assert_fresh_entry_market(decision: RiskTradeDecisionV1, now_ms: int) -> None:
        if now_ms > decision.intent.entry_expires_ts_ms:
            raise PaperExecutionSafetyError("entry deadline expired before venue mutation")
        if now_ms > decision.venue_quality.expires_at_ms:
            raise PaperExecutionSafetyError("EVEDEX venue quality expired before venue mutation")

    @property
    def _environment(self) -> str:
        return f"{self.settings.environment}:EVEDEX:DEV:PAPER"

    @property
    def _remote_account_scope(self) -> dict[str, str]:
        return {
            "environment": "evedex-dev",
            "account_id": self._required_text(
                self.settings.evedex_dev_expected_account_id,
                "expected EVEDEX DEV account ID",
            ),
            "exchange": self.adapter.name,
        }

    @staticmethod
    def _order_side(decision: RiskTradeDecisionV1) -> OrderSide:
        return OrderSide.BUY if decision.intent.side is Side.LONG else OrderSide.SELL

    @staticmethod
    def _effect_id(trade_id: str, role: OrderRole, operation: str) -> str:
        return hashlib.sha256(f"paper.v1:{trade_id}:{role.value}:{operation}".encode()).hexdigest()

    @staticmethod
    def _client_id(trade_id: str, role: OrderRole, decided_at_ms: int) -> str:
        return client_order_id(
            f"{trade_id}:{role.value}",
            "evedex",
            occurred_at=datetime.fromtimestamp(decided_at_ms / 1000, tz=UTC),
        )

    def _fresh_close_client_id(self, trade_id: str, role: OrderRole) -> str:
        now_ms = int(self.clock().astimezone(UTC).timestamp() * 1000)
        return self._client_id(trade_id, role, now_ms)

    @staticmethod
    def _cached_effect(effect: ExecutionEffect) -> dict[str, Any] | None:
        if effect.status not in {EffectStatus.CONFIRMED, EffectStatus.RECONCILED}:
            return None
        if effect.response_payload is None:
            raise PaperExecutionSafetyError(f"effect {effect.effect_key} has no response payload")
        return effect.response_payload

    @classmethod
    def _validate_entry_response(
        cls,
        response: dict[str, Any],
        *,
        decision: RiskTradeDecisionV1,
        client_order_id: str,
    ) -> tuple[str, str, float, float | None]:
        """Validate a mutation ACK without inventing missing fill fields."""
        exchange_order_id = cls._required_text(response.get("id"), "entry exchange order ID")
        if exchange_order_id != client_order_id:
            raise PaperExecutionSafetyError("entry ACK changed the deterministic client order ID")
        if str(response.get("instrument", "")).upper() != decision.venue_symbol.upper():
            raise PaperExecutionSafetyError("entry ACK has the wrong DEV instrument")
        if str(response.get("side", "")).upper() != cls._order_side(decision).value:
            raise PaperExecutionSafetyError("entry ACK has the wrong side")
        if str(response.get("type", "")).upper() != "LIMIT":
            raise PaperExecutionSafetyError("technical canary entry ACK is not an IOC LIMIT")
        limit_price = cls._positive(response.get("limitPrice"), "entry ACK limit price")
        if not math.isclose(
            limit_price,
            decision.worst_entry_price,
            rel_tol=1e-9,
            abs_tol=max(1e-12, decision.worst_entry_price * 1e-9),
        ):
            raise PaperExecutionSafetyError("entry ACK changed the capped canary price")
        status = str(response.get("status", "")).upper().replace("CANCELLED", "CANCELED")
        allowed_statuses = {
            "NEW",
            "PARTIALLY_FILLED",
            "FILLED",
            "CANCELED",
            "REJECTED",
            "EXPIRED",
            "REPLACED",
        }
        if status not in allowed_statuses:
            raise PaperExecutionSafetyError("entry ACK has an unknown status")
        quantity = cls._required_nonnegative_number(response, "quantity")
        remaining = cls._required_nonnegative_number(response, "unFilledQuantity")
        tolerance = max(1e-12, decision.quantity * 1e-9)
        if not math.isclose(quantity, decision.quantity, rel_tol=1e-9, abs_tol=tolerance):
            raise PaperExecutionSafetyError(
                "IOC LIMIT quantity differs from the exact approved canary quantity"
            )
        if status == "NEW":
            if not math.isclose(remaining, quantity, rel_tol=1e-9, abs_tol=tolerance):
                raise PaperExecutionSafetyError("NEW entry ACK reports an incoherent fill")
            filled = 0.0
        else:
            if quantity <= 0:
                if status not in {"CANCELED", "REJECTED", "EXPIRED", "REPLACED"}:
                    raise PaperExecutionSafetyError("filled entry ACK has no executed quantity")
                filled = 0.0
            else:
                if remaining > quantity + tolerance:
                    raise PaperExecutionSafetyError("entry ACK remaining quantity exceeds quantity")
                filled = max(0.0, quantity - remaining)
            if status == "PARTIALLY_FILLED" and not (filled > tolerance and remaining > tolerance):
                raise PaperExecutionSafetyError("PARTIALLY_FILLED entry ACK is incoherent")
            if status == "FILLED" and (
                filled <= tolerance or not math.isclose(remaining, 0.0, abs_tol=tolerance)
            ):
                raise PaperExecutionSafetyError("FILLED entry ACK is incoherent")
        if filled > decision.quantity + tolerance:
            raise PaperExecutionSafetyError("venue fill exceeds approved quantity")
        average_price = cls._positive_optional(response.get("filledAvgPrice"))
        if filled > tolerance and average_price is None:
            raise PaperExecutionSafetyError("non-zero entry fill lacks an average price")
        if average_price is not None:
            price_tolerance = max(1e-12, decision.worst_entry_price * 1e-9)
            if decision.intent.side is Side.LONG and average_price > (
                decision.worst_entry_price + price_tolerance
            ):
                raise PaperExecutionSafetyError("LONG IOC fill breached the Risk-approved price cap")
            if decision.intent.side is Side.SHORT and average_price < (
                decision.worst_entry_price - price_tolerance
            ):
                raise PaperExecutionSafetyError("SHORT IOC fill breached the Risk-approved price cap")
        return exchange_order_id, status, min(decision.quantity, filled), average_price

    @classmethod
    def _validate_close_response(
        cls,
        response: dict[str, Any],
        *,
        client_order_id: str,
        requested_quantity: float,
    ) -> tuple[str, str, float, float | None]:
        exchange_order_id = cls._required_text(response.get("id"), "close exchange order ID")
        if exchange_order_id != client_order_id:
            raise PaperExecutionSafetyError("close ACK changed the deterministic client order ID")
        status = str(response.get("status", "")).upper().replace("CANCELLED", "CANCELED")
        if status not in {"NEW", "PARTIALLY_FILLED", "FILLED", "CANCELED", "REJECTED"}:
            raise PaperExecutionSafetyError("close ACK has an unknown status")
        quantity = cls._required_nonnegative_number(response, "quantity")
        remaining = cls._required_nonnegative_number(response, "unFilledQuantity")
        tolerance = max(1e-12, requested_quantity * 1e-9)
        if not math.isclose(quantity, requested_quantity, rel_tol=1e-9, abs_tol=tolerance):
            raise PaperExecutionSafetyError("close ACK quantity differs from authoritative exposure")
        if remaining > quantity + tolerance:
            raise PaperExecutionSafetyError("close ACK remaining quantity exceeds quantity")
        filled = max(0.0, quantity - remaining)
        if status == "NEW" and not math.isclose(remaining, quantity, rel_tol=1e-9, abs_tol=tolerance):
            raise PaperExecutionSafetyError("NEW close ACK reports an incoherent fill")
        if status == "PARTIALLY_FILLED" and not (filled > tolerance and remaining > tolerance):
            raise PaperExecutionSafetyError("PARTIALLY_FILLED close ACK is incoherent")
        if status == "FILLED" and not math.isclose(remaining, 0.0, abs_tol=tolerance):
            raise PaperExecutionSafetyError("FILLED close ACK is incoherent")
        average_price = cls._positive_optional(response.get("filledAvgPrice"))
        if filled > tolerance and average_price is None:
            raise PaperExecutionSafetyError("non-zero close fill lacks an average price")
        return exchange_order_id, status, filled, average_price

    @classmethod
    def _response_time(
        cls,
        response: dict[str, Any],
        *,
        fallback: datetime,
        observed_at: datetime,
        not_before: datetime,
    ) -> datetime:
        observed = observed_at.astimezone(UTC)
        lower_bound = not_before.astimezone(UTC) - cls._VENUE_TIMESTAMP_SKEW
        candidates: list[datetime] = []
        for key in ("updatedAt", "createdAt"):
            value = response.get(key)
            if isinstance(value, str):
                try:
                    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                except ValueError:
                    continue
                if parsed.tzinfo is not None:
                    parsed = parsed.astimezone(UTC)
                    if parsed > observed + cls._VENUE_TIMESTAMP_SKEW:
                        raise PaperExecutionSafetyError("venue fill timestamp is in the future")
                    if parsed < lower_bound:
                        raise PaperExecutionSafetyError("venue fill timestamp predates entry eligibility")
                    candidates.append(min(parsed, observed))
        conservative = fallback.astimezone(UTC)
        if conservative > observed:
            conservative = observed
        if conservative < lower_bound:
            conservative = not_before.astimezone(UTC)
        return min([conservative, *candidates])

    @classmethod
    def _required_nonnegative_number(cls, value: dict[str, Any], field: str) -> float:
        if field not in value or value[field] is None or isinstance(value[field], bool):
            raise PaperExecutionSafetyError(f"venue ACK lacks explicit {field}")
        return cls._finite(value[field])

    @classmethod
    def _order_fee_usd(cls, order: dict[str, Any], *, required: bool) -> float:
        raw = order.get("fee")
        if raw is None:
            if required:
                raise PaperExecutionSafetyError("filled trigger order lacks explicit fee evidence")
            return 0.0
        if not isinstance(raw, list) or not all(isinstance(item, dict) for item in raw):
            raise PaperExecutionSafetyError("venue order fee list is malformed")
        total = 0.0
        for item in raw:
            coin = cls._required_text(item.get("coin"), "fee coin").upper()
            if coin not in {"USD", "USDT", "USDC"}:
                raise PaperExecutionSafetyError("trigger fee is not denominated in a USD stablecoin")
            total += cls._required_nonnegative_number(item, "quantity")
        if not math.isfinite(total):
            raise PaperExecutionSafetyError("venue order fee is non-finite")
        return total

    @classmethod
    def _required_position_unrealized(cls, position: dict[str, Any]) -> float:
        for field in ("unRealizedPnL", "unrealizedPnL"):
            if field in position and position[field] is not None:
                return cls._signed_finite(position[field])
        raise PaperExecutionSafetyError("venue position lacks explicit unrealized PnL")

    @staticmethod
    def _positive_decimal(value: Any, field: str) -> Decimal:
        if isinstance(value, bool) or value is None:
            raise PaperExecutionSafetyError(f"{field} must be a finite positive decimal")
        try:
            parsed = Decimal(str(value))
        except (InvalidOperation, ValueError) as exc:
            raise PaperExecutionSafetyError(f"{field} must be a finite positive decimal") from exc
        if not parsed.is_finite() or parsed <= 0:
            raise PaperExecutionSafetyError(f"{field} must be a finite positive decimal")
        return parsed

    @staticmethod
    def _canonical_decimal(value: Decimal) -> str:
        if not value.is_finite():
            raise PaperExecutionSafetyError("instrument decimal must be finite")
        text = format(value, "f")
        if "." in text:
            text = text.rstrip("0").rstrip(".")
        return "0" if text in {"", "-0"} else text

    @staticmethod
    def _iso_timestamp_ms(value: Any, field: str) -> int:
        if not isinstance(value, str) or not value:
            raise PaperExecutionSafetyError(f"{field} must be a non-empty ISO-8601 timestamp")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise PaperExecutionSafetyError(f"{field} must be a valid ISO-8601 timestamp") from exc
        if parsed.utcoffset() is None:
            raise PaperExecutionSafetyError(f"{field} must be timezone-aware")
        return int(parsed.astimezone(UTC).timestamp() * 1_000)

    def _position_quantity(self, venue: dict[str, Any], logical_symbol: str) -> float:
        expected = self.settings.evedex_dev_symbol_map[logical_symbol]
        return sum(
            self._required_nonnegative_number(item, "quantity")
            for item in self._list(venue.get("positions"))
            if str(item.get("instrument", "")).upper() == expected
        )

    def _position_quantity_for_trade(self, venue: dict[str, Any], trade: TradeRecord) -> float:
        expected = self.settings.evedex_dev_symbol_map[trade.symbol]
        matches = [
            item
            for item in self._list(venue.get("positions"))
            if str(item.get("instrument", "")).upper() == expected
            and self._required_nonnegative_number(item, "quantity") > 0
        ]
        if len(matches) > 1:
            raise PaperExecutionSafetyError("venue returned duplicate positions for one symbol")
        if not matches:
            return 0.0
        if str(matches[0].get("side", "")).upper() != trade.side:
            raise PaperExecutionSafetyError("venue position side differs from durable trade lineage")
        leverage = self._positive(matches[0].get("leverage"), "position leverage")
        if not math.isclose(
            leverage,
            trade.leverage,
            rel_tol=1e-9,
            abs_tol=max(1e-12, trade.leverage * 1e-9),
        ):
            raise PaperExecutionSafetyError("venue position leverage differs from durable approval")
        return self._required_nonnegative_number(matches[0], "quantity")

    @staticmethod
    def _find_order(venue: dict[str, Any], client_id: str | None) -> dict[str, Any] | None:
        if client_id is None:
            return None
        matches = [
            item
            for item in PaperExecutionEngine._list(venue.get("orders"))
            if str(item.get("id")) == client_id
        ]
        if len(matches) > 1:
            raise PaperExecutionSafetyError("venue returned duplicate deterministic order IDs")
        return None if not matches else matches[0]

    @staticmethod
    def _find_tpsl_by_id(venue: dict[str, Any], exchange_id: str | None) -> dict[str, Any] | None:
        if exchange_id is None:
            return None
        matches = [
            item
            for item in PaperExecutionEngine._list(venue.get("tpsl"))
            if str(item.get("id")) == exchange_id
        ]
        if len(matches) > 1:
            raise PaperExecutionSafetyError("venue returned duplicate TP/SL IDs")
        return None if not matches else matches[0]

    @staticmethod
    def _find_tpsl(
        venue: dict[str, Any], *, tpsl_type: str, price: float, parent_order_id: str
    ) -> dict[str, Any] | None:
        expected_type = tpsl_type.casefold().replace("_", "-")
        matches = [
            item
            for item in PaperExecutionEngine._list(venue.get("tpsl"))
            if str(item.get("type", "")).casefold() == expected_type
            and math.isclose(PaperExecutionEngine._finite(item.get("price")), price, rel_tol=1e-9)
            and str(item.get("order", "")) == parent_order_id
        ]
        if len(matches) > 1:
            raise PaperExecutionSafetyError("venue returned ambiguous TP/SL geometry")
        return None if not matches else matches[0]

    @classmethod
    def _validate_tpsl_record(
        cls,
        record: dict[str, Any],
        *,
        venue_symbol: str,
        side: str,
        tpsl_type: str,
        price: float,
        parent_order_id: str,
        require_live: bool,
        require_parent: bool = True,
    ) -> None:
        if str(record.get("instrument", "")).upper() != venue_symbol.upper():
            raise PaperExecutionSafetyError("reconciled TP/SL has the wrong DEV instrument")
        expected_type = tpsl_type.casefold().replace("_", "-")
        if str(record.get("type", "")).casefold().replace("_", "-") != expected_type:
            raise PaperExecutionSafetyError("reconciled TP/SL has the wrong lifecycle role")
        if str(record.get("side", "")).upper() != side.upper():
            raise PaperExecutionSafetyError("reconciled TP/SL has the wrong position side")
        if not math.isclose(cls._required_nonnegative_number(record, "quantity"), 0.0, abs_tol=1e-12):
            raise PaperExecutionSafetyError("reconciled TP/SL does not protect the full position")
        reconciled_price = cls._positive(record.get("price"), "TP/SL price")
        if not math.isclose(reconciled_price, price, rel_tol=1e-9, abs_tol=1e-9):
            raise PaperExecutionSafetyError("reconciled TP/SL price differs from the exit plan")
        # In the published EVEDEX response contract ``triggerOrder`` is the
        # generated exit order, populated only after a trigger. It is not entry
        # lineage and must never be compared to the parent entry ID.
        parent = record.get("order")
        if parent is not None and str(parent) != parent_order_id:
            raise PaperExecutionSafetyError("reconciled TP/SL has conflicting parent-order lineage")
        if require_parent and str(parent or "") != parent_order_id:
            raise PaperExecutionSafetyError("reconciled TP/SL lacks exact parent-order lineage")
        cls._required_text(record.get("id"), "TP/SL exchange ID")
        cls._assert_known_tpsl_status(record)
        if require_live and not cls._is_live_tpsl(record):
            raise PaperExecutionSafetyError("reconciled TP/SL is not live")

    @staticmethod
    def _list(value: Any) -> list[dict[str, Any]]:
        if isinstance(value, dict) and isinstance(value.get("list"), list):
            value = value["list"]
        if value is None:
            return []
        if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
            raise PaperExecutionSafetyError("venue reconciliation list is malformed")
        return value

    @staticmethod
    def _required_text(value: Any, field: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise PaperExecutionSafetyError(f"{field} is missing")
        return value

    @staticmethod
    def _finite(value: Any, *, default: float = 0.0) -> float:
        try:
            result = default if value is None else float(value)
        except (TypeError, ValueError) as exc:
            raise PaperExecutionSafetyError("venue numeric value is malformed") from exc
        if not math.isfinite(result) or result < 0:
            raise PaperExecutionSafetyError("venue numeric value must be finite and non-negative")
        return result

    @staticmethod
    def _signed_finite(value: Any, *, default: float = 0.0) -> float:
        try:
            result = default if value is None else float(value)
        except (TypeError, ValueError) as exc:
            raise PaperExecutionSafetyError("venue numeric value is malformed") from exc
        if not math.isfinite(result):
            raise PaperExecutionSafetyError("venue numeric value must be finite")
        return result

    @staticmethod
    def _positive(value: Any, field: str) -> float:
        result = PaperExecutionEngine._finite(value)
        if result <= 0:
            raise PaperExecutionSafetyError(f"{field} must be positive")
        return result

    @staticmethod
    def _object(value: Any, field: str) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise PaperExecutionSafetyError(f"venue {field} is malformed")
        return value

    @staticmethod
    def _timestamp_ms(value: Any, fallback: int) -> int:
        if isinstance(value, str):
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                pass
            else:
                if parsed.tzinfo is not None:
                    return max(0, int(parsed.timestamp() * 1000))
        return fallback

    @staticmethod
    def _positive_optional(value: Any) -> float | None:
        result = PaperExecutionEngine._finite(value)
        return result if result > 0 else None

    @staticmethod
    def _from_ms(value: int) -> datetime:
        return datetime.fromtimestamp(value / 1000, tz=UTC)
