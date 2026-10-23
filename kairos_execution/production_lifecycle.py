"""Explicit production lifecycle composition over the protected EVEDEX FSM.

Construction requires a separately assembled managed adapter/runtime. This is
not a factory and does not create signing, approval, or readiness authority.
"""

from __future__ import annotations

import math
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from decimal import Decimal
from types import MappingProxyType
from typing import Any, Literal
from uuid import UUID

from kairos_core.contracts import RiskTradeDecisionV1
from kairos_core.enums import (
    EntryPolicy,
    EvedexProfile,
    ReviewDecision,
    Side,
    TradingMode,
)
from kairos_persistence import (
    ExecutionJournalRepository,
    ExecutionMutationBudgetRepository,
    ExecutionRuntimeHealthRepository,
    TradeLifecycleRepository,
    TradeRecord,
    TradeState,
)
from pydantic import Field, model_validator

from .lifecycle_scope import ExecutionLifecycleScope, LifecycleAdmissionPolicy
from .managed_signer import CustodyBindingV1
from .paper_engine import (
    PaperExecutionResult,
    PaperExecutionSafetyError,
    _EvedexProtectedExecutionEngine,
)
from .production_accounting import PostgresProductionAccounting
from .production_lifecycle_binding import ProductionLifecycleBindingV1
from .production_observation import PROD_EXCHANGE_ORIGIN
from .production_readiness import (
    Identity,
    ProductionContextV1,
    StrictRecord,
    canonical_digest,
)
from .production_reconciliation import ProductionReservationReconciler, ReservationTradeBindingV1
from .profiles import profile_params


class ProductionVenueHealthV1(StrictRecord):
    """Pinned public PROD endpoint identity expected from adapter preflight."""

    profile: Literal["PROD"] = "PROD"
    chain_id: int = Field(gt=0)
    exchange_url: str
    auth_url: str
    sdk_version: Literal["1.2.11"] = "1.2.11"


class ProductionLifecycleConfigV1(StrictRecord):
    """Explicit immutable scope needed to construct one PROD lifecycle engine."""

    context: ProductionContextV1
    custody_binding: CustodyBindingV1
    strategy_revision: Identity
    expected_health: ProductionVenueHealthV1
    service_name: Identity
    symbol_map: dict[Identity, Identity]

    @model_validator(mode="after")
    def validate_profile_and_instruments(self) -> ProductionLifecycleConfigV1:
        params = profile_params(EvedexProfile.PROD)
        if self.custody_binding.context != self.context:
            raise ValueError("custody binding and production lifecycle context differ")
        if self.expected_health.chain_id != self.custody_binding.chain_id:
            raise ValueError("expected PROD health chain must match the custody chain")
        if self.expected_health.exchange_url != PROD_EXCHANGE_ORIGIN:
            raise ValueError("expected PROD exchange URL differs from the official observer origin")
        if (
            self.expected_health.exchange_url != params.exchange_url
            or self.expected_health.auth_url != params.auth_url
        ):
            raise ValueError("expected PROD health URLs differ from the official EVEDEX profile")
        approved = set(self.custody_binding.approved_instruments)
        current_universe = {
            "BTCUSDT": "BTCUSD",
            "ETHUSDT": "ETHUSD",
            "SOLUSDT": "SOLUSD",
            "BNBUSDT": "BNBUSD",
            "XRPUSDT": "XRPUSD",
        }
        if (
            len(self.symbol_map) != 5
            or len(set(self.symbol_map.values())) != 5
            or set(self.symbol_map.values()) != approved
        ):
            raise ValueError("PROD symbol map must bijectively cover the five custody-approved instruments")
        if self.symbol_map != current_universe:
            raise ValueError("PROD lifecycle cannot change the existing five-symbol universe")
        return self


class _ProductionLifecyclePolicy(LifecycleAdmissionPolicy):
    def __init__(self, scope: ExecutionLifecycleScope, strategy_id: str, strategy_revision: str) -> None:
        self._scope = scope
        self.strategy_id = strategy_id
        self.strategy_revision = strategy_revision

    @property
    def scope(self) -> ExecutionLifecycleScope:
        return self._scope

    def validate_decision_scope(self, decision: RiskTradeDecisionV1) -> None:
        if decision.trading_mode is not TradingMode.LIVE:
            raise ValueError("production lifecycle rejects non-LIVE decisions")
        if decision.evedex_profile is not EvedexProfile.PROD:
            raise ValueError("production lifecycle rejects non-PROD decisions")
        if decision.account_id != self.scope.account_id:
            raise ValueError("risk decision targets a different production account")
        if self.scope.symbol_map.get(decision.intent.symbol) != decision.venue_symbol:
            raise ValueError("risk decision venue symbol is outside the custody-approved PROD map")
        if (
            decision.intent.strategy_id != self.strategy_id
            or decision.intent.strategy_revision != self.strategy_revision
        ):
            raise ValueError("risk decision strategy/system revision differs from production context")


def _production_policy(config: ProductionLifecycleConfigV1) -> _ProductionLifecyclePolicy:
    scope_digest = canonical_digest(config.context)
    return _ProductionLifecyclePolicy(
        scope=ExecutionLifecycleScope(
            trading_mode=TradingMode.LIVE,
            profile=EvedexProfile.PROD,
            environment=f"PROD:{scope_digest}:LIVE",
            account_id=config.context.remote_account_id,
            remote_environment="evedex-prod",
            remote_account_id=config.context.remote_account_id,
            exchange="evedex",
            symbol_map=MappingProxyType(dict(config.symbol_map)),
            mutation_namespace=f"prod.v1:{scope_digest}",
            event_namespace=f"prod.v1:{scope_digest}",
        ),
        strategy_id=config.context.adaptive_system_id,
        strategy_revision=config.strategy_revision,
    )


class ProductionLifecycleEngine(_EvedexProtectedExecutionEngine):
    """One explicitly composed LIVE/PROD engine using the shared durable FSM."""

    _MAX_PROD_BOOK_AGE_MS = 2_000

    async def reconcile_closed_account(
        self,
        *,
        trade_id: str,
        reconciler: ProductionReservationReconciler,
        source_id: str,
        raw_venue_evidence: Any,
        accounting: PostgresProductionAccounting | None = None,
    ) -> dict[str, Any]:
        """Complete the explicit position→flat account→terminal-evidence path.

        Venue truth is interpreted independently by the reconciler's registered
        source. An empty account GET or successful ACK is never sufficient. The
        receipt is append-only; schema-v2 reservations deliberately remain
        counted. An explicit fresh state-v3/reconciliation-v2 composition can
        additionally accept that exact receipt through its isolated accounting
        writer; it never deletes reservations, resets loss or promotes LIVE.
        """
        if (
            not isinstance(reconciler, ProductionReservationReconciler)
            or reconciler.context != self.production_settings.context
            or reconciler.database_uuid != self.production_runtime.database_uuid
            or reconciler.trades is not self.trades
            or reconciler.effects is not self.effects
        ):
            raise PaperExecutionSafetyError("terminal reconciler differs from the exact PROD lifecycle")
        if accounting is not None and (
            not isinstance(accounting, PostgresProductionAccounting)
            or accounting.context != self.production_settings.context
            or accounting.database_uuid != self.production_runtime.database_uuid
            or accounting.expected_database != self.production_runtime.state_source.expected_database
            or accounting.expected_database != reconciler.expected_database
            or accounting.policy_namespace != self.production_runtime.state_source.policy_namespace
            or accounting.policy_namespace != reconciler.policy_namespace
            or self.production_runtime.state_source.state_schema_version != 3
            or reconciler.schema_version != 2
        ):
            raise PaperExecutionSafetyError("accounting requires the exact fresh v3/v2 PROD composition")
        async with self._lifecycle_lock:
            async with self.trades.account_lock(**self._remote_account_scope):
                await self._reconcile_once_unlocked()
                snapshot = await self._account_snapshot_unlocked()
                if snapshot.positions or snapshot.open_orders or not snapshot.reconciled:
                    raise PaperExecutionSafetyError("PROD account is not authoritatively reconciled and flat")
                trade = await self.trades.get(trade_id)
                if (
                    trade is None
                    or trade.state is not TradeState.FLAT
                    or trade.environment != self._environment
                ):
                    raise PaperExecutionSafetyError("the exact PROD trade is not durably FLAT")
                from kairos_core.enums import OrderRole

                effect_id = self._effect_id(trade_id, OrderRole.ENTRY, "place")
                plan = await self.adapter.bindings.get(effect_id)
                if (
                    plan is None
                    or plan.trade_id != trade_id
                    or plan.context != self.production_settings.context
                    or plan.role != "ENTRY"
                    or plan.lifecycle_effect_id != effect_id
                    or plan.decision_id != trade.risk_decision_id
                    or plan.risk_decision_id != trade.risk_decision_id
                    or plan.decision_sha256 != canonical_digest(self._decision_for_trade(trade))
                ):
                    raise PaperExecutionSafetyError(
                        "original create-only entry signing association is absent"
                    )
                binding = ReservationTradeBindingV1(
                    trade_id=trade_id,
                    decision_id=trade.risk_decision_id,
                    effect_id=plan.signing_effect_id,
                    lifecycle_entry_effect_id=effect_id,
                    signing_request_id=plan.request.request_id,
                    client_order_id=trade.entry_client_order_id,
                    exchange_parent_order_id=self._required_text(
                        trade.entry_exchange_order_id, "entry order ID"
                    ),
                )
                receipt = await reconciler.reconcile_terminal(
                    binding=binding, raw_venue_evidence=raw_venue_evidence, source_id=source_id
                )
                accounting_receipt = None
                if accounting is not None:
                    # A failed or ambiguous accounting append leaves the exact
                    # terminal receipt retained and does not report a release.
                    try:
                        terminal_id = UUID(receipt["receipt_id"])
                        terminal_hash = receipt["payload_sha256"]
                    except (KeyError, ValueError, TypeError, AttributeError):
                        raise PaperExecutionSafetyError(
                            "exact terminal accounting receipt is malformed"
                        ) from None
                    accounting_receipt = await accounting.accept_terminal_receipt(
                        receipt_id=terminal_id, receipt_payload_sha256=terminal_hash
                    )
                return {
                    "status": "CLOSED_ACCOUNT_RECONCILED_EVIDENCE_RECORDED",
                    "trade_id": trade_id,
                    "account_snapshot_sha256": canonical_digest(snapshot),
                    "terminal_receipt": receipt,
                    "live_ready": False,
                    "reservation_released": accounting_receipt is not None,
                    "accounting_receipt": accounting_receipt,
                }

    def __init__(
        self,
        adapter: Any,
        trades: TradeLifecycleRepository,
        effects: ExecutionJournalRepository,
        settings: ProductionLifecycleConfigV1,
        runtime: Any,
        *,
        clock: Callable[[], datetime] | None = None,
        sleeper: Callable[[float], Awaitable[None]] | None = None,
        mutation_budget: ExecutionMutationBudgetRepository | None = None,
        runtime_health: ExecutionRuntimeHealthRepository | None = None,
        prepared_exit_risk: Any | None = None,
    ) -> None:
        settings = ProductionLifecycleConfigV1.model_validate(settings)
        from .production_lifecycle_adapter import ManagedProductionLifecycleAdapter

        if not isinstance(adapter, ManagedProductionLifecycleAdapter):
            raise ValueError("production lifecycle requires the concrete managed production adapter")
        if (
            adapter.runtime is not runtime
            or adapter.trades is not trades
            or adapter.effects is not effects
            or runtime.context != settings.context
            or runtime.binding != settings.custody_binding
        ):
            raise ValueError("adapter/runtime/custody scope differs from production lifecycle settings")
        if adapter.name != "evedex":
            raise ValueError("production lifecycle supports only the managed EVEDEX adapter")
        self.production_settings = settings
        self.production_runtime = runtime
        if prepared_exit_risk is not None:
            from .production_path import ProductionPreparedExitRiskStager

            if not isinstance(prepared_exit_risk, ProductionPreparedExitRiskStager):
                raise TypeError("production exits require the concrete per-effect Risk stager")
            if clock is None:
                clock = prepared_exit_risk.clock
            if (
                prepared_exit_risk.runtime is not runtime
                or prepared_exit_risk.publisher.trades is not trades
                or prepared_exit_risk.publisher.effects is not effects
                or prepared_exit_risk.publisher.lifecycle_bindings is not adapter.bindings
                or prepared_exit_risk.clock is not clock
                or runtime._clock is not clock
            ):
                raise ValueError("exit Risk stager differs from the exact lifecycle resources/clock")
        self.prepared_exit_risk = prepared_exit_risk
        policy = _production_policy(settings)
        super().__init__(
            adapter,
            trades,
            effects,
            settings,
            lifecycle_policy=policy,
            clock=clock,
            sleeper=sleeper,
            mutation_budget=mutation_budget,
            runtime_health=runtime_health,
        )

    async def _prepare_exit_risk(self, effect_id: str) -> None:
        if self.prepared_exit_risk is not None:
            await self.prepared_exit_risk.stage(effect_id)

    async def _handle_once(self, decision: RiskTradeDecisionV1) -> PaperExecutionResult:
        # A durable completed/uncertain entry is recovery work, not a new entry
        # quote request. Requiring the old quote to be fresh would poison delayed
        # bus redelivery even after an otherwise successful protected lifecycle.
        self._validate_decision(decision)
        if decision.approved:
            trade_id = self._required_text(decision.trade_id, "trade_id")
            existing = await self.trades.get(trade_id)
            if existing is not None and existing.state is not TradeState.RECEIVED:
                if (
                    existing.environment != self._environment
                    or existing.account_id != self._lifecycle_scope.account_id
                    or existing.exchange != self.adapter.name
                    or not await self.trades.verify_chain(trade_id)
                    or canonical_digest(self._decision_for_trade(existing)) != canonical_digest(decision)
                ):
                    raise PaperExecutionSafetyError("PROD redelivery differs from exact durable decision")
                if self.recovery_blocked or not await self.trades.entries_allowed(
                    environment=self._environment,
                    account_id=self._lifecycle_scope.account_id,
                    exchange=self.adapter.name,
                ):
                    raise PaperExecutionSafetyError("PROD redelivery requires authoritative startup recovery")
                return PaperExecutionResult(events=tuple(await self._reconcile_redelivery_locked(existing)))
        # New entries, including a durable RECEIVED pre-mutation gap, retain all
        # original market freshness, operator, Risk and one-use dispatch gates.
        return await super()._handle_once(decision)

    def _expected_venue_health(self) -> dict[str, Any]:
        return self.production_settings.expected_health.model_dump(mode="python")

    def _accept_entry_health(self, health: dict[str, Any]) -> None:
        # Keep the shared entry-path mutation headroom gate (entry plus both
        # protective mutations). This is a capacity constraint, not canary
        # authority, and is independent of managed per-effect authorization.
        super()._accept_entry_health(health)

    def _assert_technical_canary_binding(self, decision: RiskTradeDecisionV1) -> None:
        """Retain canonical Core lineage and configured strategy scope only."""
        try:
            decision = RiskTradeDecisionV1.model_validate(decision.to_payload())
        except (TypeError, ValueError) as exc:
            raise PaperExecutionSafetyError("LIVE decision has invalid canonical Core lineage") from exc
        if not decision.approved or decision.rejection_reasons:
            raise PaperExecutionSafetyError("production lifecycle requires an approved Core decision")
        if not math.isclose(decision.leverage, 1.0, rel_tol=0.0, abs_tol=1e-12):
            raise PaperExecutionSafetyError("production lifecycle permits only exactly 1x leverage")
        if decision.entry_policy is not EntryPolicy.NEXT_BAR_MARKET:
            raise PaperExecutionSafetyError("production lifecycle requires NEXT_BAR_MARKET policy")
        if decision.review.decision is not ReviewDecision.ALLOW:
            raise PaperExecutionSafetyError("production lifecycle requires the original ALLOW review")
        intent = decision.intent
        route = decision.review.route
        review = decision.review
        if (
            intent.message_id != intent.intent_id
            or route.correlation_id != intent.intent_id
            or route.causation_id != intent.message_id
            or review.correlation_id != intent.intent_id
            or review.causation_id != route.message_id
            or route.intent.model_dump(mode="json") != intent.model_dump(mode="json")
            or review.intent.model_dump(mode="json") != intent.model_dump(mode="json")
        ):
            raise PaperExecutionSafetyError("Core decision route/review lineage is not canonical")
        if (
            intent.strategy_id != self.production_settings.context.adaptive_system_id
            or intent.strategy_revision != self.production_settings.strategy_revision
        ):
            raise PaperExecutionSafetyError("Core strategy identity/revision differs from PROD context")

    async def _check_operator_entry(self, decision: RiskTradeDecisionV1, effect_id: str) -> None:
        # Resolve current operator/risk/exposure authority without signing or
        # reserving. Managed dispatch independently rechecks immediately before
        # the wire effect.
        await self._inspect_entry(decision, effect_id)

    async def _bind_canary_entry(self, decision: RiskTradeDecisionV1, effect_id: str) -> None:
        # Retained FSM hook name; PROD semantics are a read-only exact-effect
        # authority inspection, never a canary-session bind or approval mint.
        await self._inspect_entry(decision, effect_id)

    async def _inspect_entry(self, decision: RiskTradeDecisionV1, effect_id: str) -> None:
        binding = await self.adapter.inspect_entry(decision, effect_id)
        if not isinstance(binding, ProductionLifecycleBindingV1) or (
            binding.context != self.production_settings.context
            or binding.decision_id != decision.decision_id
            or binding.trade_id != decision.trade_id
            or binding.role != "ENTRY"
            or binding.lifecycle_effect_id != effect_id
            or binding.request.context != self.production_settings.context
        ):
            raise PaperExecutionSafetyError("managed entry inspection differs from the prepared Core effect")

    @asynccontextmanager
    async def _entry_dispatch_guard(
        self, decision: RiskTradeDecisionV1, effect_id: str
    ) -> AsyncIterator[None]:
        # Re-read authority after PREPARED and immediately before runtime send.
        await self._inspect_entry(decision, effect_id)
        yield

    async def _assert_entry_admission(self, trade: TradeRecord) -> None:
        if not await self.trades.entries_allowed(
            environment=self._environment,
            account_id=self._lifecycle_scope.account_id,
            exchange=self.adapter.name,
        ):
            raise PaperExecutionSafetyError("durable production recovery revoked entry authority")
        await self._observe_health(await self.adapter.preflight(), require_entry=True)
        venue = await self.adapter.fetch_paper_state()
        durable = await self.trades.recovery_required(
            environment=self._environment,
            account_id=self._lifecycle_scope.account_id,
        )
        blockers = self._authoritative_account_blockers(venue, durable, ignore_trade_id=trade.trade_id)
        if any(candidate.trade_id != trade.trade_id for candidate in durable):
            blockers.append("production account already has another nonterminal trade")
        decision = self._decision_for_trade(trade)
        self._assert_production_instrument(decision, venue)
        if blockers:
            raise PaperExecutionSafetyError("production entry admission is not clean: " + "; ".join(blockers))

    def _assert_production_instrument(self, decision: RiskTradeDecisionV1, venue: dict[str, Any]) -> None:
        matches = [
            item
            for item in self._list(venue.get("instruments"))
            if str(item.get("name", "")).upper() == decision.venue_symbol.upper()
        ]
        if len(matches) != 1:
            raise PaperExecutionSafetyError("PROD instrument metadata is missing or duplicated")
        instrument = matches[0]
        if (
            str(instrument.get("trading", "")).casefold() != "all"
            or str(instrument.get("visibility", "")).casefold() != "all"
            or str(instrument.get("marketState", "")).upper() != "OPEN"
        ):
            raise PaperExecutionSafetyError("PROD instrument is not currently open and tradeable")
        updated = self._iso_timestamp_ms(instrument.get("updatedAt"), "PROD instrument updatedAt")
        now_ms = int(self.clock().astimezone(UTC).timestamp() * 1000)
        if updated > now_ms or now_ms - updated > 5 * 60 * 1000:
            raise PaperExecutionSafetyError("PROD instrument rule snapshot is stale or future-dated")
        price_increment = self._positive_decimal(instrument.get("priceIncrement"), "priceIncrement")
        quantity_increment = self._positive_decimal(instrument.get("quantityIncrement"), "quantityIncrement")
        min_price = self._positive_decimal(instrument.get("minPrice"), "minPrice")
        max_price = self._positive_decimal(instrument.get("maxPrice"), "maxPrice")
        min_quantity = self._positive_decimal(instrument.get("minQuantity"), "minQuantity")
        max_quantity = self._positive_decimal(instrument.get("maxQuantity"), "maxQuantity")
        min_volume = self._positive_decimal(instrument.get("minVolume"), "minVolume")
        lot_size = self._positive_decimal(instrument.get("lotSize"), "lotSize")
        multiplier = self._positive_decimal(instrument.get("multiplier"), "multiplier")
        if lot_size != Decimal(1) or multiplier != Decimal(1):
            raise PaperExecutionSafetyError(
                "PROD lot size/multiplier differ from supported 1x quantity assumptions"
            )
        if min_price >= max_price or min_quantity > max_quantity:
            raise PaperExecutionSafetyError("PROD instrument price/quantity bounds are incoherent")
        quantity = Decimal(str(decision.quantity))
        if (
            quantity < min_quantity
            or quantity > max_quantity
            or quantity % quantity_increment != 0
            or quantity * Decimal(str(decision.worst_entry_price)) < min_volume
        ):
            raise PaperExecutionSafetyError("Core decision quantity violates current PROD instrument rules")
        for label, raw in (
            ("entry", decision.worst_entry_price),
            ("stop", decision.exit_plan.stop_price),
            ("target", decision.exit_plan.target_price),
        ):
            price = Decimal(str(raw))
            if price < min_price or price > max_price or price % price_increment != 0:
                raise PaperExecutionSafetyError(f"Core {label} price violates current PROD instrument rules")
        self._operational_telemetry["evedex_prod_instrument_updated_at_ms"] = str(updated)

    def _assert_live_entry_book(self, decision: RiskTradeDecisionV1, depth: dict[str, Any]) -> None:
        """Require a fresh bounded book, unchanged risk cap, and sufficient depth."""
        now_ms = int(self.clock().astimezone(UTC).timestamp() * 1000)
        timestamp = depth.get("t")
        if isinstance(timestamp, bool) or not isinstance(timestamp, int):
            raise PaperExecutionSafetyError("EVEDEX PROD depth timestamp is malformed")
        age_ms = now_ms - timestamp
        if timestamp < decision.venue_quality.book_timestamp_ms or not (
            0 <= age_ms <= self._MAX_PROD_BOOK_AGE_MS
        ):
            raise PaperExecutionSafetyError("EVEDEX PROD book is stale or predates the Core risk measurement")

        def levels(field: str) -> list[tuple[Decimal, Decimal]]:
            parsed = [
                (
                    self._positive_decimal(row.get("price"), f"PROD depth {field} price"),
                    self._positive_decimal(row.get("quantity"), f"PROD depth {field} quantity"),
                )
                for row in self._list(depth.get(field))
            ]
            if not parsed:
                raise PaperExecutionSafetyError(f"EVEDEX PROD depth has no {field}")
            return parsed

        asks, bids = levels("asks"), levels("bids")
        best_ask = min(price for price, _ in asks)
        best_bid = max(price for price, _ in bids)
        if best_bid >= best_ask:
            raise PaperExecutionSafetyError("EVEDEX PROD book is crossed")
        cap = Decimal(str(decision.worst_entry_price))
        if decision.intent.side is Side.LONG:
            if cap < best_ask:
                raise PaperExecutionSafetyError("Core BUY limit cap is no longer marketable")
            executable = [(price, qty) for price, qty in asks if price <= cap]
        else:
            if cap > best_bid:
                raise PaperExecutionSafetyError("Core SELL limit cap is no longer marketable")
            executable = [(price, qty) for price, qty in bids if price >= cap]
        available_usd = sum((price * qty for price, qty in executable), start=Decimal(0))
        required_usd = max(
            Decimal(str(decision.notional_usd)),
            Decimal(str(decision.venue_quality.assessed_notional_usd)),
        )
        if available_usd < required_usd:
            raise PaperExecutionSafetyError("EVEDEX PROD executable depth is below the immutable Core limit")
        self._operational_telemetry["evedex_prod_entry_book_age_ms"] = str(age_ms)
        self._operational_telemetry["evedex_prod_entry_executable_depth_usd"] = self._canonical_decimal(
            available_usd
        )
