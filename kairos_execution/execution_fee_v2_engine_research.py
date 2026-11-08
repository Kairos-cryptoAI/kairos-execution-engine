"""Explicitly detached V2-fee lifecycle for synthetic cross-repo research.

No shipping factory constructs these classes. A caller must independently
qualify all readers and a version-aware transactional repository before any
real use. This module does not grant entry, signing, or LIVE authority.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from contextvars import ContextVar
from datetime import UTC

from kairos_core.contracts import TradeExecutionEventV1, TradeExecutionEventV2
from kairos_core.enums import TradeExecutionEventType, TradeLifecycleState
from kairos_core.topics import Topics

from .execution_fee_v2_research import build_unknown_execution_event_v2, execution_fact_key_v2
from .paper_engine import PaperExecutionSafetyError
from .production_lifecycle import ProductionLifecycleEngine
from .service import ExecutionService

_V1 = "trade-execution-event.v1"
_V2 = "trade-execution-event.v2"
_current_contract: ContextVar[str | None] = ContextVar("research_execution_contract", default=None)


class ResearchFeeV2ProductionEngine(ProductionLifecycleEngine):
    """Build V2 only for new research trades; existing trades keep their version."""

    async def _audit_scoped_public_facts(self):
        """Count lifecycle transitions separately from standalone fee facts."""
        scoped = await self.trades.list_trades_for_scope(
            environment=self._environment,
            account_id=self._lifecycle_scope.account_id,
            exchange=self.adapter.name,
            include_terminal=True,
        )
        for trade in scoped:
            version = await self.trades.get_execution_contract_version(trade.trade_id)
            if version not in {_V1, _V2}:
                raise PaperExecutionSafetyError("existing execution history has no verified event version")
            facts = await self.trades.list_execution_events(trade.trade_id)
            if [fact.event_seq for fact in facts] != list(range(1, len(facts) + 1)):
                raise PaperExecutionSafetyError("public execution fact sequence is not contiguous")
            lifecycle = []
            for fact in facts:
                if fact.contract_version != version:
                    raise PaperExecutionSafetyError("execution event version changed within a trade")
                if fact.event_type == "FEE_UPDATED":
                    if (
                        version != _V2
                        or not lifecycle
                        or fact.lifecycle_state != lifecycle[-1].lifecycle_state
                    ):
                        raise PaperExecutionSafetyError("fee update changed the durable lifecycle state")
                else:
                    lifecycle.append(fact)
            if len(lifecycle) != trade.state_version + 1:
                raise PaperExecutionSafetyError(
                    "public lifecycle facts differ from durable lifecycle versions"
                )
            if (
                not lifecycle
                or lifecycle[0].event_type is not TradeExecutionEventType.DECISION_RECEIVED
                or lifecycle[0].lifecycle_state is not TradeLifecycleState.RECEIVED
                or lifecycle[-1].lifecycle_state is not TradeLifecycleState(trade.state.value)
            ):
                raise PaperExecutionSafetyError("public lifecycle facts differ from durable trade state")

    @asynccontextmanager
    async def _research_contract_scope(self, trade_id: str, *, allow_new: bool = False):
        existing = await self.trades.get(trade_id)
        version: str | None
        if existing is None:
            if not allow_new:
                raise PaperExecutionSafetyError("execution version is unavailable for an existing trade")
            version = _V2
        else:
            version = await self.trades.get_execution_contract_version(trade_id)
            if version not in {_V1, _V2}:
                raise PaperExecutionSafetyError("existing execution history has no verified event version")
        token = _current_contract.set(version)
        try:
            yield version
        finally:
            _current_contract.reset(token)

    async def _create_trade_with_event(self, decision, new_trade):
        async with self._research_contract_scope(new_trade.trade_id, allow_new=True):
            return await super()._create_trade_with_event(decision, new_trade)

    async def _transition_with_event(self, decision, trade, target, **kwargs):
        async with self._research_contract_scope(trade.trade_id):
            return await super()._transition_with_event(decision, trade, target, **kwargs)

    async def _reconcile_trade(self, trade, venue, sidecar_events):
        async with self._research_contract_scope(trade.trade_id):
            return await super()._reconcile_trade(trade, venue, sidecar_events)

    async def _unripe_effects(self, trade, *, eligible_effect_keys):
        async with self._research_contract_scope(trade.trade_id):
            return await super()._unripe_effects(trade, eligible_effect_keys=eligible_effect_keys)

    async def _finish_venue_exit(self, decision, trade, role, reason, **kwargs):
        async with self._research_contract_scope(trade.trade_id):
            return await super()._finish_venue_exit(decision, trade, role, reason, **kwargs)

    @classmethod
    def _order_fee_usd(cls, order, *, required):
        version = _current_contract.get()
        if version == _V2:
            # Receipt fee fields can arrive late, be a different currency, or
            # have lost original precision. No accounting fact is inferred.
            return None
        if version == _V1:
            return super()._order_fee_usd(order, required=required)
        raise PaperExecutionSafetyError("fee handling requires the durable per-trade event version")

    def _event_spec(self, decision, trade, event_type, lifecycle_state, **kwargs):
        version = _current_contract.get()
        if version == _V1:
            return super()._event_spec(decision, trade, event_type, lifecycle_state, **kwargs)
        if version != _V2:
            raise PaperExecutionSafetyError("public execution event lacks a durable contract selection")
        position_quantity = kwargs.get("position_quantity")
        if position_quantity is None:
            position_quantity = kwargs.get("default_position_quantity", 0)
        fields = {
            "source": self.settings.service_name,
            "event_seq": 1,
            "occurred_at_ms": int(self.clock().astimezone(UTC).timestamp() * 1000),
            "event_type": event_type,
            "lifecycle_state": lifecycle_state,
            "trading_mode": self._lifecycle_scope.trading_mode,
            "evedex_profile": self._lifecycle_scope.profile,
            "account_id": trade.account_id,
            "venue_symbol": decision.venue_symbol,
            "strategy_id": trade.strategy_id,
            "strategy_revision": trade.strategy_revision,
            "intent_id": trade.strategy_intent_id,
            "risk_decision_id": self._required_text(decision.decision_id, "decision_id"),
            "trade_id": trade.trade_id,
            "effect_id": kwargs.get("effect_id"),
            "order_role": kwargs.get("order_role"),
            "client_order_id": kwargs.get("client_order_id"),
            "exchange_order_id": kwargs.get("exchange_order_id"),
            "requested_quantity": kwargs.get("requested_quantity", 0),
            "filled_quantity": kwargs.get("filled_quantity", 0),
            "position_quantity": position_quantity,
            "average_price": kwargs.get("average_price"),
            "exit_reason": kwargs.get("exit_reason"),
            # Operational telemetry changes over time and is not a durable
            # identity input. Preserve only the explicit lifecycle details.
            "details": kwargs.get("details", ()),
        }
        prototype = build_unknown_execution_event_v2(fields)
        fact_key = execution_fact_key_v2(prototype, namespace=self._lifecycle_scope.event_namespace)

        def build(sequence):
            return build_unknown_execution_event_v2({**fields, "event_seq": sequence})

        return fact_key, build

    def _replay_execution_event_builder(self, stored, build):
        if _current_contract.get() == _V1:
            return super()._replay_execution_event_builder(stored, build)
        if _current_contract.get() != _V2 or type(stored) is not TradeExecutionEventV2:
            raise PaperExecutionSafetyError("stored execution fact differs from its durable version")
        candidate = build(stored.event_seq)
        # Reuse the first durable time/ID on retry while requiring every
        # nonvolatile field (including fee provenance and source) to match.
        ignored = {"event_id", "message_id", "occurred_at_ms", "produced_at"}
        if candidate.model_dump(mode="json", exclude=ignored) != stored.model_dump(
            mode="json", exclude=ignored
        ):
            raise PaperExecutionSafetyError("execution fact replay conflicts with its stored payload")

        def replay(_sequence):
            return stored

        return replay


class ResearchFeeV2ExecutionService(ExecutionService):
    """Route either model by its actual contract; never publish both versions."""

    @staticmethod
    def _trade_execution_event_topic(event):
        if type(event) is TradeExecutionEventV1:
            return Topics.TRADE_EXECUTION_EVENT
        if type(event) is TradeExecutionEventV2:
            return Topics.TRADE_EXECUTION_EVENT_V2
        raise PaperExecutionSafetyError("unknown execution event version cannot be published")
