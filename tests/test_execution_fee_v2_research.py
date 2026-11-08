"""No live route: isolated V2 construction and stable synthetic fact identity."""

import asyncio
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from kairos_core.bus.base import BusEnvelope
from kairos_core.contracts import TradeExecutionEventV1
from kairos_core.enums import (
    OrderRole,
    TradeExecutionEventType,
    TradeExitReason,
    TradeLifecycleState,
    TradingMode,
)
from kairos_core.topics import Topics
from kairos_persistence import TradeState

pytest.importorskip(
    "kairos_core.contracts.execution_fee_v2", reason="V2 contract requires the explicit research source set"
)

from kairos_core.contracts import ExecutionFeeBundleV2, ExecutionFeeComponentV2

from kairos_execution.execution_fee_v2_engine_research import (
    ResearchFeeV2ExecutionService,
    ResearchFeeV2ProductionEngine,
)
from kairos_execution.execution_fee_v2_research import (
    append_research_fee_update_v2,
    build_unknown_execution_event_v2,
    execution_fact_key_v2,
)
from kairos_execution.paper_engine import PaperExecutionResult, PaperExecutionSafetyError
from kairos_execution.production_lifecycle import ProductionLifecycleEngine
from kairos_execution.production_reconciliation import (
    ProductionReconciliationError,
    ProductionReservationReconciler,
)
from kairos_execution.service import ExecutionService
from tests.test_production_lifecycle_binding import _decision
from tests.test_service import FakeBus


def _fields(**updates):
    decision = _decision()
    result = {
        "source": "synthetic-research",
        "event_seq": 1,
        "occurred_at_ms": decision.decided_at_ms,
        "event_type": TradeExecutionEventType.ENTRY_PARTIAL_FILL,
        "lifecycle_state": TradeLifecycleState.PROTECTING,
        "trading_mode": decision.trading_mode,
        "evedex_profile": decision.evedex_profile,
        "account_id": decision.account_id,
        "venue_symbol": decision.venue_symbol,
        "strategy_id": decision.intent.strategy_id,
        "strategy_revision": decision.intent.strategy_revision,
        "intent_id": decision.intent.intent_id,
        "risk_decision_id": decision.decision_id,
        "trade_id": decision.trade_id,
        "effect_id": "synthetic-effect",
        "order_role": OrderRole.ENTRY,
        "client_order_id": "synthetic-order-id",
        "requested_quantity": 0.1,
        "filled_quantity": 0.05,
        "position_quantity": 0.05,
        "average_price": 100,
    }
    result.update(updates)
    return result


def test_partial_fill_fee_is_unknown_without_losing_exposure_fact():
    event = build_unknown_execution_event_v2(_fields())
    payload = event.model_dump(mode="json")
    assert payload["contract_version"] == "trade-execution-event.v2"
    assert payload["fee_usd"] is None
    assert payload["fee"]["coverage"] == "UNKNOWN"
    assert payload["fee"]["usd_status"] == "UNKNOWN"
    assert payload["fee"]["components"] == []
    assert payload["fee"]["scope_kind"] == "ORDER"
    assert payload["fee"]["scope_reference"] == "synthetic-order-id"
    assert payload["filled_quantity"] == 0.05
    assert payload["position_quantity"] == 0.05


def test_non_order_fact_scope_is_trade_and_unknown_is_not_zero():
    event = build_unknown_execution_event_v2(
        _fields(client_order_id=None, effect_id=None, order_role=None, exchange_order_id=None)
    )
    assert event.fee.scope_kind == "TRADE"
    assert event.fee.scope_reference == event.trade_id
    assert event.fee_usd is None


@pytest.mark.parametrize(
    "forged",
    [{"fee_usd": 0}, {"fee": {}}, {"event_id": "a" * 64}, {"contract_version": "trade-execution-event.v1"}],
)
def test_caller_cannot_inject_zero_cost_or_old_identity(forged):
    with pytest.raises(ValueError):
        build_unknown_execution_event_v2(_fields(**forged))


def test_replay_fact_key_is_stable_across_new_sequence_and_clock_but_v2_scoped():
    first = build_unknown_execution_event_v2(_fields())
    later = build_unknown_execution_event_v2(_fields(event_seq=17, occurred_at_ms=first.occurred_at_ms + 1))
    assert first.event_id != later.event_id
    assert execution_fact_key_v2(first, namespace="synthetic") == execution_fact_key_v2(
        later, namespace="synthetic"
    )
    assert ":v2:" in execution_fact_key_v2(first, namespace="synthetic")
    changed = build_unknown_execution_event_v2(_fields(filled_quantity=0.06))
    assert execution_fact_key_v2(first, namespace="synthetic") != execution_fact_key_v2(
        changed, namespace="synthetic"
    )
    corrupted = first.model_copy(update={"fee_usd": 0})
    with pytest.raises(ValueError):
        execution_fact_key_v2(corrupted, namespace="synthetic")


def _engine_and_trade():
    decision = _decision()
    engine = object.__new__(ResearchFeeV2ProductionEngine)
    engine.settings = SimpleNamespace(service_name="synthetic-research")
    engine._lifecycle_scope = SimpleNamespace(
        trading_mode=decision.trading_mode,
        profile=decision.evedex_profile,
        event_namespace="synthetic",
    )
    engine.clock = lambda: datetime.fromtimestamp(decision.decided_at_ms / 1000, UTC)
    trade = SimpleNamespace(
        trade_id=decision.trade_id,
        account_id=decision.account_id,
        strategy_id=decision.intent.strategy_id,
        strategy_revision=decision.intent.strategy_revision,
        strategy_intent_id=decision.intent.intent_id,
    )
    engine.trades = SimpleNamespace(
        get=AsyncMock(return_value=trade),
        get_execution_contract_version=AsyncMock(return_value="trade-execution-event.v2"),
    )
    return engine, decision, trade


@pytest.mark.asyncio
async def test_opt_in_v2_for_new_trade_and_durable_v1_for_existing_trade():
    engine, decision, trade = _engine_and_trade()
    async with engine._research_contract_scope(trade.trade_id):
        _, build = engine._event_spec(
            decision,
            trade,
            TradeExecutionEventType.ENTRY_PARTIAL_FILL,
            TradeLifecycleState.PROTECTING,
            order_role=OrderRole.ENTRY,
            client_order_id="synthetic-order-id",
            filled_quantity=0.05,
            position_quantity=0.05,
            fee_usd=0,
        )
        assert build(1).fee_usd is None
        assert engine._order_fee_usd({"fee": [{"coin": "BTC", "quantity": 0.1}]}, required=True) is None
    engine.trades.get_execution_contract_version.return_value = "trade-execution-event.v1"
    engine._operational_telemetry = {}
    async with engine._research_contract_scope(trade.trade_id):
        _, build = engine._event_spec(
            decision,
            trade,
            TradeExecutionEventType.ENTRY_PARTIAL_FILL,
            TradeLifecycleState.PROTECTING,
        )
        assert type(build(1)) is TradeExecutionEventV1
        assert engine._order_fee_usd({"fee": []}, required=True) == 0
    engine.trades.get_execution_contract_version.return_value = None
    with pytest.raises(PaperExecutionSafetyError, match="no verified event version"):
        async with engine._research_contract_scope(trade.trade_id):
            pass


@pytest.mark.asyncio
async def test_replay_reuses_original_id_but_rejects_changed_nonvolatile_source():
    engine, decision, trade = _engine_and_trade()
    async with engine._research_contract_scope(trade.trade_id):
        key, build = engine._event_spec(
            decision,
            trade,
            TradeExecutionEventType.DECISION_RECEIVED,
            TradeLifecycleState.RECEIVED,
        )
        stored = build(1)
        engine.clock = lambda: datetime.fromtimestamp((stored.occurred_at_ms + 1000) / 1000, UTC)
        same_key, rebuild = engine._event_spec(
            decision,
            trade,
            TradeExecutionEventType.DECISION_RECEIVED,
            TradeLifecycleState.RECEIVED,
        )
        assert key == same_key
        assert engine._replay_execution_event_builder(stored, rebuild)(1) == stored
        engine.settings.service_name = "different-source"
        _, conflicting = engine._event_spec(
            decision,
            trade,
            TradeExecutionEventType.DECISION_RECEIVED,
            TradeLifecycleState.RECEIVED,
        )
        with pytest.raises(PaperExecutionSafetyError, match="replay conflicts"):
            engine._replay_execution_event_builder(stored, conflicting)


def test_research_service_routes_only_exact_known_versions():
    event = build_unknown_execution_event_v2(_fields())
    assert (
        ResearchFeeV2ExecutionService._trade_execution_event_topic(event) == "kairos.execution.trade_event.v2"
    )
    with pytest.raises(PaperExecutionSafetyError):
        ExecutionService._trade_execution_event_topic(event)
    with pytest.raises(PaperExecutionSafetyError):
        ResearchFeeV2ExecutionService._trade_execution_event_topic(object())


def test_shipping_engine_is_not_replaced_or_enabled():
    assert ResearchFeeV2ProductionEngine is not ProductionLifecycleEngine
    with pytest.raises(PaperExecutionSafetyError, match="durable per-trade"):
        ResearchFeeV2ProductionEngine._order_fee_usd({"fee": []}, required=True)


@pytest.mark.asyncio
async def test_research_service_decision_path_publishes_v2_on_v2_topic():
    decision = _decision()
    event = build_unknown_execution_event_v2(_fields())
    envelope = BusEnvelope(
        id="synthetic-risk", topic=Topics.RISK_TRADE_DECISION, payload=decision.to_payload()
    )
    bus = FakeBus({Topics.RISK_TRADE_DECISION: [envelope]})
    engine = SimpleNamespace(handle=AsyncMock(return_value=PaperExecutionResult(events=(event,))))
    service = object.__new__(ResearchFeeV2ExecutionService)
    service.settings = SimpleNamespace(trading_mode=TradingMode.PAPER)
    service.bus = bus
    service.engine = None
    service.paper_engine = engine
    service._account_refresh = asyncio.Queue(maxsize=1)
    await service._consume_paper_decisions()
    assert bus.published == [(Topics.TRADE_EXECUTION_EVENT_V2, event)]
    assert bus.events == ["publish", "ack"]


@pytest.mark.asyncio
async def test_research_service_recovery_path_publishes_v2_on_v2_topic(monkeypatch):
    event = build_unknown_execution_event_v2(_fields())
    bus = FakeBus()
    engine = SimpleNamespace(recovery_blocked=False, reconcile_once=AsyncMock(return_value=[event]))
    service = object.__new__(ResearchFeeV2ExecutionService)
    service.settings = SimpleNamespace(trading_mode=TradingMode.PAPER, journal_recovery_interval_s=1)
    service.bus = bus
    service.engine = None
    service.paper_engine = engine
    service._account_refresh = asyncio.Queue(maxsize=1)
    service._log_paper_telemetry = lambda: None
    calls = 0

    async def one_iteration(_delay):
        nonlocal calls
        calls += 1
        if calls > 1:
            raise asyncio.CancelledError

    monkeypatch.setattr(asyncio, "sleep", one_iteration)
    with pytest.raises(asyncio.CancelledError):
        await service._reconcile_paper_lifecycle()
    assert bus.published == [(Topics.TRADE_EXECUTION_EVENT_V2, event)]


@pytest.mark.asyncio
async def test_fee_update_is_standalone_incomplete_and_never_implies_position():
    prior = build_unknown_execution_event_v2(_fields())
    fee = ExecutionFeeBundleV2(
        scope_kind="ORDER",
        scope_reference=prior.fee.scope_reference,
        coverage="INCOMPLETE",
        components=(
            ExecutionFeeComponentV2(
                component_id="synthetic-fee-1",
                asset="USDT",
                amount="0.001",
                precision="APPROXIMATE",
                source_id="synthetic-source",
                source_version="1",
                source_received_at_ms=prior.occurred_at_ms,
            ),
        ),
        usd_status="UNKNOWN",
        supersedes_event_id=prior.event_id,
    )
    repo = SimpleNamespace(
        get_execution_contract_version=AsyncMock(return_value="trade-execution-event.v2"),
        get=AsyncMock(return_value=SimpleNamespace(state=TradeState.ACTIVE, state_version=3)),
        get_execution_event_with_state_version=AsyncMock(return_value=None),
        append_execution_event=AsyncMock(
            side_effect=lambda trade_id, *, fact_key, expected_state_version, build: build(9)
        ),
    )
    updated = await append_research_fee_update_v2(
        repo,
        previous=prior,
        fee=fee,
        occurred_at_ms=prior.occurred_at_ms + 1,
        namespace="synthetic",
        source_fact_id="c" * 64,
    )
    assert updated.event_type == "FEE_UPDATED" and updated.event_seq == 9
    assert updated.fee.supersedes_event_id == prior.event_id
    assert ("fee_source_fact_id", "c" * 64) in updated.details
    assert updated.fee_usd is None
    assert updated.requested_quantity is updated.filled_quantity is updated.position_quantity is None
    assert repo.append_execution_event.await_args.kwargs["expected_state_version"] == 3

    for unsafe_id in ("", "c" * 63, "C" * 64, "c" * 64 + "\n"):
        with pytest.raises(ValueError, match="SHA-256"):
            await append_research_fee_update_v2(
                repo,
                previous=prior,
                fee=fee,
                occurred_at_ms=prior.occurred_at_ms + 1,
                namespace="synthetic",
                source_fact_id=unsafe_id,
            )

    with pytest.raises(ValueError, match="matching incomplete source scope"):
        await append_research_fee_update_v2(
            repo,
            previous=prior,
            fee=fee.model_copy(update={"scope_reference": "other-order"}),
            occurred_at_ms=prior.occurred_at_ms + 1,
            namespace="synthetic",
            source_fact_id="c" * 64,
        )

    repo.get.return_value = SimpleNamespace(state=TradeState.FLAT, state_version=9)
    repo.get_execution_event_with_state_version.return_value = (updated, 3)
    replayed = await append_research_fee_update_v2(
        repo,
        previous=prior,
        fee=fee,
        occurred_at_ms=prior.occurred_at_ms + 1,
        namespace="synthetic",
        source_fact_id="c" * 64,
    )
    assert replayed == updated
    assert repo.append_execution_event.await_args.kwargs["expected_state_version"] == 3
    with pytest.raises(ValueError, match="replay conflicts"):
        await append_research_fee_update_v2(
            repo,
            previous=prior,
            fee=fee,
            occurred_at_ms=prior.occurred_at_ms + 2,
            namespace="synthetic",
            source_fact_id="c" * 64,
        )
    with pytest.raises(ValueError, match="replay conflicts"):
        await append_research_fee_update_v2(
            repo,
            previous=prior,
            fee=fee.model_copy(update={"coverage": "UNKNOWN", "components": ()}),
            occurred_at_ms=prior.occurred_at_ms + 1,
            namespace="synthetic",
            source_fact_id="c" * 64,
        )


@pytest.mark.asyncio
async def test_reconciliation_ignores_fee_update_for_lifecycle_count_not_finality():
    first = build_unknown_execution_event_v2(
        _fields(
            event_seq=1,
            event_type=TradeExecutionEventType.DECISION_RECEIVED,
            lifecycle_state=TradeLifecycleState.RECEIVED,
            effect_id=None,
            order_role=None,
            client_order_id=None,
            filled_quantity=0,
            position_quantity=0,
            average_price=None,
        )
    )
    partial = build_unknown_execution_event_v2(_fields(event_seq=2))
    fee = ExecutionFeeBundleV2(
        scope_kind="ORDER",
        scope_reference=partial.client_order_id,
        coverage="UNKNOWN",
        usd_status="UNKNOWN",
        supersedes_event_id=partial.event_id,
    )
    fee_event = type(partial).model_validate(
        {
            **partial.model_dump(mode="python", exclude={"event_id", "message_id", "produced_at"}),
            "event_seq": 3,
            "event_type": "FEE_UPDATED",
            "fee": fee,
            "requested_quantity": None,
            "filled_quantity": None,
            "position_quantity": None,
            "average_price": None,
            "fee_usd": None,
        }
    )
    final = build_unknown_execution_event_v2(
        _fields(
            event_seq=4,
            event_type=TradeExecutionEventType.EXIT_FILLED,
            lifecycle_state=TradeLifecycleState.FLAT,
            order_role=OrderRole.TIMEOUT_EXIT,
            filled_quantity=0.05,
            position_quantity=0,
            exit_reason=TradeExitReason.TIMEOUT,
        )
    )
    binding = SimpleNamespace(trade_id=partial.trade_id, decision_id=partial.risk_decision_id)
    trade = SimpleNamespace(account_id=partial.account_id, state_version=2)
    evidence = SimpleNamespace(closed_quantity=1, entry_filled_quantity=1)
    await ProductionReservationReconciler._verify_facts(
        [first, partial, fee_event, final], binding, trade, evidence
    )
    altered = fee_event.model_copy(update={"lifecycle_state": TradeLifecycleState.FLAT})
    with pytest.raises(ProductionReconciliationError, match="fee update changed"):
        await ProductionReservationReconciler._verify_facts(
            [first, partial, altered, final], binding, trade, evidence
        )
