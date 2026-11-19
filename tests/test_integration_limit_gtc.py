"""Disposable-PG native FSM tests with a synthetic GTC venue and authority."""

import asyncio
import copy
from datetime import timedelta
from decimal import Decimal

import pytest
from kairos_core.enums import EvedexProfile, OrderRole, TradeExecutionEventType
from kairos_persistence import EffectStatus, ExecutionJournalRepository, TradeLifecycleRepository, TradeState

from kairos_execution.limit_gtc_contract import LimitGtcEntryV1
from kairos_execution.managed_signer import CustodyBindingV1, reviewed_schema_sha256
from kairos_execution.production_cancellation import (
    ProductionCancellationError,
    ProductionCancellationVerifier,
)
from kairos_execution.production_lifecycle import (
    ProductionLifecycleConfigV1,
    ProductionLifecycleEngine,
    ProductionVenueHealthV1,
)
from kairos_execution.production_lifecycle_adapter import ManagedProductionLifecycleAdapter
from kairos_execution.production_lifecycle_binding import build_production_lifecycle_binding
from kairos_execution.production_readiness import ProductionContextV1, canonical_digest
from kairos_execution.profiles import profile_params
from tests.test_integration_production_lifecycle import (
    _BindingStore,
    _ProductionReads,
    _runtime,
    _synthetic_authority,
    _SyntheticCancellationTransport,
    _SyntheticCancellationVenueSource,
    _SyntheticVenue,
)
from tests.test_production_lifecycle_binding import _decision

pytest_plugins = ("tests.test_integration_production_lifecycle",)
pytestmark = pytest.mark.integration


class GtcVenue(_SyntheticVenue):
    def __init__(self, clock, account_id, *, partial):
        super().__init__(clock, account_id)
        self.partial = partial

    def partial_entry(self, body):
        assert "timeInForce" not in body  # native default is GTC
        result = super().partial_entry({**body, "timeInForce": "IOC"})
        result["leverage"] = 1
        for row in self.state["orders"] + self.state["order_history"]:
            row["leverage"] = 1
        if not self.partial:
            self.state["positions"] = []
            self.state["balance"]["positions"] = []
            result.update(status="NEW", unFilledQuantity=result["quantity"], filledAvgPrice=0)
            self.state["orders"] = [copy.deepcopy(result)]
            self.state["balance"]["openOrders"] = [copy.deepcopy(result)]
            self.state["order_history"] = [copy.deepcopy(result)]
        if getattr(self, "lose_ack", False):
            raise asyncio.CancelledError("synthetic process interruption after accepted entry, before ACK")
        return result


async def _setup(database, clock, *, partial=False, unknown_cancel=False, lose_ack=False):
    decision = _decision()
    context = ProductionContextV1(
        remote_account_id=decision.account_id,
        adaptive_system_id=decision.intent.strategy_id,
        frozen_policy_sha256="1" * 64,
        source_set_sha256="2" * 64,
    )
    custody = CustodyBindingV1(
        context=context,
        custody_reference="synthetic:custody",
        wallet_address="0x" + "12" * 20,
        chain_id=161803,
        schema_sha256=reviewed_schema_sha256(161803),
        approved_instruments=("BTCUSD", "ETHUSD", "SOLUSD", "BNBUSD", "XRPUSD"),
        custody_receipt_sha256="3" * 64,
    )
    config = ProductionLifecycleConfigV1(
        context=context,
        custody_binding=custody,
        strategy_revision=decision.intent.strategy_revision,
        expected_health=ProductionVenueHealthV1(
            chain_id=custody.chain_id,
            exchange_url=profile_params(EvedexProfile.PROD).exchange_url,
            auth_url=profile_params(EvedexProfile.PROD).auth_url,
            sdk_version="1.2.11",
        ),
        service_name="synthetic-native-gtc-test",
        entry_order_type="LIMIT_GTC",
        symbol_map={
            "BTCUSDT": "BTCUSD",
            "ETHUSDT": "ETHUSD",
            "SOLUSDT": "SOLUSD",
            "BNBUSDT": "BNBUSD",
            "XRPUSDT": "XRPUSD",
        },
    )
    venue = GtcVenue(clock, context.remote_account_id, partial=partial)
    venue.lose_ack = lose_ack
    source, claims, auth, signer, dbid, backend = _synthetic_authority(
        clock=clock, context=context, binding=custody, pool=database.pool
    )
    runtime = _runtime(
        clock=clock,
        context=context,
        binding=custody,
        source=source,
        claims=claims,
        authorization=auth,
        signer=signer,
        database_uuid=dbid,
        venue=venue,
        limit_time_in_force="GTC",
    )
    trades, effects = TradeLifecycleRepository(database.pool), ExecutionJournalRepository(database.pool)
    bindings = _BindingStore(context, database.pool)
    cancel_source = _SyntheticCancellationVenueSource(context=context, venue=venue, clock=clock)
    transport = _SyntheticCancellationTransport(venue)
    if unknown_cancel:

        async def unknown(**kwargs):
            venue.calls.append("CANCEL_UNKNOWN")
            raise TimeoutError("synthetic unknown cancellation")

        transport.cancel_order = unknown
    cancellations = ProductionCancellationVerifier(
        claims=claims,
        state_source=source,
        bindings=bindings,
        custody_binding=custody,
        trades=trades,
        effects=effects,
        venue_sources={cancel_source.source_id: cancel_source},
        transport=transport,
        database_uuid=dbid,
        context=context,
        preconditions=source.preconditions,
        owner_key=source.owner_key,
        expected_owner_key_sha256=canonical_digest(source.owner_key),
        expected_owner_identity=source.owner_key.owner_identity,
        maximum_arm_lifetime=timedelta(minutes=5),
        clock=clock,
    )
    adapter = ManagedProductionLifecycleAdapter(
        runtime=runtime,
        reads=_ProductionReads(venue, clock, context),
        bindings=bindings,
        trades=trades,
        effects=effects,
        cancellations=cancellations,
        clock=clock,
        entry_order_type="LIMIT_GTC",
    )

    async def sleep(seconds):
        clock.value += timedelta(seconds=seconds)

    engine = ProductionLifecycleEngine(adapter, trades, effects, config, runtime, clock=clock, sleeper=sleep)
    assert await engine.initialize_recovery() == ()
    now = clock()
    deadline = int((now + timedelta(seconds=4)).timestamp() * 1000)
    source.decision = decision
    for role, operation in (
        (OrderRole.ENTRY, "place"),
        (OrderRole.STOP_LOSS, "create"),
        (OrderRole.TAKE_PROFIT, "create"),
    ):
        effect = engine._effect_id(decision.trade_id, role, operation)
        parent = engine._client_id(decision.trade_id, OrderRole.ENTRY, decision.decided_at_ms)
        plan = build_production_lifecycle_binding(
            decision=decision,
            context=context,
            custody_binding=custody,
            role=role.value,
            lifecycle_effect_id=effect,
            client_order_id=engine._client_id(decision.trade_id, role, decision.decided_at_ms),
            parent_order_id=parent if role is not OrderRole.ENTRY else None,
            manual_request_sha256=source.manual_request_sha256,
            expires_at=now + timedelta(seconds=4),
            now=now,
            limit_gtc_entry=LimitGtcEntryV1(cancel_after_ms=deadline) if role is OrderRole.ENTRY else None,
        )
        bindings.plans[effect] = plan
        source.plans[plan.request.request_id] = plan
    return engine, decision, venue, bindings, deadline


@pytest.mark.asyncio
async def test_gtc_new_deadline_cancel_flat_uses_real_fsm_and_pg(production_pg_runtime):
    database, clock = production_pg_runtime
    engine, decision, venue, _, deadline = await _setup(database, clock)
    result = await engine.handle(decision)
    trade = await engine.trades.get(decision.trade_id)
    assert trade.state is TradeState.CANCELLED
    assert int(clock().timestamp() * 1000) >= deadline
    assert venue.calls == ["ENTRY", "CANCEL_ENTRY"]
    assert venue.state["positions"] == venue.state["orders"] == []
    assert any(e.event_type is TradeExecutionEventType.ENTRY_CANCELLED for e in result.events)


@pytest.mark.asyncio
async def test_gtc_partial_protected_before_cancel_and_restart_does_not_renew_deadline(production_pg_runtime):
    database, clock = production_pg_runtime
    engine, decision, venue, bindings, deadline = await _setup(database, clock, partial=True)
    await engine.handle(decision)
    assert venue.calls == ["ENTRY", "STOP_LOSS", "TAKE_PROFIT", "CANCEL_ENTRY"]
    assert len(venue.state["tpsl"]) == 2 and venue.state["positions"][0]["quantity"] > 0
    assert (await engine.trades.get(decision.trade_id)).state is TradeState.ACTIVE
    clock.value += timedelta(seconds=10)
    restarted = ProductionLifecycleEngine(
        engine.adapter,
        engine.trades,
        engine.effects,
        engine.production_settings,
        engine.production_runtime,
        clock=clock,
        sleeper=engine._sleep,
    )
    assert await restarted.initialize_recovery() == ()
    await restarted.handle(decision)
    assert venue.calls.count("ENTRY") == venue.calls.count("CANCEL_ENTRY") == 1
    plan = bindings.plans[engine._effect_id(decision.trade_id, OrderRole.ENTRY, "place")]
    assert plan.limit_gtc_entry.cancel_after_ms == deadline
    # Exact GTC journal metadata and a native explicit GTC history record must
    # remain valid ownership proof for timeout/emergency close after restart.
    venue.state["order_history"][0]["timeInForce"] = "GTC"
    await restarted._assert_terminal_entry_before_close(
        decision, await engine.trades.get(decision.trade_id), venue.state
    )


@pytest.mark.asyncio
async def test_gtc_unknown_cancel_stays_prepared_and_blocks_entries(production_pg_runtime):
    database, clock = production_pg_runtime
    engine, decision, venue, _, _ = await _setup(database, clock, unknown_cancel=True)
    with pytest.raises(ProductionCancellationError, match="cancellation outcome unresolved"):
        await engine.handle(decision)
    cancel = await engine.effects.get(engine._effect_id(decision.trade_id, OrderRole.ENTRY, "cancel"))
    assert cancel.status is EffectStatus.PREPARED
    assert venue.state["orders"]
    assert not await engine.trades.entries_allowed(
        environment=engine._environment, account_id=engine._lifecycle_scope.account_id, exchange="evedex"
    )
    assert venue.calls.count("ENTRY") == venue.calls.count("CANCEL_UNKNOWN") == 1


@pytest.mark.asyncio
async def test_gtc_unknown_cancellation_restart_keeps_original_cutoff_and_no_retry(production_pg_runtime):
    database, clock = production_pg_runtime
    engine, decision, venue, bindings, deadline = await _setup(database, clock, unknown_cancel=True)
    with pytest.raises(ProductionCancellationError, match="cancellation outcome unresolved"):
        await engine.handle(decision)
    clock.value += timedelta(seconds=1)
    restarted = ProductionLifecycleEngine(
        engine.adapter,
        engine.trades,
        engine.effects,
        engine.production_settings,
        engine.production_runtime,
        clock=clock,
        sleeper=engine._sleep,
    )
    await restarted.initialize_recovery()
    assert restarted.recovery_blocked
    assert not await restarted.trades.entries_allowed(
        environment=restarted._environment,
        account_id=restarted._lifecycle_scope.account_id,
        exchange="evedex",
    )
    assert venue.calls.count("ENTRY") == venue.calls.count("CANCEL_UNKNOWN") == 1
    origin = bindings.plans[engine._effect_id(decision.trade_id, OrderRole.ENTRY, "place")]
    assert origin.limit_gtc_entry.cancel_after_ms == deadline < int(clock().timestamp() * 1000)


@pytest.mark.asyncio
async def test_gtc_restart_after_new_ack_protects_later_fill_before_cancel(production_pg_runtime):
    database, clock = production_pg_runtime
    engine, decision, venue, bindings, deadline = await _setup(database, clock)

    async def crash_after_ack(_):
        assert (await engine.trades.get(decision.trade_id)).entry_exchange_order_id
        raise asyncio.CancelledError("synthetic process interruption after durable NEW ACK")

    engine._sleep = crash_after_ack
    with pytest.raises(asyncio.CancelledError):
        await engine.handle(decision)
    assert (await engine.trades.get(decision.trade_id)).state is TradeState.ENTRY_PENDING
    assert venue.calls == ["ENTRY"]
    clock.value += timedelta(seconds=5)
    # The resting order fills while the host is down; this is venue state,
    # not a replayed submit or a changed immutable entry plan.
    for row in venue.state["orders"] + venue.state["order_history"]:
        row.update(status="PARTIALLY_FILLED", unFilledQuantity=decision.quantity / 2, filledAvgPrice=100)
    venue.state["balance"]["openOrders"] = copy.deepcopy(venue.state["orders"])
    venue.state["positions"] = [
        {
            "instrument": "BTCUSD",
            "side": "BUY",
            "quantity": decision.quantity / 2,
            "avgPrice": 100,
            "markPrice": 100,
            "leverage": 1,
            "unRealizedPnL": 0,
        }
    ]
    venue.state["balance"]["positions"] = [
        {"instrument": "BTCUSD", "side": "BUY", "volume": decision.quantity / 2, "initialMargin": 5}
    ]
    source = engine.production_runtime.state_source
    # Recovery may stage new reduction-only protection leases; the original
    # entry binding and its already-passed cancellation cutoff stay unchanged.
    for role in (OrderRole.STOP_LOSS, OrderRole.TAKE_PROFIT):
        old = bindings.plans[engine._effect_id(decision.trade_id, role, "create")]
        fresh = build_production_lifecycle_binding(
            decision=decision,
            context=engine.production_settings.context,
            custody_binding=engine.production_settings.custody_binding,
            role=role.value,
            lifecycle_effect_id=old.lifecycle_effect_id,
            client_order_id=engine._client_id(decision.trade_id, role, decision.decided_at_ms),
            parent_order_id=engine._client_id(decision.trade_id, OrderRole.ENTRY, decision.decided_at_ms),
            manual_request_sha256=source.manual_request_sha256,
            expires_at=clock() + timedelta(seconds=4),
            now=clock(),
        )
        bindings.plans[fresh.lifecycle_effect_id] = fresh
        source.plans[fresh.request.request_id] = fresh
    restarted = ProductionLifecycleEngine(
        engine.adapter,
        engine.trades,
        engine.effects,
        engine.production_settings,
        engine.production_runtime,
        clock=clock,
    )
    assert await restarted.initialize_recovery() == ()
    assert venue.calls == ["ENTRY", "STOP_LOSS", "TAKE_PROFIT", "CANCEL_ENTRY"]
    assert (await engine.trades.get(decision.trade_id)).state is TradeState.ACTIVE
    assert (
        bindings.plans[
            engine._effect_id(decision.trade_id, OrderRole.ENTRY, "place")
        ].limit_gtc_entry.cancel_after_ms
        == deadline
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("wire_terminal", ["UNRESOLVED", None])
async def test_gtc_lost_ack_fill_is_protected_inside_ambiguity_grace_without_resend(
    production_pg_runtime, wire_terminal
):
    database, clock = production_pg_runtime
    engine, decision, venue, bindings, _ = await _setup(database, clock, partial=True, lose_ack=True)
    with pytest.raises(asyncio.CancelledError):
        await engine.handle(decision)
    entry_key = engine._effect_id(decision.trade_id, OrderRole.ENTRY, "place")
    assert (await engine.effects.get(entry_key)).status is EffectStatus.PREPARED
    assert (await engine.trades.get(decision.trade_id)).state is TradeState.ENTRY_PENDING
    plan = bindings.plans[entry_key]
    claims = engine.production_runtime.claims
    wire_key = (
        "WIRE_DISPATCH",
        f"wire:{canonical_digest(engine.production_settings.context)}",
        plan.signing_effect_id,
    )
    original_terminal = copy.deepcopy(claims.terminals[wire_key])
    assert original_terminal["terminal_status"] == "UNRESOLVED"
    if wire_terminal is None:
        claims.terminals.pop(wire_key)  # process killed before a wire terminal could be appended
        original_terminal = None
    # The actual production read parser returns Decimal for JSON numbers.
    # Its exact values must survive proof hashing and durable PG replay.
    for record in venue.state["orders"] + venue.state["order_history"]:
        for field in ("quantity", "unFilledQuantity", "limitPrice", "filledAvgPrice", "leverage"):
            record[field] = Decimal(str(record[field]))
    clock.value += timedelta(seconds=1)
    restarted = ProductionLifecycleEngine(
        engine.adapter,
        engine.trades,
        engine.effects,
        engine.production_settings,
        engine.production_runtime,
        clock=clock,
    )
    assert await restarted.initialize_recovery() == ()
    assert venue.calls == ["ENTRY", "STOP_LOSS", "TAKE_PROFIT", "CANCEL_ENTRY"]
    assert (await engine.effects.get(entry_key)).status is EffectStatus.RECONCILED
    durable_record = (await engine.effects.get(entry_key)).response_payload
    assert isinstance(durable_record["quantity"], str)
    assert Decimal(durable_record["quantity"]) == Decimal(str(decision.quantity))
    assert (await engine.trades.get(decision.trade_id)).state is TradeState.ACTIVE
    assert claims.terminals.get(wire_key) == original_terminal
    version = (await engine.trades.get(decision.trade_id)).state_version
    await restarted.handle(decision)  # emits already-journaled startup recovery facts once
    assert (await engine.trades.get(decision.trade_id)).state_version == version
    assert (await restarted.handle(decision)).events == ()
    assert venue.calls.count("ENTRY") == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault",
    [
        "missing_sign",
        "missing_wire",
        "conflicting_wire",
        "quantity",
        "price",
        "client",
        "record_absent",
        "leverage",
        "filled_with_remainder",
    ],
)
async def test_gtc_lost_ack_requires_exact_positive_order_and_scoped_claims(production_pg_runtime, fault):
    database, clock = production_pg_runtime
    engine, decision, venue, bindings, _ = await _setup(database, clock, partial=True, lose_ack=True)
    with pytest.raises(asyncio.CancelledError):
        await engine.handle(decision)
    plan = bindings.plans[engine._effect_id(decision.trade_id, OrderRole.ENTRY, "place")]
    claims = engine.production_runtime.claims
    wire_key = (
        "WIRE_DISPATCH",
        f"wire:{canonical_digest(engine.production_settings.context)}",
        plan.signing_effect_id,
    )
    if fault == "missing_sign":
        claims.claims.pop(
            (
                "TYPED_SIGNING",
                engine.production_settings.custody_binding.custody_reference,
                plan.request.request_id,
            )
        )
    elif fault == "missing_wire":
        claims.claims.pop(wire_key)
    elif fault == "conflicting_wire":
        claims.terminals[wire_key] = {"terminal_status": "REJECTED", "result_sha256": "f" * 64}
    elif fault == "record_absent":
        venue.state["orders"] = venue.state["order_history"] = []
    else:
        key, value = {
            "quantity": ("quantity", decision.quantity * 2),
            "price": ("limitPrice", decision.worst_entry_price + 1),
            "client": ("id", "00500:" + "F" * 26),
            "leverage": ("leverage", 2),
            "filled_with_remainder": ("status", "FILLED"),
        }[fault]
        for record in venue.state["orders"] + venue.state["order_history"]:
            record[key] = value
    clock.value += timedelta(seconds=1)
    restarted = ProductionLifecycleEngine(
        engine.adapter,
        engine.trades,
        engine.effects,
        engine.production_settings,
        engine.production_runtime,
        clock=clock,
    )
    assert await restarted.initialize_recovery()
    assert restarted.recovery_blocked
    assert venue.calls == ["ENTRY"]
