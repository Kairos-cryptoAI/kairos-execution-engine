"""Pure orchestration tests for the PROD closed-account reconciliation hook.

The reconciler below is deliberately a synthetic fixture: these tests prove
that the lifecycle passes the right identities and refuses unsafe projections;
they do not claim real EVEDEX evidence or reservation-release authority.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from types import SimpleNamespace
from uuid import UUID

import pytest
from kairos_core.contracts import AccountSnapshotV2
from kairos_core.enums import EvedexProfile, TradingMode
from kairos_persistence import TradeState

from kairos_execution.paper_engine import PaperExecutionSafetyError
from kairos_execution.production_lifecycle import (
    ProductionLifecycleEngine,
    _production_policy,
)
from kairos_execution.production_readiness import canonical_digest
from kairos_execution.production_reconciliation import ProductionReservationReconciler
from tests.test_production_lifecycle import _config
from tests.test_production_lifecycle_binding import _decision

_DATABASE_UUID = UUID("d5f8f2e9-04a5-4c50-9d25-7e8baab459b1")


def _snapshot(config, *, positions=()):
    return AccountSnapshotV2(
        trading_mode=TradingMode.LIVE,
        evedex_profile=EvedexProfile.PROD,
        source="synthetic-closed-account-test",
        account_id=config.context.remote_account_id,
        equity_usd=1000,
        available_balance_usd=1000,
        margin_used_usd=0,
        durable_day_start_equity_usd=1000,
        durable_peak_equity_usd=1000,
        positions=positions,
        open_orders=(),
        captured_at_ms=1_800_000_000_000,
        reconciliation_seq=7,
        reconciled=True,
    )


class _SyntheticTerminalReconciler(ProductionReservationReconciler):
    """Fixture-only stub; it performs no source verification or DB writes."""

    def __init__(self, *, context, database_uuid, trades, effects):
        self.context = context
        self.database_uuid = database_uuid
        self.trades = trades
        self.effects = effects
        self.calls = []

    async def reconcile_terminal(self, *, binding, raw_venue_evidence, source_id):
        self.calls.append((binding, raw_venue_evidence, source_id))
        return {"fixture_only": True, "receipt_id": "synthetic-fixture-receipt"}


class _Trades:
    def __init__(self, trade):
        self.trade = trade
        self.lock_scopes = []

    @asynccontextmanager
    async def account_lock(self, **scope):
        self.lock_scopes.append(scope)
        yield

    async def get(self, trade_id):
        return self.trade if self.trade.trade_id == trade_id else None


class _BindingStore:
    def __init__(self, binding):
        self.binding = binding
        self.requested_effect_ids = []

    async def get(self, effect_id):
        self.requested_effect_ids.append(effect_id)
        return self.binding


class _EngineHarness(ProductionLifecycleEngine):
    """Production method with only its DB/venue-facing orchestration hooks stubbed."""

    def __init__(self, *, config, trades, effects, plan, snapshot):
        self.production_settings = config
        self.production_runtime = SimpleNamespace(database_uuid=_DATABASE_UUID)
        self._lifecycle_policy = _production_policy(config)
        self._lifecycle_scope = self._lifecycle_policy.scope
        self.trades = trades
        self.effects = effects
        self.adapter = SimpleNamespace(bindings=_BindingStore(plan))
        self._lifecycle_lock = asyncio.Lock()
        self.synthetic_snapshot = snapshot
        self.reconcile_passes = 0
        self.snapshot_passes = 0

    async def _reconcile_once_unlocked(self):
        self.reconcile_passes += 1

    async def _account_snapshot_unlocked(self):
        self.snapshot_passes += 1
        return self.synthetic_snapshot


def _fixture(*, positions=()):
    config = _config()
    environment = _production_policy(config).scope.environment
    lifecycle_effect_id = "a" * 64
    signing_effect_id = "b" * 64
    decision = _decision()
    trade_id = decision.trade_id
    plan = SimpleNamespace(
        trade_id=trade_id,
        context=config.context,
        signing_effect_id=signing_effect_id,
        lifecycle_effect_id=lifecycle_effect_id,
        role="ENTRY",
        decision_id=decision.decision_id,
        risk_decision_id=decision.decision_id,
        decision_sha256=canonical_digest(decision),
        request=SimpleNamespace(request_id="fixture-signing-request"),
    )
    trade = SimpleNamespace(
        trade_id=trade_id,
        state=TradeState.FLAT,
        environment=environment,
        risk_decision_id=decision.decision_id,
        risk_decision_payload=decision.to_payload(),
        strategy_intent_id=decision.intent.intent_id,
        symbol=decision.intent.symbol,
        entry_client_order_id="fixture-entry-client-order",
        entry_exchange_order_id="fixture-entry-exchange-parent",
    )
    trades = _Trades(trade)
    effects = object()
    engine = _EngineHarness(
        config=config,
        trades=trades,
        effects=effects,
        plan=plan,
        snapshot=_snapshot(config, positions=positions),
    )
    from kairos_core.enums import OrderRole

    plan.lifecycle_effect_id = engine._effect_id(trade_id, OrderRole.ENTRY, "place")
    engine.adapter.bindings.binding = plan
    reconciler = _SyntheticTerminalReconciler(
        context=config.context,
        database_uuid=_DATABASE_UUID,
        trades=trades,
        effects=effects,
    )
    return config, engine, reconciler, plan, trade


@pytest.mark.asyncio
async def test_closed_account_passes_exact_distinct_signing_and_lifecycle_effect_ids():
    config, engine, reconciler, plan, trade = _fixture()

    result = await engine.reconcile_closed_account(
        trade_id=trade.trade_id,
        reconciler=reconciler,
        source_id="fixture-only-source",
        raw_venue_evidence={"synthetic_fixture": True},
    )

    assert engine.reconcile_passes == engine.snapshot_passes == 1
    assert engine.trades.lock_scopes == [engine._remote_account_scope]
    assert engine.adapter.bindings.requested_effect_ids == [plan.lifecycle_effect_id]
    assert len(reconciler.calls) == 1
    binding, raw_evidence, source_id = reconciler.calls[0]
    assert binding.trade_id == trade.trade_id
    assert binding.decision_id == trade.risk_decision_id
    assert binding.effect_id == plan.signing_effect_id
    assert binding.lifecycle_entry_effect_id == plan.lifecycle_effect_id
    assert binding.signing_request_id == plan.request.request_id
    assert binding.client_order_id == trade.entry_client_order_id
    assert binding.exchange_parent_order_id == trade.entry_exchange_order_id
    assert raw_evidence == {"synthetic_fixture": True}
    assert source_id == "fixture-only-source"
    assert result["account_snapshot_sha256"] == canonical_digest(engine.synthetic_snapshot)
    assert result["terminal_receipt"]["fixture_only"] is True
    assert result["reservation_released"] is False
    assert result["live_ready"] is False
    assert config.context == reconciler.context


@pytest.mark.asyncio
async def test_closed_account_refuses_remaining_position_before_terminal_reconciler():
    config = _config()
    position = SimpleNamespace(venue_symbol="BTCUSD", trade_id="unrelated-fixture-position")
    # Snapshot validation requires the real DTO. The nonempty position is a
    # deliberately minimal object because the method refuses before hashing it.
    engine = _BareUnsafeSnapshotHarness(
        config=config, snapshot=SimpleNamespace(positions=(position,), open_orders=(), reconciled=True)
    )
    reconciler = _SyntheticTerminalReconciler(
        context=config.context,
        database_uuid=_DATABASE_UUID,
        trades=engine.trades,
        effects=engine.effects,
    )

    with pytest.raises(PaperExecutionSafetyError, match="not authoritatively reconciled and flat"):
        await engine.reconcile_closed_account(
            trade_id=engine.trades.trade.trade_id,
            reconciler=reconciler,
            source_id="fixture-only-source",
            raw_venue_evidence={"synthetic_fixture": True},
        )

    assert reconciler.calls == []
    assert engine.adapter.bindings.requested_effect_ids == []


class _BareUnsafeSnapshotHarness(_EngineHarness):
    """Harness permits an invalid projection solely to test pre-proof refusal."""

    def __init__(self, *, config, snapshot):
        environment = _production_policy(config).scope.environment
        self.trade = SimpleNamespace(
            trade_id="c" * 64,
            state=TradeState.FLAT,
            environment=environment,
            risk_decision_id="e" * 64,
            entry_client_order_id="fixture-entry-client-order",
            entry_exchange_order_id="fixture-entry-exchange-parent",
        )
        trades = _Trades(self.trade)
        plan = SimpleNamespace(
            trade_id=self.trade.trade_id,
            context=config.context,
            signing_effect_id="b" * 64,
            lifecycle_effect_id="a" * 64,
            role="ENTRY",
            request=SimpleNamespace(request_id="fixture-signing-request"),
        )
        super().__init__(
            config=config,
            trades=trades,
            effects=object(),
            plan=plan,
            snapshot=snapshot,
        )
        from kairos_core.enums import OrderRole

        plan.lifecycle_effect_id = self._effect_id(self.trade.trade_id, OrderRole.ENTRY, "place")
        self.adapter.bindings.binding = plan


@pytest.mark.asyncio
async def test_closed_account_reconciler_with_different_context_is_rejected_without_work():
    config, engine, _reconciler, _plan, trade = _fixture()
    mismatched_context = config.context.model_copy(update={"remote_account_id": "other-prod-account"})
    reconciler = _SyntheticTerminalReconciler(
        context=mismatched_context,
        database_uuid=_DATABASE_UUID,
        trades=engine.trades,
        effects=engine.effects,
    )

    with pytest.raises(PaperExecutionSafetyError, match="terminal reconciler differs"):
        await engine.reconcile_closed_account(
            trade_id=trade.trade_id,
            reconciler=reconciler,
            source_id="fixture-only-source",
            raw_venue_evidence={"synthetic_fixture": True},
        )

    assert engine.reconcile_passes == engine.snapshot_passes == 0
    assert engine.trades.lock_scopes == []
    assert reconciler.calls == []
