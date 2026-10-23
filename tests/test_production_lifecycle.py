"""Unit-only configuration and admission tests for the PROD lifecycle engine."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from kairos_core.enums import EvedexProfile
from kairos_persistence import TradeState
from pydantic import ValidationError

from kairos_execution.paper_engine import PaperExecutionSafetyError
from kairos_execution.production_lifecycle import (
    ProductionLifecycleConfigV1,
    ProductionLifecycleEngine,
    ProductionVenueHealthV1,
    _production_policy,
)
from kairos_execution.production_observation import PROD_EXCHANGE_ORIGIN
from kairos_execution.profiles import profile_params
from tests.test_production_lifecycle_binding import _decision, _scope


def _config():
    decision = _decision()
    context, custody = _scope(decision)
    return ProductionLifecycleConfigV1(
        context=context,
        custody_binding=custody,
        strategy_revision=decision.intent.strategy_revision,
        expected_health=ProductionVenueHealthV1(
            chain_id=custody.chain_id,
            exchange_url=PROD_EXCHANGE_ORIGIN,
            auth_url=profile_params(EvedexProfile.PROD).auth_url,
            sdk_version="1.2.11",
        ),
        service_name="kairos-production-execution",
        symbol_map={
            "BTCUSDT": "BTCUSD",
            "ETHUSDT": "ETHUSD",
            "SOLUSDT": "SOLUSD",
            "BNBUSDT": "BNBUSD",
            "XRPUSDT": "XRPUSD",
        },
    )


def _bare_engine(config=None):
    engine = object.__new__(ProductionLifecycleEngine)
    engine.production_settings = config or _config()
    engine._lifecycle_policy = _production_policy(engine.production_settings)
    engine._lifecycle_scope = engine._lifecycle_policy.scope
    engine.clock = lambda: datetime.now(UTC)
    engine._operational_telemetry = {}
    return engine


def _redelivery_engine(state=TradeState.ACTIVE):
    engine = _bare_engine()
    decision = _decision()
    trade = SimpleNamespace(
        state=state,
        trade_id=decision.trade_id,
        environment=engine._environment,
        account_id=decision.account_id,
        exchange="evedex",
        risk_decision_payload=decision.to_payload(),
        risk_decision_id=decision.decision_id,
        strategy_intent_id=decision.intent.intent_id,
        symbol=decision.intent.symbol,
    )
    engine.adapter = SimpleNamespace(name="evedex")
    engine.trades = SimpleNamespace(
        get=AsyncMock(return_value=trade),
        verify_chain=AsyncMock(return_value=True),
        entries_allowed=AsyncMock(return_value=True),
    )
    engine._recovery_blockers = ()
    engine._reconcile_redelivery_locked = AsyncMock(return_value=[])
    engine.clock = lambda: datetime.fromtimestamp((decision.venue_quality.expires_at_ms + 1) / 1000, tz=UTC)
    return engine, decision, trade


@pytest.mark.asyncio
async def test_prod_durable_redelivery_recovers_without_renewing_expired_entry_quote():
    engine, decision, trade = _redelivery_engine()
    result = await engine._handle_once(decision)
    assert result.events == ()
    engine._reconcile_redelivery_locked.assert_awaited_once_with(trade)


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ["scope", "chain", "startup"])
async def test_prod_redelivery_requires_exact_scope_chain_and_startup_recovery(fault):
    engine, decision, trade = _redelivery_engine()
    if fault == "scope":
        trade.environment = "another-environment"
    elif fault == "chain":
        engine.trades.verify_chain.return_value = False
    else:
        engine._recovery_blockers = ("startup-pending",)
    with pytest.raises(PaperExecutionSafetyError):
        await engine._handle_once(decision)
    engine._reconcile_redelivery_locked.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("state", [None, TradeState.RECEIVED])
async def test_prod_new_or_received_trade_keeps_expired_quote_refusal(state):
    engine, decision, _trade = _redelivery_engine(state)
    if state is None:
        engine.trades.get.return_value = None
    with pytest.raises(PaperExecutionSafetyError, match="expired"):
        await engine._handle_once(decision)
    engine._reconcile_redelivery_locked.assert_not_awaited()


def test_production_scope_is_context_namespaced_and_account_bound():
    config = _config()
    scope = _production_policy(config).scope
    from kairos_execution.production_readiness import canonical_digest

    digest = canonical_digest(config.context)
    assert scope.environment == f"PROD:{digest}:LIVE"
    assert scope.remote_environment == "evedex-prod"
    assert scope.account_id == config.context.remote_account_id
    assert scope.remote_account_id == config.context.remote_account_id
    assert scope.mutation_namespace == scope.event_namespace == f"prod.v1:{digest}"
    assert dict(scope.symbol_map) == config.symbol_map


@pytest.mark.parametrize(
    "updates",
    [
        {"chain_id": 1},
        {"exchange_url": "https://trading-api.evedex.tech"},
        {"auth_url": "https://auth-api.evedex.tech"},
    ],
)
def test_config_rejects_wrong_chain_or_non_prod_origin(updates):
    config = _config()
    health = config.expected_health.model_dump()
    health.update(updates)
    with pytest.raises(ValidationError):
        ProductionLifecycleConfigV1.model_validate({**config.model_dump(), "expected_health": health})


def test_config_requires_bijective_five_symbol_map_to_custody_allowlist():
    config = _config()
    with pytest.raises(ValidationError, match="bijectively cover"):
        ProductionLifecycleConfigV1.model_validate({**config.model_dump(), "symbol_map": {"BTC": "BTCUSD"}})


def test_expected_health_is_exact_and_entry_keeps_common_mutation_headroom():
    engine = _bare_engine()
    expected = engine._expected_venue_health()
    health = {
        **expected,
        "auth_age_ms": 5,
        "auth_expires_in_ms": 10_000,
        "local_mutation_rate_limit_capacity": 30,
        "local_mutation_rate_limit_reserve": 7,
        "local_mutation_rate_limit_window_ms": 60_000,
        "local_mutation_compensation_reserve": 4,
        "local_mutation_entry_min_reserve": 7,
        "venue_rate_limit_observable": False,
        "venue_rate_limit_reserve": None,
    }
    engine._accept_entry_health(health)
    assert dict(engine.operational_telemetry)["evedex_local_mutation_reserve"] == "7"
    with pytest.raises(PaperExecutionSafetyError):
        engine._accept_entry_health({**health, "local_mutation_rate_limit_reserve": 0})
    with pytest.raises(PaperExecutionSafetyError, match="pinned EVEDEX DEV profile"):
        engine._accept_health({**health, "chain_id": 16182})


def test_core_policy_requires_exact_context_strategy_and_revision():
    config = _config()
    engine = _bare_engine(config)
    decision = _decision()
    engine._assert_technical_canary_binding(decision)
    engine._lifecycle_policy.validate_decision_scope(decision)
    changed_intent = decision.intent.model_copy(update={"strategy_revision": "other"})
    with pytest.raises(ValueError, match="system revision"):
        _production_policy(config).validate_decision_scope(
            decision.model_copy(update={"intent": changed_intent})
        )


def test_prod_instrument_rules_check_bounds_increments_minimum_and_1x():
    engine = _bare_engine()
    decision = _decision()
    now = engine.clock()
    instrument = {
        "name": decision.venue_symbol,
        "trading": "all",
        "visibility": "all",
        "marketState": "OPEN",
        "updatedAt": now.isoformat(),
        "lotSize": "1",
        "multiplier": "1",
        "priceIncrement": "0.01",
        "quantityIncrement": "0.1",
        "minPrice": "1",
        "maxPrice": "1000000",
        "minQuantity": "0.1",
        "maxQuantity": "100",
        "minVolume": "5",
    }
    engine._assert_production_instrument(decision, {"instruments": [instrument]})
    for field in ("lotSize", "multiplier"):
        with pytest.raises(PaperExecutionSafetyError, match="lot size/multiplier"):
            engine._assert_production_instrument(decision, {"instruments": [{**instrument, field: "2"}]})
    with pytest.raises(Exception, match="quantity violates"):
        engine._assert_production_instrument(
            decision,
            {"instruments": [{**instrument, "quantityIncrement": "0.2"}]},
        )
    changed = type(decision).model_validate(
        {**decision.model_dump(mode="python"), "decision_id": None, "trade_id": None, "leverage": 2}
    )
    with pytest.raises(PaperExecutionSafetyError, match="exactly 1x"):
        engine._assert_technical_canary_binding(changed)


def test_prod_book_requires_two_second_freshness_marketability_and_depth():
    engine = _bare_engine()
    decision = _decision()
    now_ms = max(
        int(engine.clock().timestamp() * 1000),
        decision.venue_quality.book_timestamp_ms + 1000,
    )
    engine.clock = lambda: datetime.fromtimestamp(now_ms / 1000, tz=UTC)
    depth = {
        "t": now_ms,
        "asks": [{"price": 100.5, "quantity": 1}],
        "bids": [{"price": 100.49, "quantity": 1}],
    }
    engine._assert_live_entry_book(decision, depth)
    with pytest.raises(PaperExecutionSafetyError, match="book is stale"):
        engine._assert_live_entry_book(decision, {**depth, "t": now_ms - 2001})
    with pytest.raises(PaperExecutionSafetyError, match="depth is below"):
        engine._assert_live_entry_book(
            decision,
            {**depth, "asks": [{"price": 100.5, "quantity": 0.001}]},
        )
    venue_quality = decision.venue_quality.model_dump(mode="python")
    venue_quality.update(assessed_notional_usd=200, measurement_id=None)
    larger_assessment = type(decision).model_validate(
        {
            **decision.model_dump(mode="python"),
            "venue_quality": venue_quality,
            "decision_id": None,
            "trade_id": None,
        }
    )
    with pytest.raises(PaperExecutionSafetyError, match="depth is below"):
        engine._assert_live_entry_book(larger_assessment, depth)
