"""Operator conjunct at the real PAPER prepare/send boundary, fake venue only."""

from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from kairos_persistence import EffectStatus
from kairos_persistence.operator_control import OperatorControlRefused

from kairos_execution.paper_engine import PaperExecutionSafetyError
from tests.canary_admission_fixtures import LayeredCanaryAdmission
from tests.paper_fixtures import LayeredOperatorControl, approved_decision, rejected_decision
from tests.test_canary_admission import engine_fixture


@pytest.mark.asyncio
async def test_default_operator_is_mandatory_even_with_valid_canary_scope(tmp_path):
    engine = engine_fixture(tmp_path)
    engine._operator_control = None
    engine.trades.pool = SimpleNamespace(acquire=lambda: (_ for _ in ()).throw(RuntimeError("unavailable")))
    engine._create_trade_with_event = AsyncMock()
    with pytest.raises(PaperExecutionSafetyError, match="operator control"):
        await engine._handle_once(approved_decision())
    engine._create_trade_with_event.assert_not_called()
    engine.effects.prepare.assert_not_called()
    engine.adapter.place_limit.assert_not_called()


@pytest.mark.asyncio
async def test_disarmed_prepare_has_no_durable_venue_intent(tmp_path):
    engine = engine_fixture(tmp_path)
    engine._operator_control.armed = False
    with pytest.raises(PaperExecutionSafetyError, match="operator control"):
        await engine._prepare_entry_effect(
            approved_decision(), object(), effect_id="effect", client_order_id="client"
        )
    engine.effects.prepare.assert_not_called()
    engine.adapter.place_limit.assert_not_called()


@pytest.mark.asyncio
async def test_canary_lock_delay_cannot_outlive_operator_lease_and_claim_never_retries(tmp_path):
    control = LayeredOperatorControl()

    class ExpiringCanary(LayeredCanaryAdmission):
        @asynccontextmanager
        async def final_dispatch(self, **kwargs):
            # Both committed claims exist but operator lease expires while the
            # canary lock is acquired. This must be rechecked before send.
            control.armed = False
            yield None

    engine = engine_fixture(tmp_path, admission=ExpiringCanary())
    engine._operator_control = control
    engine._assert_entry_admission = AsyncMock()
    engine._assert_live_entry_book = Mock()
    engine._reserve_mutation = AsyncMock()
    prepared = SimpleNamespace(
        created=True, effect=SimpleNamespace(effect_key="effect", status=EffectStatus.PREPARED)
    )
    with pytest.raises(PaperExecutionSafetyError, match="operator control"):
        await engine._entry_effect(
            approved_decision(),
            SimpleNamespace(symbol="BTCUSDT"),
            effect_id="effect",
            client_order_id="client",
            preparation=prepared,
        )
    assert "effect" in control.claims
    engine.adapter.place_limit.assert_not_called()
    engine.effects.confirm.assert_not_called()
    control.armed = True
    with pytest.raises(OperatorControlRefused, match="already claimed"):
        await engine._entry_effect(
            approved_decision(),
            SimpleNamespace(symbol="BTCUSDT"),
            effect_id="effect",
            client_order_id="client",
            preparation=prepared,
        )
    engine.adapter.place_limit.assert_not_called()


@pytest.mark.asyncio
async def test_rejected_decision_does_not_touch_operator_repository(tmp_path):
    engine = engine_fixture(tmp_path)
    engine._operator_control = SimpleNamespace(
        check_entry=AsyncMock(side_effect=AssertionError("operator I/O"))
    )
    assert (await engine.handle(rejected_decision())).events == ()
    engine._operator_control.check_entry.assert_not_called()


@pytest.mark.asyncio
async def test_operator_guard_wraps_canary_guard_and_actual_send(tmp_path):
    steps = []

    class Control(LayeredOperatorControl):
        @asynccontextmanager
        async def final_dispatch_guard(self, **kwargs):
            steps.append("operator")
            yield None
            steps.append("operator_unlock")

    class Canary(LayeredCanaryAdmission):
        @asynccontextmanager
        async def final_dispatch(self, **kwargs):
            assert steps == ["operator"]
            steps.append("canary")
            yield None
            steps.append("canary_unlock")

    engine = engine_fixture(tmp_path, admission=Canary())
    engine._operator_control = Control()
    engine._assert_entry_admission = AsyncMock()
    engine._assert_live_entry_book = Mock()
    engine._reserve_mutation = AsyncMock()
    engine._validate_entry_response = Mock(return_value=("client", "FILLED", 0.1, 100))

    async def send(**kwargs):
        assert steps == ["operator", "canary"]
        steps.append("send")
        return {"id": "client"}

    engine.adapter.place_limit.side_effect = send
    await engine._entry_effect(
        approved_decision(),
        SimpleNamespace(symbol="BTCUSDT"),
        effect_id="effect",
        client_order_id="client",
        preparation=SimpleNamespace(
            created=True, effect=SimpleNamespace(effect_key="effect", status=EffectStatus.PREPARED)
        ),
    )
    assert steps == ["operator", "canary", "send", "canary_unlock", "operator_unlock"]
