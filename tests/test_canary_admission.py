"""Entry admission composition without PostgreSQL, venue or paid API calls."""

import asyncio
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from kairos_persistence import EffectStatus, TradeState
from kairos_persistence.canary_session import CanaryAdmissionError, CanarySessionRepository

from kairos_execution.canary_admission import load_expected_scope
from kairos_execution.config import ExecSettings
from kairos_execution.paper_engine import PaperExecutionEngine, PaperExecutionSafetyError
from tests.canary_admission_fixtures import LayeredCanaryAdmission, expected_scope
from tests.canary_session_fixtures import fresh_decision, fresh_review, session_plan
from tests.paper_fixtures import T0, approved_decision, configured_paper_node_runtime


def settings(tmp_path, **overrides):
    return ExecSettings(
        trading_mode="PAPER",
        environment="paper-dev",
        account_id="kairos-paper-dev-01",
        evedex_dev_api_key_file=tmp_path / "api.secret",
        evedex_dev_private_key_file=tmp_path / "signing.secret",
        evedex_dev_expected_account_id="remote-paper-account-01",
        evedex_sidecar_node=configured_paper_node_runtime(),
        **overrides,
    )


def engine_fixture(tmp_path, *, scope=True, admission=None):
    config = settings(tmp_path)
    engine = PaperExecutionEngine(
        SimpleNamespace(name="evedex", place_limit=AsyncMock(), fetch_depth=AsyncMock(return_value={})),
        SimpleNamespace(entries_allowed=AsyncMock(return_value=True), get=AsyncMock(return_value=None)),
        SimpleNamespace(prepare=AsyncMock(), confirm=AsyncMock()),
        config,
        clock=lambda: datetime.fromtimestamp((T0 + 60_500) / 1000, UTC),
        mutation_budget=object(),
        runtime_health=object(),
        canary_sessions=admission or LayeredCanaryAdmission(),
        canary_scope=expected_scope(config) if scope else None,
    )
    engine._recovery_blockers = ()
    return engine


def test_independent_scope_file_is_strict_and_binds_runtime(tmp_path):
    config = settings(tmp_path)
    scope = expected_scope(config)
    path = tmp_path / "scope.json"
    path.write_text(scope.model_dump_json(), encoding="utf-8")
    configured = settings(tmp_path, canary_scope_file=path)
    assert load_expected_scope(configured) == scope
    with pytest.raises(ValueError, match="absolute independent"):
        load_expected_scope(config)
    foreign = scope.model_copy(update={"remote_account_id": "different-dev-account"})
    path.write_text(foreign.model_dump_json(), encoding="utf-8")
    with pytest.raises(ValueError, match="independently configured"):
        load_expected_scope(configured)
    path.write_text(scope.model_dump_json()[:-1] + ',"accepted":true}', encoding="utf-8")
    with pytest.raises(ValueError):
        load_expected_scope(configured)


def test_fresh_composition_contracts_obey_real_arm_and_execution_binding(tmp_path):
    from kairos_persistence.canary_arm import PaperCanaryArmRepository
    from kairos_persistence.canary_session import validate_slot_review

    from tests.test_integration_paper_engine import FakePaperAdapter

    engine = engine_fixture(tmp_path)
    scope = expected_scope(engine.settings)
    slot = session_plan().slots[0]
    review, allocation = fresh_review(scope, slot, T0 + 60_100)
    PaperCanaryArmRepository._validate_binding(review, allocation)
    validate_slot_review(slot, review)
    decision = fresh_decision(review, scope, T0 + 60_500)
    engine._validate_decision(decision)
    adapter = FakePaperAdapter(engine.clock)
    engine._assert_technical_canary_instrument(decision, adapter.state)
    engine._assert_live_entry_book(
        decision,
        {
            "t": T0 + 60_500,
            "asks": [{"price": 100.01, "quantity": 1}],
            "bids": [{"price": 99.99, "quantity": 1}],
        },
    )


@pytest.mark.asyncio
async def test_missing_scope_blocks_new_trade_before_prepare_or_venue_io(tmp_path):
    engine = engine_fixture(tmp_path, scope=False)
    engine._create_trade_with_event = AsyncMock()
    with pytest.raises(PaperExecutionSafetyError, match="independent valid scope"):
        await engine._handle_once(approved_decision())
    engine._create_trade_with_event.assert_not_called()
    engine.effects.prepare.assert_not_called()
    engine.adapter.fetch_depth.assert_not_called()
    engine.adapter.place_limit.assert_not_called()


@pytest.mark.asyncio
async def test_invalid_scope_is_entry_only_and_does_not_disclose_file_contents(tmp_path):
    config = settings(tmp_path, canary_scope_file=tmp_path / "bad.json")
    config.canary_scope_file.write_text('{"private_material":"do-not-print"}', encoding="utf-8")
    engine = engine_fixture(tmp_path, scope=False)
    # Constructor deliberately tolerates the invalid operational file so that
    # existing journal recovery/SL/TP work is never prevented at startup.
    instance = PaperExecutionEngine(
        engine.adapter,
        engine.trades,
        engine.effects,
        config,
        mutation_budget=object(),
        runtime_health=object(),
    )
    assert instance._canary_scope is None
    with pytest.raises(PaperExecutionSafetyError) as failure:
        instance._canary_entry_admission()
    assert "do-not-print" not in str(failure.value)
    assert instance.recovery_blockers == ("startup recovery has not run",)


@pytest.mark.asyncio
async def test_late_existing_trade_redelivery_never_active_rebinds(tmp_path):
    engine = engine_fixture(tmp_path, scope=False)
    decision = approved_decision()
    engine.clock = lambda: (
        datetime.fromtimestamp(decision.intent.entry_expires_ts_ms / 1000, UTC) + timedelta(days=1)
    )
    trade = SimpleNamespace(state=TradeState.ENTRY_PENDING)
    engine.trades.get.return_value = trade
    engine._create_trade_with_event = AsyncMock(return_value=(SimpleNamespace(trade=trade), False))
    engine._reconcile_redelivery_locked = AsyncMock(return_value=[])
    engine._bind_canary_entry = AsyncMock(side_effect=AssertionError("recovery tried active admission"))
    assert (await engine._handle_once(decision)).events == ()
    engine._reconcile_redelivery_locked.assert_awaited_once_with(trade)
    engine._bind_canary_entry.assert_not_called()
    engine.effects.prepare.assert_not_called()
    engine.adapter.place_limit.assert_not_called()


@pytest.mark.asyncio
async def test_admission_refusal_is_before_prepared(tmp_path):
    engine = engine_fixture(tmp_path)
    engine._bind_canary_entry = AsyncMock(side_effect=CanaryAdmissionError("session stopped"))
    engine._assert_entry_admission = AsyncMock()
    with pytest.raises(CanaryAdmissionError, match="stopped"):
        await engine._prepare_entry_effect(
            approved_decision(), object(), effect_id="effect", client_order_id="client"
        )
    engine.effects.prepare.assert_not_called()
    engine._assert_entry_admission.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("created", [False, True])
async def test_final_refusal_or_ambiguous_replay_never_calls_venue(tmp_path, created):
    class StoppedAdmission(LayeredCanaryAdmission):
        @asynccontextmanager
        async def final_dispatch(self, **kwargs):
            raise CanaryAdmissionError("session stopped after PREPARED")
            yield  # pragma: no cover

    engine = engine_fixture(tmp_path, admission=StoppedAdmission())
    engine._assert_entry_admission = AsyncMock()
    engine._assert_live_entry_book = Mock()
    engine._reserve_mutation = AsyncMock()
    prepared = SimpleNamespace(
        created=created, effect=SimpleNamespace(effect_key="effect", status=EffectStatus.PREPARED)
    )
    with pytest.raises((CanaryAdmissionError, PaperExecutionSafetyError)):
        await engine._entry_effect(
            approved_decision(),
            SimpleNamespace(symbol="BTCUSDT"),
            effect_id="effect",
            client_order_id="client",
            preparation=prepared,
        )
    assert prepared.effect.status is EffectStatus.PREPARED
    engine.effects.confirm.assert_not_called()
    engine.adapter.place_limit.assert_not_called()
    if not created:
        engine._reserve_mutation.assert_not_called()
        engine.adapter.fetch_depth.assert_not_called()


@pytest.mark.asyncio
async def test_adapter_and_durable_ack_are_inside_dispatch_lease(tmp_path):
    steps = []

    class RecordingAdmission(LayeredCanaryAdmission):
        @asynccontextmanager
        async def final_dispatch(self, **kwargs):
            steps.append("claim_committed")
            yield None
            steps.append("unlock")

    engine = engine_fixture(tmp_path, admission=RecordingAdmission())
    engine._assert_entry_admission = AsyncMock()
    engine._assert_live_entry_book = Mock()
    engine._reserve_mutation = AsyncMock()
    engine._validate_entry_response = Mock(return_value=("client", "FILLED", 0.1, 100))

    async def place(**kwargs):
        assert steps == ["claim_committed"]
        steps.append("venue")
        return {"id": "client"}

    async def confirm(*args, **kwargs):
        assert steps == ["claim_committed", "venue"]
        steps.append("durable_ack")

    engine.adapter.place_limit.side_effect = place
    engine.effects.confirm.side_effect = confirm
    await engine._entry_effect(
        approved_decision(),
        SimpleNamespace(symbol="BTCUSDT"),
        effect_id="effect",
        client_order_id="client",
        preparation=SimpleNamespace(
            created=True, effect=SimpleNamespace(effect_key="effect", status=EffectStatus.PREPARED)
        ),
    )
    assert steps == ["claim_committed", "venue", "durable_ack", "unlock"]


@pytest.mark.asyncio
@pytest.mark.parametrize("failure_mode", ["timeout", "cancel"])
async def test_real_dispatch_context_keeps_committed_claim_on_timeout_or_cancellation(tmp_path, failure_mode):
    # This executes the production context manager with an explicit transaction
    # model. Real PostgreSQL commit/process-loss evidence is tested separately.
    decision = approved_decision()
    scope = expected_scope(settings(tmp_path))
    binding = await LayeredCanaryAdmission().bind_entry(
        decision=decision,
        expected_scope=scope,
        effect_id="effect",
    )
    steps = []

    class Connection:
        committed = False

        async def fetchval(self, query, *args):
            return (
                binding.session_id
                if "session_id" in query
                else datetime.fromtimestamp((T0 + 60_500) / 1000, UTC)
            )

        async def execute(self, query, *args):
            if "INSERT INTO paper_canary_dispatch_claims" in query:
                steps.append("claim_pending")
            if "pg_advisory_unlock" in query:
                steps.append("unlock")

        @asynccontextmanager
        async def transaction(self):
            try:
                yield
            except BaseException:
                steps.append("rollback")
                raise
            else:
                self.committed = True
                steps.append("commit")

    connection = Connection()

    class Pool:
        @asynccontextmanager
        async def acquire(self):
            yield connection

    repository = CanarySessionRepository(Pool())
    repository._entry_binding = AsyncMock(return_value=binding)
    repository._assert_prepared_effect = AsyncMock()
    entered = asyncio.Event()

    async def caller():
        async with repository.final_dispatch(
            decision=decision,
            expected_scope=scope,
            effect_id="effect",
            max_hold_s=0.01 if failure_mode == "timeout" else 30,
        ) as lease:
            assert lease.dispatch_claimed and connection.committed
            entered.set()
            await asyncio.Future()

    task = asyncio.create_task(caller())
    await asyncio.wait_for(entered.wait(), timeout=1)
    if failure_mode == "cancel":
        task.cancel()
    with pytest.raises(TimeoutError if failure_mode == "timeout" else asyncio.CancelledError):
        await task
    assert connection.committed
    assert steps == ["claim_pending", "commit", "unlock"]
