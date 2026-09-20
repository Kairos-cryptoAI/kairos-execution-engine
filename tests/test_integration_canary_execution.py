"""Real scoped session -> strict Risk contract -> engine -> FAKE venue only.

Runs in the standard guarded execution integration database, including CI.
Synthetic 24h fixtures never establish venue qualification or alpha readiness.
"""

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from kairos_persistence import Database, ExecutionJournalRepository, TradeLifecycleRepository, TradeState
from kairos_persistence.canary_arm import PaperCanaryArmRepository
from kairos_persistence.canary_session import CanarySessionRepository, millis
from kairos_persistence.repository import AuditRepository

from kairos_execution.config import ExecSettings
from kairos_execution.paper_engine import PaperExecutionEngine
from tests.canary_session_fixtures import fresh_decision, fresh_review, seed_receipt
from tests.disposable_database import connect_disposable_database, disposable_settings
from tests.paper_fixtures import configured_paper_node_runtime
from tests.test_integration_paper_engine import FakePaperAdapter, MutableClock

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]


@pytest.fixture
async def scoped_database():
    database = Database(disposable_settings())
    await connect_disposable_database(database)
    try:
        # This check precedes even synthetic history updates. Preserve all rows
        # and fail if this supposedly disposable DB contains non-test sessions.
        if await database.pool.fetchval(
            "SELECT 1 FROM paper_canary_sessions WHERE remote_account_id NOT LIKE 'synthetic-%' LIMIT 1"
        ):
            raise ValueError("refusing synthetic cleanup of non-test sessions")
        await database.pool.execute(
            """UPDATE paper_canary_sessions SET state='ABORTED',stop_reason='SYNTHETIC_TEST_CLEANUP'
               WHERE state IN ('ARMED','RUNNING','DRAINING')"""
        )
        yield database
    finally:
        await database.close()


async def test_scoped_entry_claim_stop_race_redelivery_and_unscoped_restart(scoped_database, tmp_path):
    database = scoped_database
    sessions, scope, plan, session = await seed_receipt(database)
    clock = MutableClock(datetime.now(UTC))
    stop_tasks = []

    class ClaimedFakeAdapter(FakePaperAdapter):
        async def fetch_depth(self, **kwargs):
            return {
                "t": millis(clock()),
                "asks": [{"price": 100.01, "quantity": 1}],
                "bids": [{"price": 99.99, "quantity": 1}],
            }

        async def place_limit(self, **kwargs):
            # The real repository claim must be committed and visible on a
            # different connection BEFORE the fake external side effect.
            row = await database.pool.fetchrow(
                "SELECT * FROM paper_canary_dispatch_claims WHERE effect_id=$1", kwargs["effect_id"]
            )
            assert row and row["session_id"] == session["session_id"]
            assert (
                await database.pool.fetchval(
                    "SELECT status FROM execution_effects WHERE effect_key=$1", kwargs["effect_id"]
                )
                == "PREPARED"
            )
            stopper = asyncio.create_task(sessions.stop(session["session_id"]))
            stop_tasks.append(stopper)
            await asyncio.sleep(0.03)
            assert not stopper.done()
            return await super().place_limit(**kwargs)

    adapter = ClaimedFakeAdapter(clock)
    adapter.state["account"]["id"] = scope.remote_account_id
    config = ExecSettings(
        trading_mode="PAPER",
        environment=scope.environment,
        account_id=scope.account_id,
        evedex_dev_api_key_file=tmp_path / "api.secret",
        evedex_dev_private_key_file=tmp_path / "signing.secret",
        evedex_dev_expected_account_id=scope.remote_account_id,
        evedex_sidecar_node=configured_paper_node_runtime(),
    )
    trades, effects = TradeLifecycleRepository(database.pool), ExecutionJournalRepository(database.pool)
    engine = PaperExecutionEngine(
        adapter, trades, effects, config, clock=clock, canary_sessions=sessions, canary_scope=scope
    )
    assert await engine.initialize_recovery() == ()
    now = millis(await database.pool.fetchval("SELECT clock_timestamp()"))
    # Align only the synthetic input to a real eligible bar. Production DB
    # deadlines and the 5s venue gate remain unchanged even under slow hosts.
    if now % 60_000 > 15_000:
        await asyncio.sleep((60_000 - now % 60_000) / 1000 + 0.05)
    now = millis(await database.pool.fetchval("SELECT clock_timestamp()"))
    review, allocation = fresh_review(scope, plan.slots[0], now)
    adapter.state["instruments"][0]["updatedAt"] = datetime.fromtimestamp(now / 1000, UTC).isoformat()
    arms = PaperCanaryArmRepository(database.pool)
    await arms.arm(
        account_id=scope.account_id,
        review=review,
        allocation=allocation,
        session_id=session["session_id"],
        slot_id=plan.slots[0].slot_id,
    )
    consumed = await arms.consume(account_id=scope.account_id, review=review)
    assert consumed is not None
    decision = fresh_decision(review, scope, consumed.decided_at_ms)
    await AuditRepository(database.pool).append_event("kairos.risk.trade_decision.v1", decision)
    clock.value = datetime.fromtimestamp(consumed.decided_at_ms / 1000, UTC)
    result = await engine.handle(decision)
    assert result.events
    assert adapter.calls[:3] == ["ENTRY", "STOP_LOSS", "TAKE_PROFIT"]
    assert len(stop_tasks) == 1
    stopped = await asyncio.wait_for(stop_tasks[0], timeout=5)
    assert stopped["state"] == "DRAINING"
    assert (
        await database.pool.fetchval(
            "SELECT count(*) FROM paper_canary_dispatch_claims WHERE session_id=$1", session["session_id"]
        )
        == 1
    )
    await engine.handle(decision)
    assert adapter.calls.count("ENTRY") == 1

    # A restarted engine with NO scope file must recover and close its existing
    # exposure under a stopped session, never require new entry permission.
    restarted = PaperExecutionEngine(adapter, trades, effects, config, clock=clock)
    assert restarted._canary_scope is None
    assert await restarted.initialize_recovery() == ()
    trade = await trades.get(decision.trade_id)
    assert trade and trade.state is TradeState.ACTIVE and trade.timeout_at is not None
    clock.value = trade.timeout_at + timedelta(milliseconds=1)
    await restarted.reconcile_once()
    trade = await trades.get(decision.trade_id)
    assert trade and trade.state is TradeState.FLAT
    assert not adapter.state["positions"]
    await restarted.handle(decision)
    assert adapter.calls.count("ENTRY") == 1
    restored = CanarySessionRepository(database.pool)
    finished = await restored.refresh(session["session_id"])
    assert finished["state"] == "ABORTED"
    assert finished["attempts_reserved"] == 1
    assert finished["attempts"][0]["terminal_reason"] == "FLAT"
    assert len(await restored.status(session["session_id"])) > 0
