"""Opt-in actual PG lock test with synthetic session evidence, never LIVE."""

import asyncio
import os
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import UUID, uuid4

import asyncpg
import pytest

from kairos_execution.production_dispatch import ProductionDispatchError, ProductionEffectDispatcher
from kairos_execution.production_session_loss import DDL, VerifiedSessionObservationV1
from kairos_execution.production_state import (
    AsyncPostgresProductionSigningStateSource,
    ProductionStateError,
    _account_scope_sha256,
)
from kairos_execution.session_stop_boundary import PostgresSessionStopBoundary, SessionStopBoundaryError
from tests.test_managed_signer import setup_signer
from tests.test_production_dispatch import CurrentState, SyntheticSignatureVerifier
from tests.test_session_stop_boundary_wiring import signed_wire

DB = "kairos_production_evidence_joinedtest20261109"


@pytest.mark.asyncio
async def test_real_latch_and_io_boundary_share_account_lock(monkeypatch):
    dsn = os.getenv("KAIROS_JOINED_SESSION_DSN")
    if not dsn:
        pytest.skip("explicit disposable local PostgreSQL required")
    if not dsn.startswith("postgresql://postgres@127.0.0.1:") or not dsn.endswith("/" + DB):
        pytest.fail("refusing non-disposable database")
    pool = await asyncpg.create_pool(dsn, min_size=2, max_size=4)
    try:
        async with pool.acquire() as connection:
            assert await connection.fetchval("SELECT current_database()") == DB
            assert await connection.fetchval("SELECT to_regnamespace('kairos_session_loss_v1')") is None
            await connection.execute(DDL)
        signer, request, _, _, _ = setup_signer()
        source = AsyncPostgresProductionSigningStateSource(
            pool,
            expected_database=DB,
            database_uuid=uuid4(),
            policy_namespace="synthetic:joined",
            runtime_role="synthetic_reader",
            context=request.context,
            require_session_loss_latch=True,
        )

        async def inspect_for_test(connection):
            assert await connection.fetchval("SELECT current_database()") == DB

        monkeypatch.setattr(source, "inspect", inspect_for_test)
        # The real pinned source is unqualified and must refuse even an empty
        # database; replacing it below is solely for exercising SQL order.
        with pytest.raises(ProductionStateError):
            await source.observe_session_loss_async({})
        async with pool.acquire() as connection:
            assert await connection.fetchval("SELECT count(*) FROM kairos_session_loss_v1.events") == 0

        account = _account_scope_sha256(request.context)
        session_id = UUID("d155f463-931f-4c62-871f-40fb9404d1f0")
        baseline = VerifiedSessionObservationV1(
            account_sha256=account,
            session_id=session_id,
            sequence=1,
            baseline_equity_usd=Decimal("100"),
            baseline_net_deposits_usd=Decimal("0"),
            net_deposits_usd=Decimal("0"),
            equity_usd=Decimal("100"),
            remaining_incremental_risk_usd=Decimal("0"),
            evidence_sha256="a" * 64,
            observed_at=datetime.now(UTC),
        )
        observation = [baseline]

        def synthetic_verify(raw, *, account_sha256):
            assert account_sha256 == account
            return observation[0]

        monkeypatch.setattr(source._session_loss_verifier, "verify", synthetic_verify)
        assert await source.observe_session_loss_async({}) == "ACTIVE"
        barrier = PostgresSessionStopBoundary(source, session_id=session_id, max_age=timedelta(seconds=5))
        waiting = asyncio.Event()

        async def append_stop():
            waiting.set()
            return await source.observe_session_loss_async({})

        async with barrier.entry(context=request.context):
            observation[0] = baseline.model_copy(
                update={
                    "sequence": 2,
                    "equity_usd": Decimal("95"),
                    "evidence_sha256": "b" * 64,
                    "observed_at": datetime.now(UTC),
                }
            )
            stop_task = asyncio.create_task(append_stop())
            await waiting.wait()
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(asyncio.shield(stop_task), timeout=0.1)
        assert await asyncio.wait_for(stop_task, timeout=3) == "STOP"
        with pytest.raises(SessionStopBoundaryError, match="STOP or current evidence unavailable"):
            async with barrier.entry(context=request.context):
                pytest.fail("committed STOP cannot admit entry")

        claims, _, wire, now = await signed_wire()
        assert wire.context == request.context == signer.binding.context
        sends = []

        async def sender(**kwargs):
            sends.append(kwargs)
            return {"status": "SYNTHETIC"}

        dispatcher = ProductionEffectDispatcher(
            authorization=CurrentState(),
            signature_verifier=SyntheticSignatureVerifier(),
            claims=claims,
            database_uuid=claims.database_uuid,
            context=wire.context,
            clock=lambda: now,
            sender=sender,
            session_stop_boundary=barrier,
        )
        with pytest.raises(ProductionDispatchError, match="atomic session entry fence is unavailable"):
            await dispatcher.dispatch_one(wire)
        assert not sends
    finally:
        await pool.close()
