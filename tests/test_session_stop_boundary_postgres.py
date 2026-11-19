"""Optional tests against a disposable local PostgreSQL, never a venue."""

import asyncio
import os
from datetime import timedelta
from uuid import uuid4

import asyncpg
import pytest

from kairos_execution.production_state import (
    AsyncPostgresProductionSigningStateSource,
    _account_reservation_lock,
    _account_scope_sha256,
)
from kairos_execution.session_stop_boundary import PostgresSessionStopBoundary, SessionStopBoundaryError
from tests.test_managed_signer import setup_signer


@pytest.mark.asyncio
async def test_postgres_lock_orders_stop_but_disconnect_loses_fence():
    dsn = os.getenv("KAIROS_SESSION_BOUNDARY_TEST_DSN")
    if not dsn or os.getenv("KAIROS_SESSION_BOUNDARY_DISPOSABLE") != "1":
        pytest.skip("requires explicit disposable PostgreSQL")
    if not dsn.startswith("postgresql://postgres@127.0.0.1:"):
        raise ValueError("tests accept only explicit localhost disposable PostgreSQL")
    pool = await asyncpg.create_pool(dsn, min_size=2, max_size=4)
    try:
        async with pool.acquire() as connection:
            assert await connection.fetchval("SELECT to_regnamespace('kairos_session_loss_v1')") is None
            await connection.execute("CREATE SCHEMA kairos_session_loss_v1")
            await connection.execute(
                "CREATE TABLE kairos_session_loss_v1.events "
                "(account_sha256 text, session_id uuid, sequence bigint, "
                "state text, observed_at timestamptz)"
            )
        signer, _, _, _, _ = setup_signer()
        context = signer.binding.context
        source = object.__new__(AsyncPostgresProductionSigningStateSource)
        source.pool = pool
        source.context = context
        source.pid = None

        async def inspect_for_test(connection):
            # The production identity/ACL inspection is independently tested by
            # production_state tests; this isolated fixture tests SQL locking.
            source.pid = connection.get_server_pid()

        source.inspect = inspect_for_test
        session_id = uuid4()
        guard = PostgresSessionStopBoundary(source, session_id=session_id, max_age=timedelta(seconds=5))
        scope = _account_scope_sha256(context)
        lock = _account_reservation_lock(context)
        with pytest.raises(SessionStopBoundaryError, match="STOP or current evidence unavailable"):
            async with guard.entry(context=context):
                pytest.fail("missing session evidence must block")
        async with pool.acquire() as connection:
            await connection.execute(
                "INSERT INTO kairos_session_loss_v1.events VALUES($1,$2,1,'ACTIVE',clock_timestamp())",
                scope, session_id,
            )
        wrong_session = PostgresSessionStopBoundary(source, session_id=uuid4(), max_age=timedelta(seconds=5))
        with pytest.raises(SessionStopBoundaryError, match="STOP or current evidence unavailable"):
            async with wrong_session.entry(context=context):
                pytest.fail("foreign session must block")
        stale = PostgresSessionStopBoundary(source, session_id=session_id, max_age=timedelta(microseconds=1))
        with pytest.raises(SessionStopBoundaryError, match="STOP or current evidence unavailable"):
            async with stale.entry(context=context):
                pytest.fail("stale evidence must block")

        waiting = asyncio.Event()

        async def append_stop():
            async with pool.acquire() as connection, connection.transaction():
                waiting.set()
                await connection.fetchval("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", lock)
                await connection.execute(
                    "INSERT INTO kairos_session_loss_v1.events VALUES($1,$2,2,'STOP',clock_timestamp())",
                    scope, session_id,
                )

        async with guard.entry(context=context):
            task = asyncio.create_task(append_stop())
            await waiting.wait()
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(asyncio.shield(task), timeout=0.1)
        await asyncio.wait_for(task, timeout=3)
        with pytest.raises(SessionStopBoundaryError, match="STOP or current evidence unavailable"):
            async with guard.entry(context=context):
                pytest.fail("committed STOP must block the operation")

        # A disconnected PostgreSQL backend loses its advisory lock even if
        # the caller's in-flight operation is still running.
        async with pool.acquire() as connection:
            await connection.execute("TRUNCATE kairos_session_loss_v1.events")
            await connection.execute(
                "INSERT INTO kairos_session_loss_v1.events VALUES($1,$2,1,'ACTIVE',clock_timestamp())",
                scope, session_id,
            )
        with pytest.raises(SessionStopBoundaryError, match="unavailable or operation unresolved"):
            async with guard.entry(context=context) as lease:
                async with pool.acquire() as killer:
                    assert await killer.fetchval("SELECT pg_terminate_backend($1)", source.pid)
                task = asyncio.create_task(append_stop())
                await asyncio.wait_for(task, timeout=3)
                with pytest.raises(SessionStopBoundaryError, match="lease was lost"):
                    lease.assert_live()
    finally:
        await pool.close()
