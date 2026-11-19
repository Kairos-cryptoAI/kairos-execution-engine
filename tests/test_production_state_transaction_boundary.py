"""Verify production write COMMIT boundaries without enabling LIVE.

The PostgreSQL case uses a disposable, explicitly identified fixture database.
It does not call an exchange, handle keys, or provide session-stop authority.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

import asyncpg
import pytest

from kairos_execution.production_state import ProductionStateError, _StateDB


class _PoolForConnection:
    def __init__(self, connection):
        self.connection = connection

    @asynccontextmanager
    async def acquire(self):
        yield self.connection


class _WriteHarness:
    _write = _StateDB._write

    def __init__(self, connection, inspect_callback=None):
        self.pool = _PoolForConnection(connection)
        self.inspect_callback = inspect_callback

    async def inspect(self, connection):
        if self.inspect_callback is not None:
            await self.inspect_callback(connection)


class _FakeConnection:
    def __init__(self, active=False):
        self.active = active
        self.transaction_started = False

    def is_in_transaction(self):
        return self.active

    def transaction(self):
        self.transaction_started = True
        raise AssertionError("transaction must not start")


@pytest.mark.asyncio
async def test_write_refuses_outer_transaction_before_inspection():
    connection = _FakeConnection(active=True)
    inspected = False
    callback_called = False

    async def inspect(_connection):
        nonlocal inspected
        inspected = True

    async def callback(_connection):
        nonlocal callback_called
        callback_called = True

    with pytest.raises(ProductionStateError, match="idle connection"):
        await _WriteHarness(connection, inspect)._write(callback)
    assert not inspected and not callback_called and not connection.transaction_started


@pytest.mark.asyncio
async def test_write_refuses_when_inspection_opens_outer_transaction():
    connection = _FakeConnection()

    async def inspect(value):
        value.active = True

    async def callback(_connection):
        raise AssertionError("callback must not run")

    with pytest.raises(ProductionStateError, match="inspection left an open transaction"):
        await _WriteHarness(connection, inspect)._write(callback)
    assert not connection.transaction_started


@pytest.mark.asyncio
async def test_real_postgres_rejects_savepoint_and_commits_idle_write():
    dsn = os.getenv("KAIROS_SYNTHETIC_STATE_BOUNDARY_DSN")
    if not dsn:
        pytest.skip("explicit disposable synthetic PostgreSQL DSN required")
    connection = await asyncpg.connect(
        dsn, server_settings={"application_name": "kairos-state-boundary-test"}
    )
    try:
        address = connection._addr  # noqa: SLF001 -- reject accidental production targets
        if (
            not isinstance(address, tuple)
            or address[0] != "127.0.0.1"
            or await connection.fetchval("SELECT current_database()")
            != "kairos_state_boundary_fixture_20261109"
            or connection.get_settings().application_name != "kairos-state-boundary-test"
        ):
            raise AssertionError("isolated loopback fixture database required")
        await connection.execute("CREATE TEMP TABLE boundary_events (event text PRIMARY KEY)")

        async def inspect(value):
            # An ordinary SELECT does not leave an asyncpg transaction open.
            assert await value.fetchval("SELECT 1") == 1

        harness = _WriteHarness(connection, inspect)
        outer = connection.transaction()
        await outer.start()

        async def should_not_write(value):
            await value.execute("INSERT INTO boundary_events VALUES ('nested')")

        with pytest.raises(ProductionStateError, match="idle connection"):
            await harness._write(should_not_write)
        assert connection.is_in_transaction()
        await outer.rollback()
        assert await connection.fetchval("SELECT count(*) FROM boundary_events") == 0

        async def write_and_return(value):
            await value.execute("INSERT INTO boundary_events VALUES ('committed')")
            return "STOP_NEW_ENTRIES"

        assert await harness._write(write_and_return) == "STOP_NEW_ENTRIES"
        assert not connection.is_in_transaction()
        assert await connection.fetchval("SELECT event FROM boundary_events") == "committed"

        async def write_then_fail(value):
            await value.execute("INSERT INTO boundary_events VALUES ('rolled_back')")
            raise RuntimeError("synthetic callback failure")

        with pytest.raises(ProductionStateError, match="outcome unavailable"):
            await harness._write(write_then_fail)
        assert not connection.is_in_transaction()
        assert await connection.fetchval("SELECT count(*) FROM boundary_events") == 1
    finally:
        await connection.close()
