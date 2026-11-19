"""Supplemental PostgreSQL STOP barrier for one explicit account session.

This is not a source qualification or a LIVE authority.  Its ACTIVE state
does not prove equity, fees, cashflows, funding, or that a sender already in
flight can be recalled.  It cannot fence older workers or direct venue access.
It complements, rather than replaces, the existing static entry denial.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from uuid import UUID


class SessionStopBoundaryError(PermissionError):
    """A current session observation or its transaction is unavailable."""


class SessionIoLease:
    """Observe connection loss; this cannot recall already-started I/O."""

    def __init__(self, connection) -> None:
        self.connection = connection
        self.lost = False

    def on_termination(self, _connection) -> None:
        self.lost = True

    def assert_live(self) -> None:
        if self.lost or self.connection.is_closed() or self.connection.is_in_transaction() is not True:
            raise SessionStopBoundaryError("session lease was lost; external I/O may be unresolved")


class PostgresSessionStopBoundary:
    """Hold the account reservation lock through custody or a venue call.

    The risk writer must use the same lock before appending a STOP.  A STOP
    committed before this lock is acquired prevents the call.  A call already
    holding the lock is ordered before STOP and may have an unknown outcome.
    """

    def __init__(self, state_source, *, session_id: UUID, max_age: timedelta) -> None:
        from .production_state import AsyncPostgresProductionSigningStateSource

        if type(state_source) is not AsyncPostgresProductionSigningStateSource:
            raise TypeError("the exact production state source is required")
        if not isinstance(session_id, UUID) or session_id.int == 0:
            raise ValueError("an explicit nonzero session UUID is required")
        if not timedelta(0) < max_age <= timedelta(seconds=5):
            raise ValueError("session evidence freshness must be at most five seconds")
        self.source = state_source
        self.session_id = session_id
        self.max_age = max_age

    @asynccontextmanager
    async def entry(self, *, context):
        from .production_state import _account_reservation_lock, _account_scope_sha256

        if context != self.source.context:
            raise SessionStopBoundaryError("session boundary account context mismatch")
        try:
            async with self.source.pool.acquire() as connection:
                if connection.is_in_transaction() is not False:
                    raise SessionStopBoundaryError("session boundary requires an idle connection")
                await self.source.inspect(connection)
                if connection.is_in_transaction() is not False:
                    raise SessionStopBoundaryError("session inspection left an open transaction")
                async with connection.transaction():
                    await connection.execute("SET LOCAL statement_timeout='5s'")
                    await connection.fetchval(
                        "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                        _account_reservation_lock(context),
                    )
                    now = await connection.fetchval("SELECT clock_timestamp()")
                    row = await connection.fetchrow(
                        "SELECT state,session_id,sequence,observed_at "
                        "FROM kairos_session_loss_v1.events WHERE account_sha256=$1 "
                        "ORDER BY sequence DESC LIMIT 1",
                        _account_scope_sha256(context),
                    )
                    if (
                        not isinstance(now, datetime)
                        or now.tzinfo is None
                        or row is None
                        or row["state"] != "ACTIVE"
                        or row["session_id"] != self.session_id
                        or type(row["sequence"]) is not int
                        or row["sequence"] <= 0
                        or not isinstance(row["observed_at"], datetime)
                        or row["observed_at"].tzinfo is None
                        or row["observed_at"] > now
                        or now - row["observed_at"] > self.max_age
                    ):
                        raise SessionStopBoundaryError("session STOP or current evidence unavailable")
                    # The transaction and account lock remain held across the
                    # caller's operation, bounded by its existing deadline.
                    lease = SessionIoLease(connection)
                    connection.add_termination_listener(lease.on_termination)
                    try:
                        lease.assert_live()
                        yield lease
                    finally:
                        connection.remove_termination_listener(lease.on_termination)
        except SessionStopBoundaryError:
            raise
        except Exception:
            raise SessionStopBoundaryError("session boundary unavailable or operation unresolved") from None
