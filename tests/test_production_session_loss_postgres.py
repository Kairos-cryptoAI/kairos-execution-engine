"""Synthetic session data, actual transaction wrapper/reservation, disposable PG only.

The test monkeypatches the unqualified source and claims inspection. It does
not establish exchange account truth, source qualification or LIVE readiness.
"""

import os
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import UUID

import asyncpg
import pytest

from kairos_execution.production_claims import PostgresProductionClaims
from kairos_execution.production_session_loss import (
    DDL,
    PinnedEvedexSessionVerifier,
    SessionLossError,
    VerifiedSessionObservationV1,
    projected_session_loss_usd,
)
from kairos_execution.production_state import (
    AsyncPostgresProductionSigningStateSource,
    ProductionStateError,
    _account_scope_sha256,
)
from kairos_execution.session_entry_io import DDL as ENTRY_IO_DDL
from tests.test_signing_authorization import fixture

DB = "kairos_production_evidence_sessionloss20261109"


def test_unqualified_evedex_source_never_verifies():
    with pytest.raises(SessionLossError, match="unavailable"):
        PinnedEvedexSessionVerifier().verify({}, account_sha256="a" * 64)


def test_incremental_exposure_is_counted_once_and_costs_are_required():
    values = dict(
        account_sha256="a" * 64,
        session_id=UUID("73b3a3b6-a006-4e09-bc52-d61cb4ae2402"),
        sequence=2,
        baseline_equity_usd=Decimal("100"),
        baseline_net_deposits_usd=Decimal("0"),
        net_deposits_usd=Decimal("25"),
        equity_usd=Decimal("121"),
        remaining_incremental_risk_usd=Decimal("0.50"),
        evidence_sha256="a" * 64,
        observed_at=datetime.now(UTC),
    )
    observation = VerifiedSessionObservationV1(**values)
    assert projected_session_loss_usd(observation, Decimal("0.25")) == Decimal("4.75")
    values.pop("remaining_incremental_risk_usd")
    with pytest.raises(ValueError):
        VerifiedSessionObservationV1(**values)


@pytest.mark.asyncio
async def test_native_reservation_commits_stop_and_observer_survives_restart(monkeypatch):
    dsn = os.getenv("KAIROS_SESSION_LOSS_TEST_DSN")
    if not dsn:
        pytest.skip("explicit isolated local session-loss test database required")
    pool = await asyncpg.create_pool(dsn, min_size=1, max_size=3)
    try:
        async with pool.acquire() as connection:
            if (
                connection._addr[0] != "127.0.0.1"
                or await connection.fetchval("SELECT current_database()") != DB
            ):
                pytest.fail("wrong database: refuse fixture writes")
            await connection.execute(DDL)
            await connection.execute(ENTRY_IO_DDL)
            # PostgreSQL numeric accepts NaN and infinities, and NaN sorts
            # above Infinity. Test the database constraint independently of
            # the Pydantic source model so direct writers cannot bypass it.
            for field in range(5):
                for nonfinite in (Decimal("NaN"), Decimal("Infinity"), Decimal("-Infinity")):
                    amounts = [Decimal("100"), Decimal("0"), Decimal("0"), Decimal("100"), Decimal("0")]
                    amounts[field] = nonfinite
                    with pytest.raises(asyncpg.PostgresError):
                        await connection.execute(
                            "INSERT INTO kairos_session_loss_v1.events "
                            "(account_sha256,session_id,sequence,state,baseline_equity_usd,"
                            "baseline_net_deposits_usd,net_deposits_usd,equity_usd,"
                            "remaining_incremental_risk_usd,evidence_sha256,observed_at) "
                            "VALUES ($1,$2,1,'ACTIVE',$3,$4,$5,$6,$7,$8,now())",
                            "a" * 64,
                            UUID("73b3a3b6-a006-4e09-bc52-d61cb4ae2402"),
                            *amounts,
                            "b" * 64,
                        )
            with pytest.raises(asyncpg.PostgresError):
                await connection.execute(
                    "INSERT INTO kairos_session_loss_v1.events "
                    "(account_sha256,session_id,sequence,state,baseline_equity_usd,"
                    "baseline_net_deposits_usd,net_deposits_usd,equity_usd,"
                    "remaining_incremental_risk_usd,evidence_sha256,observed_at) "
                    "VALUES ($1,$2,1,'ACTIVE',100,0,0,100,0,$3,'infinity'::timestamptz)",
                    "a" * 64,
                    UUID("73b3a3b6-a006-4e09-bc52-d61cb4ae2402"),
                    "b" * 64,
                )
            await connection.execute(
                "CREATE SCHEMA kairos_production_state_v1; "
                "CREATE TABLE kairos_production_state_v1.risk_reservations (effect_id text)"
            )
            await connection.execute("""
                CREATE FUNCTION kairos_session_loss_v1.fail_commit_fixture() RETURNS trigger
                LANGUAGE plpgsql AS $$ BEGIN
                  IF NEW.evidence_sha256 = repeat('e',64) THEN RAISE EXCEPTION 'commit failure'; END IF;
                  RETURN NEW;
                END $$;
                CREATE CONSTRAINT TRIGGER fail_commit_fixture AFTER INSERT
                  ON kairos_session_loss_v1.events DEFERRABLE INITIALLY DEFERRED
                  FOR EACH ROW EXECUTE FUNCTION kairos_session_loss_v1.fail_commit_fixture();
            """)
        _, request, binding, evidence, _ = fixture()
        source = AsyncPostgresProductionSigningStateSource(
            pool,
            expected_database=DB,
            database_uuid=UUID("6f352b15-7e33-4e87-a0f0-b59d85ec45e7"),
            policy_namespace="synthetic:session",
            runtime_role="synthetic_reader",
            context=binding.context,
            require_session_loss_latch=True,
        )
        account = _account_scope_sha256(binding.context)
        now = datetime.now(UTC)
        sample = VerifiedSessionObservationV1(
            account_sha256=account,
            session_id=UUID("73b3a3b6-a006-4e09-bc52-d61cb4ae2402"),
            sequence=1,
            baseline_equity_usd=Decimal("100"),
            baseline_net_deposits_usd=Decimal("0"),
            net_deposits_usd=Decimal("0"),
            equity_usd=Decimal("100"),
            remaining_incremental_risk_usd=Decimal("0"),
            evidence_sha256="a" * 64,
            observed_at=now,
        )
        current = sample

        def fake_verify(raw, *, account_sha256):
            assert account_sha256 == account
            return current

        async def fake_resolve(connection, *, account_sha256, context_sha256, now):
            assert account_sha256 == account
            return current

        async def isolated_inspect(connection):
            assert connection._addr[0] == "127.0.0.1"
            assert await connection.fetchval("SELECT current_database()") == DB

        async def fake_claim_inspect(self, connection):
            await isolated_inspect(connection)

        monkeypatch.setattr(source, "inspect", isolated_inspect)
        with pytest.raises(ProductionStateError):
            await source.observe_session_loss_async({})
        async with pool.acquire() as connection:
            assert await connection.fetchval("SELECT count(*) FROM kairos_session_loss_v1.events") == 0
        monkeypatch.setattr(source._session_loss_verifier, "verify", fake_verify)
        monkeypatch.setattr(source._session_loss_verifier, "resolve", fake_resolve)
        monkeypatch.setattr(PostgresProductionClaims, "inspect", fake_claim_inspect)
        assert await source.observe_session_loss_async({}) == "ACTIVE"
        assert await source.observe_session_loss_async({}) == "ACTIVE"  # exact duplicate
        current = sample.model_copy(
            update={
                "sequence": 2,
                "net_deposits_usd": Decimal("25"),
                "equity_usd": Decimal("124"),
                "evidence_sha256": "e" * 64,
                "observed_at": now + timedelta(microseconds=1),
            }
        )
        stale_risk = evidence.risk.model_copy(update={"observed_at": now - timedelta(minutes=1)})
        stale_evidence = evidence.model_copy(update={"risk": stale_risk})
        # The session observation is appended, candidate validation fails, and
        # the deferred trigger rejects the outer COMMIT. No partial effect may
        # survive. This simulates a known commit error, not a lost reply.
        with pytest.raises(ProductionStateError):
            await source.reserve_entry_async(request=request, binding=binding, evidence=stale_evidence)
        async with pool.acquire() as connection:
            assert await connection.fetchval("SELECT count(*) FROM kairos_session_loss_v1.events") == 1
            assert await connection.fetchval(
                "SELECT count(*) FROM kairos_production_state_v1.risk_reservations"
            ) == 0
        current = current.model_copy(update={"evidence_sha256": "b" * 64})
        # The incomplete synthetic production schema causes a PostgreSQL
        # error during candidate validation. The savepoint is rolled back,
        # the observation remains, and the failure is reported as operational.
        with pytest.raises(ProductionStateError, match="session reservation failed"):
            await source.reserve_entry_async(request=request, binding=binding, evidence=evidence)
        async with pool.acquire() as connection:
            assert await connection.fetchval("SELECT count(*) FROM kairos_session_loss_v1.events") == 2
        current = current.model_copy(update={
            "sequence": 3, "evidence_sha256": "c" * 64,
            "observed_at": now + timedelta(microseconds=2),
        })
        with pytest.raises(ProductionStateError, match="session risk reservation refused"):
            await source.reserve_entry_async(request=request, binding=binding, evidence=stale_evidence)
        async with pool.acquire() as connection:
            assert await connection.fetchval("SELECT count(*) FROM kairos_session_loss_v1.events") == 3
            assert await connection.fetchval(
                "SELECT count(*) FROM kairos_production_state_v1.risk_reservations"
            ) == 0
        current = current.model_copy(update={
            "sequence": 4, "equity_usd": Decimal("120"), "evidence_sha256": "d" * 64,
            "observed_at": now + timedelta(microseconds=3),
        })
        with pytest.raises(ProductionStateError, match=r"session \$5 loss limit reached"):
            await source.reserve_entry_async(request=request, binding=binding, evidence=evidence)
        # The real reservation callback returned before the outward exception,
        # so the breached STOP was committed, not rolled back.
        await pool.close()
        pool = await asyncpg.create_pool(dsn, min_size=1, max_size=3)
        source.pool = pool
        async with pool.acquire() as connection:
            assert (
                await connection.fetchval(
                    "SELECT state FROM kairos_session_loss_v1.events ORDER BY sequence DESC LIMIT 1"
                )
                == "STOP"
            )
        assert await source.observe_session_loss_async({}) == "STOP"  # replay of breached observation
        current = current.model_copy(
            update={
                "sequence": 5,
                "equity_usd": Decimal("130"),
                "evidence_sha256": "f" * 64,
                "observed_at": now + timedelta(microseconds=4),
            }
        )
        assert await source.observe_session_loss_async({}) == "STOP"  # recovery never resets STOP
        async with pool.acquire() as connection:
            with pytest.raises(asyncpg.PostgresError):
                await connection.execute("UPDATE kairos_session_loss_v1.events SET state='ACTIVE'")
            with pytest.raises(asyncpg.PostgresError):
                await connection.execute("DELETE FROM kairos_session_loss_v1.events")
            with pytest.raises(asyncpg.PostgresError):
                await connection.execute(
                    "INSERT INTO kairos_session_loss_v1.events SELECT account_sha256,session_id,"
                    "sequence+1,'ACTIVE',baseline_equity_usd,baseline_net_deposits_usd,"
                    "net_deposits_usd,equity_usd,remaining_incremental_risk_usd,evidence_sha256,"
                    "observed_at + interval '1 second' FROM kairos_session_loss_v1.events "
                    "WHERE sequence=5"
                )
            assert (
                await connection.fetchval(
                    "SELECT state FROM kairos_session_loss_v1.events ORDER BY sequence DESC LIMIT 1"
                )
                == "STOP"
            )
    finally:
        await pool.close()
