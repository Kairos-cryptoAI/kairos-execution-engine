"""Synthetic I/O journal operations against explicitly disposable PostgreSQL."""

import os
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import UUID, uuid4

import asyncpg
import pytest

from kairos_execution.production_claims import DDL as CLAIMS_DDL
from kairos_execution.production_claims import PostgresProductionClaims
from kairos_execution.production_session_loss import DDL as SESSION_DDL
from kairos_execution.production_session_loss import VerifiedSessionObservationV1
from kairos_execution.production_state import (
    AsyncPostgresProductionSigningStateSource,
    ProductionStateError,
    _account_scope_sha256,
)
from kairos_execution.session_entry_io import DDL as IO_DDL
from kairos_execution.session_entry_io import PostgresEntryIoJournal
from tests.test_signing_authorization import fixture

DB = "kairos_production_evidence_iounknown20261109"


@pytest.mark.asyncio
async def test_account_wide_pending_survives_lost_ack_and_restart(monkeypatch):
    dsn = os.getenv("KAIROS_ENTRY_IO_TEST_DSN")
    if not dsn:
        pytest.skip("explicit disposable local database required")
    if not dsn.startswith("postgresql://postgres@127.0.0.1:") or not dsn.endswith("/" + DB):
        pytest.fail("refusing non-disposable database")
    pool = await asyncpg.create_pool(dsn, min_size=1, max_size=4)
    try:
        async with pool.acquire() as connection:
            assert await connection.fetchval("SELECT current_database()") == DB
            for schema in (
                "kairos_session_entry_io_v1",
                "kairos_session_loss_v1",
                "kairos_production_evidence_v1",
            ):
                assert await connection.fetchval("SELECT to_regnamespace($1)", schema) is None
            await connection.execute(SESSION_DDL)
            await connection.execute(CLAIMS_DDL)
            await connection.execute(IO_DDL)
        _, request, binding, evidence, _ = fixture()
        source = AsyncPostgresProductionSigningStateSource(
            pool,
            expected_database=DB,
            database_uuid=uuid4(),
            policy_namespace="synthetic:io",
            runtime_role="synthetic_reader",
            context=request.context,
            require_session_loss_latch=True,
        )
        claims = PostgresProductionClaims(
            pool,
            expected_database=DB,
            database_uuid=source.database_uuid,
            policy_namespace=source.policy_namespace,
            runtime_role=source.runtime_role,
            context=request.context,
        )

        async def inspect(connection):
            assert await connection.fetchval("SELECT current_database()") == DB

        monkeypatch.setattr(source, "inspect", inspect)

        async def inspect_claims(_self, connection):
            await inspect(connection)

        monkeypatch.setattr(PostgresProductionClaims, "inspect", inspect_claims)
        account = _account_scope_sha256(request.context)
        session_id = UUID("e76b83bb-86d6-4a93-a300-0409dc066952")
        observation = VerifiedSessionObservationV1(
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
        monkeypatch.setattr(
            source._session_loss_verifier, "verify", lambda raw, *, account_sha256: observation
        )
        assert await source.observe_session_loss_async({}) == "ACTIVE"
        journal = PostgresEntryIoJournal(source, claims, session_id=session_id, max_age=timedelta(seconds=5))
        request_sha, signature_sha = "b" * 64, "c" * 64
        reference, request_id = binding.custody_reference, request.request_id
        async with pool.acquire() as connection:
            await connection.execute(
                "INSERT INTO kairos_production_evidence_v1.claims "
                "(claim_kind,namespace,identity,request_sha256,context_sha256) "
                "VALUES('TYPED_SIGNING',$1,$2,$3,$4)",
                reference,
                request_id,
                request_sha,
                source.context_sha256,
            )

        real_write = source._write

        async def lost_ack(callback):
            await real_write(callback)
            raise ConnectionError("simulated lost commit acknowledgement")

        monkeypatch.setattr(source, "_write", lost_ack)
        with pytest.raises(ConnectionError, match="simulated"):
            await journal.begin_sign(
                custody_reference=reference, request_id=request_id, request_sha=request_sha
            )
        monkeypatch.setattr(source, "_write", real_write)

        async def synthetic_resolve(connection, *, account_sha256, context_sha256, now):
            return observation

        monkeypatch.setattr(source._session_loss_verifier, "resolve", synthetic_resolve)
        with pytest.raises(ProductionStateError, match="session risk reservation refused"):
            await source.reserve_entry_async(request=request, binding=binding, evidence=evidence)
        await pool.close()
        pool = await asyncpg.create_pool(dsn, min_size=1, max_size=4)
        source.pool = claims.pool = pool
        with pytest.raises(PermissionError):
            await journal.begin_sign(custody_reference=reference, request_id="other", request_sha=request_sha)
        with pytest.raises(PermissionError):
            await journal.begin_wire(
                custody_reference=reference,
                request_id=request_id,
                request_sha=request_sha,
                signature_sha=signature_sha,
                effect_id="effect",
                wire_sha="d" * 64,
            )
        # Synthetic completed claim is inserted only in this isolated fixture.
        async with pool.acquire() as connection:
            await connection.execute(
                "INSERT INTO kairos_production_evidence_v1.terminals "
                "(claim_kind,namespace,identity,request_sha256,terminal_status,result_sha256) "
                "VALUES('TYPED_SIGNING',$1,$2,$3,'COMPLETED',$4)",
                reference,
                request_id,
                request_sha,
                signature_sha,
            )
        await journal.complete_sign(
            custody_reference=reference,
            request_id=request_id,
            request_sha=request_sha,
            signature_sha=signature_sha,
        )
        # SQL three-valued logic must not allow a NULL signature to advance.
        async with pool.acquire() as connection:
            with pytest.raises(asyncpg.PostgresError):
                await connection.execute(
                    "INSERT INTO kairos_session_entry_io_v1.events "
                    "(account_sha256,session_id,sequence,phase,custody_reference,request_id,"
                    "request_sha256,signature_sha256,effect_id,wire_sha256) "
                    "VALUES($1,$2,3,'WIRE_STARTED',$3,$4,$5,NULL,'effect',$6)",
                    account,
                    session_id,
                    reference,
                    request_id,
                    request_sha,
                    "d" * 64,
                )
        async with pool.acquire() as connection:
            await connection.execute(
                "INSERT INTO kairos_production_evidence_v1.claims "
                "(claim_kind,namespace,identity,request_sha256,context_sha256) "
                "VALUES('WIRE_DISPATCH',$1,$2,$3,$4)",
                "wire:" + source.context_sha256,
                "effect",
                "d" * 64,
                source.context_sha256,
            )
        await journal.begin_wire(
            custody_reference=reference,
            request_id=request_id,
            request_sha=request_sha,
            signature_sha=signature_sha,
            effect_id="effect",
            wire_sha="d" * 64,
        )
        with pytest.raises(PermissionError):
            await journal.begin_wire(
                custody_reference=reference,
                request_id=request_id,
                request_sha=request_sha,
                signature_sha=signature_sha,
                effect_id="effect",
                wire_sha="d" * 64,
            )
        async with pool.acquire() as connection:
            rows = await connection.fetch(
                "SELECT phase FROM kairos_session_entry_io_v1.events ORDER BY sequence"
            )
            assert [row["phase"] for row in rows] == ["SIGN_STARTED", "SIGNED", "WIRE_STARTED"]
            with pytest.raises(asyncpg.PostgresError):
                await connection.execute("DELETE FROM kairos_session_entry_io_v1.events")
    finally:
        await pool.close()
