"""Explicit isolated database/role qualification; never default or primary DDL.

Root must create a fresh exact-prefix database and separate preexisting roles.
Only the opt-in TEST_PROVISION flag invokes the owner provisioning function.
No database/role creation, data deletion or cleanup is performed by this test.
"""

import asyncio
import os
from uuid import UUID

import asyncpg
import pytest

from kairos_execution.production_claims import (
    SCHEMA,
    PostgresProductionClaims,
    ProductionClaimError,
    provision_isolated_schema,
)
from tests.production_evidence_fixtures import signed_gate_fixture


@pytest.mark.integration
@pytest.mark.asyncio
async def test_native_isolated_claims_races_restart_unknown_and_role_boundary():
    if os.getenv("KAIROS_PRODUCTION_CLAIMS_TEST_PROVISION") != "1":
        pytest.skip("explicit isolated production-claims provisioning is not enabled")
    names = (
        "OWNER_DSN",
        "RUNTIME_DSN",
        "DATABASE",
        "DATABASE_UUID",
        "POLICY_NAMESPACE",
        "OWNER_ROLE",
        "RUNTIME_ROLE",
    )
    settings = {name: os.getenv("KAIROS_PRODUCTION_CLAIMS_TEST_" + name) for name in names}
    if not all(settings.values()):
        pytest.fail(
            "isolated database identity and preexisting owner/runtime roles are required", pytrace=False
        )
    # Never print DSNs or native exception messages even when authentication fails.
    try:
        owner = await asyncpg.connect(settings["OWNER_DSN"], timeout=5, command_timeout=5)
        pool = await asyncpg.create_pool(
            settings["RUNTIME_DSN"], min_size=1, max_size=4, timeout=5, command_timeout=5
        )
    except Exception:
        pytest.fail("isolated native connection unavailable", pytrace=False)
    try:
        database_uuid = UUID(settings["DATABASE_UUID"])
        await provision_isolated_schema(
            owner,
            expected_database=settings["DATABASE"],
            database_uuid=database_uuid,
            policy_namespace=settings["POLICY_NAMESPACE"],
            owner_role=settings["OWNER_ROLE"],
            runtime_role=settings["RUNTIME_ROLE"],
        )
        scope = signed_gate_fixture()[3]
        kwargs = dict(
            expected_database=settings["DATABASE"],
            database_uuid=database_uuid,
            policy_namespace=settings["POLICY_NAMESPACE"],
            runtime_role=settings["RUNTIME_ROLE"],
            context=scope,
        )
        store = PostgresProductionClaims(pool, **kwargs)
        claim = dict(
            custody_reference="fixture:custody", request_id="concurrent-once", request_sha256="a" * 64
        )
        results = await asyncio.gather(*(store.claim_once_async(**claim) for _ in range(8)))
        assert results.count(True) == 1 and results.count(False) == 7
        await pool.close()
        pool = await asyncpg.create_pool(settings["RUNTIME_DSN"], min_size=1, max_size=4, command_timeout=5)
        restarted = PostgresProductionClaims(pool, **kwargs)
        assert await restarted.claim_once_async(**claim) is False
        row = await restarted.load_claim(
            kind="TYPED_SIGNING", namespace="fixture:custody", identity="concurrent-once"
        )
        assert row["terminal_status"] is None  # Process-loss CLAIMED stays unknown, not retryable.
        with pytest.raises(ProductionClaimError, match="rebound"):
            await restarted.claim_once_async(**{**claim, "request_sha256": "b" * 64})
        with pytest.raises(ProductionClaimError):
            await PostgresProductionClaims(pool, **{**kwargs, "database_uuid": UUID(int=1)}).claim_once_async(
                **claim
            )
        await restarted.finish_signing_async(**claim, terminal_status="UNRESOLVED", result_sha256=None)
        with pytest.raises(ProductionClaimError, match="conflict"):
            await restarted.finish_signing_async(**claim, terminal_status="COMPLETED", result_sha256="b" * 64)
        nonce = dict(owner_identity="fixture:owner", nonce="one-use", request_sha256="c" * 64)
        assert await restarted.consume_once_async(**nonce)
        assert await restarted.consume_once_async(**nonce) is False
        runtime = await pool.acquire()
        try:
            await restarted.inspect(runtime)
            with pytest.raises(asyncpg.InsufficientPrivilegeError):
                await runtime.execute(f"DELETE FROM {SCHEMA}.claims")
            with pytest.raises(asyncpg.InsufficientPrivilegeError):
                await runtime.execute(f"TRUNCATE {SCHEMA}.claims CASCADE")
            with pytest.raises(asyncpg.ForeignKeyViolationError):
                await runtime.execute(
                    f"INSERT INTO {SCHEMA}.terminals VALUES('TYPED_SIGNING','fixture:custody',"
                    "'unbound-terminal',$1,'COMPLETED',$2,DEFAULT) ON CONFLICT DO NOTHING",
                    "b" * 64,
                    "d" * 64,
                )
        finally:
            await pool.release(runtime)
        # Owner can provision, but immutable UPDATE/DELETE is blocked even there.
        with pytest.raises(asyncpg.RaiseError):
            await owner.execute(f"UPDATE {SCHEMA}.claims SET request_sha256=$1", "e" * 64)
        runtime_role = settings["RUNTIME_ROLE"]
        await owner.execute(f'GRANT UPDATE ON {SCHEMA}.claims TO "{runtime_role}"')
        try:
            with pytest.raises(ProductionClaimError, match="alter immutable"):
                await restarted.claim_once_async(**{**claim, "request_id": "unsafe-grant"})
        finally:
            await owner.execute(f'REVOKE UPDATE ON {SCHEMA}.claims FROM "{runtime_role}"')
    finally:
        await pool.close()
        await owner.close()
