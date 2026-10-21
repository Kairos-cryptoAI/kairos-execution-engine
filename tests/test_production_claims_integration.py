"""Explicit isolated database/role qualification; never default or primary DDL.

Root must create a fresh exact-prefix database and separate preexisting roles.
Only the opt-in TEST_PROVISION flag invokes the owner provisioning function.
No database/role creation, data deletion or cleanup is performed by this test.
"""

import asyncio
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import asyncpg
import pytest

from kairos_execution.local_custody import CoincurveTypedDataVerifier, LocalEncryptedKeystoreBackend
from kairos_execution.managed_signer import (
    CustodyBindingV1,
    ManagedSignerBoundary,
    ManagedSigningError,
    ManagedSigningRequestV1,
    reviewed_schema_sha256,
)
from kairos_execution.production_claims import (
    SCHEMA,
    PostgresProductionClaims,
    ProductionClaimError,
    provision_isolated_schema,
)
from tests.production_evidence_fixtures import signed_gate_fixture


async def _qualify_synthetic_local_custody(store, restarted, scope, tmp_path):
    """Real SQL claims + one-shot child + independent recovery; no venue authority.

    The authorization here is deliberately a test double, not a production
    issuer/operator/risk verifier. The public key-one wallet never has funds.
    """
    from eth_account import Account

    from tests.test_local_custody import _make_private

    chain = 161803
    instruments = ("BTCUSD", "ETHUSD", "SOLUSD", "BNBUSD", "XRPUSD")
    synthetic_key = (1).to_bytes(32, "big")
    unlock = "synthetic-native-test-only"
    wallet = Account.from_key(synthetic_key).address
    key_path, unlock_path = tmp_path / "synthetic-wallet.json", tmp_path / "synthetic-unlock.txt"
    _make_private(key_path, json.dumps(Account.encrypt(synthetic_key, unlock, kdf="pbkdf2")).encode())
    _make_private(unlock_path, unlock.encode())
    binding = CustodyBindingV1(
        context=scope,
        custody_reference="fixture:native-local-custody",
        wallet_address=wallet,
        chain_id=chain,
        schema_sha256=reviewed_schema_sha256(chain),
        approved_instruments=instruments,
        custody_receipt_sha256="a" * 64,
    )

    class FixtureAuthorization:
        def verify_request(self, request, expected_binding):
            assert expected_binding == binding
            assert request.manual_request_sha256 == "b" * 64

    backend = LocalEncryptedKeystoreBackend(
        python_executable=Path(os.path.abspath(os.sys.executable)),
        keystore_file=key_path,
        unlock_file=unlock_path,
        custody_reference=binding.custody_reference,
        wallet_address=wallet,
        chain_id=chain,
        approved_instruments=instruments,
    )
    signer = ManagedSignerBoundary(
        binding,
        backend=backend,
        verifier=CoincurveTypedDataVerifier(),
        claims=store,  # Only the async API below is used.
        authorization=FixtureAuthorization(),
    )
    now = datetime.now(UTC)
    message = {
        "id": "00384:ABCDEF0123456789ABCDEF0123",
        "instrument": instruments[0],
        "side": "BUY",
        "leverage": 1,
        "quantity": 100,
        "limitPrice": 1000,
        "chainId": chain,
    }
    request = ManagedSigningRequestV1(
        request_id="native-local-once",
        context=scope,
        manual_request_sha256="b" * 64,
        custody_receipt_sha256=binding.custody_receipt_sha256,
        operation="New limit order",
        message_json=json.dumps(message),
        expires_at=now + timedelta(seconds=30),
    )
    result = await signer.sign_async(request, now=now, claims=store)
    row = await restarted.load_claim(
        kind="TYPED_SIGNING", namespace=binding.custody_reference, identity=request.request_id
    )
    assert row["terminal_status"] == "COMPLETED"
    assert row["result_sha256"] == result.signature_sha256
    assert result.signature not in repr(result) and "signature" not in result.model_dump()
    with pytest.raises(ManagedSigningError, match="claimed or unresolved"):
        await signer.sign_async(request, now=now, claims=restarted)

    # A failed real decrypt becomes an immutable native UNRESOLVED terminal.
    # Fixing the file afterwards cannot release or replay that consumed claim.
    _make_private(unlock_path, b"intentionally-wrong-test-unlock")
    failed = request.model_copy(update={"request_id": "native-local-failed"})
    with pytest.raises(ManagedSigningError, match="unresolved"):
        await signer.sign_async(failed, now=now, claims=store)
    failed_row = await restarted.load_claim(
        kind="TYPED_SIGNING", namespace=binding.custody_reference, identity=failed.request_id
    )
    assert failed_row["terminal_status"] == "UNRESOLVED"
    _make_private(unlock_path, unlock.encode())
    with pytest.raises(ManagedSigningError, match="claimed or unresolved"):
        await signer.sign_async(failed, now=now, claims=restarted)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_native_isolated_claims_races_restart_unknown_and_role_boundary(tmp_path):
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
        if await owner.fetchval("SELECT to_regnamespace($1)", SCHEMA) is None:
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
        async with pool.acquire() as connection:
            await store.inspect(connection)
        claim = dict(
            custody_reference="fixture:custody", request_id="concurrent-once", request_sha256="a" * 64
        )
        results = await asyncio.gather(*(store.claim_once_async(**claim) for _ in range(8)))
        assert results.count(True) == 1 and results.count(False) == 7
        await pool.close()
        pool = await asyncpg.create_pool(settings["RUNTIME_DSN"], min_size=1, max_size=4, command_timeout=5)
        restarted = PostgresProductionClaims(pool, **kwargs)
        await _qualify_synthetic_local_custody(
            PostgresProductionClaims(pool, **kwargs), restarted, scope, tmp_path
        )
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
        wire_claim = dict(namespace="wire:" + "f" * 64, effect_id="1" * 64, request_sha256="2" * 64)
        assert await restarted.claim_wire_once_async(**wire_claim)
        await restarted.finish_wire_async(**wire_claim, terminal_status="COMPLETED", response_sha256="3" * 64)
        wire_row = await restarted.load_claim(
            kind="WIRE_DISPATCH", namespace=wire_claim["namespace"], identity=wire_claim["effect_id"]
        )
        assert wire_row["terminal_status"] == "COMPLETED" and wire_row["result_sha256"] == "3" * 64
        assert await restarted.claim_wire_once_async(**wire_claim) is False
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
            with pytest.raises(asyncpg.InsufficientPrivilegeError):
                await runtime.execute(f"DELETE FROM {SCHEMA}.wire_terminals")
            with pytest.raises(asyncpg.ForeignKeyViolationError):
                await runtime.execute(
                    f"INSERT INTO {SCHEMA}.terminals VALUES('TYPED_SIGNING','fixture:custody',"
                    "'unbound-terminal',$1,'COMPLETED',$2,DEFAULT) ON CONFLICT DO NOTHING",
                    "b" * 64,
                    "d" * 64,
                )
            with pytest.raises(asyncpg.ForeignKeyViolationError):
                await runtime.execute(
                    f"INSERT INTO {SCHEMA}.wire_terminals VALUES('WIRE_DISPATCH','fixture:wire',"
                    "'unbound-terminal',$1,'COMPLETED',$2,DEFAULT)",
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
