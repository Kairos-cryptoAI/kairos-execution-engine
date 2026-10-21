"""Opt-in native state-source test on the fresh isolated CI PostgreSQL service.

Only public synthetic owner, operator, risk and exposure records are inserted.
The test never connects to the primary DB or starts an execution runtime.
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import UUID

import asyncpg
import pytest

from kairos_execution.managed_signer import ManagedSignerBoundary, ManagedSigningError
from kairos_execution.production_claims import (
    SCHEMA as CLAIMS_SCHEMA,
)
from kairos_execution.production_claims import (
    PostgresProductionClaims,
    provision_isolated_schema,
)
from kairos_execution.production_readiness import canonical_digest
from kairos_execution.production_state import (
    SCHEMA as STATE_SCHEMA,
)
from kairos_execution.production_state import (
    AsyncPostgresProductionSigningStateSource,
    PostgresExposureStateWriter,
    PostgresOperatorStateWriter,
    PostgresRiskStateWriter,
    ProductionStateError,
    _account_scope_sha256,
    provision_production_state_schema,
)
from kairos_execution.signing_authorization import signing_effect_id
from tests.test_signing_authorization import fixture


@pytest.mark.integration
@pytest.mark.asyncio
async def test_native_async_production_source_reads_exact_scoped_state():
    if (
        os.getenv("KAIROS_PRODUCTION_CLAIMS_TEST_PROVISION") != "1"
        or os.getenv("KAIROS_PRODUCTION_STATE_TEST_PROVISION") != "1"
    ):
        pytest.skip("explicit isolated production-state provisioning is not enabled")
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
    writer_settings = {
        name: os.getenv("KAIROS_PRODUCTION_STATE_TEST_" + name)
        for name in (
            "OPERATOR_WRITER_DSN",
            "RISK_WRITER_DSN",
            "EXPOSURE_WRITER_DSN",
            "OPERATOR_WRITER_ROLE",
            "RISK_WRITER_ROLE",
            "EXPOSURE_WRITER_ROLE",
        )
    }
    if not all(settings.values()) or not all(writer_settings.values()):
        pytest.fail("isolated state database and separate writer roles are required", pytrace=False)
    try:
        owner = await asyncpg.connect(settings["OWNER_DSN"], timeout=5, command_timeout=5)
        pools = {
            "reader": await asyncpg.create_pool(
                settings["RUNTIME_DSN"], min_size=1, max_size=2, timeout=5, command_timeout=5
            ),
            "operator": await asyncpg.create_pool(
                writer_settings["OPERATOR_WRITER_DSN"], min_size=1, max_size=2, timeout=5, command_timeout=5
            ),
            "risk": await asyncpg.create_pool(
                writer_settings["RISK_WRITER_DSN"], min_size=1, max_size=2, timeout=5, command_timeout=5
            ),
            "exposure": await asyncpg.create_pool(
                writer_settings["EXPOSURE_WRITER_DSN"], min_size=1, max_size=2, timeout=5, command_timeout=5
            ),
        }
    except Exception:
        pytest.fail("isolated native state connections unavailable", pytrace=False)

    database_uuid = UUID(settings["DATABASE_UUID"])
    verifier, request, binding, expected, _ = fixture(operation="Position close order")
    context = binding.context
    claims_kwargs = {
        "expected_database": settings["DATABASE"],
        "database_uuid": database_uuid,
        "policy_namespace": settings["POLICY_NAMESPACE"],
        "runtime_role": settings["RUNTIME_ROLE"],
        "context": context,
    }
    state_kwargs = {
        "expected_database": settings["DATABASE"],
        "database_uuid": database_uuid,
        "policy_namespace": settings["POLICY_NAMESPACE"],
        "context": context,
    }
    try:
        if await owner.fetchval("SELECT to_regnamespace($1)", CLAIMS_SCHEMA) is None:
            await provision_isolated_schema(
                owner,
                expected_database=settings["DATABASE"],
                database_uuid=database_uuid,
                policy_namespace=settings["POLICY_NAMESPACE"],
                owner_role=settings["OWNER_ROLE"],
                runtime_role=settings["RUNTIME_ROLE"],
            )
        claims = PostgresProductionClaims(pools["reader"], **claims_kwargs)
        async with pools["reader"].acquire() as connection:
            await claims.inspect(connection)
        await provision_production_state_schema(
            owner,
            expected_database=settings["DATABASE"],
            database_uuid=database_uuid,
            policy_namespace=settings["POLICY_NAMESPACE"],
            context=context,
            owner_role=settings["OWNER_ROLE"],
            runtime_role=settings["RUNTIME_ROLE"],
            operator_writer_role=writer_settings["OPERATOR_WRITER_ROLE"],
            risk_writer_role=writer_settings["RISK_WRITER_ROLE"],
            exposure_writer_role=writer_settings["EXPOSURE_WRITER_ROLE"],
        )

        # Prove the manual nonce is a real durable accepted claim in this same DB.
        assert await claims.consume_once_async(
            owner_identity=expected.owner_nonce_claim.owner_identity,
            nonce=expected.owner_nonce_claim.nonce,
            request_sha256=expected.owner_nonce_claim.request_sha256,
        )
        operator_writer = PostgresOperatorStateWriter(
            pools["operator"],
            **state_kwargs,
            expected_role=writer_settings["OPERATOR_WRITER_ROLE"],
        )
        risk_writer = PostgresRiskStateWriter(
            pools["risk"],
            **state_kwargs,
            expected_role=writer_settings["RISK_WRITER_ROLE"],
        )
        exposure_writer = PostgresExposureStateWriter(
            pools["exposure"],
            **state_kwargs,
            expected_role=writer_settings["EXPOSURE_WRITER_ROLE"],
        )
        await operator_writer.append_owner_arm_async(expected.owner_arm)
        now = datetime.now(UTC)
        request = request.model_copy(update={"expires_at": now + timedelta(seconds=3)})
        disarmed = expected.operator.model_copy(
            update={
                "version": 1,
                "state": "DISARMED",
                "arm_nonce": None,
                "arm_request_sha256": None,
                "observed_at": now - timedelta(seconds=2),
                "changed_at": now - timedelta(seconds=2),
                "expires_at": None,
                "command_sha256": "f" * 64,
                "previous_command_sha256": "0" * 64,
            }
        )
        armed = expected.operator.model_copy(
            update={
                "version": 2,
                "state": "ARMED",
                "observed_at": now - timedelta(seconds=1),
                "changed_at": now - timedelta(seconds=1),
                "previous_command_sha256": disarmed.command_sha256,
            }
        )
        await operator_writer.append_operator_observation_async(disarmed)
        await operator_writer.append_operator_observation_async(armed)
        risk = expected.risk.model_copy(
            update={
                "observed_at": now - timedelta(milliseconds=500),
                "valid_until": now + timedelta(seconds=20),
            }
        )
        exposure = expected.exposure.model_copy(
            update={
                "observed_at": now - timedelta(milliseconds=250),
                "valid_until": now + timedelta(seconds=4, milliseconds=500),
            }
        )
        await risk_writer.append_risk_decision_async(risk)
        await exposure_writer.append_exposure_async(exposure)

        source = AsyncPostgresProductionSigningStateSource(
            pools["reader"],
            **claims_kwargs,
        )
        evidence = await source.resolve_signing_evidence_async(
            request=request,
            binding=binding,
            now=datetime.now(UTC),
        )
        assert evidence.owner_arm == expected.owner_arm
        assert evidence.owner_nonce_claim.database_uuid == database_uuid
        assert evidence.operator is not None and evidence.operator.state == "ARMED"
        assert evidence.risk == risk
        assert evidence.exposure == exposure

        # The async policy consumes this real PostgreSQL snapshot. A sync call
        # must fail closed rather than block the event loop or bridge to async.
        verifier._source = source
        verifier._claim_database_uuid = database_uuid
        with pytest.raises(ManagedSigningError, match="async state source requires async authorization"):
            verifier.verify_request_at(request, binding, now=now)
        # This fixture is a position-close request. Exits validate the
        # authoritative exposure lineage but do not reserve additive entry
        # risk; retain the native exit-resolution assertion separately.
        await verifier.verify_request_async(request, binding)
        assert (
            await pools["reader"].fetchval(
                f"SELECT count(*) FROM {STATE_SCHEMA}.risk_reservations WHERE account_sha256=$1",
                _account_scope_sha256(context),
            )
            == 0
        )

        # Exercise the durable reserve-before-sign path with a fresh entry
        # request in the same database/account context and accepted owner arm.
        entry_verifier, entry_request, entry_binding, entry_expected, _ = fixture()
        entry_request = entry_request.model_copy(
            update={"expires_at": datetime.now(UTC) + timedelta(seconds=20)}
        )
        entry_risk = entry_expected.risk.model_copy(
            update={
                "observed_at": datetime.now(UTC) - timedelta(milliseconds=200),
                "valid_until": datetime.now(UTC) + timedelta(seconds=20),
            }
        )
        await risk_writer.append_risk_decision_async(entry_risk)
        entry_verifier._source = source
        entry_verifier._claim_database_uuid = database_uuid
        await entry_verifier.verify_request_async(entry_request, entry_binding)
        initial_reservation = await pools["reader"].fetchrow(
            f"SELECT account_sha256,effect_id,risk_usd,notional_usd FROM {STATE_SCHEMA}.risk_reservations "
            "WHERE context_sha256=$1 AND signing_request_id=$2",
            canonical_digest(context),
            entry_request.request_id,
        )
        assert initial_reservation is not None
        assert initial_reservation["account_sha256"] == _account_scope_sha256(context)
        assert initial_reservation["effect_id"] == entry_risk.effect_id
        assert initial_reservation["risk_usd"] == Decimal("1")
        assert initial_reservation["notional_usd"] == Decimal("0.0000000001")

        # Missing authoritative risk must stop in async authorization before
        # either the durable typed-signing claim or the managed backend.
        class NeverBackend:
            calls = 0

            def sign_typed_data(self, **kwargs):
                del kwargs
                self.calls += 1
                return "0x" + "11" * 65

        class NeverSignatureVerifier:
            def verify(self, **kwargs):
                del kwargs
                return True

        backend = NeverBackend()
        missing_risk = entry_request.model_copy(
            update={
                "request_id": entry_request.request_id + "-missing-risk",
                "expires_at": datetime.now(UTC) + timedelta(seconds=20),
            }
        )
        signer = ManagedSignerBoundary(
            binding,
            backend=backend,
            verifier=NeverSignatureVerifier(),
            claims=claims,
            authorization=entry_verifier,
        )
        with pytest.raises(ManagedSigningError, match="independent signing authorization failed"):
            await signer.sign_async(missing_risk, now=datetime.now(UTC), claims=claims)
        assert backend.calls == 0
        assert (
            await claims.load_claim(
                kind="TYPED_SIGNING",
                namespace=binding.custody_reference,
                identity=missing_risk.request_id,
            )
            is None
        )

        # Two contexts for the same remote account share one reservation
        # bucket. Concurrent exact entries cannot both spend the remaining
        # daily-risk allowance; the immutable records survive as unknown.
        fresh_operator = armed.model_copy(
            update={"observed_at": datetime.now(UTC) - timedelta(milliseconds=50)}
        )
        await operator_writer.append_operator_observation_async(fresh_operator)

        verifier2, request2, binding2, expected2, now2 = fixture(
            remote_account_id=context.remote_account_id,
            adaptive_system_id="adaptive-v2",
            nonce="owner-nonce-2",
        )
        context2 = binding2.context
        claims_kwargs2 = {**claims_kwargs, "context": context2}
        state_kwargs2 = {**state_kwargs, "context": context2}
        claims2 = PostgresProductionClaims(pools["reader"], **claims_kwargs2)
        assert await claims2.consume_once_async(
            owner_identity=expected2.owner_nonce_claim.owner_identity,
            nonce=expected2.owner_nonce_claim.nonce,
            request_sha256=expected2.owner_nonce_claim.request_sha256,
        )
        operator_writer2 = PostgresOperatorStateWriter(
            pools["operator"],
            **state_kwargs2,
            expected_role=writer_settings["OPERATOR_WRITER_ROLE"],
        )
        risk_writer2 = PostgresRiskStateWriter(
            pools["risk"],
            **state_kwargs2,
            expected_role=writer_settings["RISK_WRITER_ROLE"],
        )
        await operator_writer2.append_owner_arm_async(expected2.owner_arm)
        disarmed2 = expected2.operator.model_copy(
            update={
                "version": 1,
                "state": "DISARMED",
                "arm_nonce": None,
                "arm_request_sha256": None,
                "observed_at": now2 - timedelta(seconds=2),
                "changed_at": now2 - timedelta(seconds=2),
                "expires_at": None,
                "command_sha256": "1" * 64,
                "previous_command_sha256": "0" * 64,
            }
        )
        armed2 = expected2.operator.model_copy(
            update={
                "version": 2,
                "observed_at": now2 - timedelta(seconds=1),
                "changed_at": now2 - timedelta(seconds=1),
                "previous_command_sha256": disarmed2.command_sha256,
            }
        )
        await operator_writer2.append_operator_observation_async(disarmed2)
        await operator_writer2.append_operator_observation_async(armed2)
        await operator_writer2.append_operator_observation_async(
            armed2.model_copy(update={"observed_at": datetime.now(UTC) - timedelta(milliseconds=50)})
        )
        source2 = AsyncPostgresProductionSigningStateSource(pools["reader"], **claims_kwargs2)
        verifier2._source = source2
        verifier2._claim_database_uuid = database_uuid

        async def add_candidate(base_request, candidate_risk, writer, *, suffix, loss):
            candidate_request = base_request.model_copy(
                update={
                    "request_id": "reservation-" + suffix,
                    "expires_at": datetime.now(UTC) + timedelta(seconds=20),
                }
            )
            geometry = json.loads(candidate_request.message_json)
            geometry["id"] = "00384:" + format(int(suffix[-2:], 16), "024X")
            candidate_request = candidate_request.model_copy(
                update={"message_json": json.dumps(geometry, sort_keys=True)}
            )
            decision_id = "risk-" + suffix
            candidate_risk = candidate_risk.model_copy(
                update={
                    "signing_request_id": candidate_request.request_id,
                    "decision_id": decision_id,
                    "effect_id": signing_effect_id(
                        request=candidate_request, message=geometry, decision_id=decision_id
                    ),
                    "client_order_id": geometry["id"],
                    "worst_case_loss_usd": Decimal(loss),
                    "aggregate_open_risk_usd": Decimal("0"),
                    "aggregate_open_notional_usd": Decimal("0"),
                    "observed_at": datetime.now(UTC) - timedelta(milliseconds=100),
                    "valid_until": datetime.now(UTC) + timedelta(seconds=25),
                }
            )
            await writer.append_risk_decision_async(candidate_risk)
            return candidate_request

        candidate1 = await add_candidate(entry_request, entry_risk, risk_writer, suffix="ctx1-01", loss="6")
        candidate2 = await add_candidate(request2, expected2.risk, risk_writer2, suffix="ctx2-02", loss="6")
        results = await asyncio.gather(
            entry_verifier.verify_request_async(candidate1, entry_binding),
            verifier2.verify_request_async(candidate2, binding2),
            return_exceptions=True,
        )
        assert sum(result is None for result in results) == 1
        assert sum(isinstance(result, ManagedSigningError) for result in results) == 1
        total_after_race = await pools["reader"].fetchval(
            f"SELECT sum(risk_usd) FROM {STATE_SCHEMA}.risk_reservations WHERE account_sha256=$1",
            _account_scope_sha256(context),
        )
        assert total_after_race == Decimal("7")

        # Exact cap boundary is accepted; the next cent is refused. No local
        # clock expiry or ambiguous signing outcome frees either reservation.
        candidate3 = await add_candidate(request2, expected2.risk, risk_writer2, suffix="ctx2-03", loss="3")
        await verifier2.verify_request_async(candidate3, binding2)
        await verifier2.verify_request_async(candidate3, binding2)
        evidence3 = await source2.resolve_signing_evidence_async(
            request=candidate3, binding=binding2, now=datetime.now(UTC)
        )
        rebound_evidence3 = evidence3.model_copy(
            update={"risk": evidence3.risk.model_copy(update={"worst_case_loss_usd": Decimal("4")})}
        )
        with pytest.raises(ProductionStateError, match="persisted decision"):
            await source2.reserve_entry_async(
                request=candidate3, binding=binding2, evidence=rebound_evidence3
            )
        candidate4 = await add_candidate(
            entry_request, entry_risk, risk_writer, suffix="ctx1-04", loss="0.01"
        )
        with pytest.raises(ManagedSigningError, match="independent signing authorization failed"):
            await entry_verifier.verify_request_async(candidate4, entry_binding)
        retained_count = await pools["reader"].fetchval(
            f"SELECT count(*) FROM {STATE_SCHEMA}.risk_reservations WHERE account_sha256=$1",
            _account_scope_sha256(context),
        )
        assert retained_count == 3
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await pools["reader"].execute(
                f"UPDATE {STATE_SCHEMA}.risk_reservations SET risk_usd=0 WHERE effect_id=$1",
                candidate3.request_id,
            )

        # Once that exact nonce has armed and later disarmed, PostgreSQL itself
        # refuses to re-arm it; a new signed/consumed owner command is required.
        server_now = await pools["operator"].fetchval("SELECT clock_timestamp()")
        disarmed_at = max(
            armed.observed_at + timedelta(milliseconds=1),
            server_now - timedelta(milliseconds=500),
        )
        disarmed_again = armed.model_copy(
            update={
                "version": 3,
                "state": "DISARMED",
                "arm_nonce": None,
                "arm_request_sha256": None,
                "observed_at": disarmed_at,
                "changed_at": disarmed_at,
                "expires_at": None,
                "command_sha256": "e" * 64,
                "previous_command_sha256": armed.command_sha256,
            }
        )
        await operator_writer.append_operator_observation_async(disarmed_again)
        reused_arm = armed.model_copy(
            update={
                "version": 4,
                "observed_at": disarmed_at + timedelta(milliseconds=100),
                "changed_at": disarmed_at + timedelta(milliseconds=100),
                "previous_command_sha256": disarmed_again.command_sha256,
            }
        )
        with pytest.raises(ProductionStateError):
            await operator_writer.append_operator_observation_async(reused_arm)

        # Separate writer roles are real DB boundaries, not labels on an object.
        async with pools["risk"].acquire() as connection:
            assert not await connection.fetchval(
                "SELECT has_table_privilege(current_user,$1,'INSERT')",
                f"{STATE_SCHEMA}.operator_observations",
            )
            with pytest.raises(asyncpg.InsufficientPrivilegeError):
                await connection.execute(f"DELETE FROM {STATE_SCHEMA}.risk_decisions")
        async with pools["reader"].acquire() as connection:
            with pytest.raises(asyncpg.InsufficientPrivilegeError):
                await connection.execute(f"DELETE FROM {STATE_SCHEMA}.owner_arms")
    except asyncpg.PostgresError:
        # Do not surface server diagnostics/connection information from native CI.
        pytest.fail("native production-state database assertion failed", pytrace=False)
    finally:
        for pool in pools.values():
            await pool.close()
        await owner.close()
