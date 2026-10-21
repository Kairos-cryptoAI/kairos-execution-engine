"""Unit checks for fail-closed, async production-state boundaries.

These tests use synthetic records only; native database acceptance lives in the
opt-in isolated PostgreSQL integration test.
"""

from datetime import timedelta
from uuid import UUID

import pytest

from kairos_execution.production_readiness import ProductionContextV1
from kairos_execution.production_state import (
    AsyncPostgresProductionSigningStateSource,
    ProductionStateError,
    _payload,
    provision_production_state_schema,
)
from tests.test_signing_authorization import fixture


class _WrongIdentityConnection:
    def __init__(self) -> None:
        self.ddl_seen = False

    async def fetchrow(self, query: str, *args):
        if "current_database()" in query:
            return {"db": "postgres", "role": "not_owner"}
        raise AssertionError("unexpected query before database/owner identity check")

    async def execute(self, query: str, *args):
        self.ddl_seen = True
        raise AssertionError("provisioning DDL must not run on a wrong database")

    def transaction(self):
        raise AssertionError("provisioning transaction must not start before owner validation")


@pytest.mark.asyncio
async def test_provisioning_refuses_wrong_database_identity_before_ddl():
    _, _, binding, _, _ = fixture()
    source_context = binding.context
    connection = _WrongIdentityConnection()
    with pytest.raises(ProductionStateError, match="owner/database mismatch"):
        await provision_production_state_schema(
            connection,  # type: ignore[arg-type]
            expected_database="kairos_production_evidence_123456789abc",
            database_uuid=UUID("31da18d5-2b77-407d-b0dc-5366f03ae10a"),
            policy_namespace="fixture:production-state",
            context=source_context,
            owner_role="state_owner",
            runtime_role="state_reader",
            operator_writer_role="operator_writer",
            risk_writer_role="risk_writer",
            exposure_writer_role="exposure_writer",
        )
    assert connection.ddl_seen is False


def test_production_context_payload_digest_is_deterministic():
    context = ProductionContextV1(
        remote_account_id="synthetic-account",
        adaptive_system_id="synthetic-adaptive",
        frozen_policy_sha256="b" * 64,
        source_set_sha256="c" * 64,
    )
    first = _payload(context)
    second = _payload(context.model_copy())
    assert first == second
    assert len(first[1]) == 64


def test_source_rejects_longer_than_five_second_freshness_contract():
    _, _, binding, _, _ = fixture()
    with pytest.raises(ValueError, match="may not exceed five seconds"):
        AsyncPostgresProductionSigningStateSource(
            object(),  # type: ignore[arg-type]
            expected_database="kairos_production_evidence_123456789abc",
            database_uuid=UUID("31da18d5-2b77-407d-b0dc-5366f03ae10a"),
            policy_namespace="fixture:production-state",
            runtime_role="state_reader",
            context=binding.context,
            max_snapshot_age=timedelta(seconds=6),
        )
