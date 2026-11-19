"""Synthetic-only auth milestone validation; no endpoint is called."""

from uuid import UUID

import pytest

from kairos_execution.auth_audit import AuthAuditJournal, public_auth_error_code
from kairos_execution.local_custody import LocalCustodyError
from kairos_execution.production_claims import PostgresProductionClaims
from kairos_execution.production_readiness import ProductionContextV1


def fixture():
    context = ProductionContextV1(
        remote_account_id="synthetic-account",
        adaptive_system_id="synthetic-auth",
        frozen_policy_sha256="1" * 64,
        source_set_sha256="2" * 64,
    )
    claims = PostgresProductionClaims(
        object(),
        expected_database="kairos_production_evidence_auth_audit_test",
        database_uuid=UUID(int=1),
        policy_namespace="synthetic-auth",
        runtime_role="auth_runtime",
        context=context,
    )
    return claims


@pytest.mark.asyncio
async def test_audit_persists_only_safe_stages_and_digests(monkeypatch):
    claims = fixture()
    calls = []

    async def claim(*args):
        calls.append(args)
        return True

    monkeypatch.setattr(claims, "claim", claim)
    audit = AuthAuditJournal(claims)
    await audit.record("SIGN_STARTED")
    await audit.record("AUTH_HTTP", http_status=201)
    await audit.record("AUTH_ERROR_CODE", http_status=400, code="TWOFA_REQUIRED")
    assert [call[2] for call in calls] == [
        "SIGN_STARTED",
        "AUTH_HTTP:201",
        "AUTH_ERROR_CODE:400:TWOFA_REQUIRED",
    ]
    assert all(len(call[3]) == 64 for call in calls)
    assert public_auth_error_code("synthetic-private-message") == "OTHER"


@pytest.mark.asyncio
async def test_audit_duplicate_or_unavailable_commit_refuses(monkeypatch):
    claims = fixture()

    async def claim(*args):
        return False

    monkeypatch.setattr(claims, "claim", claim)
    with pytest.raises(LocalCustodyError):
        await AuthAuditJournal(claims).record("AUTH_POST_STARTED")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "stage,status,code",
    [
        ("synthetic-private", None, None),
        ("AUTH_HTTP", True, None),
        ("AUTH_HTTP", 600, None),
        ("AUTH_HTTP", 99, None),
        ("AUTH_ERROR_CODE", 400, "synthetic-private"),
    ],
)
async def test_untrusted_stage_fields_refused_before_write(monkeypatch, stage, status, code):
    claims = fixture()

    async def claim(*args):
        pytest.fail("invalid audit values must not enter the ledger")

    monkeypatch.setattr(claims, "claim", claim)
    with pytest.raises(LocalCustodyError):
        await AuthAuditJournal(claims).record(stage, http_status=status, code=code)
