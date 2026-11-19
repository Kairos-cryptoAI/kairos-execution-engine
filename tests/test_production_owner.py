"""Owner tools produce material that the production verifiers accept, and nothing else."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest

from kairos_execution.production_owner import (
    OWNER_KEY_FILE,
    OwnerToolError,
    freeze_policy,
    generate_issuer,
    generate_owner_key,
    issue_receipt,
    sign_manual_arm,
    store_artifact,
)
from kairos_execution.production_readiness import (
    EvidenceKind,
    PreconditionsV1,
    ProductionContextV1,
    _verify_owner_signed_arm,
    canonical_digest,
)
from kairos_execution.signed_evidence import (
    DirectoryEvidenceResolver,
    FrozenGatePolicyV1,
    OperatorFactsV1,
    SignedReceiptInterpreter,
)

NOW = datetime(2026, 11, 14, 12, 0, tzinfo=UTC)


def _frozen() -> FrozenGatePolicyV1:
    return FrozenGatePolicyV1(
        adaptive_system_id="hourly_trend_candidates_v1",
        source_set_sha256="b" * 64,
        campaign_id="kairos-evedex-2026",
        evaluator_sha256="c" * 64,
        minimum_profit_factor=Decimal("1.2"),
        maximum_drawdown_fraction=Decimal("0.2"),
        crash_scenario_sha256s=("d" * 64,),
        required_alert_names=("local-process-health", "local-supervisor-restart"),
        minimum_forward_days=365,
        minimum_natural_closes=500,
        frozen_at=NOW - timedelta(days=1),
    )


def _context(evidence_dir) -> ProductionContextV1:
    return ProductionContextV1(
        remote_account_id="evedex-account-1",
        adaptive_system_id="hourly_trend_candidates_v1",
        frozen_policy_sha256=freeze_policy(evidence_dir, _frozen()),
        source_set_sha256="b" * 64,
    )


def _preconditions(context: ProductionContextV1) -> PreconditionsV1:
    return PreconditionsV1(
        context=context,
        evidence_sha256="e" * 64,
        verified_at=NOW - timedelta(minutes=1),
        valid_until=NOW + timedelta(hours=6),
        owner_identity="owner-1",
        dollar_cap=Decimal("200"),
        daily_stop_loss_usd=Decimal("5"),
    )


def test_owner_arm_is_accepted_by_the_production_arm_verifier(tmp_path):
    context = _context(tmp_path / "evidence")
    key = generate_owner_key(
        tmp_path / "owner",
        owner_identity="owner-1",
        context=context,
        valid_from=NOW - timedelta(hours=1),
        valid_until=NOW + timedelta(days=30),
    )
    preconditions = _preconditions(context)
    signed = sign_manual_arm(
        tmp_path / "owner" / OWNER_KEY_FILE, key, preconditions, lifetime=timedelta(minutes=10), now=NOW
    )
    request, _digest = _verify_owner_signed_arm(
        signed,
        preconditions,
        owner_key=key,
        expected_owner_key_sha256=canonical_digest(key),
        expected_owner_identity="owner-1",
        now=NOW + timedelta(seconds=5),
        maximum_lifetime=timedelta(minutes=15),
    )
    assert request.dollar_cap == Decimal("200") and request.expires_at == NOW + timedelta(minutes=10)
    assert "BEGIN" not in (tmp_path / "owner" / "owner-arm-key.json").read_text(encoding="utf-8")
    other = sign_manual_arm(
        tmp_path / "owner" / OWNER_KEY_FILE, key, preconditions, lifetime=timedelta(minutes=10), now=NOW
    )
    assert other.request.nonce != signed.request.nonce, "every arm has its own nonce"


def test_owner_tools_never_overwrite_keys_and_refuse_a_foreign_key(tmp_path):
    context = _context(tmp_path / "evidence")
    window = dict(valid_from=NOW - timedelta(hours=1), valid_until=NOW + timedelta(days=1))
    key = generate_owner_key(tmp_path / "a", owner_identity="owner-1", context=context, **window)
    with pytest.raises(OwnerToolError, match="already exists"):
        generate_owner_key(tmp_path / "a", owner_identity="owner-1", context=context, **window)
    generate_owner_key(tmp_path / "b", owner_identity="owner-1", context=context, **window)
    with pytest.raises(OwnerToolError, match="does not match"):
        sign_manual_arm(
            tmp_path / "b" / OWNER_KEY_FILE,
            key,
            _preconditions(context),
            lifetime=timedelta(minutes=5),
            now=NOW,
        )


def test_issued_receipt_is_verified_by_the_production_interpreter(tmp_path):
    evidence = tmp_path / "evidence"
    context = _context(evidence)
    drill = store_artifact(evidence, b'{"drill": "operator kill and resume"}')
    policy = generate_issuer(
        tmp_path / "issuer",
        issuer_id="owner-1",
        frozen=_frozen(),
        context=context,
        allowed_kinds=[EvidenceKind.GLOBAL_OPERATOR_CONTROL],
        valid_from=NOW - timedelta(hours=1),
        valid_until=NOW + timedelta(days=30),
    )
    facts = OperatorFactsV1(
        artifact_sha256s=(drill,),
        control_database_identity="kairos_production_evidence_x",
        operator_role="kx_operator_x",
        runtime_role="kx_runtime_x",
        operator_version=2,
        killed_at=NOW - timedelta(minutes=30),
        resumed_at=NOW - timedelta(minutes=20),
        restart_observed_version=2,
        entries_dispatched_after_kill=0,
        protected_exit_failures=0,
        duplicate_dispatches=0,
        unknown_claim_retries=0,
        denied_unsafe_privilege_count=3,
    )
    reference = issue_receipt(
        tmp_path / "issuer" / "evidence-issuer.ed25519",
        policy,
        kind=EvidenceKind.GLOBAL_OPERATOR_CONTROL,
        facts=facts,
        evidence_dir=evidence,
        issued_at=NOW,
    )
    verified = SignedReceiptInterpreter(
        EvidenceKind.GLOBAL_OPERATOR_CONTROL, (policy,), DirectoryEvidenceResolver(evidence)
    ).verify(reference, context)
    assert verified.reference == reference and verified.outcome == "SEALED_PASS"
    raw = (evidence / f"{reference.content_sha256}.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == reference.content_sha256
    with pytest.raises(OwnerToolError, match="not allowed"):
        issue_receipt(
            tmp_path / "issuer" / "evidence-issuer.ed25519",
            policy,
            kind=EvidenceKind.PRODUCTION_LIMITS,
            facts=facts,
            evidence_dir=evidence,
            issued_at=NOW,
        )


def test_facts_that_cite_a_missing_artifact_are_not_signed(tmp_path):
    evidence = tmp_path / "evidence"
    context = _context(evidence)
    policy = generate_issuer(
        tmp_path / "issuer",
        issuer_id="owner-1",
        frozen=_frozen(),
        context=context,
        allowed_kinds=[EvidenceKind.GLOBAL_OPERATOR_CONTROL],
        valid_from=NOW - timedelta(hours=1),
        valid_until=NOW + timedelta(days=30),
    )
    facts = OperatorFactsV1(
        artifact_sha256s=("f" * 64,),
        control_database_identity="db",
        operator_role="op",
        runtime_role="rt",
        operator_version=1,
        killed_at=NOW - timedelta(minutes=2),
        resumed_at=NOW - timedelta(minutes=1),
        restart_observed_version=1,
        entries_dispatched_after_kill=0,
        protected_exit_failures=0,
        duplicate_dispatches=0,
        unknown_claim_retries=0,
        denied_unsafe_privilege_count=1,
    )
    with pytest.raises(OwnerToolError, match="not stored"):
        issue_receipt(
            tmp_path / "issuer" / "evidence-issuer.ed25519",
            policy,
            kind=EvidenceKind.GLOBAL_OPERATOR_CONTROL,
            facts=facts,
            evidence_dir=evidence,
            issued_at=NOW,
        )
