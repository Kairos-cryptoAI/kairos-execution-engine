"""Owner drills: real operations on a disposable database, facts the system accepts."""

from __future__ import annotations

import tempfile
from datetime import timedelta
from decimal import Decimal
from pathlib import Path

import asyncpg  # type: ignore[import-untyped]
import pytest

from kairos_execution.production_drills import (
    LIMIT_TESTS,
    DrillFailed,
    limits_drill,
    operator_drill,
    recovery_drill,
)
from kairos_execution.production_owner import freeze_policy, generate_issuer, issue_receipt
from kairos_execution.production_provisioning import provision_production_database
from kairos_execution.production_readiness import EvidenceKind, ProductionContextV1
from kairos_execution.signed_evidence import DirectoryEvidenceResolver, SignedReceiptInterpreter
from kairos_execution.utc_clock import precise_utc_now
from tests.rest_stand import stand_admin_dsn, stand_container
from tests.test_production_owner import _frozen

JUNIT_OK = b'<testsuites><testsuite><testcase name="a"/><testcase name="b"/></testsuite></testsuites>'
JUNIT_FAILED = b'<testsuites><testsuite><testcase name="a"><failure/></testcase></testsuite></testsuites>'


def _fake_run(junit: bytes):
    calls = []

    def run(command, stdin=None):
        calls.append(list(command))
        if command[0] == "git":
            return b"0123456789abcdef\n"
        target = next(arg for arg in command if arg.startswith("--junitxml="))
        Path(target.split("=", 1)[1]).write_bytes(junit)
        return b""

    return run, calls


def test_limits_drill_counts_passing_refusal_tests_and_cites_their_reports(tmp_path):
    run, calls = _fake_run(JUNIT_OK)
    facts = limits_drill(
        evidence_dir=tmp_path / "evidence",
        repositories={"risk": tmp_path / "risk", "execution": tmp_path / "execution"},
        owner_identity="owner",
        dollar_cap=Decimal("200"),
        daily_stop_loss_usd=Decimal("5"),
        risk_per_trade_fraction=Decimal("0.0025"),
        maximum_total_open_risk_fraction=Decimal("0.01"),
        work_dir=tmp_path,
        run=run,
    )
    assert (
        facts.blocked_missing_limit_count
        == facts.blocked_over_cap_count
        == facts.blocked_daily_stop_count
        == 2
    )
    assert facts.maximum_leverage == 1 and len(facts.artifact_sha256s) == len(LIMIT_TESTS)
    pytest_calls = [call for call in calls if "pytest" in call]
    assert len(pytest_calls) == len(LIMIT_TESTS)
    for digest in facts.artifact_sha256s:
        assert (tmp_path / "evidence" / f"{digest}.artifact").is_file()


def test_limits_drill_fails_when_any_refusal_test_fails(tmp_path):
    run, _ = _fake_run(JUNIT_FAILED)
    with pytest.raises(DrillFailed, match="did not pass"):
        limits_drill(
            evidence_dir=tmp_path / "evidence",
            repositories={"risk": tmp_path, "execution": tmp_path},
            owner_identity="owner",
            dollar_cap=Decimal("200"),
            daily_stop_loss_usd=Decimal("5"),
            risk_per_trade_fraction=Decimal("0.0025"),
            maximum_total_open_risk_fraction=Decimal("0.01"),
            work_dir=tmp_path,
            run=run,
        )


def test_limits_drill_rejects_limits_above_the_constitution(tmp_path):
    run, _ = _fake_run(JUNIT_OK)
    with pytest.raises(ValueError):
        limits_drill(
            evidence_dir=tmp_path / "evidence",
            repositories={"risk": tmp_path, "execution": tmp_path},
            owner_identity="owner",
            dollar_cap=Decimal("200"),
            daily_stop_loss_usd=Decimal("5"),
            risk_per_trade_fraction=Decimal("0.05"),
            maximum_total_open_risk_fraction=Decimal("0.01"),
            work_dir=tmp_path,
            run=run,
        )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_recovery_and_operator_drills_on_a_provisioned_database_yield_signable_facts():
    admin_dsn = stand_admin_dsn()
    container = stand_container()
    root = Path(tempfile.mkdtemp(prefix="drills-"))
    evidence = root / "evidence"
    now = precise_utc_now().replace(microsecond=0)
    frozen = _frozen().model_copy(update={"frozen_at": now - timedelta(days=1)})
    context = ProductionContextV1(
        remote_account_id="synthetic-drill-account",
        adaptive_system_id=frozen.adaptive_system_id,
        frozen_policy_sha256=freeze_policy(evidence, frozen),
        source_set_sha256=frozen.source_set_sha256,
    )
    manifest = await provision_production_database(
        admin_dsn, context=context, secrets_dir=root / "secrets", policy_namespace="synthetic:drills"
    )
    try:
        recovery = await recovery_drill(
            manifest, admin_dsn=admin_dsn, container=container, evidence_dir=evidence
        )
        operator = await operator_drill(manifest, evidence_dir=evidence)
    finally:
        admin = await asyncpg.connect(admin_dsn)
        try:
            await admin.execute(f'DROP DATABASE IF EXISTS "{manifest.database}" WITH (FORCE)')
            for role in manifest.roles.values():
                await admin.execute(f'DROP ROLE IF EXISTS "{role}"')
        finally:
            await admin.close()
    assert recovery.backup_sha256 == recovery.restored_backup_sha256
    assert recovery.before_history_sha256 == recovery.after_history_sha256
    assert operator.killed_at < operator.resumed_at
    assert operator.restart_observed_version >= operator.operator_version
    assert operator.denied_unsafe_privilege_count == 5
    policy = generate_issuer(
        root / "issuer",
        issuer_id="owner",
        frozen=frozen,
        context=context,
        allowed_kinds=[EvidenceKind.PRIMARY_RECOVERY, EvidenceKind.GLOBAL_OPERATOR_CONTROL],
        valid_from=now - timedelta(hours=1),
        valid_until=now + timedelta(days=1),
    )
    for kind, facts in (
        (EvidenceKind.PRIMARY_RECOVERY, recovery),
        (EvidenceKind.GLOBAL_OPERATOR_CONTROL, operator),
    ):
        reference = issue_receipt(
            root / "issuer" / "evidence-issuer.ed25519",
            policy,
            kind=kind,
            facts=facts,
            evidence_dir=evidence,
            issued_at=precise_utc_now().replace(microsecond=0),
        )
        verified = SignedReceiptInterpreter(kind, (policy,), DirectoryEvidenceResolver(evidence)).verify(
            reference, context
        )
        assert verified.outcome == "SEALED_PASS"


def _custody_binding(address: str):
    from kairos_execution.managed_signer import CustodyBindingV1, reviewed_schema_sha256
    from tests.test_local_custody import CHAIN, INSTRUMENTS, REFERENCE

    context = ProductionContextV1(
        remote_account_id="synthetic-drill-account",
        adaptive_system_id="hourly_trend_candidates_v1",
        frozen_policy_sha256="a" * 64,
        source_set_sha256="b" * 64,
    )
    return CustodyBindingV1(
        context=context,
        custody_reference=REFERENCE,
        wallet_address=address,
        chain_id=CHAIN,
        schema_sha256=reviewed_schema_sha256(CHAIN),
        approved_instruments=INSTRUMENTS,
        custody_receipt_sha256="c" * 64,
    )


def test_custody_drill_signs_refuses_and_recovers_with_the_local_keystore(tmp_path):
    from kairos_execution.production_drills import custody_drill
    from tests.test_local_custody import _backend

    (tmp_path / "primary").mkdir()
    (tmp_path / "backup").mkdir()
    backend, address = _backend(tmp_path / "primary")
    recovery, recovered_address = _backend(tmp_path / "backup")
    assert recovered_address == address
    binding = _custody_binding(address)
    facts = custody_drill(
        backend,
        binding,
        recovery_backend=recovery,
        dev_custody_reference="local-dev-keystore",
        evidence_dir=tmp_path / "evidence",
    )
    assert facts.malformed_requests_rejected == facts.unauthorized_requests_rejected == 1
    assert facts.successful_verified_signatures == 2 and facts.unverified_signatures == 0
    assert facts.wallet_address == address
    stored = b"".join(path.read_bytes() for path in (tmp_path / "evidence").iterdir())
    assert b"0x" + b"11" * 10 not in stored and b'"signature":' not in stored


@pytest.mark.asyncio
async def test_pairing_drill_binds_the_api_key_account_to_the_custody_wallet(tmp_path):
    from kairos_execution.production_drills import pairing_drill
    from kairos_execution.production_reads import ProductionEvedexReads
    from kairos_execution.production_transport import ProductionEvedexSdkClient
    from tests.rest_stand import FakeEvedex
    from tests.test_local_custody import _backend

    backend, address = _backend(tmp_path)
    binding = _custody_binding(address)
    venue = FakeEvedex(binding.context.remote_account_id)
    client = ProductionEvedexSdkClient(
        node_executable=Path(__file__).resolve().parent / "fixtures" / "node.exe",
        api_key_file=Path(__file__).resolve().parent / "fixtures" / "must-not-be-read.key",
        expected_account_id=binding.context.remote_account_id,
    )
    client._call = venue.call  # type: ignore[method-assign]
    reads = ProductionEvedexReads(client, symbol_map={"BTCUSDT": "BTCUSD"})
    facts = await pairing_drill(reads, backend, binding, evidence_dir=tmp_path / "evidence")
    assert facts.remote_account_id == "synthetic-drill-account" and facts.wallet_address == address
    assert facts.credential_pairing_conflicts == 0
