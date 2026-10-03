from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from pydantic import ValidationError

from kairos_execution.production_readiness import (
    EvidenceKind,
    ManualArmRequestV1,
    ProductionContextV1,
    ProductionPreconditionsVerifier,
    VerifiedEvidenceV1,
    canonical_digest,
    validate_manual_arm,
)
from tests.production_evidence_fixtures import signed_gate_fixture

NOW = datetime(2026, 10, 2, 20, tzinfo=UTC)


def context():
    return signed_gate_fixture()[3]


class Interpreter:
    def __init__(self):
        self.days = 365
        self.trades = 500
        self.scope = None
        self.valid_until = NOW + timedelta(minutes=30)

    def verify(self, reference, scope):
        return VerifiedEvidenceV1(
            reference=reference,
            context=self.scope or scope,
            outcome="SEALED_PASS",
            verified_at=NOW,
            valid_until=self.valid_until,
            complete_forward_days=self.days,
            naturally_closed_simulated_trades=self.trades,
        )


def setup_gate():
    verifier, refs, control, *_ = signed_gate_fixture()
    return verifier, refs, control


class Nonces:
    def __init__(self):
        self.claims = set()

    def consume_once(self, *, owner_identity, nonce, request_sha256):
        key = (owner_identity, nonce)
        if key in self.claims:
            return False
        self.claims.add(key)
        return True


def test_complete_offline_fixture_never_grants_live_authority():
    verifier, refs, _ = setup_gate()
    result = verifier.verify(context(), refs, now=NOW)
    assert result.outcome == "PRECONDITIONS_VALIDATED_ONLY"
    assert result.live_ready is False and result.mutation_authority is False


@pytest.mark.parametrize(
    "mutation", ["missing", "duplicate", "untrusted", "scope", "stale", "days", "trades"]
)
def test_each_gate_identity_and_science_boundary_fail_closed(mutation):
    verifier, refs, interpreter = setup_gate()
    scope = context()
    if mutation == "missing":
        refs = refs[:-1]
    elif mutation == "duplicate":
        refs = (*refs[:-1], refs[0])
    elif mutation == "untrusted":
        refs = (refs[0].model_copy(update={"issuer_id": "foreign"}), *refs[1:])
    elif mutation == "scope":
        interpreter.scope = context().model_copy(update={"source_set_sha256": "d" * 64})
    elif mutation == "stale":
        interpreter.valid_until = NOW + timedelta(seconds=1)
    elif mutation == "days":
        interpreter.days = 364
    else:
        interpreter.trades = 499
    with pytest.raises(ValueError):
        verifier.verify(scope, refs, now=NOW + timedelta(seconds=2))


def test_no_provisioned_interpreters_cannot_adopt_engineering_flags():
    _, refs, _ = setup_gate()
    with pytest.raises(ValueError, match="not fully provisioned"):
        ProductionPreconditionsVerifier({}).verify(context(), refs, now=NOW)
    with pytest.raises(ValidationError):
        ProductionContextV1(**context().model_dump(), accepted=True)
    with pytest.raises(ValidationError):
        ProductionContextV1(
            **{**context().model_dump(), "adaptive_system_id": "regime_aligned_right_tail_v1"}
        )


def test_manual_arm_binds_owner_limits_digest_nonce_and_is_not_capability():
    verifier, refs, _ = setup_gate()
    result = verifier.verify(context(), refs, now=NOW)
    request = ManualArmRequestV1(
        context=context(),
        preconditions_sha256=canonical_digest(result),
        nonce="owner-once",
        owner_identity="owner",
        created_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        dollar_cap=Decimal("10"),
        daily_stop_loss_usd=Decimal("1"),
    )
    store = Nonces()
    kwargs = {
        "expected_owner_identity": "owner",
        "nonce_store": store,
        "now": NOW,
        "maximum_lifetime": timedelta(minutes=10),
    }
    assert validate_manual_arm(request, result, **kwargs) == "MANUAL_REQUEST_VALIDATED_ONLY"
    with pytest.raises(ValueError, match="consumed or unresolved"):
        validate_manual_arm(request, result, **kwargs)
    for update in (
        {"owner_identity": "foreign"},
        {"preconditions_sha256": "f" * 64},
        {"expires_at": NOW + timedelta(hours=1)},
        {"created_at": NOW + timedelta(seconds=1)},
    ):
        with pytest.raises(ValueError):
            validate_manual_arm(
                request.model_copy(update=update), result, **{**kwargs, "nonce_store": Nonces()}
            )


@pytest.mark.parametrize("cap,stop", [("0", "1"), ("NaN", "1"), ("10", "Infinity"), ("1", "2")])
def test_invalid_or_unprovided_owner_limits_are_not_inferred(cap, stop):
    with pytest.raises(ValidationError):
        ManualArmRequestV1(
            context=context(),
            preconditions_sha256="e" * 64,
            nonce="once",
            owner_identity="owner",
            created_at=NOW,
            expires_at=NOW + timedelta(minutes=1),
            dollar_cap=Decimal(cap),
            daily_stop_loss_usd=Decimal(stop),
        )


def test_naive_and_nonutc_time_and_interpreter_failure_are_rejected():
    verifier, refs, _ = setup_gate()
    with pytest.raises(ValueError, match="UTC"):
        verifier.verify(context(), refs, now=NOW.replace(tzinfo=None))

    class FailedInterpreter:
        def verify(self, reference, scope):
            raise RuntimeError("underlying receipt unavailable")

    broken = ProductionPreconditionsVerifier(
        {kind: ("test-only", FailedInterpreter()) for kind in EvidenceKind}
    )
    with pytest.raises(ValueError, match="concrete signed"):
        broken.verify(context(), refs, now=NOW)


def test_construct_copy_bypass_cannot_admit_historical_or_negative_limits():
    verifier, refs, _ = setup_gate()
    with pytest.raises(ValidationError):
        verifier.verify(context().model_copy(update={"adaptive_system_id": "trial15"}), refs, now=NOW)
    result = verifier.verify(context(), refs, now=NOW)
    request = ManualArmRequestV1(
        context=context(),
        preconditions_sha256=canonical_digest(result),
        nonce="fresh",
        owner_identity="owner",
        created_at=NOW,
        expires_at=NOW + timedelta(minutes=1),
        dollar_cap=Decimal("10"),
        daily_stop_loss_usd=Decimal("1"),
    )
    with pytest.raises(ValidationError):
        validate_manual_arm(
            request.model_copy(update={"dollar_cap": Decimal("-1")}),
            result,
            expected_owner_identity="owner",
            nonce_store=Nonces(),
            now=NOW,
            maximum_lifetime=timedelta(minutes=5),
        )


def test_nonce_unknown_outcome_never_discloses_backend_text():
    verifier, refs, _ = setup_gate()
    result = verifier.verify(context(), refs, now=NOW)
    request = ManualArmRequestV1(
        context=context(),
        preconditions_sha256=canonical_digest(result),
        nonce="fresh",
        owner_identity="owner",
        created_at=NOW,
        expires_at=NOW + timedelta(minutes=1),
        dollar_cap=Decimal("10"),
        daily_stop_loss_usd=Decimal("1"),
    )

    class UnknownNonce:
        def consume_once(self, **kwargs):
            raise RuntimeError("DO_NOT_LEAK_DATABASE_SECRET")

    with pytest.raises(ValueError, match="unresolved; do not retry") as failure:
        validate_manual_arm(
            request,
            result,
            expected_owner_identity="owner",
            nonce_store=UnknownNonce(),
            now=NOW,
            maximum_lifetime=timedelta(minutes=5),
        )
    assert "DO_NOT_LEAK" not in str(failure.value)
