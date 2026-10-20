import base64
import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from kairos_execution.production_readiness import (
    EvidenceKind,
    ManualArmRequestV1,
    OwnerArmKeyV1,
    ProductionContextV1,
    ProductionPreconditionsVerifier,
    SignedManualArmRequestV1,
    VerifiedEvidenceV1,
    canonical_digest,
    validate_manual_arm,
    validate_signed_manual_arm,
    validate_signed_manual_arm_async,
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


def _signed_arm(*, request=None, key_id="owner-key", private_key=None, domain=None):
    private_key = private_key or Ed25519PrivateKey.generate()
    request = request or ManualArmRequestV1(
        context=context(),
        preconditions_sha256="a" * 64,
        nonce="signed-once",
        owner_identity="owner",
        created_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        dollar_cap=Decimal("10"),
        daily_stop_loss_usd=Decimal("1"),
    )
    payload = json.dumps(
        request.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    signature = private_key.sign((domain or b"kairos.signed-manual-arm-request.v1\x00") + payload)
    public = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    signed = SignedManualArmRequestV1(
        request=request, key_id=key_id, signature_base64=base64.b64encode(signature).decode()
    )
    owner_key = OwnerArmKeyV1(
        owner_identity="owner",
        key_id="owner-key",
        public_key_base64=base64.b64encode(public).decode(),
        context=context(),
        valid_from=NOW - timedelta(days=1),
        valid_until=NOW + timedelta(days=1),
    )
    return signed, owner_key, private_key


def _request_for(preconditions, *, nonce="signed-once", **updates):
    fields = {
        "context": context(),
        "preconditions_sha256": canonical_digest(preconditions),
        "nonce": nonce,
        "owner_identity": "owner",
        "created_at": NOW,
        "expires_at": NOW + timedelta(minutes=5),
        "dollar_cap": Decimal("10"),
        "daily_stop_loss_usd": Decimal("1"),
    }
    fields.update(updates)
    return ManualArmRequestV1(**fields)


def _owner_key_pin(owner_key):
    return canonical_digest(owner_key)


def test_signed_manual_arm_authenticates_complete_request_then_consumes_once():
    verifier, refs, _ = setup_gate()
    preconditions = verifier.verify(context(), refs, now=NOW)
    request = ManualArmRequestV1(
        context=context(),
        preconditions_sha256=canonical_digest(preconditions),
        nonce="signed-once",
        owner_identity="owner",
        created_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        dollar_cap=Decimal("10"),
        daily_stop_loss_usd=Decimal("1"),
    )
    signed, owner_key, _ = _signed_arm(request=request)
    store = Nonces()
    kwargs = {
        "owner_key": owner_key,
        "expected_owner_key_sha256": _owner_key_pin(owner_key),
        "expected_owner_identity": "owner",
        "nonce_store": store,
        "now": NOW,
        "maximum_lifetime": timedelta(minutes=10),
    }
    assert validate_signed_manual_arm(signed, preconditions, **kwargs) == (
        "OWNER_AUTHENTICATED_MANUAL_REQUEST_VALIDATED_ONLY"
    )
    with pytest.raises(ValueError, match="consumed or unresolved"):
        validate_signed_manual_arm(signed, preconditions, **kwargs)
    assert preconditions.live_ready is False and preconditions.mutation_authority is False


def test_signed_arm_rejects_attacker_key_substitution_against_independent_pin_before_nonce_claim():
    verifier, refs, _ = setup_gate()
    preconditions = verifier.verify(context(), refs, now=NOW)
    request = _request_for(preconditions)
    _, trusted_key, _ = _signed_arm(request=request)
    attacker_signed, attacker_key, _ = _signed_arm(request=request)
    trusted_pin = _owner_key_pin(trusted_key)
    store = Nonces()
    with pytest.raises(ValueError, match="does not match the independently pinned policy"):
        validate_signed_manual_arm(
            attacker_signed,
            preconditions,
            owner_key=attacker_key,
            expected_owner_key_sha256=trusted_pin,
            expected_owner_identity="owner",
            nonce_store=store,
            now=NOW,
            maximum_lifetime=timedelta(minutes=10),
        )
    assert not store.claims


def test_signed_arm_rejects_malformed_pin_and_constructed_invalid_owner_policy():
    verifier, refs, _ = setup_gate()
    preconditions = verifier.verify(context(), refs, now=NOW)
    signed, owner_key, _ = _signed_arm(request=_request_for(preconditions))
    kwargs = {
        "expected_owner_identity": "owner",
        "nonce_store": Nonces(),
        "now": NOW,
        "maximum_lifetime": timedelta(minutes=10),
    }
    with pytest.raises(ValueError, match="independently pinned"):
        validate_signed_manual_arm(
            signed,
            preconditions,
            owner_key=owner_key,
            expected_owner_key_sha256="not-a-sha256",
            **kwargs,
        )
    forged_key = OwnerArmKeyV1.model_construct(
        owner_identity=owner_key.owner_identity,
        key_id=owner_key.key_id,
        public_key_base64="attacker-controlled",
        context=owner_key.context,
        valid_from=owner_key.valid_from,
        valid_until=owner_key.valid_until,
    )
    with pytest.raises(ValidationError):
        validate_signed_manual_arm(
            signed,
            preconditions,
            owner_key=forged_key,
            expected_owner_key_sha256=canonical_digest(forged_key),
            **kwargs,
        )


@pytest.mark.parametrize("mutation", ["wrong_owner", "wrong_key", "wrong_context", "expired_key"])
def test_signed_manual_arm_requires_pinned_owner_key_scope_and_validity(mutation):
    verifier, refs, _ = setup_gate()
    preconditions = verifier.verify(context(), refs, now=NOW)
    signed, owner_key, _ = _signed_arm(request=_request_for(preconditions))
    if mutation == "wrong_owner":
        owner_key = owner_key.model_copy(update={"owner_identity": "other-owner"})
    elif mutation == "wrong_key":
        signed = signed.model_copy(update={"key_id": "unknown-key"})
    elif mutation == "wrong_context":
        owner_key = owner_key.model_copy(
            update={"context": context().model_copy(update={"source_set_sha256": "f" * 64})}
        )
    else:
        owner_key = owner_key.model_copy(update={"valid_until": NOW - timedelta(seconds=1)})
    with pytest.raises((ValueError, ValidationError)):
        validate_signed_manual_arm(
            signed,
            preconditions,
            owner_key=owner_key,
            expected_owner_key_sha256=_owner_key_pin(owner_key),
            expected_owner_identity="owner",
            nonce_store=Nonces(),
            now=NOW,
            maximum_lifetime=timedelta(minutes=10),
        )


def test_signed_manual_arm_rejects_tampering_wrong_domain_and_invalid_model_construct():
    verifier, refs, _ = setup_gate()
    preconditions = verifier.verify(context(), refs, now=NOW)
    signed, owner_key, private_key = _signed_arm(request=_request_for(preconditions))
    tampered = signed.model_copy(
        update={"request": signed.request.model_copy(update={"dollar_cap": Decimal("11")})}
    )
    request = signed.request
    payload = json.dumps(
        request.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    # A valid signature under the same pinned key but a different domain must fail.
    wrong_domain_signature = base64.b64encode(private_key.sign(b"other.protocol.v1\x00" + payload)).decode()
    wrong_domain = signed.model_copy(update={"signature_base64": wrong_domain_signature})
    invalid = signed.model_copy(
        update={"request": signed.request.model_copy(update={"daily_stop_loss_usd": Decimal("12")})}
    )
    forged_request = ManualArmRequestV1.model_construct(
        **{**signed.request.model_dump(), "dollar_cap": Decimal("-1")}
    )
    forged = SignedManualArmRequestV1.model_construct(
        request=forged_request, key_id=signed.key_id, signature_base64=signed.signature_base64
    )
    malformed = signed.model_copy(update={"signature_base64": "not-a-signature"})
    for candidate in (tampered, wrong_domain, invalid, forged, malformed):
        with pytest.raises((ValueError, ValidationError)):
            validate_signed_manual_arm(
                candidate,
                preconditions,
                owner_key=owner_key,
                expected_owner_key_sha256=_owner_key_pin(owner_key),
                expected_owner_identity="owner",
                nonce_store=Nonces(),
                now=NOW,
                maximum_lifetime=timedelta(minutes=10),
            )


def test_signed_manual_arm_checks_request_time_limits_and_unresolved_nonce_before_any_authority():
    verifier, refs, _ = setup_gate()
    preconditions = verifier.verify(context(), refs, now=NOW)
    request = _request_for(preconditions)
    signed, owner_key, _ = _signed_arm(request=request)
    with pytest.raises(ValueError, match="stale, future-dated"):
        validate_signed_manual_arm(
            signed,
            preconditions,
            owner_key=owner_key,
            expected_owner_key_sha256=_owner_key_pin(owner_key),
            expected_owner_identity="owner",
            nonce_store=Nonces(),
            now=NOW + timedelta(minutes=6),
            maximum_lifetime=timedelta(minutes=10),
        )

    class UnknownNonce:
        def consume_once(self, **kwargs):
            raise RuntimeError("secret backend detail")

    with pytest.raises(ValueError, match="unresolved; do not retry") as failure:
        validate_signed_manual_arm(
            signed,
            preconditions,
            owner_key=owner_key,
            expected_owner_key_sha256=_owner_key_pin(owner_key),
            expected_owner_identity="owner",
            nonce_store=UnknownNonce(),
            now=NOW,
            maximum_lifetime=timedelta(minutes=10),
        )
    assert "secret backend detail" not in str(failure.value)


@pytest.mark.parametrize("invalidity", ["future", "expired", "too_long", "stale_preconditions"])
def test_signed_manual_arm_rejects_invalid_time_bounds_before_consuming_nonce(invalidity):
    verifier, refs, _ = setup_gate()
    preconditions = verifier.verify(context(), refs, now=NOW)
    request_preconditions = preconditions
    fields = {}
    if invalidity == "future":
        fields = {"created_at": NOW + timedelta(seconds=1), "expires_at": NOW + timedelta(minutes=5)}
    elif invalidity == "expired":
        fields = {"created_at": NOW - timedelta(minutes=2), "expires_at": NOW - timedelta(minutes=1)}
    elif invalidity == "too_long":
        fields = {"expires_at": NOW + timedelta(minutes=11)}
    else:
        request_preconditions = preconditions.model_copy(update={"valid_until": NOW})
    request = _request_for(request_preconditions, **fields)
    signed, owner_key, _ = _signed_arm(request=request)
    store = Nonces()
    with pytest.raises(ValueError):
        validate_signed_manual_arm(
            signed,
            request_preconditions,
            owner_key=owner_key,
            expected_owner_key_sha256=_owner_key_pin(owner_key),
            expected_owner_identity="owner",
            nonce_store=store,
            now=NOW,
            maximum_lifetime=timedelta(minutes=10),
        )
    assert not store.claims


async def test_signed_manual_arm_async_uses_same_authentication_and_one_use_nonce_boundary():
    verifier, refs, _ = setup_gate()
    preconditions = verifier.verify(context(), refs, now=NOW)
    signed, owner_key, _ = _signed_arm(request=_request_for(preconditions, nonce="async-once"))

    class AsyncNonces:
        def __init__(self):
            self.store = Nonces()

        async def consume_once_async(self, **kwargs):
            return self.store.consume_once(**kwargs)

    store = AsyncNonces()
    kwargs = {
        "owner_key": owner_key,
        "expected_owner_key_sha256": _owner_key_pin(owner_key),
        "expected_owner_identity": "owner",
        "nonce_store": store,
        "now": NOW,
        "maximum_lifetime": timedelta(minutes=10),
    }
    assert await validate_signed_manual_arm_async(signed, preconditions, **kwargs) == (
        "OWNER_AUTHENTICATED_MANUAL_REQUEST_VALIDATED_ONLY"
    )
    with pytest.raises(ValueError, match="consumed or unresolved"):
        await validate_signed_manual_arm_async(signed, preconditions, **kwargs)
