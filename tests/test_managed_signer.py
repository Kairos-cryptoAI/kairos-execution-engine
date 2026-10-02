import json
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from kairos_execution.managed_signer import (
    CustodyBindingV1,
    ManagedSignerBoundary,
    ManagedSigningError,
    ManagedSigningRequestV1,
    reviewed_schema_sha256,
)
from kairos_execution.production_readiness import ProductionContextV1

NOW = datetime(2026, 10, 2, 20, tzinfo=UTC)


class Backend:
    def __init__(self):
        self.calls = []
        self.fail = False
        self.mutate = False

    def sign_typed_data(self, **kwargs):
        self.calls.append(kwargs)
        if self.fail:
            raise RuntimeError("DO_NOT_LEAK_BACKEND_SECRET")
        if self.mutate:
            kwargs["message"]["quantity"] = 999
        return "0x" + "11" * 65


class Verifier:
    def __init__(self):
        self.quantity = None
        self.allow = True

    def verify(self, **kwargs):
        self.quantity = kwargs["message"]["quantity"]
        return self.allow


class Claims:
    def __init__(self):
        self.ids = set()

    def claim_once(self, *, custody_reference, request_id, request_sha256):
        key = (custody_reference, request_id)
        if key in self.ids:
            return False
        self.ids.add(key)
        return True


class Authorization:
    def __init__(self):
        self.allow = True

    def verify_request(self, request, binding):
        if not self.allow:
            raise ValueError("missing manual-arm record")


def setup_signer():
    scope = ProductionContextV1(
        remote_account_id="prod-reviewed-account",
        adaptive_system_id="adaptive-v1",
        frozen_policy_sha256="a" * 64,
        source_set_sha256="b" * 64,
    )
    binding = CustodyBindingV1(
        context=scope,
        custody_reference="kms:reviewed-opaque-reference",
        wallet_address="0x" + "12" * 20,
        chain_id=161803,
        schema_sha256=reviewed_schema_sha256(161803),
        approved_instruments=("BTCUSD", "ETHUSD", "SOLUSD", "BNBUSD", "XRPUSD"),
        custody_receipt_sha256="c" * 64,
    )
    request = ManagedSigningRequestV1(
        request_id="request-once",
        context=scope,
        manual_request_sha256="d" * 64,
        custody_receipt_sha256="c" * 64,
        operation="New limit order",
        message_json=json.dumps(
            {
                "id": "00384:ABCDEF0123456789ABCDEF0123",
                "instrument": "BTCUSD",
                "side": "BUY",
                "leverage": 1,
                "quantity": 100,
                "limitPrice": 10000,
                "chainId": 161803,
            }
        ),
        expires_at=NOW + timedelta(seconds=20),
    )
    backend, verifier, claims, authorization = Backend(), Verifier(), Claims(), Authorization()
    signer = ManagedSignerBoundary(
        binding,
        backend=backend,
        verifier=verifier,
        claims=claims,
        authorization=authorization,
    )
    return signer, request, backend, verifier, authorization


def test_only_typed_request_claimed_once_and_signature_hidden_from_receipt():
    signer, request, backend, _, _ = setup_signer()
    signed = signer.sign(request, now=NOW)
    assert signed.signature not in repr(signed)
    assert "signature" not in signed.model_dump()
    with pytest.raises(ManagedSigningError, match="claimed or unresolved"):
        signer.sign(request, now=NOW)
    assert len(backend.calls) == 1


@pytest.mark.parametrize(
    "change",
    [
        "scope",
        "chain",
        "instrument",
        "extra",
        "bool",
        "quantity",
        "side",
        "leverage",
        "id",
        "expired",
        "long",
        "duplicate",
        "schema",
        "auth",
    ],
)
def test_invalid_requests_fail_before_claim_or_backend(change):
    signer, request, backend, _, authorization = setup_signer()
    payload = json.loads(request.message_json)
    if change == "scope":
        request = request.model_copy(
            update={"context": request.context.model_copy(update={"remote_account_id": "other"})}
        )
    elif change == "chain":
        payload["chainId"] = 1
    elif change == "instrument":
        payload["instrument"] = "UNKNOWN"
    elif change == "extra":
        payload["recipient"] = "foreign-wallet"
    elif change == "bool":
        payload["quantity"] = True
    elif change == "quantity":
        payload["quantity"] = 0
    elif change == "side":
        payload["side"] = "WAIT"
    elif change == "leverage":
        payload["leverage"] = 2
    elif change == "id":
        payload["id"] = "arbitrary"
    elif change == "expired":
        request = request.model_copy(update={"expires_at": NOW})
    elif change == "long":
        request = request.model_copy(update={"expires_at": NOW + timedelta(seconds=31)})
    elif change == "schema":
        signer.binding = signer.binding.model_copy(update={"schema_sha256": "f" * 64})
    elif change == "auth":
        authorization.allow = False
    if change == "duplicate":
        request = request.model_copy(update={"message_json": '{"quantity":1,"quantity":2}'})
    else:
        request = request.model_copy(update={"message_json": json.dumps(payload)})
    with pytest.raises(ManagedSigningError):
        signer.sign(request, now=NOW)
    assert backend.calls == []
    assert signer._claims.ids == set()


def test_withdraw_and_raw_digest_are_not_supported():
    _, request, _, _, _ = setup_signer()
    with pytest.raises(ValidationError):
        ManagedSigningRequestV1(**{**request.model_dump(), "operation": "Withdraw"})
    assert not hasattr(ManagedSignerBoundary, "sign_raw")


def test_backend_failure_is_sanitized_and_never_retried():
    signer, request, backend, _, _ = setup_signer()
    backend.fail = True
    with pytest.raises(ManagedSigningError) as failure:
        signer.sign(request, now=NOW)
    assert "DO_NOT_LEAK" not in str(failure.value)
    with pytest.raises(ManagedSigningError, match="claimed or unresolved"):
        signer.sign(request, now=NOW)
    assert len(backend.calls) == 1


def test_verifier_receives_original_bytes_even_if_backend_mutates_its_copy():
    signer, request, backend, verifier, _ = setup_signer()
    backend.mutate = True
    signer.sign(request, now=NOW)
    assert verifier.quantity == 100


def test_independent_signature_rejection_does_not_grant_retry():
    signer, request, backend, verifier, _ = setup_signer()
    verifier.allow = False
    with pytest.raises(ManagedSigningError, match="unresolved"):
        signer.sign(request, now=NOW)
    with pytest.raises(ManagedSigningError, match="claimed or unresolved"):
        signer.sign(request, now=NOW)
    assert len(backend.calls) == 1


@pytest.mark.parametrize("truthy", [1, "accepted", {"ok": True}])
def test_claim_and_signature_verifier_require_exact_boolean_success(truthy):
    signer, request, backend, verifier, _ = setup_signer()

    class MalformedClaims:
        def claim_once(self, **kwargs):
            return truthy

    signer._claims = MalformedClaims()
    with pytest.raises(ManagedSigningError, match="claimed or unresolved"):
        signer.sign(request, now=NOW)
    assert backend.calls == []
    signer, request, backend, verifier, _ = setup_signer()
    verifier.allow = truthy
    with pytest.raises(ManagedSigningError, match="unresolved"):
        signer.sign(request, now=NOW)
    assert len(backend.calls) == 1
