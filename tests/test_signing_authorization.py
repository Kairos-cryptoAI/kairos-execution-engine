"""Synthetic policy tests only; not deployed production-state acceptance tests."""

import base64
import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import UUID

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from kairos_execution.crypto import EIP712_SCHEMAS, build_domain
from kairos_execution.managed_signer import (
    CustodyBindingV1,
    ManagedSigningError,
    ManagedSigningRequestV1,
    reviewed_schema_sha256,
)
from kairos_execution.production_readiness import (
    ManualArmRequestV1,
    OwnerArmKeyV1,
    PreconditionsV1,
    ProductionContextV1,
    SignedManualArmRequestV1,
    canonical_digest,
)
from kairos_execution.signing_authorization import (
    AcceptedManualNonceV1,
    ExposureSnapshotV1,
    LiveOperatorStateV1,
    ProductionSigningAuthorizationVerifier,
    ProductionSigningEvidenceV1,
    RiskGeometryV1,
    signing_effect_id,
)

H = "a" * 64
PARENT_ID = "00384:ABCDEF0123456789ABCDEF0123"
ARM_DOMAIN = b"kairos.signed-manual-arm-request.v1\x00"


class SyntheticStateSource:
    """In-memory fixture, intentionally not claimed to authenticate live state."""

    def __init__(self, evidence):
        self.evidence = evidence

    def resolve_signing_evidence(self, *, request, binding, now):
        return self.evidence


def fixture(operation="New limit order"):
    now = datetime.now(UTC).replace(microsecond=0)
    context = ProductionContextV1(
        remote_account_id="prod-account",
        adaptive_system_id="adaptive-v1",
        frozen_policy_sha256="b" * 64,
        source_set_sha256="c" * 64,
    )
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    public = key.public_key().public_bytes_raw()
    owner_key = OwnerArmKeyV1(
        owner_identity="owner",
        key_id="owner-key",
        public_key_base64=base64.b64encode(public).decode(),
        context=context,
        valid_from=now - timedelta(minutes=1),
        valid_until=now + timedelta(hours=1),
    )
    preconditions = PreconditionsV1(
        context=context,
        evidence_sha256=H,
        verified_at=now - timedelta(minutes=1),
        valid_until=now + timedelta(hours=1),
        owner_identity="owner",
        dollar_cap=Decimal("100"),
        daily_stop_loss_usd=Decimal("10"),
    )
    arm = ManualArmRequestV1(
        context=context,
        preconditions_sha256=canonical_digest(preconditions),
        nonce="owner-nonce-1",
        owner_identity="owner",
        created_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(minutes=5),
        dollar_cap=Decimal("100"),
        daily_stop_loss_usd=Decimal("10"),
    )
    payload = json.dumps(arm.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode()
    signed_arm = SignedManualArmRequestV1(
        request=arm,
        key_id="owner-key",
        signature_base64=base64.b64encode(key.sign(ARM_DOMAIN + payload)).decode(),
    )
    arm_digest = canonical_digest(arm)
    binding = CustodyBindingV1(
        context=context,
        custody_reference="custody:prod-account",
        wallet_address="0x" + "12" * 20,
        chain_id=161803,
        schema_sha256=reviewed_schema_sha256(161803),
        approved_instruments=("BTCUSD", "ETHUSD", "SOLUSD", "BNBUSD", "XRPUSD"),
        custody_receipt_sha256="d" * 64,
    )
    geometry = {
        "id": "00384:ABCDEF0123456789ABCDEF0123",
        "instrument": "BTCUSD",
        "side": "BUY",
        "leverage": 1,
        "quantity": 100,
        "limitPrice": 10000,
        "chainId": 161803,
    }
    if operation == "Position close order":
        geometry = {
            "id": "00384:ABCDEF0123456789ABCDEF0123",
            "instrument": "BTCUSD",
            "leverage": 1,
            "quantity": 3,
            "chainId": 161803,
        }
    elif operation == "New take-profit/stop-loss":
        geometry = {
            "instrument": "BTCUSD",
            "type": "stop-loss",
            "side": "BUY",
            "quantity": 3,
            "price": 9000,
            "order": PARENT_ID,
        }
    request = ManagedSigningRequestV1(
        request_id="sign-request-1",
        context=context,
        manual_request_sha256=arm_digest,
        custody_receipt_sha256=binding.custody_receipt_sha256,
        operation=operation,
        message_json=json.dumps(geometry),
        expires_at=now
        + timedelta(seconds=3 if operation in {"Position close order", "New take-profit/stop-loss"} else 20),
    )
    decision_id = "risk-decision-1"
    evidence = ProductionSigningEvidenceV1(
        owner_arm=signed_arm,
        owner_nonce_claim=AcceptedManualNonceV1(
            owner_identity="owner",
            nonce=arm.nonce,
            request_sha256=arm_digest,
            context_sha256=canonical_digest(context),
            database_uuid=UUID("31da18d5-2b77-407d-b0dc-5366f03ae10a"),
            claimed_at=now - timedelta(milliseconds=500),
        ),
        operator=LiveOperatorStateV1(
            context=context,
            version=5,
            state="ARMED",
            arm_nonce=arm.nonce,
            arm_request_sha256=arm_digest,
            observed_at=now - timedelta(milliseconds=500),
            changed_at=now - timedelta(milliseconds=500),
            expires_at=now + timedelta(minutes=1),
            command_sha256="e" * 64,
            previous_command_sha256="f" * 64,
        ),
        risk=RiskGeometryV1(
            context=context,
            decision_id=decision_id,
            signing_request_id=request.request_id,
            effect_id=signing_effect_id(request=request, message=geometry, decision_id=decision_id),
            client_order_id=geometry.get("id"),
            operation=operation,
            instrument="BTCUSD",
            side=geometry.get("side", "SELL"),
            quantity=geometry.get("quantity", 100),
            cash_quantity=None,
            price=geometry.get("limitPrice", geometry.get("price")),
            stop_price=None,
            protection_type=geometry.get("type"),
            trigger_price=geometry.get("price") if operation == "New take-profit/stop-loss" else None,
            parent_order_id=geometry.get("order", PARENT_ID if operation != "New limit order" else None),
            leverage=1,
            worst_case_loss_usd=Decimal("1"),
            account_equity_usd=Decimal("10000"),
            daily_realized_loss_usd=Decimal("0"),
            aggregate_open_risk_usd=Decimal("0"),
            aggregate_open_notional_usd=Decimal("0"),
            approved=True,
            observed_at=now - timedelta(milliseconds=500),
            valid_until=now + timedelta(seconds=25),
        ),
        exposure=(
            ExposureSnapshotV1(
                context=context,
                instrument="BTCUSD",
                position_side="BUY",
                remaining_quantity=4,
                parent_order_id=PARENT_ID,
                observed_at=now - timedelta(milliseconds=500),
                valid_until=now + timedelta(seconds=4),
            )
            if operation != "New limit order"
            else None
        ),
        resolved_at=now - timedelta(milliseconds=500),
    )
    verifier = ProductionSigningAuthorizationVerifier(
        source=SyntheticStateSource(evidence),
        preconditions=preconditions,
        owner_key=owner_key,
        expected_owner_key_sha256=canonical_digest(owner_key),
        expected_owner_identity="owner",
        expected_claim_database_uuid=UUID("31da18d5-2b77-407d-b0dc-5366f03ae10a"),
        maximum_arm_lifetime=timedelta(minutes=10),
    )
    return verifier, request, binding, evidence, now


def test_exact_signed_owner_arm_claim_operator_and_risk_geometry_are_required():
    verifier, request, binding, _, now = fixture()
    verifier.verify_request_at(request, binding, now=now)


@pytest.mark.parametrize("state", ["DISARMED", "KILLED"])
def test_inactive_operator_record_accepts_no_arm_or_expiry_and_refuses_entry(state):
    verifier, request, binding, evidence, now = fixture()
    operator = LiveOperatorStateV1.model_validate(
        {
            **evidence.operator.model_dump(),
            "state": state,
            "arm_nonce": None,
            "arm_request_sha256": None,
            "expires_at": None,
        }
    )
    verifier._source.evidence = evidence.model_copy(update={"operator": operator})
    with pytest.raises(ManagedSigningError, match="not armed"):
        verifier.verify_request_at(request, binding, now=now)


def test_unchanged_operator_command_allows_a_fresh_current_snapshot():
    verifier, request, binding, evidence, now = fixture()
    operator = evidence.operator.model_copy(update={"changed_at": now - timedelta(hours=1)})
    verifier._source.evidence = evidence.model_copy(update={"operator": operator})
    verifier.verify_request_at(request, binding, now=now)


def test_entry_signing_deadline_must_not_outlive_risk_lease():
    verifier, request, binding, evidence, now = fixture()
    risk = evidence.risk.model_copy(update={"valid_until": request.expires_at - timedelta(milliseconds=1)})
    verifier._source.evidence = evidence.model_copy(update={"risk": risk})
    with pytest.raises(ManagedSigningError, match="risk authorization lease"):
        verifier.verify_request_at(request, binding, now=now)


@pytest.mark.parametrize(
    "change",
    [
        "owner-claim",
        "claim-database",
        "operator-disarmed",
        "operator-stale",
        "risk-quantity",
        "risk-instrument",
        "owner-cap",
        "daily-stop",
        "order-id",
        "effect-id",
        "request-id",
        "per-trade-ceiling",
        "aggregate-ceiling",
        "open-notional-cap",
    ],
)
def test_entry_refuses_missing_stale_or_mismatched_authority(change):
    verifier, request, binding, evidence, now = fixture()
    if change == "owner-claim":
        claim = evidence.owner_nonce_claim.model_copy(update={"request_sha256": "0" * 64})
        evidence = evidence.model_copy(update={"owner_nonce_claim": claim})
    elif change == "claim-database":
        claim = evidence.owner_nonce_claim.model_copy(
            update={"database_uuid": UUID("41da18d5-2b77-407d-b0dc-5366f03ae10a")}
        )
        evidence = evidence.model_copy(update={"owner_nonce_claim": claim})
    elif change == "operator-disarmed":
        op = evidence.operator.model_copy(update={"state": "KILLED"})
        evidence = evidence.model_copy(update={"operator": op})
    elif change == "operator-stale":
        op = evidence.operator.model_copy(update={"observed_at": now - timedelta(seconds=6)})
        evidence = evidence.model_copy(update={"operator": op})
    elif change == "risk-quantity":
        risk = evidence.risk.model_copy(update={"quantity": 99})
        evidence = evidence.model_copy(update={"risk": risk})
    elif change == "risk-instrument":
        risk = evidence.risk.model_copy(update={"instrument": "ETHUSD"})
        evidence = evidence.model_copy(update={"risk": risk})
    elif change == "owner-cap":
        risk = evidence.risk.model_copy(update={"worst_case_loss_usd": Decimal("101")})
        evidence = evidence.model_copy(update={"risk": risk})
    elif change == "daily-stop":
        risk = evidence.risk.model_copy(update={"daily_realized_loss_usd": Decimal("10")})
        evidence = evidence.model_copy(update={"risk": risk})
    elif change == "order-id":
        message = json.loads(request.message_json)
        message["id"] = "00384:BCDEF0123456789ABCDEF01234"
        request = request.model_copy(update={"message_json": json.dumps(message)})
    elif change == "effect-id":
        risk = evidence.risk.model_copy(update={"effect_id": "0" * 64})
        evidence = evidence.model_copy(update={"risk": risk})
    elif change == "request-id":
        risk = evidence.risk.model_copy(update={"signing_request_id": "another-request"})
        evidence = evidence.model_copy(update={"risk": risk})
    elif change == "per-trade-ceiling":
        risk = evidence.risk.model_copy(update={"worst_case_loss_usd": Decimal("26")})
        evidence = evidence.model_copy(update={"risk": risk})
    elif change == "aggregate-ceiling":
        risk = evidence.risk.model_copy(update={"aggregate_open_risk_usd": Decimal("100")})
        evidence = evidence.model_copy(update={"risk": risk})
    elif change == "open-notional-cap":
        risk = evidence.risk.model_copy(update={"aggregate_open_notional_usd": Decimal("101")})
        evidence = evidence.model_copy(update={"risk": risk})
    verifier._source.evidence = evidence
    with pytest.raises(ManagedSigningError):
        verifier.verify_request_at(request, binding, now=now)


def test_protective_exit_is_independent_of_entry_arm_but_bounded_by_exposure():
    verifier, request, binding, evidence, now = fixture("New take-profit/stop-loss")
    verifier._source.evidence = evidence.model_copy(update={"operator": None})
    verifier.verify_request_at(request, binding, now=now)

    excessive = evidence.model_copy(
        update={"exposure": evidence.exposure.model_copy(update={"remaining_quantity": 2})}
    )
    verifier._source.evidence = excessive
    with pytest.raises(ManagedSigningError, match="exceeds remaining exposure"):
        verifier.verify_request_at(request, binding, now=now)


@pytest.mark.parametrize("position_side", ["BUY", "SELL"])
def test_protection_side_is_the_position_side_not_the_closing_order_side(position_side):
    verifier, request, binding, evidence, now = fixture("New take-profit/stop-loss")
    message = json.loads(request.message_json)
    message["side"] = position_side
    request = request.model_copy(update={"message_json": json.dumps(message)})
    risk = evidence.risk.model_copy(
        update={
            "side": position_side,
            "effect_id": signing_effect_id(
                request=request, message=message, decision_id=evidence.risk.decision_id
            ),
        }
    )
    exposure = evidence.exposure.model_copy(update={"position_side": position_side})
    verifier._source.evidence = evidence.model_copy(update={"risk": risk, "exposure": exposure})
    verifier.verify_request_at(request, binding, now=now)
    exposure = exposure.model_copy(update={"position_side": "SELL" if position_side == "BUY" else "BUY"})
    verifier._source.evidence = evidence.model_copy(update={"risk": risk, "exposure": exposure})
    with pytest.raises(ManagedSigningError, match="protected position side"):
        verifier.verify_request_at(request, binding, now=now)


def test_exit_signing_deadline_must_not_outlive_exposure_lease():
    verifier, request, binding, evidence, now = fixture("New take-profit/stop-loss")
    exposure = evidence.exposure.model_copy(
        update={"valid_until": request.expires_at - timedelta(milliseconds=1)}
    )
    verifier._source.evidence = evidence.model_copy(update={"exposure": exposure})
    with pytest.raises(ManagedSigningError, match="exposure snapshot lease"):
        verifier.verify_request_at(request, binding, now=now)


def test_position_close_is_independent_of_arm_and_requires_reducing_risk_side():
    verifier, request, binding, evidence, now = fixture("Position close order")
    verifier._source.evidence = evidence.model_copy(
        update={
            "operator": evidence.operator.model_copy(
                update={"state": "DISARMED", "changed_at": now - timedelta(hours=1)}
            )
        }
    )
    verifier.verify_request_at(request, binding, now=now)

    wrong_side = verifier._source.evidence.model_copy(
        update={"risk": evidence.risk.model_copy(update={"side": "BUY"})}
    )
    verifier._source.evidence = wrong_side
    with pytest.raises(ManagedSigningError, match="reducing side"):
        verifier.verify_request_at(request, binding, now=now)


def test_protective_exit_refuses_wrong_parent_or_wrong_protected_position_side():
    verifier, request, binding, evidence, now = fixture("New take-profit/stop-loss")
    wrong_parent = evidence.model_copy(
        update={"exposure": evidence.exposure.model_copy(update={"parent_order_id": "other-parent"})}
    )
    verifier._source.evidence = wrong_parent
    with pytest.raises(ManagedSigningError):
        verifier.verify_request_at(request, binding, now=now)

    wrong_side = evidence.model_copy(
        update={"exposure": evidence.exposure.model_copy(update={"position_side": "SELL"})}
    )
    verifier._source.evidence = wrong_side
    with pytest.raises(ManagedSigningError, match="protected position side"):
        verifier.verify_request_at(request, binding, now=now)


@pytest.mark.parametrize(
    "mutation",
    [
        {"protection_type": "take-profit"},
        {"trigger_price": 9001},
        {"parent_order_id": "00384:BCDEF0123456789ABCDEF01234"},
    ],
)
def test_protective_exit_requires_exact_trigger_and_parent_geometry(mutation):
    verifier, request, binding, evidence, now = fixture("New take-profit/stop-loss")
    risk = evidence.risk.model_copy(update=mutation)
    verifier._source.evidence = evidence.model_copy(update={"risk": risk})
    with pytest.raises(ManagedSigningError):
        verifier.verify_request_at(request, binding, now=now)


def test_expired_owner_arm_does_not_block_exit_after_historically_accepted_claim():
    verifier, request, binding, evidence, now = fixture("New take-profit/stop-loss")
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    old_arm = evidence.owner_arm.request.model_copy(
        update={"created_at": now - timedelta(seconds=50), "expires_at": now - timedelta(seconds=30)}
    )
    payload = json.dumps(old_arm.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode()
    signed_arm = evidence.owner_arm.model_copy(
        update={
            "request": old_arm,
            "signature_base64": base64.b64encode(key.sign(ARM_DOMAIN + payload)).decode(),
        }
    )
    arm_digest = canonical_digest(old_arm)
    old_claim = evidence.owner_nonce_claim.model_copy(
        update={
            "nonce": old_arm.nonce,
            "request_sha256": arm_digest,
            "claimed_at": now - timedelta(seconds=40),
        }
    )
    expired_evidence = evidence.model_copy(
        update={
            "owner_arm": signed_arm,
            "owner_nonce_claim": old_claim,
            "operator": None,
            "risk": evidence.risk.model_copy(
                update={
                    "aggregate_open_notional_usd": Decimal("1000000"),
                    "aggregate_open_risk_usd": Decimal("1000000"),
                }
            ),
        }
    )
    verifier._source.evidence = expired_evidence
    request = request.model_copy(update={"manual_request_sha256": arm_digest})
    verifier.verify_request_at(request, binding, now=now)


def test_source_failure_and_expired_deadline_fail_closed():
    verifier, request, binding, _, now = fixture()
    verifier._source.resolve_signing_evidence = lambda **_: (_ for _ in ()).throw(RuntimeError("hidden"))
    with pytest.raises(ManagedSigningError, match="owner arm"):
        verifier.verify_request_at(request, binding, now=now)
    verifier, request, binding, _, now = fixture()
    with pytest.raises(ManagedSigningError, match="expired"):
        verifier.verify_request_at(request, binding, now=request.expires_at)


@pytest.mark.parametrize("change", ["custody-receipt", "schema"])
def test_direct_verification_rechecks_custody_and_schema_binding(change):
    verifier, request, binding, _, now = fixture()
    if change == "custody-receipt":
        request = request.model_copy(update={"custody_receipt_sha256": "0" * 64})
    else:
        binding = binding.model_copy(update={"schema_sha256": "0" * 64})
    with pytest.raises(ManagedSigningError, match="custody receipt or reviewed schema"):
        verifier.verify_request_at(request, binding, now=now)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_state_age": timedelta(seconds=6)},
        {"maximum_arm_lifetime": timedelta(minutes=11)},
    ],
)
def test_constructor_rejects_unbounded_authorization_lifetimes(kwargs):
    verifier, _, _, _, _ = fixture()
    args = {
        "source": verifier._source,
        "preconditions": verifier._preconditions,
        "owner_key": verifier._owner_key,
        "expected_owner_key_sha256": verifier._owner_key_sha256,
        "expected_owner_identity": verifier._owner,
        "expected_claim_database_uuid": verifier._claim_database_uuid,
        "maximum_arm_lifetime": timedelta(minutes=10),
    }
    args.update(kwargs)
    with pytest.raises(ValueError):
        ProductionSigningAuthorizationVerifier(**args)


def _native_test_signer(tmp_path, *, authority_change=None):
    pytest.importorskip("eth_account")
    pytest.importorskip("coincurve")
    from kairos_execution.local_custody import CoincurveTypedDataVerifier
    from kairos_execution.managed_signer import ManagedSignerBoundary
    from tests.test_local_custody import CHAIN, INSTRUMENTS, REFERENCE, _backend

    verifier, request, binding, evidence, now = fixture()
    local_backend, wallet = _backend(tmp_path)
    binding = binding.model_copy(
        update={
            "custody_reference": REFERENCE,
            "wallet_address": wallet,
            "chain_id": CHAIN,
            "schema_sha256": reviewed_schema_sha256(CHAIN),
            "approved_instruments": INSTRUMENTS,
        }
    )
    message = json.loads(request.message_json)
    message.update(instrument=INSTRUMENTS[0], chainId=CHAIN)
    request = request.model_copy(update={"message_json": json.dumps(message)})
    risk = evidence.risk.model_copy(
        update={
            "instrument": INSTRUMENTS[0],
            "effect_id": signing_effect_id(
                request=request, message=message, decision_id=evidence.risk.decision_id
            ),
        }
    )
    operator = evidence.operator
    if authority_change == "disarmed":
        operator = operator.model_copy(update={"state": "KILLED"})
    if authority_change == "wrong-order":
        risk = risk.model_copy(update={"client_order_id": "00384:BCDEF0123456789ABCDEF01234"})
    evidence = evidence.model_copy(update={"risk": risk, "operator": operator})
    verifier._source.evidence = evidence

    class CountingBackend:
        def __init__(self, backend):
            self.backend = backend
            self.calls = 0

        def sign_typed_data(self, **kwargs):
            self.calls += 1
            return self.backend.sign_typed_data(**kwargs)

    class SyntheticAsyncClaims:
        """Ephemeral synthetic CAS/terminal store, never a production claim adapter."""

        def __init__(self):
            self.claims = {}
            self.terminals = {}

        async def claim_once_async(self, *, custody_reference, request_id, request_sha256):
            key = (custody_reference, request_id)
            if key in self.claims:
                return False
            self.claims[key] = request_sha256
            return True

        async def finish_signing_async(
            self,
            *,
            custody_reference,
            request_id,
            request_sha256,
            terminal_status,
            result_sha256,
        ):
            key = (custody_reference, request_id)
            assert self.claims[key] == request_sha256
            self.terminals[key] = (terminal_status, result_sha256)

    backend = CountingBackend(local_backend)
    claims = SyntheticAsyncClaims()
    signer = ManagedSignerBoundary(
        binding,
        backend=backend,
        verifier=CoincurveTypedDataVerifier(),
        claims=claims,
        authorization=verifier,
    )
    return signer, request, binding, backend, claims, verifier, now, message


@pytest.mark.asyncio
@pytest.mark.parametrize("authority_change", ["disarmed", "wrong-order"])
async def test_sign_async_authorization_refusal_precedes_any_claim_or_local_key_call(
    tmp_path, authority_change
):
    signer, request, _, backend, claims, _, now, _ = _native_test_signer(
        tmp_path, authority_change=authority_change
    )
    with pytest.raises(ManagedSigningError, match="authorization"):
        await signer.sign_async(request, now=now, claims=claims)
    assert claims.claims == {}
    assert backend.calls == 0


@pytest.mark.asyncio
async def test_sign_async_authorization_reaches_synthetic_local_custody_and_records_terminal(tmp_path):
    signer, request, binding, backend, claims, _, now, message = _native_test_signer(tmp_path)
    receipt = await signer.sign_async(request, now=now, claims=claims)

    assert backend.calls == 1
    assert len(claims.claims) == 1
    assert len(claims.terminals) == 1
    assert next(iter(claims.terminals.values()))[0] == "COMPLETED"
    assert claims.terminals.keys() == claims.claims.keys()
    assert receipt.signature not in repr(receipt)
    assert "signature" not in receipt.model_dump()

    from kairos_execution.local_custody import CoincurveTypedDataVerifier

    assert (
        CoincurveTypedDataVerifier().verify(
            wallet_address=binding.wallet_address,
            domain=build_domain(binding.chain_id),
            types=EIP712_SCHEMAS[request.operation],
            message=message,
            signature=receipt.signature,
        )
        is True
    )
