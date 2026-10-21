"""Synthetic one-effect dispatcher contract tests; no production endpoint calls."""

import asyncio
import json
from datetime import timedelta
from uuid import UUID

import pytest

from kairos_execution.production_dispatch import (
    ProductionDispatchError,
    ProductionEffectDispatcher,
    ProductionWireRequestV1,
)
from kairos_execution.production_readiness import canonical_digest
from kairos_execution.signing_authorization import signing_effect_id
from tests.test_managed_signer import NOW, setup_signer
from tests.test_production_claims import claims_fixture


class CurrentState:
    def __init__(self):
        self.calls = []
        self.fail_on = None

    async def verify_effect_async(self, request, binding, *, decision_id, effect_id):
        self.calls.append((request.request_id, binding.wallet_address, decision_id, effect_id))
        if self.fail_on == len(self.calls):
            raise PermissionError("operator disarmed")


class SyntheticSignatureVerifier:
    def verify(self, *, wallet_address, domain, types, message, signature):
        return (
            wallet_address == "0x" + "12" * 20
            and signature == "0x" + "11" * 65
            and domain["chainId"] == "161803"
        )


@pytest.mark.asyncio
async def test_wire_claim_and_second_state_check_precede_one_exact_transport_call():
    # Run the signing helper inside this loop using a fresh fixture (asyncio.run
    # in wire_fixture is not valid after loop creation, so construct first).
    signer, signing_request, _, _, _ = setup_signer()
    claims, db = claims_fixture(context=signing_request.context)
    signed = await signer.sign_async(signing_request, now=NOW, claims=claims)
    message = json.loads(signing_request.message_json)
    decision_id = "decision-synthetic-1"
    effect_id = signing_effect_id(request=signing_request, message=message, decision_id=decision_id)
    request = ProductionWireRequestV1(
        context=signing_request.context,
        database_uuid=claims.database_uuid,
        decision_id=decision_id,
        effect_id=effect_id,
        effect_type="PLACE_ORDER",
        method="POST",
        path="/api/v2/order/limit",
        body={**message, "signature": signed.signature},
        signing_request=signing_request,
        custody_binding=signer.binding,
        signed=signed,
    )
    auth = CurrentState()
    sends = []

    async def sender(**kwargs):
        assert len(db.claims) == 2  # typed-signing + distinct WIRE_DISPATCH committed
        assert len(auth.calls) == 2
        db.events.append("WIRE_SEND")
        sends.append(kwargs)
        return {"id": message["id"], "status": "NEW"}

    dispatcher = ProductionEffectDispatcher(
        authorization=auth,
        signature_verifier=SyntheticSignatureVerifier(),
        claims=claims,
        database_uuid=claims.database_uuid,
        context=signing_request.context,
        clock=lambda: NOW,
        sender=sender,
    )
    result = await dispatcher.dispatch_one(request)
    assert result["status"] == "NEW"
    assert len(sends) == 1
    assert db.events.index("INSERT_CLAIM") < db.events.index("WIRE_SEND")
    assert db.events[-2:] == ["INSERT_TERMINAL", "COMMIT"]
    row = await claims.load_claim(
        kind="WIRE_DISPATCH", namespace="wire:" + canonical_digest(request.context), identity=effect_id
    )
    assert row["terminal_status"] == "COMPLETED"


@pytest.mark.asyncio
async def test_duplicate_delivery_never_sends_twice():
    signer, signing_request, _, _, _ = setup_signer()
    claims, _ = claims_fixture(context=signing_request.context)
    signed = await signer.sign_async(signing_request, now=NOW, claims=claims)
    message = json.loads(signing_request.message_json)
    decision_id = "decision-synthetic-1"
    effect_id = signing_effect_id(request=signing_request, message=message, decision_id=decision_id)
    request = ProductionWireRequestV1(
        context=signing_request.context,
        database_uuid=claims.database_uuid,
        decision_id=decision_id,
        effect_id=effect_id,
        effect_type="PLACE_ORDER",
        method="POST",
        path="/api/v2/order/limit",
        body={**message, "signature": signed.signature},
        signing_request=signing_request,
        custody_binding=signer.binding,
        signed=signed,
    )
    auth, sends = CurrentState(), []

    async def sender(**kwargs):
        sends.append(kwargs)
        return {"id": kwargs["body"]["id"], "status": "NEW"}

    dispatcher = ProductionEffectDispatcher(
        authorization=auth,
        signature_verifier=SyntheticSignatureVerifier(),
        claims=claims,
        database_uuid=claims.database_uuid,
        context=request.context,
        clock=lambda: NOW,
        sender=sender,
    )
    await dispatcher.dispatch_one(request)
    with pytest.raises(ProductionDispatchError, match="already claimed"):
        await dispatcher.dispatch_one(request)
    assert len(sends) == 1


@pytest.mark.asyncio
async def test_changed_wire_body_or_signature_claim_fails_before_wire_admission():
    signer, signing_request, _, _, _ = setup_signer()
    claims, db = claims_fixture(context=signing_request.context)
    signed = await signer.sign_async(signing_request, now=NOW, claims=claims)
    message = json.loads(signing_request.message_json)
    decision_id = "decision-synthetic-1"
    effect_id = signing_effect_id(request=signing_request, message=message, decision_id=decision_id)
    request = ProductionWireRequestV1(
        context=signing_request.context,
        database_uuid=claims.database_uuid,
        decision_id=decision_id,
        effect_id=effect_id,
        effect_type="PLACE_ORDER",
        method="POST",
        path="/api/v2/order/limit",
        body={**message, "signature": signed.signature, "quantity": 101},
        signing_request=signing_request,
        custody_binding=signer.binding,
        signed=signed,
    )
    auth, sends = CurrentState(), []

    async def sender(**kwargs):
        sends.append(kwargs)
        return {"id": "unexpected", "status": "NEW"}

    dispatcher = ProductionEffectDispatcher(
        authorization=auth,
        signature_verifier=SyntheticSignatureVerifier(),
        claims=claims,
        database_uuid=claims.database_uuid,
        context=request.context,
        clock=lambda: NOW,
        sender=sender,
    )
    with pytest.raises(ProductionDispatchError, match="differs from the exact"):
        await dispatcher.dispatch_one(request)
    assert not sends and not auth.calls
    assert not any(key[0] == "WIRE_DISPATCH" for key in db.claims)


@pytest.mark.asyncio
@pytest.mark.parametrize("altered", [True, 1.0, "1"])
async def test_wire_json_numeric_type_substitution_is_rejected_before_authorization(altered):
    signer, signing_request, _, _, _ = setup_signer()
    claims, db = claims_fixture(context=signing_request.context)
    signed = await signer.sign_async(signing_request, now=NOW, claims=claims)
    message = json.loads(signing_request.message_json)
    decision_id = "decision-synthetic-1"
    request = ProductionWireRequestV1(
        context=signing_request.context,
        database_uuid=claims.database_uuid,
        decision_id=decision_id,
        effect_id=signing_effect_id(request=signing_request, message=message, decision_id=decision_id),
        effect_type="PLACE_ORDER",
        method="POST",
        path="/api/v2/order/limit",
        body={**message, "signature": signed.signature, "leverage": altered},
        signing_request=signing_request,
        custody_binding=signer.binding,
        signed=signed,
    )
    auth, sends = CurrentState(), []

    async def sender(**kwargs):
        sends.append(kwargs)
        return {"status": "unexpected"}

    dispatcher = ProductionEffectDispatcher(
        authorization=auth,
        signature_verifier=SyntheticSignatureVerifier(),
        claims=claims,
        database_uuid=claims.database_uuid,
        context=request.context,
        clock=lambda: NOW,
        sender=sender,
    )
    with pytest.raises(ProductionDispatchError, match="differs from the exact"):
        await dispatcher.dispatch_one(request)
    assert not sends and not auth.calls
    assert not any(key[0] == "WIRE_DISPATCH" for key in db.claims)


@pytest.mark.asyncio
async def test_independent_signature_failure_refuses_before_durable_wire_claim():
    signer, signing_request, _, _, _ = setup_signer()
    claims, db = claims_fixture(context=signing_request.context)
    signed = await signer.sign_async(signing_request, now=NOW, claims=claims)
    message = json.loads(signing_request.message_json)
    decision_id = "decision-synthetic-1"
    effect_id = signing_effect_id(request=signing_request, message=message, decision_id=decision_id)
    request = ProductionWireRequestV1(
        context=signing_request.context,
        database_uuid=claims.database_uuid,
        decision_id=decision_id,
        effect_id=effect_id,
        effect_type="PLACE_ORDER",
        method="POST",
        path="/api/v2/order/limit",
        body={**message, "signature": signed.signature},
        signing_request=signing_request,
        custody_binding=signer.binding,
        signed=signed,
    )

    class RejectingVerifier(SyntheticSignatureVerifier):
        def verify(self, **kwargs):
            return False

    auth, sends = CurrentState(), []

    async def sender(**kwargs):
        sends.append(kwargs)
        return {"id": "unexpected", "status": "NEW"}

    dispatcher = ProductionEffectDispatcher(
        authorization=auth,
        signature_verifier=RejectingVerifier(),
        claims=claims,
        database_uuid=claims.database_uuid,
        context=request.context,
        clock=lambda: NOW,
        sender=sender,
    )
    with pytest.raises(ProductionDispatchError, match="independent wire-bound"):
        await dispatcher.dispatch_one(request)
    assert not sends and not auth.calls
    assert not any(key[0] == "WIRE_DISPATCH" for key in db.claims)


@pytest.mark.asyncio
async def test_disarm_between_claim_and_transport_marks_unresolved_without_send():
    signer, signing_request, _, _, _ = setup_signer()
    claims, db = claims_fixture(context=signing_request.context)
    signed = await signer.sign_async(signing_request, now=NOW, claims=claims)
    message = json.loads(signing_request.message_json)
    decision_id = "decision-synthetic-1"
    effect_id = signing_effect_id(request=signing_request, message=message, decision_id=decision_id)
    request = ProductionWireRequestV1(
        context=signing_request.context,
        database_uuid=claims.database_uuid,
        decision_id=decision_id,
        effect_id=effect_id,
        effect_type="PLACE_ORDER",
        method="POST",
        path="/api/v2/order/limit",
        body={**message, "signature": signed.signature},
        signing_request=signing_request,
        custody_binding=signer.binding,
        signed=signed,
    )
    auth, sends = CurrentState(), []
    auth.fail_on = 2

    async def sender(**kwargs):
        sends.append(kwargs)
        return {"id": "ok", "status": "NEW"}

    dispatcher = ProductionEffectDispatcher(
        authorization=auth,
        signature_verifier=SyntheticSignatureVerifier(),
        claims=claims,
        database_uuid=claims.database_uuid,
        context=request.context,
        clock=lambda: NOW,
        sender=sender,
    )
    with pytest.raises(ProductionDispatchError, match="not retryable"):
        await dispatcher.dispatch_one(request)
    assert sends == []
    row = await claims.load_claim(
        kind="WIRE_DISPATCH", namespace="wire:" + canonical_digest(request.context), identity=effect_id
    )
    assert row["terminal_status"] == "UNRESOLVED"


@pytest.mark.asyncio
async def test_transport_cancellation_is_terminal_unresolved_and_never_retried():
    signer, signing_request, _, _, _ = setup_signer()
    claims, _ = claims_fixture(context=signing_request.context)
    signed = await signer.sign_async(signing_request, now=NOW, claims=claims)
    message = json.loads(signing_request.message_json)
    decision_id = "decision-synthetic-1"
    effect_id = signing_effect_id(request=signing_request, message=message, decision_id=decision_id)
    request = ProductionWireRequestV1(
        context=signing_request.context,
        database_uuid=claims.database_uuid,
        decision_id=decision_id,
        effect_id=effect_id,
        effect_type="PLACE_ORDER",
        method="POST",
        path="/api/v2/order/limit",
        body={**message, "signature": signed.signature},
        signing_request=signing_request,
        custody_binding=signer.binding,
        signed=signed,
    )
    auth, sends = CurrentState(), []

    async def sender(**kwargs):
        sends.append(kwargs)
        raise asyncio.CancelledError

    dispatcher = ProductionEffectDispatcher(
        authorization=auth,
        signature_verifier=SyntheticSignatureVerifier(),
        claims=claims,
        database_uuid=claims.database_uuid,
        context=request.context,
        clock=lambda: NOW,
        sender=sender,
    )
    with pytest.raises(asyncio.CancelledError):
        await dispatcher.dispatch_one(request)
    with pytest.raises(ProductionDispatchError, match="already claimed"):
        await dispatcher.dispatch_one(request)
    assert len(sends) == 1


@pytest.mark.asyncio
async def test_dispatch_deadline_covers_durable_reads_and_caps_signing_expiry():
    signer, signing_request, _, _, _ = setup_signer()
    claims, db = claims_fixture(context=signing_request.context)
    signed = await signer.sign_async(signing_request, now=NOW, claims=claims)
    message = json.loads(signing_request.message_json)
    decision_id = "decision-deadline"
    effect_id = signing_effect_id(request=signing_request, message=message, decision_id=decision_id)
    request = ProductionWireRequestV1(
        context=signing_request.context,
        database_uuid=claims.database_uuid,
        decision_id=decision_id,
        effect_id=effect_id,
        effect_type="PLACE_ORDER",
        method="POST",
        path="/api/v2/order/limit",
        body={**message, "signature": signed.signature},
        signing_request=signing_request.model_copy(update={"expires_at": NOW + timedelta(seconds=60)}),
        custody_binding=signer.binding,
        signed=signed,
    )
    dispatcher = ProductionEffectDispatcher(
        authorization=CurrentState(),
        signature_verifier=SyntheticSignatureVerifier(),
        claims=claims,
        database_uuid=claims.database_uuid,
        context=request.context,
        clock=lambda: NOW,
        sender=lambda **kwargs: asyncio.sleep(0, result={"status": "NEW"}),
    )
    with pytest.raises(ProductionDispatchError, match="30-second"):
        await dispatcher.dispatch_one(request)

    signer2, signing_request2, _, _, _ = setup_signer()
    claims2, db2 = claims_fixture(context=signing_request2.context)
    short_signing_request = signing_request2.model_copy(
        update={"expires_at": NOW + timedelta(milliseconds=200)}
    )
    short_signed = await signer2.sign_async(short_signing_request, now=NOW, claims=claims2)
    short_message = json.loads(short_signing_request.message_json)
    short_effect_id = signing_effect_id(
        request=short_signing_request, message=short_message, decision_id=decision_id
    )
    short_request = ProductionWireRequestV1(
        context=short_signing_request.context,
        database_uuid=claims2.database_uuid,
        decision_id=decision_id,
        effect_id=short_effect_id,
        effect_type="PLACE_ORDER",
        method="POST",
        path="/api/v2/order/limit",
        body={**short_message, "signature": short_signed.signature},
        signing_request=short_signing_request,
        custody_binding=signer2.binding,
        signed=short_signed,
    )
    dispatcher2 = ProductionEffectDispatcher(
        authorization=CurrentState(),
        signature_verifier=SyntheticSignatureVerifier(),
        claims=claims2,
        database_uuid=claims2.database_uuid,
        context=short_request.context,
        clock=lambda: NOW,
        sender=lambda **kwargs: asyncio.sleep(0, result={"status": "NEW"}),
    )
    original_load = claims2.load_claim

    async def slow_load(**kwargs):
        await asyncio.sleep(1)
        return await original_load(**kwargs)

    claims2.load_claim = slow_load
    with pytest.raises(ProductionDispatchError, match="deadline elapsed"):
        await dispatcher2.dispatch_one(short_request)
    assert not any(key[0] == "WIRE_DISPATCH" for key in db2.claims)


@pytest.mark.asyncio
async def test_wall_clock_rollback_and_zero_database_uuid_fail_closed():
    signer, signing_request, _, _, _ = setup_signer()
    claims, db = claims_fixture(context=signing_request.context)
    signed = await signer.sign_async(signing_request, now=NOW, claims=claims)
    message = json.loads(signing_request.message_json)
    decision_id = "decision-clock"
    effect_id = signing_effect_id(request=signing_request, message=message, decision_id=decision_id)
    request = ProductionWireRequestV1(
        context=signing_request.context,
        database_uuid=claims.database_uuid,
        decision_id=decision_id,
        effect_id=effect_id,
        effect_type="PLACE_ORDER",
        method="POST",
        path="/api/v2/order/limit",
        body={**message, "signature": signed.signature},
        signing_request=signing_request,
        custody_binding=signer.binding,
        signed=signed,
    )
    ticks = iter((NOW, NOW - timedelta(seconds=1)))
    dispatcher = ProductionEffectDispatcher(
        authorization=CurrentState(),
        signature_verifier=SyntheticSignatureVerifier(),
        claims=claims,
        database_uuid=claims.database_uuid,
        context=request.context,
        clock=lambda: next(ticks),
        sender=lambda **kwargs: asyncio.sleep(0, result={"status": "NEW"}),
    )
    with pytest.raises(ProductionDispatchError, match="moved backwards"):
        await dispatcher.dispatch_one(request)
    assert not any(key[0] == "WIRE_DISPATCH" for key in db.claims)

    with pytest.raises(ValueError, match="database UUID"):
        ProductionEffectDispatcher(
            authorization=CurrentState(),
            signature_verifier=SyntheticSignatureVerifier(),
            claims=claims,
            database_uuid=UUID(int=0),
            context=request.context,
            clock=lambda: NOW,
            sender=lambda **kwargs: asyncio.sleep(0, result={"status": "NEW"}),
        )


@pytest.mark.asyncio
async def test_sender_deadline_returns_no_late_success_and_refuses_replay():
    signer, signing_request, _, _, _ = setup_signer()
    claims, _ = claims_fixture(context=signing_request.context)
    signing_request = signing_request.model_copy(update={"expires_at": NOW + timedelta(milliseconds=250)})
    signed = await signer.sign_async(signing_request, now=NOW, claims=claims)
    message = json.loads(signing_request.message_json)
    decision_id = "decision-sender-timeout"
    effect_id = signing_effect_id(request=signing_request, message=message, decision_id=decision_id)
    request = ProductionWireRequestV1(
        context=signing_request.context,
        database_uuid=claims.database_uuid,
        decision_id=decision_id,
        effect_id=effect_id,
        effect_type="PLACE_ORDER",
        method="POST",
        path="/api/v2/order/limit",
        body={**message, "signature": signed.signature},
        signing_request=signing_request,
        custody_binding=signer.binding,
        signed=signed,
    )
    calls = []

    async def slow_sender(**kwargs):
        calls.append(kwargs)
        await asyncio.sleep(5)
        return {"status": "LATE"}

    dispatcher = ProductionEffectDispatcher(
        authorization=CurrentState(),
        signature_verifier=SyntheticSignatureVerifier(),
        claims=claims,
        database_uuid=claims.database_uuid,
        context=request.context,
        clock=lambda: NOW,
        sender=slow_sender,
    )
    with pytest.raises(ProductionDispatchError):
        await dispatcher.dispatch_one(request)
    with pytest.raises(ProductionDispatchError, match="already claimed"):
        await dispatcher.dispatch_one(request)
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_terminal_timeout_does_not_wait_for_late_ack_or_allow_replay():
    signer, signing_request, _, _, _ = setup_signer()
    claims, _ = claims_fixture(context=signing_request.context)
    signing_request = signing_request.model_copy(update={"expires_at": NOW + timedelta(milliseconds=250)})
    signed = await signer.sign_async(signing_request, now=NOW, claims=claims)
    message = json.loads(signing_request.message_json)
    decision_id = "decision-terminal-timeout"
    effect_id = signing_effect_id(request=signing_request, message=message, decision_id=decision_id)
    request = ProductionWireRequestV1(
        context=signing_request.context,
        database_uuid=claims.database_uuid,
        decision_id=decision_id,
        effect_id=effect_id,
        effect_type="PLACE_ORDER",
        method="POST",
        path="/api/v2/order/limit",
        body={**message, "signature": signed.signature},
        signing_request=signing_request,
        custody_binding=signer.binding,
        signed=signed,
    )
    allow_terminal_ack = asyncio.Event()
    original_finish = claims.finish_wire_async

    async def delayed_finish(**kwargs):
        await allow_terminal_ack.wait()
        await original_finish(**kwargs)

    claims.finish_wire_async = delayed_finish
    sends = []

    async def sender(**kwargs):
        sends.append(kwargs)
        return {"status": "NEW"}

    dispatcher = ProductionEffectDispatcher(
        authorization=CurrentState(),
        signature_verifier=SyntheticSignatureVerifier(),
        claims=claims,
        database_uuid=claims.database_uuid,
        context=request.context,
        clock=lambda: NOW,
        sender=sender,
    )
    with pytest.raises(ProductionDispatchError, match="deadline elapsed"):
        await dispatcher.dispatch_one(request)
    allow_terminal_ack.set()
    await asyncio.sleep(0.05)
    row = await claims.load_claim(
        kind="WIRE_DISPATCH", namespace="wire:" + canonical_digest(request.context), identity=effect_id
    )
    assert row["terminal_status"] == "COMPLETED"
    with pytest.raises(ProductionDispatchError, match="already claimed"):
        await dispatcher.dispatch_one(request)
    assert len(sends) == 1
