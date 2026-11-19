"""Static denial of pre-signed entries; no LIVE authority or venue calls."""

import json

import pytest

from kairos_execution.managed_signer import ManagedSignerBoundary
from kairos_execution.production_dispatch import (
    ProductionDispatchError,
    ProductionEffectDispatcher,
    ProductionWireRequestV1,
    production_wire_body,
)
from kairos_execution.signing_authorization import signing_effect_id
from tests.test_managed_signer import Authorization, Backend, Claims, NOW, Verifier, setup_signer
from tests.test_production_claims import claims_fixture
from tests.test_production_dispatch import CurrentState, SyntheticSignatureVerifier
from tests.test_signing_authorization import fixture


@pytest.mark.asyncio
@pytest.mark.parametrize("claimed_effect", ["PLACE_ORDER", "CLOSE_POSITION", "PROTECTIVE_STOP"])
@pytest.mark.parametrize("operation", ["New limit order", "New market order", "New stop-limit order"])
async def test_required_fence_denies_previously_signed_entry_before_any_wire_io(claimed_effect, operation):
    signer, request, _, _, _ = setup_signer()
    claims, db = claims_fixture(context=request.context)
    signed = await signer.sign_async(request, now=NOW, claims=claims)
    message = json.loads(request.message_json)
    decision_id = "decision-1"
    # Only the limit request is a valid signed effect. The other substitutions
    # check early refusal for each blocked operation, not valid signatures.
    signed_request = request.model_copy(update={"operation": operation})
    wire = ProductionWireRequestV1(
        context=request.context,
        database_uuid=claims.database_uuid,
        decision_id=decision_id,
        effect_id=signing_effect_id(request=request, message=message, decision_id=decision_id),
        effect_type=claimed_effect,
        method="POST",
        path="/api/v2/order/limit",
        body=production_wire_body(request.operation, message, signed.signature),
        signing_request=signed_request,
        custody_binding=signer.binding,
        signed=signed,
    )
    auth, sends = CurrentState(), []

    async def sender(**kwargs):
        sends.append(kwargs)
        return {"status": "NEW"}

    dispatcher = ProductionEffectDispatcher(
        authorization=auth, signature_verifier=SyntheticSignatureVerifier(), claims=claims,
        database_uuid=claims.database_uuid, context=request.context, clock=lambda: NOW,
        sender=sender, require_session_entry_fence=True,
    )
    with pytest.raises(ProductionDispatchError, match="atomic session entry fence is unavailable"):
        await dispatcher.dispatch_one(wire)
    assert not auth.calls and not sends
    assert not any(key[0] == "WIRE_DISPATCH" for key in db.claims)


@pytest.mark.asyncio
@pytest.mark.parametrize("operation,effect,path", [
    ("Position close order", "CLOSE_POSITION", "/api/v2/position/BTCUSD/close"),
    ("New take-profit/stop-loss", "PROTECTIVE_STOP", "/api/tpsl/BTCUSD"),
])
async def test_required_fence_keeps_authorized_protection_and_close(operation, effect, path):
    _, request, binding, _, now = fixture(operation)
    claims, _ = claims_fixture(context=request.context)
    signer = ManagedSignerBoundary(binding, backend=Backend(), verifier=Verifier(), claims=Claims(),
                                   authorization=Authorization(), require_session_entry_fence=True)
    signed = await signer.sign_async(request, now=now, claims=claims)
    message = json.loads(request.message_json)
    decision_id = "decision-1"
    wire = ProductionWireRequestV1(
        context=request.context, database_uuid=claims.database_uuid, decision_id=decision_id,
        effect_id=signing_effect_id(request=request, message=message, decision_id=decision_id),
        effect_type=effect, method="POST", path=path,
        body=production_wire_body(request.operation, message, signed.signature),
        signing_request=request, custody_binding=binding, signed=signed,
    )
    auth, sends = CurrentState(), []

    async def sender(**kwargs):
        sends.append(kwargs)
        return {"status": "SYNTHETIC"}

    dispatcher = ProductionEffectDispatcher(
        authorization=auth, signature_verifier=SyntheticSignatureVerifier(), claims=claims,
        database_uuid=claims.database_uuid, context=request.context, clock=lambda: now,
        sender=sender, require_session_entry_fence=True,
    )
    assert await dispatcher.dispatch_one(wire) == {"status": "SYNTHETIC"}
    assert len(auth.calls) == 2 and len(sends) == 1
