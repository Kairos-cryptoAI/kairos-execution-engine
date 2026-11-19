"""Synthetic tests for the supplemental STOP boundary; no LIVE authority."""

import json
from contextlib import asynccontextmanager
from datetime import timedelta
from uuid import uuid4

import pytest

from kairos_execution.managed_signer import ManagedSignerBoundary, ManagedSigningError
from kairos_execution.production_dispatch import (
    ProductionDispatchError,
    ProductionEffectDispatcher,
    ProductionWireRequestV1,
    production_wire_body,
)
from kairos_execution.production_runtime_builder import build_clocked_production_runtime
from kairos_execution.signing_authorization import signing_effect_id
from tests.test_managed_signer import NOW, Authorization, Backend, Claims, Verifier, setup_signer
from tests.test_production_claims import claims_fixture
from tests.test_production_dispatch import CurrentState, SyntheticSignatureVerifier
from tests.test_production_runtime_builder import setup as builder_setup  # noqa: F401
from tests.test_signing_authorization import fixture


class SyntheticStop:
    def __init__(self, *, active):
        self.active = active
        self.calls = []

    @asynccontextmanager
    async def entry(self, *, context):
        self.calls.append(context)
        if not self.active:
            raise PermissionError("synthetic stopped session")
        yield


@pytest.mark.asyncio
async def test_forged_active_guard_never_enables_direct_signer():
    original, request, backend, verifier, authorization = setup_signer()
    claims, _ = claims_fixture(context=request.context)
    boundary = SyntheticStop(active=True)
    signer = ManagedSignerBoundary(
        original.binding, backend=backend, verifier=verifier, claims=Claims(),
        authorization=authorization, session_stop_boundary=boundary,
    )
    with pytest.raises(ManagedSigningError, match="atomic session entry fence is unavailable"):
        await signer.sign_async(request, now=NOW, claims=claims)
    assert boundary.calls == [] and backend.calls == []


@pytest.mark.asyncio
async def test_stop_after_signing_claim_prevents_custody_and_claim_is_unresolved():
    original, request, backend, verifier, authorization = setup_signer()
    claims, db = claims_fixture(context=request.context)
    boundary = SyntheticStop(active=False)
    signer = ManagedSignerBoundary(
        original.binding, backend=backend, verifier=verifier, claims=Claims(),
        authorization=authorization, session_stop_boundary=boundary,
    )
    # Deliberately disable only in this synthetic boundary-mechanics test.
    # A constructed production runtime rejects this inconsistent state.
    signer._require_session_entry_fence = False
    with pytest.raises(ManagedSigningError, match="outcome failed or is unresolved"):
        await signer.sign_async(request, now=NOW, claims=claims)
    assert boundary.calls == [request.context]
    assert backend.calls == []
    assert any(record.get("terminal_status") == "UNRESOLVED" for record in db.terminals.values())


def test_sync_entry_cannot_skip_configured_async_boundary():
    original, request, backend, verifier, authorization = setup_signer()
    signer = ManagedSignerBoundary(
        original.binding, backend=backend, verifier=verifier, claims=Claims(),
        authorization=authorization, session_stop_boundary=SyntheticStop(active=True),
    )
    signer._require_session_entry_fence = False  # synthetic mechanics only
    with pytest.raises(ManagedSigningError, match="require asynchronous signing"):
        signer.sign(request, now=NOW)
    assert not backend.calls


async def signed_wire(operation="New limit order"):
    if operation == "New limit order":
        signer, request, _, _, _ = setup_signer()
        now = NOW
    else:
        _, request, binding, _, now = fixture(operation)
        signer = ManagedSignerBoundary(
            binding, backend=Backend(), verifier=Verifier(), claims=Claims(), authorization=Authorization()
        )
    claims, db = claims_fixture(context=request.context)
    signed = await signer.sign_async(request, now=now, claims=claims)
    message = json.loads(request.message_json)
    decision_id = "decision-1"
    effect, path = {
        "New limit order": ("PLACE_ORDER", "/api/v2/order/limit"),
        "Position close order": ("CLOSE_POSITION", "/api/v2/position/BTCUSD/close"),
        "New take-profit/stop-loss": ("PROTECTIVE_STOP", "/api/tpsl/BTCUSD"),
    }[operation]
    wire = ProductionWireRequestV1(
        context=request.context, database_uuid=claims.database_uuid, decision_id=decision_id,
        effect_id=signing_effect_id(request=request, message=message, decision_id=decision_id),
        effect_type=effect, method="POST", path=path,
        body=production_wire_body(request.operation, message, signed.signature),
        signing_request=request, custody_binding=signer.binding, signed=signed,
    )
    return claims, db, wire, now


@pytest.mark.asyncio
async def test_forged_active_guard_never_enables_direct_dispatch():
    claims, _, wire, now = await signed_wire()
    boundary, sends = SyntheticStop(active=True), []

    async def sender(**kwargs):
        sends.append(kwargs)
        return {"status": "SYNTHETIC"}

    dispatcher = ProductionEffectDispatcher(
        authorization=CurrentState(), signature_verifier=SyntheticSignatureVerifier(),
        claims=claims, database_uuid=claims.database_uuid, context=wire.context,
        clock=lambda: now, sender=sender, session_stop_boundary=boundary,
    )
    with pytest.raises(ProductionDispatchError, match="atomic session entry fence is unavailable"):
        await dispatcher.dispatch_one(wire)
    assert boundary.calls == [] and sends == []


@pytest.mark.asyncio
async def test_stop_after_wire_claim_prevents_previously_signed_entry():
    claims, db, wire, now = await signed_wire()
    boundary, sends = SyntheticStop(active=False), []

    async def sender(**kwargs):
        sends.append(kwargs)
        return {"status": "SYNTHETIC"}

    dispatcher = ProductionEffectDispatcher(
        authorization=CurrentState(), signature_verifier=SyntheticSignatureVerifier(),
        claims=claims, database_uuid=claims.database_uuid, context=wire.context,
        clock=lambda: now, sender=sender, session_stop_boundary=boundary,
    )
    dispatcher._require_session_entry_fence = False  # synthetic mechanics only
    with pytest.raises(ProductionDispatchError, match="outcome is unresolved"):
        await dispatcher.dispatch_one(wire)
    assert boundary.calls == [wire.context]
    assert not sends
    assert any(record.get("terminal_status") == "UNRESOLVED" for record in db.wire_terminals.values())


@pytest.mark.asyncio
async def test_wire_expiring_while_waiting_for_lock_never_calls_sender():
    claims, _, wire, now = await signed_wire()
    current, sends = [now], []

    class WaitPastExpiry:
        @asynccontextmanager
        async def entry(self, *, context):
            assert context == wire.context
            current[0] = wire.signing_request.expires_at + timedelta(microseconds=1)
            yield

    async def sender(**kwargs):
        sends.append(kwargs)
        return {"status": "SYNTHETIC"}

    dispatcher = ProductionEffectDispatcher(
        authorization=CurrentState(), signature_verifier=SyntheticSignatureVerifier(),
        claims=claims, database_uuid=claims.database_uuid, context=wire.context,
        clock=lambda: current[0], sender=sender, session_stop_boundary=WaitPastExpiry(),
    )
    dispatcher._require_session_entry_fence = False  # synthetic mechanics only
    with pytest.raises(ProductionDispatchError, match="outcome is unresolved"):
        await dispatcher.dispatch_one(wire)
    assert not sends


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["Position close order", "New take-profit/stop-loss"])
async def test_stopped_boundary_does_not_block_authorized_protection(operation):
    claims, _, wire, now = await signed_wire(operation)
    boundary, sends = SyntheticStop(active=False), []

    async def sender(**kwargs):
        sends.append(kwargs)
        return {"status": "SYNTHETIC"}

    dispatcher = ProductionEffectDispatcher(
        authorization=CurrentState(), signature_verifier=SyntheticSignatureVerifier(),
        claims=claims, database_uuid=claims.database_uuid, context=wire.context,
        clock=lambda: now, sender=sender, session_stop_boundary=boundary,
    )
    assert await dispatcher.dispatch_one(wire) == {"status": "SYNTHETIC"}
    assert len(sends) == 1 and boundary.calls == []


def test_builder_wires_one_session_boundary_without_changing_static_fence(builder_setup):  # noqa: F811
    *_, arguments = builder_setup
    runtime = build_clocked_production_runtime(**arguments, session_stop_id=uuid4())
    boundary = runtime.signer._session_stop_boundary
    assert boundary is runtime.dispatcher._session_stop_boundary
    assert boundary.source is runtime.state_source
    assert runtime.state_source._require_session_loss_latch
    assert runtime.signer._require_session_entry_fence
    assert runtime.dispatcher._require_session_entry_fence
    assert runtime.state_source._require_session_entry_fence
    assert runtime.signer._session_entry_io is runtime.dispatcher._session_entry_io
    assert runtime.signer._session_entry_io.source is runtime.state_source


@pytest.mark.asyncio
@pytest.mark.parametrize("broken", [
    "latch", "signer", "dispatcher", "foreign_source", "source_static", "signer_static", "wire_static",
    "io_signer", "io_dispatcher", "io_source", "io_claims", "io_session",
])
async def test_runtime_refuses_inconsistent_session_configuration(builder_setup, broken):  # noqa: F811
    *_, arguments = builder_setup
    runtime = build_clocked_production_runtime(**arguments, session_stop_id=uuid4())
    if broken == "latch":
        runtime.state_source._require_session_loss_latch = False
    elif broken == "signer":
        runtime.signer._session_stop_boundary = None
    elif broken == "dispatcher":
        runtime.dispatcher._session_stop_boundary = None
    elif broken == "foreign_source":
        runtime.signer._session_stop_boundary.source = object()
    elif broken == "source_static":
        runtime.state_source._require_session_entry_fence = False
    elif broken == "signer_static":
        runtime.signer._require_session_entry_fence = False
    elif broken == "wire_static":
        runtime.dispatcher._require_session_entry_fence = False
    elif broken == "io_signer":
        runtime.signer._session_entry_io = None
    elif broken == "io_dispatcher":
        runtime.dispatcher._session_entry_io = None
    elif broken == "io_source":
        runtime.signer._session_entry_io.source = object()
    elif broken == "io_claims":
        runtime.signer._session_entry_io.claims = object()
    else:
        runtime.signer._session_entry_io.session_id = uuid4()
    _, request, _, _, _ = setup_signer()
    with pytest.raises(ValueError, match="session"):
        await runtime.inspect_authority(request)
