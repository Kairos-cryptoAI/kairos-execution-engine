"""Synthetic I/O ordering only; no exchange authority or real signatures."""

import pytest

from kairos_execution.managed_signer import ManagedSignerBoundary, ManagedSigningError
from kairos_execution.production_dispatch import ProductionDispatchError, ProductionEffectDispatcher
from tests.test_managed_signer import NOW, Claims, setup_signer
from tests.test_production_claims import claims_fixture
from tests.test_production_dispatch import CurrentState, SyntheticSignatureVerifier
from tests.test_session_stop_boundary_wiring import signed_wire


class SyntheticJournal:
    def __init__(self, *, fail):
        self.fail = fail
        self.calls = []

    async def begin_sign(self, **kwargs):
        self.calls.append("SIGN_STARTED")
        if self.fail == "SIGN_STARTED":
            raise ConnectionError("synthetic journal unavailable")

    async def complete_sign(self, **kwargs):
        self.calls.append("SIGNED")
        if self.fail == "SIGNED":
            raise ConnectionError("synthetic journal unavailable")

    async def begin_wire(self, **kwargs):
        self.calls.append("WIRE_STARTED")
        if self.fail == "WIRE_STARTED":
            raise ConnectionError("synthetic journal unavailable")


@pytest.mark.asyncio
@pytest.mark.parametrize("fail,expected_backend", [("SIGN_STARTED", 0), ("SIGNED", 1)])
async def test_signer_never_releases_signature_when_journal_is_unknown(fail, expected_backend):
    original, request, backend, verifier, authorization = setup_signer()
    claims, _ = claims_fixture(context=request.context)
    journal = SyntheticJournal(fail=fail)
    signer = ManagedSignerBoundary(
        original.binding, backend=backend, verifier=verifier, claims=Claims(),
        authorization=authorization, session_entry_io=journal,
    )
    # Synthetic mechanics only; production runtime rejects this state.
    signer._require_session_entry_fence = False
    with pytest.raises(ManagedSigningError):
        await signer.sign_async(request, now=NOW, claims=claims)
    assert len(backend.calls) == expected_backend
    assert journal.calls == (["SIGN_STARTED"] if not expected_backend else ["SIGN_STARTED", "SIGNED"])


@pytest.mark.asyncio
async def test_wire_journal_failure_prevents_sender():
    claims, _, wire, now = await signed_wire()
    journal, sends = SyntheticJournal(fail="WIRE_STARTED"), []

    async def sender(**kwargs):
        sends.append(kwargs)
        return {"status": "SYNTHETIC"}

    dispatcher = ProductionEffectDispatcher(
        authorization=CurrentState(), signature_verifier=SyntheticSignatureVerifier(),
        claims=claims, database_uuid=claims.database_uuid, context=wire.context,
        clock=lambda: now, sender=sender, session_entry_io=journal,
    )
    dispatcher._require_session_entry_fence = False  # synthetic mechanics only
    with pytest.raises(ProductionDispatchError, match="outcome is unresolved"):
        await dispatcher.dispatch_one(wire)
    assert journal.calls == ["WIRE_STARTED"] and sends == []


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["Position close order", "New take-profit/stop-loss"])
async def test_journal_does_not_block_authorized_protection(operation):
    claims, _, wire, now = await signed_wire(operation)
    journal, sends = SyntheticJournal(fail="WIRE_STARTED"), []

    async def sender(**kwargs):
        sends.append(kwargs)
        return {"status": "SYNTHETIC"}

    dispatcher = ProductionEffectDispatcher(
        authorization=CurrentState(), signature_verifier=SyntheticSignatureVerifier(),
        claims=claims, database_uuid=claims.database_uuid, context=wire.context,
        clock=lambda: now, sender=sender, session_entry_io=journal,
    )
    assert await dispatcher.dispatch_one(wire) == {"status": "SYNTHETIC"}
    assert len(sends) == 1 and journal.calls == []
