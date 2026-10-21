"""Async state composition tests, not venue acceptance or LIVE authority."""

import asyncio
from datetime import timedelta

import pytest

from kairos_execution.managed_signer import ManagedSigningError
from tests.test_managed_signer import NOW, setup_signer
from tests.test_production_claims import claims_fixture
from tests.test_signing_authorization import fixture


class AsyncSource:
    def __init__(self, evidence):
        self.evidence = evidence
        self.calls = 0

    async def resolve_signing_evidence_async(self, **kwargs):
        self.calls += 1
        await asyncio.sleep(0)
        return self.evidence


@pytest.mark.asyncio
async def test_async_policy_uses_native_source_and_retains_exact_policy():
    verifier, request, binding, evidence, now = fixture()
    source = AsyncSource(evidence)
    verifier._source = source
    verifier._clock = lambda: now
    await verifier.verify_request_async(request, binding)
    assert source.calls == 1
    source.evidence = evidence.model_copy(
        update={"risk": evidence.risk.model_copy(update={"quantity": evidence.risk.quantity + 1})}
    )
    with pytest.raises(ManagedSigningError, match="geometry"):
        await verifier.verify_request_async(request, binding)
    with pytest.raises(ManagedSigningError, match="unavailable"):
        verifier.verify_request_at(request, binding, now=now)


@pytest.mark.asyncio
@pytest.mark.parametrize("clock_change", [timedelta(seconds=21), timedelta(seconds=-1)])
async def test_async_policy_rechecks_clock_after_source_read(clock_change):
    verifier, request, binding, evidence, now = fixture()
    times = iter((now, now + clock_change))
    verifier._clock = lambda: next(times)
    verifier._source = AsyncSource(evidence)
    with pytest.raises(ManagedSigningError, match="expired|backwards"):
        await verifier.verify_request_async(request, binding)


@pytest.mark.asyncio
async def test_async_source_error_is_sanitized():
    verifier, request, binding, _, now = fixture()

    class FailedSource:
        async def resolve_signing_evidence_async(self, **kwargs):
            raise RuntimeError("DO_NOT_LEAK_DATABASE_PASSWORD")

    verifier._source = FailedSource()
    verifier._clock = lambda: now
    with pytest.raises(ManagedSigningError) as error:
        await verifier.verify_request_async(request, binding)
    assert "DO_NOT_LEAK" not in str(error.value)
    assert error.value.__suppress_context__


@pytest.mark.asyncio
async def test_wire_effect_must_resolve_the_exact_current_risk_identity():
    verifier, request, binding, evidence, now = fixture()
    verifier._source = AsyncSource(evidence)
    verifier._clock = lambda: now
    await verifier.verify_effect_async(
        request, binding, decision_id=evidence.risk.decision_id, effect_id=evidence.risk.effect_id
    )
    for decision_id, effect_id in (
        ("guessed-decision", evidence.risk.effect_id),
        (evidence.risk.decision_id, "0" * 64),
    ):
        with pytest.raises(ManagedSigningError, match="wire effect differs"):
            await verifier.verify_effect_async(request, binding, decision_id=decision_id, effect_id=effect_id)


@pytest.mark.asyncio
async def test_signer_awaits_authorization_before_claim_and_does_not_block_loop():
    signer, request, backend, _, _ = setup_signer()
    claims, db = claims_fixture(context=request.context)
    entered, release = asyncio.Event(), asyncio.Event()

    class Authorization:
        async def verify_request_async(self, request, binding):
            entered.set()
            await release.wait()

    signer._authorization = Authorization()
    task = asyncio.create_task(signer.sign_async(request, now=NOW, claims=claims))
    await asyncio.wait_for(entered.wait(), timeout=2)
    assert not db.claims and not backend.calls
    release.set()
    await task
    assert db.claims and db.terminals and len(backend.calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel", [False, True])
async def test_async_authorization_timeout_or_cancellation_never_claims_or_signs(cancel):
    signer, request, backend, _, _ = setup_signer()
    request = request.model_copy(update={"expires_at": NOW + timedelta(milliseconds=100)})
    claims, db = claims_fixture(context=request.context)
    entered = asyncio.Event()

    class Authorization:
        async def verify_request_async(self, request, binding):
            entered.set()
            await asyncio.Event().wait()

    signer._authorization = Authorization()
    task = asyncio.create_task(signer.sign_async(request, now=NOW, claims=claims))
    await asyncio.wait_for(entered.wait(), timeout=2)
    if cancel:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    else:
        with pytest.raises(ManagedSigningError, match="end-to-end signing deadline"):
            await asyncio.wait_for(task, timeout=2)
    assert not db.claims and not backend.calls


def test_sync_signer_cannot_bypass_async_only_authorization():
    signer, request, backend, _, _ = setup_signer()

    class Authorization:
        async def verify_request_async(self, request, binding):
            return None

    signer._authorization = Authorization()
    with pytest.raises(ManagedSigningError, match="authorization failed"):
        signer.sign(request, now=NOW)
    assert not signer._claims.ids and not backend.calls
