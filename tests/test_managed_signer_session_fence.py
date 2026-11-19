"""Unavailable session fencing denies order types, never grants LIVE authority."""

import pytest

from kairos_execution.managed_signer import ManagedSignerBoundary, ManagedSigningError
from tests.test_managed_signer import NOW, Authorization, Backend, Claims, Verifier, setup_signer
from tests.test_production_claims import claims_fixture
from tests.test_signing_authorization import fixture


def require_fence(signer):
    return ManagedSignerBoundary(
        signer.binding,
        backend=signer._backend,
        verifier=signer._verifier,
        claims=signer._claims,
        authorization=signer._authorization,
        require_session_entry_fence=True,
    )


@pytest.mark.parametrize("operation", ["New limit order", "New market order", "New stop-limit order"])
def test_required_fence_denies_entry_before_sync_claim_and_custody(operation):
    signer, request, backend, _, authorization = setup_signer()
    signer = require_fence(signer)
    request = request.model_copy(update={"operation": operation})
    authorization.allow = False  # No independent callback can override the denial.
    with pytest.raises(ManagedSigningError, match="atomic session entry fence is unavailable"):
        signer.sign(request, now=NOW)
    assert not signer._claims.ids and not backend.calls


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["New limit order", "New market order", "New stop-limit order"])
async def test_required_fence_denies_entry_before_async_claim_and_custody(operation):
    signer, request, backend, _, _ = setup_signer()
    signer = require_fence(signer)
    claims, db = claims_fixture(context=request.context)
    request = request.model_copy(update={"operation": operation})
    with pytest.raises(ManagedSigningError, match="atomic session entry fence is unavailable"):
        await signer.sign_async(request, now=NOW, claims=claims)
    assert not db.claims and not backend.calls


@pytest.mark.parametrize("operation", ["Position close order", "New take-profit/stop-loss"])
def test_required_fence_keeps_protection_subject_to_independent_authorization(operation):
    _, request, binding, _, now = fixture(operation)
    backend, claims, authorization = Backend(), Claims(), Authorization()
    signer = ManagedSignerBoundary(
        binding,
        backend=backend,
        verifier=Verifier(),
        claims=claims,
        authorization=authorization,
        require_session_entry_fence=True,
    )
    authorization.allow = False
    with pytest.raises(ManagedSigningError, match="independent signing authorization failed"):
        signer.sign(request, now=now)
    assert not claims.ids and not backend.calls
    authorization.allow = True
    signer.sign(request, now=now)
    assert len(claims.ids) == len(backend.calls) == 1


def test_fence_requirement_rejects_non_boolean_configuration():
    signer, _, _, _, _ = setup_signer()
    with pytest.raises(TypeError, match="must be boolean"):
        ManagedSignerBoundary(
            signer.binding,
            backend=signer._backend,
            verifier=signer._verifier,
            claims=signer._claims,
            authorization=signer._authorization,
            require_session_entry_fence="false",
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["Position close order", "New take-profit/stop-loss"])
async def test_async_required_fence_preserves_authorized_protection(operation):
    _, request, binding, _, now = fixture(operation)
    backend, authorization = Backend(), Authorization()
    claims, db = claims_fixture(context=request.context)
    signer = ManagedSignerBoundary(
        binding,
        backend=backend,
        verifier=Verifier(),
        claims=Claims(),
        authorization=authorization,
        require_session_entry_fence=True,
    )
    authorization.allow = False
    with pytest.raises(ManagedSigningError, match="independent signing authorization failed"):
        await signer.sign_async(request, now=now, claims=claims)
    assert not db.claims and not backend.calls
    authorization.allow = True
    await signer.sign_async(request, now=now, claims=claims)
    assert len(db.claims) == len(backend.calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["Position close order", "New take-profit/stop-loss"])
async def test_real_authorizer_and_claims_still_gate_allowlisted_operations(operation):
    authorization, request, binding, _, now = fixture(operation)
    source = authorization._source

    async def resolve_signing_evidence_async(*, request, binding, now):
        return source.resolve_signing_evidence(request=request, binding=binding, now=now)

    source.resolve_signing_evidence_async = resolve_signing_evidence_async
    backend = Backend()
    claims, db = claims_fixture(context=request.context)
    signer = ManagedSignerBoundary(
        binding,
        backend=backend,
        verifier=Verifier(),
        claims=Claims(),
        authorization=authorization,
        require_session_entry_fence=True,
    )
    await signer.sign_async(request, now=now, claims=claims)
    with pytest.raises(ManagedSigningError, match="claimed or unresolved"):
        await signer.sign_async(request, now=now, claims=claims)
    assert len(db.claims) == len(backend.calls) == 1
