"""Durable adapter callback ordering; synthetic backends, not native custody."""

import asyncio
import threading
import time
from datetime import timedelta

import pytest

from kairos_execution.managed_signer import ManagedSigningError
from tests.test_managed_signer import NOW, setup_signer
from tests.test_production_claims import claims_fixture


@pytest.mark.asyncio
async def test_async_sign_only_after_acknowledged_commit_and_terminal_before_return():
    signer, request, backend, _, _ = setup_signer()
    claims, db = claims_fixture(context=request.context)
    callback = backend.sign_typed_data

    def assert_committed(**kwargs):
        assert db.events[-1] == "COMMIT" and len(db.claims) == 1
        return callback(**kwargs)

    backend.sign_typed_data = assert_committed
    receipt = await signer.sign_async(request, now=NOW, claims=claims)
    assert receipt.signature not in repr(receipt)
    assert db.events[-2:] == ["INSERT_TERMINAL", "COMMIT"]
    restarted, _ = claims_fixture(db, context=request.context)
    with pytest.raises(ManagedSigningError, match="claimed or unresolved"):
        await signer.sign_async(request, now=NOW, claims=restarted)
    assert len(backend.calls) == 1


@pytest.mark.asyncio
async def test_claim_commit_loss_before_any_callback_never_grants_retry():
    signer, request, backend, _, _ = setup_signer()
    claims, db = claims_fixture(context=request.context)
    db.commit_lost = True
    with pytest.raises(ManagedSigningError, match="claim outcome is unresolved"):
        await signer.sign_async(request, now=NOW, claims=claims)
    with pytest.raises(ManagedSigningError, match="claimed or unresolved"):
        await signer.sign_async(request, now=NOW, claims=claims)
    assert backend.calls == []


@pytest.mark.asyncio
async def test_terminal_commit_loss_discards_signature_without_replay():
    signer, request, backend, _, _ = setup_signer()
    claims, db = claims_fixture(context=request.context)
    original = backend.sign_typed_data

    def lose_terminal_ack(**kwargs):
        db.commit_lost = True
        return original(**kwargs)

    backend.sign_typed_data = lose_terminal_ack
    with pytest.raises(ManagedSigningError, match="terminal outcome is unresolved"):
        await signer.sign_async(request, now=NOW, claims=claims)
    with pytest.raises(ManagedSigningError, match="claimed or unresolved"):
        await signer.sign_async(request, now=NOW, claims=claims)
    assert len(backend.calls) == 1 and next(iter(db.terminals.values()))["terminal_status"] == "COMPLETED"


@pytest.mark.asyncio
async def test_failed_backend_keeps_unresolved_terminal_and_sanitizes_error():
    signer, request, backend, _, _ = setup_signer()
    backend.fail = True
    claims, db = claims_fixture(context=request.context)
    with pytest.raises(ManagedSigningError, match="unresolved") as error:
        await signer.sign_async(request, now=NOW, claims=claims)
    assert "DO_NOT_LEAK" not in str(error.value)
    assert next(iter(db.terminals.values()))["terminal_status"] == "UNRESOLVED"
    with pytest.raises(ManagedSigningError, match="claimed or unresolved"):
        await signer.sign_async(request, now=NOW, claims=claims)


@pytest.mark.asyncio
async def test_cancelled_callback_leaves_unknown_claim_without_retry():
    signer, request, backend, _, _ = setup_signer()
    claims, db = claims_fixture(context=request.context)
    began, release = threading.Event(), threading.Event()
    original = backend.sign_typed_data

    def blocked(**kwargs):
        began.set()
        assert release.wait(timeout=5)
        return original(**kwargs)

    backend.sign_typed_data = blocked
    task = asyncio.create_task(signer.sign_async(request, now=NOW, claims=claims))
    try:
        assert await asyncio.to_thread(began.wait, 3)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert db.claims and not db.terminals
        with pytest.raises(ManagedSigningError, match="claimed or unresolved"):
            await signer.sign_async(request, now=NOW, claims=claims)
    finally:
        release.set()  # Never leave the synthetic worker waiting beyond the test.


@pytest.mark.asyncio
async def test_slow_claim_uses_the_same_deadline_before_any_backend_dispatch():
    signer, request, backend, _, _ = setup_signer()
    request = request.model_copy(update={"expires_at": NOW + timedelta(milliseconds=20)})
    claims, db = claims_fixture(context=request.context)
    original = claims.claim_once_async

    async def delayed_claim(**kwargs):
        admitted = await original(**kwargs)
        await asyncio.sleep(0.2)
        return admitted

    claims.claim_once_async = delayed_claim
    with pytest.raises(ManagedSigningError, match="end-to-end signing deadline"):
        await signer.sign_async(request, now=NOW, claims=claims)
    assert db.claims and not db.terminals and backend.calls == []
    claims.claim_once_async = original
    with pytest.raises(ManagedSigningError, match="claimed or unresolved"):
        await signer.sign_async(request, now=NOW, claims=claims)


@pytest.mark.asyncio
async def test_claim_latency_consumes_backend_budget_timeout_preserves_unknown():
    signer, request, backend, _, _ = setup_signer()
    request = request.model_copy(update={"expires_at": NOW + timedelta(milliseconds=80)})
    claims, db = claims_fixture(context=request.context)
    original_claim, original_sign = claims.claim_once_async, backend.sign_typed_data
    began, release = threading.Event(), threading.Event()

    async def delayed_claim(**kwargs):
        admitted = await original_claim(**kwargs)
        await asyncio.sleep(0.05)
        return admitted

    def blocked(**kwargs):
        began.set()
        assert release.wait(timeout=5)
        return original_sign(**kwargs)

    claims.claim_once_async = delayed_claim
    backend.sign_typed_data = blocked
    started = time.monotonic()
    try:
        with pytest.raises(ManagedSigningError, match="end-to-end signing deadline"):
            await signer.sign_async(request, now=NOW, claims=claims)
        assert time.monotonic() - started < 0.5
        assert began.is_set() and db.claims and not db.terminals
        claims.claim_once_async = original_claim
        with pytest.raises(ManagedSigningError, match="claimed or unresolved"):
            await signer.sign_async(request, now=NOW, claims=claims)
    finally:
        release.set()  # Cancellation cannot terminate an arbitrary custody thread.


@pytest.mark.asyncio
async def test_late_terminal_commit_never_returns_a_signature_or_grants_replay():
    signer, request, backend, _, _ = setup_signer()
    request = request.model_copy(update={"expires_at": NOW + timedelta(milliseconds=30)})
    claims, db = claims_fixture(context=request.context)
    original = claims.finish_signing_async

    async def late_terminal(**kwargs):
        # A misbehaving dependency can suppress cancellation after COMMIT.
        # The explicit monotonic check must still reject its late result.
        await original(**kwargs)
        try:
            await asyncio.sleep(0.2)
        except asyncio.CancelledError:
            await asyncio.sleep(0.005)

    claims.finish_signing_async = late_terminal
    with pytest.raises(ManagedSigningError, match="end-to-end signing deadline"):
        await signer.sign_async(request, now=NOW, claims=claims)
    assert next(iter(db.terminals.values()))["terminal_status"] == "COMPLETED"
    with pytest.raises(ManagedSigningError, match="claimed or unresolved"):
        await signer.sign_async(request, now=NOW, claims=claims)
    assert len(backend.calls) == 1


@pytest.mark.asyncio
async def test_async_manual_nonce_validation_preserves_approved_limits_and_no_authority():
    from datetime import timedelta
    from decimal import Decimal

    from kairos_execution.production_readiness import (
        ManualArmRequestV1,
        canonical_digest,
        validate_manual_arm_async,
    )
    from tests.production_evidence_fixtures import signed_gate_fixture

    verifier, refs, _, scope, *_ = signed_gate_fixture()
    preconditions = verifier.verify(scope, refs, now=NOW)
    request = ManualArmRequestV1(
        context=scope,
        preconditions_sha256=canonical_digest(preconditions),
        owner_identity="owner",
        nonce="once",
        created_at=NOW,
        expires_at=NOW + timedelta(seconds=30),
        dollar_cap=Decimal("10"),
        daily_stop_loss_usd=Decimal("1"),
    )
    claims, db = claims_fixture(context=scope)
    kwargs = dict(
        expected_owner_identity="owner", nonce_store=claims, now=NOW, maximum_lifetime=timedelta(minutes=1)
    )
    with pytest.raises(ValueError, match="mismatch"):
        await validate_manual_arm_async(
            request.model_copy(update={"dollar_cap": Decimal("11")}), preconditions, **kwargs
        )
    assert not db.claims
    assert (
        await validate_manual_arm_async(request, preconditions, **kwargs) == "MANUAL_REQUEST_VALIDATED_ONLY"
    )
    assert not preconditions.live_ready and not preconditions.mutation_authority
    with pytest.raises(ValueError, match="consumed or unresolved"):
        await validate_manual_arm_async(request, preconditions, **kwargs)
