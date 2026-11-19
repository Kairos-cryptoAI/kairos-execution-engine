"""Bounded availability waits preserve strict source and signing checks."""

from datetime import timedelta

import pytest

from kairos_execution.managed_signer import ManagedSigningError
from kairos_execution.production_state import ProductionStateError, _validate_snapshot_clock_after_wait
from kairos_execution.utc_clock import precise_utc_now
from tests.test_signing_authorization import fixture


@pytest.mark.asyncio
async def test_wait_uses_real_current_time_before_accepting_immutable_snapshot():
    started = precise_utc_now()
    resolved = started + timedelta(milliseconds=2)
    await _validate_snapshot_clock_after_wait(
        started_at=started, resolved_at=resolved, clock_probe=precise_utc_now, max_age=timedelta(seconds=5)
    )
    assert precise_utc_now() >= resolved
    assert resolved == started + timedelta(milliseconds=2)


@pytest.mark.asyncio
async def test_stalled_utc_clock_times_out_without_accepting_future_snapshot():
    now = precise_utc_now()
    with pytest.raises(ProductionStateError, match="timed out"):
        await _validate_snapshot_clock_after_wait(
            started_at=now,
            resolved_at=now + timedelta(milliseconds=1),
            clock_probe=lambda: now,
            max_age=timedelta(seconds=5),
        )


@pytest.mark.asyncio
async def test_large_future_snapshot_is_rejected_without_waiting():
    now = precise_utc_now()
    calls = 0

    def clock():
        nonlocal calls
        calls += 1
        return now

    with pytest.raises(ProductionStateError, match="future-dated"):
        await _validate_snapshot_clock_after_wait(
            started_at=now,
            resolved_at=now + timedelta(milliseconds=51),
            clock_probe=clock,
            max_age=timedelta(seconds=5),
        )
    assert calls == 1


@pytest.mark.asyncio
async def test_clock_rollback_during_wait_refuses():
    now = precise_utc_now()
    values = iter([now, now - timedelta(microseconds=1)])
    with pytest.raises(ProductionStateError, match="backwards"):
        await _validate_snapshot_clock_after_wait(
            started_at=now,
            resolved_at=now + timedelta(milliseconds=1),
            clock_probe=lambda: next(values),
            max_age=timedelta(seconds=5),
        )


@pytest.mark.asyncio
async def test_strict_snapshot_age_is_rechecked_after_wait():
    now = precise_utc_now()
    values = iter([now, now + timedelta(seconds=6)])
    with pytest.raises(ProductionStateError, match="stale"):
        await _validate_snapshot_clock_after_wait(
            started_at=now,
            resolved_at=now + timedelta(milliseconds=1),
            clock_probe=lambda: next(values),
            max_age=timedelta(seconds=5),
        )


@pytest.mark.asyncio
async def test_authorization_rechecks_original_request_expiry_after_source_wait():
    verifier, request, binding, evidence, now = fixture()
    original_expiry = now + timedelta(milliseconds=1)
    request = request.model_copy(update={"expires_at": original_expiry})
    clock_value = now

    class WaitingSource:
        completed = False

        async def resolve_signing_evidence_async(self, **kwargs):
            nonlocal clock_value
            resolved = now + timedelta(milliseconds=1)

            def clock():
                nonlocal clock_value
                value = clock_value
                clock_value = resolved
                return value

            await _validate_snapshot_clock_after_wait(
                started_at=now, resolved_at=resolved, clock_probe=clock, max_age=timedelta(seconds=5)
            )
            self.completed = True
            return evidence.model_copy(update={"resolved_at": resolved})

    source = WaitingSource()
    verifier._source = source
    verifier._clock = lambda: clock_value
    with pytest.raises(ManagedSigningError, match="expired"):
        await verifier.inspect_request_async(request, binding)
    assert source.completed
    assert request.expires_at == original_expiry
