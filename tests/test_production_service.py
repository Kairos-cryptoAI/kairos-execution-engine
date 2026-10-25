"""Offline driver tests; all coordinator effects below are explicitly synthetic."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from kairos_core.enums import SystemMode

from kairos_execution.production_path import ProductionLiveEntryResult, ProductionLiveLifecycleCoordinator
from kairos_execution.production_service import (
    ProductionEntryEnvelope,
    ProductionServiceDriver,
    ProductionServiceError,
)


class SyntheticCoordinator(ProductionLiveLifecycleCoordinator):
    """Synthetic in-memory double: no venue, signing, DB, or authority evidence."""

    def __init__(self, *, recovery=(), entry_error=None):
        self.calls = []
        self.recovery = recovery
        self.entry_error = entry_error
        self.entered = asyncio.Event()
        self.allow_entry = asyncio.Event()
        self.engine = SimpleNamespace(clock=lambda: datetime.now(UTC), recovery_blocked=False)

    async def initialize_recovery(self):
        self.calls.append(("recovery",))
        return self.recovery

    async def reconcile_once(self):
        self.calls.append(("reconcile",))
        return []

    async def admit_and_handle_entry(self, **kwargs):
        self.calls.append(("entry", kwargs))
        self.entered.set()
        await self.allow_entry.wait()
        if self.entry_error is not None:
            raise self.entry_error
        return ProductionLiveEntryResult(risk_stage=object(), execution_result=object())

    async def reconcile_closed_account(self, **kwargs):
        self.calls.append(("closed", kwargs))
        return {"synthetic": True}


def envelope(envelope_id="e-1"):
    # Deliberately opaque synthetic proof objects. They are not signed or valid.
    return ProductionEntryEnvelope(
        envelope_id=envelope_id,
        raw_account_evidence=object(),
        raw_inputs_evidence=object(),
        source_id="synthetic-source",
        review=object(),
        venue=object(),
        allocation=object(),
        owner_arm=object(),
        expires_at=datetime.now(UTC) + timedelta(seconds=30),
        system_mode=SystemMode.NORMAL,
    )


@pytest.mark.asyncio
async def test_startup_recovery_precedes_processing_and_default_is_reject_all():
    coordinator = SyntheticCoordinator()
    driver = ProductionServiceDriver(coordinator, reconciliation_interval_s=60)
    status = await driver.start()
    try:
        assert coordinator.calls[0] == ("recovery",)
        assert status.recovery_complete
        assert status.entries_blocked
        assert status.entry_policy == "REJECT_ALL"
        assert status.readiness is False
        with pytest.raises(ProductionServiceError, match="entries are blocked"):
            await driver.submit(envelope())
        assert not any(call[0] == "entry" for call in coordinator.calls)
    finally:
        await driver.close()


@pytest.mark.asyncio
async def test_exact_envelope_fields_are_forwarded_once_when_gate_allows():
    coordinator = SyntheticCoordinator()

    def admission():
        return True  # Synthetic interlock only; coordinator is still a test double.

    driver = ProductionServiceDriver(coordinator, entry_admission=admission, reconciliation_interval_s=60)
    await driver.start()
    item = envelope()
    coordinator.allow_entry.set()
    try:
        result = await driver.submit(item)
        assert isinstance(result, ProductionLiveEntryResult)
        call = next(call for call in coordinator.calls if call[0] == "entry")
        forwarded = call[1]
        assert callable(forwarded.pop("entry_interlock"))
        assert forwarded == {
            "raw_account_evidence": item.raw_account_evidence,
            "raw_inputs_evidence": item.raw_inputs_evidence,
            "source_id": item.source_id,
            "review": item.review,
            "venue": item.venue,
            "allocation": item.allocation,
            "owner_arm": item.owner_arm,
            "expires_at": item.expires_at,
            "system_mode": item.system_mode,
        }
    finally:
        await driver.close()


@pytest.mark.asyncio
async def test_unknown_entry_outcome_latches_admission_closed_and_never_retries():
    coordinator = SyntheticCoordinator(entry_error=RuntimeError("secret payload must not escape"))
    driver = ProductionServiceDriver(coordinator, entry_admission=lambda: True, reconciliation_interval_s=60)
    await driver.start()
    coordinator.allow_entry.set()
    try:
        with pytest.raises(ProductionServiceError, match="outcome unresolved") as error:
            await driver.submit(envelope())
        assert "secret payload" not in str(error.value)
        assert driver.status.entries_blocked
        with pytest.raises(ProductionServiceError, match="entries are blocked"):
            await driver.submit(envelope("e-2"))
        assert sum(call[0] == "entry" for call in coordinator.calls) == 1
    finally:
        await driver.close()


@pytest.mark.asyncio
async def test_concurrent_submissions_are_serialized_and_duplicate_ids_rejected():
    coordinator = SyntheticCoordinator()
    driver = ProductionServiceDriver(coordinator, entry_admission=lambda: True, reconciliation_interval_s=60)
    await driver.start()
    first = asyncio.create_task(driver.submit(envelope("same")))
    try:
        await coordinator.entered.wait()
        with pytest.raises(ProductionServiceError, match="already seen"):
            await driver.submit(envelope("same"))
        second = asyncio.create_task(driver.submit(envelope("next")))
        await asyncio.sleep(0)
        assert sum(call[0] == "entry" for call in coordinator.calls) == 1
        coordinator.allow_entry.set()
        await asyncio.gather(first, second)
        entry_calls = [call for call in coordinator.calls if call[0] == "entry"]
        assert len(entry_calls) == 2
    finally:
        await driver.close()


@pytest.mark.asyncio
async def test_recovery_blockers_keep_entries_closed_but_reconciliation_runs():
    coordinator = SyntheticCoordinator(recovery=("synthetic blocker",))
    driver = ProductionServiceDriver(
        coordinator, entry_admission=lambda: True, reconciliation_interval_s=0.01
    )
    status = await driver.start()
    try:
        assert status.recovery_blockers == ("AUTHORITATIVE_RECOVERY_BLOCKED",)
        await asyncio.sleep(0.03)
        assert any(call[0] == "reconcile" for call in coordinator.calls)
        with pytest.raises(ProductionServiceError, match="entries are blocked"):
            await driver.submit(envelope())
    finally:
        await driver.close()


@pytest.mark.asyncio
async def test_close_cancels_tasks_and_rejects_pending_work():
    coordinator = SyntheticCoordinator()
    driver = ProductionServiceDriver(coordinator, entry_admission=lambda: True, reconciliation_interval_s=60)
    await driver.start()
    pending = asyncio.create_task(driver.submit(envelope()))
    await coordinator.entered.wait()
    await driver.close()
    with pytest.raises(ProductionServiceError):
        await pending
    assert not driver.status.started
    assert driver.status.entries_blocked


@pytest.mark.parametrize(
    "kwargs",
    [
        {"queue_capacity": True},
        {"queue_capacity": 1.5},
        {"queue_capacity": 129},
        {"maximum_admissions": 0},
        {"maximum_admissions": True},
        {"operation_timeout_s": float("nan")},
        {"operation_timeout_s": float("inf")},
        {"operation_timeout_s": 31},
        {"operation_timeout_s": True},
        {"reconciliation_interval_s": 61},
        {"shutdown_timeout_s": 6},
    ],
)
def test_service_parameters_have_strict_finite_bounds(kwargs):
    with pytest.raises(ValueError):
        ProductionServiceDriver(SyntheticCoordinator(), **kwargs)


@pytest.mark.parametrize("admission_result", [False, 1, "yes", object()])
@pytest.mark.asyncio
async def test_truthy_nonboolean_admission_cannot_reach_coordinator(admission_result):
    coordinator = SyntheticCoordinator()
    coordinator.allow_entry.set()
    driver = ProductionServiceDriver(coordinator, entry_admission=lambda: admission_result)
    await driver.start()
    try:
        with pytest.raises(ProductionServiceError, match="unresolved"):
            await driver.submit(envelope())
        assert not any(call[0] == "entry" for call in coordinator.calls)
        assert driver.status.entries_blocked and not driver.status.recovery_complete
        assert driver._worker_task is not None and not driver._worker_task.done()
    finally:
        await driver.close()


@pytest.mark.asyncio
async def test_raising_or_async_interlock_fails_closed_without_worker_death():
    for async_interlock in (False, True):
        coordinator = SyntheticCoordinator()

        def raises():
            raise RuntimeError("private interlock error must not escape")

        async def asynchronous():
            return True

        driver = ProductionServiceDriver(
            coordinator, entry_admission=asynchronous if async_interlock else raises
        )
        await driver.start()
        try:
            with pytest.raises(ProductionServiceError, match="unresolved") as error:
                await driver.submit(envelope())
            assert "private" not in str(error.value)
            assert not any(call[0] == "entry" for call in coordinator.calls)
            assert driver._worker_task is not None and not driver._worker_task.done()
        finally:
            await driver.close()


@pytest.mark.parametrize("cancel_caller", [False, True], ids=["timeout", "cancel"])
@pytest.mark.asyncio
async def test_caller_cancelled_while_waiting_for_account_lock_never_enters(cancel_caller):
    coordinator = SyntheticCoordinator()
    coordinator.allow_entry.set()
    driver = ProductionServiceDriver(coordinator, entry_admission=lambda: True, operation_timeout_s=0.05)
    await driver.start()
    await driver._account_lock.acquire()
    pending = asyncio.create_task(driver.submit(envelope()))
    try:
        while "e-1" not in driver._seen_envelope_ids:
            await asyncio.sleep(0)
        await asyncio.sleep(0)
        if cancel_caller:
            pending.cancel()
            with pytest.raises(asyncio.CancelledError):
                await pending
        else:
            with pytest.raises(ProductionServiceError):
                await pending
        driver._account_lock.release()
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert not any(call[0] == "entry" for call in coordinator.calls)
        assert driver.status.entries_blocked
    finally:
        if driver._account_lock.locked():
            driver._account_lock.release()
        await driver.close()


@pytest.mark.asyncio
async def test_underlying_fsm_blocked_state_is_not_reported_as_healthy_maintenance():
    coordinator = SyntheticCoordinator()
    driver = ProductionServiceDriver(coordinator, entry_admission=lambda: True)
    await driver.start()
    try:
        coordinator.engine.recovery_blocked = True
        await driver.reconcile_once()
        assert driver.status.entries_blocked
        assert not driver.status.recovery_complete
        assert driver.status.recovery_blockers == ("AUTHORITATIVE_RECOVERY_BLOCKED",)
    finally:
        await driver.close()


@pytest.mark.asyncio
async def test_bounded_admission_fence_does_not_evict_old_identities():
    coordinator = SyntheticCoordinator()
    coordinator.allow_entry.set()
    driver = ProductionServiceDriver(coordinator, entry_admission=lambda: True, maximum_admissions=1)
    await driver.start()
    try:
        await driver.submit(envelope())
        with pytest.raises(ProductionServiceError, match="capacity exhausted"):
            await driver.submit(envelope("e-2"))
        assert driver._seen_envelope_ids == {"e-1"}
        assert driver.status.entries_blocked
    finally:
        await driver.close()


@pytest.mark.parametrize("cancel_caller", [False, True], ids=["timeout", "cancel"])
@pytest.mark.asyncio
async def test_caller_cancellation_interrupts_inflight_staging_before_effect(cancel_caller):
    coordinator = SyntheticCoordinator()
    effects = []

    async def staging(**kwargs):
        coordinator.entered.set()
        await coordinator.allow_entry.wait()
        if kwargs["entry_interlock"]():
            effects.append("synthetic-effect")
        return ProductionLiveEntryResult(risk_stage=object(), execution_result=object())

    coordinator.admit_and_handle_entry = staging
    driver = ProductionServiceDriver(coordinator, entry_admission=lambda: True, operation_timeout_s=0.05)
    await driver.start()
    pending = asyncio.create_task(driver.submit(envelope()))
    try:
        await coordinator.entered.wait()
        if cancel_caller:
            pending.cancel()
            with pytest.raises(asyncio.CancelledError):
                await pending
        else:
            with pytest.raises(ProductionServiceError):
                await pending
        coordinator.allow_entry.set()
        await asyncio.sleep(0)
        assert not effects
        assert driver.status.entries_blocked
    finally:
        await driver.close()
