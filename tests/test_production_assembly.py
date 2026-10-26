"""Offline structural tests for the explicit PROD assembly boundary."""

from __future__ import annotations

import asyncio
from typing import Any, cast
from unittest.mock import AsyncMock

import pytest

from kairos_execution.production_assembly import (
    ProductionAssembly,
    ProductionAssemblyError,
    ProductionAssemblyResources,
    ProductionAssemblyStatus,
    build_production_assembly,
)
from kairos_execution.production_path import ProductionLiveLifecycleCoordinator
from kairos_execution.production_service import ProductionServiceDriver


def _assembly_shell() -> ProductionAssembly:
    """Use exact class shells: no DB, SDK process, or source is created."""
    shell = cast(Any, object())
    return ProductionAssembly(
        runtime=shell,
        reads=shell,
        entry_risk=shell,
        exit_risk=shell,
        cancellation_verifier=shell,
        lifecycle_adapter=shell,
        engine=shell,
        coordinator=shell,
        reconciler=shell,
        accounting=shell,
        canary_verifier=shell,
    )


def _started_driver_shell() -> ProductionServiceDriver:
    coordinator = object.__new__(ProductionLiveLifecycleCoordinator)
    driver = ProductionServiceDriver(coordinator)
    driver._started = True
    return driver


def test_assembly_rejects_incomplete_runtime_before_provider_io():
    calls = []

    class Provider:
        source_id = "synthetic-must-not-be-read"

        async def capture_prepared_exit(self, **kwargs):
            calls.append(("exit", kwargs))

        async def read_cancellation_snapshot_async(self, **kwargs):
            calls.append(("cancel", kwargs))

        def verify_cancellation_snapshot(self, *args, **kwargs):
            calls.append(("verify-cancel", kwargs))

        def verify_terminal_evidence(self, *args, **kwargs):
            calls.append(("terminal", kwargs))

    provider = Provider()
    resources = ProductionAssemblyResources(
        runtime=cast(Any, object()),
        risk_evaluator=cast(Any, object()),
        risk_writer=cast(Any, object()),
        exposure_writer=cast(Any, object()),
        exit_verifier=provider,
        exit_evidence_provider=provider,
        cancellation_sources={provider.source_id: provider},
        terminal_verifiers={provider.source_id: provider},
        trades=cast(Any, object()),
        effects=cast(Any, object()),
        lifecycle_settings=cast(Any, object()),
        reconciliation_pool=cast(Any, object()),
        reconciler_role="reconciler",
        accounting_pool=cast(Any, object()),
        accounting_role="accounting",
        canary_verifier=cast(Any, object()),
        clock=lambda: None,
    )

    with pytest.raises(TypeError, match="exact ProductionExecutionRuntime"):
        build_production_assembly(resources)
    assert calls == []


@pytest.mark.asyncio
async def test_canary_start_latches_before_await_and_never_retries(monkeypatch):
    assembly = _assembly_shell()
    calls = []
    entered = asyncio.Event()
    release = asyncio.Event()

    async def fail_start(**kwargs):
        calls.append(kwargs)
        entered.set()
        await release.wait()
        raise RuntimeError("synthetic unresolved start")

    monkeypatch.setattr("kairos_execution.production_assembly.start_technical_canary_service", fail_start)

    first_attempt = asyncio.create_task(assembly.start_technical_canary(references=(), owner_arm=object()))
    await entered.wait()
    with pytest.raises(ProductionAssemblyError, match="already attempted"):
        await assembly.start_technical_canary(references=(), owner_arm=object())
    release.set()
    with pytest.raises(RuntimeError, match="synthetic unresolved start"):
        await first_attempt
    assert assembly.status == ProductionAssemblyStatus(start_attempted=True)
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_closed_reconciliation_always_uses_attached_accounting_under_driver_lock():
    observed = {}

    class EngineShell:
        async def reconcile_closed_account(self, **kwargs):
            observed.update(kwargs)
            return {"reservation_released": True, "accounting_receipt": {"created": True}}

    coordinator = object.__new__(ProductionLiveLifecycleCoordinator)
    coordinator.engine = EngineShell()
    driver = ProductionServiceDriver(coordinator)
    driver._started = True
    driver._closing = False
    driver._entries_blocked = True
    driver._recovery_complete = False
    driver._recovery_blockers = ("synthetic",)
    driver._cleanup_unresolved = False

    assembly = _assembly_shell()
    assembly._driver = driver
    result = await assembly.reconcile_closed_account(
        trade_id="trade-1",
        source_id="terminal-source",
        raw_venue_evidence={"synthetic": True},
    )

    assert result["reservation_released"] is True
    assert observed["reconciler"] is assembly.reconciler
    assert observed["accounting"] is assembly.accounting
    assert observed["trade_id"] == "trade-1"


@pytest.mark.asyncio
async def test_closed_reconciliation_refuses_when_accounting_did_not_accept():
    class EngineShell:
        async def reconcile_closed_account(self, **kwargs):
            assert kwargs["accounting"] is assembly.accounting
            return {"reservation_released": False, "accounting_receipt": None}

    coordinator = object.__new__(ProductionLiveLifecycleCoordinator)
    coordinator.engine = EngineShell()
    driver = ProductionServiceDriver(coordinator)
    driver._started = True
    driver._closing = False
    driver._entries_blocked = True
    driver._recovery_complete = False
    driver._recovery_blockers = ("synthetic",)
    driver._cleanup_unresolved = False

    assembly = _assembly_shell()
    assembly._driver = driver
    with pytest.raises(ProductionAssemblyError, match="not accepted"):
        await assembly.reconcile_closed_account(
            trade_id="trade-1",
            source_id="terminal-source",
            raw_venue_evidence={"synthetic": True},
        )


@pytest.mark.asyncio
async def test_run_waits_for_stop_without_restarting_already_started_driver(monkeypatch):
    assembly = _assembly_shell()
    driver = _started_driver_shell()
    start = AsyncMock(side_effect=AssertionError("driver must not be started twice"))
    monkeypatch.setattr(driver, "start", start)
    assembly._driver = driver
    stop = asyncio.Event()
    stop.set()

    await assembly.run(stop=stop)

    start.assert_not_awaited()
    assert driver.status.started is False


@pytest.mark.asyncio
async def test_run_closes_driver_when_wait_is_cancelled():
    assembly = _assembly_shell()
    driver = _started_driver_shell()
    assembly._driver = driver
    stop = asyncio.Event()
    run = asyncio.create_task(assembly.run(stop=stop))
    await asyncio.sleep(0)

    run.cancel()
    with pytest.raises(asyncio.CancelledError):
        await run

    assert driver.status.started is False


@pytest.mark.asyncio
async def test_run_closes_driver_before_rejecting_invalid_stop_signal():
    assembly = _assembly_shell()
    driver = _started_driver_shell()
    assembly._driver = driver

    with pytest.raises(TypeError, match="asyncio.Event"):
        await assembly.run(stop=object())

    assert driver.status.started is False
