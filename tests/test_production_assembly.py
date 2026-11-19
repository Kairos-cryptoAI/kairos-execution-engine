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
async def test_canary_start_refuses_without_the_typed_transport_before_service_start(monkeypatch):
    assembly = _assembly_shell()
    started = []

    async def must_not_start(**kwargs):
        started.append(kwargs)

    monkeypatch.setattr("kairos_execution.production_assembly.start_technical_canary_service", must_not_start)
    with pytest.raises(ProductionAssemblyError, match="typed PROD EVEDEX transport"):
        await assembly.start_technical_canary(references=(), owner_arm=object())
    with pytest.raises(ProductionAssemblyError, match="already attempted"):
        await assembly.start_technical_canary(references=(), owner_arm=object())
    assert started == []


def _assembly_with_transport(monkeypatch, preflights):
    from types import SimpleNamespace

    from kairos_execution.production_transport import ProductionEvedexTransport

    async def preflight(self):
        preflights.append(self)
        return {"exchangeId": "synthetic"}

    monkeypatch.setattr(ProductionEvedexTransport, "preflight", preflight)
    transport = object.__new__(ProductionEvedexTransport)
    assembly = _assembly_shell()
    assembly.runtime = cast(
        Any, SimpleNamespace(dispatcher=SimpleNamespace(sender=transport.send_signed_post))
    )
    return assembly, transport


@pytest.mark.asyncio
async def test_canary_start_runs_the_transport_preflight_before_the_service(monkeypatch):
    preflights, order = [], []

    async def start(**kwargs):
        order.append(len(preflights))
        raise RuntimeError("synthetic refused start")

    monkeypatch.setattr("kairos_execution.production_assembly.start_technical_canary_service", start)
    assembly, transport = _assembly_with_transport(monkeypatch, preflights)
    with pytest.raises(RuntimeError, match="synthetic refused start"):
        await assembly.start_technical_canary(references=(), owner_arm=object())
    assert preflights == [transport] and order == [1]


@pytest.mark.asyncio
async def test_canary_start_latches_before_await_and_never_retries(monkeypatch):
    assembly, _ = _assembly_with_transport(monkeypatch, [])
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
