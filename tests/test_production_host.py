"""Offline supervisory host tests; every envelope and status here is synthetic."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock

import pytest
from kairos_core.enums import SystemMode
from kairos_persistence import TradeState

from kairos_execution.production_assembly import ProductionAssembly
from kairos_execution.production_host import PendingTerminalEvidence, ProductionHost, ProductionHostError
from kairos_execution.production_path import ProductionLiveEntryResult, ProductionLiveLifecycleCoordinator
from kairos_execution.production_readiness import canonical_digest
from kairos_execution.production_service import ProductionEntryEnvelope, ProductionServiceDriver
from tests.test_production_service import SyntheticCoordinator
from tests.test_technical_canary_service import setup_session


def _assembly() -> ProductionAssembly:
    class TradeRepositoryShell:
        def __init__(self):
            self.record = SimpleNamespace(trade_id="owned-trade-1", state=TradeState.ACTIVE)

        async def get(self, trade_id):
            return self.record if trade_id == self.record.trade_id else None

    shell = cast(Any, object())
    trade_repository = TradeRepositoryShell()
    engine = SimpleNamespace(trades=trade_repository, clock=lambda: datetime.now(UTC))
    return ProductionAssembly(
        runtime=shell,
        reads=shell,
        entry_risk=shell,
        exit_risk=shell,
        cancellation_verifier=shell,
        lifecycle_adapter=shell,
        engine=engine,
        coordinator=SimpleNamespace(engine=engine),
        reconciler=SimpleNamespace(source_verifiers={"terminal-source": object()}),
        accounting=shell,
        canary_verifier=shell,
    )


def _driver(*, recovered: bool = True) -> ProductionServiceDriver:
    coordinator = object.__new__(ProductionLiveLifecycleCoordinator)
    coordinator.engine = SimpleNamespace(clock=lambda: datetime.now(UTC))
    driver = ProductionServiceDriver(coordinator)
    driver._started = True
    driver._recovery_complete = recovered
    driver._recovery_blockers = () if recovered else ("AUTHORITATIVE_RECOVERY_BLOCKED",)
    driver._entries_blocked = not recovered
    driver.check_health = lambda: replace(
        driver.status,
        entry_worker_running=True,
        lifecycle_worker_running=True,
    )
    return driver


def _host(assembly, *, entry_provider, terminal_evidence_provider, **options):
    return ProductionHost(
        assembly,
        entry_provider=entry_provider,
        terminal_evidence_provider=terminal_evidence_provider,
        terminal_source_id="terminal-source",
        **options,
    )


def _envelope(owner_arm: object) -> ProductionEntryEnvelope:
    return ProductionEntryEnvelope(
        envelope_id="native-envelope-1",
        raw_account_evidence=object(),
        raw_inputs_evidence=object(),
        source_id="qualified-original-source",
        review=object(),
        venue=object(),
        allocation=None,
        owner_arm=owner_arm,
        expires_at=datetime.now(UTC) + timedelta(seconds=20),
        system_mode=SystemMode.NORMAL,
    )


def _accepted_result(trade_id: str) -> ProductionLiveEntryResult:
    result = object.__new__(ProductionLiveEntryResult)
    object.__setattr__(
        result,
        "risk_stage",
        SimpleNamespace(lifecycle_binding=SimpleNamespace(trade_id=trade_id)),
    )
    object.__setattr__(result, "execution_result", object())
    return result


def _patch_start(monkeypatch, driver: ProductionServiceDriver) -> None:
    async def start(self, **_kwargs):
        self._driver = driver
        return driver

    monkeypatch.setattr(ProductionAssembly, "start_technical_canary", start)


@pytest.mark.asyncio
async def test_start_is_one_shot_and_failed_start_is_never_retried(monkeypatch):
    kwargs, _, _ = setup_session(monkeypatch)
    assembly = _assembly()
    host = _host(assembly, entry_provider=AsyncMock(), terminal_evidence_provider=AsyncMock())
    start = AsyncMock(side_effect=RuntimeError("synthetic unresolved start"))
    monkeypatch.setattr(ProductionAssembly, "start_technical_canary", start)

    with pytest.raises(ProductionHostError, match="start was refused or is unresolved"):
        await host.start(references=kwargs["references"], owner_arm=kwargs["owner_arm"])
    with pytest.raises(ProductionHostError, match="already attempted"):
        await host.start(references=kwargs["references"], owner_arm=kwargs["owner_arm"])

    assert start.await_count == 1
    assert host.status.start_attempted and host.status.readiness is False


@pytest.mark.asyncio
async def test_recovery_blocked_status_refuses_without_calling_original_entry_provider(monkeypatch):
    kwargs, _, _ = setup_session(monkeypatch)
    assembly = _assembly()
    driver = _driver(recovered=False)
    _patch_start(monkeypatch, driver)
    provider = AsyncMock(side_effect=AssertionError("producer must not be called while recovery is blocked"))
    host = _host(assembly, entry_provider=provider, terminal_evidence_provider=AsyncMock())
    await host.start(references=kwargs["references"], owner_arm=kwargs["owner_arm"])

    with pytest.raises(ProductionHostError, match="recovery/status"):
        await host.submit_one()

    provider.assert_not_awaited()
    assert host.status.started and not host.status.recovery_complete and host.status.entries_blocked


@pytest.mark.asyncio
async def test_one_original_envelope_is_bound_to_exact_arm_and_second_admission_is_refused(monkeypatch):
    kwargs, _, _ = setup_session(monkeypatch)
    assembly = _assembly()
    driver = _driver()
    submit = AsyncMock(return_value=_accepted_result("owned-trade-1"))
    _patch_start(monkeypatch, driver)
    monkeypatch.setattr(ProductionAssembly, "submit_entry", submit)
    item = _envelope(kwargs["owner_arm"])
    provider = AsyncMock(return_value=item)
    host = _host(assembly, entry_provider=provider, terminal_evidence_provider=AsyncMock())
    await host.start(references=kwargs["references"], owner_arm=kwargs["owner_arm"])

    result = await host.submit_one()
    assert result is submit.return_value
    assert submit.await_args.args == (item,)
    assert canonical_digest(submit.await_args.args[0].owner_arm) == canonical_digest(kwargs["owner_arm"])
    with pytest.raises(ProductionHostError, match="already attempted"):
        await host.submit_one()
    assert provider.await_count == 1
    assert host.status.admission_attempted
    assert host.status.owned_trade_id == "owned-trade-1"


@pytest.mark.asyncio
async def test_envelope_with_different_owner_arm_is_not_submitted(monkeypatch):
    kwargs, _, _ = setup_session(monkeypatch)
    assembly = _assembly()
    driver = _driver()
    submit = AsyncMock()
    _patch_start(monkeypatch, driver)
    monkeypatch.setattr(ProductionAssembly, "submit_entry", submit)
    original_arm = kwargs["owner_arm"]
    other = original_arm.model_copy(
        update={"request": original_arm.request.model_copy(update={"nonce": "different-synthetic-arm"})}
    )
    host = _host(
        assembly,
        entry_provider=AsyncMock(return_value=_envelope(other)),
        terminal_evidence_provider=AsyncMock(),
    )
    await host.start(references=kwargs["references"], owner_arm=kwargs["owner_arm"])

    with pytest.raises(ProductionHostError, match="one-entry attempt was refused or is unresolved"):
        await host.submit_one()
    submit.assert_not_awaited()
    assert host.status.entries_blocked


@pytest.mark.asyncio
async def test_terminal_evidence_unknown_outcome_is_latched_and_not_retried(monkeypatch):
    kwargs, _, _ = setup_session(monkeypatch)
    assembly = _assembly()
    driver = _driver()
    reconcile = AsyncMock(side_effect=RuntimeError("synthetic unknown accounting outcome"))
    _patch_start(monkeypatch, driver)
    monkeypatch.setattr(ProductionAssembly, "reconcile_closed_account", reconcile)
    evidence = AsyncMock(return_value={"synthetic": "only"})
    submit = AsyncMock(return_value=_accepted_result("owned-trade-1"))
    monkeypatch.setattr(ProductionAssembly, "submit_entry", submit)
    host = _host(
        assembly,
        entry_provider=AsyncMock(return_value=_envelope(kwargs["owner_arm"])),
        terminal_evidence_provider=evidence,
    )
    await host.start(references=kwargs["references"], owner_arm=kwargs["owner_arm"])
    assert not await host.reconcile_closed_account()
    assert evidence.await_count == 0
    await host.submit_one()
    assembly.engine.trades.record.state = TradeState.FLAT

    with pytest.raises(ProductionHostError, match="refused or unresolved"):
        await host.reconcile_closed_account()
    assert not await host.reconcile_closed_account()
    assert evidence.await_count == 1
    assert evidence.await_args.args == ("owned-trade-1", "terminal-source")
    assert reconcile.await_count == 1
    assert not host.status.terminal_accounting_accepted


@pytest.mark.asyncio
async def test_terminal_reconciliation_requires_owned_trade_and_reports_only_accepted_accounting(monkeypatch):
    kwargs, _, _ = setup_session(monkeypatch)
    assembly = _assembly()
    driver = _driver()
    _patch_start(monkeypatch, driver)
    evidence = AsyncMock(return_value={"original": "synthetic-test-evidence"})
    reconcile = AsyncMock(
        return_value={"reservation_released": True, "accounting_receipt": {"receipt_id": "test"}}
    )
    monkeypatch.setattr(
        ProductionAssembly, "submit_entry", AsyncMock(return_value=_accepted_result("owned-trade-7"))
    )
    monkeypatch.setattr(ProductionAssembly, "reconcile_closed_account", reconcile)
    host = _host(
        assembly,
        entry_provider=AsyncMock(return_value=_envelope(kwargs["owner_arm"])),
        terminal_evidence_provider=evidence,
    )
    await host.start(references=kwargs["references"], owner_arm=kwargs["owner_arm"])

    assert not await host.reconcile_closed_account()
    assert evidence.await_count == 0
    await host.submit_one()
    assembly.engine.trades.record.trade_id = "owned-trade-7"
    assembly.engine.trades.record.state = TradeState.FLAT
    result = await host.reconcile_closed_account()

    assert result is True
    assert host.status.owned_trade_id == "owned-trade-7"
    assert host.status.terminal_accounting_accepted
    assert reconcile.await_args.kwargs["trade_id"] == "owned-trade-7"


@pytest.mark.asyncio
async def test_typed_pending_terminal_evidence_does_not_consume_final_accounting_attempt(monkeypatch):
    kwargs, _, _ = setup_session(monkeypatch)
    assembly = _assembly()
    driver = _driver()
    _patch_start(monkeypatch, driver)
    reconcile = AsyncMock(
        return_value={"reservation_released": True, "accounting_receipt": {"receipt_id": "test"}}
    )
    monkeypatch.setattr(
        ProductionAssembly, "submit_entry", AsyncMock(return_value=_accepted_result("owned-trade-1"))
    )
    monkeypatch.setattr(ProductionAssembly, "reconcile_closed_account", reconcile)
    pending = PendingTerminalEvidence(
        trade_id="owned-trade-1",
        source_id="terminal-source",
        observed_at=datetime.now(UTC),
    )
    evidence = AsyncMock(side_effect=[pending, {"final": "synthetic-test-evidence"}])
    host = _host(
        assembly,
        entry_provider=AsyncMock(return_value=_envelope(kwargs["owner_arm"])),
        terminal_evidence_provider=evidence,
    )
    await host.start(references=kwargs["references"], owner_arm=kwargs["owner_arm"])
    await host.submit_one()
    assembly.engine.trades.record.state = TradeState.FLAT

    assert not await host.reconcile_owned_if_closed()
    assert evidence.await_count == 1
    assert reconcile.await_count == 0
    assert not host.status.terminal_accounting_accepted
    host._terminal_next_poll = asyncio.get_running_loop().time() - 1

    assert await host.reconcile_owned_if_closed()
    assert evidence.await_count == 2
    assert reconcile.await_count == 1
    assert host.status.terminal_accounting_accepted


@pytest.mark.asyncio
async def test_run_auto_reconciles_only_after_owned_trade_is_naturally_flat(monkeypatch):
    kwargs, _, _ = setup_session(monkeypatch)
    assembly = _assembly()
    driver = ProductionServiceDriver(
        SyntheticCoordinator(), entry_admission=lambda: True, reconciliation_interval_s=60
    )
    await driver.start()
    _patch_start(monkeypatch, driver)
    closed_accounting = AsyncMock(
        return_value={"reservation_released": True, "accounting_receipt": {"receipt_id": "test"}}
    )
    monkeypatch.setattr(
        ProductionAssembly, "submit_entry", AsyncMock(return_value=_accepted_result("owned-trade-1"))
    )
    monkeypatch.setattr(ProductionAssembly, "reconcile_closed_account", closed_accounting)
    evidence_read = asyncio.Event()

    async def final_evidence(trade_id, source_id):
        assert (trade_id, source_id) == ("owned-trade-1", "terminal-source")
        evidence_read.set()
        return {"final": "synthetic-test-evidence"}

    host = _host(
        assembly,
        entry_provider=AsyncMock(return_value=_envelope(kwargs["owner_arm"])),
        terminal_evidence_provider=final_evidence,
    )
    await host.start(references=kwargs["references"], owner_arm=kwargs["owner_arm"])
    await host.submit_one()
    assert not await host.reconcile_owned_if_closed()
    assert not evidence_read.is_set()

    assembly.engine.trades.record.state = TradeState.FLAT
    host._terminal_next_poll = asyncio.get_running_loop().time() - 1
    stop = asyncio.Event()
    run_task = asyncio.create_task(host.run(stop=stop))
    await asyncio.wait_for(evidence_read.wait(), timeout=1)
    assert host.status.terminal_accounting_accepted
    assert closed_accounting.await_count == 1
    stop.set()
    await run_task


@pytest.mark.asyncio
async def test_run_uses_real_driver_health_and_closes_once_on_operator_stop(monkeypatch):
    kwargs, _, _ = setup_session(monkeypatch)
    assembly = _assembly()
    driver = ProductionServiceDriver(SyntheticCoordinator(), reconciliation_interval_s=60)
    await driver.start()
    _patch_start(monkeypatch, driver)
    host = _host(assembly, entry_provider=AsyncMock(), terminal_evidence_provider=AsyncMock())
    await host.start(references=kwargs["references"], owner_arm=kwargs["owner_arm"])
    stop = asyncio.Event()
    stop.set()

    await host.run(stop=stop)

    assert not driver.status.started
    assert not host.status.started
    assert driver.status.readiness is False


@pytest.mark.asyncio
async def test_run_latches_and_closes_when_real_driver_worker_disappears(monkeypatch):
    kwargs, _, _ = setup_session(monkeypatch)
    assembly = _assembly()
    driver = ProductionServiceDriver(SyntheticCoordinator(), reconciliation_interval_s=60)
    await driver.start()
    driver._worker_task.cancel()
    await asyncio.gather(driver._worker_task, return_exceptions=True)
    _patch_start(monkeypatch, driver)
    host = _host(assembly, entry_provider=AsyncMock(), terminal_evidence_provider=AsyncMock())
    await host.start(references=kwargs["references"], owner_arm=kwargs["owner_arm"])

    stop = asyncio.Event()
    running = asyncio.create_task(host.run(stop=stop))
    await asyncio.sleep(0)

    assert driver.status.entries_blocked
    assert driver.status.started and driver.status.lifecycle_worker_running
    assert host.status.supervisor_failure == "DRIVER_TASKS_MISSING"
    assert not running.done()
    stop.set()
    await running
    assert not driver.status.started
