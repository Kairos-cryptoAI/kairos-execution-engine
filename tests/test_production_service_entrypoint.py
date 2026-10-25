"""Explicit factory/runner wiring; the coordinator below is synthetic only."""

import asyncio
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from kairos_core.enums import TradingMode
from pydantic import ValidationError

from kairos_execution.config import ExecSettings
from kairos_execution.factory import build_adapter, build_production_service
from kairos_execution.production_path import ProductionLiveLifecycleCoordinator
from kairos_execution.service import run_production_service


class SyntheticIdleCoordinator(ProductionLiveLifecycleCoordinator):
    def __init__(self):
        self.recoveries = 0
        self.engine = SimpleNamespace(clock=lambda: datetime.now(UTC), recovery_blocked=False)

    async def initialize_recovery(self):
        self.recoveries += 1
        return ()

    async def reconcile_once(self):
        return []


def test_explicit_factory_constructs_only_an_idle_reject_all_driver():
    coordinator = SyntheticIdleCoordinator()
    driver = build_production_service(coordinator=coordinator)
    assert driver.coordinator is coordinator
    assert not driver.status.started
    assert not driver.status.readiness
    assert driver.status.entries_blocked
    assert driver.status.entry_policy == "REJECT_ALL"
    assert coordinator.recoveries == 0


def test_explicit_factory_rejects_an_uncomposed_object():
    with pytest.raises(TypeError, match="coordinator"):
        build_production_service(coordinator=object())


def test_explicit_factory_does_not_change_default_live_refusal():
    with pytest.raises(ValidationError, match="LIVE is disabled"):
        ExecSettings(trading_mode=TradingMode.LIVE)
    settings = ExecSettings().model_copy(update={"trading_mode": TradingMode.LIVE})
    with pytest.raises(ValueError, match="LIVE is disabled"):
        build_adapter(settings)


@pytest.mark.asyncio
async def test_explicit_runner_recovers_then_closes_when_stop_is_already_set():
    coordinator = SyntheticIdleCoordinator()
    driver = build_production_service(coordinator=coordinator)
    stop = asyncio.Event()
    stop.set()
    await run_production_service(driver, stop=stop)
    assert coordinator.recoveries == 1
    assert not driver.status.started
    assert driver.status.entries_blocked
    assert not driver.status.readiness


@pytest.mark.asyncio
async def test_runner_rejects_foreign_driver_and_stop_objects():
    with pytest.raises(TypeError, match="explicitly composed"):
        await run_production_service(object(), stop=asyncio.Event())
    driver = build_production_service(coordinator=SyntheticIdleCoordinator())
    with pytest.raises(TypeError, match="stop event"):
        await run_production_service(driver, stop=object())
    assert not driver.status.started
