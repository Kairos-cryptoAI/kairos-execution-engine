"""Execution service: consume ValidatedOrder + SYSTEM_CONTROL from the bus."""
from __future__ import annotations

import asyncio

from kairos_core.bus import build_bus
from kairos_core.contracts import ValidatedOrder
from kairos_core.enums import SystemMode
from kairos_core.logging import configure_logging, get_logger
from kairos_core.topics import Topics

from .config import ExecSettings
from .engine import ExecutionEngine
from .factory import build_adapter

log = get_logger("execution")


class ExecutionService:
    def __init__(self, settings: ExecSettings | None = None) -> None:
        self.settings = settings or ExecSettings()
        self.bus = build_bus(self.settings)
        self.engine = ExecutionEngine(build_adapter(self.settings), default_trail_pct=self.settings.default_trail_pct)

    async def _consume_control(self) -> None:
        async for env in self.bus.subscribe(Topics.SYSTEM_CONTROL, group="execution", consumer="ctrl"):
            try:
                mode = env.payload.get("mode")
                if mode in SystemMode.__members__:
                    self.engine.set_mode(SystemMode(mode))
            finally:
                await self.bus.ack(Topics.SYSTEM_CONTROL, env, group="execution")

    async def _consume_orders(self) -> None:
        async for env in self.bus.subscribe(Topics.VALIDATED_ORDER, group="execution", consumer="orders"):
            try:
                order = ValidatedOrder.model_validate(env.payload)
                report = await self.engine.handle(order)
                if report is not None:
                    await self.bus.publish(Topics.EXECUTION_REPORT, report)
            finally:
                await self.bus.ack(Topics.VALIDATED_ORDER, env, group="execution")

    async def run(self) -> None:  # pragma: no cover - network
        configure_logging(self.settings.log_level, json_logs=self.settings.log_json, service=self.settings.service_name)
        log.info("execution.start", exchange=self.settings.exchange, dry_run=self.settings.dry_run)
        await asyncio.gather(self._consume_orders(), self._consume_control())


def main() -> None:  # pragma: no cover
    asyncio.run(ExecutionService().run())


if __name__ == "__main__":
    main()
