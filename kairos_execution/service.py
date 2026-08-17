"""Execution service: consume ValidatedOrder + SYSTEM_CONTROL from the bus."""

from __future__ import annotations

import asyncio
from datetime import UTC, date, datetime

from kairos_core.bus import build_bus
from kairos_core.contracts import AccountSnapshot, ValidatedOrder
from kairos_core.enums import SystemMode
from kairos_core.logging import configure_logging, get_logger
from kairos_core.topics import Topics
from kairos_persistence import DurableMessageBus

from .config import ExecSettings
from .engine import ExecutionEngine, ExecutionSafetyError
from .factory import build_adapter

log = get_logger("execution")


class ExecutionService:
    def __init__(self, settings: ExecSettings | None = None) -> None:
        self.settings = settings or ExecSettings()
        transport = build_bus(self.settings)
        self.bus = (
            transport
            if self.settings.bus_backend == "memory"
            else DurableMessageBus(transport, service_name=self.settings.service_name)
        )
        self.engine = ExecutionEngine(
            build_adapter(self.settings),
            default_trail_pct=self.settings.default_trail_pct,
            allowed_symbols=set(self.settings.trading_symbols),
            idempotency_cache_size=self.settings.idempotency_cache_size,
        )
        self._account_refresh: asyncio.Queue[None] = asyncio.Queue(maxsize=1)
        self._peak_equity_usd = self.settings.dry_run_equity_usd if self.settings.dry_run else 0.0
        self._session_day: date | None = None
        self._day_start_equity_usd: float | None = None

    async def _consume_control(self) -> None:
        async for env in self.bus.subscribe(Topics.SYSTEM_CONTROL, group="execution", consumer="ctrl"):
            try:
                raw_mode = env.payload.get("mode")
                try:
                    mode = SystemMode(str(raw_mode))
                except ValueError:
                    log.warning("execution.invalid_system_mode", mode=raw_mode)
                else:
                    self.engine.set_mode(mode)
                await self.bus.ack(Topics.SYSTEM_CONTROL, env, group="execution")
            except Exception:
                log.exception("execution.control_processing_failed", envelope_id=env.id)

    async def _consume_orders(self) -> None:
        async for env in self.bus.subscribe(Topics.VALIDATED_ORDER, group="execution", consumer="orders"):
            try:
                order = ValidatedOrder.model_validate(env.payload)
                report = await self.engine.handle(order)
                if report is not None:
                    await self.bus.publish(Topics.EXECUTION_REPORT, report)
                    self._request_account_refresh()
                await self.bus.ack(Topics.VALIDATED_ORDER, env, group="execution")
            except ExecutionSafetyError:
                # The source entry remains pending, while reconciliation is
                # accelerated so Risk does not rely on a stale pre-failure view.
                self._request_account_refresh()
                log.exception("execution.order_safety_failure", envelope_id=env.id)
            except Exception:
                # Adapter and transport exceptions may have happened after a
                # venue mutation.  Even when the engine could not classify the
                # failure, immediately revoke the age of the last account view.
                self._request_account_refresh()
                log.exception("execution.order_processing_failed", envelope_id=env.id)

    def _request_account_refresh(self) -> None:
        if self._account_refresh.empty():
            self._account_refresh.put_nowait(None)

    def _apply_session_accounting(self, snapshot: AccountSnapshot) -> AccountSnapshot:
        if not snapshot.reconciled:
            return snapshot
        snapshot_day = snapshot.captured_at.astimezone(UTC).date()
        if self._session_day != snapshot_day or self._day_start_equity_usd is None:
            self._session_day = snapshot_day
            self._day_start_equity_usd = snapshot.equity_usd
        self._peak_equity_usd = max(self._peak_equity_usd, snapshot.equity_usd)
        daily_pnl_pct = (
            (snapshot.equity_usd - self._day_start_equity_usd) / self._day_start_equity_usd * 100.0
        )
        return snapshot.model_copy(
            update={
                "peak_equity_usd": self._peak_equity_usd,
                "daily_pnl_pct": daily_pnl_pct,
            }
        )

    async def _publish_account_snapshot(self) -> None:
        try:
            snapshot = await self.engine.adapter.fetch_account_snapshot(
                account_id=self.settings.account_id,
                peak_equity_usd=self._peak_equity_usd,
            )
            snapshot = self._apply_session_accounting(snapshot)
        except Exception as exc:
            log.exception("execution.account_reconciliation_failed")
            snapshot = AccountSnapshot(
                source=self.settings.service_name,
                exchange=self.settings.exchange,
                account_id=self.settings.account_id,
                equity_usd=max(1.0, self._peak_equity_usd),
                available_balance_usd=0.0,
                peak_equity_usd=max(1.0, self._peak_equity_usd),
                captured_at=datetime.now(UTC),
                reconciled=False,
                reconciliation_detail=f"{type(exc).__name__}: {exc}",
            )
        await self.bus.publish(Topics.ACCOUNT_SNAPSHOT, snapshot)
        log.info(
            "execution.account_snapshot",
            reconciled=snapshot.reconciled,
            positions=len(snapshot.positions),
            open_orders=len(snapshot.open_order_ids),
        )

    async def _produce_account_snapshots(self) -> None:
        while True:
            await self._publish_account_snapshot()
            try:
                await asyncio.wait_for(
                    self._account_refresh.get(),
                    timeout=self.settings.account_snapshot_interval_s,
                )
            except TimeoutError:
                pass

    async def close(self) -> None:
        """Release both resources even if the first close operation fails."""
        try:
            await self.engine.adapter.close()
        finally:
            await self.bus.close()

    async def run(self) -> None:  # pragma: no cover - network
        try:
            configure_logging(
                self.settings.log_level, json_logs=self.settings.log_json, service=self.settings.service_name
            )
            log.info("execution.start", exchange=self.settings.exchange, dry_run=self.settings.dry_run)
            async with asyncio.TaskGroup() as tasks:
                tasks.create_task(self._consume_orders(), name="validated-orders")
                tasks.create_task(self._consume_control(), name="system-control")
                tasks.create_task(self._produce_account_snapshots(), name="account-snapshots")
        finally:
            await self.close()


def main() -> None:  # pragma: no cover
    asyncio.run(ExecutionService().run())


if __name__ == "__main__":
    main()
