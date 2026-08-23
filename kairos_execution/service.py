"""Execution service with isolated legacy DRY_RUN and strict PAPER routes."""

from __future__ import annotations

import asyncio
from datetime import UTC, date, datetime

from kairos_core.bus import build_bus
from kairos_core.contracts import AccountSnapshot, RiskTradeDecisionV1, ValidatedOrder
from kairos_core.enums import SystemMode, TradingMode
from kairos_core.logging import configure_logging, get_logger
from kairos_core.topics import Topics
from kairos_persistence import (
    DurableMessageBus,
    ExecutionJournalRepository,
    TradeLifecycleRepository,
)

from .config import ExecSettings
from .engine import ExecutionEngine, ExecutionSafetyError
from .factory import build_adapter
from .journaled_adapter import JournaledExchangeAdapter
from .paper_engine import (
    PaperExecutionEngine,
    PaperExecutionSafetyError,
)

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
        adapter = build_adapter(self.settings)
        self.engine: ExecutionEngine | None = None
        self.paper_engine: PaperExecutionEngine | None = None
        self._paper_adapter = None
        if self.settings.trading_mode is TradingMode.PAPER:
            from .adapters.evedex_sidecar import EvedexSidecarAdapter

            if not isinstance(adapter, EvedexSidecarAdapter):
                raise RuntimeError("PAPER startup did not build the official EVEDEX sidecar adapter")
            self._paper_adapter = adapter
        else:
            self.engine = ExecutionEngine(
                adapter,
                default_trail_pct=self.settings.default_trail_pct,
                allowed_symbols=set(self.settings.trading_symbols),
                idempotency_cache_size=self.settings.idempotency_cache_size,
            )
        self._account_refresh: asyncio.Queue[None] = asyncio.Queue(maxsize=1)
        self._peak_equity_usd = (
            self.settings.dry_run_equity_usd if self.settings.trading_mode is TradingMode.DRY_RUN else 0.0
        )
        self._session_day: date | None = None
        self._day_start_equity_usd: float | None = None
        self._journaled_adapter: JournaledExchangeAdapter | None = None

    async def _consume_control(self) -> None:
        async for env in self.bus.subscribe(Topics.SYSTEM_CONTROL, group="execution", consumer="ctrl"):
            try:
                raw_mode = env.payload.get("mode")
                try:
                    mode = SystemMode(str(raw_mode))
                except ValueError:
                    log.warning("execution.invalid_system_mode", mode=raw_mode)
                else:
                    self._legacy_engine().set_mode(mode)
                await self.bus.ack(Topics.SYSTEM_CONTROL, env, group="execution")
            except Exception:
                log.exception("execution.control_processing_failed", envelope_id=env.id)

    async def _consume_orders(self) -> None:
        if self._is_paper:
            raise RuntimeError("PAPER must never subscribe to the legacy ValidatedOrder route")
        async for env in self.bus.subscribe(Topics.VALIDATED_ORDER, group="execution", consumer="orders"):
            try:
                order = ValidatedOrder.model_validate(env.payload)
                report = await self._legacy_engine().handle(order)
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

    async def _consume_paper_decisions(self) -> None:
        if not self._is_paper:
            raise RuntimeError("the strict RiskTradeDecision route is PAPER-only")
        async for env in self.bus.subscribe(
            Topics.RISK_TRADE_DECISION,
            group="execution-paper",
            consumer="risk-decisions",
        ):
            try:
                decision = RiskTradeDecisionV1.model_validate(env.payload)
                result = await self._required_paper_engine().handle(decision)
                for event in result.events:
                    await self.bus.publish(Topics.TRADE_EXECUTION_EVENT, event)
                self._request_account_refresh()
                await self.bus.ack(Topics.RISK_TRADE_DECISION, env, group="execution-paper")
            except PaperExecutionSafetyError as exc:
                await self._required_paper_engine().block_entries(str(exc))
                self._request_account_refresh()
                log.exception("execution.paper_safety_failure", envelope_id=env.id)
            except Exception as exc:
                await self._required_paper_engine().block_entries(
                    f"unclassified PAPER processing error: {type(exc).__name__}"
                )
                self._request_account_refresh()
                log.exception("execution.paper_processing_failed", envelope_id=env.id)

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
        if self._is_paper:
            try:
                snapshot_v2 = await self._required_paper_engine().account_snapshot()
            except Exception as exc:
                # Never substitute a synthetic PAPER balance. Risk's freshness
                # gate will expire the previous snapshot and fail closed.
                await self._required_paper_engine().block_entries(
                    f"account reconciliation failed: {type(exc).__name__}"
                )
                log.exception("execution.paper_account_reconciliation_failed")
                return
            await self.bus.publish(Topics.ACCOUNT_SNAPSHOT_V2, snapshot_v2)
            log.info(
                "execution.paper_account_snapshot",
                reconciled=snapshot_v2.reconciled,
                positions=len(snapshot_v2.positions),
                open_orders=len(snapshot_v2.open_orders),
            )
            return
        try:
            engine = self._legacy_engine()
            snapshot = await engine.adapter.fetch_account_snapshot(
                account_id=self.settings.account_id,
                peak_equity_usd=self._peak_equity_usd,
            )
            snapshot = self._apply_session_accounting(snapshot)
            if getattr(engine, "recovery_blocked", False):
                snapshot = snapshot.model_copy(
                    update={
                        "reconciled": False,
                        "reconciliation_detail": (
                            "account snapshot read succeeded, but execution journal recovery is incomplete"
                        ),
                    }
                )
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

    async def _initialize_execution_journal(self) -> None:
        if self._is_paper:
            raise RuntimeError("PAPER uses the dedicated trade lifecycle journal")
        if not isinstance(self.bus, DurableMessageBus):
            return
        await self.bus.start()
        journal = ExecutionJournalRepository(self.bus.database.pool)
        engine = self._legacy_engine()
        wrapped = JournaledExchangeAdapter(engine.adapter, journal)
        engine.adapter = wrapped
        self._journaled_adapter = wrapped
        blockers = await wrapped.recover_pending()
        engine.set_recovery_blockers(blockers)

    async def _initialize_paper_execution(self) -> None:
        if not isinstance(self.bus, DurableMessageBus):
            raise RuntimeError("PAPER requires the durable PostgreSQL bus")
        if self._paper_adapter is None:
            raise RuntimeError("PAPER adapter is unavailable")
        await self.bus.start()
        pool = self.bus.database.pool
        self.paper_engine = PaperExecutionEngine(
            self._paper_adapter,
            TradeLifecycleRepository(pool),
            ExecutionJournalRepository(pool),
            self.settings,
        )
        blockers = await self.paper_engine.initialize_recovery()
        self._log_paper_telemetry()
        if blockers:
            log.error("execution.paper_recovery_blocked", blockers=blockers)
        else:
            log.info("execution.paper_recovery_complete")

    async def _recover_execution_journal(self) -> None:
        journaled_adapter = getattr(self, "_journaled_adapter", None)
        if journaled_adapter is None:
            return
        while True:
            await asyncio.sleep(getattr(self.settings, "journal_recovery_interval_s", 15.0))
            try:
                blockers = await journaled_adapter.recover_pending()
            except Exception as exc:
                blockers = [f"journal recovery scan failed: {type(exc).__name__}: {exc}"]
                log.exception("execution.journal_recovery_failed")
            self._legacy_engine().set_recovery_blockers(blockers)
            if blockers:
                self._request_account_refresh()

    async def _reconcile_paper_lifecycle(self) -> None:
        while True:
            await asyncio.sleep(self.settings.journal_recovery_interval_s)
            try:
                engine = self._required_paper_engine()
                if engine.recovery_blocked:
                    await engine.initialize_recovery()
                events = await engine.reconcile_once()
                self._log_paper_telemetry()
                for event in events:
                    await self.bus.publish(Topics.TRADE_EXECUTION_EVENT, event)
            except Exception as exc:
                await self._required_paper_engine().block_entries(
                    f"lifecycle reconciliation failed: {type(exc).__name__}"
                )
                self._request_account_refresh()
                log.exception("execution.paper_lifecycle_reconciliation_failed")
            else:
                if events:
                    self._request_account_refresh()

    async def close(self) -> None:
        """Release both resources even if the first close operation fails."""
        try:
            if self._is_paper:
                if self._paper_adapter is not None:
                    await self._paper_adapter.close()
            else:
                await self._legacy_engine().adapter.close()
        finally:
            await self.bus.close()

    async def run(self) -> None:  # pragma: no cover - network
        try:
            configure_logging(
                self.settings.log_level, json_logs=self.settings.log_json, service=self.settings.service_name
            )
            log.info(
                "execution.start",
                exchange=self.settings.exchange,
                trading_mode=self._trading_mode.value,
            )
            if self._is_paper:
                await self._initialize_paper_execution()
                async with asyncio.TaskGroup() as tasks:
                    tasks.create_task(self._consume_paper_decisions(), name="paper-risk-decisions")
                    tasks.create_task(self._produce_account_snapshots(), name="paper-account-snapshots")
                    tasks.create_task(
                        self._reconcile_paper_lifecycle(), name="paper-lifecycle-reconciliation"
                    )
            else:
                await self._initialize_execution_journal()
                async with asyncio.TaskGroup() as tasks:
                    tasks.create_task(self._consume_orders(), name="validated-orders")
                    tasks.create_task(self._consume_control(), name="system-control")
                    tasks.create_task(self._produce_account_snapshots(), name="account-snapshots")
                    tasks.create_task(self._recover_execution_journal(), name="execution-journal-recovery")
        finally:
            await self.close()

    @property
    def _is_paper(self) -> bool:
        return self._trading_mode is TradingMode.PAPER

    @property
    def _trading_mode(self) -> TradingMode:
        return getattr(self.settings, "trading_mode", TradingMode.DRY_RUN)

    def _legacy_engine(self) -> ExecutionEngine:
        engine = self.engine
        if engine is None:
            raise RuntimeError("legacy execution engine is unavailable in PAPER")
        return engine

    def _required_paper_engine(self) -> PaperExecutionEngine:
        if self.paper_engine is None:
            raise RuntimeError("PAPER execution engine has not completed startup recovery")
        return self.paper_engine

    def _log_paper_telemetry(self) -> None:
        telemetry = dict(self._required_paper_engine().operational_telemetry)
        if telemetry:
            log.info("execution.paper_operational_telemetry", **telemetry)


def main() -> None:  # pragma: no cover
    asyncio.run(ExecutionService().run())


if __name__ == "__main__":
    main()
