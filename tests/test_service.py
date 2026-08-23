import asyncio
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from kairos_core.bus.base import BusEnvelope
from kairos_core.contracts import AccountSnapshot, ExecutionReport, OrderIntent, ValidatedOrder
from kairos_core.enums import (
    OrderSide,
    OrderStatus,
    OrderType,
    ReasonCode,
    SystemMode,
    TradingMode,
)
from kairos_core.topics import Topics

from kairos_execution.engine import ExecutionSafetyError
from kairos_execution.paper_engine import PaperExecutionResult
from kairos_execution.service import ExecutionService
from tests.paper_fixtures import approved_decision


class FakeAdapter:
    def __init__(
        self,
        *,
        close_error: Exception | None = None,
        snapshot: AccountSnapshot | None = None,
        snapshot_error: Exception | None = None,
    ) -> None:
        self.closed = False
        self.close_error = close_error
        self.snapshot = snapshot
        self.snapshot_error = snapshot_error

    async def close(self) -> None:
        self.closed = True
        if self.close_error is not None:
            raise self.close_error

    async def fetch_account_snapshot(self, *, account_id, peak_equity_usd):
        if self.snapshot_error is not None:
            raise self.snapshot_error
        if self.snapshot is not None:
            return self.snapshot
        return AccountSnapshot(
            source="test-execution",
            exchange="fake",
            account_id=account_id,
            equity_usd=10_000,
            available_balance_usd=10_000,
            peak_equity_usd=max(10_000, peak_equity_usd),
            reconciled=True,
        )


class FakeEngine:
    def __init__(self, events: list[str], *, error: Exception | None = None) -> None:
        self.adapter = FakeAdapter()
        self.events = events
        self.error = error

    async def handle(self, order: ValidatedOrder) -> ExecutionReport:
        self.events.append("handle")
        if self.error is not None:
            raise self.error
        return ExecutionReport(
            source="execution-engine",
            client_order_id="test-order",
            symbol=order.intent.symbol,
            side=order.intent.side,
            status=OrderStatus.NEW,
        )

    def set_mode(self, mode) -> None:
        self.events.append("control")


class FakeBus:
    def __init__(
        self,
        envelopes: dict[str, list[BusEnvelope]] | None = None,
        *,
        publish_error: Exception | None = None,
    ) -> None:
        self.envelopes = envelopes or {}
        self.publish_error = publish_error
        self.events: list[str] = []
        self.published: list[tuple[str, object]] = []
        self.closed = False

    async def subscribe(self, topic, *, group=None, consumer=None):
        for envelope in self.envelopes.get(topic, []):
            yield envelope

    async def publish(self, topic, message) -> str:
        self.events.append("publish")
        if self.publish_error is not None:
            raise self.publish_error
        self.published.append((topic, message))
        return "report-1"

    async def ack(self, topic, envelope, *, group=None) -> None:
        self.events.append("ack")

    async def close(self) -> None:
        self.closed = True


def _validated_order() -> ValidatedOrder:
    reason = ReasonCode.ENTER_LONG_TREND
    intent = OrderIntent(
        source="risk",
        symbol="BTCUSDT",
        side=OrderSide.BUY,
        order_type=OrderType.LIMIT,
        quantity=0.1,
        price=65_000,
        reason_code=reason,
    )
    return ValidatedOrder(source="risk", intent=intent, approved=True, reason_code=reason)


def _service(bus: FakeBus, engine: FakeEngine) -> ExecutionService:
    service = object.__new__(ExecutionService)
    service.settings = SimpleNamespace(
        log_level="INFO",
        log_json=False,
        service_name="test-execution",
        exchange="fake",
        dry_run=True,
        account_id="primary",
        account_snapshot_interval_s=3600,
        dry_run_equity_usd=10_000,
    )
    service.bus = bus
    service.engine = engine
    service._account_refresh = asyncio.Queue(maxsize=1)
    service._peak_equity_usd = 10_000
    service._session_day = None
    service._day_start_equity_usd = None
    return service


def _order_envelope() -> BusEnvelope:
    return BusEnvelope(
        id="validated-1",
        topic=Topics.VALIDATED_ORDER,
        payload=_validated_order().to_payload(),
    )


def _control_envelope(mode: object) -> BusEnvelope:
    return BusEnvelope(
        id="control-1",
        topic=Topics.SYSTEM_CONTROL,
        payload={"mode": mode},
    )


@pytest.mark.asyncio
async def test_order_is_acked_only_after_handle_and_publish_succeed():
    events: list[str] = []
    bus = FakeBus({Topics.VALIDATED_ORDER: [_order_envelope()]})
    bus.events = events
    service = _service(bus, FakeEngine(events))

    await service._consume_orders()

    assert events == ["handle", "publish", "ack"]
    assert service._account_refresh.qsize() == 1


@pytest.mark.asyncio
async def test_transient_handle_failure_leaves_order_pending():
    events: list[str] = []
    bus = FakeBus({Topics.VALIDATED_ORDER: [_order_envelope()]})
    bus.events = events
    service = _service(bus, FakeEngine(events, error=RuntimeError("exchange unavailable")))

    await service._consume_orders()

    assert events == ["handle"]
    assert service._account_refresh.qsize() == 1


@pytest.mark.asyncio
async def test_safety_failure_schedules_reconciliation_and_leaves_order_pending():
    events: list[str] = []
    bus = FakeBus({Topics.VALIDATED_ORDER: [_order_envelope()]})
    bus.events = events
    service = _service(
        bus,
        FakeEngine(events, error=ExecutionSafetyError("position is not flat")),
    )

    await service._consume_orders()

    assert events == ["handle"]
    assert service._account_refresh.qsize() == 1


@pytest.mark.asyncio
async def test_publish_failure_leaves_order_pending():
    events: list[str] = []
    bus = FakeBus(
        {Topics.VALIDATED_ORDER: [_order_envelope()]},
        publish_error=RuntimeError("redis unavailable"),
    )
    bus.events = events
    service = _service(bus, FakeEngine(events))

    await service._consume_orders()

    assert events == ["handle", "publish"]
    assert service._account_refresh.qsize() == 1


@pytest.mark.asyncio
async def test_paper_consumes_only_strict_risk_decisions_and_acks_after_handle():
    decision = approved_decision()
    envelope = BusEnvelope(
        id="paper-decision-1",
        topic=Topics.RISK_TRADE_DECISION,
        payload=decision.to_payload(),
    )
    events: list[str] = []
    bus = FakeBus({Topics.RISK_TRADE_DECISION: [envelope], Topics.VALIDATED_ORDER: [_order_envelope()]})
    bus.events = events

    class FakePaperEngine:
        async def handle(self, value):
            assert value.trade_id == decision.trade_id
            events.append("paper-handle")
            return PaperExecutionResult(events=())

    service = object.__new__(ExecutionService)
    service.settings = SimpleNamespace(trading_mode=TradingMode.PAPER)
    service.bus = bus
    service.engine = None
    service.paper_engine = FakePaperEngine()
    service._account_refresh = asyncio.Queue(maxsize=1)

    await service._consume_paper_decisions()

    assert events == ["paper-handle", "ack"]
    assert service._account_refresh.qsize() == 1
    with pytest.raises(RuntimeError, match="must never subscribe"):
        await service._consume_orders()


@pytest.mark.asyncio
async def test_valid_control_is_applied_before_ack():
    events: list[str] = []
    bus = FakeBus({Topics.SYSTEM_CONTROL: [_control_envelope(SystemMode.LOCAL_QUANT_MODE.value)]})
    bus.events = events
    service = _service(bus, FakeEngine(events))

    await service._consume_control()

    assert events == ["control", "ack"]


@pytest.mark.asyncio
async def test_invalid_control_is_acked_as_poison_message():
    events: list[str] = []
    bus = FakeBus({Topics.SYSTEM_CONTROL: [_control_envelope("UNKNOWN")]})
    bus.events = events
    service = _service(bus, FakeEngine(events))

    await service._consume_control()

    assert events == ["ack"]


@pytest.mark.asyncio
async def test_task_group_cancels_peer_and_closes_resources(monkeypatch):
    events: list[str] = []
    bus = FakeBus()
    engine = FakeEngine(events)
    service = _service(bus, engine)
    control_started = asyncio.Event()
    control_cancelled = asyncio.Event()

    async def fail_orders() -> None:
        await asyncio.sleep(0)
        raise RuntimeError("subscription failed")

    async def wait_for_control() -> None:
        control_started.set()
        try:
            await asyncio.Future()
        finally:
            control_cancelled.set()

    monkeypatch.setattr(service, "_consume_orders", fail_orders)
    monkeypatch.setattr(service, "_consume_control", wait_for_control)

    with pytest.raises(ExceptionGroup) as exc_info:
        await service.run()

    assert len(exc_info.value.exceptions) == 1
    assert isinstance(exc_info.value.exceptions[0], RuntimeError)
    assert str(exc_info.value.exceptions[0]) == "subscription failed"
    assert control_started.is_set()
    assert control_cancelled.is_set()
    assert engine.adapter.closed is True
    assert bus.closed is True


@pytest.mark.asyncio
async def test_bus_is_closed_even_if_adapter_close_fails():
    bus = FakeBus()
    engine = FakeEngine([])
    engine.adapter = FakeAdapter(close_error=RuntimeError("adapter close failed"))
    service = _service(bus, engine)

    with pytest.raises(RuntimeError, match="adapter close failed"):
        await service.close()

    assert engine.adapter.closed is True
    assert bus.closed is True


@pytest.mark.asyncio
async def test_reconciled_account_snapshot_is_published():
    bus = FakeBus()
    snapshot = AccountSnapshot(
        source="test-execution",
        exchange="fake",
        account_id="primary",
        equity_usd=10_250,
        available_balance_usd=8_000,
        peak_equity_usd=10_250,
        reconciled=True,
        captured_at=datetime(2026, 8, 12, 12, tzinfo=UTC),
    )
    engine = FakeEngine([])
    engine.adapter = FakeAdapter(snapshot=snapshot)
    service = _service(bus, engine)

    await service._publish_account_snapshot()

    topic, published = bus.published[0]
    assert topic == Topics.ACCOUNT_SNAPSHOT
    assert published.reconciled is True
    assert published.equity_usd == 10_250
    assert published.daily_pnl_pct == 0


@pytest.mark.asyncio
async def test_reconciliation_error_publishes_explicit_failure_snapshot():
    bus = FakeBus()
    engine = FakeEngine([])
    engine.adapter = FakeAdapter(snapshot_error=RuntimeError("positions unavailable"))
    service = _service(bus, engine)

    await service._publish_account_snapshot()

    topic, published = bus.published[0]
    assert topic == Topics.ACCOUNT_SNAPSHOT
    assert published.reconciled is False
    assert published.available_balance_usd == 0
    assert published.reconciliation_detail == "RuntimeError: positions unavailable"


def test_session_accounting_tracks_peak_and_intraday_drawdown():
    service = _service(FakeBus(), FakeEngine([]))
    start = AccountSnapshot(
        source="test-execution",
        exchange="fake",
        account_id="primary",
        equity_usd=10_000,
        available_balance_usd=10_000,
        peak_equity_usd=10_000,
        captured_at=datetime(2026, 8, 12, 9, tzinfo=UTC),
        reconciled=True,
    )
    lower = start.model_copy(
        update={
            "equity_usd": 9_500,
            "available_balance_usd": 9_500,
            "captured_at": datetime(2026, 8, 12, 10, tzinfo=UTC),
        }
    )

    service._apply_session_accounting(start)
    result = service._apply_session_accounting(lower)

    assert result.peak_equity_usd == 10_000
    assert result.daily_pnl_pct == -5
