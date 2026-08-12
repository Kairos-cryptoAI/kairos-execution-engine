import asyncio
from types import SimpleNamespace

import pytest
from kairos_core.bus.base import BusEnvelope
from kairos_core.contracts import ExecutionReport, OrderIntent, ValidatedOrder
from kairos_core.enums import OrderSide, OrderStatus, OrderType, ReasonCode, SystemMode
from kairos_core.topics import Topics

from kairos_execution.service import ExecutionService


class FakeAdapter:
    def __init__(self, *, close_error: Exception | None = None) -> None:
        self.closed = False
        self.close_error = close_error

    async def close(self) -> None:
        self.closed = True
        if self.close_error is not None:
            raise self.close_error


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
        self.closed = False

    async def subscribe(self, topic, *, group=None, consumer=None):
        for envelope in self.envelopes.get(topic, []):
            yield envelope

    async def publish(self, topic, message) -> str:
        self.events.append("publish")
        if self.publish_error is not None:
            raise self.publish_error
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
    )
    service.bus = bus
    service.engine = engine
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


@pytest.mark.asyncio
async def test_transient_handle_failure_leaves_order_pending():
    events: list[str] = []
    bus = FakeBus({Topics.VALIDATED_ORDER: [_order_envelope()]})
    bus.events = events
    service = _service(bus, FakeEngine(events, error=RuntimeError("exchange unavailable")))

    await service._consume_orders()

    assert events == ["handle"]


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
