import asyncio
from kairos_core.contracts import OrderIntent, ValidatedOrder
from kairos_core.enums import OrderSide, OrderType, ReasonCode, SystemMode
from kairos_execution.engine import ExecutionEngine
from kairos_execution.adapters.base import ExchangeAdapter
from kairos_core.contracts import ExecutionReport
from kairos_core.enums import OrderStatus


class FakeAdapter(ExchangeAdapter):
    name = "fake"
    def __init__(self, fill_price=0.0, fail_stop=False):
        self.placed = []
        self.trailing = []
        self.closed = []
        self.fill_price = fill_price
        self.fail_stop = fail_stop
    async def place_order(self, intent):
        self.placed.append(intent)
        return ExecutionReport(source="x", client_order_id="1", symbol=intent.symbol,
                               side=intent.side, status=OrderStatus.NEW, avg_price=self.fill_price)
    async def cancel_order(self, symbol, order_id): ...
    async def close_position(self, symbol):
        self.closed.append(symbol)
        return ExecutionReport(source="x", client_order_id="2", symbol=symbol,
                               side=OrderSide.SELL, status=OrderStatus.NEW)
    async def set_leverage(self, symbol, leverage): ...
    async def set_trailing_stop(self, symbol, stop_price, side):
        if self.fail_stop:
            raise RuntimeError("stop rejected")
        self.trailing.append((symbol, stop_price, side))


def _order(reason=ReasonCode.ENTER_LONG_TREND, approved=True, price=65000, order_type=OrderType.LIMIT):
    intent = OrderIntent(source="risk", symbol="BTCUSDT", side=OrderSide.BUY, order_type=order_type,
                         quantity=0.1, price=price, reason_code=reason)
    return ValidatedOrder(source="risk", intent=intent, approved=approved, reason_code=reason)


def _engine(adapter):
    return ExecutionEngine(
        adapter,
        allowed_symbols={"BTCUSDT", "ETHUSDT", "SOLUSDT", "BNBUSDT", "XRPUSDT"},
    )


def test_market_order_arms_trailing_stop_from_fill_price():
    # Market orders have no intent.price; the stop must be armed off the exchange fill.
    a = FakeAdapter(fill_price=64500.0)
    eng = _engine(a)
    asyncio.run(eng.handle(_order(price=None, order_type=OrderType.MARKET)))
    assert len(a.placed) == 1
    assert len(a.trailing) == 1  # protective stop MUST still be armed
    _sym, stop, side = a.trailing[0]
    assert side == "SELL" and stop < 64500.0


def test_open_places_order_and_arms_trailing_stop():
    a = FakeAdapter()
    eng = _engine(a)
    asyncio.run(eng.handle(_order()))
    assert len(a.placed) == 1
    assert len(a.trailing) == 1  # protective stop armed
    sym, stop, side = a.trailing[0]
    assert side == "SELL" and stop < 65000


def test_same_validated_order_gets_same_exchange_client_id():
    adapter = FakeAdapter()
    engine = _engine(adapter)
    order = _order()
    asyncio.run(engine.handle(order))
    first_id = adapter.placed[0].client_order_id
    asyncio.run(engine.handle(order))
    assert adapter.placed[1].client_order_id == first_id
    assert first_id.startswith("krs-")


def test_stop_failure_requests_emergency_close():
    adapter = FakeAdapter(fail_stop=True)
    with __import__("pytest").raises(RuntimeError, match="stop rejected"):
        asyncio.run(_engine(adapter).handle(_order()))
    assert adapter.closed == ["BTCUSDT"]


def test_missing_entry_price_requests_emergency_close():
    adapter = FakeAdapter(fill_price=0)
    report = asyncio.run(_engine(adapter).handle(
        _order(price=None, order_type=OrderType.MARKET)
    ))
    assert adapter.closed == ["BTCUSDT"]
    assert "emergency close" in report.message


def test_unapproved_order_is_ignored():
    a = FakeAdapter()
    eng = _engine(a)
    asyncio.run(eng.handle(_order(approved=False)))
    assert not a.placed


def test_unknown_symbol_is_rejected_before_adapter_call():
    adapter = FakeAdapter()
    order = _order().model_copy(
        update={"intent": _order().intent.model_copy(update={"symbol": "DOGEUSDT"})},
    )
    report = asyncio.run(_engine(adapter).handle(order))
    assert report is None
    assert adapter.placed == []
    assert adapter.closed == []


def test_local_quant_mode_blocks_new_entries():
    a = FakeAdapter()
    eng = _engine(a)
    eng.set_mode(SystemMode.LOCAL_QUANT_MODE)
    asyncio.run(eng.handle(_order()))
    assert not a.placed  # opening blocked while LLM detached
