import asyncio
from kairos_core.contracts import OrderIntent, ValidatedOrder
from kairos_core.enums import OrderSide, OrderType, ReasonCode, SystemMode
from kairos_execution.engine import ExecutionEngine
from kairos_execution.adapters.base import ExchangeAdapter
from kairos_core.contracts import ExecutionReport
from kairos_core.enums import OrderStatus


class FakeAdapter(ExchangeAdapter):
    name = "fake"
    def __init__(self):
        self.placed = []
        self.trailing = []
        self.closed = []
    async def place_order(self, intent):
        self.placed.append(intent)
        return ExecutionReport(source="x", client_order_id="1", symbol=intent.symbol,
                               side=intent.side, status=OrderStatus.NEW)
    async def cancel_order(self, symbol, order_id): ...
    async def close_position(self, symbol):
        self.closed.append(symbol)
        return ExecutionReport(source="x", client_order_id="2", symbol=symbol, side=OrderSide.SELL, status=OrderStatus.NEW)
    async def set_leverage(self, symbol, leverage): ...
    async def set_trailing_stop(self, symbol, stop_price, side):
        self.trailing.append((symbol, stop_price, side))


def _order(reason=ReasonCode.ENTER_LONG_TREND, approved=True):
    intent = OrderIntent(source="risk", symbol="BTCUSD", side=OrderSide.BUY, order_type=OrderType.LIMIT,
                         quantity=0.1, price=65000, reason_code=reason)
    return ValidatedOrder(source="risk", intent=intent, approved=approved, reason_code=reason)


def test_open_places_order_and_arms_trailing_stop():
    a = FakeAdapter(); eng = ExecutionEngine(a)
    asyncio.run(eng.handle(_order()))
    assert len(a.placed) == 1
    assert len(a.trailing) == 1  # protective stop armed
    sym, stop, side = a.trailing[0]
    assert side == "SELL" and stop < 65000


def test_unapproved_order_is_ignored():
    a = FakeAdapter(); eng = ExecutionEngine(a)
    asyncio.run(eng.handle(_order(approved=False)))
    assert not a.placed


def test_local_quant_mode_blocks_new_entries():
    a = FakeAdapter(); eng = ExecutionEngine(a)
    eng.set_mode(SystemMode.LOCAL_QUANT_MODE)
    asyncio.run(eng.handle(_order()))
    assert not a.placed  # opening blocked while LLM detached
