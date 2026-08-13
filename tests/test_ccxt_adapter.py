from datetime import UTC, datetime

import pytest
from kairos_core.enums import OrderSide

from kairos_execution.adapters.ccxt_adapter import CCXTAdapter


class FakeClient:
    def __init__(self) -> None:
        self.calls = []

    async def fetch_balance(self):
        return {
            "total": {"USDT": 10_000},
            "free": {"USDT": 8_000},
            "info": {
                "totalMarginBalance": "10250",
                "availableBalance": "8000",
                "totalInitialMargin": "1500",
                "totalUnrealizedProfit": "250",
            },
        }

    async def fetch_positions(self, symbols=None):
        return [
            {
                "symbol": "BTC/USDT:USDT",
                "side": "long",
                "contracts": 0.2,
                "entryPrice": 65_000,
                "markPrice": 66_000,
                "leverage": 2,
                "liquidationPrice": 32_000,
                "unrealizedPnl": 200,
                "initialMargin": 1_500,
            }
        ]

    async def fetch_open_orders(self):
        return [
            {
                "id": "stop-1",
                "symbol": "BTC/USDT:USDT",
                "stopPrice": 64_000,
                "reduceOnly": True,
                "info": {},
            }
        ]

    async def create_order(self, *args):
        self.calls.append(("create_order", args))
        return {
            "id": "close-1",
            "clientOrderId": "client-close-1",
            "status": "closed",
            "filled": 0.2,
            "remaining": 0,
            "average": 66_000,
        }

    async def cancel_order(self, order_id, symbol):
        self.calls.append(("cancel_order", order_id, symbol))

    async def set_leverage(self, leverage, symbol):
        self.calls.append(("set_leverage", leverage, symbol))


def _live_adapter() -> CCXTAdapter:
    adapter = CCXTAdapter(dry_run=True)
    adapter.dry_run = False
    adapter._client = FakeClient()
    return adapter


@pytest.mark.asyncio
async def test_ccxt_snapshot_normalizes_balance_positions_orders_and_stop():
    adapter = _live_adapter()

    snapshot = await adapter.fetch_account_snapshot(account_id="primary", peak_equity_usd=10_000)

    assert snapshot.reconciled is True
    assert snapshot.equity_usd == 10_250
    assert snapshot.available_balance_usd == 8_000
    assert snapshot.margin_used_usd == 1_500
    assert snapshot.open_order_ids == ["stop-1"]
    assert snapshot.positions[0].symbol == "BTCUSDT"
    assert snapshot.positions[0].signed_quantity == 0.2
    assert snapshot.positions[0].protective_stop_order_id == "stop-1"
    assert snapshot.captured_at <= datetime.now(UTC)


@pytest.mark.asyncio
async def test_ccxt_close_uses_exact_quantity_and_reduce_only():
    adapter = _live_adapter()

    report = await adapter.close_position(
        "BTC/USDT:USDT",
        quantity=0.2,
        side=OrderSide.SELL,
        client_order_id="client-close-1",
    )

    assert report.filled_qty == 0.2
    _, args = adapter._client.calls[0]
    assert args[:5] == ("BTC/USDT:USDT", "market", "sell", 0.2, None)
    assert args[5] == {"reduceOnly": True, "clientOrderId": "client-close-1"}
