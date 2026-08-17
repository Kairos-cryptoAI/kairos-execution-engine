from datetime import UTC, datetime

import pytest
from kairos_core.enums import OrderSide

from kairos_execution.adapters.ccxt_adapter import CCXTAdapter


class FakeClient:
    def __init__(self) -> None:
        self.calls = []
        self.positions = [
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
        self.open_orders = [
            {
                "id": "stop-1",
                "clientOrderId": "client-stop-1",
                "symbol": "BTC/USDT:USDT",
                "side": "sell",
                "stopPrice": 64_000,
                "reduceOnly": True,
                "closePosition": True,
                "info": {},
            }
        ]

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
        return self.positions

    async def fetch_open_orders(self, symbol=None):
        return self.open_orders

    async def create_order(self, *args):
        self.calls.append(("create_order", args))
        if args[1] == "STOP_MARKET":
            return {
                "id": "protective-1",
                "status": "open",
                "symbol": args[0],
                "side": args[2],
            }
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


@pytest.mark.asyncio
async def test_ccxt_protective_stop_returns_venue_order_id():
    adapter = _live_adapter()

    ack = await adapter.set_protective_stop(
        "BTC/USDT:USDT",
        64_000.0,
        OrderSide.BUY,
        "client-entry-1",
    )

    assert ack.exchange_order_id == "protective-1"
    _, args = adapter._client.calls[0]
    assert args[:3] == ("BTC/USDT:USDT", "STOP_MARKET", "sell")


@pytest.mark.asyncio
async def test_ccxt_snapshot_does_not_treat_wrong_side_or_partial_stop_as_full_protection():
    adapter = _live_adapter()
    adapter._client.open_orders = [
        {
            "id": "wrong-side",
            "symbol": "BTC/USDT:USDT",
            "side": "buy",
            "stopPrice": 64_000,
            "closePosition": True,
            "info": {},
        },
        {
            "id": "partial",
            "symbol": "BTC/USDT:USDT",
            "side": "sell",
            "stopPrice": 64_000,
            "reduceOnly": True,
            "closePosition": "false",
            "info": {},
        },
    ]

    snapshot = await adapter.fetch_account_snapshot(account_id="primary", peak_equity_usd=10_000)

    assert snapshot.positions[0].protective_stop_order_id is None


@pytest.mark.asyncio
async def test_ccxt_reconciliation_queries_live_orders_and_positions():
    adapter = _live_adapter()

    assert await adapter.is_order_active_by_client_id("BTC/USDT:USDT", "client-stop-1") is True
    assert await adapter.is_order_active_by_client_id("BTC/USDT:USDT", "stop-1") is False
    assert await adapter.is_position_flat("BTC/USDT:USDT") is False


@pytest.mark.asyncio
async def test_ccxt_cancellation_resolves_client_id_to_unique_server_id():
    adapter = _live_adapter()

    await adapter.cancel_order_by_client_id("BTC/USDT:USDT", "client-stop-1")

    assert adapter._client.calls[-1] == ("cancel_order", "stop-1", "BTC/USDT:USDT")


@pytest.mark.asyncio
async def test_ccxt_cancellation_never_treats_server_id_as_client_id():
    adapter = _live_adapter()

    await adapter.cancel_order_by_client_id("BTC/USDT:USDT", "stop-1")

    assert adapter._client.calls == []


@pytest.mark.asyncio
async def test_ccxt_duplicate_client_id_resolution_fails_closed():
    adapter = _live_adapter()
    adapter._client.open_orders.append({"id": "stop-2", "clientOrderId": "client-stop-1", "info": {}})

    with pytest.raises(ValueError, match="multiple CCXT open orders"):
        await adapter.cancel_order_by_client_id("BTC/USDT:USDT", "client-stop-1")


@pytest.mark.parametrize("contracts", [None, "not-a-number", float("nan"), float("inf")])
@pytest.mark.asyncio
async def test_ccxt_malformed_contracts_never_reconcile_as_flat(contracts):
    adapter = _live_adapter()
    adapter._client.positions = [{"symbol": "BTC/USDT:USDT", "contracts": contracts}]

    with pytest.raises(ValueError, match="contracts"):
        await adapter.is_position_flat("BTC/USDT:USDT")


def test_ccxt_unknown_order_status_is_not_coerced_to_new():
    with pytest.raises(ValueError, match="unknown order status"):
        CCXTAdapter._execution_report(
            {"id": "server-1", "clientOrderId": "client-1", "status": "mystery"},
            symbol="BTCUSDT",
            side=OrderSide.BUY,
            requested=0.1,
        )
