"""CCXT adapter — used to test strategies on Binance testnet and other venues."""

from __future__ import annotations

from kairos_core.contracts import ExecutionReport, OrderIntent
from kairos_core.enums import OrderSide, OrderStatus, OrderType

from .base import ExchangeAdapter

try:
    import ccxt.async_support as ccxt
except Exception:  # pragma: no cover
    ccxt = None  # type: ignore


class CCXTAdapter(ExchangeAdapter):
    name = "ccxt"

    def __init__(
        self,
        exchange_id: str = "binanceusdm",
        *,
        api_key="",
        secret="",
        sandbox: bool = True,
        dry_run: bool = True,
    ) -> None:
        self.dry_run = dry_run
        self._client = None
        if ccxt is not None and not dry_run:  # pragma: no cover - network
            self._client = getattr(ccxt, exchange_id)(
                {"apiKey": api_key, "secret": secret, "options": {"defaultType": "future"}}
            )
            if sandbox:
                self._client.set_sandbox_mode(True)

    async def place_order(self, intent: OrderIntent) -> ExecutionReport:
        if self.dry_run or self._client is None:
            return ExecutionReport(
                source="execution-engine",
                client_order_id=intent.client_order_id or "dry",
                symbol=intent.symbol,
                side=intent.side,
                status=OrderStatus.NEW,
                message="dry_run",
            )
        otype = "market" if intent.order_type is OrderType.MARKET else "limit"  # pragma: no cover
        params = {"clientOrderId": intent.client_order_id} if intent.client_order_id else {}
        order = await self._client.create_order(
            intent.symbol,
            otype,
            intent.side.value.lower(),
            intent.quantity,
            intent.price,
            params,
        )
        return ExecutionReport(
            source="execution-engine",
            client_order_id=str(order.get("clientOrderId", "")),
            exchange_order_id=str(order.get("id")),
            symbol=intent.symbol,
            side=intent.side,
            status=OrderStatus.NEW,
        )

    async def cancel_order(self, symbol, order_id): ...  # pragma: no cover
    async def close_position(self, symbol, *, client_order_id=None):  # pragma: no cover
        return ExecutionReport(
            source="execution-engine",
            client_order_id=client_order_id or "dry-close",
            symbol=symbol,
            side=OrderSide.BUY,
            status=OrderStatus.NEW,
        )

    async def set_leverage(self, symbol, leverage): ...  # pragma: no cover
    async def set_trailing_stop(self, symbol, stop_price, side): ...  # pragma: no cover
    async def close(self):  # pragma: no cover
        if self._client is not None:
            await self._client.close()
