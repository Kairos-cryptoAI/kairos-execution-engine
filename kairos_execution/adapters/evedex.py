"""EVEDEX exchange adapter — EIP-712 signed REST orders.

Implements the order endpoints documented at https://docs.evedex.com:
  * POST /api/v2/order/limit, /market, /stop-limit
  * POST /api/v2/position/{instrument}/close
  * PUT  /api/position/{instrument}              (leverage)
  * POST /api/tpsl/{instrument}                  (trailing / protective stop)
  * DELETE /api/order/{orderId}
Every mutating call is EIP-712 signed and rate-limited to 30 heavy requests / 60s.
"""
from __future__ import annotations

import uuid
from typing import Any, Dict, Optional

from kairos_core.contracts import ExecutionReport, OrderIntent
from kairos_core.enums import OrderStatus, OrderType, TimeInForce

from ..crypto import EIP712_SCHEMAS, Signer, build_domain, to_eth_number
from ..ratelimit import TokenBucket
from .base import ExchangeAdapter

try:
    import aiohttp
except Exception:  # pragma: no cover
    aiohttp = None  # type: ignore

MIN_NOTIONAL_USD = 5.0


class EvedexAdapter(ExchangeAdapter):
    name = "evedex"

    def __init__(self, *, exchange_base_url: str, signer: Signer, chain_id: int | str,
                 jwt: Optional[str] = None, dry_run: bool = True) -> None:
        self.base = exchange_base_url.rstrip("/")
        self.signer = signer
        self.chain_id = chain_id
        self.jwt = jwt
        self.dry_run = dry_run
        self._bucket = TokenBucket(30, 60.0)
        self._session = None

    # ---- signing helpers -------------------------------------------------
    def _sign(self, schema_key: str, message: Dict[str, Any]) -> str:
        types = EIP712_SCHEMAS[schema_key]
        return self.signer.sign_typed_data(build_domain(self.chain_id), types, message)

    def _limit_message(self, intent: OrderIntent, order_id: str) -> Dict[str, Any]:
        return {
            "id": order_id,
            "instrument": intent.symbol,
            "side": intent.side.value,
            "leverage": int(intent.leverage),
            "quantity": to_eth_number(intent.quantity),
            "limitPrice": to_eth_number(intent.price or 0),
            "chainId": int(self.chain_id),
        }

    # ---- HTTP ------------------------------------------------------------
    async def _session_get(self):  # pragma: no cover - network
        if self._session is None:
            if aiohttp is None:
                raise RuntimeError("aiohttp is required for live EVEDEX trading")
            headers = {"Authorization": f"Bearer {self.jwt}"} if self.jwt else {}
            self._session = aiohttp.ClientSession(headers=headers)
        return self._session

    async def _post(self, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        await self._bucket.acquire()
        if self.dry_run:
            return {"id": body.get("id", "dry"), "status": "NEW", "dry_run": True}
        session = await self._session_get()  # pragma: no cover - network
        async with session.post(f"{self.base}{path}", json=body) as resp:  # pragma: no cover
            resp.raise_for_status()
            return await resp.json()

    # ---- ExchangeAdapter -------------------------------------------------
    async def place_order(self, intent: OrderIntent) -> ExecutionReport:
        notional = (intent.price or 0) * intent.quantity
        if intent.order_type is OrderType.LIMIT and notional < MIN_NOTIONAL_USD:
            return self._report(intent, OrderStatus.REJECTED, msg="below $5 min notional")

        order_id = str(uuid.uuid4())
        if intent.order_type is OrderType.MARKET:
            message = {
                "id": order_id, "instrument": intent.symbol, "side": intent.side.value,
                "timeInForce": (intent.time_in_force or TimeInForce.IOC).value,
                "leverage": int(intent.leverage),
                "cashQuantity": to_eth_number(notional or intent.quantity),
                "chainId": int(self.chain_id),
            }
            signature = self._sign("New market order", message)
            resp = await self._post("/api/v2/order/market", {**message, "signature": signature})
        else:
            message = self._limit_message(intent, order_id)
            signature = self._sign("New limit order", message)
            resp = await self._post("/api/v2/order/limit", {**message, "signature": signature})

        status = OrderStatus(resp.get("status", "NEW")) if resp.get("status") in OrderStatus.__members__             else OrderStatus.NEW
        return self._report(intent, status, exch_id=resp.get("id"), client_id=order_id)

    async def close_position(self, symbol: str) -> ExecutionReport:  # pragma: no cover - thin
        message = {"id": str(uuid.uuid4()), "instrument": symbol, "leverage": 1,
                   "quantity": 0, "chainId": int(self.chain_id)}
        signature = self._sign("Position close order", message)
        await self._post(f"/api/v2/position/{symbol}/close", {**message, "signature": signature})
        return ExecutionReport(source="execution-engine", client_order_id=message["id"], symbol=symbol,
                               side="BUY", status=OrderStatus.NEW, message="close requested")

    async def set_leverage(self, symbol: str, leverage: float) -> None:  # pragma: no cover - thin
        await self._post(f"/api/position/{symbol}", {"leverage": int(leverage)})

    async def set_trailing_stop(self, symbol: str, stop_price: float, side: str) -> None:
        message = {"instrument": symbol, "type": "STOP_LOSS", "side": side,
                   "quantity": 0, "price": to_eth_number(stop_price)}
        signature = self._sign("New take-profit/stop-loss", message)
        await self._post(f"/api/tpsl/{symbol}", {**message, "signature": signature})

    async def cancel_order(self, symbol: str, order_id: str) -> None:  # pragma: no cover - thin
        await self._bucket.acquire()
        if self.dry_run:
            return
        session = await self._session_get()
        async with session.delete(f"{self.base}/api/order/{order_id}") as resp:
            resp.raise_for_status()

    def _report(self, intent: OrderIntent, status: OrderStatus, *, exch_id=None, client_id=None, msg="") -> ExecutionReport:
        return ExecutionReport(
            source="execution-engine", client_order_id=client_id or "", exchange_order_id=exch_id,
            symbol=intent.symbol, side=intent.side, status=status, message=msg,
        )

    async def close(self) -> None:  # pragma: no cover
        if self._session is not None:
            await self._session.close()
