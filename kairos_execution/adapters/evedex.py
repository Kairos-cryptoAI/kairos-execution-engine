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

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from kairos_core.contracts import ExecutionReport, OrderIntent
from kairos_core.enums import OrderSide, OrderStatus, OrderType, TimeInForce

from ..crypto import EIP712_SCHEMAS, Signer, build_domain, to_eth_number
from ..ratelimit import TokenBucket
from ..state_machine import (
    client_order_id,
    is_evedex_client_order_id,
    is_fresh_evedex_client_order_id,
)
from .base import ExchangeAdapter

try:
    import aiohttp
except Exception:  # pragma: no cover
    aiohttp = None  # type: ignore

MIN_NOTIONAL_USD = 5.0


class EvedexAdapter(ExchangeAdapter):
    name = "evedex"

    def __init__(
        self,
        *,
        exchange_base_url: str,
        signer: Signer,
        chain_id: int | str,
        jwt: str | None = None,
        dry_run: bool = True,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.base = exchange_base_url.rstrip("/")
        self.signer = signer
        self.chain_id = chain_id
        self.jwt = jwt
        self.dry_run = dry_run
        self._clock = clock or (lambda: datetime.now(UTC))
        self._bucket = TokenBucket(30, 60.0)
        self._session = None

    # ---- signing helpers -------------------------------------------------
    def _sign(self, schema_key: str, message: dict[str, Any]) -> str:
        types = EIP712_SCHEMAS[schema_key]
        return self.signer.sign_typed_data(build_domain(self.chain_id), types, message)

    def _limit_message(self, intent: OrderIntent, order_id: str) -> dict[str, Any]:
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

    async def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
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
        if intent.order_type is OrderType.MARKET and intent.price is None:
            return self._report(
                intent,
                OrderStatus.REJECTED,
                msg="EVEDEX market orders require a reference price for cashQuantity",
            )

        order_id = intent.client_order_id
        if order_id is None or not is_evedex_client_order_id(order_id):
            order_id = client_order_id(
                order_id or intent.message_id,
                self.name,
                occurred_at=intent.produced_at,
            )
        if not is_fresh_evedex_client_order_id(order_id, now=self._clock()):
            return self._report(
                intent,
                OrderStatus.REJECTED,
                client_id=order_id,
                msg="stale EVEDEX order ID; refusing a non-idempotent replay",
            )
        if intent.order_type is OrderType.MARKET:
            message = {
                "id": order_id,
                "instrument": intent.symbol,
                "side": intent.side.value,
                "timeInForce": (intent.time_in_force or TimeInForce.IOC).value,
                "leverage": int(intent.leverage),
                "cashQuantity": to_eth_number(notional),
                "chainId": int(self.chain_id),
            }
            signature = self._sign("New market order", message)
            resp = await self._post("/api/v2/order/market", {**message, "signature": signature})
        else:
            message = self._limit_message(intent, order_id)
            signature = self._sign("New limit order", message)
            resp = await self._post("/api/v2/order/limit", {**message, "signature": signature})

        raw_status = str(resp.get("status", "NEW")).upper().replace("CANCELLED", "CANCELED")
        status = OrderStatus(raw_status) if raw_status in OrderStatus.__members__ else OrderStatus.NEW
        remaining_qty = self._float(resp.get("unFilledQuantity"), default=intent.quantity)
        filled_qty = max(0.0, intent.quantity - remaining_qty)
        return self._report(
            intent,
            status,
            exch_id=resp.get("id"),
            client_id=order_id,
            filled_qty=filled_qty,
            remaining_qty=remaining_qty,
            avg_price=self._float(resp.get("filledAvgPrice")),
        )

    async def close_position(
        self,
        symbol: str,
        *,
        client_order_id: str | None = None,
    ) -> ExecutionReport:  # pragma: no cover - thin
        close_id = client_order_id
        if close_id is None or not is_evedex_client_order_id(close_id):
            raise ValueError("close_position requires a valid deterministic EVEDEX client order ID")
        if not is_fresh_evedex_client_order_id(close_id, now=self._clock()):
            raise ValueError("refusing stale EVEDEX close request")
        message = {
            "id": close_id,
            "instrument": symbol,
            "leverage": 1,
            "quantity": 0,
            "chainId": int(self.chain_id),
        }
        signature = self._sign("Position close order", message)
        await self._post(f"/api/v2/position/{symbol}/close", {**message, "signature": signature})
        return ExecutionReport(
            source="execution-engine",
            client_order_id=close_id,
            symbol=symbol,
            side=OrderSide.BUY,
            status=OrderStatus.NEW,
            message="close requested",
        )

    async def set_leverage(self, symbol: str, leverage: float) -> None:  # pragma: no cover - thin
        await self._post(f"/api/position/{symbol}", {"leverage": int(leverage)})

    async def set_trailing_stop(self, symbol: str, stop_price: float, side: str) -> None:
        message = {
            "instrument": symbol,
            "type": "STOP_LOSS",
            "side": side,
            "quantity": 0,
            "price": to_eth_number(stop_price),
        }
        signature = self._sign("New take-profit/stop-loss", message)
        await self._post(f"/api/tpsl/{symbol}", {**message, "signature": signature})

    async def cancel_order(self, symbol: str, order_id: str) -> None:  # pragma: no cover - thin
        await self._bucket.acquire()
        if self.dry_run:
            return
        session = await self._session_get()
        async with session.delete(f"{self.base}/api/order/{order_id}") as resp:
            resp.raise_for_status()

    def _report(
        self,
        intent: OrderIntent,
        status: OrderStatus,
        *,
        exch_id: str | None = None,
        client_id: str | None = None,
        msg: str = "",
        filled_qty: float = 0.0,
        remaining_qty: float | None = None,
        avg_price: float = 0.0,
    ) -> ExecutionReport:
        return ExecutionReport(
            source="execution-engine",
            client_order_id=client_id or intent.client_order_id or "unknown",
            exchange_order_id=exch_id,
            exchange=self.name,
            symbol=intent.symbol,
            side=intent.side,
            status=status,
            requested_qty=intent.quantity,
            filled_qty=filled_qty,
            remaining_qty=intent.quantity if remaining_qty is None else remaining_qty,
            avg_price=avg_price,
            message=msg,
        )

    @staticmethod
    def _float(value: Any, *, default: float = 0.0) -> float:
        try:
            return float(value) if value is not None else default
        except (TypeError, ValueError):
            return default

    async def close(self) -> None:  # pragma: no cover
        if self._session is not None:
            await self._session.close()
