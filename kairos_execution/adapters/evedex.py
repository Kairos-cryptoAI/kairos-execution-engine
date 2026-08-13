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

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from kairos_core.contracts import AccountSnapshot, ExecutionReport, OrderIntent, PositionSnapshot
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
        dry_run_equity_usd: float = 10_000.0,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.base = exchange_base_url.rstrip("/")
        self.signer = signer
        self.chain_id = chain_id
        self.jwt = jwt
        self.dry_run = dry_run
        self.dry_run_equity_usd = dry_run_equity_usd
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

    async def _get(self, path: str) -> Any:
        await self._bucket.acquire()
        session = await self._session_get()  # pragma: no cover - network
        async with session.get(f"{self.base}{path}") as resp:  # pragma: no cover
            resp.raise_for_status()
            return await resp.json()

    async def _put(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        await self._bucket.acquire()
        if self.dry_run:
            return {"status": "dry_run"}
        session = await self._session_get()  # pragma: no cover - network
        async with session.put(f"{self.base}{path}", json=body) as resp:  # pragma: no cover
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
        quantity: float | None = None,
        side: OrderSide | None = None,
        client_order_id: str | None = None,
    ) -> ExecutionReport:  # pragma: no cover - thin
        close_id = client_order_id
        if close_id is None or not is_evedex_client_order_id(close_id):
            raise ValueError("close_position requires a valid deterministic EVEDEX client order ID")
        if not is_fresh_evedex_client_order_id(close_id, now=self._clock()):
            raise ValueError("refusing stale EVEDEX close request")
        if quantity is None and not self.dry_run:
            quantity = await self._open_position_quantity(symbol)
        if quantity is not None and quantity <= 0:
            raise ValueError("close_position quantity must be positive")
        message = {
            "id": close_id,
            "instrument": symbol,
            "leverage": 1,
            "quantity": to_eth_number(quantity or 0),
            "chainId": int(self.chain_id),
        }
        signature = self._sign("Position close order", message)
        await self._post(f"/api/v2/position/{symbol}/close", {**message, "signature": signature})
        return ExecutionReport(
            source="execution-engine",
            client_order_id=close_id,
            symbol=symbol,
            side=side or OrderSide.BUY,
            status=OrderStatus.NEW,
            requested_qty=quantity or 0,
            message="close requested",
        )

    async def set_leverage(self, symbol: str, leverage: float) -> None:  # pragma: no cover - thin
        await self._put(f"/api/position/{symbol}", {"leverage": int(leverage)})

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

    async def fetch_account_snapshot(
        self,
        *,
        account_id: str,
        peak_equity_usd: float,
    ) -> AccountSnapshot:
        """Fetch and cross-check all authoritative EVEDEX account components."""
        captured_at = self._clock()
        if self.dry_run:
            equity = self.dry_run_equity_usd
            return AccountSnapshot(
                source="kairos-execution-engine",
                exchange=self.name,
                account_id=account_id,
                equity_usd=equity,
                available_balance_usd=equity,
                peak_equity_usd=max(peak_equity_usd, equity),
                captured_at=captured_at,
                reconciled=True,
                reconciliation_detail="synthetic dry-run account; no live exchange calls",
            )

        account, balance, raw_positions, raw_orders, raw_tpsl = await asyncio.gather(
            self._get("/api/user/me"),
            self._get("/api/market/available-balance"),
            self._get("/api/position"),
            self._get("/api/order/opened"),
            self._get("/api/tpsl"),
        )
        if not isinstance(account, dict) or not isinstance(balance, dict):
            raise ValueError("EVEDEX account endpoints returned malformed objects")
        if account.get("marginCall") is True:
            raise ValueError("EVEDEX account is in margin call")

        positions = self._as_list(raw_positions)
        orders = self._as_list(raw_orders)
        tpsl = self._as_list(raw_tpsl)
        self._cross_check_positions(balance.get("position", []), positions)
        self._cross_check_orders(balance.get("openOrder", []), orders)

        funding = balance.get("funding")
        if not isinstance(funding, dict):
            raise ValueError("EVEDEX available-balance response has no funding object")
        funding_balance = self._required_float(funding.get("balance"), "funding.balance")
        available = self._required_float(balance.get("availableBalance"), "availableBalance")
        negative_unpnl = abs(self._float(balance.get("negativeUnPnL")))
        unrealized = -negative_unpnl
        equity = funding_balance + unrealized
        if equity <= 0:
            raise ValueError("EVEDEX reconciled equity is not positive")

        stop_by_symbol = {
            str(item.get("instrument")): str(item.get("id"))
            for item in tpsl
            if str(item.get("type", "")).casefold() == "stop-loss"
            and str(item.get("status", "")).casefold() in {"waitorder", "active", "process"}
            and item.get("instrument")
            and item.get("id")
        }
        position_snapshots = [
            self._position_snapshot(
                position,
                account_id=account_id,
                captured_at=captured_at,
                protective_stop_id=stop_by_symbol.get(str(position.get("instrument"))),
            )
            for position in positions
            if self._float(position.get("quantity")) > 0
        ]
        margin_used = sum(
            self._float(item.get("initialMargin"))
            for item in balance.get("position", [])
            if isinstance(item, dict)
        )
        remote_id = account.get("exchangeId") or account.get("id") or account.get("user")
        return AccountSnapshot(
            source="kairos-execution-engine",
            exchange=self.name,
            account_id=account_id,
            equity_usd=equity,
            available_balance_usd=max(0.0, available),
            margin_used_usd=max(0.0, margin_used),
            peak_equity_usd=max(peak_equity_usd, equity),
            unrealized_pnl_usd=unrealized,
            positions=position_snapshots,
            open_order_ids=[str(order["id"]) for order in orders if order.get("id")],
            captured_at=captured_at,
            reconciled=True,
            reconciliation_detail=(
                f"cross-checked balance, {len(positions)} positions, {len(orders)} open orders, "
                f"and {len(tpsl)} TP/SL records; exchange_account={remote_id}"
            ),
        )

    async def _open_position_quantity(self, symbol: str) -> float:
        positions = self._as_list(await self._get("/api/position"))
        quantity = sum(
            self._float(item.get("quantity"))
            for item in positions
            if str(item.get("instrument", "")).upper() == symbol.upper()
        )
        if quantity <= 0:
            raise ValueError(f"no open EVEDEX position for {symbol}")
        return quantity

    def _position_snapshot(
        self,
        item: dict[str, Any],
        *,
        account_id: str,
        captured_at: datetime,
        protective_stop_id: str | None,
    ) -> PositionSnapshot:
        symbol = str(item.get("instrument", ""))
        if not symbol:
            raise ValueError("EVEDEX position has no instrument")
        quantity = self._required_float(item.get("quantity"), f"{symbol}.quantity")
        side = str(item.get("side", "")).upper()
        if side not in {"BUY", "SELL"}:
            raise ValueError(f"EVEDEX position {symbol} has invalid side")
        entry = self._required_float(item.get("avgPrice"), f"{symbol}.avgPrice")
        mark = self._float(item.get("markPrice") or item.get("currentPrice"), default=entry)
        return PositionSnapshot(
            source="kairos-execution-engine",
            exchange=self.name,
            account_id=account_id,
            symbol=symbol,
            signed_quantity=quantity if side == "BUY" else -quantity,
            entry_price=entry,
            mark_price=mark,
            leverage=max(1.0, self._float(item.get("leverage"), default=1.0)),
            liquidation_price=self._optional_positive_float(item.get("liquidationPrice")),
            unrealized_pnl_usd=self._float(item.get("unrealizedPnL") or item.get("unrealizedPnl")),
            protective_stop_order_id=protective_stop_id,
            captured_at=captured_at,
        )

    @classmethod
    def _cross_check_positions(cls, summaries: Any, positions: list[dict[str, Any]]) -> None:
        if not isinstance(summaries, list):
            raise ValueError("EVEDEX position summary is malformed")
        expected = cls._position_totals(summaries, quantity_key="volume")
        actual = cls._position_totals(positions, quantity_key="quantity")
        cls._assert_totals("position", expected, actual)

    @classmethod
    def _cross_check_orders(cls, summaries: Any, orders: list[dict[str, Any]]) -> None:
        if not isinstance(summaries, list):
            raise ValueError("EVEDEX open-order summary is malformed")
        expected = cls._position_totals(summaries, quantity_key="unFilledVolume")
        actual = cls._position_totals(orders, quantity_key="unFilledQuantity")
        cls._assert_totals("open-order", expected, actual)

    @classmethod
    def _position_totals(cls, items: list[Any], *, quantity_key: str) -> dict[tuple[str, str], float]:
        result: dict[tuple[str, str], float] = {}
        for item in items:
            if not isinstance(item, dict):
                raise ValueError("EVEDEX reconciliation list contains a non-object")
            key = (str(item.get("instrument", "")), str(item.get("side", "")).upper())
            if not all(key):
                raise ValueError("EVEDEX reconciliation item has no instrument or side")
            result[key] = result.get(key, 0.0) + cls._required_float(
                item.get(quantity_key),
                f"{key[0]}.{quantity_key}",
            )
        return result

    @staticmethod
    def _assert_totals(
        kind: str,
        expected: dict[tuple[str, str], float],
        actual: dict[tuple[str, str], float],
    ) -> None:
        if expected.keys() != actual.keys() or any(
            abs(expected[key] - actual[key]) > 1e-8 for key in expected
        ):
            raise ValueError(f"EVEDEX {kind} detail does not match available-balance snapshot")

    @staticmethod
    def _as_list(payload: Any) -> list[dict[str, Any]]:
        if isinstance(payload, list):
            values = payload
        elif isinstance(payload, dict) and isinstance(payload.get("list"), list):
            values = payload["list"]
        else:
            raise ValueError("EVEDEX list endpoint returned a malformed response")
        if not all(isinstance(item, dict) for item in values):
            raise ValueError("EVEDEX list endpoint contains a non-object")
        return values

    @staticmethod
    def _required_float(value: Any, field: str) -> float:
        try:
            result = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"EVEDEX {field} is not numeric") from exc
        if result < 0:
            raise ValueError(f"EVEDEX {field} must not be negative")
        return result

    @staticmethod
    def _optional_positive_float(value: Any) -> float | None:
        parsed = EvedexAdapter._float(value)
        return parsed if parsed > 0 else None

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
