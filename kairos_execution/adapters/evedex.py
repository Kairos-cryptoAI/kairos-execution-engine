"""EVEDEX exchange adapter — EIP-712 signed REST orders.

Implements the order endpoints documented at https://docs.evedex.com:
  * POST /api/v2/order/limit, /market, /stop-limit
  * POST /api/v2/position/{instrument}/close
  * PUT  /api/position/{instrument}              (leverage)
  * POST /api/tpsl/{instrument}                  (protective stop)
  * DELETE /api/order/{orderId}
Every mutating call is EIP-712 signed and rate-limited to 30 heavy requests / 60s.
"""

from __future__ import annotations

import asyncio
import math
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
from .base import ExchangeAdapter, ProtectiveStopAck

try:
    import aiohttp
except Exception:  # pragma: no cover
    aiohttp = None  # type: ignore

MIN_NOTIONAL_USD = 5.0


class EvedexAdapter(ExchangeAdapter):
    name = "evedex"
    exchange_order_id_matches_client_order_id = True

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
            if path.startswith("/api/tpsl/"):
                return {
                    "id": f"dry-tpsl-{body.get('order', 'unlinked')}",
                    "status": "waitOrder",
                    "dry_run": True,
                }
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

        response_id = resp.get("id")
        if response_id is None or str(response_id) != order_id:
            raise ValueError("EVEDEX order response ID does not match the submitted order ID")
        status = self._order_status(resp.get("status"))
        remaining_qty = self._float(resp.get("unFilledQuantity"), default=intent.quantity)
        filled_qty = max(0.0, intent.quantity - remaining_qty)
        return self._report(
            intent,
            status,
            exch_id=order_id,
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
        resp = await self._post(
            f"/api/v2/position/{symbol}/close",
            {**message, "signature": signature},
        )
        response_id = resp.get("id")
        if response_id is None or str(response_id) != close_id:
            raise ValueError("EVEDEX close response ID does not match the submitted close ID")
        requested_qty = quantity or 0.0
        remaining_qty = self._float(resp.get("unFilledQuantity"), default=requested_qty)
        return ExecutionReport(
            source="execution-engine",
            client_order_id=close_id,
            exchange_order_id=close_id,
            exchange=self.name,
            symbol=symbol,
            side=side or OrderSide.BUY,
            status=self._order_status(resp.get("status")),
            requested_qty=requested_qty,
            filled_qty=max(0.0, requested_qty - remaining_qty),
            remaining_qty=remaining_qty,
            avg_price=self._float(resp.get("filledAvgPrice")),
            message="close response received",
        )

    async def set_leverage(self, symbol: str, leverage: float) -> None:  # pragma: no cover - thin
        await self._put(f"/api/position/{symbol}", {"leverage": int(leverage)})

    async def set_protective_stop(
        self,
        symbol: str,
        stop_price: float,
        position_side: OrderSide,
        parent_order_id: str,
    ) -> ProtectiveStopAck:
        if not is_evedex_client_order_id(parent_order_id):
            raise ValueError("EVEDEX protective stop requires the authoritative parent order ID")
        message = {
            "instrument": symbol,
            "type": "stop-loss",
            # EVEDEX TpSl.side is the protected position side, not the side of
            # the market order that will eventually close that position.
            "side": position_side.value,
            "quantity": 0,
            "price": to_eth_number(stop_price),
            "order": parent_order_id,
        }
        signature = self._sign("New take-profit/stop-loss", message)
        resp = await self._post(
            f"/api/tpsl/{symbol}",
            {
                **message,
                "signature": signature,
            },
        )
        if str(resp.get("status", "")).casefold() not in {"waitorder", "active"}:
            raise ValueError("EVEDEX protective-stop create status is neither waitOrder nor active")
        # EVEDEX creates the TP/SL record ID.  It is deliberately not included
        # in ``message``; `order` above is the signed parent entry ID.
        server_id = resp.get("id")
        if server_id is None or not str(server_id).strip():
            raise ValueError("EVEDEX protective-stop response has no server-assigned ID")
        if not self.dry_run:
            records = self._as_list(await self._get("/api/tpsl"))
            matches = [item for item in records if str(item.get("id")) == str(server_id)]
            if len(matches) != 1:
                raise ValueError("EVEDEX protective-stop ID was not uniquely reconciled via GET /api/tpsl")
            self._validate_protective_stop_record(
                matches[0],
                symbol=symbol,
                position_side=position_side,
                parent_order_id=parent_order_id,
                stop_price=stop_price,
            )
        return ProtectiveStopAck(exchange_order_id=str(server_id))

    async def cancel_order_by_client_id(
        self,
        symbol: str,
        client_order_id: str,
    ) -> None:  # pragma: no cover - thin
        if not is_evedex_client_order_id(client_order_id):
            raise ValueError("EVEDEX cancellation requires a deterministic client order ID")
        if self.dry_run:
            return
        if not await self.is_order_active_by_client_id(symbol, client_order_id):
            return
        await self._bucket.acquire()
        session = await self._session_get()
        async with session.delete(f"{self.base}/api/order/{client_order_id}") as resp:
            resp.raise_for_status()

    async def is_order_active_by_client_id(self, symbol: str, client_order_id: str) -> bool:
        if not is_evedex_client_order_id(client_order_id):
            raise ValueError("EVEDEX reconciliation requires a deterministic client order ID")
        if self.dry_run:
            return False
        orders = self._as_list(await self._get("/api/order/opened"))
        return any(
            str(item.get("id")) == client_order_id
            and str(item.get("instrument", "")).upper() == symbol.upper()
            for item in orders
        )

    async def is_position_flat(self, symbol: str) -> bool:
        if self.dry_run:
            return True
        positions = self._as_list(await self._get("/api/position"))
        for item in positions:
            if str(item.get("instrument", "")).upper() != symbol.upper():
                continue
            if self._required_float(item.get("quantity"), f"{symbol}.quantity") > 0:
                return False
        return True

    @staticmethod
    def _validate_protective_stop_record(
        record: dict[str, Any],
        *,
        symbol: str,
        position_side: OrderSide,
        parent_order_id: str,
        stop_price: float,
    ) -> None:
        if str(record.get("instrument", "")).upper() != symbol.upper():
            raise ValueError("EVEDEX reconciled protective stop has the wrong instrument")
        stop_type = str(record.get("type", "")).casefold().replace("_", "-")
        if stop_type != "stop-loss":
            raise ValueError("EVEDEX reconciled protective stop has the wrong type")
        if str(record.get("side", "")).upper() != position_side.value:
            raise ValueError("EVEDEX reconciled protective stop has the wrong position side")
        status = str(record.get("status", "")).casefold()
        if status not in {"waitorder", "active"}:
            raise ValueError("EVEDEX reconciled protective stop is not in a protective lifecycle state")
        quantity = EvedexAdapter._required_float(record.get("quantity"), f"{symbol}.tpsl.quantity")
        if quantity != 0:
            raise ValueError("EVEDEX reconciled protective stop is not for the full position")
        reconciled_price = EvedexAdapter._required_float(
            record.get("price"),
            f"{symbol}.tpsl.price",
        )
        price_tolerance = max(1e-8, abs(stop_price) * 1e-9)
        if reconciled_price <= 0 or abs(reconciled_price - stop_price) > price_tolerance:
            raise ValueError("EVEDEX reconciled protective stop has the wrong price")
        echoed_parent = record.get("order")
        if echoed_parent is not None and str(echoed_parent) != parent_order_id:
            raise ValueError("EVEDEX reconciled protective stop has the wrong parent order")

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
        if self._required_bool(account.get("marginCall"), "marginCall"):
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

        stop_by_position: dict[tuple[str, str], str] = {}
        for item in tpsl:
            if str(item.get("type", "")).casefold() != "stop-loss" or str(
                item.get("status", "")
            ).casefold() not in {"waitorder", "active"}:
                continue
            instrument = str(item.get("instrument", "")).upper()
            side = str(item.get("side", "")).upper()
            stop_id = str(item.get("id", ""))
            if not instrument or side not in {"BUY", "SELL"} or not stop_id:
                raise ValueError("EVEDEX live protective stop has incomplete identity")
            quantity = self._required_float(
                item.get("quantity"),
                f"{instrument}.tpsl.quantity",
            )
            # The official contract defines zero as a full-position TP/SL.
            # A partial stop must not make the whole position look protected.
            if quantity == 0:
                stop_by_position.setdefault((instrument, side), stop_id)
        position_snapshots: list[PositionSnapshot] = []
        for position in positions:
            symbol = str(position.get("instrument", ""))
            quantity = self._required_float(position.get("quantity"), f"{symbol}.quantity")
            if quantity <= 0:
                continue
            position_snapshots.append(
                self._position_snapshot(
                    position,
                    account_id=account_id,
                    captured_at=captured_at,
                    protective_stop_id=stop_by_position.get(
                        (symbol.upper(), str(position.get("side", "")).upper())
                    ),
                )
            )
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
            self._required_float(item.get("quantity"), f"{symbol}.quantity")
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
        if not math.isfinite(result) or result < 0:
            raise ValueError(f"EVEDEX {field} must be finite and non-negative")
        return result

    @staticmethod
    def _optional_positive_float(value: Any) -> float | None:
        parsed = EvedexAdapter._float(value)
        return parsed if parsed > 0 else None

    @staticmethod
    def _required_bool(value: Any, field: str) -> bool:
        """Parse a required API boolean and reject undocumented representations."""
        if isinstance(value, bool):
            return value
        if isinstance(value, int) and value in {0, 1}:
            return bool(value)
        if isinstance(value, str):
            normalized = value.strip().casefold()
            if normalized in {"0", "false"}:
                return False
            if normalized in {"1", "true"}:
                return True
        raise ValueError(f"EVEDEX {field} is not a valid boolean")

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

    @staticmethod
    def _order_status(value: Any) -> OrderStatus:
        raw_status = str(value or "").upper().replace("CANCELLED", "CANCELED")
        if raw_status not in OrderStatus.__members__:
            raise ValueError(f"EVEDEX returned unknown order status {value!r}")
        return OrderStatus(raw_status)

    async def close(self) -> None:  # pragma: no cover
        if self._session is not None:
            await self._session.close()
