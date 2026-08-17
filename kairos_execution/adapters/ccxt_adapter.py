"""CCXT adapter — used to test strategies on Binance testnet and other venues."""

from __future__ import annotations

import asyncio
import math
from datetime import UTC, datetime
from typing import Any

from kairos_core.contracts import AccountSnapshot, ExecutionReport, OrderIntent, PositionSnapshot
from kairos_core.enums import OrderSide, OrderStatus, OrderType

from .base import ExchangeAdapter, ProtectiveStopAck

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
        dry_run_equity_usd: float = 10_000.0,
    ) -> None:
        self.dry_run = dry_run
        self.dry_run_equity_usd = dry_run_equity_usd
        self._client = None
        if ccxt is not None and not dry_run:  # pragma: no cover - network
            self._client = getattr(ccxt, exchange_id)(
                {"apiKey": api_key, "secret": secret, "options": {"defaultType": "future"}}
            )
            if sandbox:
                self._client.set_sandbox_mode(True)

    async def place_order(self, intent: OrderIntent) -> ExecutionReport:
        if self.dry_run or self._client is None:
            client_id = intent.client_order_id or "dry"
            return ExecutionReport(
                source="execution-engine",
                client_order_id=client_id,
                exchange_order_id=f"dry-{client_id}",
                exchange=self.name,
                symbol=intent.symbol,
                side=intent.side,
                status=OrderStatus.NEW,
                requested_qty=intent.quantity,
                remaining_qty=intent.quantity,
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
        return self._execution_report(
            order,
            symbol=intent.symbol,
            side=intent.side,
            requested=intent.quantity,
        )

    async def cancel_order_by_client_id(
        self,
        symbol: str,
        client_order_id: str,
    ) -> None:  # pragma: no cover
        if self.dry_run or self._client is None:
            return
        order = await self._open_order_by_client_id(symbol, client_order_id)
        if order is None:
            return
        exchange_order_id = order.get("id")
        if exchange_order_id is None or not str(exchange_order_id).strip():
            raise ValueError("CCXT open order matched client ID but has no exchange order ID")
        await self._client.cancel_order(str(exchange_order_id), symbol)

    async def is_order_active_by_client_id(self, symbol: str, client_order_id: str) -> bool:
        if self.dry_run or self._client is None:
            return False
        return await self._open_order_by_client_id(symbol, client_order_id) is not None

    async def is_position_flat(self, symbol: str) -> bool:
        if self.dry_run or self._client is None:
            return True
        positions = await self._client.fetch_positions([symbol])
        for position in positions:
            contracts = self._required_contracts(position)
            if abs(contracts) > 0:
                return False
        return True

    async def close_position(
        self,
        symbol,
        *,
        quantity=None,
        side=None,
        client_order_id=None,
    ):  # pragma: no cover
        if not self.dry_run and self._client is not None:
            if quantity is None:
                positions = await self._client.fetch_positions([symbol])
                open_positions = [item for item in positions if self._required_contracts(item) > 0]
                position_sides = {str(item.get("side", "")).casefold() for item in open_positions}
                if len(position_sides) != 1 or not position_sides <= {"long", "short"}:
                    raise ValueError(f"cannot infer one-sided CCXT position for {symbol}")
                quantity = sum(self._required_contracts(item) for item in open_positions)
                side = OrderSide.SELL if position_sides == {"long"} else OrderSide.BUY
            if not quantity or quantity <= 0:
                raise ValueError(f"no open CCXT position for {symbol}")
            close_side = side or OrderSide.SELL
            order = await self._client.create_order(
                symbol,
                "market",
                close_side.value.lower(),
                quantity,
                None,
                {"reduceOnly": True, "clientOrderId": client_order_id},
            )
            return self._execution_report(order, symbol=symbol, side=close_side, requested=quantity)
        return ExecutionReport(
            source="execution-engine",
            client_order_id=client_order_id or "dry-close",
            symbol=symbol,
            side=side or OrderSide.BUY,
            status=OrderStatus.NEW,
            requested_qty=quantity or 0,
            message="dry_run",
        )

    async def set_leverage(self, symbol, leverage):  # pragma: no cover
        if not self.dry_run and self._client is not None:
            await self._client.set_leverage(int(leverage), symbol)

    async def set_protective_stop(
        self,
        symbol: str,
        stop_price: float,
        position_side: OrderSide,
        parent_order_id: str,
    ) -> ProtectiveStopAck:  # pragma: no cover
        del parent_order_id  # CCXT venues do not expose a portable linked-stop field.
        close_side = OrderSide.SELL if position_side is OrderSide.BUY else OrderSide.BUY
        if not self.dry_run and self._client is not None:
            order = await self._client.create_order(
                symbol,
                "STOP_MARKET",
                close_side.value.lower(),
                None,
                None,
                {
                    "stopPrice": stop_price,
                    "closePosition": True,
                    "reduceOnly": True,
                },
            )
            if not isinstance(order, dict):
                raise ValueError("CCXT protective-stop response is not an order object")
            order_id = order.get("id")
            if order_id is None or not str(order_id).strip():
                raise ValueError("CCXT protective-stop response has no exchange order ID")
            if str(order.get("status") or "").casefold() not in {"new", "open"}:
                raise ValueError("CCXT protective-stop response is not in a live order state")
            return ProtectiveStopAck(exchange_order_id=str(order_id))
        return ProtectiveStopAck(exchange_order_id=f"dry-protective-{symbol}")

    async def fetch_account_snapshot(
        self,
        *,
        account_id: str,
        peak_equity_usd: float,
    ) -> AccountSnapshot:
        captured_at = datetime.now(UTC)
        if self.dry_run or self._client is None:
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

        balance, raw_positions, orders = await asyncio.gather(
            self._client.fetch_balance(),
            self._client.fetch_positions(),
            self._client.fetch_open_orders(),
        )
        info = balance.get("info", {}) if isinstance(balance, dict) else {}
        if not isinstance(info, dict):
            info = {}
        total = self._balance_currency(balance, "total", "USDT")
        free = self._balance_currency(balance, "free", "USDT")
        equity = self._first_positive(info.get("totalMarginBalance"), total)
        available = self._first_nonnegative(info.get("availableBalance"), free)
        if equity <= 0:
            raise ValueError("CCXT account equity is not positive")

        protective_stops: dict[tuple[str, str], str] = {}
        for order in orders:
            order_info = order.get("info", {}) if isinstance(order.get("info"), dict) else {}
            is_close_position = self._is_true(order.get("closePosition")) or self._is_true(
                order_info.get("closePosition")
            )
            stop_price = self._float(order.get("stopPrice") or order_info.get("stopPrice"))
            close_side = str(order.get("side") or order_info.get("side") or "").casefold()
            order_id = order.get("id")
            if (
                is_close_position
                and math.isfinite(stop_price)
                and stop_price > 0
                and close_side in {"buy", "sell"}
                and order_id is not None
                and str(order_id).strip()
            ):
                position_side = "SELL" if close_side == "buy" else "BUY"
                protective_stops.setdefault(
                    (self._symbol(order.get("symbol")), position_side),
                    str(order_id),
                )

        positions: list[PositionSnapshot] = []
        for item in raw_positions:
            contracts = self._required_contracts(item)
            if contracts <= 0:
                continue
            side_text = str(item.get("side", "")).casefold()
            if side_text not in {"long", "short"}:
                raise ValueError("CCXT position has no normalized long/short side")
            symbol = self._symbol(item.get("symbol"))
            entry = self._float(item.get("entryPrice"))
            mark = self._float(item.get("markPrice"), default=entry)
            if not symbol or entry <= 0 or mark <= 0:
                raise ValueError("CCXT position is missing symbol, entry price, or mark price")
            positions.append(
                PositionSnapshot(
                    source="kairos-execution-engine",
                    exchange=self.name,
                    account_id=account_id,
                    symbol=symbol,
                    signed_quantity=contracts if side_text == "long" else -contracts,
                    entry_price=entry,
                    mark_price=mark,
                    leverage=max(1.0, self._float(item.get("leverage"), default=1.0)),
                    liquidation_price=self._positive_or_none(item.get("liquidationPrice")),
                    unrealized_pnl_usd=self._float(item.get("unrealizedPnl")),
                    protective_stop_order_id=protective_stops.get(
                        (symbol, "BUY" if side_text == "long" else "SELL")
                    ),
                    captured_at=captured_at,
                )
            )

        unrealized = self._float(
            info.get("totalUnrealizedProfit"),
            default=sum(position.unrealized_pnl_usd for position in positions),
        )
        margin_used = self._float(
            info.get("totalInitialMargin"),
            default=sum(self._float(item.get("initialMargin")) for item in raw_positions),
        )
        return AccountSnapshot(
            source="kairos-execution-engine",
            exchange=self.name,
            account_id=account_id,
            equity_usd=equity,
            available_balance_usd=max(0.0, available),
            margin_used_usd=max(0.0, margin_used),
            peak_equity_usd=max(peak_equity_usd, equity),
            unrealized_pnl_usd=unrealized,
            positions=positions,
            open_order_ids=[str(order["id"]) for order in orders if order.get("id")],
            captured_at=captured_at,
            reconciled=True,
            reconciliation_detail=(
                f"CCXT fetched balance, {len(positions)} positions, and {len(orders)} open orders"
            ),
        )

    @staticmethod
    def _execution_report(order: dict[str, Any], *, symbol: str, side: OrderSide, requested: float):
        status_text = str(order.get("status") or "").upper()
        status_map = {
            "OPEN": OrderStatus.NEW,
            "CLOSED": OrderStatus.FILLED,
            "CANCELED": OrderStatus.CANCELED,
            "CANCELLED": OrderStatus.CANCELED,
            "REJECTED": OrderStatus.REJECTED,
            "EXPIRED": OrderStatus.REJECTED,
            "PARTIALLY_FILLED": OrderStatus.PARTIALLY_FILLED,
        }
        filled = CCXTAdapter._float(order.get("filled"))
        try:
            status = status_map[status_text]
        except KeyError as exc:
            raise ValueError(f"CCXT returned unknown order status {order.get('status')!r}") from exc
        if status is OrderStatus.NEW and filled > 0:
            status = OrderStatus.PARTIALLY_FILLED
        return ExecutionReport(
            source="execution-engine",
            client_order_id=CCXTAdapter._client_order_identity(order) or "unknown",
            exchange_order_id=str(order["id"]) if order.get("id") is not None else None,
            exchange="ccxt",
            symbol=symbol,
            side=side,
            status=status,
            requested_qty=requested,
            filled_qty=filled,
            remaining_qty=max(0.0, CCXTAdapter._float(order.get("remaining"), default=requested - filled)),
            avg_price=CCXTAdapter._float(order.get("average")),
        )

    async def _open_order_by_client_id(
        self,
        symbol: str,
        client_order_id: str,
    ) -> dict[str, Any] | None:
        """Resolve one active CCXT order without treating a server ID as a client ID."""
        if not client_order_id.strip():
            raise ValueError("CCXT client order ID must not be empty")
        if self._client is None:
            raise RuntimeError("CCXT client is not initialized")
        orders = await self._client.fetch_open_orders(symbol)
        matches = [order for order in orders if self._client_order_identity(order) == client_order_id]
        if len(matches) > 1:
            raise ValueError(f"multiple CCXT open orders have client ID {client_order_id!r}")
        return matches[0] if matches else None

    @staticmethod
    def _client_order_identity(order: Any) -> str | None:
        if not isinstance(order, dict):
            return None
        info = order.get("info")
        sources = (order, info if isinstance(info, dict) else {})
        for source in sources:
            for key in (
                "clientOrderId",
                "clientOrderID",
                "clientOid",
                "clOrdId",
                "origClientOrderId",
            ):
                value = source.get(key)
                if value is not None and str(value).strip():
                    return str(value)
        return None

    @staticmethod
    def _is_true(value: Any) -> bool:
        """Parse exchange boolean flags without treating ``"false"`` as true."""
        if value is True:
            return True
        if isinstance(value, int) and not isinstance(value, bool):
            return value == 1
        return isinstance(value, str) and value.strip().casefold() in {"1", "true"}

    @staticmethod
    def _required_contracts(position: Any) -> float:
        if not isinstance(position, dict) or position.get("contracts") is None:
            raise ValueError("CCXT position is missing contracts")
        try:
            contracts = float(position["contracts"])
        except (TypeError, ValueError) as exc:
            raise ValueError("CCXT position contracts is not numeric") from exc
        if not math.isfinite(contracts) or contracts < 0:
            raise ValueError("CCXT position contracts must be finite and non-negative")
        return contracts

    @staticmethod
    def _balance_currency(balance: Any, field: str, currency: str) -> float:
        if not isinstance(balance, dict):
            return 0.0
        values = balance.get(field, {})
        return CCXTAdapter._float(values.get(currency)) if isinstance(values, dict) else 0.0

    @staticmethod
    def _symbol(value: Any) -> str:
        return str(value or "").replace("/", "").split(":", maxsplit=1)[0].upper()

    @staticmethod
    def _float(value: Any, *, default: float = 0.0) -> float:
        try:
            return float(value) if value is not None else default
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _first_positive(*values: Any) -> float:
        return next((parsed for value in values if (parsed := CCXTAdapter._float(value)) > 0), 0.0)

    @staticmethod
    def _first_nonnegative(*values: Any) -> float:
        for value in values:
            parsed = CCXTAdapter._float(value, default=-1.0)
            if parsed >= 0:
                return parsed
        return 0.0

    @staticmethod
    def _positive_or_none(value: Any) -> float | None:
        parsed = CCXTAdapter._float(value)
        return parsed if parsed > 0 else None

    async def close(self):  # pragma: no cover
        if self._client is not None:
            await self._client.close()
