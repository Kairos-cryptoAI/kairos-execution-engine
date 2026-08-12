"""CCXT adapter — used to test strategies on Binance testnet and other venues."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

from kairos_core.contracts import AccountSnapshot, ExecutionReport, OrderIntent, PositionSnapshot
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
        return self._execution_report(
            order,
            symbol=intent.symbol,
            side=intent.side,
            requested=intent.quantity,
        )

    async def cancel_order(self, symbol, order_id):  # pragma: no cover
        if self.dry_run or self._client is None:
            return
        await self._client.cancel_order(order_id, symbol)

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
                open_positions = [item for item in positions if abs(self._float(item.get("contracts"))) > 0]
                position_sides = {str(item.get("side", "")).casefold() for item in open_positions}
                if len(position_sides) != 1 or not position_sides <= {"long", "short"}:
                    raise ValueError(f"cannot infer one-sided CCXT position for {symbol}")
                quantity = sum(abs(self._float(item.get("contracts"))) for item in open_positions)
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

    async def set_trailing_stop(self, symbol, stop_price, side):  # pragma: no cover
        if not self.dry_run and self._client is not None:
            await self._client.create_order(
                symbol,
                "STOP_MARKET",
                side.lower(),
                None,
                None,
                {
                    "stopPrice": stop_price,
                    "closePosition": True,
                    "reduceOnly": True,
                },
            )

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

        protective_stops: dict[str, str] = {}
        for order in orders:
            order_info = order.get("info", {}) if isinstance(order.get("info"), dict) else {}
            is_protective = bool(
                order.get("reduceOnly") or order_info.get("reduceOnly") or order_info.get("closePosition")
            ) and bool(order.get("stopPrice") or order_info.get("stopPrice"))
            if is_protective and order.get("id"):
                protective_stops[self._symbol(order.get("symbol"))] = str(order["id"])

        positions: list[PositionSnapshot] = []
        for item in raw_positions:
            contracts = abs(self._float(item.get("contracts")))
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
                    protective_stop_order_id=protective_stops.get(symbol),
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
        status_text = str(order.get("status", "open")).upper()
        status_map = {
            "OPEN": OrderStatus.NEW,
            "CLOSED": OrderStatus.FILLED,
            "CANCELED": OrderStatus.CANCELED,
            "REJECTED": OrderStatus.REJECTED,
            "EXPIRED": OrderStatus.REJECTED,
        }
        filled = CCXTAdapter._float(order.get("filled"))
        return ExecutionReport(
            source="execution-engine",
            client_order_id=str(order.get("clientOrderId") or order.get("id") or "unknown"),
            exchange_order_id=str(order["id"]) if order.get("id") is not None else None,
            exchange="ccxt",
            symbol=symbol,
            side=side,
            status=status_map.get(status_text, OrderStatus.NEW),
            requested_qty=requested,
            filled_qty=filled,
            remaining_qty=max(0.0, CCXTAdapter._float(order.get("remaining"), default=requested - filled)),
            avg_price=CCXTAdapter._float(order.get("average")),
        )

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
