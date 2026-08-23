"""PAPER-only adapter backed by the official EVEDEX Node SDK sidecar."""

from __future__ import annotations

import math
from datetime import UTC, datetime
from typing import Any, NoReturn

from kairos_core.contracts import AccountSnapshot, OrderIntent, PositionSnapshot
from kairos_core.enums import OrderSide

from ..sidecar import EvedexSidecarClient
from .base import ExchangeAdapter, ProtectiveStopAck


class LegacyPaperMutationRejected(RuntimeError):
    """PAPER must never consume the legacy ValidatedOrder mutation route."""


class EvedexSidecarAdapter(ExchangeAdapter):
    name = "evedex"
    exchange_order_id_matches_client_order_id = True
    protective_stop_lookup_authoritative = True

    def __init__(
        self,
        client: EvedexSidecarClient,
        *,
        symbol_map: dict[str, str],
    ) -> None:
        self.client = client
        self.symbol_map = {key.upper(): value.upper() for key, value in symbol_map.items()}
        self.reverse_symbol_map = {value: key for key, value in self.symbol_map.items()}

    async def preflight(self) -> dict[str, Any]:
        return self._object((await self.client.call("health"))["data"])

    async def place_market(
        self,
        *,
        effect_id: str,
        client_order_id: str,
        symbol: str,
        side: OrderSide,
        cash_quantity: float,
        leverage: float,
    ) -> dict[str, Any]:
        return self._object(
            (
                await self.client.call(
                    "place_market",
                    {
                        "effect_id": effect_id,
                        "client_order_id": client_order_id,
                        "instrument": self._venue_symbol(symbol),
                        "side": side.value,
                        "cash_quantity": cash_quantity,
                        "leverage": leverage,
                    },
                    mutation=True,
                )
            )["data"]
        )

    async def place_limit(
        self,
        *,
        effect_id: str,
        client_order_id: str,
        symbol: str,
        side: OrderSide,
        quantity: float,
        limit_price: float,
        leverage: float,
        post_only: bool = False,
    ) -> dict[str, Any]:
        return self._object(
            (
                await self.client.call(
                    "place_limit",
                    {
                        "effect_id": effect_id,
                        "client_order_id": client_order_id,
                        "instrument": self._venue_symbol(symbol),
                        "side": side.value,
                        "quantity": quantity,
                        "limit_price": limit_price,
                        "leverage": leverage,
                        "post_only": post_only,
                    },
                    mutation=True,
                )
            )["data"]
        )

    async def create_tpsl(
        self,
        *,
        effect_id: str,
        symbol: str,
        side: OrderSide,
        tpsl_type: str,
        quantity: float,
        price: float,
        parent_order_id: str,
    ) -> dict[str, Any]:
        return self._object(
            (
                await self.client.call(
                    "create_tpsl",
                    {
                        "effect_id": effect_id,
                        "instrument": self._venue_symbol(symbol),
                        "side": side.value,
                        "tpsl_type": tpsl_type,
                        "quantity": quantity,
                        "price": price,
                        "parent_order_id": parent_order_id,
                    },
                    mutation=True,
                )
            )["data"]
        )

    async def cancel_tpsl(self, *, effect_id: str, symbol: str, tpsl_id: str) -> dict[str, Any]:
        return self._object(
            (
                await self.client.call(
                    "cancel_tpsl",
                    {
                        "effect_id": effect_id,
                        "instrument": self._venue_symbol(symbol),
                        "tpsl_id": tpsl_id,
                    },
                    mutation=True,
                )
            )["data"]
        )

    async def paper_cancel_order(
        self, *, effect_id: str, symbol: str, client_order_id: str
    ) -> dict[str, Any]:
        return self._object(
            (
                await self.client.call(
                    "cancel_order",
                    {
                        "effect_id": effect_id,
                        "instrument": self._venue_symbol(symbol),
                        "client_order_id": client_order_id,
                    },
                    mutation=True,
                )
            )["data"]
        )

    async def paper_close_position(
        self,
        *,
        effect_id: str,
        client_order_id: str,
        symbol: str,
        quantity: float,
        leverage: float,
    ) -> dict[str, Any]:
        return self._object(
            (
                await self.client.call(
                    "close_position",
                    {
                        "effect_id": effect_id,
                        "client_order_id": client_order_id,
                        "instrument": self._venue_symbol(symbol),
                        "quantity": quantity,
                        "leverage": leverage,
                    },
                    mutation=True,
                )
            )["data"]
        )

    async def fetch_paper_state(self) -> dict[str, Any]:
        return self._object((await self.client.call("fetch_account"))["data"])

    async def fetch_depth(self, *, symbol: str, max_level: int = 100) -> dict[str, Any]:
        """Read the current authenticated SDK book without opening another network boundary."""
        if not 1 <= max_level <= 100:
            raise ValueError("EVEDEX depth level must be between 1 and 100")
        return self._object(
            (
                await self.client.call(
                    "fetch_depth",
                    {
                        "instrument": self._venue_symbol(symbol),
                        "max_level": max_level,
                    },
                )
            )["data"]
        )

    async def drain_events(self, *, limit: int = 100) -> list[dict[str, Any]]:
        result = self._object(
            (await self.client.call("drain_events", {"limit": max(1, min(limit, 1000))}))["data"]
        )
        return self._list(result.get("events"))

    async def find_tpsl_record(
        self,
        *,
        symbol: str,
        tpsl_id: str | None = None,
        tpsl_type: str | None = None,
        price: float | None = None,
        parent_order_id: str | None = None,
    ) -> dict[str, Any] | None:
        raw = (await self.client.call("fetch_tpsl", {"instrument": self._venue_symbol(symbol)}))["data"]
        matches: list[dict[str, Any]] = []
        expected_type = None if tpsl_type is None else tpsl_type.casefold().replace("_", "-")
        for item in self._list(raw):
            if tpsl_id is not None and str(item.get("id")) != tpsl_id:
                continue
            if expected_type is not None and str(item.get("type", "")).casefold() != expected_type:
                continue
            if price is not None and not math.isclose(
                self._float(item.get("price")), price, rel_tol=1e-9, abs_tol=1e-9
            ):
                continue
            # Published SDK TP/SL records do not expose parent lineage.
            # ``triggerOrder`` is the generated exit order after triggering,
            # never the parent entry order.
            parent = item.get("order")
            if parent_order_id is not None and str(parent or "") != parent_order_id:
                continue
            matches.append(item)
        if len(matches) > 1:
            raise ValueError("EVEDEX returned duplicate TP/SL records for one lifecycle role")
        return None if not matches else matches[0]

    async def place_order(self, intent: OrderIntent) -> NoReturn:
        self._reject_legacy()

    async def cancel_order_by_client_id(self, symbol: str, client_order_id: str) -> NoReturn:
        self._reject_legacy()

    async def close_position(
        self,
        symbol: str,
        *,
        quantity: float | None = None,
        side: OrderSide | None = None,
        client_order_id: str | None = None,
    ) -> NoReturn:
        self._reject_legacy()

    async def set_leverage(self, symbol: str, leverage: float) -> NoReturn:
        self._reject_legacy()

    async def set_protective_stop(
        self,
        symbol: str,
        stop_price: float,
        position_side: OrderSide,
        parent_order_id: str,
    ) -> NoReturn:
        self._reject_legacy()

    async def is_order_active_by_client_id(self, symbol: str, client_order_id: str) -> bool:
        raw = (await self.client.call("fetch_open_orders"))["data"]
        orders = self._list(raw)
        venue_symbol = self._venue_symbol(symbol)
        return any(
            str(order.get("id")) == client_order_id
            and str(order.get("instrument", "")).upper() == venue_symbol
            for order in orders
        )

    async def is_position_flat(self, symbol: str) -> bool:
        raw = (await self.client.call("fetch_positions"))["data"]
        venue_symbol = self._venue_symbol(symbol)
        return not any(
            str(position.get("instrument", "")).upper() == venue_symbol
            and self._float(position.get("quantity")) > 0
            for position in self._list(raw)
        )

    async def find_protective_stop(
        self,
        symbol: str,
        stop_price: float,
        position_side: OrderSide,
        parent_order_id: str,
    ) -> ProtectiveStopAck | None:
        raw = (await self.client.call("fetch_tpsl", {"instrument": self._venue_symbol(symbol)}))["data"]
        matches = [
            item
            for item in self._list(raw)
            if str(item.get("type", "")).casefold() == "stop-loss"
            and str(item.get("side", "")).upper() == position_side.value
            and str(item.get("order", "")) == parent_order_id
            and str(item.get("status", "")).casefold() in {"waitorder", "active"}
            and math.isclose(self._float(item.get("price")), stop_price, rel_tol=1e-9)
        ]
        if len(matches) > 1:
            raise ValueError("EVEDEX returned duplicate protective stops for one trade")
        if not matches:
            return None
        return ProtectiveStopAck(exchange_order_id=str(matches[0]["id"]))

    async def fetch_account_snapshot(self, *, account_id: str, peak_equity_usd: float) -> AccountSnapshot:
        state = await self.fetch_paper_state()
        balance = self._object(state.get("balance"))
        funding = self._object(balance.get("funding"))
        equity = self._float(funding.get("balance"))
        available = self._float(balance.get("availableBalance"))
        if equity <= 0 or available < 0:
            raise ValueError("EVEDEX sidecar returned invalid account balances")
        positions: list[PositionSnapshot] = []
        for item in self._list(state.get("positions")):
            quantity = self._float(item.get("quantity"))
            if quantity <= 0:
                continue
            venue_symbol = str(item.get("instrument", "")).upper()
            logical_symbol = self.reverse_symbol_map.get(venue_symbol)
            if logical_symbol is None:
                raise ValueError(f"unexpected EVEDEX DEV position {venue_symbol!r}")
            raw_side = str(item.get("side", "")).upper()
            if raw_side not in {"BUY", "SELL"}:
                raise ValueError("EVEDEX position has an invalid side")
            entry = self._float(item.get("avgPrice"))
            mark = self._float(item.get("markPrice"), default=entry)
            positions.append(
                PositionSnapshot(
                    source="kairos-execution-engine",
                    exchange=self.name,
                    account_id=account_id,
                    symbol=logical_symbol,
                    signed_quantity=quantity if raw_side == "BUY" else -quantity,
                    entry_price=entry,
                    mark_price=mark,
                    leverage=max(1.0, self._float(item.get("leverage"), default=1.0)),
                    unrealized_pnl_usd=self._float(item.get("unRealizedPnL", item.get("unrealizedPnL"))),
                    captured_at=datetime.now(UTC),
                )
            )
        orders = self._list(state.get("orders"))
        return AccountSnapshot(
            source="kairos-execution-engine",
            exchange=self.name,
            account_id=account_id,
            equity_usd=equity,
            available_balance_usd=available,
            peak_equity_usd=max(peak_equity_usd, equity),
            positions=positions,
            open_order_ids=[str(order["id"]) for order in orders if order.get("id")],
            captured_at=datetime.now(UTC),
            reconciled=True,
            reconciliation_detail="official SDK preflight and authoritative account fetch succeeded",
        )

    async def close(self) -> None:
        await self.client.close()

    def _venue_symbol(self, symbol: str) -> str:
        try:
            return self.symbol_map[symbol.upper()]
        except KeyError as exc:
            raise ValueError(f"symbol {symbol!r} is outside the PAPER allowlist") from exc

    @staticmethod
    def _reject_legacy() -> NoReturn:
        raise LegacyPaperMutationRejected(
            "PAPER rejects legacy TacticalCommand/ValidatedOrder exchange mutations"
        )

    @staticmethod
    def _object(value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise ValueError("EVEDEX sidecar returned a non-object")
        return value

    @staticmethod
    def _list(value: Any) -> list[dict[str, Any]]:
        if isinstance(value, dict) and isinstance(value.get("list"), list):
            value = value["list"]
        if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
            raise ValueError("EVEDEX sidecar returned a malformed list")
        return value

    @staticmethod
    def _float(value: Any, *, default: float = 0.0) -> float:
        try:
            result = default if value is None else float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("EVEDEX sidecar numeric field is malformed") from exc
        if not math.isfinite(result):
            raise ValueError("EVEDEX sidecar numeric field is non-finite")
        return result
