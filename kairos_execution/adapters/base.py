"""Exchange adapter interface — the engine only ever talks to this."""

from __future__ import annotations

import abc

from kairos_core.contracts import AccountSnapshot, ExecutionReport, OrderIntent
from kairos_core.enums import OrderSide


class ExchangeAdapter(abc.ABC):
    name: str = "base"

    @abc.abstractmethod
    async def place_order(self, intent: OrderIntent) -> ExecutionReport: ...

    @abc.abstractmethod
    async def cancel_order(self, symbol: str, order_id: str) -> None: ...

    @abc.abstractmethod
    async def close_position(
        self,
        symbol: str,
        *,
        quantity: float | None = None,
        side: OrderSide | None = None,
        client_order_id: str | None = None,
    ) -> ExecutionReport: ...

    @abc.abstractmethod
    async def set_leverage(self, symbol: str, leverage: float) -> None: ...

    @abc.abstractmethod
    async def set_trailing_stop(self, symbol: str, stop_price: float, side: str) -> None: ...

    async def fetch_account_snapshot(
        self,
        *,
        account_id: str,
        peak_equity_usd: float,
    ) -> AccountSnapshot:
        raise NotImplementedError(f"{self.name} does not implement account reconciliation")

    async def close(self) -> None:  # pragma: no cover
        return None
