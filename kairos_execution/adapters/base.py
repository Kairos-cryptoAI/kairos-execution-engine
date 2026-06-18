"""Exchange adapter interface — the engine only ever talks to this."""
from __future__ import annotations

import abc

from kairos_core.contracts import ExecutionReport, OrderIntent


class ExchangeAdapter(abc.ABC):
    name: str = "base"

    @abc.abstractmethod
    async def place_order(self, intent: OrderIntent) -> ExecutionReport: ...

    @abc.abstractmethod
    async def cancel_order(self, symbol: str, order_id: str) -> None: ...

    @abc.abstractmethod
    async def close_position(self, symbol: str) -> ExecutionReport: ...

    @abc.abstractmethod
    async def set_leverage(self, symbol: str, leverage: float) -> None: ...

    @abc.abstractmethod
    async def set_trailing_stop(self, symbol: str, stop_price: float, side: str) -> None: ...

    async def close(self) -> None:  # pragma: no cover
        return None
