"""Exchange adapter interface — the engine only ever talks to this."""

from __future__ import annotations

import abc
from dataclasses import dataclass

from kairos_core.contracts import AccountSnapshot, ExecutionReport, OrderIntent
from kairos_core.enums import OrderSide


@dataclass(frozen=True, slots=True)
class ProtectiveStopAck:
    """Venue acknowledgement for a newly created protective stop.

    The TP/SL identifier is assigned by the venue.  Callers may link a parent
    entry order where documented, but must not manufacture the TP/SL record ID.
    """

    exchange_order_id: str

    def __post_init__(self) -> None:
        if not self.exchange_order_id.strip():
            raise ValueError("protective-stop acknowledgement has no exchange order ID")


class ExchangeAdapter(abc.ABC):
    name: str = "base"
    exchange_order_id_matches_client_order_id: bool = False
    protective_stop_lookup_authoritative: bool = False

    @abc.abstractmethod
    async def place_order(self, intent: OrderIntent) -> ExecutionReport: ...

    @abc.abstractmethod
    async def cancel_order_by_client_id(self, symbol: str, client_order_id: str) -> None:
        """Cancel the unique active order submitted with ``client_order_id``.

        The caller deliberately supplies its deterministic pre-submission
        identity, never an exchange ID copied from an untrusted acknowledgement.
        Venue adapters must resolve that identity without falling back to a
        similarly shaped server ID.
        """

    @abc.abstractmethod
    async def is_order_active_by_client_id(self, symbol: str, client_order_id: str) -> bool:
        """Reconcile whether the deterministically submitted order can still fill."""

    @abc.abstractmethod
    async def is_position_flat(self, symbol: str) -> bool:
        """Reconcile whether the venue has no open position for ``symbol``."""

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
    async def set_protective_stop(
        self,
        symbol: str,
        stop_price: float,
        position_side: OrderSide,
        parent_order_id: str,
    ) -> ProtectiveStopAck:
        """Protect the position on ``position_side`` at ``stop_price``.

        Venue adapters own the mapping from position side to their wire-level
        TP/SL or closing-order side semantics.  ``parent_order_id`` is the
        trusted submitted entry identity; venues without linked TP/SL orders may
        ignore it.
        """

    async def find_protective_stop(
        self,
        symbol: str,
        stop_price: float,
        position_side: OrderSide,
        parent_order_id: str,
    ) -> ProtectiveStopAck | None:
        """Return one exact live stop, or ``None`` when the venue proves absence.

        Adapters that cannot query a parent-linked stop must retain the default
        fail-closed result; callers must not infer deduplication from geometry.
        """
        return None

    async def fetch_account_snapshot(
        self,
        *,
        account_id: str,
        peak_equity_usd: float,
    ) -> AccountSnapshot:
        raise NotImplementedError(f"{self.name} does not implement account reconciliation")

    async def close(self) -> None:  # pragma: no cover
        return None
