"""Protective-stop calculations and optional in-memory trailing state.

The manager can advance an anchor when a caller supplies reviewed price updates.
The execution service currently submits the initial computed stop to the venue;
it does not imply that the venue order is dynamically replaced by this module.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from kairos_core.enums import OrderSide


@dataclass
class TrailingStop:
    side: OrderSide
    trail_pct: float
    anchor: float  # best price seen so far (high for longs, low for shorts)

    def __post_init__(self) -> None:
        if not math.isfinite(self.anchor) or self.anchor <= 0:
            raise ValueError("trailing-stop anchor must be finite and positive")
        if not math.isfinite(self.trail_pct) or not 0 < self.trail_pct < 1:
            raise ValueError("trail_pct must be finite and within (0, 1)")

    def update(self, price: float) -> float:
        self._validate_price(price)
        if self.side is OrderSide.BUY:  # long: trail below the highest price
            self.anchor = max(self.anchor, price)
        else:
            self.anchor = min(self.anchor, price)  # short: trail above the lowest price
        return self.stop_price

    def is_triggered(self, price: float) -> bool:
        # Pure check against the current stop (does not advance the anchor).
        self._validate_price(price)
        if self.side is OrderSide.BUY:
            return price <= self.stop_price
        return price >= self.stop_price

    @staticmethod
    def _validate_price(price: float) -> None:
        if not math.isfinite(price) or price <= 0:
            raise ValueError("trailing-stop price must be finite and positive")

    @property
    def stop_price(self) -> float:
        if self.side is OrderSide.BUY:
            result = self.anchor * (1 - self.trail_pct)
        else:
            result = self.anchor * (1 + self.trail_pct)
        if not math.isfinite(result) or result <= 0:
            raise ValueError("computed protective-stop price must be finite and positive")
        return result


class TrailingStopManager:
    def __init__(self, default_trail_pct: float = 0.01) -> None:
        if not math.isfinite(default_trail_pct) or not 0 < default_trail_pct < 1:
            raise ValueError("default_trail_pct must be finite and within (0, 1)")
        self.default_trail_pct = default_trail_pct
        self._stops: dict[str, TrailingStop] = {}

    def open(
        self, symbol: str, side: OrderSide, entry_price: float, trail_pct: float | None = None
    ) -> TrailingStop:
        selected_trail = self.default_trail_pct if trail_pct is None else trail_pct
        ts = TrailingStop(side=side, trail_pct=selected_trail, anchor=entry_price)
        self._stops[symbol] = ts
        return ts

    def on_price(self, symbol: str, price: float) -> float | None:
        ts = self._stops.get(symbol)
        if not ts:
            return None
        return ts.update(price)

    def close(self, symbol: str) -> None:
        self._stops.pop(symbol, None)
