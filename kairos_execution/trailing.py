"""Server-side trailing-stop tracking.

A trailing stop follows the best price reached since entry by ``trail_pct``. The
engine pushes the computed stop to the exchange as a TP/SL order so the position
stays protected even if the bot disconnects (spec, Layer 6).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict

from kairos_core.enums import OrderSide


@dataclass
class TrailingStop:
    side: OrderSide
    trail_pct: float
    anchor: float            # best price seen so far (high for longs, low for shorts)

    def update(self, price: float) -> float:
        if self.side is OrderSide.BUY:      # long: trail below the highest price
            self.anchor = max(self.anchor, price)
            return self.anchor * (1 - self.trail_pct)
        self.anchor = min(self.anchor, price)  # short: trail above the lowest price
        return self.anchor * (1 + self.trail_pct)

    def is_triggered(self, price: float) -> bool:
        # Pure check against the current stop (does not advance the anchor).
        if self.side is OrderSide.BUY:
            return price <= self.stop_price
        return price >= self.stop_price

    @property
    def stop_price(self) -> float:
        if self.side is OrderSide.BUY:
            return self.anchor * (1 - self.trail_pct)
        return self.anchor * (1 + self.trail_pct)


class TrailingStopManager:
    def __init__(self, default_trail_pct: float = 0.01) -> None:
        self.default_trail_pct = default_trail_pct
        self._stops: Dict[str, TrailingStop] = {}

    def open(
        self, symbol: str, side: OrderSide, entry_price: float, trail_pct: float | None = None
    ) -> TrailingStop:
        ts = TrailingStop(side=side, trail_pct=trail_pct or self.default_trail_pct, anchor=entry_price)
        self._stops[symbol] = ts
        return ts

    def on_price(self, symbol: str, price: float) -> float | None:
        ts = self._stops.get(symbol)
        if not ts:
            return None
        return ts.update(price)

    def close(self, symbol: str) -> None:
        self._stops.pop(symbol, None)
