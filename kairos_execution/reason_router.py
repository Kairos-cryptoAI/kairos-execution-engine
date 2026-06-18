"""Translate a validated reason_code into a concrete execution action."""
from __future__ import annotations

from enum import Enum

from kairos_core.enums import OrderSide, ReasonCode


class Action(str, Enum):
    OPEN = "OPEN"
    CLOSE = "CLOSE"
    REDUCE = "REDUCE"
    NOOP = "NOOP"


def action_for(reason: ReasonCode) -> tuple[Action, OrderSide | None]:
    """Return ``(action, side)`` — the engine never free-interprets text, only this code."""
    return {
        ReasonCode.ENTER_LONG_TREND: (Action.OPEN, OrderSide.BUY),
        ReasonCode.ENTER_SHORT_TREND: (Action.OPEN, OrderSide.SELL),
        ReasonCode.CLOSE_POSITION: (Action.CLOSE, None),
        ReasonCode.REDUCE_LEVERAGE: (Action.REDUCE, None),
        ReasonCode.REBALANCE: (Action.OPEN, None),
        ReasonCode.HOLD: (Action.NOOP, None),
        ReasonCode.NO_TRADE: (Action.NOOP, None),
    }.get(reason, (Action.NOOP, None))
