"""Admission status of EVEDEX native protection on the production venue."""

# The previous adapter sent the entry side on TP/SL. EVEDEX executed that
# direction. Portfolio admission requires verified use of the opposing side.
EVEDEX_NATIVE_PROTECTION_UNAVAILABLE = (
    "EVEDEX native stop-loss/take-profit is not qualified to reduce positions on production"
)


def reducing_side(position_side: str) -> str:
    """Exchange order direction that decreases an existing BUY or SELL position."""
    return {"BUY": "SELL", "SELL": "BUY"}[position_side]
