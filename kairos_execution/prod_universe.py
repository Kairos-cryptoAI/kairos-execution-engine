"""The owner-reviewed EVEDEX PROD universe of the production path.

Binance USD-M signal symbol to EVEDEX PROD instrument, the same closed pairs as
``kairos_quant.runtime_venue_gate.PROD_SYMBOL_MAP`` (Quant Scouts can measure venue quality
only for these). A deployment's custody binding approves a non-empty subset of the venue
instruments, and its lifecycle symbol map covers exactly that subset. Adding a pair here
is an owner decision recorded in source, never a runtime setting.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Final

PROD_SYMBOL_MAP: Final = MappingProxyType(
    {
        "BTCUSDT": "BTCUSD",
        "ETHUSDT": "ETHUSD",
        "SOLUSDT": "SOLUSD",
        "BNBUSDT": "BNBUSD",
        "XRPUSDT": "XRPUSD",
        # Added 2026-11-13 by owner decision for the live runner (kairos-autotrader).
        "AAVEUSDT": "AAVEUSD",
        "DOGEUSDT": "DOGEUSD",
        "HYPEUSDT": "HYPEUSD",
        "LINKUSDT": "LINKUSD",
        "SUIUSDT": "SUIUSD",
        "ZECUSDT": "ZECUSD",
        # Added 2026-11-16 by owner decision: thirteen more pairs with a Binance USD-M
        # contract, open EVEDEX trading, a spread of about 5 bps or less and a deep book.
        "ENAUSDT": "ENAUSD",
        "1000PEPEUSDT": "1000PEPEUSD",
        "LTCUSDT": "LTCUSD",
        "TRXUSDT": "TRXUSD",
        "ARBUSDT": "ARBUSD",
        "TAOUSDT": "TAOUSD",
        "APTUSDT": "APTUSD",
        "1000BONKUSDT": "1000BONKUSD",
        "VIRTUALUSDT": "VIRTUALUSD",
        "BCHUSDT": "BCHUSD",
        "OPUSDT": "OPUSD",
        "DOTUSDT": "DOTUSD",
        "AVAXUSDT": "AVAXUSD",
    }
)
PROD_INSTRUMENTS: Final = frozenset(PROD_SYMBOL_MAP.values())


DEV_INSTRUMENTS: Final = frozenset(f"{instrument}:DEV" for instrument in PROD_INSTRUMENTS)


def valid_instrument_set(instruments: object) -> bool:
    """A non-empty collection of distinct reviewed instruments, all PROD or all DEV.

    Local custody also signs for the EVEDEX DEV profile, whose instruments carry the
    ``:DEV`` suffix; production paths refuse ``:DEV`` instruments separately.
    """
    if not isinstance(instruments, (tuple, list)) or not instruments:
        return False
    if not all(isinstance(item, str) and item for item in instruments):
        return False
    unique = set(instruments)
    return len(unique) == len(instruments) and (unique <= PROD_INSTRUMENTS or unique <= DEV_INSTRUMENTS)


__all__ = ["DEV_INSTRUMENTS", "PROD_INSTRUMENTS", "PROD_SYMBOL_MAP", "valid_instrument_set"]
