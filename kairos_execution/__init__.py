"""Kairos Layer 6 — Execution Engine.

The hands of the system (no LLM). It consumes a risk-validated order, switches on
its ``reason_code`` and places atomic orders on the exchange, always attaching a
server-side protective stop so a position is never left naked if the bot loses
connectivity. Ships with an EVEDEX adapter (EIP-712 signed) and a CCXT adapter
for testing on other venues.
"""
from __future__ import annotations

__version__ = "0.1.0"

from .crypto import to_eth_number, EIP712_SCHEMAS, build_domain
from .ratelimit import TokenBucket
from .reason_router import action_for
from .trailing import TrailingStop, TrailingStopManager
from .adapters.base import ExchangeAdapter

__all__ = ["to_eth_number", "EIP712_SCHEMAS", "build_domain", "TokenBucket",
           "action_for", "TrailingStop", "TrailingStopManager", "ExchangeAdapter", "__version__"]
