"""Kairos Layer 6 — deterministic execution without an LLM.

The engine submits a risk-validated order and requests one initial venue-side
protective stop.  It does not implement a live replace/cancel loop and therefore
does not claim dynamic trailing.  If protection is not acknowledged, it cancels
any active entry remainder and requires venue reconciliation to prove the
position flat before treating compensation as complete.
"""

from __future__ import annotations

__version__ = "0.1.0"

from .adapters.base import ExchangeAdapter, ProtectiveStopAck
from .crypto import EIP712_SCHEMAS, build_domain, to_eth_number
from .ratelimit import TokenBucket
from .reason_router import action_for
from .trailing import TrailingStop, TrailingStopManager

__all__ = [
    "to_eth_number",
    "EIP712_SCHEMAS",
    "build_domain",
    "TokenBucket",
    "action_for",
    "TrailingStop",
    "TrailingStopManager",
    "ExchangeAdapter",
    "ProtectiveStopAck",
    "__version__",
]
