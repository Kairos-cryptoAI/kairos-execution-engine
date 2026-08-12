"""Deterministic execution state transitions and idempotency identity."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256

EVEDEX_CLIENT_ORDER_ID_RE = re.compile(r"^[0-9]{5}:[0-9A-Fa-f]{26}$")
EVEDEX_ORDER_ID_EPOCH = datetime(2025, 7, 24, tzinfo=UTC)


class ExecutionState(StrEnum):
    RECEIVED = "RECEIVED"
    SUBMITTING = "SUBMITTING"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    PARTIALLY_FILLED = "PARTIALLY_FILLED"
    FILLED = "FILLED"
    CANCELLED = "CANCELLED"
    REJECTED = "REJECTED"
    UNKNOWN = "UNKNOWN"


TERMINAL_STATES = {
    ExecutionState.FILLED,
    ExecutionState.CANCELLED,
    ExecutionState.REJECTED,
}
_ALLOWED = {
    ExecutionState.RECEIVED: {ExecutionState.SUBMITTING, ExecutionState.REJECTED},
    ExecutionState.SUBMITTING: {
        ExecutionState.ACKNOWLEDGED,
        ExecutionState.PARTIALLY_FILLED,
        ExecutionState.FILLED,
        ExecutionState.REJECTED,
        ExecutionState.UNKNOWN,
    },
    ExecutionState.ACKNOWLEDGED: {
        ExecutionState.PARTIALLY_FILLED,
        ExecutionState.FILLED,
        ExecutionState.CANCELLED,
        ExecutionState.REJECTED,
        ExecutionState.UNKNOWN,
    },
    ExecutionState.PARTIALLY_FILLED: {
        ExecutionState.PARTIALLY_FILLED,
        ExecutionState.FILLED,
        ExecutionState.CANCELLED,
        ExecutionState.UNKNOWN,
    },
    ExecutionState.UNKNOWN: {
        ExecutionState.ACKNOWLEDGED,
        ExecutionState.PARTIALLY_FILLED,
        ExecutionState.FILLED,
        ExecutionState.CANCELLED,
        ExecutionState.REJECTED,
    },
}


def client_order_id(
    validated_order_id: str,
    exchange: str,
    *,
    occurred_at: datetime | None = None,
) -> str:
    """Stable, exchange-safe ID: same input event always maps to the same order."""
    digest = sha256(f"kairos:v1:{exchange}:{validated_order_id}".encode()).hexdigest()[:32]
    if exchange.casefold() == "evedex":
        timestamp = occurred_at or datetime.now(UTC)
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=UTC)
        days_since_epoch = (timestamp.astimezone(UTC).date() - EVEDEX_ORDER_ID_EPOCH.date()).days
        if not 0 <= days_since_epoch <= 99_999:
            raise ValueError("EVEDEX order timestamp is outside the supported ID range")
        return f"{days_since_epoch:05d}:{digest[:26].upper()}"
    return f"krs-{digest}"


def is_evedex_client_order_id(value: str) -> bool:
    """Return whether ``value`` matches EVEDEX's wire-level client ID format."""
    return EVEDEX_CLIENT_ORDER_ID_RE.fullmatch(value) is not None


def is_fresh_evedex_client_order_id(value: str, *, now: datetime | None = None) -> bool:
    """EVEDEX accepts prefixes created today or yesterday (UTC)."""
    if not is_evedex_client_order_id(value):
        return False
    timestamp = now or datetime.now(UTC)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)
    current_day = (timestamp.astimezone(UTC).date() - EVEDEX_ORDER_ID_EPOCH.date()).days
    order_day = int(value[:5])
    return order_day in {current_day, current_day - 1}


@dataclass
class OrderState:
    client_order_id: str
    state: ExecutionState = ExecutionState.RECEIVED

    def transition(self, target: ExecutionState) -> None:
        if target not in _ALLOWED.get(self.state, set()):
            raise ValueError(f"invalid execution transition {self.state} -> {target}")
        self.state = target
