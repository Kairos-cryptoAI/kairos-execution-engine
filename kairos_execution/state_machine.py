"""Deterministic execution state transitions and idempotency identity."""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256


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
    ExecutionState.FILLED, ExecutionState.CANCELLED, ExecutionState.REJECTED,
}
_ALLOWED = {
    ExecutionState.RECEIVED: {ExecutionState.SUBMITTING, ExecutionState.REJECTED},
    ExecutionState.SUBMITTING: {
        ExecutionState.ACKNOWLEDGED, ExecutionState.PARTIALLY_FILLED,
        ExecutionState.FILLED, ExecutionState.REJECTED, ExecutionState.UNKNOWN,
    },
    ExecutionState.ACKNOWLEDGED: {
        ExecutionState.PARTIALLY_FILLED, ExecutionState.FILLED,
        ExecutionState.CANCELLED, ExecutionState.REJECTED, ExecutionState.UNKNOWN,
    },
    ExecutionState.PARTIALLY_FILLED: {
        ExecutionState.PARTIALLY_FILLED, ExecutionState.FILLED,
        ExecutionState.CANCELLED, ExecutionState.UNKNOWN,
    },
    ExecutionState.UNKNOWN: {
        ExecutionState.ACKNOWLEDGED, ExecutionState.PARTIALLY_FILLED,
        ExecutionState.FILLED, ExecutionState.CANCELLED, ExecutionState.REJECTED,
    },
}


def client_order_id(validated_order_id: str, exchange: str) -> str:
    """Stable, exchange-safe ID: same input event always maps to the same order."""
    digest = sha256(f"kairos:v1:{exchange}:{validated_order_id}".encode()).hexdigest()[:32]
    return f"krs-{digest}"


@dataclass
class OrderState:
    client_order_id: str
    state: ExecutionState = ExecutionState.RECEIVED

    def transition(self, target: ExecutionState) -> None:
        if target not in _ALLOWED.get(self.state, set()):
            raise ValueError(f"invalid execution transition {self.state} -> {target}")
        self.state = target
