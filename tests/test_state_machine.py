import re
from datetime import UTC, datetime

import pytest

from kairos_execution.state_machine import (
    ExecutionState,
    OrderState,
    client_order_id,
    is_fresh_evedex_client_order_id,
)

NOW = datetime(2026, 8, 12, 12, tzinfo=UTC)


def test_client_order_id_is_deterministic_and_exchange_scoped():
    first = client_order_id("validated-1", "evedex", occurred_at=NOW)
    assert first == client_order_id("validated-1", "evedex", occurred_at=NOW)
    assert first != client_order_id("validated-1", "ccxt")
    assert len(first) <= 64


def test_evedex_client_order_id_matches_exchange_format_and_is_deterministic():
    first = client_order_id("validated-1", "evedex", occurred_at=NOW)
    assert first == client_order_id("validated-1", "evedex", occurred_at=NOW)
    assert first != client_order_id("validated-2", "evedex", occurred_at=NOW)
    assert re.fullmatch(r"[0-9]{5}:[0-9A-Fa-f]{26}", first)
    assert first.startswith("00384:")
    assert is_fresh_evedex_client_order_id(first, now=NOW)
    assert not is_fresh_evedex_client_order_id("00382:" + first.split(":", 1)[1], now=NOW)


def test_happy_path_and_partial_fill_transitions():
    order = OrderState("krs-1")
    order.transition(ExecutionState.SUBMITTING)
    order.transition(ExecutionState.ACKNOWLEDGED)
    order.transition(ExecutionState.PARTIALLY_FILLED)
    order.transition(ExecutionState.FILLED)
    assert order.state is ExecutionState.FILLED


def test_terminal_and_invalid_transitions_are_rejected():
    order = OrderState("krs-1")
    with pytest.raises(ValueError, match="invalid execution transition"):
        order.transition(ExecutionState.FILLED)
    order.transition(ExecutionState.REJECTED)
    with pytest.raises(ValueError):
        order.transition(ExecutionState.SUBMITTING)


def test_unknown_state_can_only_be_resolved_from_exchange_lookup():
    order = OrderState("krs-1")
    order.transition(ExecutionState.SUBMITTING)
    order.transition(ExecutionState.UNKNOWN)
    order.transition(ExecutionState.ACKNOWLEDGED)
    assert order.state is ExecutionState.ACKNOWLEDGED
