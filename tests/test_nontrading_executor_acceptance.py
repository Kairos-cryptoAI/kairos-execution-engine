"""Finite DB-backed executor lifecycle acceptance; never a venue qualification.

This composes the real PAPER state machine, PostgreSQL lifecycle/effect journals,
and recovery path with the existing deterministic local adapter double. It does
not exercise an exchange, signing custody, provider, strategy, or profitability.
"""

from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from kairos_core.enums import OrderRole, TradeExecutionEventType, TradeExitReason
from kairos_persistence import (
    Database,
    ExecutionJournalRepository,
    TradeLifecycleRepository,
    TradeState,
)

from kairos_execution.paper_engine import PaperExecutionEngine, PaperExecutionSafetyError
from tests.canary_admission_fixtures import LayeredCanaryAdmission, expected_scope
from tests.paper_fixtures import LayeredOperatorControl, approved_decision
from tests.test_integration_paper_engine import (
    FakePaperAdapter,
    MutableClock,
)

pytest_plugins = ("tests.test_integration_paper_engine",)
pytestmark = pytest.mark.integration


class PartialFillAdapter(FakePaperAdapter):
    """Local transport double that leaves half the requested entry unfilled."""

    async def place_limit(self, **kwargs: Any) -> dict[str, Any]:
        client_order_id = str(kwargs["client_order_id"])
        response = self.simulate_filled_entry(
            client_order_id,
            side=kwargs["side"],
            leverage=float(kwargs["leverage"]),
            quantity=float(kwargs["quantity"]),
            limit_price=float(kwargs["limit_price"]),
        )
        response["status"] = "PARTIALLY_FILLED"
        response["unFilledQuantity"] = float(kwargs["quantity"]) / 2
        filled_quantity = float(kwargs["quantity"]) / 2
        self.state["positions"][0]["quantity"] = filled_quantity
        self.state["balance"]["positions"][0]["volume"] = filled_quantity
        self.state["orders"] = [response]
        self.state["balance"]["openOrders"] = [response]
        self.state["order_history"] = [response]
        self.calls.append("ENTRY")
        return copy.deepcopy(response)


def _engine(
    database: Database,
    settings: Any,
    clock: MutableClock,
    adapter: PartialFillAdapter,
    operator: LayeredOperatorControl,
) -> PaperExecutionEngine:
    return PaperExecutionEngine(
        adapter,  # type: ignore[arg-type] -- intentional local transport double
        TradeLifecycleRepository(database.pool),
        ExecutionJournalRepository(database.pool),
        settings,
        clock=clock,
        canary_sessions=LayeredCanaryAdmission(),
        canary_scope=expected_scope(settings),
        operator_control=operator,
    )


async def test_finite_nonstrategy_executor_lifecycle_survives_recovery_and_deduplicates(
    paper_runtime,
) -> None:
    """Exercise durable executor behavior with fixed local decision/venue doubles only."""
    database, settings, clock = paper_runtime
    adapter = PartialFillAdapter(clock)
    operator = LayeredOperatorControl()
    decision = approved_decision()
    assert decision.source == "risk-manager"
    assert decision.intent.source == "kairos-paper-canary"
    assert decision.review.reviewer == "DETERMINISTIC"
    engine = _engine(database, settings, clock, adapter, operator)
    assert await engine.initialize_recovery() == ()

    # Stale decision evidence is refused before any durable or transport effect.
    clock.value = datetime.fromtimestamp((decision.venue_quality.expires_at_ms + 1) / 1000, tz=UTC)
    with pytest.raises(PaperExecutionSafetyError, match="venue quality expired"):
        await engine.handle(decision)
    assert adapter.calls == []
    entry_effect_id = engine._effect_id(decision.trade_id, OrderRole.ENTRY, "place")
    assert await engine.effects.get(entry_effect_id) is None

    # The same immutable decision, now within its evidence window, enters and
    # immediately protects the observed partial fill before remainder cancel.
    clock.value = datetime.fromtimestamp((decision.decided_at_ms + 100) / 1000, tz=UTC)
    opened = await engine.handle(decision)
    assert any(event.event_type is TradeExecutionEventType.ENTRY_PARTIAL_FILL for event in opened.events)
    assert adapter.calls[:3] == ["ENTRY", "STOP_LOSS", "TAKE_PROFIT"]
    telemetry = dict(engine.operational_telemetry)
    assert telemetry["evedex_local_mutation_capacity"] == "30"
    assert telemetry["evedex_local_mutation_compensation_reserve"] == "4"
    trade = await engine.trades.get(decision.trade_id)
    assert trade is not None and trade.state is TradeState.ACTIVE and trade.timeout_at is not None
    # EVEDEX quantity=0 explicitly protects the whole current position, including
    # its partial fill; it must not be confused with the requested entry size.
    assert adapter.state["positions"][0]["quantity"] == pytest.approx(decision.quantity / 2)
    assert adapter.state["tpsl"][0]["quantity"] == 0

    # Expiry cancels only the unfilled remainder; the protected partial remains.
    clock.value = datetime.fromtimestamp((decision.intent.entry_expires_ts_ms + 1) / 1000, tz=UTC)
    await engine.reconcile_once()
    assert adapter.calls.count("CANCEL_ENTRY") == 1
    trade = await engine.trades.get(decision.trade_id)
    assert trade is not None and trade.state is TradeState.ACTIVE

    # Process loss/reconstruction uses the same durable DB and adapter state.
    restarted = _engine(database, settings, clock, adapter, operator)
    assert await restarted.initialize_recovery() == ()
    replay = await restarted.handle(decision)
    assert replay.events == ()
    assert adapter.calls.count("ENTRY") == 1
    assert adapter.calls.count("STOP_LOSS") == 1
    assert adapter.calls.count("TAKE_PROFIT") == 1
    assert adapter.calls.count("CANCEL_ENTRY") == 1

    # Disarming the entry control leaves the already-protected close path usable.
    operator.armed = False
    with pytest.raises(PaperExecutionSafetyError, match="operator control refused"):
        await restarted._check_operator_entry(
            decision,
            restarted._effect_id(decision.trade_id, OrderRole.ENTRY, "kill-probe"),
        )

    # A target fill is already authoritative when the timeout clock expires.
    # Reconciliation must record that one terminal exit, not issue a competing close.
    trade = await restarted.trades.get(decision.trade_id)
    assert trade is not None and trade.timeout_at is not None
    adapter.state["positions"] = []
    adapter.state["balance"]["positions"] = []
    for record in adapter.state["tpsl"]:
        record["status"] = "done" if record["type"] == "take-profit" else "cancelled"
        if record["status"] == "done":
            record.update(
                triggerOrder="target-exit-order-id",
                triggeredQuantity=str(decision.quantity / 2),
                cancelledReason="",
            )
        else:
            record.update(triggerOrder=None, triggeredQuantity="0", cancelledReason="oco-sibling")
    adapter.state["order_history"].append(
        {
            "id": "target-exit-order-id",
            "instrument": "BTCUSD:DEV",
            "side": "SELL",
            "type": "MARKET",
            "group": "tpsl",
            "quantity": decision.quantity / 2,
            "unFilledQuantity": 0,
            "filledAvgPrice": 105,
            "status": "FILLED",
            "fee": [],
        }
    )
    clock.value = trade.timeout_at + timedelta(milliseconds=1)
    exits = await restarted.reconcile_once()
    assert exits and all(event.exit_reason is TradeExitReason.TARGET for event in exits)
    assert adapter.calls.count("CLOSE") == 0
    terminal = await restarted.trades.get(decision.trade_id)
    assert terminal is not None and terminal.state is TradeState.FLAT
    saved_events = await restarted.trades.list_execution_events(decision.trade_id)
    assert sum(event.event_type is TradeExecutionEventType.EXIT_FILLED for event in saved_events) == 1
    assert await restarted.reconcile_once() == []
    assert await restarted.trades.list_execution_events(decision.trade_id) == saved_events
