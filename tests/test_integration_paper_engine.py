"""Timescale-backed fault and lifecycle tests for EVEDEX DEV PAPER."""

from __future__ import annotations

import asyncio
import copy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from kairos_core.enums import OrderRole, OrderSide, TradeExecutionEventType, TradeExitReason
from kairos_persistence import (
    Database,
    EffectStatus,
    EffectType,
    ExecutionJournalRepository,
    NewTrade,
    TradeLifecycleRepository,
    TradeState,
)

from kairos_execution.config import ExecSettings
from kairos_execution.paper_engine import PaperExecutionEngine, PaperExecutionSafetyError
from tests.disposable_database import connect_disposable_database, disposable_settings
from tests.paper_fixtures import T0, approved_decision

pytestmark = pytest.mark.integration


class MutableClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


class FakePaperAdapter:
    name = "evedex"

    def __init__(self, clock: MutableClock, *, fail_tpsl: str | None = None) -> None:
        self.clock = clock
        self.fail_tpsl = fail_tpsl
        self.calls: list[str] = []
        self.state: dict[str, Any] = {
            "account": {"id": "remote-paper-account-01", "marginCall": False},
            "balance": {
                "funding": {"balance": "10000"},
                "availableBalance": "10000",
                "positions": [],
                "openOrders": [],
            },
            "positions": [],
            "orders": [],
            "tpsl": [],
            "order_history": [],
            "instruments": [
                {
                    "name": "BTCUSD:DEV",
                    "trading": "all",
                    "visibility": "all",
                    "marketState": "OPEN",
                    "markPrice": 100,
                    "updatedAt": datetime.fromtimestamp((T0 + 60_100) / 1000, tz=UTC)
                    .isoformat()
                    .replace("+00:00", "Z"),
                    "lotSize": "1",
                    "multiplier": "1",
                    "minPrice": "1",
                    "maxPrice": "1000000",
                    "minQuantity": "0.1",
                    "maxQuantity": "100",
                    "quantityIncrement": "0.1",
                    "priceIncrement": "0.01",
                    "minVolume": "5",
                }
            ],
        }

    async def preflight(self) -> dict[str, Any]:
        return {
            "profile": "DEV",
            "chain_id": 16182,
            "exchange_url": "https://trading-api.evedex.tech",
            "auth_url": "https://auth-api.evedex.tech",
            "sdk_version": "1.2.11",
            "auth_age_ms": 500,
            "auth_expires_in_ms": 60_000,
            "local_mutation_rate_limit_reserve": 29,
            "local_mutation_rate_limit_capacity": 30,
            "local_mutation_rate_limit_window_ms": 60_000,
            "local_mutation_compensation_reserve": 4,
            "local_mutation_entry_min_reserve": 7,
            "venue_rate_limit_reserve": None,
            "venue_rate_limit_observable": False,
        }

    async def fetch_paper_state(self) -> dict[str, Any]:
        return copy.deepcopy(self.state)

    async def fetch_depth(self, *, symbol: str, max_level: int = 100) -> dict[str, Any]:
        assert symbol == "BTCUSDT"
        assert max_level == 100
        return {
            "t": max(int(self.clock().timestamp() * 1000), T0 + 60_100),
            "asks": [
                {"price": 100.5, "quantity": 1},
                {"price": 100.51, "quantity": 1},
            ],
            "bids": [
                {"price": 100.49, "quantity": 1},
                {"price": 100.48, "quantity": 1},
            ],
        }

    async def drain_events(self, *, limit: int = 1000) -> list[dict[str, Any]]:
        return []

    async def place_limit(
        self,
        *,
        effect_id: str,
        client_order_id: str,
        symbol: str,
        side: OrderSide,
        quantity: float,
        limit_price: float,
        leverage: float,
        post_only: bool,
    ) -> dict[str, Any]:
        self.calls.append("ENTRY")
        response = self.simulate_filled_entry(
            client_order_id,
            side=side,
            leverage=leverage,
            quantity=quantity,
            limit_price=limit_price,
        )
        return response

    def simulate_filled_entry(
        self,
        client_order_id: str,
        *,
        side: OrderSide = OrderSide.BUY,
        leverage: float = 1,
        quantity: float = 0.1,
        limit_price: float = 100.51,
    ) -> dict[str, Any]:
        now = self.clock().isoformat().replace("+00:00", "Z")
        response = {
            "id": client_order_id,
            "instrument": "BTCUSD:DEV",
            "side": side.value,
            "type": "LIMIT",
            "quantity": quantity,
            "unFilledQuantity": 0,
            "limitPrice": limit_price,
            "filledAvgPrice": 100,
            "status": "FILLED",
            "createdAt": now,
            "updatedAt": now,
        }
        self.state["positions"] = [
            {
                "instrument": "BTCUSD:DEV",
                "side": side.value,
                "quantity": quantity,
                "avgPrice": 100,
                "markPrice": 100,
                "leverage": leverage,
                "unRealizedPnL": 0,
            }
        ]
        self.state["balance"]["positions"] = [
            {
                "instrument": "BTCUSD:DEV",
                "side": side.value,
                "volume": quantity,
                "initialMargin": 10,
            }
        ]
        self.state["order_history"] = [response]
        return response

    async def create_tpsl(
        self,
        *,
        effect_id: str,
        symbol: str,
        side: OrderSide,
        tpsl_type: str,
        quantity: float,
        price: float,
        parent_order_id: str,
    ) -> dict[str, Any]:
        self.calls.append(tpsl_type)
        if self.fail_tpsl == tpsl_type:
            raise RuntimeError(f"injected {tpsl_type} failure")
        tpsl_id = f"{tpsl_type.lower()}-venue-id"
        record = {
            "id": tpsl_id,
            "instrument": "BTCUSD:DEV",
            "side": side.value,
            "type": tpsl_type.lower().replace("_", "-"),
            "quantity": quantity,
            "price": price,
            "order": parent_order_id,
            "status": "active",
        }
        self.state["tpsl"].append(record)
        return copy.deepcopy(record)

    async def find_tpsl_record(
        self,
        *,
        symbol: str,
        tpsl_id: str | None = None,
        tpsl_type: str | None = None,
        price: float | None = None,
        parent_order_id: str | None = None,
    ) -> dict[str, Any] | None:
        for record in self.state["tpsl"]:
            if tpsl_id is not None and record["id"] != tpsl_id:
                continue
            if tpsl_type is not None and record["type"] != tpsl_type:
                continue
            if price is not None and record["price"] != price:
                continue
            if parent_order_id is not None and record["order"] != parent_order_id:
                continue
            return copy.deepcopy(record)
        return None

    async def paper_cancel_order(
        self, *, effect_id: str, symbol: str, client_order_id: str
    ) -> dict[str, Any]:
        self.calls.append("CANCEL_ENTRY")
        self.state["orders"] = [item for item in self.state["orders"] if item["id"] != client_order_id]
        self.state["balance"]["openOrders"] = []
        return {"id": client_order_id, "status": "CANCELED"}

    async def paper_close_position(
        self,
        *,
        effect_id: str,
        client_order_id: str,
        symbol: str,
        quantity: float,
        leverage: float,
    ) -> dict[str, Any]:
        self.calls.append("CLOSE")
        self.state["positions"] = []
        self.state["balance"]["positions"] = []
        response = {
            "id": client_order_id,
            "quantity": quantity,
            "unFilledQuantity": 0,
            "filledAvgPrice": 100,
            "status": "FILLED",
        }
        self.state["order_history"].append(response)
        return response

    async def cancel_tpsl(self, *, effect_id: str, symbol: str, tpsl_id: str) -> dict[str, Any]:
        self.calls.append(f"CANCEL:{tpsl_id}")
        for record in self.state["tpsl"]:
            if record["id"] == tpsl_id:
                record["status"] = "cancelled"
        return {"id": tpsl_id, "status": "CANCELED"}


def _exec_settings(tmp_path: Path) -> ExecSettings:
    return ExecSettings(
        trading_mode="PAPER",
        environment="paper-dev",
        account_id="kairos-paper-dev-01",
        evedex_dev_api_key_file=tmp_path / "api.secret",
        evedex_dev_private_key_file=tmp_path / "signing.secret",
        evedex_dev_expected_account_id="remote-paper-account-01",
    )


@pytest.fixture
async def paper_runtime(tmp_path: Path):
    database = Database(disposable_settings())
    await connect_disposable_database(database)
    settings = _exec_settings(tmp_path)
    environment = f"{settings.environment}:EVEDEX:DEV:PAPER"
    pool = database.pool
    await pool.execute("DELETE FROM execution_runtime_health")
    await pool.execute("DELETE FROM execution_mutation_reservations")
    await pool.execute("DELETE FROM execution_mutation_budget_scopes")
    await pool.execute("DELETE FROM public_execution_events")
    await pool.execute("DELETE FROM execution_trade_events")
    await pool.execute("DELETE FROM execution_trades WHERE environment=$1", environment)
    await pool.execute(
        "DELETE FROM execution_effect_events WHERE effect_key IN "
        "(SELECT effect_key FROM execution_effects WHERE environment=$1)",
        environment,
    )
    await pool.execute("DELETE FROM execution_effects WHERE environment=$1", environment)
    await pool.execute("DELETE FROM execution_recovery_state WHERE environment=$1", environment)
    await pool.execute("DELETE FROM account_equity_state WHERE environment=$1", environment)
    clock = MutableClock(datetime.fromtimestamp((T0 + 60_500) / 1000, tz=UTC))
    try:
        yield database, settings, clock
    finally:
        await pool.execute("DELETE FROM execution_runtime_health")
        await pool.execute("DELETE FROM execution_mutation_reservations")
        await pool.execute("DELETE FROM execution_mutation_budget_scopes")
        await pool.execute("DELETE FROM public_execution_events")
        await pool.execute("DELETE FROM execution_trade_events")
        await pool.execute("DELETE FROM execution_trades WHERE environment=$1", environment)
        await pool.execute(
            "DELETE FROM execution_effect_events WHERE effect_key IN "
            "(SELECT effect_key FROM execution_effects WHERE environment=$1)",
            environment,
        )
        await pool.execute("DELETE FROM execution_effects WHERE environment=$1", environment)
        await pool.execute("DELETE FROM execution_recovery_state WHERE environment=$1", environment)
        await pool.execute("DELETE FROM account_equity_state WHERE environment=$1", environment)
        await database.close()


def _engine(database: Database, settings: ExecSettings, clock: MutableClock, adapter: FakePaperAdapter):
    return PaperExecutionEngine(
        adapter,  # type: ignore[arg-type]
        TradeLifecycleRepository(database.pool),
        ExecutionJournalRepository(database.pool),
        settings,
        clock=clock,
    )


def _new_trade(engine: PaperExecutionEngine, decision: Any) -> NewTrade:
    entry_client_id = engine._client_id(decision.trade_id, OrderRole.ENTRY, decision.decided_at_ms)
    return NewTrade(
        trade_id=decision.trade_id,
        strategy_intent_id=decision.intent.intent_id,
        risk_decision_id=decision.decision_id,
        risk_decision_payload=decision.to_payload(),
        strategy_id=decision.intent.strategy_id,
        strategy_revision=decision.intent.strategy_revision,
        trading_mode="PAPER",
        environment=engine._environment,
        profile="DEV",
        exchange="evedex",
        account_id=decision.account_id,
        symbol=decision.intent.symbol,
        venue_symbol=decision.venue_symbol,
        side="BUY",
        quantity=decision.quantity,
        leverage=decision.leverage,
        stop_price=decision.exit_plan.stop_price,
        target_price=decision.exit_plan.target_price,
        entry_eligible_at=datetime.fromtimestamp(decision.intent.entry_eligible_ts_ms / 1000, tz=UTC),
        entry_expires_at=datetime.fromtimestamp(decision.intent.entry_expires_ts_ms / 1000, tz=UTC),
        max_holding_ms=decision.exit_plan.max_holding_ms,
        entry_client_order_id=entry_client_id,
    )


async def _atomic_entry_pending(
    engine: PaperExecutionEngine,
    decision: Any,
) -> Any:
    creation, _created = await engine._create_trade_with_event(decision, _new_trade(engine, decision))
    trade, _pending = await engine._transition_with_event(
        decision,
        creation.trade,
        TradeState.ENTRY_PENDING,
        journal_event_type="ENTRY_EFFECT_READY",
        public_event_type=TradeExecutionEventType.RECONCILIATION,
        lifecycle_state=TradeState.ENTRY_PENDING,
        order_role=OrderRole.ENTRY,
        client_order_id=creation.trade.entry_client_order_id,
        requested_quantity=creation.trade.quantity,
        details=(("reason", "entry_effect_ready"),),
    )
    return trade


@pytest.mark.asyncio
async def test_full_protected_round_trip_times_out_once(paper_runtime) -> None:
    database, settings, clock = paper_runtime
    adapter = FakePaperAdapter(clock)
    engine = _engine(database, settings, clock, adapter)
    assert await engine.initialize_recovery() == ()

    decision = approved_decision()
    result = await engine.handle(decision)
    telemetry = dict(engine.operational_telemetry)
    assert telemetry["evedex_auth_age_ms"] == "500"
    assert telemetry["evedex_local_mutation_reserve"] == "29"
    assert telemetry["evedex_venue_rate_limit_observable"] == "false"
    entry_fill = next(
        event for event in result.events if event.event_type is TradeExecutionEventType.ENTRY_FILLED
    )
    fill_details = dict(entry_fill.details)
    assert fill_details["execution_average_price"] == "100"
    assert float(fill_details["execution_shortfall_bps"]) < 0
    assert fill_details["evedex_auth_age_ms"] == "500"
    telemetry_keys = {
        "evedex_auth_age_ms",
        "evedex_auth_expires_in_ms",
        "evedex_local_mutation_reserve",
        "evedex_local_mutation_capacity",
        "evedex_local_mutation_window_ms",
        "evedex_local_mutation_compensation_reserve",
        "evedex_local_mutation_entry_min_reserve",
        "evedex_venue_rate_limit_observable",
        "evedex_venue_rate_limit_reserve",
    }
    assert all(telemetry_keys <= dict(event.details).keys() for event in result.events)
    assert [event.event_type for event in result.events][-5:] == [
        TradeExecutionEventType.ENTRY_FILLED,
        TradeExecutionEventType.STOP_CREATED,
        TradeExecutionEventType.STOP_RECONCILED,
        TradeExecutionEventType.TARGET_CREATED,
        TradeExecutionEventType.TARGET_RECONCILED,
    ]
    trade = await engine.trades.get(decision.trade_id)
    assert trade is not None and trade.state is TradeState.ACTIVE
    assert adapter.calls[:3] == ["ENTRY", "STOP_LOSS", "TAKE_PROFIT"]
    persisted = await engine.trades.list_execution_events(decision.trade_id)
    assert [event.event_id for event in persisted] == [event.event_id for event in result.events]
    outbox_count = await database.pool.fetchval(
        """SELECT count(*) FROM message_outbox AS outbox
             JOIN public_execution_events AS facts
               ON outbox.message_id=facts.payload->>'message_id'
            WHERE facts.trade_id=$1 AND outbox.topic='kairos.execution.trade_event.v1'""",
        decision.trade_id,
    )
    assert outbox_count == len(result.events)
    assert (await engine.handle(decision)).events == ()
    assert len(await engine.trades.list_execution_events(decision.trade_id)) == len(result.events)

    assert trade.timeout_at is not None
    clock.value = trade.timeout_at + timedelta(milliseconds=1)
    exit_events = await engine.reconcile_once()

    assert [event.exit_reason for event in exit_events] == [
        TradeExitReason.TIMEOUT,
        TradeExitReason.TIMEOUT,
    ]
    assert adapter.calls.count("CLOSE") == 1
    trade = await engine.trades.get(decision.trade_id)
    assert trade is not None and trade.state is TradeState.FLAT
    all_events = await engine.trades.list_execution_events(decision.trade_id)
    assert [event.event_seq for event in all_events] == list(range(1, len(all_events) + 1))
    assert len(all_events) == len(result.events) + len(exit_events)


@pytest.mark.asyncio
async def test_profile_or_telemetry_mismatch_keeps_recovery_blocked(paper_runtime) -> None:
    database, settings, clock = paper_runtime

    class WrongProfileAdapter(FakePaperAdapter):
        async def preflight(self) -> dict[str, Any]:
            health = await super().preflight()
            health["chain_id"] = 421614
            return health

    engine = _engine(database, settings, clock, WrongProfileAdapter(clock))

    blockers = await engine.initialize_recovery()

    assert blockers and "venue preflight failed" in blockers[0]
    assert engine.recovery_blocked is True
    assert (
        await engine.trades.entries_allowed(
            environment=engine._environment,
            account_id=settings.account_id,
            exchange="evedex",
        )
        is False
    )


@pytest.mark.asyncio
async def test_delayed_delivery_rejects_stale_venue_quality_before_durable_effect(
    paper_runtime,
) -> None:
    database, settings, clock = paper_runtime
    adapter = FakePaperAdapter(clock)
    engine = _engine(database, settings, clock, adapter)
    assert await engine.initialize_recovery() == ()
    decision = approved_decision()
    clock.value = datetime.fromtimestamp((decision.venue_quality.expires_at_ms + 1) / 1000, tz=UTC)

    with pytest.raises(PaperExecutionSafetyError, match="venue quality expired"):
        await engine.handle(decision)

    assert adapter.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failure", "message"),
    [
        ("unmarketable", "no longer marketable"),
        ("effective_minimum", "effective minimum at the current marketable IOC price"),
        ("stale", "predates the Risk-bound book"),
    ],
)
async def test_entry_rechecks_current_sdk_book_after_durable_prepare(
    paper_runtime,
    failure: str,
    message: str,
) -> None:
    database, settings, clock = paper_runtime

    class ChangedBookAdapter(FakePaperAdapter):
        async def fetch_depth(self, *, symbol: str, max_level: int = 100) -> dict[str, Any]:
            depth = await super().fetch_depth(symbol=symbol, max_level=max_level)
            if failure == "unmarketable":
                depth["asks"] = [{"price": 101, "quantity": 1}]
                depth["bids"] = [{"price": 100.99, "quantity": 1}]
            elif failure == "effective_minimum":
                depth["asks"] = [{"price": 40, "quantity": 1}]
                depth["bids"] = [{"price": 39.99, "quantity": 1}]
            else:
                depth["t"] = int(self.clock().timestamp() * 1000) - 5_001
            return depth

    adapter = ChangedBookAdapter(clock)
    engine = _engine(database, settings, clock, adapter)
    assert await engine.initialize_recovery() == ()
    decision = approved_decision()

    with pytest.raises(PaperExecutionSafetyError, match=message):
        await engine.handle(decision)

    assert "ENTRY" not in adapter.calls
    effect = await engine.effects.get(engine._effect_id(decision.trade_id, OrderRole.ENTRY, "place"))
    assert effect is not None and effect.status is EffectStatus.PREPARED
    assert engine.recovery_blocked is True


@pytest.mark.asyncio
async def test_trade_creation_and_decision_fact_roll_back_together(
    paper_runtime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, settings, clock = paper_runtime
    adapter = FakePaperAdapter(clock)
    engine = _engine(database, settings, clock, adapter)
    assert await engine.initialize_recovery() == ()
    decision = approved_decision()
    original_event_spec = engine._event_spec
    outbox_before = await database.pool.fetchval("SELECT count(*) FROM message_outbox")
    audit_before = await database.pool.fetchval("SELECT count(*) FROM event_audit")

    def fail_creation_fact(*args: Any, **kwargs: Any):
        fact_key, build = original_event_spec(*args, **kwargs)
        if args[2] is TradeExecutionEventType.DECISION_RECEIVED:

            def crash_inside_atomic_transaction(_sequence: int):
                raise RuntimeError("injected crash while building atomic creation fact")

            return fact_key, crash_inside_atomic_transaction
        return fact_key, build

    monkeypatch.setattr(engine, "_event_spec", fail_creation_fact)
    with pytest.raises(RuntimeError, match="injected crash"):
        await engine.handle(decision)

    assert await engine.trades.get(decision.trade_id) is None
    assert (
        await database.pool.fetchval(
            "SELECT count(*) FROM execution_trade_events WHERE trade_id=$1",
            decision.trade_id,
        )
        == 0
    )
    assert (
        await database.pool.fetchval(
            "SELECT count(*) FROM public_execution_events WHERE trade_id=$1",
            decision.trade_id,
        )
        == 0
    )
    assert await database.pool.fetchval("SELECT count(*) FROM message_outbox") == outbox_before
    assert await database.pool.fetchval("SELECT count(*) FROM event_audit") == audit_before
    assert adapter.calls == []


@pytest.mark.asyncio
async def test_startup_audits_terminal_trades_and_fails_closed_on_missing_fact(
    paper_runtime,
) -> None:
    database, settings, clock = paper_runtime
    adapter = FakePaperAdapter(clock)
    engine = _engine(database, settings, clock, adapter)
    decision = approved_decision()
    malformed = await engine.trades.create(_new_trade(engine, decision))
    malformed = await engine.trades.transition(
        malformed.trade_id,
        TradeState.CANCELLED,
        event_type="LEGACY_NON_ATOMIC_CANCEL_FOR_AUDIT_FIXTURE",
    )
    assert malformed.state is TradeState.CANCELLED
    scoped = await engine.trades.list_trades_for_scope(
        environment=engine._environment,
        account_id=settings.account_id,
        exchange="evedex",
        include_terminal=True,
    )
    assert [trade.trade_id for trade in scoped] == [decision.trade_id]

    blockers = await engine.initialize_recovery()

    assert len(blockers) == 1
    assert "public lifecycle audit failed" in blockers[0]
    assert "0 public facts for 2 durable lifecycle versions" in blockers[0]
    assert engine.recovery_blocked is True


@pytest.mark.asyncio
async def test_paper_rejects_an_approved_alpha_strategy_before_durable_trade_create(
    paper_runtime,
) -> None:
    database, settings, clock = paper_runtime
    adapter = FakePaperAdapter(clock)
    engine = _engine(database, settings, clock, adapter)
    assert await engine.initialize_recovery() == ()
    decision = approved_decision()
    alpha_intent = decision.intent.model_copy(
        update={"strategy_id": "trend-breakout", "strategy_revision": "2026-08-23.1"}
    )
    alpha_decision = decision.model_copy(update={"intent": alpha_intent})

    with pytest.raises(PaperExecutionSafetyError, match="technical-canary@1"):
        await engine.handle(alpha_decision)

    assert adapter.calls == []
    assert await engine.trades.get(decision.trade_id) is None


@pytest.mark.asyncio
async def test_small_local_clock_skew_waits_to_next_bar_without_redis_reclaim(
    paper_runtime,
) -> None:
    database, settings, clock = paper_runtime
    decision = approved_decision()
    clock.value = datetime.fromtimestamp((decision.intent.entry_eligible_ts_ms - 100) / 1000, tz=UTC)
    waits: list[float] = []

    async def advance_clock(delay_s: float) -> None:
        waits.append(delay_s)
        clock.value += timedelta(seconds=delay_s)

    adapter = FakePaperAdapter(clock)
    engine = PaperExecutionEngine(
        adapter,  # type: ignore[arg-type]
        TradeLifecycleRepository(database.pool),
        ExecutionJournalRepository(database.pool),
        settings,
        clock=clock,
        sleeper=advance_clock,
    )
    assert await engine.initialize_recovery() == ()

    result = await engine.handle(decision)

    assert waits == pytest.approx([0.1])
    assert result.events
    assert adapter.calls[:3] == ["ENTRY", "STOP_LOSS", "TAKE_PROFIT"]


@pytest.mark.asyncio
async def test_ioc_new_ack_is_cancelled_and_proven_exposure_free_before_return(
    paper_runtime,
) -> None:
    database, settings, clock = paper_runtime

    class NewIocAdapter(FakePaperAdapter):
        async def place_limit(self, **kwargs: Any) -> dict[str, Any]:
            self.calls.append("ENTRY")
            now = self.clock().isoformat().replace("+00:00", "Z")
            response = {
                "id": str(kwargs["client_order_id"]),
                "instrument": "BTCUSD:DEV",
                "side": str(kwargs["side"].value),
                "type": "LIMIT",
                "quantity": float(kwargs["quantity"]),
                "unFilledQuantity": float(kwargs["quantity"]),
                "limitPrice": float(kwargs["limit_price"]),
                "filledAvgPrice": None,
                "status": "NEW",
                "createdAt": now,
                "updatedAt": now,
            }
            self.state["orders"] = [copy.deepcopy(response)]
            self.state["balance"]["openOrders"] = [copy.deepcopy(response)]
            self.state["order_history"] = [copy.deepcopy(response)]
            return response

    adapter = NewIocAdapter(clock)
    engine = _engine(database, settings, clock, adapter)
    assert await engine.initialize_recovery() == ()

    result = await engine.handle(approved_decision())

    assert adapter.calls == ["ENTRY", "CANCEL_ENTRY"]
    assert result.events[-1].event_type is TradeExecutionEventType.ENTRY_CANCELLED
    assert adapter.state["positions"] == []
    assert adapter.state["orders"] == []


@pytest.mark.asyncio
async def test_ioc_new_ack_fill_projection_is_protected_before_return(paper_runtime) -> None:
    database, settings, clock = paper_runtime

    class DeferredIocFillAdapter(FakePaperAdapter):
        submitted_client_id: str | None = None

        async def place_limit(self, **kwargs: Any) -> dict[str, Any]:
            self.calls.append("ENTRY")
            self.submitted_client_id = str(kwargs["client_order_id"])
            now = self.clock().isoformat().replace("+00:00", "Z")
            response = {
                "id": self.submitted_client_id,
                "instrument": "BTCUSD:DEV",
                "side": str(kwargs["side"].value),
                "type": "LIMIT",
                "quantity": float(kwargs["quantity"]),
                "unFilledQuantity": float(kwargs["quantity"]),
                "limitPrice": float(kwargs["limit_price"]),
                "filledAvgPrice": None,
                "status": "NEW",
                "createdAt": now,
                "updatedAt": now,
            }
            self.state["orders"] = [copy.deepcopy(response)]
            self.state["order_history"] = [copy.deepcopy(response)]
            return response

        async def fetch_paper_state(self) -> dict[str, Any]:
            if self.submitted_client_id is not None and not self.state["positions"]:
                self.simulate_filled_entry(self.submitted_client_id)
                self.state["orders"] = []
                self.submitted_client_id = None
            return await super().fetch_paper_state()

    adapter = DeferredIocFillAdapter(clock)
    engine = _engine(database, settings, clock, adapter)
    assert await engine.initialize_recovery() == ()

    result = await engine.handle(approved_decision())

    assert adapter.calls[:3] == ["ENTRY", "STOP_LOSS", "TAKE_PROFIT"]
    assert "CANCEL_ENTRY" not in adapter.calls
    assert any(event.event_type is TradeExecutionEventType.ENTRY_FILLED for event in result.events)


@pytest.mark.asyncio
async def test_ioc_fill_history_waits_for_lagging_position_and_never_cancels(
    paper_runtime,
) -> None:
    database, settings, clock = paper_runtime

    class LaggingPositionAdapter(FakePaperAdapter):
        submitted_client_id: str | None = None
        reads_after_entry = 0

        async def place_limit(self, **kwargs: Any) -> dict[str, Any]:
            self.calls.append("ENTRY")
            self.submitted_client_id = str(kwargs["client_order_id"])
            now = self.clock().isoformat().replace("+00:00", "Z")
            acknowledged = {
                "id": self.submitted_client_id,
                "instrument": "BTCUSD:DEV",
                "side": str(kwargs["side"].value),
                "type": "LIMIT",
                "quantity": float(kwargs["quantity"]),
                "unFilledQuantity": float(kwargs["quantity"]),
                "limitPrice": float(kwargs["limit_price"]),
                "filledAvgPrice": None,
                "status": "NEW",
                "createdAt": now,
                "updatedAt": now,
            }
            filled = {
                **acknowledged,
                "unFilledQuantity": 0,
                "filledAvgPrice": 100,
                "status": "FILLED",
            }
            self.state["orders"] = []
            self.state["order_history"] = [filled]
            return acknowledged

        async def fetch_paper_state(self) -> dict[str, Any]:
            if self.submitted_client_id is not None:
                self.reads_after_entry += 1
                if self.reads_after_entry == 3:
                    self.simulate_filled_entry(self.submitted_client_id)
                    self.state["orders"] = []
                    self.submitted_client_id = None
            return await super().fetch_paper_state()

        async def paper_cancel_order(self, **kwargs: Any) -> dict[str, Any]:
            raise AssertionError("an IOC with authoritative fill evidence must never be cancelled")

    adapter = LaggingPositionAdapter(clock)
    engine = _engine(database, settings, clock, adapter)
    assert await engine.initialize_recovery() == ()

    result = await engine.handle(approved_decision())

    assert adapter.calls[:3] == ["ENTRY", "STOP_LOSS", "TAKE_PROFIT"]
    assert "CANCEL_ENTRY" not in adapter.calls
    assert any(event.event_type is TradeExecutionEventType.ENTRY_FILLED for event in result.events)


@pytest.mark.asyncio
async def test_ioc_fill_history_without_position_blocks_and_does_not_cancel(
    paper_runtime,
) -> None:
    database, settings, clock = paper_runtime

    class MissingPositionAdapter(FakePaperAdapter):
        async def place_limit(self, **kwargs: Any) -> dict[str, Any]:
            self.calls.append("ENTRY")
            now = self.clock().isoformat().replace("+00:00", "Z")
            acknowledged = {
                "id": str(kwargs["client_order_id"]),
                "instrument": "BTCUSD:DEV",
                "side": str(kwargs["side"].value),
                "type": "LIMIT",
                "quantity": float(kwargs["quantity"]),
                "unFilledQuantity": float(kwargs["quantity"]),
                "limitPrice": float(kwargs["limit_price"]),
                "filledAvgPrice": None,
                "status": "NEW",
                "createdAt": now,
                "updatedAt": now,
            }
            self.state["order_history"] = [
                {
                    **acknowledged,
                    "unFilledQuantity": 0,
                    "filledAvgPrice": 100,
                    "status": "FILLED",
                }
            ]
            return acknowledged

        async def paper_cancel_order(self, **kwargs: Any) -> dict[str, Any]:
            raise AssertionError("an IOC with authoritative fill evidence must never be cancelled")

    adapter = MissingPositionAdapter(clock)
    engine = _engine(database, settings, clock, adapter)
    assert await engine.initialize_recovery() == ()

    with pytest.raises(PaperExecutionSafetyError, match="fill projection did not converge"):
        await engine.handle(approved_decision())

    assert adapter.calls == ["ENTRY"]
    assert engine.recovery_blocked


@pytest.mark.parametrize(
    ("fault", "message"),
    [
        ("missing_position_quantity", "explicit quantity"),
        ("wrong_position_leverage", "leverage differs"),
        ("missing_tpsl_quantity", "explicit quantity"),
    ],
)
@pytest.mark.asyncio
async def test_authoritative_numeric_omissions_or_leverage_drift_fail_closed(
    paper_runtime,
    fault: str,
    message: str,
) -> None:
    database, settings, clock = paper_runtime
    adapter = FakePaperAdapter(clock)
    engine = _engine(database, settings, clock, adapter)
    assert await engine.initialize_recovery() == ()
    await engine.handle(approved_decision())
    if fault == "missing_position_quantity":
        del adapter.state["positions"][0]["quantity"]
    elif fault == "wrong_position_leverage":
        adapter.state["positions"][0]["leverage"] = 2
    else:
        del adapter.state["tpsl"][0]["quantity"]

    with pytest.raises(PaperExecutionSafetyError, match=message):
        await engine.reconcile_once()

    assert engine.recovery_blocked


@pytest.mark.parametrize(
    ("instrument_field", "value", "message"),
    [
        ("minVolume", "50", "differs from the Risk-bound"),
        ("priceIncrement", "0.1", "differs from the Risk-bound"),
        ("marketState", "CLOSED", "marketState is not OPEN"),
    ],
)
@pytest.mark.asyncio
async def test_canary_rejects_current_instrument_rule_mismatch_before_entry_mutation(
    paper_runtime,
    instrument_field: str,
    value: str,
    message: str,
) -> None:
    database, settings, clock = paper_runtime
    adapter = FakePaperAdapter(clock)
    adapter.state["instruments"][0][instrument_field] = value
    engine = _engine(database, settings, clock, adapter)
    assert await engine.initialize_recovery() == ()

    with pytest.raises(PaperExecutionSafetyError, match=message):
        await engine.handle(approved_decision())

    assert "ENTRY" not in adapter.calls


@pytest.mark.parametrize("failed_role", ["STOP_LOSS", "TAKE_PROFIT"])
@pytest.mark.asyncio
async def test_ambiguous_protection_failure_emergency_closes_and_blocks(
    paper_runtime, failed_role: str
) -> None:
    database, settings, clock = paper_runtime
    adapter = FakePaperAdapter(clock, fail_tpsl=failed_role)
    engine = _engine(database, settings, clock, adapter)
    assert await engine.initialize_recovery() == ()

    decision = approved_decision()
    with pytest.raises(PaperExecutionSafetyError, match="cancellation cannot be proven"):
        await engine.handle(decision)

    assert adapter.calls.count("CLOSE") == 1
    trade = await engine.trades.get(decision.trade_id)
    assert trade is not None and trade.state is TradeState.EXITING_EMERGENCY


@pytest.mark.parametrize("missing_role", ["stop-loss", "take-profit"])
@pytest.mark.asyncio
async def test_confirmed_protection_with_transient_read_miss_is_closed_and_cancelled(
    paper_runtime,
    missing_role: str,
) -> None:
    database, settings, clock = paper_runtime

    class TransientReadMissAdapter(FakePaperAdapter):
        missed = False

        async def find_tpsl_record(self, **kwargs: Any) -> dict[str, Any] | None:
            if not self.missed and kwargs.get("tpsl_type") == missing_role:
                self.missed = True
                return None
            return await super().find_tpsl_record(**kwargs)

    adapter = TransientReadMissAdapter(clock)
    engine = _engine(database, settings, clock, adapter)
    assert await engine.initialize_recovery() == ()

    result = await engine.handle(approved_decision())

    assert result.events[-1].event_type is TradeExecutionEventType.EMERGENCY_CLOSE
    assert adapter.calls.count("CLOSE") == 1
    assert all(record["status"] == "cancelled" for record in adapter.state["tpsl"])
    trade = await engine.trades.get(approved_decision().trade_id)
    assert trade is not None and trade.state is TradeState.FLAT
    assert (
        await engine.effects.recovery_required(
            exchange="evedex",
            environment=engine._environment,
            account_id=settings.account_id,
        )
        == []
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [("status", "cancelled"), ("side", "SELL"), ("quantity", 0.1)],
)
@pytest.mark.asyncio
async def test_tpsl_follow_up_read_requires_live_side_and_full_position_semantics(
    paper_runtime,
    field: str,
    value: object,
) -> None:
    database, settings, clock = paper_runtime

    class MalformedReadAdapter(FakePaperAdapter):
        async def find_tpsl_record(self, **kwargs: Any) -> dict[str, Any] | None:
            record = await super().find_tpsl_record(**kwargs)
            if record is not None:
                record[field] = value
            return record

    adapter = MalformedReadAdapter(clock)
    engine = _engine(database, settings, clock, adapter)
    assert await engine.initialize_recovery() == ()

    result = await engine.handle(approved_decision())

    assert result.events[-1].event_type is TradeExecutionEventType.EMERGENCY_CLOSE
    assert adapter.calls.count("CLOSE") == 1
    assert all(record["status"] == "cancelled" for record in adapter.state["tpsl"])


@pytest.mark.asyncio
async def test_unproven_orphan_cancellation_keeps_trade_out_of_flat(paper_runtime) -> None:
    database, settings, clock = paper_runtime

    class UnprovenCancelAdapter(FakePaperAdapter):
        missed = False

        async def find_tpsl_record(self, **kwargs: Any) -> dict[str, Any] | None:
            if not self.missed and kwargs.get("tpsl_type") == "stop-loss":
                self.missed = True
                return None
            return await super().find_tpsl_record(**kwargs)

        async def cancel_tpsl(self, *, effect_id: str, symbol: str, tpsl_id: str) -> dict[str, Any]:
            self.calls.append(f"CANCEL:{tpsl_id}")
            return {"id": tpsl_id, "status": "CANCELED"}

    adapter = UnprovenCancelAdapter(clock)
    engine = _engine(database, settings, clock, adapter)
    assert await engine.initialize_recovery() == ()
    decision = approved_decision()

    with pytest.raises(PaperExecutionSafetyError, match="did not reconcile to terminal"):
        await engine.handle(decision)

    trade = await engine.trades.get(decision.trade_id)
    assert trade is not None and trade.state is TradeState.EXITING_EMERGENCY
    assert any(record["status"] == "active" for record in adapter.state["tpsl"])

    recovered = _engine(database, settings, clock, adapter)
    blockers = await recovered.initialize_recovery()
    assert blockers and "confirmed TP/SL cancellation remains live" in blockers[0]


@pytest.mark.asyncio
async def test_crash_after_venue_call_recovers_without_second_entry(paper_runtime) -> None:
    database, settings, clock = paper_runtime
    adapter = FakePaperAdapter(clock)
    trades = TradeLifecycleRepository(database.pool)
    effects = ExecutionJournalRepository(database.pool)
    engine = PaperExecutionEngine(
        adapter,  # type: ignore[arg-type]
        trades,
        effects,
        settings,
        clock=clock,
    )
    decision = approved_decision()
    trade = await _atomic_entry_pending(engine, decision)
    entry_client_id = trade.entry_client_order_id
    effect_id = engine._effect_id(trade.trade_id, OrderRole.ENTRY, "place")
    await effects.prepare(
        effect_key=effect_id,
        effect_type=EffectType.PLACE_ORDER,
        exchange="evedex",
        symbol=trade.symbol,
        client_order_id=entry_client_id,
        request_payload={
            "trade_id": trade.trade_id,
            "intent_id": trade.strategy_intent_id,
            "client_order_id": entry_client_id,
            "venue_symbol": decision.venue_symbol,
            "side": "BUY",
            "quantity_hex": float(decision.quantity).hex(),
            "limit_price_hex": float(decision.worst_entry_price).hex(),
            "leverage_hex": float(decision.leverage).hex(),
        },
        environment=trade.environment,
        account_id=trade.account_id,
        trade_id=trade.trade_id,
        order_role=OrderRole.ENTRY.value,
        recovery_delay=timedelta(0),
    )
    adapter.simulate_filled_entry(entry_client_id)

    recovered = _engine(database, settings, clock, adapter)
    assert await recovered.initialize_recovery() == ()
    # The Redis message may be reclaimed after restart. Redelivery must publish
    # the recovered fill/protection facts rather than silently discarding them.
    events = (await recovered.handle(decision)).events

    assert adapter.calls.count("ENTRY") == 0
    assert adapter.calls[:2] == ["STOP_LOSS", "TAKE_PROFIT"]
    effect = await effects.get(effect_id)
    assert effect is not None and effect.status is EffectStatus.RECONCILED
    trade = await trades.get(decision.trade_id)
    assert trade is not None and trade.state is TradeState.ACTIVE
    assert any(event.event_type is TradeExecutionEventType.ENTRY_FILLED for event in events)


@pytest.mark.asyncio
async def test_crash_after_entry_pending_before_effect_prepare_cancels_without_mutation(
    paper_runtime,
) -> None:
    database, settings, clock = paper_runtime
    adapter = FakePaperAdapter(clock)
    trades = TradeLifecycleRepository(database.pool)
    decision = approved_decision()
    engine = _engine(database, settings, clock, adapter)
    trade = await _atomic_entry_pending(engine, decision)
    assert await engine.initialize_recovery() == ()

    events = (await engine.handle(decision)).events

    assert adapter.calls == []
    assert [event.event_type for event in events] == [TradeExecutionEventType.ENTRY_CANCELLED]
    trade = await trades.get(decision.trade_id)
    assert trade is not None and trade.state is TradeState.CANCELLED


@pytest.mark.asyncio
async def test_crash_after_effect_prepare_before_call_recovers_fact_and_terminal_cancel(
    paper_runtime,
) -> None:
    database, settings, clock = paper_runtime
    adapter = FakePaperAdapter(clock)
    trades = TradeLifecycleRepository(database.pool)
    effects = ExecutionJournalRepository(database.pool)
    engine = _engine(database, settings, clock, adapter)
    decision = approved_decision()
    trade = await _atomic_entry_pending(engine, decision)
    entry_client_id = trade.entry_client_order_id
    effect_id = engine._effect_id(trade.trade_id, OrderRole.ENTRY, "place")
    await effects.prepare(
        effect_key=effect_id,
        effect_type=EffectType.PLACE_ORDER,
        exchange="evedex",
        symbol=trade.symbol,
        client_order_id=entry_client_id,
        request_payload={
            "trade_id": trade.trade_id,
            "intent_id": trade.strategy_intent_id,
            "client_order_id": entry_client_id,
            "venue_symbol": decision.venue_symbol,
            "side": "BUY",
            "quantity_hex": float(decision.quantity).hex(),
            "limit_price_hex": float(decision.worst_entry_price).hex(),
            "leverage_hex": float(decision.leverage).hex(),
        },
        environment=trade.environment,
        account_id=trade.account_id,
        trade_id=trade.trade_id,
        order_role=OrderRole.ENTRY.value,
        recovery_delay=timedelta(0),
    )

    assert await engine.initialize_recovery() == ()

    public = await trades.list_execution_events(decision.trade_id)
    assert [event.event_type for event in public] == [
        TradeExecutionEventType.DECISION_RECEIVED,
        TradeExecutionEventType.RECONCILIATION,
        TradeExecutionEventType.ENTRY_CANCELLED,
    ]
    assert adapter.calls == []
    trade = await trades.get(decision.trade_id)
    assert trade is not None and trade.state is TradeState.CANCELLED


@pytest.mark.asyncio
async def test_partial_fill_is_protected_then_remainder_is_cancelled_at_expiry(
    paper_runtime,
) -> None:
    database, settings, clock = paper_runtime

    class PartialFillAdapter(FakePaperAdapter):
        async def place_limit(self, **kwargs: Any) -> dict[str, Any]:
            client_order_id = str(kwargs["client_order_id"])
            response = self.simulate_filled_entry(
                client_order_id,
                quantity=float(kwargs["quantity"]),
                limit_price=float(kwargs["limit_price"]),
            )
            response["status"] = "PARTIALLY_FILLED"
            response["unFilledQuantity"] = 0.05
            self.state["positions"][0]["quantity"] = 0.05
            self.state["orders"] = [response]
            self.state["order_history"] = [response]
            self.calls.append("ENTRY")
            return copy.deepcopy(response)

    adapter = PartialFillAdapter(clock)
    engine = _engine(database, settings, clock, adapter)
    assert await engine.initialize_recovery() == ()
    decision = approved_decision()

    result = await engine.handle(decision)

    assert any(event.event_type is TradeExecutionEventType.ENTRY_PARTIAL_FILL for event in result.events)
    assert adapter.calls[:3] == ["ENTRY", "STOP_LOSS", "TAKE_PROFIT"]
    trade = await engine.trades.get(decision.trade_id)
    assert trade is not None and trade.state is TradeState.ACTIVE

    clock.value = datetime.fromtimestamp((decision.intent.entry_expires_ts_ms + 1) / 1000, tz=UTC)
    await engine.reconcile_once()

    assert adapter.calls.count("CANCEL_ENTRY") == 1
    trade = await engine.trades.get(decision.trade_id)
    assert trade is not None and trade.state is TradeState.ACTIVE


@pytest.mark.asyncio
async def test_authoritative_target_wins_target_vs_timeout_race(paper_runtime) -> None:
    database, settings, clock = paper_runtime
    adapter = FakePaperAdapter(clock)
    engine = _engine(database, settings, clock, adapter)
    assert await engine.initialize_recovery() == ()
    decision = approved_decision()
    await engine.handle(decision)
    trade = await engine.trades.get(decision.trade_id)
    assert trade is not None and trade.timeout_at is not None

    adapter.state["positions"] = []
    adapter.state["balance"]["positions"] = []
    for record in adapter.state["tpsl"]:
        record["status"] = "done" if record["type"] == "take-profit" else "cancelled"
        if record["status"] == "done":
            record["triggerOrder"] = "target-exit-order-id"
            record["triggeredQuantity"] = "0.1"
            record["cancelledReason"] = ""
        else:
            record["triggerOrder"] = None
            record["triggeredQuantity"] = "0"
            record["cancelledReason"] = "oco-sibling"
    adapter.state["order_history"].append(
        {
            "id": "target-exit-order-id",
            "instrument": "BTCUSD:DEV",
            "side": "SELL",
            "type": "MARKET",
            "group": "tpsl",
            "quantity": 0.1,
            "unFilledQuantity": 0,
            "filledAvgPrice": 105,
            "status": "FILLED",
            "fee": [{"coin": "USDT", "quantity": 0.01}],
        }
    )
    clock.value = trade.timeout_at + timedelta(milliseconds=1)

    events = await engine.reconcile_once()

    assert [event.exit_reason for event in events] == [
        TradeExitReason.TARGET,
        TradeExitReason.TARGET,
    ]
    assert adapter.calls.count("CLOSE") == 0
    assert events[-1].exchange_order_id == "target-exit-order-id"
    assert events[-1].average_price == 105
    assert events[-1].fee_usd == pytest.approx(0.01)
    trade = await engine.trades.get(decision.trade_id)
    assert trade is not None and trade.state is TradeState.FLAT


@pytest.mark.parametrize(
    ("fault", "message"),
    [
        ("missing_trigger", "exit order ID"),
        ("missing_history", "complete order history"),
        ("wrong_side", "wrong closing side"),
        ("not_filled", "is not FILLED"),
    ],
)
@pytest.mark.asyncio
async def test_flat_position_requires_exact_generated_tpsl_fill_proof(
    paper_runtime,
    fault: str,
    message: str,
) -> None:
    database, settings, clock = paper_runtime
    adapter = FakePaperAdapter(clock)
    engine = _engine(database, settings, clock, adapter)
    assert await engine.initialize_recovery() == ()
    decision = approved_decision()
    await engine.handle(decision)
    adapter.state["positions"] = []
    adapter.state["balance"]["positions"] = []
    for record in adapter.state["tpsl"]:
        if record["type"] == "take-profit":
            record.update(
                status="done",
                triggerOrder=(None if fault == "missing_trigger" else "target-exit-order-id"),
                triggeredQuantity="0.1",
                cancelledReason="",
            )
        else:
            record.update(
                status="cancelled",
                triggerOrder=None,
                triggeredQuantity="0",
                cancelledReason="oco-sibling",
            )
    if fault != "missing_history" and fault != "missing_trigger":
        adapter.state["order_history"].append(
            {
                "id": "target-exit-order-id",
                "instrument": "BTCUSD:DEV",
                "side": "BUY" if fault == "wrong_side" else "SELL",
                "type": "MARKET",
                "group": "tpsl",
                "quantity": 0.1,
                "unFilledQuantity": 0,
                "filledAvgPrice": 105,
                "status": "NEW" if fault == "not_filled" else "FILLED",
                "fee": [],
            }
        )

    with pytest.raises(PaperExecutionSafetyError, match=message):
        await engine.reconcile_once()

    trade = await engine.trades.get(decision.trade_id)
    assert trade is not None and trade.state is TradeState.ACTIVE


@pytest.mark.asyncio
async def test_two_engine_instances_share_database_exit_race_lock(paper_runtime) -> None:
    database, settings, clock = paper_runtime
    adapter = FakePaperAdapter(clock)
    first = _engine(database, settings, clock, adapter)
    second = _engine(database, settings, clock, adapter)
    assert await first.initialize_recovery() == ()
    assert await second.initialize_recovery() == ()
    decision = approved_decision()
    await first.handle(decision)
    trade = await first.trades.get(decision.trade_id)
    assert trade is not None and trade.timeout_at is not None
    clock.value = trade.timeout_at + timedelta(milliseconds=1)

    results = await asyncio.gather(first.reconcile_once(), second.reconcile_once())

    assert adapter.calls.count("CLOSE") == 1
    assert sum(len(events) for events in results) == 2
    trade = await first.trades.get(decision.trade_id)
    assert trade is not None and trade.state is TradeState.FLAT


@pytest.mark.asyncio
async def test_tpsl_fill_during_manual_timeout_close_blocks_competing_exit_lineage(
    paper_runtime,
) -> None:
    database, settings, clock = paper_runtime

    class CompetingTargetAdapter(FakePaperAdapter):
        async def paper_close_position(self, **kwargs: Any) -> dict[str, Any]:
            response = await super().paper_close_position(**kwargs)
            for record in self.state["tpsl"]:
                if record["type"] == "take-profit":
                    record.update(
                        status="done",
                        triggerOrder="target-race-order-id",
                        triggeredQuantity="0.1",
                        cancelledReason="",
                    )
                else:
                    record.update(
                        status="cancelled",
                        triggerOrder=None,
                        triggeredQuantity="0",
                        cancelledReason="oco-sibling",
                    )
            self.state["order_history"].append(
                {
                    "id": "target-race-order-id",
                    "instrument": "BTCUSD:DEV",
                    "side": "SELL",
                    "type": "MARKET",
                    "group": "tpsl",
                    "quantity": 0.1,
                    "unFilledQuantity": 0,
                    "filledAvgPrice": 105,
                    "status": "FILLED",
                    "fee": [],
                }
            )
            return response

    adapter = CompetingTargetAdapter(clock)
    engine = _engine(database, settings, clock, adapter)
    assert await engine.initialize_recovery() == ()
    decision = approved_decision()
    await engine.handle(decision)
    trade = await engine.trades.get(decision.trade_id)
    assert trade is not None and trade.timeout_at is not None
    clock.value = trade.timeout_at + timedelta(milliseconds=1)

    with pytest.raises(PaperExecutionSafetyError, match="competing terminal venue evidence"):
        await engine.reconcile_once()

    trade = await engine.trades.get(decision.trade_id)
    assert trade is not None and trade.state is TradeState.EXITING_TIMEOUT


@pytest.mark.asyncio
async def test_terminal_transition_and_public_fact_roll_back_together_then_recover(
    paper_runtime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, settings, clock = paper_runtime
    adapter = FakePaperAdapter(clock)
    engine = _engine(database, settings, clock, adapter)
    assert await engine.initialize_recovery() == ()
    decision = approved_decision()
    await engine.handle(decision)
    trade = await engine.trades.get(decision.trade_id)
    assert trade is not None and trade.timeout_at is not None
    clock.value = trade.timeout_at + timedelta(milliseconds=1)
    original_event_spec = engine._event_spec

    def fail_terminal_fact(*args: Any, **kwargs: Any):
        fact_key, build = original_event_spec(*args, **kwargs)
        lifecycle_state = args[3]
        if lifecycle_state is TradeState.FLAT:

            def crash_inside_atomic_transaction(_sequence: int):
                raise RuntimeError("injected crash while building atomic FLAT fact")

            return fact_key, crash_inside_atomic_transaction
        return fact_key, build

    monkeypatch.setattr(engine, "_event_spec", fail_terminal_fact)
    with pytest.raises(RuntimeError, match="injected crash"):
        await engine.reconcile_once()
    monkeypatch.setattr(engine, "_event_spec", original_event_spec)
    trade = await engine.trades.get(decision.trade_id)
    # The FSM update happened before the injected builder failure inside the
    # PostgreSQL transaction. Both it and the fact/outbox insert rolled back.
    assert trade is not None and trade.state is TradeState.EXITING_TIMEOUT
    assert not any(
        event.lifecycle_state.value == "FLAT"
        for event in await engine.trades.list_execution_events(decision.trade_id)
    )

    recovered = _engine(database, settings, clock, adapter)
    assert await recovered.initialize_recovery() == ()
    events = (await recovered.handle(decision)).events

    assert len(events) == 1
    assert events[0].event_type is TradeExecutionEventType.EXIT_FILLED
    assert events[0].exit_reason is TradeExitReason.TIMEOUT
    assert events[0].lifecycle_state.value == "FLAT"
    outbox_exists = await database.pool.fetchval(
        "SELECT EXISTS(SELECT 1 FROM message_outbox WHERE message_id=$1)",
        events[0].message_id,
    )
    assert outbox_exists is True


@pytest.mark.asyncio
async def test_expired_decision_is_durably_cancelled_without_venue_call(paper_runtime) -> None:
    database, settings, clock = paper_runtime
    adapter = FakePaperAdapter(clock)
    engine = _engine(database, settings, clock, adapter)
    assert await engine.initialize_recovery() == ()
    decision = approved_decision()
    clock.value = datetime.fromtimestamp((decision.intent.entry_expires_ts_ms + 1) / 1000, tz=UTC)

    result = await engine.handle(decision)

    assert adapter.calls == []
    assert result.events[-1].event_type is TradeExecutionEventType.ENTRY_CANCELLED
    trade = await engine.trades.get(decision.trade_id)
    assert trade is not None and trade.state is TradeState.CANCELLED
