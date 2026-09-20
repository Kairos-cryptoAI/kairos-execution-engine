"""Disposable PostgreSQL proof for the isolated simulator controller.

This is intentionally opt-in: it writes only to an explicitly named
``kairos_sim_controller_*`` database supplied by the isolated Compose gate.
It does not use the runtime/PAPER database or any external market endpoint.
"""

from __future__ import annotations

import hashlib
import os
import re
from urllib.parse import urlsplit

import pytest
from kairos_core.contracts import (
    CandidateReviewV1,
    CandidateRouteV1,
    ClosedBarEventV1,
    ExitPlanV1,
    RecordedBookLevelV1,
    RecordedTopNBookFrameV1,
    SimulationAdmissionV2,
    SimulationRiskDecisionV1,
    SimulationSessionV1,
    SimulationStrategyRefV1,
    StrategyIntentV1,
    StrategyProvenanceV1,
)
from kairos_core.enums import CandidateReviewTier, ReasoningEffort, ReviewDecision, Side
from kairos_persistence import Database, MigrationProfile, PersistenceSettings, SimulationRepository
from kairos_persistence.database_target import connect_verified_database, require_database_target_url

from kairos_execution.simulation import SimulationExecutionController

T0 = 1_800_000_000_000
_DB_PREFIX = "kairos_sim_controller_"
_SIMPLE_DATABASE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,62}\Z")
_SYMBOLS = ("BTCUSDT", "ETHUSDT", "SOLUSDT", "BNBUSDT", "XRPUSDT")


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _settings() -> tuple[PersistenceSettings, str]:
    url = os.getenv("KAIROS_SIM_CONTROLLER_DATABASE_URL")
    if not url:
        pytest.skip("KAIROS_SIM_CONTROLLER_DATABASE_URL is required for simulator controller integration")
    name = urlsplit(url).path.removeprefix("/")
    if not (name.startswith(_DB_PREFIX) and _SIMPLE_DATABASE_NAME.fullmatch(name)):
        raise RuntimeError("controller integration requires a disposable kairos_sim_controller database")
    require_database_target_url(url, name, local_only=True)
    return PersistenceSettings(database_url=url), name


def _bar(symbol: str, *, open_time_ms: int = T0, low: float = 99.0, high: float = 102.0) -> ClosedBarEventV1:
    return ClosedBarEventV1(
        source="sim-controller-integration",
        symbol=symbol,
        open_time_ms=open_time_ms,
        close_time_ms=open_time_ms + 59_999,
        open=100.0,
        high=high,
        low=low,
        close=100.0,
        base_volume=10.0,
        quote_volume=1_000.0,
        taker_buy_base_volume=5.0,
        taker_buy_quote_volume=500.0,
    )


def _frame(
    *,
    tape_id: str,
    sequence: int,
    symbol: str,
    persisted_at_ms: int,
    previous_frame_sha256: str | None,
    bids: tuple[tuple[float, float], ...] = ((99.9, 1.0),),
    asks: tuple[tuple[float, float], ...] = ((100.1, 1.0),),
) -> RecordedTopNBookFrameV1:
    return RecordedTopNBookFrameV1(
        source="sim-controller-integration",
        tape_id=tape_id,
        stream_epoch="integration-epoch-1",
        symbol=symbol,
        tape_sequence=sequence,
        exchange_update_id=sequence,
        exchange_at_ms=persisted_at_ms - 10,
        received_at_ms=persisted_at_ms - 5,
        persisted_at_ms=persisted_at_ms,
        raw_payload_sha256=_hash(f"raw-{sequence}"),
        previous_frame_sha256=previous_frame_sha256,
        continuity="ADMITTED",
        bids=tuple(RecordedBookLevelV1(price=price, quantity=quantity) for price, quantity in bids),
        asks=tuple(RecordedBookLevelV1(price=price, quantity=quantity) for price, quantity in asks),
    )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_durable_controller_replays_only_sealed_inputs_and_stop_wins() -> None:
    settings, database_name = _settings()
    database = Database(settings, migration_profile=MigrationProfile.SIMULATOR)
    await connect_verified_database(database, database_name, local_only=True)
    try:
        await database.migrate()
        repository = SimulationRepository(database.pool)
        tape_id = "controller-integration-tape"
        input_bars = {symbol: _bar(symbol) for symbol in _SYMBOLS}
        exit_bar = _bar("BTCUSDT", open_time_ms=T0 + 60_000, low=94.0, high=106.0)
        for symbol in _SYMBOLS:
            assert await repository.record_closed_bar(tape_id, input_bars[symbol])
        assert await repository.record_closed_bar(tape_id, exit_bar)

        prior: str | None = None
        frames: list[RecordedTopNBookFrameV1] = []
        for sequence, symbol in enumerate(_SYMBOLS, start=1):
            frame = _frame(
                tape_id=tape_id,
                sequence=sequence,
                symbol=symbol,
                persisted_at_ms=T0 + 60_010 + sequence - 1,
                previous_frame_sha256=prior,
            )
            assert await repository.record_book_frame(frame)
            frames.append(frame)
            prior = frame.frame_sha256
        exit_frame = _frame(
            tape_id=tape_id,
            sequence=6,
            symbol="BTCUSDT",
            persisted_at_ms=T0 + 120_010,
            previous_frame_sha256=prior,
            bids=((96.0, 1.0),),
        )
        assert await repository.record_book_frame(exit_frame)
        seal = await repository.seal_tape(tape_id, sealed_at_ms=T0 + 130_000)
        assert await repository.verify_tape(tape_id)

        intent = StrategyIntentV1(
            source="sim-controller-integration",
            strategy_id="fixture-strategy",
            strategy_revision="v1",
            symbol="BTCUSDT",
            side=Side.LONG,
            decision_ts_ms=T0 + 59_999,
            entry_eligible_ts_ms=T0 + 60_000,
            entry_expires_ts_ms=T0 + 180_000,
            reference_price=100.0,
            signal_strength=0.5,
            gross_reward_bps=500.0,
            exit_plan=ExitPlanV1(stop_price=95.0, target_price=105.0, max_holding_ms=90_000),
            provenance=StrategyProvenanceV1(
                strategy_code_sha256=_hash("strategy"),
                config_sha256=_hash("config"),
                input_window_sha256=_hash("window"),
                features_sha256=_hash("features"),
                input_bar_sha256s=(input_bars["BTCUSDT"].bar_sha256,),
            ),
        )
        session = SimulationSessionV1(
            source="sim-controller-integration",
            tape_id=tape_id,
            tape_sha256=seal.tape_sha256,
            assumptions={
                "latency_ms": 25,
                "maximum_book_age_ms": 5_000,
                "maximum_frame_latency_ms": 1_000,
                "depth_participation_fraction": 1.0,
                "adverse_slippage_bps": 0.0,
                "taker_fee_bps": 5.0,
                "price_tick": 0.1,
                "quantity_step": 0.001,
            },
            strategy_allowlist=(
                SimulationStrategyRefV1(strategy_id="fixture-strategy", strategy_revision="v1"),
            ),
            started_at_ms=T0 + 60_000,
            ends_at_ms=T0 + 300_000,
        )
        assert await repository.create_session(session)
        route = CandidateRouteV1(
            source="sim-controller-integration",
            intent=intent,
            review_tier=CandidateReviewTier.NORMAL,
            requested_reasoning_effort=ReasoningEffort.MEDIUM,
            routed_at_ms=T0 + 60_000,
            review_deadline_ms=T0 + 60_100,
        )
        review = CandidateReviewV1(
            source="sim-controller-integration",
            route=route,
            intent=intent,
            decision=ReviewDecision.ALLOW,
            priority=0,
            reviewed_at_ms=T0 + 60_010,
            reviewer="DETERMINISTIC",
            reason_codes=("SIM_TEST_ALLOW",),
        )
        decision = SimulationRiskDecisionV1(
            source="sim-controller-integration",
            session=session,
            intent=intent,
            review=review,
            selected_book_frame=frames[0],
            approved=True,
            quantity=0.01,
            price_cap=100.2,
            decided_at_ms=T0 + 60_010,
        )
        assert await repository.record_risk_decision(decision)
        admission = SimulationAdmissionV2(
            source="sim-controller-integration",
            decision=decision,
            admitted_at_ms=T0 + 60_010,
        )
        controller = SimulationExecutionController(repository)
        trade = await controller.start_trade(admission, created_at_ms=T0 + 60_010)
        entry = await controller.submit_entry(trade, as_of_ms=T0 + 60_035)
        assert entry.receipt is not None and entry.receipt.status == "FILLED"
        exit_outcome = await controller.process_closed_bar(
            trade,
            exit_bar,
            as_of_ms=T0 + 120_025,
        )
        assert exit_outcome is not None and exit_outcome.receipt is not None
        assert exit_outcome.command.command_kind == "STOP_EXIT_IOC"
        assert exit_outcome.receipt.status == "FILLED"
        assert exit_outcome.lifecycle_state == "FLAT"
        assert await repository.verify_trade_chain(trade.trade_id)
        journal = await repository.load_trade_journal(trade.trade_id)
        assert journal is not None and journal.state == "FLAT" and len(journal.events) == 3
        assert await repository.list_prepared_commands(session.session_id) == ()
        assert await repository.list_terminal_trades_without_result(session.session_id) == ()
    finally:
        await database.close()
