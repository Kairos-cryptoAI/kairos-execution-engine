"""Hermetic lifecycle coverage for the isolated simulator controller."""

from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass
from pathlib import Path

import pytest
from kairos_core.contracts import (
    CandidateReviewV1,
    CandidateRouteV1,
    ClosedBarEventV1,
    ExitPlanV1,
    RecordedBookLevelV1,
    RecordedTopNBookFrameV1,
    SimulationAdmissionV2,
    SimulationCommandReceiptV1,
    SimulationCommandV1,
    SimulationResultV1,
    SimulationRiskDecisionV1,
    SimulationSessionV1,
    SimulationStrategyRefV1,
    SimulationTradeEventV2,
    SimulationTradeV1,
    StrategyIntentV1,
    StrategyProvenanceV1,
)
from kairos_core.enums import CandidateReviewTier, ReasoningEffort, ReviewDecision, Side
from kairos_persistence import (
    SimulationCommandCompletion,
    SimulationCommandPreparation,
    SimulationTradeJournal,
)

from kairos_execution.simulation import SimulationExecutionController

T0 = 1_800_000_000_000
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
_TERMINAL = {"FLAT", "UNRESOLVED", "NO_FILL", "BLOCKED"}


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass
class _Prepared:
    command: SimulationCommandV1
    status: str


class _MemoryRepository:
    """Small journal double; no external process, network, or mutable venue."""

    def __init__(self, frames: tuple[RecordedTopNBookFrameV1, ...]) -> None:
        self.frames = frames
        self.trades: dict[str, SimulationTradeV1] = {}
        self.events: dict[str, list[SimulationTradeEventV2]] = {}
        self.states: dict[str, str] = {}
        self.prepared: dict[str, _Prepared] = {}
        self.receipts: dict[str, SimulationCommandReceiptV1] = {}
        self.liquidity: dict[tuple[str, str], tuple[str, dict]] = {}
        self.results: dict[str, SimulationResultV1] = {}

    async def create_admission(self, admission: SimulationAdmissionV2) -> bool:
        del admission
        return True

    async def create_trade(self, trade: SimulationTradeV1) -> bool:
        assert trade.trade_id is not None
        if trade.trade_id in self.trades:
            assert self.trades[trade.trade_id] == trade
            return False
        self.trades[trade.trade_id] = trade
        self.events[trade.trade_id] = []
        self.states[trade.trade_id] = "PENDING"
        return True

    async def append_trade_event(self, event: SimulationTradeEventV2) -> bool:
        assert event.trade_id is not None
        recorded = self.events[event.trade_id]
        if any(current.event_id == event.event_id for current in recorded):
            return False
        assert event.event_seq == len(recorded) + 1
        assert event.previous_event_sha256 == (recorded[-1].event_id if recorded else None)
        assert event.from_state == (self.states[event.trade_id] if recorded else None)
        recorded.append(event)
        self.states[event.trade_id] = event.to_state
        return True

    async def prepare_command(self, command: SimulationCommandV1) -> SimulationCommandPreparation:
        assert command.command_id is not None
        current = self.prepared.get(command.command_id)
        if current is not None:
            assert current.command == command
            return SimulationCommandPreparation(
                command=current.command,
                created=False,
                status=current.status,  # type: ignore[arg-type]
            )
        self.prepared[command.command_id] = _Prepared(command=command, status="PREPARED")
        return SimulationCommandPreparation(command=command, created=True, status="PREPARED")

    async def complete_command(
        self,
        command: SimulationCommandV1,
        receipt: SimulationCommandReceiptV1,
        *,
        model_state_schema_version: str,
        model_state_payload: dict,
        events: tuple[SimulationTradeEventV2, ...],
    ) -> SimulationCommandCompletion:
        assert (
            command.command_id is not None and command.session_id is not None and command.symbol is not None
        )
        existing = self.receipts.get(command.command_id)
        if existing is not None:
            assert existing == receipt
            return SimulationCommandCompletion(receipt=existing, created=False)
        prepared = self.prepared[command.command_id]
        assert prepared.status == "PREPARED"
        self.receipts[command.command_id] = receipt
        self.liquidity[(command.session_id, command.symbol)] = (
            model_state_schema_version,
            model_state_payload,
        )
        for event in events:
            await self.append_trade_event(event)
        prepared.status = "COMPLETED"
        return SimulationCommandCompletion(receipt=receipt, created=True)

    async def load_command_receipt(self, command_id: str) -> SimulationCommandReceiptV1 | None:
        return self.receipts.get(command_id)

    async def load_liquidity_state(self, session_id: str, symbol: str):
        return self.liquidity.get((session_id, symbol))

    async def load_latest_book_frame(
        self,
        tape_id: str,
        symbol: str,
        *,
        as_of_ms: int,
    ) -> RecordedTopNBookFrameV1 | None:
        eligible = [
            frame
            for frame in self.frames
            if frame.tape_id == tape_id
            and frame.symbol == symbol
            and frame.continuity == "ADMITTED"
            and frame.persisted_at_ms <= as_of_ms
        ]
        return (
            max(eligible, key=lambda frame: (frame.persisted_at_ms, frame.tape_sequence))
            if eligible
            else None
        )

    async def load_trade_journal(self, trade_id: str) -> SimulationTradeJournal | None:
        trade = self.trades.get(trade_id)
        if trade is None:
            return None
        events = tuple(self.events[trade_id])
        return SimulationTradeJournal(
            trade=trade,
            state=self.states[trade_id],  # type: ignore[arg-type]
            next_event_seq=len(events) + 1,
            journal_head_sha256=None if not events else events[-1].event_id,
            events=events,
        )

    async def list_prepared_commands(self, session_id: str) -> tuple[SimulationCommandV1, ...]:
        return tuple(
            current.command
            for current in self.prepared.values()
            if current.status == "PREPARED" and current.command.session_id == session_id
        )

    async def list_terminal_trades_without_result(self, session_id: str) -> tuple[SimulationTradeV1, ...]:
        return tuple(
            trade
            for trade_id, trade in self.trades.items()
            if trade.session_id == session_id
            and self.states[trade_id] in _TERMINAL
            and trade_id not in self.results
        )

    async def record_result(self, result: SimulationResultV1) -> bool:
        existing = self.results.get(result.trade_id)
        if existing is not None:
            assert existing == result
            return False
        self.results[result.trade_id] = result
        return True


def _frame(
    *,
    sequence: int,
    persisted_at_ms: int,
    bids: tuple[tuple[float, float], ...] = ((99.9, 1.0),),
    asks: tuple[tuple[float, float], ...] = ((100.1, 1.0),),
    previous_frame_sha256: str | None = None,
) -> RecordedTopNBookFrameV1:
    return RecordedTopNBookFrameV1(
        source="controller-test",
        tape_id="sealed-tape",
        stream_epoch="test-epoch-1",
        symbol="BTCUSDT",
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


def _bar(*, low: float, high: float, close: float) -> ClosedBarEventV1:
    return ClosedBarEventV1(
        source="controller-test",
        symbol="BTCUSDT",
        open_time_ms=T0 + 60_000,
        close_time_ms=T0 + 119_999,
        open=100.0,
        high=high,
        low=low,
        close=close,
        base_volume=10.0,
        quote_volume=1_000.0,
        taker_buy_base_volume=5.0,
        taker_buy_quote_volume=500.0,
    )


def _admission(frame: RecordedTopNBookFrameV1, *, quantity: float = 0.01) -> SimulationAdmissionV2:
    intent = StrategyIntentV1(
        source="controller-test",
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
            strategy_code_sha256=SHA_A,
            config_sha256=SHA_B,
            input_window_sha256=SHA_C,
            features_sha256=SHA_D,
            input_bar_sha256s=(SHA_A,),
        ),
    )
    session = SimulationSessionV1(
        source="controller-test",
        tape_id="sealed-tape",
        tape_sha256="e" * 64,
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
        strategy_allowlist=(SimulationStrategyRefV1(strategy_id="fixture-strategy", strategy_revision="v1"),),
        started_at_ms=T0 + 60_000,
        ends_at_ms=T0 + 300_000,
    )
    route = CandidateRouteV1(
        source="controller-test",
        intent=intent,
        review_tier=CandidateReviewTier.NORMAL,
        requested_reasoning_effort=ReasoningEffort.MEDIUM,
        routed_at_ms=T0 + 60_000,
        review_deadline_ms=T0 + 60_100,
    )
    review = CandidateReviewV1(
        source="controller-test",
        route=route,
        intent=intent,
        decision=ReviewDecision.ALLOW,
        priority=0,
        reviewed_at_ms=T0 + 60_010,
        reviewer="DETERMINISTIC",
        reason_codes=("SIM_TEST_ALLOW",),
    )
    decision = SimulationRiskDecisionV1(
        source="controller-test",
        session=session,
        intent=intent,
        review=review,
        selected_book_frame=frame,
        approved=True,
        quantity=quantity,
        price_cap=100.2,
        decided_at_ms=T0 + 60_010,
    )
    return SimulationAdmissionV2(
        source="controller-test",
        decision=decision,
        admitted_at_ms=T0 + 60_010,
    )


@pytest.mark.asyncio
async def test_stop_wins_same_candle_and_produces_one_flat_simulated_result() -> None:
    entry_frame = _frame(sequence=1, persisted_at_ms=T0 + 60_010)
    exit_frame = _frame(
        sequence=2,
        persisted_at_ms=T0 + 120_010,
        bids=((96.0, 1.0),),
        previous_frame_sha256=entry_frame.frame_sha256,
    )
    repository = _MemoryRepository((entry_frame, exit_frame))
    controller = SimulationExecutionController(repository)  # type: ignore[arg-type]
    trade = await controller.start_trade(_admission(entry_frame), created_at_ms=T0 + 60_010)

    entry = await controller.submit_entry(trade, as_of_ms=T0 + 60_035)
    assert entry.receipt is not None and entry.receipt.status == "FILLED"
    assert entry.lifecycle_state == "ACTIVE"
    assert await controller.start_trade(_admission(entry_frame), created_at_ms=T0 + 60_010) == trade

    exit_outcome = await controller.process_closed_bar(
        trade,
        _bar(low=94.0, high=106.0, close=100.0),
        as_of_ms=T0 + 120_025,
    )
    assert exit_outcome is not None and exit_outcome.receipt is not None
    assert exit_outcome.command.command_kind == "STOP_EXIT_IOC"
    assert exit_outcome.receipt.status == "FILLED"
    assert exit_outcome.lifecycle_state == "FLAT"
    assert trade.trade_id is not None
    result = repository.results[trade.trade_id]
    assert result.final_state == "FLAT"
    assert result.entry_filled_quantity == pytest.approx(0.01)
    assert result.exit_filled_quantity == pytest.approx(0.01)
    assert result.venue_execution_observed is False
    assert result.paper_qualification_eligible is False


@pytest.mark.asyncio
async def test_partial_entry_and_partial_stop_exit_stay_honestly_unresolved() -> None:
    entry_frame = _frame(sequence=1, persisted_at_ms=T0 + 60_010, asks=((100.1, 0.005),))
    exit_frame = _frame(
        sequence=2,
        persisted_at_ms=T0 + 120_010,
        bids=((96.0, 0.003),),
        previous_frame_sha256=entry_frame.frame_sha256,
    )
    repository = _MemoryRepository((entry_frame, exit_frame))
    controller = SimulationExecutionController(repository)  # type: ignore[arg-type]
    trade = await controller.start_trade(_admission(entry_frame), created_at_ms=T0 + 60_010)

    entry = await controller.submit_entry(trade, as_of_ms=T0 + 60_035)
    assert entry.receipt is not None and entry.receipt.status == "PARTIAL"
    exit_outcome = await controller.process_closed_bar(
        trade,
        _bar(low=94.0, high=104.0, close=100.0),
        as_of_ms=T0 + 120_025,
    )
    assert exit_outcome is not None and exit_outcome.receipt is not None
    assert exit_outcome.receipt.status == "PARTIAL"
    assert exit_outcome.lifecycle_state == "UNRESOLVED"
    assert trade.trade_id is not None
    result = repository.results[trade.trade_id]
    assert result.final_state == "UNRESOLVED"
    assert result.entry_filled_quantity == pytest.approx(0.005)
    assert result.exit_filled_quantity == pytest.approx(0.003)


@pytest.mark.asyncio
async def test_missing_book_blocks_entry_without_synthetic_fill_and_replays_receipt() -> None:
    admission_frame = _frame(sequence=1, persisted_at_ms=T0 + 60_010)
    repository = _MemoryRepository(())
    controller = SimulationExecutionController(repository)  # type: ignore[arg-type]
    trade = await controller.start_trade(_admission(admission_frame), created_at_ms=T0 + 60_010)

    first = await controller.submit_entry(trade, as_of_ms=T0 + 60_035)
    assert first.receipt is not None and first.receipt.status == "BLOCKED"
    assert first.receipt.model_frame_sha256 is None
    assert first.lifecycle_state == "BLOCKED"
    replay = await controller.submit_entry(trade, as_of_ms=T0 + 120_000)
    assert replay.replayed and replay.receipt == first.receipt
    assert trade.trade_id is not None
    assert len(repository.events[trade.trade_id]) == 2
    assert repository.results[trade.trade_id].entry_filled_quantity == 0


@pytest.mark.asyncio
async def test_recovery_leaves_pre_arrival_command_prepared_then_completes_once() -> None:
    frame = _frame(sequence=1, persisted_at_ms=T0 + 60_010)
    repository = _MemoryRepository((frame,))
    controller = SimulationExecutionController(repository)  # type: ignore[arg-type]
    admission = _admission(frame)
    trade = await controller.start_trade(admission, created_at_ms=T0 + 60_010)

    pending = await controller.submit_entry(trade, as_of_ms=T0 + 60_020)
    assert pending.pending
    assert admission.session_id is not None
    recovered = await controller.recover_prepared(admission.session_id, as_of_ms=T0 + 60_035)
    assert len(recovered) == 1
    assert recovered[0].receipt is not None and recovered[0].receipt.status == "FILLED"
    assert await controller.recover_prepared(admission.session_id, as_of_ms=T0 + 60_050) == ()


def test_controller_has_no_external_execution_or_secret_import_path() -> None:
    module = Path(__file__).parents[1] / "kairos_execution" / "simulation" / "controller.py"
    tree = ast.parse(module.read_text(encoding="utf-8"))
    imported_modules = {
        alias.name.lower() for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names
    }
    imported_modules.update(
        (node.module or "").lower() for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    )
    forbidden = ("adapter", "sidecar", "paper", "evedex", "secret", "vault", "tradingmode")
    assert not any(token in module_name for token in forbidden for module_name in imported_modules)
