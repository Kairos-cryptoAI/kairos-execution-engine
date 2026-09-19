"""Exact public-contract to Decimal-kernel adapter coverage."""

from __future__ import annotations

import ast
from decimal import Decimal
from pathlib import Path

import pytest
from kairos_core.contracts import (
    CandidateReviewV1,
    CandidateRouteV1,
    ExitPlanV1,
    RecordedBookLevelV1,
    RecordedTopNBookFrameV1,
    SimulationAdmissionV1,
    SimulationAssumptionsV1,
    SimulationSessionV1,
    SimulationStrategyRefV1,
    SimulationTradeV1,
    StrategyIntentV1,
    StrategyProvenanceV1,
)
from kairos_core.enums import CandidateReviewTier, ReasoningEffort, ReviewDecision, Side

from kairos_execution.simulation import (
    LiquidityState,
    command_receipt,
    decimal_from_contract,
    kernel_assumptions,
    kernel_command,
    kernel_frame,
    simulate_ioc,
)

T0 = 1_800_000_000_000
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64


def _session() -> SimulationSessionV1:
    return SimulationSessionV1(
        source="simulator-test",
        tape_id="sim-tape",
        tape_sha256="e" * 64,
        assumptions=SimulationAssumptionsV1(
            latency_ms=25,
            maximum_book_age_ms=5_000,
            maximum_frame_latency_ms=1_000,
            depth_participation_fraction=0.1,
            adverse_slippage_bps=2.0,
            taker_fee_bps=5.0,
            price_tick=0.1,
            quantity_step=0.001,
        ),
        strategy_allowlist=(SimulationStrategyRefV1(strategy_id="sim-test-strategy", strategy_revision="1"),),
        started_at_ms=T0,
        ends_at_ms=T0 + 360_000,
    )


def _intent() -> StrategyIntentV1:
    return StrategyIntentV1(
        source="strategy-engine",
        strategy_id="sim-test-strategy",
        strategy_revision="1",
        symbol="BTCUSDT",
        side=Side.LONG,
        decision_ts_ms=T0 + 59_999,
        entry_eligible_ts_ms=T0 + 60_000,
        entry_expires_ts_ms=T0 + 120_000,
        reference_price=100.0,
        signal_strength=0.7,
        gross_reward_bps=500.0,
        exit_plan=ExitPlanV1(stop_price=95.0, target_price=105.0, max_holding_ms=180_000),
        provenance=StrategyProvenanceV1(
            strategy_code_sha256=SHA_A,
            config_sha256=SHA_B,
            input_window_sha256=SHA_C,
            features_sha256=SHA_D,
            input_bar_sha256s=(SHA_A, SHA_B),
        ),
    )


def _command(session: SimulationSessionV1):
    intent = _intent()
    route = CandidateRouteV1(
        source="router",
        intent=intent,
        review_tier=CandidateReviewTier.NORMAL,
        requested_reasoning_effort=ReasoningEffort.MEDIUM,
        routed_at_ms=T0 + 60_000,
        review_deadline_ms=T0 + 119_000,
    )
    CandidateReviewV1(
        source="aggregator",
        route=route,
        intent=intent,
        decision=ReviewDecision.ALLOW,
        priority=50,
        reviewed_at_ms=T0 + 60_100,
        reviewer="DETERMINISTIC",
        reason_codes=("ALLOW",),
    )
    admission = SimulationAdmissionV1(
        source="simulator-test",
        session=session,
        intent=intent,
        quantity=0.1,
        price_cap=100.2,
        admitted_at_ms=T0 + 60_100,
    )
    trade = SimulationTradeV1(source="simulator-test", admission=admission, created_at_ms=T0 + 60_100)
    from kairos_core.contracts import SimulationCommandV1

    return SimulationCommandV1(
        source="simulator-test",
        trade=trade,
        command_kind="ENTRY_IOC",
        quantity=0.1,
        price_cap=100.2,
        submitted_at_ms=T0 + 60_100,
        persisted_at_ms=T0 + 60_100,
        eligible_at_ms=T0 + 60_100,
        expires_at_ms=T0 + 120_000,
    )


def _frame() -> RecordedTopNBookFrameV1:
    return RecordedTopNBookFrameV1(
        source="quant-scouts",
        tape_id="sim-tape",
        stream_epoch="epoch-1",
        symbol="BTCUSDT",
        tape_sequence=1,
        exchange_update_id=1,
        exchange_at_ms=T0 + 60_000,
        received_at_ms=T0 + 60_050,
        persisted_at_ms=T0 + 60_100,
        raw_payload_sha256="f" * 64,
        continuity="ADMITTED",
        bids=(RecordedBookLevelV1(price=99.9, quantity=2.0),),
        asks=(RecordedBookLevelV1(price=100.1, quantity=2.0),),
    )


def test_float_contract_values_cross_decimal_boundary_through_text() -> None:
    assert decimal_from_contract(0.1, field="value") == Decimal("0.1")
    with pytest.raises(ValueError, match="finite"):
        decimal_from_contract(float("nan"), field="value")


def test_bridge_preserves_public_frame_identity_in_terminal_receipt() -> None:
    session = _session()
    command = _command(session)
    recorded_frame = _frame()
    frame = kernel_frame(recorded_frame)
    state = LiquidityState(
        session_id=session.session_id or "",
        tape_id=session.tape_id,
        stream_epoch=frame.stream_epoch,
        symbol="BTCUSDT",
    )

    step = simulate_ioc(
        kernel_command(command),
        frame,
        kernel_assumptions(session),
        state,
        as_of_ms=T0 + 60_200,
    )
    receipt = command_receipt(
        command=command,
        outcome=step.outcome,
        recorded_frame=recorded_frame,
        source="market-simulator",
    )

    assert receipt.status == "FILLED"
    assert receipt.model_frame_sha256 == recorded_frame.frame_sha256
    assert receipt.model_frame_sha256 != step.outcome.frame_sha256
    assert receipt.average_price == pytest.approx(100.2)
    assert receipt.filled_quantity == pytest.approx(0.1)


def test_bridge_has_no_external_execution_import() -> None:
    module = Path(__file__).parents[1] / "kairos_execution" / "simulation" / "bridge.py"
    tree = ast.parse(module.read_text(encoding="utf-8"))
    imported_modules = {
        alias.name.lower() for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names
    }
    imported_modules.update(
        (node.module or "").lower() for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    )

    assert not any("adapter" in name or "sidecar" in name or "paper" in name for name in imported_modules)
