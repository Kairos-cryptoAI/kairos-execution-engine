"""Exact adapter between public SIM contracts and the pure Decimal IOC kernel."""

from __future__ import annotations

import math
from decimal import Decimal

from kairos_core.contracts import (
    RecordedTopNBookFrameV1,
    SimulationCommandReceiptV1,
    SimulationCommandV1,
    SimulationFillLevelV1,
    SimulationSessionV1,
)

from .models import AcceptedBookFrame, BookLevel, FillAssumptions, FillOutcome, IOCCommand


def decimal_from_contract(value: float, *, field: str) -> Decimal:
    """Convert a finite float through its decimal text, never binary storage."""

    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError(f"{field} must be a finite numeric contract value")
    return Decimal(str(value))


def kernel_frame(frame: RecordedTopNBookFrameV1) -> AcceptedBookFrame:
    """Map one immutable recorded public frame into the pure kernel DTO."""

    return AcceptedBookFrame(
        tape_id=frame.tape_id,
        stream_epoch=frame.stream_epoch,
        symbol=frame.symbol,
        sequence=frame.tape_sequence,
        exchange_update_id=frame.exchange_update_id,
        exchange_at_ms=frame.exchange_at_ms,
        received_at_ms=frame.received_at_ms,
        persisted_at_ms=frame.persisted_at_ms,
        raw_payload_sha256=frame.raw_payload_sha256,
        continuity=frame.continuity,
        bids=tuple(
            BookLevel(
                price=decimal_from_contract(level.price, field="bid_price"),
                quantity=decimal_from_contract(level.quantity, field="bid_quantity"),
            )
            for level in frame.bids
        ),
        asks=tuple(
            BookLevel(
                price=decimal_from_contract(level.price, field="ask_price"),
                quantity=decimal_from_contract(level.quantity, field="ask_quantity"),
            )
            for level in frame.asks
        ),
    )


def kernel_assumptions(session: SimulationSessionV1) -> FillAssumptions:
    """Map frozen public assumptions into exact kernel arithmetic inputs."""

    values = session.assumptions
    return FillAssumptions(
        latency_ms=values.latency_ms,
        maximum_book_age_ms=values.maximum_book_age_ms,
        maximum_frame_latency_ms=values.maximum_frame_latency_ms,
        depth_participation_fraction=decimal_from_contract(
            values.depth_participation_fraction,
            field="depth_participation_fraction",
        ),
        adverse_slippage_bps=decimal_from_contract(
            values.adverse_slippage_bps,
            field="adverse_slippage_bps",
        ),
        taker_fee_bps=decimal_from_contract(values.taker_fee_bps, field="taker_fee_bps"),
        price_tick=decimal_from_contract(values.price_tick, field="price_tick"),
        quantity_step=decimal_from_contract(values.quantity_step, field="quantity_step"),
    )


def kernel_command(command: SimulationCommandV1) -> IOCCommand:
    """Map a typed SIM command into a pure IOC kernel command."""

    if command.command_id is None or command.session_id is None or command.symbol is None:
        raise ValueError("simulation command must carry canonical session, command and symbol identities")
    if command.order_side is None:
        raise ValueError("simulation command must carry its derived order side")
    return IOCCommand(
        session_id=command.session_id,
        command_id=command.command_id,
        symbol=command.symbol,
        side=command.order_side,
        quantity=decimal_from_contract(command.quantity, field="quantity"),
        price_cap=decimal_from_contract(command.price_cap, field="price_cap"),
        submitted_at_ms=command.submitted_at_ms,
        persisted_at_ms=command.persisted_at_ms,
        eligible_at_ms=command.eligible_at_ms,
        expires_at_ms=command.expires_at_ms,
    )


def command_receipt(
    *,
    command: SimulationCommandV1,
    outcome: FillOutcome,
    recorded_frame: RecordedTopNBookFrameV1 | None,
    source: str,
) -> SimulationCommandReceiptV1:
    """Convert one terminal kernel outcome into its public immutable receipt."""

    if outcome.status == "WAIT":
        raise ValueError("a non-terminal kernel WAIT outcome cannot become durable evidence")
    if outcome.status not in {"FILLED", "PARTIAL", "NO_FILL", "BLOCKED"}:
        raise ValueError("kernel outcome has an unknown terminal status")
    filled = float(outcome.filled_quantity)
    if filled > 0:
        if recorded_frame is None or recorded_frame.frame_sha256 is None:
            raise ValueError("a terminal model fill requires its exact public recorded book frame")
        return SimulationCommandReceiptV1(
            source=source,
            command=command,
            model_frame_sha256=recorded_frame.frame_sha256,
            status=outcome.status,
            reason_codes=(outcome.reason,),
            arrival_at_ms=outcome.arrival_at_ms,
            filled_quantity=filled,
            cancelled_quantity=float(outcome.cancelled_quantity),
            average_price=_float(outcome.average_price, field="average_price"),
            notional_quote=float(outcome.notional_quote),
            fee_quote=float(outcome.fee_quote),
            arrival_mid_price=_float(outcome.arrival_mid_price, field="arrival_mid_price"),
            implementation_shortfall_quote=float(outcome.implementation_shortfall_quote),
            level_fills=tuple(
                SimulationFillLevelV1(
                    book_price=float(level.book_price),
                    execution_price=float(level.execution_price),
                    quantity=float(level.quantity),
                    fee_quote=float(level.fee_quote),
                )
                for level in outcome.level_fills
            ),
        )
    return SimulationCommandReceiptV1(
        source=source,
        command=command,
        status=outcome.status,
        reason_codes=(outcome.reason,),
        arrival_at_ms=outcome.arrival_at_ms,
        filled_quantity=0.0,
        cancelled_quantity=float(outcome.cancelled_quantity),
        notional_quote=0.0,
        fee_quote=0.0,
        implementation_shortfall_quote=0.0,
    )


def _float(value: Decimal | None, *, field: str) -> float:
    if value is None:
        raise ValueError(f"{field} is required for a non-zero model fill")
    result = float(value)
    if not math.isfinite(result) or result <= 0:
        raise ValueError(f"{field} cannot be represented as a positive finite float")
    return result
