"""Causal IOC depth walk with explicit assumptions and no process/network state."""

from __future__ import annotations

from decimal import ROUND_CEILING, ROUND_FLOOR, Context, Decimal, localcontext
from typing import Any

from .models import (
    MAX_COMMANDS,
    AcceptedBookFrame,
    BookSide,
    CommandReceipt,
    ConsumedDepth,
    FillAssumptions,
    FillOutcome,
    IOCCommand,
    LevelFill,
    LiquidityState,
    ModelStep,
)

_ARITHMETIC = Context(prec=96)
_ZERO = Decimal(0)
_BPS = Decimal(10_000)


class SimulationIdentityConflict(ValueError):
    """A caller attempted to reuse or mix immutable simulation identities."""


def _frame_issue(
    frame: AcceptedBookFrame, state: LiquidityState, arrival: int, policy: FillAssumptions
) -> str | None:
    if state.barrier_reason is not None:
        return state.barrier_reason
    if frame.stream_epoch != state.stream_epoch:
        return "STREAM_EPOCH_CHANGED"
    if frame.continuity != "ADMITTED":
        return f"SOURCE_{frame.continuity}"
    if frame.persisted_at_ms > arrival:
        return "FRAME_NOT_DURABLE_AT_ARRIVAL"
    if arrival - frame.exchange_at_ms > policy.maximum_book_age_ms:
        return "STALE_BOOK"
    if frame.received_at_ms - frame.exchange_at_ms > policy.maximum_frame_latency_ms:
        return "EXCESSIVE_FRAME_LATENCY"
    if frame.sequence < state.last_frame_sequence:
        return "FRAME_SEQUENCE_REGRESSION"
    if frame.sequence == state.last_frame_sequence:
        if frame.fingerprint() != state.last_frame_sha256:
            return "FRAME_IDENTITY_CONFLICT"
    elif (
        frame.exchange_update_id <= state.last_exchange_update_id
        or frame.exchange_at_ms < state.last_exchange_at_ms
        or frame.received_at_ms < state.last_received_at_ms
    ):
        return "EXCHANGE_ORDER_REGRESSION"
    if any(level.price % policy.price_tick for level in (*frame.bids, *frame.asks)):
        return "BOOK_PRICE_RULE_MISMATCH"
    if any(level.quantity % policy.quantity_step for level in (*frame.bids, *frame.asks)):
        return "BOOK_QUANTITY_RULE_MISMATCH"
    return None


def simulate_ioc(
    command: IOCCommand,
    frame: AcceptedBookFrame,
    assumptions: FillAssumptions,
    state: LiquidityState,
    *,
    as_of_ms: int,
) -> ModelStep:
    """Return a model outcome and next immutable state; never persist or contact a venue.

    The caller must have admitted/persisted the input tape and atomically store the
    returned state/outcome. ``ADMITTED`` is evidence supplied by that caller, not a
    guarantee this pure function can establish. Only already-durable snapshots at
    order arrival may fill; historical price gaps are never interpolated.
    """
    command = IOCCommand.model_validate(command)
    frame = AcceptedBookFrame.model_validate(frame)
    assumptions = FillAssumptions.model_validate(assumptions)
    state = LiquidityState.model_validate(state)
    if isinstance(as_of_ms, bool) or not isinstance(as_of_ms, int) or as_of_ms < state.last_as_of_ms:
        raise ValueError("as_of_ms must be a non-negative non-regressing integer clock event")
    if command.session_id != state.session_id or command.symbol != state.symbol:
        raise SimulationIdentityConflict("command belongs to a different simulation session/symbol")
    if frame.tape_id != state.tape_id or frame.symbol != state.symbol:
        raise SimulationIdentityConflict("book belongs to a different tape/symbol")
    policy_hash = assumptions.fingerprint()
    command_hash = command.fingerprint()
    if state.assumptions_sha256 not in {None, policy_hash}:
        raise SimulationIdentityConflict("simulation assumptions changed inside one session")
    for receipt in state.receipts:
        if receipt.command_id == command.command_id:
            if receipt.command_sha256 != command_hash or receipt.assumptions_sha256 != policy_hash:
                raise SimulationIdentityConflict("command ID was reused with different content")
            return ModelStep(outcome=receipt.outcome, state=state, replayed=True)
    if len(state.receipts) >= MAX_COMMANDS:
        raise ValueError("bounded simulation receipt capacity exhausted; never evict idempotency evidence")
    if command.submitted_at_ms + assumptions.latency_ms < state.last_arrival_at_ms:
        raise SimulationIdentityConflict("new command arrival predates an already processed terminal command")

    with localcontext(_ARITHMETIC):
        return _evaluate(command, frame, assumptions, state, as_of_ms, command_hash, policy_hash)


def _evaluate(
    command: IOCCommand,
    frame: AcceptedBookFrame,
    policy: FillAssumptions,
    state: LiquidityState,
    as_of_ms: int,
    command_hash: str,
    policy_hash: str,
) -> ModelStep:
    arrival = command.submitted_at_ms + policy.latency_ms
    outcome_fields: dict[str, Any] = dict(
        command_id=command.command_id,
        command_sha256=command_hash,
        assumptions_sha256=policy_hash,
        frame_sha256=frame.fingerprint(),
        arrival_at_ms=arrival,
        requested_quantity=command.quantity,
        filled_quantity=_ZERO,
        cancelled_quantity=command.quantity,
        notional_quote=_ZERO,
        fee_quote=_ZERO,
        implementation_shortfall_quote=_ZERO,
        level_fills=(),
    )
    if as_of_ms < arrival:
        outcome = FillOutcome(
            **(outcome_fields | dict(status="WAIT", reason="NOT_ARRIVED", cancelled_quantity=_ZERO))
        )
        return ModelStep(outcome=outcome, state=state)

    state_fields = state.model_dump(mode="python") | dict(
        assumptions_sha256=policy_hash,
        last_as_of_ms=as_of_ms,
        last_arrival_at_ms=arrival,
    )
    reason = None
    if command.persisted_at_ms > arrival:
        reason = "COMMAND_NOT_DURABLE_AT_ARRIVAL"
    elif arrival < command.eligible_at_ms or command.submitted_at_ms < command.eligible_at_ms:
        reason = "NOT_YET_ELIGIBLE"
    elif arrival > command.expires_at_ms:
        reason = "ENTRY_EXPIRED"
    elif command.quantity % policy.quantity_step:
        reason = "INVALID_QUANTITY_STEP"
    elif command.price_cap % policy.price_tick:
        reason = "INVALID_PRICE_CAP_STEP"
    if reason is not None:
        outcome = FillOutcome(**outcome_fields, status="NO_FILL", reason=reason)
    elif (issue := _frame_issue(frame, state, arrival, policy)) is not None:
        state_fields["barrier_reason"] = issue
        outcome = FillOutcome(**outcome_fields, status="BLOCKED", reason=issue)
    else:
        state_fields.update(
            last_frame_sequence=frame.sequence,
            last_frame_sha256=frame.fingerprint(),
            last_exchange_update_id=frame.exchange_update_id,
            last_exchange_at_ms=frame.exchange_at_ms,
            last_received_at_ms=frame.received_at_ms,
        )
        fills, consumption = _walk(command, frame, policy, state)
        quantity = sum((fill.quantity for fill in fills), _ZERO)
        notional = sum((fill.execution_price * fill.quantity for fill in fills), _ZERO)
        fees = sum((fill.fee_quote for fill in fills), _ZERO)
        mid = (frame.bids[0].price + frame.asks[0].price) / 2
        direction = Decimal(1) if command.side == "BUY" else Decimal(-1)
        shortfall = (notional - quantity * mid) * direction
        status = "NO_FILL" if quantity == 0 else "FILLED" if quantity == command.quantity else "PARTIAL"
        outcome = FillOutcome(
            **(
                outcome_fields
                | dict(
                    status=status,
                    reason="NO_EXECUTABLE_DISPLAYED_CAPACITY" if quantity == 0 else "MODEL_IOC",
                    filled_quantity=quantity,
                    cancelled_quantity=command.quantity - quantity,
                    notional_quote=notional,
                    fee_quote=fees,
                    average_price=notional / quantity if quantity else None,
                    arrival_mid_price=mid,
                    implementation_shortfall_quote=shortfall,
                    level_fills=fills,
                )
            )
        )
        state_fields["consumed_depth"] = consumption

    receipt = CommandReceipt(
        command_id=command.command_id,
        command_sha256=command_hash,
        assumptions_sha256=policy_hash,
        outcome=outcome,
    )
    state_fields["receipts"] = (*state.receipts, receipt)
    return ModelStep(outcome=outcome, state=LiquidityState.model_validate(state_fields))


def _walk(
    command: IOCCommand,
    frame: AcceptedBookFrame,
    policy: FillAssumptions,
    state: LiquidityState,
) -> tuple[tuple[LevelFill, ...], tuple[ConsumedDepth, ...]]:
    consumed = {(item.side, item.price): item.quantity for item in state.consumed_depth}
    buying = command.side == "BUY"
    book_side: BookSide = "ASK" if buying else "BID"
    levels = frame.asks if buying else frame.bids
    direction = Decimal(1) if buying else Decimal(-1)
    remaining = command.quantity
    fills: list[LevelFill] = []
    for level in levels:
        raw_price = level.price * (1 + direction * policy.adverse_slippage_bps / _BPS)
        price = (raw_price / policy.price_tick).to_integral_value(
            rounding=ROUND_CEILING if buying else ROUND_FLOOR,
        ) * policy.price_tick
        if price <= 0 or (buying and price > command.price_cap) or (not buying and price < command.price_cap):
            break
        key = (book_side, level.price)
        debit = consumed.get(key, _ZERO)
        available = max(_ZERO, level.quantity * policy.depth_participation_fraction - debit)
        capacity = (available / policy.quantity_step).to_integral_value(
            rounding=ROUND_FLOOR
        ) * policy.quantity_step
        quantity = min(remaining, capacity)
        if quantity == 0:
            continue
        fills.append(
            LevelFill(
                book_price=level.price,
                execution_price=price,
                quantity=quantity,
                fee_quote=quantity * price * policy.taker_fee_bps / _BPS,
            )
        )
        consumed[key] = debit + quantity
        remaining -= quantity
        if remaining == 0:
            break
    consumption = tuple(
        ConsumedDepth(side=side, price=price, quantity=quantity)
        for (side, price), quantity in sorted(consumed.items())
    )
    return tuple(fills), consumption
