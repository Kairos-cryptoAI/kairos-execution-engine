"""Hermetic tests for a model kernel, not venue or simulator qualification."""

from decimal import ROUND_DOWN, Decimal, localcontext
from itertools import product

import pytest
from pydantic import ValidationError

from kairos_execution.simulation import (
    AcceptedBookFrame,
    BookLevel,
    FillAssumptions,
    FillOutcome,
    IOCCommand,
    LiquidityState,
    SimulationIdentityConflict,
    simulate_ioc,
)
from kairos_execution.simulation.models import MAX_COMMANDS, CommandReceipt, ConsumedDepth

D = Decimal


def frame(**updates: object) -> AcceptedBookFrame:
    fields = dict(
        tape_id="test-tape",
        stream_epoch="epoch-1",
        symbol="BTCUSDT",
        sequence=1,
        exchange_update_id=100,
        exchange_at_ms=1_000,
        received_at_ms=1_010,
        persisted_at_ms=1_020,
        raw_payload_sha256="a" * 64,
        continuity="ADMITTED",
        bids=(BookLevel(price=D("99"), quantity=D("2")), BookLevel(price=D("98"), quantity=D("3"))),
        asks=(BookLevel(price=D("101"), quantity=D("2")), BookLevel(price=D("102"), quantity=D("3"))),
    )
    return AcceptedBookFrame.model_validate(fields | updates)


def command(**updates: object) -> IOCCommand:
    fields = dict(
        session_id="test-session",
        command_id="command-1",
        symbol="BTCUSDT",
        side="BUY",
        quantity=D("1"),
        price_cap=D("110"),
        submitted_at_ms=1_100,
        persisted_at_ms=1_110,
        eligible_at_ms=1_100,
        expires_at_ms=2_000,
    )
    return IOCCommand.model_validate(fields | updates)


def policy(**updates: object) -> FillAssumptions:
    fields = dict(
        latency_ms=100,
        maximum_book_age_ms=500,
        maximum_frame_latency_ms=100,
        depth_participation_fraction=D("0.5"),
        adverse_slippage_bps=D("0"),
        taker_fee_bps=D("10"),
        price_tick=D("0.01"),
        quantity_step=D("0.1"),
    )
    return FillAssumptions.model_validate(fields | updates)


def state(**updates: object) -> LiquidityState:
    return LiquidityState.model_validate(
        dict(
            session_id="test-session",
            tape_id="test-tape",
            stream_epoch="epoch-1",
            symbol="BTCUSDT",
        )
        | updates
    )


def run(
    order: IOCCommand | None = None,
    book: AcceptedBookFrame | None = None,
    assumptions: FillAssumptions | None = None,
    prior: LiquidityState | None = None,
    as_of_ms: int = 1_200,
):
    return simulate_ioc(
        order or command(), book or frame(), assumptions or policy(), prior or state(), as_of_ms=as_of_ms
    )


def test_full_buy_is_a_model_fill_with_spread_and_explicit_taker_fee() -> None:
    original = state()
    step = run(prior=original)
    outcome = step.outcome
    assert outcome.status == "FILLED"
    assert outcome.filled_quantity == D("1")
    assert outcome.cancelled_quantity == 0
    assert outcome.notional_quote == D("101")
    assert outcome.average_price == D("101")
    assert outcome.fee_quote == D("0.101")
    assert outcome.arrival_mid_price == D("100")
    assert outcome.implementation_shortfall_quote == D("1")
    assert outcome.quote_asset == "USDT"
    assert outcome.execution_kind == "SIMULATED"
    assert not outcome.venue_execution_observed and not outcome.alpha_claim
    assert original == state()
    assert step.state.last_arrival_at_ms == step.state.last_as_of_ms == 1_200
    assert step.state.consumed_depth == (ConsumedDepth(side="ASK", price=D("101"), quantity=D("1")),)


@pytest.mark.parametrize("side,cap,expected", [("BUY", "110", "101.11"), ("SELL", "90", "98.90")])
def test_adverse_slippage_rounds_away_from_trader_and_taker_fee_uses_actual_price(
    side: str,
    cap: str,
    expected: str,
) -> None:
    outcome = run(
        command(side=side, price_cap=D(cap)), assumptions=policy(adverse_slippage_bps=D("10"))
    ).outcome
    assert outcome.average_price == D(expected)
    assert outcome.fee_quote == D(expected) / 1_000
    assert outcome.implementation_shortfall_quote == abs(D(expected) - D("100"))


@pytest.mark.parametrize("side,cap", [("BUY", "101.10"), ("SELL", "98.91")])
def test_limit_caps_apply_to_adverse_execution_price_not_unadjusted_quote(side: str, cap: str) -> None:
    step = run(command(side=side, price_cap=D(cap)), assumptions=policy(adverse_slippage_bps=D("10")))
    assert step.outcome.status == "NO_FILL"
    assert step.outcome.cancelled_quantity == 1
    assert not step.state.consumed_depth


def test_book_walk_partial_fill_never_extrapolates_beyond_displayed_haircut_depth() -> None:
    outcome = run(command(quantity=D("3"))).outcome
    assert outcome.status == "PARTIAL"
    assert [fill.quantity for fill in outcome.level_fills] == [D("1"), D("1.5")]
    assert [fill.execution_price for fill in outcome.level_fills] == [D("101"), D("102")]
    assert outcome.filled_quantity == D("2.5")
    assert outcome.cancelled_quantity == D("0.5")
    assert outcome.notional_quote == D("254")
    assert outcome.fee_quote == D("0.254")
    assert outcome.average_price == D("101.6")


def test_price_cap_and_quantity_rounding_are_conservative() -> None:
    limited = run(command(quantity=D("3"), price_cap=D("101"))).outcome
    assert limited.filled_quantity == 1 and limited.cancelled_quantity == 2
    rounded = run(
        command(quantity=D("3")), assumptions=policy(depth_participation_fraction=D("0.33"))
    ).outcome
    assert [fill.quantity for fill in rounded.level_fills] == [D("0.6"), D("0.9")]
    assert rounded.filled_quantity == D("1.5")


def test_distinct_commands_share_consumption_on_the_same_frame() -> None:
    first = run(command(price_cap=D("101")))
    second = run(command(command_id="command-2", price_cap=D("101")), prior=first.state)
    assert second.outcome.status == "NO_FILL"
    assert second.outcome.reason == "NO_EXECUTABLE_DISPLAYED_CAPACITY"
    assert second.state.consumed_depth == first.state.consumed_depth
    opposite = run(command(command_id="command-3", side="SELL", price_cap=D("99")), prior=second.state)
    assert opposite.outcome.status == "FILLED"
    assert len(opposite.state.consumed_depth) == 2


def test_new_snapshot_or_temporarily_missing_price_does_not_reset_cumulative_depth_debit() -> None:
    first = run(command(price_cap=D("101")))
    absent = frame(sequence=2, exchange_update_id=101, asks=(BookLevel(price=D("102"), quantity=D("3")),))
    second = run(command(command_id="command-2", price_cap=D("101")), absent, prior=first.state)
    returned = frame(sequence=3, exchange_update_id=102)
    third = run(command(command_id="command-3", price_cap=D("101")), returned, prior=second.state)
    assert third.outcome.filled_quantity == 0
    assert third.state.consumed_depth == first.state.consumed_depth


def test_larger_new_displayed_depth_only_exposes_capacity_above_prior_debit() -> None:
    first = run(command(price_cap=D("101")))
    bigger = frame(sequence=2, exchange_update_id=101, asks=(BookLevel(price=D("101"), quantity=D("3")),))
    second = run(command(command_id="command-2", price_cap=D("101")), bigger, prior=first.state)
    assert second.outcome.filled_quantity == D("0.5")
    assert second.outcome.cancelled_quantity == D("0.5")


def test_wait_is_non_terminal_and_does_not_consume_book_or_remember_identity() -> None:
    original = state()
    waiting = run(prior=original, as_of_ms=1_199)
    assert waiting.outcome.status == "WAIT"
    assert waiting.outcome.filled_quantity == waiting.outcome.cancelled_quantity == 0
    assert waiting.state == original and not waiting.state.receipts
    completed = run(prior=waiting.state)
    assert completed.outcome.status == "FILLED" and len(completed.state.receipts) == 1


@pytest.mark.parametrize(
    "updates,reason",
    [
        ({"persisted_at_ms": 1_201}, "COMMAND_NOT_DURABLE_AT_ARRIVAL"),
        ({"eligible_at_ms": 1_101}, "NOT_YET_ELIGIBLE"),
        ({"eligible_at_ms": 1_201}, "NOT_YET_ELIGIBLE"),
        ({"expires_at_ms": 1_199}, "ENTRY_EXPIRED"),
        ({"quantity": D("0.15")}, "INVALID_QUANTITY_STEP"),
        ({"price_cap": D("110.001")}, "INVALID_PRICE_CAP_STEP"),
    ],
)
def test_rejected_command_is_terminal_and_does_not_consume_depth(updates: dict, reason: str) -> None:
    result = run(command(**updates))
    assert result.outcome.status == "NO_FILL" and result.outcome.reason == reason
    assert result.outcome.cancelled_quantity == result.outcome.requested_quantity
    assert not result.state.consumed_depth and result.state.barrier_reason is None
    assert len(result.state.receipts) == 1


def test_exact_expiry_and_age_boundaries_are_inclusive() -> None:
    result = run(command(expires_at_ms=1_200), assumptions=policy(maximum_book_age_ms=200))
    assert result.outcome.status == "FILLED"


@pytest.mark.parametrize("continuity", ["GAP", "RECONNECT", "UNKNOWN", "UNAVAILABLE"])
def test_continuity_failure_sets_sticky_barrier_even_if_a_fresh_frame_follows(continuity: str) -> None:
    first = run(book=frame(continuity=continuity, bids=(), asks=()))
    assert first.outcome.status == "BLOCKED" and first.outcome.reason == f"SOURCE_{continuity}"
    second = run(
        command(command_id="command-2"), frame(sequence=2, exchange_update_id=101), prior=first.state
    )
    assert second.outcome.status == "BLOCKED"
    assert second.state.barrier_reason == first.state.barrier_reason
    assert not second.state.consumed_depth


@pytest.mark.parametrize(
    "book_updates,policy_updates,reason",
    [
        ({"stream_epoch": "epoch-2"}, {}, "STREAM_EPOCH_CHANGED"),
        ({"persisted_at_ms": 1_201}, {}, "FRAME_NOT_DURABLE_AT_ARRIVAL"),
        ({"received_at_ms": 1_201, "persisted_at_ms": 1_202}, {}, "FRAME_NOT_DURABLE_AT_ARRIVAL"),
        (
            {"exchange_at_ms": 1_201, "received_at_ms": 1_202, "persisted_at_ms": 1_203},
            {},
            "FRAME_NOT_DURABLE_AT_ARRIVAL",
        ),
        ({}, {"maximum_book_age_ms": 199}, "STALE_BOOK"),
        ({}, {"maximum_frame_latency_ms": 9}, "EXCESSIVE_FRAME_LATENCY"),
        ({"asks": (BookLevel(price=D("101.001"), quantity=D("2")),)}, {}, "BOOK_PRICE_RULE_MISMATCH"),
        ({"asks": (BookLevel(price=D("101"), quantity=D("2.01")),)}, {}, "BOOK_QUANTITY_RULE_MISMATCH"),
    ],
)
def test_unusable_frame_never_becomes_a_fill(book_updates: dict, policy_updates: dict, reason: str) -> None:
    result = run(book=frame(**book_updates), assumptions=policy(**policy_updates))
    assert result.outcome.status == "BLOCKED" and result.outcome.reason == reason
    assert not result.state.consumed_depth


@pytest.mark.parametrize(
    "updates,reason",
    [
        ({"sequence": 1}, "FRAME_SEQUENCE_REGRESSION"),
        ({"sequence": 2, "raw_payload_sha256": "b" * 64}, "FRAME_IDENTITY_CONFLICT"),
        ({"sequence": 3, "exchange_update_id": 100}, "EXCHANGE_ORDER_REGRESSION"),
        ({"sequence": 3, "exchange_update_id": 102, "exchange_at_ms": 999}, "EXCHANGE_ORDER_REGRESSION"),
        ({"sequence": 3, "exchange_update_id": 102, "received_at_ms": 1_009}, "EXCHANGE_ORDER_REGRESSION"),
    ],
)
def test_book_identity_and_explicit_order_must_not_regress(updates: dict, reason: str) -> None:
    first = run(book=frame(sequence=2, exchange_update_id=101))
    broken = frame(**(dict(sequence=2, exchange_update_id=101) | updates))
    result = run(command(command_id="command-2"), broken, prior=first.state)
    assert result.outcome.status == "BLOCKED" and result.outcome.reason == reason
    assert result.state.consumed_depth == first.state.consumed_depth


def test_skipped_unselected_frames_require_caller_admission_not_synthetic_gap_detection() -> None:
    first = run()
    later = frame(sequence=19, exchange_update_id=200)
    result = run(command(command_id="command-2", quantity=D("2")), later, prior=first.state)
    assert result.outcome.status == "PARTIAL"
    assert result.state.last_frame_sequence == 19


def test_new_backdated_command_is_rejected_even_when_evaluation_time_has_advanced() -> None:
    first = run()
    old = command(
        command_id="command-old", submitted_at_ms=1_099, persisted_at_ms=1_100, eligible_at_ms=1_099
    )
    with pytest.raises(SimulationIdentityConflict, match="arrival predates"):
        run(old, prior=first.state, as_of_ms=1_500)


@pytest.mark.parametrize("clock", [-1, True, 1_199, D("1200"), 1_200.0])
def test_clock_is_strict_and_non_regressing(clock: object) -> None:
    first = run()
    with pytest.raises(ValueError, match="clock event"):
        run(command(command_id="command-2"), prior=first.state, as_of_ms=clock)


def test_restart_round_trip_replays_exact_outcome_without_consuming_again() -> None:
    first = run()
    reloaded = LiquidityState.model_validate_json(first.state.canonical_bytes())
    fresh_frame = frame(sequence=2, exchange_update_id=101)
    duplicate = run(book=fresh_frame, prior=reloaded, as_of_ms=1_500)
    assert duplicate.replayed
    assert duplicate.outcome.canonical_bytes() == first.outcome.canonical_bytes()
    assert duplicate.state == reloaded
    next_order = run(command(command_id="command-2", price_cap=D("101")), fresh_frame, prior=reloaded)
    assert next_order.outcome.status == "NO_FILL"


@pytest.mark.parametrize("updates", [{"quantity": D("2")}, {"price_cap": D("111")}, {"expires_at_ms": 2_001}])
def test_reused_command_id_cannot_change_content_after_restart(updates: dict) -> None:
    first = run()
    with pytest.raises(SimulationIdentityConflict, match="reused with different"):
        run(command(**updates), prior=LiquidityState.model_validate_json(first.state.model_dump_json()))


@pytest.mark.parametrize(
    "part,updates",
    [
        ("command", {"session_id": "another-session"}),
        ("command", {"symbol": "ETHUSDT"}),
        ("frame", {"symbol": "ETHUSDT"}),
        ("frame", {"tape_id": "another-tape"}),
        ("policy", {"taker_fee_bps": D("11")}),
    ],
)
def test_scope_and_assumption_fingerprint_cannot_drift(part: str, updates: dict) -> None:
    first = run()
    with pytest.raises(SimulationIdentityConflict):
        run(
            command(**updates) if part == "command" else command(command_id="command-2"),
            frame(**updates) if part == "frame" else frame(),
            policy(**updates) if part == "policy" else policy(),
            first.state,
        )


def test_canonical_fingerprints_ignore_decimal_spelling_and_negative_zero() -> None:
    assert command(quantity=D("1.000")).canonical_bytes() == command(quantity=D("1")).canonical_bytes()
    assert policy(adverse_slippage_bps=D("-0.00")).fingerprint() == policy().fingerprint()
    assert command(price_cap=D("111")).fingerprint() != command().fingerprint()


def test_fixed_arithmetic_does_not_depend_on_process_decimal_context() -> None:
    request = command(quantity=D("2.3"))
    expected = run(request).outcome.canonical_bytes()
    with localcontext() as ambient:
        ambient.prec = 6
        ambient.rounding = ROUND_DOWN
        actual = run(request).outcome.canonical_bytes()
    assert actual == expected


@pytest.mark.parametrize(
    "value", [D("NaN"), D("Infinity"), D("-Infinity"), D("0"), D("-1"), D("1e19"), 1.0, "1", True]
)
def test_amount_inputs_reject_nonfinite_nonpositive_oversized_or_coerced_values(value: object) -> None:
    with pytest.raises(ValidationError):
        command(quantity=value)


@pytest.mark.parametrize(
    "updates",
    [
        {"sequence": True},
        {"received_at_ms": 1_010.0},
        {"raw_payload_sha256": "not-a-sha256"},
        {"exchange_at_ms": 1_011},
        {"persisted_at_ms": 1_009},
        {"bids": ()},
        {"asks": ()},
        {"asks": (BookLevel(price=D("99"), quantity=D("1")),)},
        {"bids": (BookLevel(price=D("99"), quantity=D("1")), BookLevel(price=D("99"), quantity=D("2")))},
        {"asks": (BookLevel(price=D("102"), quantity=D("1")), BookLevel(price=D("101"), quantity=D("2")))},
        {"side_channel": "not-allowed"},
    ],
)
def test_frame_schema_is_strict_ordered_uncrossed_and_timed(updates: dict) -> None:
    with pytest.raises(ValidationError):
        frame(**updates)


@pytest.mark.parametrize(
    "updates",
    [
        {"depth_participation_fraction": D("0")},
        {"depth_participation_fraction": D("1.01")},
        {"adverse_slippage_bps": D("10000")},
        {"adverse_slippage_bps": D("-1")},
        {"taker_fee_bps": D("10001")},
        {"latency_ms": True},
        {"maximum_book_age_ms": 0},
        {"price_tick": D("0")},
        {"maker_queue": True},
    ],
)
def test_model_assumptions_are_explicit_and_bounded(updates: dict) -> None:
    with pytest.raises(ValidationError):
        policy(**updates)


def test_models_are_frozen_and_construct_bypass_is_revalidated_on_entry() -> None:
    book = frame()
    with pytest.raises(ValidationError):
        book.sequence = 2
    invalid = command().model_copy(update={"quantity": D("NaN")})
    with pytest.raises(ValidationError):
        run(invalid)


@pytest.mark.parametrize(
    "updates",
    [
        {"notional_quote": D("1")},
        {"filled_quantity": D("0.5")},
        {"fee_quote": D("0")},
        {"cancelled_quantity": D("1")},
        {"average_price": D("100")},
        {"status": "NO_FILL"},
        {"arrival_mid_price": None},
        {"venue_execution_observed": True},
        {"alpha_claim": True},
    ],
)
def test_tampered_receipt_totals_or_qualification_claims_are_rejected(updates: dict) -> None:
    outcome = run().outcome
    with pytest.raises(ValidationError):
        FillOutcome.model_validate(outcome.model_dump(mode="python") | updates)


def test_receipt_order_and_cursor_are_validated_when_loading_state() -> None:
    first = run()
    with pytest.raises(ValidationError, match="arrival order"):
        LiquidityState.model_validate(first.state.model_dump(mode="python") | {"last_arrival_at_ms": 1_199})
    with pytest.raises(ValidationError, match="unique"):
        LiquidityState.model_validate(
            first.state.model_dump(mode="python") | {"receipts": first.state.receipts * 2}
        )


def test_session_capacity_never_evicts_deduplication_evidence() -> None:
    first = run()
    receipts = []
    for index in range(MAX_COMMANDS):
        request = command(command_id=f"command-{index}", price_cap=D("100"))
        fields = first.outcome.model_dump(mode="python") | dict(
            command_id=request.command_id,
            command_sha256=request.fingerprint(),
            status="NO_FILL",
            filled_quantity=D("0"),
            cancelled_quantity=D("1"),
            notional_quote=D("0"),
            fee_quote=D("0"),
            average_price=None,
            implementation_shortfall_quote=D("0"),
            level_fills=(),
        )
        outcome = FillOutcome.model_validate(fields)
        receipts.append(
            CommandReceipt(
                command_id=request.command_id,
                command_sha256=request.fingerprint(),
                assumptions_sha256=policy().fingerprint(),
                outcome=outcome,
            )
        )
    full_state = state(
        assumptions_sha256=policy().fingerprint(),
        last_as_of_ms=1_200,
        last_arrival_at_ms=1_200,
        receipts=tuple(receipts),
    )
    with pytest.raises(ValueError, match="capacity exhausted"):
        run(command(command_id="beyond-cap"), prior=full_state)
    assert run(command(command_id="command-0", price_cap=D("100")), prior=full_state).replayed


@pytest.mark.parametrize(
    "updates",
    [
        {"execution_environment": "PAPER"},
        {"execution_environment": "DEV"},
        {"symbol": "BTC:DEV"},
        {"symbol": "DOGEUSDT"},
        {"order_type": "MARKET"},
        {"private_key": "forbidden-field"},
    ],
)
def test_model_namespace_never_accepts_dev_or_live_command_payload(updates: dict) -> None:
    with pytest.raises(ValidationError):
        command(**updates)


def test_minimum_decimal_scale_and_fractional_mid_remain_representable() -> None:
    tiny = D("0.000000000000000001")
    book = frame(
        bids=(BookLevel(price=tiny, quantity=tiny),),
        asks=(BookLevel(price=D("0.000000000000000002"), quantity=tiny),),
    )
    parameters = policy(
        price_tick=tiny, quantity_step=tiny, depth_participation_fraction=D("1"), taker_fee_bps=tiny
    )
    outcome = run(command(quantity=tiny, price_cap=tiny * 3), book, parameters).outcome
    assert outcome.status == "FILLED"
    assert outcome.arrival_mid_price == D("1.5e-18")
    assert outcome.notional_quote == D("2e-36")
    assert outcome.fee_quote == D("2e-58")


def test_decimal_ceiling_inputs_do_not_overflow_calculated_amounts() -> None:
    maximum = D("1000000000000000000")
    book = frame(
        bids=(BookLevel(price=D("999999999999999999"), quantity=maximum),),
        asks=(BookLevel(price=maximum, quantity=maximum),),
    )
    result = run(
        command(quantity=maximum, price_cap=maximum),
        book,
        policy(depth_participation_fraction=D("1"), taker_fee_bps=D("10000")),
    ).outcome
    assert result.status == "FILLED" and result.notional_quote == result.fee_quote == D("1e36")


def test_bounded_grid_quantity_and_cashflow_properties() -> None:
    for side, quantity, fraction, slippage in product(
        ("BUY", "SELL"),
        ("0.1", "0.7", "1.5", "3", "10"),
        ("0.1", "0.5", "1"),
        ("0", "10"),
    ):
        assumptions = policy(depth_participation_fraction=D(fraction), adverse_slippage_bps=D(slippage))
        request = command(side=side, quantity=D(quantity), price_cap=D("120" if side == "BUY" else "80"))
        result = run(request, assumptions=assumptions).outcome
        assert 0 <= result.filled_quantity <= request.quantity
        assert result.filled_quantity + result.cancelled_quantity == request.quantity
        assert result.filled_quantity <= D("5") * assumptions.depth_participation_fraction
        assert sum((fill.fee_quote for fill in result.level_fills), D("0")) == result.fee_quote
        assert all(fill.quantity % assumptions.quantity_step == 0 for fill in result.level_fills)
        assert all(fill.execution_price % assumptions.price_tick == 0 for fill in result.level_fills)
        assert result.implementation_shortfall_quote >= 0
        assert run(request, assumptions=assumptions).outcome.canonical_bytes() == result.canonical_bytes()
