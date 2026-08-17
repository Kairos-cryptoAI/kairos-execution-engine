import asyncio

import pytest
from kairos_core.contracts import ExecutionReport, OrderIntent, ValidatedOrder
from kairos_core.enums import OrderSide, OrderStatus, OrderType, ReasonCode, SystemMode

from kairos_execution.adapters.base import ExchangeAdapter, ProtectiveStopAck
from kairos_execution.engine import ExecutionEngine, ExecutionSafetyError


class FakeAdapter(ExchangeAdapter):
    name = "fake"

    def __init__(
        self,
        fill_price=0.0,
        fail_stop=False,
        rejected=False,
        *,
        entry_status=OrderStatus.NEW,
        entry_exchange_id="entry-1",
        entry_filled_qty=None,
        entry_remaining_qty=None,
        order_active_after_cancel=False,
        position_flat=(False, True),
        close_status=OrderStatus.FILLED,
        close_remaining_qty=0.0,
        entry_report_updates=None,
        close_report_updates=None,
        place_error=None,
        close_error=None,
    ):
        self.placed = []
        self.trailing = []
        self.closed = []
        self.canceled = []
        self.events = []
        self.fill_price = fill_price
        self.fail_stop = fail_stop
        self.rejected = rejected
        self.entry_status = OrderStatus.REJECTED if rejected else entry_status
        self.entry_exchange_id = entry_exchange_id
        self.entry_filled_qty = entry_filled_qty
        self.entry_remaining_qty = entry_remaining_qty
        self.order_active_after_cancel = order_active_after_cancel
        self.position_flat = list(position_flat)
        self.close_status = close_status
        self.close_remaining_qty = close_remaining_qty
        self.entry_report_updates = entry_report_updates or {}
        self.close_report_updates = close_report_updates or {}
        self.place_error = place_error
        self.close_error = close_error
        self._last_position_flat = False

    async def place_order(self, intent):
        self.events.append("place")
        self.placed.append(intent)
        if self.place_error is not None:
            raise self.place_error
        filled_qty = self.entry_filled_qty
        if filled_qty is None:
            filled_qty = intent.quantity if self.entry_status is OrderStatus.FILLED else 0.0
        remaining_qty = self.entry_remaining_qty
        if remaining_qty is None:
            remaining_qty = intent.quantity - filled_qty
        # model_construct intentionally emulates a malformed venue adapter for
        # the NaN regression; the engine must validate its trust boundary.
        report_values = {
            "source": "x",
            "client_order_id": intent.client_order_id,
            "exchange_order_id": self.entry_exchange_id,
            "exchange": self.name,
            "symbol": intent.symbol,
            "side": intent.side,
            "status": self.entry_status,
            "requested_qty": intent.quantity,
            "filled_qty": filled_qty,
            "remaining_qty": remaining_qty,
            "avg_price": self.fill_price,
            "message": "",
            "retryable": False,
            **self.entry_report_updates,
        }
        return ExecutionReport.model_construct(**report_values)

    async def cancel_order_by_client_id(self, symbol, order_id):
        self.events.append("cancel")
        self.canceled.append((symbol, order_id))

    async def is_order_active_by_client_id(self, symbol, order_id):
        self.events.append("reconcile_order")
        return self.order_active_after_cancel

    async def is_position_flat(self, symbol):
        self.events.append("reconcile_position")
        if not self.position_flat:
            return self._last_position_flat
        self._last_position_flat = self.position_flat.pop(0)
        return self._last_position_flat

    async def close_position(
        self,
        symbol,
        *,
        quantity=None,
        side=None,
        client_order_id=None,
    ):
        self.events.append("close")
        self.closed.append((symbol, client_order_id, quantity, side))
        if self.close_error is not None:
            raise self.close_error
        requested_qty = quantity or 0.1
        report_values = {
            "source": "x",
            "client_order_id": client_order_id,
            "exchange_order_id": "close-1",
            "exchange": self.name,
            "symbol": symbol,
            "side": side or OrderSide.SELL,
            "status": self.close_status,
            "requested_qty": requested_qty,
            "filled_qty": max(0.0, requested_qty - self.close_remaining_qty),
            "remaining_qty": self.close_remaining_qty,
            "avg_price": 0.0,
            "fees_usd": 0.0,
            **self.close_report_updates,
        }
        return ExecutionReport.model_construct(**report_values)

    async def set_leverage(self, symbol, leverage): ...

    async def set_protective_stop(self, symbol, stop_price, position_side, parent_order_id):
        self.events.append("protect")
        if self.fail_stop:
            raise RuntimeError("stop rejected")
        self.trailing.append((symbol, stop_price, position_side, parent_order_id))
        return ProtectiveStopAck(exchange_order_id="stop-1")


class EchoIdentityFakeAdapter(FakeAdapter):
    exchange_order_id_matches_client_order_id = True


def _order(
    reason=ReasonCode.ENTER_LONG_TREND,
    approved=True,
    price=65000,
    order_type=OrderType.LIMIT,
    stop_price=None,
    side=OrderSide.BUY,
):
    intent = OrderIntent(
        source="risk",
        symbol="BTCUSDT",
        side=side,
        order_type=order_type,
        quantity=0.1,
        price=price,
        stop_price=stop_price,
        reason_code=reason,
    )
    return ValidatedOrder(source="risk", intent=intent, approved=approved, reason_code=reason)


def _engine(adapter):
    return ExecutionEngine(
        adapter,
        allowed_symbols={"BTCUSDT", "ETHUSDT", "SOLUSDT", "BNBUSDT", "XRPUSDT"},
    )


def test_market_order_arms_trailing_stop_from_fill_price():
    # Market orders have no intent.price; the stop must be armed off the exchange fill.
    a = FakeAdapter(fill_price=64500.0)
    eng = _engine(a)
    asyncio.run(eng.handle(_order(price=None, order_type=OrderType.MARKET)))
    assert len(a.placed) == 1
    assert len(a.trailing) == 1  # protective stop MUST still be armed
    _sym, stop, side, parent = a.trailing[0]
    assert side is OrderSide.BUY and stop < 64500.0
    assert parent == a.placed[0].client_order_id


def test_open_places_order_and_arms_trailing_stop():
    a = FakeAdapter()
    eng = _engine(a)
    asyncio.run(eng.handle(_order()))
    assert len(a.placed) == 1
    assert len(a.trailing) == 1  # protective stop armed
    sym, stop, side, parent = a.trailing[0]
    assert side is OrderSide.BUY and stop < 65000
    assert parent == a.placed[0].client_order_id


def test_unresolved_execution_journal_blocks_new_entries_but_preserves_close_path():
    adapter = FakeAdapter(position_flat=(True,))
    engine = _engine(adapter)
    engine.set_recovery_blockers(["effect-1: unresolved"])

    with pytest.raises(ExecutionSafetyError, match="journal recovery is incomplete"):
        asyncio.run(engine.handle(_order()))
    assert adapter.placed == []
    assert engine.recovery_blocked is True

    close_report = asyncio.run(engine.handle(_order(reason=ReasonCode.CLOSE_POSITION)))
    assert close_report is not None
    assert "position already flat" in close_report.message

    engine.set_recovery_blockers([])
    assert engine.recovery_blocked is False


def test_explicit_protective_stop_takes_priority_over_default_distance():
    adapter = FakeAdapter(fill_price=65_000.0)

    asyncio.run(_engine(adapter).handle(_order(stop_price=63_700.0)))

    assert adapter.trailing[0][:3] == ("BTCUSDT", 63_700.0, OrderSide.BUY)
    assert adapter.trailing[0][3] == adapter.placed[0].client_order_id
    assert adapter.closed == []


def test_stop_on_wrong_side_requests_emergency_close():
    adapter = FakeAdapter(fill_price=65_000.0, entry_status=OrderStatus.FILLED)

    report = asyncio.run(_engine(adapter).handle(_order(stop_price=66_000.0)))

    assert adapter.trailing == []
    assert adapter.closed[0][0] == "BTCUSDT"
    assert report.status is OrderStatus.CANCELED
    assert "invalid protective stop" in report.message


def test_short_stop_with_unbounded_distance_requests_emergency_close():
    adapter = FakeAdapter(fill_price=65_000.0, entry_status=OrderStatus.FILLED)

    report = asyncio.run(
        _engine(adapter).handle(
            _order(
                reason=ReasonCode.ENTER_SHORT_TREND,
                side=OrderSide.SELL,
                stop_price=140_000.0,
            )
        )
    )

    assert adapter.trailing == []
    assert adapter.closed[0][0] == "BTCUSDT"
    assert "invalid protective stop" in report.message


def test_duplicate_delivery_is_suppressed_after_successful_protection():
    adapter = FakeAdapter()
    engine = _engine(adapter)
    order = _order()
    asyncio.run(engine.handle(order))
    first_id = adapter.placed[0].client_order_id
    asyncio.run(engine.handle(order))
    assert len(adapter.placed) == 1
    assert len(adapter.trailing) == 1
    assert first_id.startswith("krs-")


def test_malformed_client_identity_is_compensated_using_submitted_identity():
    adapter = FakeAdapter(
        fill_price=65_000.0,
        entry_status=OrderStatus.FILLED,
        position_flat=(True,),
        entry_report_updates={"client_order_id": "untrusted-response-id"},
    )

    report = asyncio.run(_engine(adapter).handle(_order()))

    submitted_id = adapter.placed[0].client_order_id
    assert adapter.canceled == [("BTCUSDT", submitted_id)]
    assert report.client_order_id == submitted_id
    assert report.exchange_order_id is None


def test_echo_identity_adapter_rejects_mismatched_exchange_order_id():
    adapter = EchoIdentityFakeAdapter(
        fill_price=65_000.0,
        entry_status=OrderStatus.FILLED,
        position_flat=(True,),
        entry_report_updates={"exchange_order_id": "untrusted-response-id"},
    )

    report = asyncio.run(_engine(adapter).handle(_order()))

    submitted_id = adapter.placed[0].client_order_id
    assert adapter.canceled == [("BTCUSDT", submitted_id)]
    assert report.status is OrderStatus.CANCELED


@pytest.mark.parametrize(
    "entry_status,filled_qty,remaining_qty",
    [
        (OrderStatus.FILLED, 0.0, 0.0),
        (OrderStatus.PARTIALLY_FILLED, 0.0, 0.1),
        (OrderStatus.PARTIALLY_FILLED, 0.1, 0.0),
        (OrderStatus.NEW, 0.0, 0.09),
    ],
)
def test_status_accounting_mismatch_is_compensated(
    entry_status,
    filled_qty,
    remaining_qty,
):
    adapter = FakeAdapter(
        fill_price=65_000.0,
        entry_status=entry_status,
        entry_filled_qty=filled_qty,
        entry_remaining_qty=remaining_qty,
        position_flat=(True,),
    )

    report = asyncio.run(_engine(adapter).handle(_order()))

    assert report.status is OrderStatus.CANCELED
    assert adapter.canceled == [("BTCUSDT", adapter.placed[0].client_order_id)]


def test_reused_message_id_with_different_payload_fails_closed():
    adapter = FakeAdapter()
    engine = _engine(adapter)
    first = _order()
    conflicting = _order(price=64_000).model_copy(update={"message_id": first.message_id})

    asyncio.run(engine.handle(first))

    with pytest.raises(ExecutionSafetyError, match="reused with a different payload"):
        asyncio.run(engine.handle(conflicting))

    assert len(adapter.placed) == 1


def test_close_passes_exact_risk_validated_quantity_and_side():
    adapter = FakeAdapter(position_flat=(False, True))
    order = _order(reason=ReasonCode.CLOSE_POSITION)

    asyncio.run(_engine(adapter).handle(order))

    assert adapter.closed[0][0] == "BTCUSDT"
    assert adapter.closed[0][2] == 0.1
    assert adapter.closed[0][3] is OrderSide.BUY


def test_close_preflight_flat_is_idempotent_without_submitting_a_fill():
    adapter = FakeAdapter(position_flat=(True,))
    engine = _engine(adapter)
    order = _order(reason=ReasonCode.CLOSE_POSITION)

    first = asyncio.run(engine.handle(order))
    second = asyncio.run(engine.handle(order))

    assert first.status is OrderStatus.CANCELED
    assert first.filled_qty == 0
    assert second == first
    assert adapter.closed == []


def test_ambiguous_close_that_reconciles_flat_converges_without_claiming_fill():
    adapter = FakeAdapter(
        position_flat=(False, True),
        close_error=RuntimeError("timeout after submit"),
    )
    engine = _engine(adapter)
    order = _order(reason=ReasonCode.CLOSE_POSITION)

    first = asyncio.run(engine.handle(order))
    second = asyncio.run(engine.handle(order))

    assert first.status is OrderStatus.CANCELED
    assert first.filled_qty == 0
    assert "ambiguous close reconciled flat" in first.message
    assert second == first
    assert len(adapter.closed) == 1


def test_ambiguous_close_nonflat_remains_pending():
    adapter = FakeAdapter(
        position_flat=(False, False),
        close_error=RuntimeError("timeout after submit"),
    )

    with pytest.raises(ExecutionSafetyError, match="position is not flat"):
        asyncio.run(_engine(adapter).handle(_order(reason=ReasonCode.CLOSE_POSITION)))


def test_active_deterministic_close_is_not_submitted_again():
    adapter = FakeAdapter(position_flat=(False,), order_active_after_cancel=True)

    with pytest.raises(ExecutionSafetyError, match="still active"):
        asyncio.run(_engine(adapter).handle(_order(reason=ReasonCode.CLOSE_POSITION)))

    assert adapter.closed == []


def test_malformed_close_ack_stays_pending_then_flat_redelivery_converges():
    adapter = FakeAdapter(
        position_flat=(False, True),
        close_report_updates={"client_order_id": "untrusted-response-id"},
    )
    engine = _engine(adapter)
    order = _order(reason=ReasonCode.CLOSE_POSITION)

    with pytest.raises(ExecutionSafetyError, match="malformed close acknowledgement"):
        asyncio.run(engine.handle(order))

    report = asyncio.run(engine.handle(order))
    assert report.status is OrderStatus.CANCELED
    assert report.filled_qty == 0
    assert len(adapter.closed) == 1


def test_rejected_close_converges_to_desired_state_when_position_is_flat():
    adapter = FakeAdapter(position_flat=(False, True), close_status=OrderStatus.REJECTED)

    report = asyncio.run(_engine(adapter).handle(_order(reason=ReasonCode.CLOSE_POSITION)))

    assert report.status is OrderStatus.CANCELED
    assert report.filled_qty == 0
    assert "no unverified fill is claimed" in report.message


def test_filled_close_is_not_acknowledged_until_position_is_flat():
    adapter = FakeAdapter(position_flat=(False,), close_status=OrderStatus.FILLED)

    with pytest.raises(ExecutionSafetyError, match="did not flatten position"):
        asyncio.run(_engine(adapter).handle(_order(reason=ReasonCode.CLOSE_POSITION)))


def test_stop_failure_requests_emergency_close():
    adapter = FakeAdapter(fail_stop=True, entry_status=OrderStatus.FILLED)
    report = asyncio.run(_engine(adapter).handle(_order()))
    assert adapter.closed[0][0] == "BTCUSDT"
    assert adapter.closed[0][1].startswith("krs-")
    assert report.status is OrderStatus.CANCELED


def test_ambiguous_place_order_is_neutralized_and_left_pending():
    adapter = FakeAdapter(
        place_error=RuntimeError("timeout after submit"),
        position_flat=(True,),
    )

    with pytest.raises(ExecutionSafetyError, match="reconciled inactive and flat"):
        asyncio.run(_engine(adapter).handle(_order()))

    submitted_id = adapter.placed[0].client_order_id
    assert adapter.canceled == [("BTCUSDT", submitted_id)]
    assert adapter.closed == []


def test_missing_entry_price_requests_emergency_close():
    adapter = FakeAdapter(fill_price=0, position_flat=(True,))
    report = asyncio.run(_engine(adapter).handle(_order(price=None, order_type=OrderType.MARKET)))
    assert adapter.canceled == [("BTCUSDT", adapter.placed[0].client_order_id)]
    assert adapter.closed == []
    assert report.status is OrderStatus.CANCELED
    assert "reconciled flat" in report.message


@pytest.mark.parametrize("fill_price", [float("nan"), float("inf")])
def test_non_finite_fill_is_compensated(fill_price):
    adapter = FakeAdapter(fill_price=fill_price, entry_status=OrderStatus.FILLED)

    report = asyncio.run(_engine(adapter).handle(_order()))

    assert report.status is OrderStatus.CANCELED
    assert adapter.trailing == []
    assert adapter.closed[0][0] == "BTCUSDT"


@pytest.mark.parametrize("filled_qty", [float("nan"), float("inf")])
def test_non_finite_filled_quantity_is_compensated(filled_qty):
    adapter = FakeAdapter(
        fill_price=65_000.0,
        entry_status=OrderStatus.FILLED,
        entry_filled_qty=filled_qty,
        entry_remaining_qty=0.0,
    )

    report = asyncio.run(_engine(adapter).handle(_order()))

    assert report.status is OrderStatus.CANCELED
    assert adapter.trailing == []
    assert adapter.closed[0][0] == "BTCUSDT"


@pytest.mark.parametrize(
    "report_updates",
    [
        {"symbol": "ETHUSDT"},
        {"side": OrderSide.SELL},
        {"exchange": "wrong-venue"},
        {"requested_qty": 0.2},
        {"filled_qty": 0.11},
        {"remaining_qty": 0.11},
        {"filled_qty": 0.06, "remaining_qty": 0.06},
        {"filled_qty": "not-numeric"},
        {"status": "NEW"},
        {"fees_usd": float("inf")},
        {"fees_usd": -0.01},
    ],
)
def test_malformed_entry_identity_or_accounting_is_compensated(report_updates):
    adapter = FakeAdapter(
        fill_price=65_000.0,
        entry_status=OrderStatus.FILLED,
        entry_report_updates=report_updates,
    )

    report = asyncio.run(_engine(adapter).handle(_order()))

    assert report.status is OrderStatus.CANCELED
    assert report.symbol == "BTCUSDT"
    assert report.side is OrderSide.BUY
    assert report.fees_usd >= 0
    assert adapter.trailing == []
    assert adapter.closed[0][0] == "BTCUSDT"


def test_active_entry_without_exchange_order_id_is_neutralized_by_trusted_client_id():
    adapter = FakeAdapter(entry_exchange_id=None, position_flat=(True,))

    report = asyncio.run(_engine(adapter).handle(_order()))

    assert report.status is OrderStatus.CANCELED
    assert adapter.canceled == [("BTCUSDT", adapter.placed[0].client_order_id)]
    assert adapter.trailing == []


def test_overflowing_computed_stop_is_never_submitted():
    adapter = FakeAdapter(fill_price=1e308, entry_status=OrderStatus.FILLED)
    engine = ExecutionEngine(adapter, default_trail_pct=0.99, allowed_symbols={"BTCUSDT"})

    report = asyncio.run(
        engine.handle(
            _order(
                reason=ReasonCode.ENTER_SHORT_TREND,
                price=1e308,
                side=OrderSide.SELL,
            )
        )
    )

    assert report.status is OrderStatus.CANCELED
    assert adapter.trailing == []


def test_active_entry_is_canceled_and_reconciled_before_close_decision():
    adapter = FakeAdapter(fill_price=65_000.0, position_flat=(True,))

    report = asyncio.run(_engine(adapter).handle(_order(stop_price=66_000.0)))

    assert report.status is OrderStatus.CANCELED
    assert adapter.events == ["place", "cancel", "reconcile_order", "reconcile_position"]
    assert adapter.closed == []


def test_partial_entry_is_canceled_before_live_position_is_closed():
    adapter = FakeAdapter(
        fill_price=65_000.0,
        entry_status=OrderStatus.PARTIALLY_FILLED,
        entry_filled_qty=0.04,
        entry_remaining_qty=0.06,
        position_flat=(False, True),
    )

    report = asyncio.run(_engine(adapter).handle(_order(stop_price=66_000.0)))

    assert report.status is OrderStatus.CANCELED
    assert adapter.events == [
        "place",
        "cancel",
        "reconcile_order",
        "reconcile_position",
        "reconcile_order",
        "close",
        "reconcile_position",
        "reconcile_order",
    ]


@pytest.mark.parametrize("close_status", [OrderStatus.REJECTED, OrderStatus.PARTIALLY_FILLED])
def test_unverified_emergency_close_is_a_safety_failure(close_status):
    adapter = FakeAdapter(
        fill_price=65_000.0,
        entry_status=OrderStatus.PARTIALLY_FILLED,
        entry_filled_qty=0.04,
        entry_remaining_qty=0.06,
        position_flat=(False, False),
        close_status=close_status,
        close_remaining_qty=0.02,
    )

    with pytest.raises(ExecutionSafetyError, match="(?:did not flatten position|status=REJECTED)"):
        asyncio.run(_engine(adapter).handle(_order(stop_price=66_000.0)))


def test_active_entry_that_survives_cancel_is_a_safety_failure():
    adapter = FakeAdapter(
        fill_price=65_000.0,
        order_active_after_cancel=True,
        position_flat=(True,),
    )

    with pytest.raises(ExecutionSafetyError, match="remains active"):
        asyncio.run(_engine(adapter).handle(_order(stop_price=66_000.0)))

    assert adapter.closed == []


def test_unapproved_order_is_ignored():
    a = FakeAdapter()
    eng = _engine(a)
    asyncio.run(eng.handle(_order(approved=False)))
    assert not a.placed


def test_exchange_rejection_does_not_request_emergency_close():
    adapter = FakeAdapter(rejected=True)

    report = asyncio.run(_engine(adapter).handle(_order()))

    assert report.status is OrderStatus.REJECTED
    assert adapter.closed == []


def test_unknown_symbol_is_rejected_before_adapter_call():
    adapter = FakeAdapter()
    order = _order().model_copy(
        update={"intent": _order().intent.model_copy(update={"symbol": "DOGEUSDT"})},
    )
    report = asyncio.run(_engine(adapter).handle(order))
    assert report is None
    assert adapter.placed == []
    assert adapter.closed == []


def test_local_quant_mode_blocks_new_entries():
    a = FakeAdapter()
    eng = _engine(a)
    eng.set_mode(SystemMode.LOCAL_QUANT_MODE)
    asyncio.run(eng.handle(_order()))
    assert not a.placed  # opening blocked while LLM detached
