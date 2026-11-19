"""Native sizing on explicit synthetic flat facts, never venue authority."""

from dataclasses import replace
from datetime import timedelta
from decimal import Decimal

import pytest
from kairos_core.contracts import canonical_sha256
from kairos_risk.live import LiveRiskEvaluator

from kairos_execution.one_canary_account import CanaryAccountError, CanaryAccountObservation
from kairos_execution.one_canary_risk import CanaryInstrumentRules, OperationalFlatCanaryRisk
from tests.test_production_risk import NOW, _inputs


@pytest.fixture
def sizing():
    review, venue, allocation, _, _, _, publisher, _, scope = _inputs()
    now = NOW
    intent_data = review.intent.model_dump(mode="python")
    intent_data["intent_id"] = None
    intent_data["exit_plan"] = {**intent_data["exit_plan"], "stop_price": 99.0, "target_price": 103.0}
    intent_data["gross_reward_bps"] = (
        abs(103.0 - intent_data["reference_price"]) / intent_data["reference_price"] * 10000
    )
    intent = type(review.intent).model_validate(intent_data)
    observation = CanaryAccountObservation(
        scope.account_id,
        now - timedelta(days=1),
        now - timedelta(seconds=1),
        now,
        Decimal("109.42"),
        Decimal("109.42"),
        Decimal(0),
        0,
        0,
        0,
        0,
        (),
        (),
    )
    instrument = CanaryInstrumentRules.from_native(
        {
            "name": venue.symbol,
            "trading": "all",
            "visibility": "all",
            "marketState": "OPEN",
            "lotSize": "1",
            "multiplier": "1",
            "priceIncrement": "0.0001",
            "quantityIncrement": "0.00000001",
            "minQuantity": "0.00000001",
            "maxQuantity": "1000",
            "minPrice": "0.0001",
            "maxPrice": "1000000000",
            "minVolume": "5",
        },
        observed_at=now,
        body_sha256="c" * 64,
    )
    return OperationalFlatCanaryRisk(publisher.evaluator), {
        "intent": intent,
        "venue": venue,
        "allocation": allocation,
        "observation": observation,
        "instrument": instrument,
        "baseline_equity_usdt": observation.equity_lower_bound_usdt,
        "net_deposits_usdt": Decimal(0),
        "entry_slippage_bps": Decimal("2"),
        "stop_exit_slippage_bps": Decimal("2"),
        "extra_cost_bound_usdt": Decimal("0.01"),
        "now": now,
    }


def test_eligible_respects_dollars_cash_and_two_sided_cost(sizing):
    risk, inputs = sizing
    result = risk.evaluate(**inputs)
    assert result.status == "ELIGIBLE", result.reason
    assert 0 < result.estimated_loss_usdt <= result.loss_budget_usdt <= Decimal("0.25")
    assert result.cash_required_usdt <= 100
    assert result.quantity % inputs["instrument"].quantity_step == 0
    assert len(result.input_binding_sha256) == 64
    assert not hasattr(result, "reconciled")
    assert result.entry_limit_price % inputs["instrument"].tick == 0
    assert result.entry_limit_price == Decimal(str(inputs["venue"].best_ask))


def test_cost_cap_only_reduces_native_sizing(sizing):
    risk, inputs = sizing
    first = risk.evaluate(**inputs)
    second = risk.evaluate(
        **{**inputs, "entry_slippage_bps": Decimal("30"), "stop_exit_slippage_bps": Decimal("30")}
    )
    assert first.status == "ELIGIBLE"
    assert second.status == "WAIT" or second.quantity <= first.quantity
    assert first.input_binding_sha256 != second.input_binding_sha256


def test_unknown_cost_is_wait(sizing):
    risk, inputs = sizing
    assert risk.evaluate(**{**inputs, "extra_cost_bound_usdt": None}).reason == "cost_bound_missing"


def test_unknown_venue_fee_and_nonzero_adverse_pnl_are_wait(sizing):
    risk, inputs = sizing
    venue = inputs["venue"].model_copy(update={"taker_fee_bps": None})
    assert risk.evaluate(**{**inputs, "venue": venue}).status == "WAIT"
    account = replace(inputs["observation"], adverse_unrealized_usdt=Decimal("-0.01"))
    assert risk.evaluate(**{**inputs, "observation": account}).status == "WAIT"


@pytest.mark.parametrize(
    "change,cap",
    [
        ({"per_trade_risk_fraction": 0.001}, Decimal("0.1")),
        ({"aggregate_open_risk_fraction": 0.0005}, Decimal("0.05")),
        ({"per_trade_dollar_cap_usd": 0.1}, Decimal("0.1")),
        ({"daily_loss_cap_usd": 0.1}, Decimal("0.1")),
    ],
)
def test_stricter_native_limits_cannot_be_relaxed(sizing, change, cap):
    original, inputs = sizing
    limits = type(original._native.limits).model_validate(
        original._native.limits.model_copy(update=change).model_dump(mode="python")
    )
    scope = original._native.scope.model_copy(
        update={"risk_limits_sha256": canonical_sha256(limits.model_dump(mode="json"))}
    )
    result = OperationalFlatCanaryRisk(LiveRiskEvaluator(scope, limits)).evaluate(**inputs)
    assert result.status == "WAIT" or result.estimated_loss_usdt <= result.loss_budget_usdt <= cap


def test_minimum_lot_cannot_expand_risk(sizing):
    risk, inputs = sizing
    instrument = replace(inputs["instrument"], min_quantity=Decimal("100"))
    assert risk.evaluate(**{**inputs, "instrument": instrument}).reason == "minimum_lot_exceeds_risk_budget"


def test_changed_account_and_stale_quote_are_wait(sizing):
    risk, inputs = sizing
    foreign = replace(inputs["observation"], account_id="another")
    assert risk.evaluate(**{**inputs, "observation": foreign}).status == "WAIT"
    assert risk.evaluate(**{**inputs, "now": inputs["now"] + timedelta(seconds=10)}).status == "WAIT"


def test_fixed_actual_baseline_and_deposit_cannot_mask_five_dollars(sizing):
    risk, inputs = sizing
    # An actual $109.42 baseline and $5 loss must stop even though sizing uses
    # only $100 of capital. A new $25 deposit does not clear the loss.
    current = replace(inputs["observation"], funding_usdt=Decimal("129.42"), available_usdt=Decimal("129.42"))
    result = risk.evaluate(**{**inputs, "observation": current, "net_deposits_usdt": Decimal("25")})
    assert result.reason == "session_or_trade_budget_exhausted"


def test_rule_parser_rejects_unsupported_instrument_economics(sizing):
    instrument = sizing[1]["instrument"]
    with pytest.raises(CanaryAccountError):
        CanaryInstrumentRules.from_native(
            {"lotSize": "1000"}, observed_at=instrument.observed_at, body_sha256=instrument.evidence_sha256
        )
