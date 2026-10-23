"""Unit-only strict Core-to-managed-signing lifecycle binding tests."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from kairos_core.contracts import RiskTradeDecisionV1, VenueQualityV1
from kairos_core.enums import EvedexProfile, TradingMode

from kairos_execution.managed_signer import CustodyBindingV1
from kairos_execution.production_lifecycle_binding import (
    ProductionLifecycleBindingV1,
    build_production_lifecycle_binding,
    compare_entry_risk_to_decision,
)
from kairos_execution.production_readiness import ProductionContextV1, canonical_digest
from kairos_execution.state_machine import client_order_id
from tests.paper_fixtures import approved_decision
from tests.test_signing_authorization import fixture as signing_fixture


def _decision() -> RiskTradeDecisionV1:
    source = approved_decision()
    values = source.model_dump(mode="python")
    venue_quality = source.venue_quality.model_dump(mode="python")
    venue_quality.update(profile=EvedexProfile.PROD, symbol="BTCUSD", measurement_id=None)
    values.update(
        decision_id=None,
        trade_id=None,
        trading_mode=TradingMode.LIVE,
        evedex_profile=EvedexProfile.PROD,
        venue_symbol="BTCUSD",
        venue_quality=venue_quality,
    )
    return RiskTradeDecisionV1.model_validate(values)


def _scope(decision: RiskTradeDecisionV1):
    context = ProductionContextV1(
        remote_account_id=decision.account_id,
        adaptive_system_id=decision.intent.strategy_id,
        frozen_policy_sha256="1" * 64,
        source_set_sha256="2" * 64,
    )
    custody = CustodyBindingV1(
        context=context,
        custody_reference="fixture:custody",
        wallet_address="0x" + "12" * 20,
        chain_id=161803,
        schema_sha256="3" * 64,
        approved_instruments=("BTCUSD", "ETHUSD", "SOLUSD", "BNBUSD", "XRPUSD"),
        custody_receipt_sha256="4" * 64,
    )
    return context, custody


def _build(
    decision,
    context,
    custody,
    role="ENTRY",
    *,
    expiry_delta=timedelta(seconds=2),
    close_quantity=None,
    risk_decision_id=None,
):
    now = datetime.fromtimestamp(decision.decided_at_ms / 1000, tz=UTC)
    expires_at = now + expiry_delta
    effect_id = hashlib.sha256(f"fixture:{decision.trade_id}:{role}".encode()).hexdigest()
    order_role = role
    client_id = client_order_id(f"{decision.trade_id}:{order_role}", "evedex", occurred_at=expires_at)
    parent_order_id = (
        client_order_id(f"{decision.trade_id}:ENTRY", "evedex", occurred_at=expires_at)
        if role in {"STOP_LOSS", "TAKE_PROFIT"}
        else None
    )
    result = build_production_lifecycle_binding(
        decision=decision,
        context=context,
        custody_binding=custody,
        role=role,
        lifecycle_effect_id=effect_id,
        client_order_id=client_id,
        parent_order_id=parent_order_id,
        manual_request_sha256="5" * 64,
        expires_at=expires_at,
        now=now,
        close_quantity=close_quantity,
        risk_decision_id=risk_decision_id,
    )
    return result, now, expires_at


def test_builds_deterministic_entry_protection_and_close_bindings():
    decision = _decision()
    context, custody = _scope(decision)
    for role, operation in (
        ("ENTRY", "New limit order"),
        ("STOP_LOSS", "New take-profit/stop-loss"),
        ("TAKE_PROFIT", "New take-profit/stop-loss"),
        ("TIMEOUT_EXIT", "Position close order"),
    ):
        first, _, deadline = _build(decision, context, custody, role)
        second, _, _ = _build(decision, context, custody, role)
        assert first == second
        assert first.request.operation == operation
        assert first.request.expires_at == deadline
        assert first.decision_id == decision.decision_id
        assert first.trade_id == decision.trade_id
        assert first.decision_sha256 == canonical_digest(decision)
        assert first.signing_effect_id != first.lifecycle_effect_id
        message = json.loads(first.request.message_json)
        if role == "ENTRY":
            assert message["side"] == "BUY"
            assert message["leverage"] == 1
            assert message["quantity"] == 10_000_000
            assert message["limitPrice"] == 10_051_000_000
            assert message["chainId"] == custody.chain_id
        elif role in {"STOP_LOSS", "TAKE_PROFIT"}:
            assert message["quantity"] == 0
            assert message["side"] == "BUY"
            assert message["order"] == client_order_id(
                f"{decision.trade_id}:ENTRY", "evedex", occurred_at=deadline
            )
            assert message["type"] == ("stop-loss" if role == "STOP_LOSS" else "take-profit")


def test_request_id_binds_context_trade_effect_decision_and_role():
    decision = _decision()
    context, custody = _scope(decision)
    entry, _, _ = _build(decision, context, custody, "ENTRY")
    other_role, _, _ = _build(decision, context, custody, "TIMEOUT_EXIT")
    assert entry.request.request_id != other_role.request.request_id
    changed_context = context.model_copy(update={"source_set_sha256": "6" * 64})
    changed_custody = custody.model_copy(update={"context": changed_context})
    changed, _, _ = _build(decision, changed_context, changed_custody, "ENTRY")
    assert entry.request.request_id != changed.request.request_id


def test_rejects_rounding_of_core_decision_quantity():
    decision = _decision()
    quantity = 0.100000001
    updates = {
        "quantity": quantity,
        "notional_usd": quantity * decision.worst_entry_price,
        "estimated_fees_usd": quantity
        * (decision.worst_entry_price + decision.exit_plan.stop_price)
        * decision.venue_quality.taker_fee_bps
        / 10_000,
        "estimated_slippage_usd": quantity
        * decision.venue_quality.venue_mid_price
        * decision.venue_quality.buy_slippage_bps
        / 10_000,
    }
    updates["worst_case_loss_usd"] = (
        quantity * abs(decision.worst_entry_price - decision.exit_plan.stop_price)
        + updates["estimated_fees_usd"]
        + updates["estimated_slippage_usd"]
    )
    updates["loss_budget_usd"] = max(decision.loss_budget_usd, updates["worst_case_loss_usd"])
    changed = RiskTradeDecisionV1.model_validate(
        {**decision.model_dump(mode="python"), **updates, "decision_id": None, "trade_id": None}
    )
    context, custody = _scope(changed)
    with pytest.raises(ValueError, match="not exactly representable"):
        _build(changed, context, custody, "ENTRY")


def test_rejects_rounding_of_core_decision_price():
    decision = _decision()
    new_ask = 100.500000001
    venue_values = decision.venue_quality.model_dump(mode="python")
    new_mid = (decision.venue_quality.best_bid + new_ask) / 2
    venue_values.update(
        best_ask=new_ask,
        venue_mid_price=new_mid,
        basis_bps=(new_mid - decision.venue_quality.reference_mid_price)
        / decision.venue_quality.reference_mid_price
        * 10_000,
        spread_bps=(new_ask - decision.venue_quality.best_bid) / new_mid * 10_000,
        measurement_id=None,
    )
    venue_quality = VenueQualityV1.model_validate(venue_values)
    quantity = decision.quantity
    fees = quantity * (new_ask + decision.exit_plan.stop_price) * venue_quality.taker_fee_bps / 10_000
    slippage = quantity * new_mid * venue_quality.buy_slippage_bps / 10_000
    loss = quantity * abs(new_ask - decision.exit_plan.stop_price) + fees + slippage
    changed = RiskTradeDecisionV1.model_validate(
        {
            **decision.model_dump(mode="python"),
            "venue_quality": venue_quality,
            "decision_id": None,
            "trade_id": None,
            "worst_entry_price": new_ask,
            "notional_usd": quantity * new_ask,
            "estimated_fees_usd": fees,
            "estimated_slippage_usd": slippage,
            "worst_case_loss_usd": loss,
            "loss_budget_usd": max(decision.loss_budget_usd, loss),
        }
    )
    context, custody = _scope(changed)
    with pytest.raises(ValueError, match="not exactly representable"):
        _build(changed, context, custody, "ENTRY")


@pytest.mark.parametrize("seconds", [0, 31])
def test_refuses_expired_or_retimed_deadlines(seconds):
    decision = _decision()
    context, custody = _scope(decision)
    with pytest.raises(ValueError, match="next 30 seconds"):
        _build(decision, context, custody, expiry_delta=timedelta(seconds=seconds))


def test_refuses_context_or_identity_substitution():
    decision = _decision()
    context, custody = _scope(decision)
    wrong_context = context.model_copy(update={"remote_account_id": "other-account"})
    wrong_custody = custody.model_copy(update={"context": wrong_context})
    with pytest.raises(ValueError, match="scope differ"):
        _build(decision, wrong_context, wrong_custody)
    wrong_decision = RiskTradeDecisionV1.model_validate(
        {
            **decision.model_dump(mode="python"),
            "account_id": "other-account",
            "decision_id": None,
            "trade_id": None,
        }
    )
    with pytest.raises(ValueError, match="scope differ"):
        _build(wrong_decision, context, custody)


def test_entry_risk_comparison_checks_actual_production_evidence_without_authorizing_it():
    decision = _decision()
    context, custody = _scope(decision)
    lifecycle, _, _ = _build(decision, context, custody)
    _, _, _, evidence, _ = signing_fixture()
    message = json.loads(lifecycle.request.message_json)
    risk = evidence.risk.model_copy(
        update={
            "context": context,
            "decision_id": decision.decision_id,
            "signing_request_id": lifecycle.request.request_id,
            "effect_id": lifecycle.signing_effect_id,
            "client_order_id": message["id"],
            "operation": "New limit order",
            "instrument": decision.venue_symbol,
            "side": message["side"],
            "quantity": message["quantity"],
            "price": message["limitPrice"],
            "stop_price": None,
            "protection_type": None,
            "trigger_price": None,
            "parent_order_id": None,
            "leverage": 1,
            "worst_case_loss_usd": Decimal(str(decision.worst_case_loss_usd)),
            "approved": True,
        }
    )
    matching = evidence.model_copy(update={"risk": risk})
    compare_entry_risk_to_decision(decision=decision, lifecycle=lifecycle, evidence=matching)
    altered = matching.model_copy(update={"risk": risk.model_copy(update={"quantity": risk.quantity + 1})})
    with pytest.raises(ValueError, match="differs from the immutable Core entry decision"):
        compare_entry_risk_to_decision(decision=decision, lifecycle=lifecycle, evidence=altered)


def test_binding_record_round_trips_as_strict_persistable_json():
    decision = _decision()
    context, custody = _scope(decision)
    lifecycle, _, _ = _build(decision, context, custody)
    saved = ProductionLifecycleBindingV1.model_validate_json(lifecycle.model_dump_json())
    assert saved == lifecycle
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        ProductionLifecycleBindingV1.model_validate(
            {**lifecycle.model_dump(), "untrusted_extra": "not allowed"}
        )
