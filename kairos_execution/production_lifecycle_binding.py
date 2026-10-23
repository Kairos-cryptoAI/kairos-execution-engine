"""Strict, non-authorizing bridge from a Core LIVE decision to signing requests.

This module deterministically binds one immutable Core risk decision to EVEDEX
typed messages and persistable lifecycle/signing identities. It neither creates
policy approval nor signs, dispatches, or reserves anything.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Literal

from kairos_core.contracts import RiskTradeDecisionV1
from kairos_core.enums import EvedexProfile, Side, TradingMode

from .crypto import MATCHER_PRECISION
from .managed_signer import (
    CustodyBindingV1,
    ManagedSigningRequestV1,
    SigningOperation,
    _typed_message,
)
from .production_readiness import Digest, ProductionContextV1, StrictRecord, canonical_digest
from .signing_authorization import (
    ProductionSigningEvidenceV1,
    RiskGeometryV1,
    signing_effect_id,
)
from .state_machine import (
    EVEDEX_ORDER_ID_EPOCH,
    is_fresh_evedex_client_order_id,
)
from .state_machine import client_order_id as deterministic_client_order_id

LifecycleRole = Literal["ENTRY", "STOP_LOSS", "TAKE_PROFIT", "TIMEOUT_EXIT", "EMERGENCY_EXIT"]

_ROLE_DETAILS: dict[LifecycleRole, tuple[str, str]] = {
    "ENTRY": ("New limit order", "place"),
    "STOP_LOSS": ("New take-profit/stop-loss", "create"),
    "TAKE_PROFIT": ("New take-profit/stop-loss", "create"),
    "TIMEOUT_EXIT": ("Position close order", "close"),
    "EMERGENCY_EXIT": ("Position close order", "close"),
}


class ProductionLifecycleBindingV1(StrictRecord):
    """Persistable association between an FSM effect and one signing request."""

    version: Literal["kairos.production-lifecycle-binding.v1"] = "kairos.production-lifecycle-binding.v1"
    context: ProductionContextV1
    decision_id: Digest
    trade_id: Digest
    decision_sha256: Digest
    role: LifecycleRole
    risk_decision_id: Digest
    lifecycle_effect_id: Digest
    signing_effect_id: Digest
    request: ManagedSigningRequestV1


def _sha256_json(payload: object) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    ).hexdigest()


def _exact_evedex_integer(value: float, *, field: str) -> int:
    """Convert a Core float only when its decimal spelling is exact at 1e8."""
    decimal_value = Decimal(str(value))
    if not decimal_value.is_finite() or decimal_value <= 0:
        raise ValueError(f"{field} must be finite and positive")
    scaled = decimal_value * (Decimal(10) ** MATCHER_PRECISION)
    integral = scaled.to_integral_value()
    if scaled != integral:
        raise ValueError(f"{field} is not exactly representable at EVEDEX precision 1e8")
    return int(integral)


def _validate_client_id_for_decision(value: str, decision: RiskTradeDecisionV1, role: LifecycleRole) -> None:
    """Require the stored client ID to be the engine's deterministic ID for this trade/role."""
    if len(value) < 6 or value[5] != ":" or not value[:5].isdigit():
        raise ValueError("persisted EVEDEX client ID is malformed")
    order_date = EVEDEX_ORDER_ID_EPOCH + timedelta(days=int(value[:5]))
    expected = deterministic_client_order_id(f"{decision.trade_id}:{role}", "evedex", occurred_at=order_date)
    if value != expected:
        raise ValueError("persisted EVEDEX client ID differs from the original Core trade/role")


def _validate_inputs(
    decision: RiskTradeDecisionV1,
    context: ProductionContextV1,
    binding: CustodyBindingV1,
) -> tuple[RiskTradeDecisionV1, ProductionContextV1, CustodyBindingV1]:
    decision = RiskTradeDecisionV1.model_validate(decision.to_payload())
    context = ProductionContextV1.model_validate(context)
    binding = CustodyBindingV1.model_validate(binding)
    if not decision.approved or decision.trading_mode is not TradingMode.LIVE:
        raise ValueError("only an approved Core LIVE decision can be bridged")
    if decision.evedex_profile is not EvedexProfile.PROD:
        raise ValueError("Core LIVE decision must target EVEDEX PROD")
    if decision.decision_id is None or decision.trade_id is None:
        raise ValueError("Core decision and trade identities are required")
    if (
        decision.account_id != context.remote_account_id
        or decision.account_id != binding.context.remote_account_id
        or context != binding.context
    ):
        raise ValueError("Core decision, production context, and custody scope differ")
    if decision.intent.strategy_id != context.adaptive_system_id:
        raise ValueError("Core decision strategy differs from the production adaptive system")
    if decision.venue_symbol.endswith(":DEV") or decision.venue_symbol not in binding.approved_instruments:
        raise ValueError("Core decision instrument is not an approved EVEDEX PROD instrument")
    if decision.leverage != 1:
        raise ValueError("production lifecycle bridge permits only 1x leverage")
    return decision, context, binding


def build_production_lifecycle_binding(
    *,
    decision: RiskTradeDecisionV1,
    context: ProductionContextV1,
    custody_binding: CustodyBindingV1,
    role: LifecycleRole,
    lifecycle_effect_id: str,
    client_order_id: str,
    manual_request_sha256: str,
    expires_at: datetime,
    now: datetime,
    parent_order_id: str | None = None,
    close_quantity: float | None = None,
    risk_decision_id: str | None = None,
) -> ProductionLifecycleBindingV1:
    """Build one bounded EVEDEX signing request; this function grants no authority.

    ``expires_at`` is the original authorization deadline supplied by the caller.
    It is preserved byte-for-byte as a datetime and must be in the next 30s;
    this bridge never renews or retimes it.
    """
    decision, context, custody_binding = _validate_inputs(decision, context, custody_binding)
    if decision.decision_id is None or decision.trade_id is None:
        raise ValueError("canonical Core decision and trade identities are required")
    if role not in _ROLE_DETAILS:
        raise ValueError("unsupported lifecycle role")
    if now.tzinfo is None or now.utcoffset() != timedelta(0):
        raise ValueError("now must be an explicit UTC timestamp")
    if expires_at.tzinfo is None or expires_at.utcoffset() != timedelta(0):
        raise ValueError("expires_at must be an explicit UTC timestamp")
    if expires_at <= now or expires_at - now > timedelta(seconds=30):
        raise ValueError("original signing deadline must be in the next 30 seconds")
    if role == "ENTRY":
        original_deadline_ms = min(decision.intent.entry_expires_ts_ms, decision.venue_quality.expires_at_ms)
        if (
            now.timestamp() * 1000 < max(decision.decided_at_ms, decision.intent.entry_eligible_ts_ms)
            or expires_at.timestamp() * 1000 > original_deadline_ms
        ):
            raise ValueError("entry signing cannot retime the original Core decision/evidence window")
    if len(manual_request_sha256) != 64 or any(c not in "0123456789abcdef" for c in manual_request_sha256):
        raise ValueError("manual request digest must be lowercase SHA-256")
    selected_risk_decision_id = risk_decision_id or decision.decision_id
    if len(selected_risk_decision_id) != 64 or any(
        c not in "0123456789abcdef" for c in selected_risk_decision_id
    ):
        raise ValueError("risk decision ID must be lowercase SHA-256")
    if role == "ENTRY" and selected_risk_decision_id != decision.decision_id:
        raise ValueError("entry risk identity must be the original Core decision")

    quantity = _exact_evedex_integer(decision.quantity, field="decision quantity")
    instrument = decision.venue_symbol
    position_side = "BUY" if decision.intent.side is Side.LONG else "SELL"
    if decision.intent.side not in {Side.LONG, Side.SHORT}:
        raise ValueError("flat Core decisions cannot create lifecycle effects")
    if len(lifecycle_effect_id) != 64 or any(c not in "0123456789abcdef" for c in lifecycle_effect_id):
        raise ValueError("persisted lifecycle effect ID must be lowercase SHA-256")
    if not is_fresh_evedex_client_order_id(client_order_id, now=now):
        raise ValueError("EVEDEX lifecycle client order ID is not fresh")
    _validate_client_id_for_decision(client_order_id, decision, role)

    operation: SigningOperation
    if role == "ENTRY":
        message = {
            "id": client_order_id,
            "instrument": instrument,
            "side": position_side,
            "leverage": 1,
            "quantity": quantity,
            "limitPrice": _exact_evedex_integer(decision.worst_entry_price, field="worst entry price"),
            "chainId": custody_binding.chain_id,
        }
        operation = "New limit order"
    elif role in {"STOP_LOSS", "TAKE_PROFIT"}:
        if parent_order_id is None:
            raise ValueError("protective lifecycle effect requires its persisted parent entry ID")
        _validate_client_id_for_decision(parent_order_id, decision, "ENTRY")
        message = {
            "instrument": instrument,
            "type": "stop-loss" if role == "STOP_LOSS" else "take-profit",
            "side": position_side,
            # EVEDEX's zero quantity means protect the whole current position.
            "quantity": 0,
            "price": _exact_evedex_integer(
                decision.exit_plan.stop_price if role == "STOP_LOSS" else decision.exit_plan.target_price,
                field="protective trigger price",
            ),
            "order": parent_order_id,
        }
        operation = "New take-profit/stop-loss"
    else:
        closing_quantity = decision.quantity if close_quantity is None else close_quantity
        message = {
            "id": client_order_id,
            "instrument": instrument,
            "leverage": 1,
            "quantity": _exact_evedex_integer(closing_quantity, field="close quantity"),
            "chainId": custody_binding.chain_id,
        }
        operation = "Position close order"

    request_id = "lifecycle-" + _sha256_json(
        {
            "domain": "kairos.production-lifecycle-request.v1",
            "context_sha256": canonical_digest(context),
            "trade_id": decision.trade_id,
            "decision_id": decision.decision_id,
            "decision_sha256": canonical_digest(decision),
            "lifecycle_effect_id": lifecycle_effect_id,
            "role": role,
        }
    )
    request = ManagedSigningRequestV1(
        request_id=request_id,
        context=context,
        manual_request_sha256=manual_request_sha256,
        custody_receipt_sha256=custody_binding.custody_receipt_sha256,
        operation=operation,
        message_json=json.dumps(message, sort_keys=True, separators=(",", ":")),
        expires_at=expires_at,
    )
    _, validated_message = _typed_message(request, custody_binding)
    signing_id = signing_effect_id(
        request=request,
        message=validated_message,
        decision_id=selected_risk_decision_id,
    )
    return ProductionLifecycleBindingV1(
        context=context,
        decision_id=decision.decision_id,
        trade_id=decision.trade_id,
        decision_sha256=canonical_digest(decision),
        role=role,
        risk_decision_id=selected_risk_decision_id,
        lifecycle_effect_id=lifecycle_effect_id,
        signing_effect_id=signing_id,
        request=request,
    )


def compare_entry_risk_to_decision(
    *,
    decision: RiskTradeDecisionV1,
    lifecycle: ProductionLifecycleBindingV1,
    evidence: ProductionSigningEvidenceV1,
) -> None:
    """Raise unless actual signing evidence exactly matches Core entry geometry.

    This checks evidence only; it does not mark it approved, create risk
    authorization, or relax the existing policy's per-effect exit checks.
    """
    decision = RiskTradeDecisionV1.model_validate(decision.to_payload())
    lifecycle = ProductionLifecycleBindingV1.model_validate(lifecycle)
    evidence = ProductionSigningEvidenceV1.model_validate(evidence)
    if lifecycle.role != "ENTRY":
        raise ValueError("Core entry comparison applies only to ENTRY effects")
    if (
        lifecycle.decision_id != decision.decision_id
        or lifecycle.trade_id != decision.trade_id
        or lifecycle.decision_sha256 != canonical_digest(decision)
        or lifecycle.risk_decision_id != decision.decision_id
    ):
        raise ValueError("lifecycle binding differs from the immutable Core decision")
    risk: RiskGeometryV1 = evidence.risk
    message = json.loads(lifecycle.request.message_json)
    expected = {
        "context": lifecycle.context,
        "decision_id": decision.decision_id,
        "signing_request_id": lifecycle.request.request_id,
        "effect_id": lifecycle.signing_effect_id,
        "client_order_id": message["id"],
        "operation": "New limit order",
        "instrument": decision.venue_symbol,
        "side": "BUY" if decision.intent.side is Side.LONG else "SELL",
        "quantity": message["quantity"],
        "price": message["limitPrice"],
        "leverage": 1,
        "worst_case_loss_usd": Decimal(str(decision.worst_case_loss_usd)),
    }
    actual = {key: getattr(risk, key) for key in expected}
    if actual != expected:
        raise ValueError("production signing risk geometry differs from the immutable Core entry decision")
    if not risk.approved:
        raise ValueError("production signing risk evidence is not approved")
