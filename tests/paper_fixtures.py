"""Strict Strategy Parity -> PAPER contract fixtures shared by execution tests."""

from __future__ import annotations

from kairos_core.contracts import (
    CandidateReviewV1,
    CandidateRouteV1,
    EvidenceReferenceV1,
    ExitPlanV1,
    RiskTradeDecisionV1,
    StrategyIntentV1,
    StrategyProvenanceV1,
    VenueQualityV1,
    canonical_sha256,
)
from kairos_core.enums import (
    CandidateReviewTier,
    EntryPolicy,
    EvedexProfile,
    ReasoningEffort,
    ReviewDecision,
    Side,
    TradingMode,
)

T0 = 1_800_000_000_000
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64


def _instrument_rule() -> tuple[dict[str, object], str]:
    payload: dict[str, object] = {
        "domain": "evedex-dev-instrument-rule.v1",
        "venue_lot_size": "1",
        "venue_market_state": "OPEN",
        "venue_max_price": "1000000",
        "venue_max_quantity": "100",
        "venue_min_price": "1",
        "venue_min_quantity": "0.1",
        "venue_min_volume_usd": "5",
        "venue_multiplier": "1",
        "venue_price_increment": "0.01",
        "venue_quantity_increment": "0.1",
        "venue_symbol": "BTCUSD:DEV",
        "venue_trading": "all",
        "venue_updated_at_ms": T0 + 60_100,
    }
    return payload, canonical_sha256(payload)


def approved_decision(**overrides: object) -> RiskTradeDecisionV1:
    plan = ExitPlanV1(stop_price=95, target_price=105, max_holding_ms=180_000)
    rule, rule_hash = _instrument_rule()
    metadata = (
        ("account_id", "kairos-paper-dev-01"),
        ("alpha_claim", "false"),
        ("canary_entry_order", "MARKETABLE_IOC_LIMIT"),
        ("canary_quantity", "0.1"),
        ("entry_policy", "NEXT_BAR_MARKET"),
        ("instrument_rules_sha256", rule_hash),
        ("purpose", "technical_execution_canary"),
        *((key, str(value)) for key, value in rule.items() if key != "domain"),
    )
    intent = StrategyIntentV1(
        source="kairos-paper-canary",
        strategy_id="technical-canary",
        strategy_revision="1",
        symbol="BTCUSDT",
        side=Side.LONG,
        decision_ts_ms=T0 + 59_999,
        entry_eligible_ts_ms=T0 + 60_000,
        entry_expires_ts_ms=T0 + 120_000,
        reference_price=100,
        signal_strength=0,
        gross_reward_bps=500,
        exit_plan=plan,
        provenance=StrategyProvenanceV1(
            strategy_code_sha256=SHA_A,
            config_sha256=SHA_B,
            input_window_sha256=SHA_C,
            features_sha256=SHA_D,
            input_bar_sha256s=(SHA_A,),
        ),
        evidence=(
            EvidenceReferenceV1(
                kind="closed_bar",
                reference=f"BINANCE_UM:BTCUSDT:{T0}",
                content_sha256=SHA_A,
                observed_at_ms=T0 + 59_999,
            ),
            EvidenceReferenceV1(
                kind="venue_instrument",
                reference=f"EVEDEX_DEV:BTCUSD:DEV:{T0 + 60_100}",
                content_sha256=rule_hash,
                observed_at_ms=T0 + 60_100,
            ),
        ),
        metadata=metadata,
    )
    route = CandidateRouteV1(
        source="kairos-paper-canary",
        correlation_id=intent.intent_id,
        causation_id=intent.message_id,
        intent=intent,
        review_tier=CandidateReviewTier.NORMAL,
        requested_reasoning_effort=ReasoningEffort.MEDIUM,
        routed_at_ms=intent.decision_ts_ms,
        review_deadline_ms=intent.entry_expires_ts_ms,
        evidence_ids=(SHA_A, rule_hash),
    )
    review = CandidateReviewV1(
        source="kairos-paper-canary",
        correlation_id=intent.intent_id,
        causation_id=route.message_id,
        route=route,
        intent=intent,
        decision=ReviewDecision.ALLOW,
        priority=0,
        reviewed_at_ms=intent.entry_eligible_ts_ms,
        reviewer="DETERMINISTIC",
        reason_codes=("TECHNICAL_CANARY_MANUAL_POLICY",),
        evidence=intent.evidence,
    )
    venue = VenueQualityV1(
        source="venue-gate",
        profile=EvedexProfile.DEV,
        symbol="BTCUSD:DEV",
        observed_at_ms=T0 + 60_300,
        expires_at_ms=T0 + 65_000,
        reference_timestamp_ms=T0 + 60_000,
        book_timestamp_ms=T0 + 60_100,
        reference_mid_price=100,
        best_bid=100.49,
        best_ask=100.51,
        venue_mid_price=100.5,
        basis_bps=50,
        spread_bps=(100.51 - 100.49) / 100.5 * 10_000,
        assessed_notional_usd=10.051,
        depth_usd=5_000,
        buy_slippage_bps=1,
        sell_slippage_bps=1.2,
        taker_fee_bps=5,
        reference_age_ms=300,
        book_age_ms=200,
        latency_ms=80,
        timestamp_skew_ms=100,
        entry_allowed=True,
    )
    quantity = 0.1
    worst_entry = venue.best_ask
    notional = quantity * worst_entry
    fees = quantity * (worst_entry + plan.stop_price) * venue.taker_fee_bps / 10_000
    slippage = quantity * venue.venue_mid_price * venue.buy_slippage_bps / 10_000
    worst_loss = quantity * abs(worst_entry - plan.stop_price) + fees + slippage
    values: dict[str, object] = {
        "source": "risk-manager",
        "intent": intent,
        "review": review,
        "venue_quality": venue,
        "approved": True,
        "decided_at_ms": T0 + 60_400,
        "entry_policy": EntryPolicy.NEXT_BAR_MARKET,
        "trading_mode": TradingMode.PAPER,
        "evedex_profile": EvedexProfile.DEV,
        "account_id": "kairos-paper-dev-01",
        "venue_symbol": "BTCUSD:DEV",
        "quantity": quantity,
        "leverage": 1,
        "notional_usd": notional,
        "loss_budget_usd": 1,
        "worst_case_loss_usd": worst_loss,
        "worst_entry_price": worst_entry,
        "estimated_fees_usd": fees,
        "estimated_slippage_usd": slippage,
        "exit_plan": plan,
    }
    values.update(overrides)
    return RiskTradeDecisionV1(**values)


def rejected_decision(**overrides: object) -> RiskTradeDecisionV1:
    values: dict[str, object] = {
        "approved": False,
        "rejection_reasons": ("venue_entry_blocked",),
        "quantity": 0,
        "notional_usd": 0,
        "worst_case_loss_usd": 0,
        "estimated_fees_usd": 0,
        "estimated_slippage_usd": 0,
    }
    values.update(overrides)
    return approved_decision(**values)
