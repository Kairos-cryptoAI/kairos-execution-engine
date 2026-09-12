"""Risk refusals are acknowledged audit facts, never execution attempts."""

from types import SimpleNamespace

import pytest
from kairos_core.contracts import CandidateReviewV1, CandidateRouteV1, StrategyIntentV1, VenueQualityV1
from kairos_core.enums import EvedexProfile, ReviewDecision, TradingMode

from kairos_execution.paper_engine import PaperExecutionEngine, PaperExecutionSafetyError
from tests.paper_fixtures import T0, approved_decision, rejected_decision


class NoExecutionIO:
    def __getattr__(self, name):
        pytest.fail(f"a rejected decision attempted execution I/O: {name}")


def rejection_engine() -> PaperExecutionEngine:
    io = NoExecutionIO()
    settings = SimpleNamespace(
        trading_mode=TradingMode.PAPER,
        account_id="kairos-paper-dev-01",
        evedex_dev_symbol_map={"BTCUSDT": "BTCUSD:DEV"},
    )
    return PaperExecutionEngine(
        io,
        io,
        io,
        settings,
        clock=lambda: pytest.fail("a rejected decision read the execution clock"),
        mutation_budget=io,
        runtime_health=io,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("recovery_blocked", [False, True])
async def test_rejected_decision_and_redelivery_have_no_execution_side_effects(recovery_blocked):
    engine = rejection_engine()
    blockers = ("recovery already active",) if recovery_blocked else ()
    engine._recovery_blockers = blockers
    decision = rejected_decision()

    for _ in range(2):
        result = await engine.handle(decision)
        assert result.events == ()
        assert engine.recovery_blockers == blockers


@pytest.mark.asyncio
async def test_expired_rejected_decision_does_not_require_fresh_admission_inputs():
    engine = rejection_engine()
    decision = rejected_decision(
        decided_at_ms=T0 + 180_000,
        rejection_reasons=("candidate_expired", "venue_quality_stale"),
    )

    assert (await engine.handle(decision)).events == ()


@pytest.mark.asyncio
@pytest.mark.parametrize("review_decision", [ReviewDecision.VETO, ReviewDecision.DEFER])
async def test_refused_non_canary_review_needs_no_canary_mutation_authority(review_decision):
    base = approved_decision()
    envelope_fields = {"message_id", "correlation_id", "produced_at", "causation_id"}
    intent = StrategyIntentV1.model_validate(
        base.intent.model_dump(exclude=envelope_fields | {"intent_id"})
        | {"strategy_id": "future-alpha", "source": "kairos-strategy-engine"}
    )
    route = CandidateRouteV1.model_validate(
        base.review.route.model_dump(exclude=envelope_fields | {"route_id", "intent_sha256"})
        | {"intent": intent.to_payload(), "source": "kairos-router"}
    )
    review = CandidateReviewV1.model_validate(
        base.review.model_dump(exclude=envelope_fields | {"review_id", "intent_sha256"})
        | {
            "intent": intent.to_payload(),
            "route": route.to_payload(),
            "source": "kairos-aggregator",
            "decision": review_decision,
            "reason_codes": ("review_refused",),
        }
    )
    decision = rejected_decision(
        intent=intent,
        review=review,
        rejection_reasons=(f"review_{review_decision.value.lower()}",),
    )

    assert (await rejection_engine().handle(decision)).events == ()


@pytest.mark.asyncio
async def test_rejected_venue_may_expire_before_candidate_eligibility():
    base = approved_decision().venue_quality
    payload = base.model_dump(exclude={"measurement_id", "message_id", "correlation_id", "produced_at"})
    for field in ("observed_at_ms", "expires_at_ms", "reference_timestamp_ms", "book_timestamp_ms"):
        payload[field] -= 60_000
    venue = VenueQualityV1.model_validate(payload)
    decision = rejected_decision(venue_quality=venue, rejection_reasons=("venue_quality_stale",))

    assert (await rejection_engine().handle(decision)).events == ()


@pytest.mark.asyncio
async def test_rejected_entry_geometry_is_valid_refusal_evidence():
    base = approved_decision().venue_quality
    payload = base.model_dump(exclude={"measurement_id", "message_id", "correlation_id", "produced_at"})
    payload.update(
        best_bid=94.98,
        best_ask=95.0,
        venue_mid_price=94.99,
        basis_bps=(94.99 - 100) / 100 * 10_000,
        spread_bps=(95 - 94.98) / 94.99 * 10_000,
    )
    venue = VenueQualityV1.model_validate(payload)
    decision = rejected_decision(
        venue_quality=venue,
        worst_entry_price=95,
        rejection_reasons=("long_entry_exit_geometry_invalid",),
    )

    assert (await rejection_engine().handle(decision)).events == ()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"trading_mode": TradingMode.DRY_RUN}, "non-PAPER"),
        ({"evedex_profile": EvedexProfile.PROD}, "non-DEV"),
        ({"account_id": "different-account"}, "different PAPER account"),
        ({"venue_symbol": "ETHUSD:DEV"}, "outside the DEV allowlist"),
        ({"decision_id": "f" * 64}, "invalid canonical lineage"),
        ({"trade_id": "f" * 64}, "invalid canonical lineage"),
    ],
)
async def test_rejected_decision_does_not_bypass_scope_or_hash_validation(changes, message):
    decision = rejected_decision().model_copy(update=changes)

    with pytest.raises(PaperExecutionSafetyError, match=message):
        await rejection_engine().handle(decision)


@pytest.mark.asyncio
async def test_rejected_decision_with_execution_economics_is_not_silently_discarded():
    decision = approved_decision(approved=False, rejection_reasons=("venue_entry_blocked",))

    with pytest.raises(PaperExecutionSafetyError, match="zero execution economics"):
        await rejection_engine().handle(decision)


@pytest.mark.asyncio
async def test_refusal_does_not_bypass_immutable_exit_plan_validation():
    decision = rejected_decision()
    changed_plan = decision.exit_plan.model_copy(update={"stop_price": decision.exit_plan.target_price})

    with pytest.raises(PaperExecutionSafetyError, match="invalid canonical lineage"):
        await rejection_engine().handle(decision.model_copy(update={"exit_plan": changed_plan}))


def test_approved_decision_retains_canary_mutation_validation():
    engine = rejection_engine()
    engine._validate_decision(approved_decision())
    decision = approved_decision()
    changed_intent = decision.intent.model_copy(update={"source": "untrusted-candidate-source"})

    with pytest.raises(PaperExecutionSafetyError, match="dedicated source lineage"):
        engine._validate_decision(decision.model_copy(update={"intent": changed_intent}))
