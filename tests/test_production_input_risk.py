"""Synthetic-only tests for opt-in Risk/verifier composition."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from kairos_core.contracts import (
    CandidateReviewV1,
    CandidateRouteV1,
    ObservedSimStrategyIntentV2,
    StrategyIntentV1,
    canonical_sha256,
)
from kairos_core.enums import SystemMode
from kairos_risk.live import LiveRiskEvaluator

from kairos_execution.production_exposure import GAPS
from kairos_execution.production_history import ProductionHistoryCaptureV1, ProductionHistoryComponentV1
from kairos_execution.production_input_risk import build_opt_in_production_live_risk_evaluator
from kairos_execution.production_risk import PinnedEvedexLiveAccountVerifier
from tests.test_production_inputs import TEST_SEED, _signed_fixture
from tests.test_production_risk import NOW, _inputs


def _public_key() -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(TEST_SEED)
        .public_key()
        .public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )


def _capture(context) -> ProductionHistoryCaptureV1:
    started = NOW - timedelta(milliseconds=1)
    payload = "{}"
    component = ProductionHistoryComponentV1(
        path="/synthetic/history",
        query_json="{}",
        payload_json=payload,
        payload_sha256=hashlib.sha256(payload.encode()).hexdigest(),
        started_at=started,
        finished_at=NOW,
    )
    return ProductionHistoryCaptureV1(
        context=context,
        account_id=context.remote_account_id,
        collection_started_at=started,
        collection_finished_at=NOW,
        components=(component,),
        order_count=0,
        protection_count=0,
    )


def _factory(scope, limits, trust):
    return build_opt_in_production_live_risk_evaluator(
        scope=scope,
        limits=limits,
        producer_trust=trust,
        producer_public_key=_public_key(),
    )


def test_factory_composes_signed_inputs_but_keeps_pinned_account_refusal():
    _review, _venue, _allocation, _account, _writer, _bindings, publisher, context, scope = _inputs()
    verifier, proof, _decision_context, review, venue, _scope, decided_ms = _signed_fixture()
    evaluator = _factory(scope, publisher.evaluator.limits, verifier.trust)
    assert isinstance(evaluator, LiveRiskEvaluator)

    # A valid synthetic envelope is authenticated and its provenance reaches
    # the ordinary Risk evaluation, even though account evidence still fails.
    result = evaluator.evaluate(
        object(),
        source_id=SOURCE_ID,
        review=review,
        venue=venue,
        allocation=None,
        decided_at_ms=decided_ms,
        system_mode=SystemMode.NORMAL,
        raw_inputs_evidence=proof,
    )
    assert result.inputs_source_id == "synthetic-source"
    assert result.inputs_evidence_sha256 is not None
    assert result.inputs_observed_at_ms == proof.observed_at_ms
    assert "account_source_verification_failed" in result.decision.rejection_reasons

    # The fixed production account verifier intentionally cannot establish
    # account economics; no input proof can turn this into account authority.
    account_verifier = evaluator._account_verifiers[SOURCE_ID]
    with pytest.raises(PermissionError, match="cannot authorize an exposure write"):
        account_verifier.verify(_capture(context), source_id=SOURCE_ID, expected_scope=scope)
    assert GAPS


def test_factory_rejects_trust_scope_substitution():
    _review, _venue, _allocation, _account, _writer, _bindings, publisher, _context, scope = _inputs()
    verifier, _proof, *_ = _signed_fixture()
    wrong = verifier.trust.model_copy(update={"source_set_sha256": "f" * 64})
    with pytest.raises(ValueError, match="trust policy does not match"):
        _factory(scope, publisher.evaluator.limits, wrong)


def test_malformed_signed_input_is_rejected_and_does_not_create_verified_facts():
    _review, _venue, _allocation, _account, _writer, _bindings, publisher, _context, scope = _inputs()
    verifier, proof, context, review, venue, _scope, decided_ms = _signed_fixture()
    evaluator = _factory(scope, publisher.evaluator.limits, verifier.trust)
    tampered = proof.model_copy(update={"observed_at_ms": proof.observed_at_ms - 1})
    result = evaluator.evaluate(
        object(),
        source_id=SOURCE_ID,
        review=review,
        venue=venue,
        allocation=None,
        decided_at_ms=decided_ms,
        system_mode=SystemMode.NORMAL,
        raw_inputs_evidence=tampered,
    )
    assert result.inputs_source_id is None
    assert result.inputs_evidence_sha256 is None
    assert "input_source_verification_failed" in result.decision.rejection_reasons
    assert context.authority == "review_only"


def test_observed_sim_intent_remains_rejected_by_actual_risk_evaluator():
    _fixture_review, _venue, _allocation, _account, _writer, _bindings, base_publisher, *_ = _inputs()
    base = base_publisher.evaluator
    _unused_verifier, _proof, _ctx, normal_review, venue, _scope, decided_ms = _signed_fixture()
    original = StrategyIntentV1.model_validate(normal_review.intent.model_dump(mode="json"))
    route_ms = original.entry_eligible_ts_ms
    close_ms = route_ms - 1
    plan = original.exit_plan
    metadata = {
        "hypothesis_id": "1" * 64,
        "source_set_sha256": "2" * 64,
        "entry_quote_sha256": "3" * 64,
        "protection_sha256": canonical_sha256(
            {
                "stop_price": plan.stop_price,
                "target_price": plan.target_price,
                "max_holding_ms": plan.max_holding_ms,
                "trailing_activation_price": None,
                "trailing_distance": None,
            }
        ),
        "evidence_kind": "TEST_FIXTURE",
        "confirmation_bar_close_ms": str(close_ms),
    }
    sim_intent = ObservedSimStrategyIntentV2(
        source="synthetic-current-chain-test",
        produced_at=datetime.fromtimestamp(route_ms / 1_000, tz=UTC),
        strategy_id=original.strategy_id,
        strategy_revision=original.strategy_revision,
        symbol=original.symbol,
        side=original.side,
        decision_ts_ms=route_ms,
        entry_eligible_ts_ms=route_ms,
        entry_expires_ts_ms=original.entry_expires_ts_ms,
        reference_price=original.reference_price,
        signal_strength=original.signal_strength,
        gross_reward_bps=original.gross_reward_bps,
        exit_plan=plan,
        provenance=original.provenance,
        metadata=tuple(sorted(metadata.items())),
    )
    route = normal_review.route.model_copy(
        update={"intent": sim_intent, "route_id": None, "intent_sha256": None}
    )
    # Revalidate to derive a fresh route identity around the SIM-only intent.
    route = CandidateRouteV1.model_validate(route.model_dump(mode="json"))
    sim_review = CandidateReviewV1.model_validate(
        normal_review.model_copy(
            update={"route": route, "intent": sim_intent, "review_id": None, "intent_sha256": None}
        ).model_dump(mode="json")
    )
    result = base.evaluate(
        object(),
        source_id=SOURCE_ID,
        review=sim_review,
        venue=venue,
        allocation=None,
        decided_at_ms=decided_ms,
        system_mode=SystemMode.NORMAL,
        raw_inputs_evidence=None,
    )
    assert "SIM_ONLY_INTENT" in result.decision.rejection_reasons
    assert "input_source_proof_missing" in result.decision.rejection_reasons


SOURCE_ID = PinnedEvedexLiveAccountVerifier.source_id
