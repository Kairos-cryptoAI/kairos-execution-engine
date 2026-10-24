"""Focused synthetic tests for the opt-in upstream-input signature verifier."""

from __future__ import annotations

import base64
import hashlib

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from kairos_core.contracts import (
    CandidateReviewV1,
    CandidateRouteV1,
    ClosedBarEventV1,
    DecisionContextReceiptV1,
    DecisionContextSourceV1,
    DecisionContextV1,
    ExitPlanV1,
    MarketSnapshot,
    ModelProvenanceV1,
    SentimentSignal,
    StrategyIntentV1,
    StrategyProvenanceV1,
    canonical_json_bytes,
    canonical_sha256,
)
from kairos_core.contracts.base import datetime_from_unix_ms
from kairos_core.enums import (
    CandidateReviewTier,
    ImpactDirection,
    ReasoningEffort,
    ReviewDecision,
    Side,
    SystemMode,
)
from kairos_core.topics import Topics

from kairos_execution.production_inputs import (
    _DOMAIN,
    LiveInputProducerTrustV1,
    LiveInputsSourceVerifier,
    LiveInputStageReceiptV1,
    SignedLiveInputsEnvelopeV1,
)
from tests.test_production_risk import _inputs

TEST_SEED = bytes(range(32))  # Existing deterministic test-only vector; never a deployment key.


def _trust(scope):
    return LiveInputProducerTrustV1(
        producer_id="synthetic-producer",
        source_id="synthetic-source",
        purpose="LIVE_UPSTREAM_INPUT_CAPTURE",
        source_set_sha256=scope.source_set_sha256,
        policy_sha256=scope.policy_sha256,
        expected_text_source_names=("synthetic-rss-source",),
        capture_implementation_id="synthetic-capture-fixture",
        capture_implementation_sha256="a" * 64,
        registration_id="synthetic-test-registration",
    )


def _receipt(stage, body, source_ms, captured_ms, *, parent_receipt_ids=()):
    is_raw_source = stage in {"TEXT_SOURCE", "MACRO_SOURCE", "BINANCE_REFERENCE", "EVEDEX_BOOK"}
    return LiveInputStageReceiptV1(
        stage=stage,
        receipt_id=f"fixture-{stage.casefold().replace('_', '-')}",
        source_name=(
            "synthetic-rss-source"
            if stage == "TEXT_SOURCE"
            else "synthetic-macro-source"
            if stage == "MACRO_SOURCE"
            else None
        ),
        status="CAPTURED",
        output_origin=(
            "NATIVE_DETERMINISTIC_FALLBACK" if stage in {"TEXT_AGGREGATE", "MACRO_ALLOCATION"} else None
        ),
        source_timestamp_ms=source_ms,
        requested_at_ms=source_ms - 10 if is_raw_source else None,
        received_at_ms=source_ms + 10 if is_raw_source else None,
        persisted_at_ms=captured_ms if is_raw_source else None,
        captured_at_ms=captured_ms,
        content_sha256=hashlib.sha256(body).hexdigest(),
        content_base64=base64.b64encode(body).decode("ascii"),
        parent_receipt_ids=parent_receipt_ids,
    )


def _envelope(review, context, venue, allocation, scope, decided_ms, *, system_mode=SystemMode.NORMAL):
    stages = []
    for name in (
        "TEXT_SOURCE",
        "TEXT_AGGREGATE",
        "MACRO_SOURCE",
        "MACRO_ALLOCATION",
        "DECISION_CONTEXT",
        "BINANCE_REFERENCE",
        "EVEDEX_BOOK",
    ):
        if name in {"MACRO_SOURCE", "MACRO_ALLOCATION"} and allocation is None:
            stages.append(
                LiveInputStageReceiptV1(
                    stage=name,
                    receipt_id=f"fixture-{name.casefold().replace('_', '-')}",
                    source_name="synthetic-macro-source" if name == "MACRO_SOURCE" else None,
                    status="UNAVAILABLE",
                    reason_code="NO_MACRO_SOURCE_IN_FIXTURE",
                    source_timestamp_ms=None,
                    captured_at_ms=decided_ms - 100,
                )
            )
            continue
        if name == "TEXT_AGGREGATE":
            text_context = next(source for source in context.sources if source.kind == "text")
            body = text_context.payloads_json.encode("utf-8")
        elif name == "MACRO_ALLOCATION":
            body = canonical_json_bytes(allocation)
        elif name == "DECISION_CONTEXT":
            body = canonical_json_bytes(context)
        else:
            body = f"synthetic-{name}".encode()
        if name in {"MACRO_SOURCE", "MACRO_ALLOCATION"}:
            source_ms = int(allocation.produced_at.timestamp() * 1000)
        else:
            source_ms = {
                "TEXT_SOURCE": context.captured_at_ms - 20,
                "TEXT_AGGREGATE": max(
                    receipt.event_at_ms
                    for source in context.sources
                    if source.kind == "text"
                    for receipt in source.receipts
                ),
                "DECISION_CONTEXT": context.captured_at_ms,
                "BINANCE_REFERENCE": venue.reference_timestamp_ms,
                "EVEDEX_BOOK": venue.book_timestamp_ms,
            }[name]
        parents = (
            ("fixture-text-source",)
            if name == "TEXT_AGGREGATE"
            else ("fixture-macro-source",)
            if name == "MACRO_ALLOCATION"
            else ()
        )
        captured_ms = (
            context.captured_at_ms
            if name in {"TEXT_SOURCE", "TEXT_AGGREGATE", "DECISION_CONTEXT"}
            else decided_ms - 100
        )
        stages.append(_receipt(name, body, source_ms, captured_ms, parent_receipt_ids=parents))
    stages.extend(
        [
            _receipt(
                "ROUTER_OUTPUT",
                canonical_json_bytes(review.route),
                review.route.routed_at_ms,
                decided_ms - 100,
            ),
            _receipt("REVIEW_OUTPUT", canonical_json_bytes(review), review.reviewed_at_ms, decided_ms - 100),
            _receipt("VENUE_QUALITY", canonical_json_bytes(venue), venue.observed_at_ms, decided_ms - 100),
        ]
    )
    unsigned = SignedLiveInputsEnvelopeV1(
        producer_id="synthetic-producer",
        source_id="synthetic-source",
        purpose="LIVE_UPSTREAM_INPUT_CAPTURE",
        registration_id="synthetic-test-registration",
        capture_implementation_id="synthetic-capture-fixture",
        capture_implementation_sha256="a" * 64,
        source_set_sha256=scope.source_set_sha256,
        policy_sha256=scope.policy_sha256,
        scope_sha256=scope.scope_sha256,
        observed_at_ms=decided_ms - 100,
        route=review.route,
        review=review,
        context=context,
        venue=venue,
        allocation=allocation,
        system_mode=system_mode,
        stages=tuple(stages),
        signature_base64=base64.b64encode(bytes(64)).decode("ascii"),
    )
    private = Ed25519PrivateKey.from_private_bytes(TEST_SEED)
    signature = private.sign(_DOMAIN + unsigned.signed_payload())
    return unsigned.model_copy(update={"signature_base64": base64.b64encode(signature).decode("ascii")})


def _verifier(scope):
    private = Ed25519PrivateKey.from_private_bytes(TEST_SEED)
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return LiveInputsSourceVerifier(trust=_trust(scope), public_key=public)


def _resign(proof):
    unsigned = proof.model_copy(update={"signature_base64": base64.b64encode(bytes(64)).decode("ascii")})
    private = Ed25519PrivateKey.from_private_bytes(TEST_SEED)
    signature = private.sign(_DOMAIN + unsigned.signed_payload())
    return unsigned.model_copy(update={"signature_base64": base64.b64encode(signature).decode("ascii")})


def _with_stage(proof, receipt_id, **updates):
    stages = tuple(
        stage.model_copy(update=updates) if stage.receipt_id == receipt_id else stage
        for stage in proof.stages
    )
    return _resign(proof.model_copy(update={"stages": stages}))


def _model_artifact(
    stage,
    *,
    receipt_id,
    call_id,
    request_id,
    output_sha256,
    workload_id="TEXT_AGGREGATION",
    budget_reservation_id=None,
):
    body = f"synthetic {call_id} {stage}".encode()
    return LiveInputStageReceiptV1(
        stage=stage,
        receipt_id=receipt_id,
        workload_id=workload_id,
        call_id=call_id,
        provider="synthetic-provider",
        model="synthetic-model",
        reasoning_effort="none",
        request_id=request_id,
        budget_reservation_id=budget_reservation_id or f"reservation-{call_id}",
        bound_output_sha256=output_sha256,
        status="CAPTURED",
        source_timestamp_ms=1_800_000_060_049,
        captured_at_ms=1_800_000_060_050,
        content_sha256=hashlib.sha256(body).hexdigest(),
        content_base64=base64.b64encode(body).decode("ascii"),
    )


def _native_context_and_review(scope, venue):
    route_ms = 1_800_000_060_000
    close_ms = route_ms - 1
    captured_ms = route_ms + 50
    bar = ClosedBarEventV1(
        source="synthetic-quant-scouts",
        symbol="BTCUSDT",
        open_time_ms=close_ms - 59_999,
        close_time_ms=close_ms,
        open=100.0,
        high=101.0,
        low=99.0,
        close=100.5,
        base_volume=10.0,
        quote_volume=1_000.0,
        taker_buy_base_volume=5.0,
        taker_buy_quote_volume=500.0,
    )
    intent = StrategyIntentV1(
        source="synthetic-strategy-engine",
        strategy_id=scope.strategy_id,
        strategy_revision=scope.strategy_revision,
        symbol="BTCUSDT",
        side=Side.LONG,
        decision_ts_ms=close_ms,
        entry_eligible_ts_ms=route_ms,
        entry_expires_ts_ms=1_800_000_120_000,
        reference_price=100.0,
        signal_strength=0.5,
        gross_reward_bps=500.0,
        exit_plan=ExitPlanV1(stop_price=95.0, target_price=105.0, max_holding_ms=180_000),
        provenance=StrategyProvenanceV1(
            strategy_code_sha256="a" * 64,
            config_sha256="b" * 64,
            input_window_sha256="c" * 64,
            features_sha256="d" * 64,
            input_bar_sha256s=(bar.bar_sha256,),
        ),
    )
    signal = SentimentSignal(
        source="synthetic-text-scouts",
        message_id="synthetic-text-1",
        produced_at=datetime_from_unix_ms(route_ms - 10),
        topic="BTCUSDT",
        sentiment=0.0,
        impact=ImpactDirection.NEUTRAL,
        confidence=0.5,
        sources=["https://fixture.invalid/item"],
        summary="Synthetic verifier test data only.",
    )
    route = CandidateRouteV1(
        source="synthetic-router",
        intent=intent,
        review_tier=CandidateReviewTier.NORMAL,
        requested_reasoning_effort=ReasoningEffort.MEDIUM,
        routed_at_ms=route_ms,
        review_deadline_ms=route_ms + 20_000,
        evidence_ids=(signal.message_id,),
    )
    market = MarketSnapshot(
        source="synthetic-quant-scouts",
        message_id="synthetic-market-1",
        produced_at=datetime_from_unix_ms(route_ms - 20),
        symbol="BTCUSDT",
        mid_price=100.0,
        volume_usd=1_000.0,
        order_book={
            "best_bid": 99.9,
            "best_ask": 100.1,
            "spread_bps": 20.0,
            "imbalance": 0.2,
            "depth_usd": 10_000.0,
        },
        derivatives={"funding_rate": 0.0001, "open_interest": 100_000.0},
        indicators={"rsi_14": 55.0, "macd": 0.1, "macd_signal": 0.05, "macd_hist": 0.05},
    )

    def available(kind, message, topic, *, event_ms, ttl_ms):
        payload = message.model_dump(mode="json")
        return DecisionContextSourceV1(
            kind=kind,
            availability="AVAILABLE",
            receipts=(
                DecisionContextReceiptV1(
                    message_id=message.message_id,
                    source=message.source,
                    topic=topic,
                    content_sha256=canonical_sha256(payload),
                    event_at_ms=event_ms,
                    produced_at_ms=int(message.produced_at.timestamp() * 1_000),
                    received_at_ms=route_ms + 25,
                    ttl_ms=ttl_ms,
                ),
            ),
            payloads_json=canonical_json_bytes({"items": [payload]}).decode("utf-8"),
        )

    context = DecisionContextV1(
        source="synthetic-native-context",
        route_id=route.route_id,
        intent_id=intent.intent_id,
        route_identity_json=canonical_json_bytes(route.identity_payload()).decode("utf-8"),
        intent_identity_json=intent.canonical_intent_bytes().decode("utf-8"),
        symbol=intent.symbol,
        event_as_of_ms=route.routed_at_ms,
        knowledge_cutoff_ms=route_ms + 25,
        captured_at_ms=captured_ms,
        review_deadline_ms=route.review_deadline_ms,
        maximum_closed_bars=1,
        required_sources=("market", "closed_bars", "text"),
        sources=(
            available("market", market, Topics.MARKET_SNAPSHOT, event_ms=route_ms - 20, ttl_ms=5_000),
            available("closed_bars", bar, Topics.CLOSED_BAR, event_ms=bar.close_time_ms, ttl_ms=90_000),
            available("text", signal, Topics.SENTIMENT_SIGNAL, event_ms=route_ms - 10, ttl_ms=30 * 60_000),
            DecisionContextSourceV1(
                kind="macro",
                availability="UNAVAILABLE",
                reason_code="NO_SYNTHETIC_MACRO_ALLOCATION",
            ),
        ),
    )
    context.validate_for_route(route)
    review = CandidateReviewV1(
        source="synthetic-review",
        route=route,
        intent=intent,
        decision=ReviewDecision.ALLOW,
        reviewed_at_ms=venue.observed_at_ms,
        reviewer="DETERMINISTIC",
        reason_codes=("SYNTHETIC_NATIVE_CONTEXT_FIXTURE",),
        evidence=context.evidence_references(),
    )
    return context, review


def test_signed_envelope_derives_exact_risk_hashes_and_accepts_explicit_missing_macro():
    _fixture_review, venue, allocation, _account, _writer, _bindings, _publisher, _context, scope = _inputs()
    context, review = _native_context_and_review(scope, venue)
    decided_ms = venue.observed_at_ms + 100
    proof = _envelope(review, context, venue, None, scope, decided_ms)
    verified = _verifier(scope).verify(
        proof,
        expected_scope=scope,
        review=review,
        venue=venue,
        allocation=None,
        system_mode=SystemMode.NORMAL,
        decided_at_ms=decided_ms,
    )
    assert verified.source_id == "synthetic-source"
    assert verified.review_sha256 == canonical_sha256(review)
    assert verified.allocation_sha256 is None
    assert context.authority == "review_only"
    assert context.missing_required_sources() == ()
    assert review.evidence == context.evidence_references()


def test_signature_and_exact_input_substitution_fail_closed():
    _fixture_review, venue, allocation, _account, _writer, _bindings, _publisher, _context, scope = _inputs()
    context, review = _native_context_and_review(scope, venue)
    decided_ms = venue.observed_at_ms + 100
    proof = _envelope(review, context, venue, None, scope, decided_ms)
    verifier = _verifier(scope)
    tampered = proof.model_copy(update={"observed_at_ms": proof.observed_at_ms - 1})
    with pytest.raises(ValueError, match="signature"):
        verifier.verify(
            tampered,
            expected_scope=scope,
            review=review,
            venue=venue,
            allocation=None,
            system_mode=SystemMode.NORMAL,
            decided_at_ms=decided_ms,
        )
    substituted_review = review.model_copy(update={"priority": review.priority + 1})
    with pytest.raises(ValueError, match="exact Risk input DTOs"):
        verifier.verify(
            proof,
            expected_scope=scope,
            review=substituted_review,
            venue=venue,
            allocation=None,
            system_mode=SystemMode.NORMAL,
            decided_at_ms=decided_ms,
        )


def test_expired_venue_clock_is_not_relaxed():
    _fixture_review, venue, _allocation, _account, _writer, _bindings, _publisher, _context, scope = _inputs()
    context, review = _native_context_and_review(scope, venue)
    decided_ms = venue.observed_at_ms + 2_500
    proof = _envelope(review, context, venue, None, scope, decided_ms)
    with pytest.raises(ValueError, match="two-second"):
        _verifier(scope).verify(
            proof,
            expected_scope=scope,
            review=review,
            venue=venue,
            allocation=None,
            system_mode=SystemMode.NORMAL,
            decided_at_ms=decided_ms,
        )


def _signed_fixture():
    _fixture_review, venue, _allocation, _account, _writer, _bindings, _publisher, _context, scope = _inputs()
    context, review = _native_context_and_review(scope, venue)
    decided_ms = venue.observed_at_ms + 100
    proof = _envelope(review, context, venue, None, scope, decided_ms)
    return _verifier(scope), proof, context, review, venue, scope, decided_ms


def _verify(verifier, proof, review, venue, scope, decided_ms):
    return verifier.verify(
        proof,
        expected_scope=scope,
        review=review,
        venue=venue,
        allocation=None,
        system_mode=SystemMode.NORMAL,
        decided_at_ms=decided_ms,
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("context_sha256", "c" * 64),
        ("source_set_sha256", "d" * 64),
        ("policy_sha256", "e" * 64),
        ("account_id", "different-account"),
    ],
)
def test_scope_substitution_fails_even_with_a_valid_producer_signature(field, value):
    verifier, proof, _context, review, venue, scope, decided_ms = _signed_fixture()
    substituted_scope = scope.model_copy(update={field: value})
    with pytest.raises(ValueError, match="identity mismatch"):
        verifier.verify(
            proof,
            expected_scope=substituted_scope,
            review=review,
            venue=venue,
            allocation=None,
            system_mode=SystemMode.NORMAL,
            decided_at_ms=decided_ms,
        )


@pytest.mark.parametrize("field", ["producer_id", "source_id", "registration_id"])
def test_signed_producer_identity_substitution_fails_closed(field):
    verifier, proof, _context, review, venue, scope, decided_ms = _signed_fixture()
    changed = _resign(proof.model_copy(update={field: "substituted-producer"}))
    with pytest.raises(ValueError, match="identity mismatch"):
        _verify(verifier, changed, review, venue, scope, decided_ms)


def test_signed_context_substitution_cannot_reuse_the_callers_review():
    verifier, proof, context, review, venue, scope, decided_ms = _signed_fixture()
    changed_context = context.model_copy(update={"source": "substituted-context-producer"})
    changed_review = review.model_copy(
        update={"evidence": changed_context.evidence_references(), "review_id": None}
    )
    changed_context_bytes = canonical_json_bytes(changed_context)
    changed_review_bytes = canonical_json_bytes(changed_review)
    changed_stages = []
    for stage in proof.stages:
        if stage.stage == "DECISION_CONTEXT":
            body = changed_context_bytes
        elif stage.stage == "REVIEW_OUTPUT":
            body = changed_review_bytes
        else:
            changed_stages.append(stage)
            continue
        changed_stages.append(
            stage.model_copy(
                update={
                    "content_base64": base64.b64encode(body).decode("ascii"),
                    "content_sha256": hashlib.sha256(body).hexdigest(),
                }
            )
        )
    changed = _resign(
        proof.model_copy(
            update={"context": changed_context, "review": changed_review, "stages": tuple(changed_stages)}
        )
    )
    with pytest.raises(ValueError, match="exact Risk input DTOs"):
        _verify(verifier, changed, review, venue, scope, decided_ms)


@pytest.mark.parametrize(
    "missing_stage",
    sorted(
        {
            "TEXT_SOURCE",
            "TEXT_AGGREGATE",
            "MACRO_SOURCE",
            "MACRO_ALLOCATION",
            "ROUTER_OUTPUT",
            "REVIEW_OUTPUT",
            "DECISION_CONTEXT",
            "VENUE_QUALITY",
            "BINANCE_REFERENCE",
            "EVEDEX_BOOK",
        }
    ),
)
def test_each_required_stage_must_be_present(missing_stage):
    verifier, proof, _context, review, venue, scope, decided_ms = _signed_fixture()
    remaining = tuple(stage for stage in proof.stages if stage.stage != missing_stage)
    incomplete = _resign(proof.model_copy(update={"stages": remaining}))
    with pytest.raises(ValueError, match="required upstream stages"):
        _verify(verifier, incomplete, review, venue, scope, decided_ms)


def test_text_source_original_30_minute_ttl_is_checked_at_capture_not_retimed():
    verifier, proof, _context, review, venue, scope, decided_ms = _signed_fixture()
    text = next(stage for stage in proof.stages if stage.stage == "TEXT_SOURCE")
    old_source_ms = text.captured_at_ms - 30 * 60 * 1_000 - 1
    stale = _with_stage(
        proof,
        text.receipt_id,
        source_timestamp_ms=old_source_ms,
        requested_at_ms=old_source_ms,
        received_at_ms=old_source_ms + 1,
        persisted_at_ms=text.captured_at_ms,
    )
    with pytest.raises(ValueError, match="TEXT_SOURCE exceeds its existing source/planning TTL"):
        _verify(verifier, stale, review, venue, scope, decided_ms)


def test_text_planning_ten_minute_ttl_is_not_extended_by_fresh_envelope():
    verifier, proof, _context, review, venue, scope, decided_ms = _signed_fixture()
    text = next(stage for stage in proof.stages if stage.stage == "TEXT_AGGREGATE")
    stale = _with_stage(
        proof,
        text.receipt_id,
        source_timestamp_ms=text.captured_at_ms - 10 * 60 * 1_000 - 1,
    )
    with pytest.raises(ValueError, match="TEXT_AGGREGATE exceeds its existing source/planning TTL"):
        _verify(verifier, stale, review, venue, scope, decided_ms)


def test_future_envelope_observation_is_rejected_after_a_valid_signature():
    verifier, proof, _context, review, venue, scope, decided_ms = _signed_fixture()
    future = _resign(proof.model_copy(update={"observed_at_ms": decided_ms + 1}))
    with pytest.raises(ValueError, match="future-dated"):
        _verify(verifier, future, review, venue, scope, decided_ms)


def test_stage_content_substitution_with_recomputed_digest_fails_native_join():
    verifier, proof, _context, review, venue, scope, decided_ms = _signed_fixture()
    stage = next(item for item in proof.stages if item.stage == "VENUE_QUALITY")
    changed_body = b"substituted venue DTO"
    changed = _with_stage(
        proof,
        stage.receipt_id,
        content_base64=base64.b64encode(changed_body).decode("ascii"),
        content_sha256=hashlib.sha256(changed_body).hexdigest(),
    )
    with pytest.raises(ValueError, match="native stage bytes do not equal signed VENUE_QUALITY DTO"):
        _verify(verifier, changed, review, venue, scope, decided_ms)


def test_malformed_base64_fails_after_signature_verification():
    verifier, proof, _context, review, venue, scope, decided_ms = _signed_fixture()
    source = next(stage for stage in proof.stages if stage.stage == "TEXT_SOURCE")
    malformed = _with_stage(proof, source.receipt_id, content_base64="%%%not-base64%%")
    with pytest.raises(ValueError, match="not valid base64"):
        _verify(verifier, malformed, review, venue, scope, decided_ms)


def test_per_receipt_body_limit_is_checked_before_signature_or_full_validation():
    verifier, proof, _context, review, venue, scope, decided_ms = _signed_fixture()
    source = next(stage for stage in proof.stages if stage.stage == "TEXT_SOURCE")
    oversized = _with_stage(proof, source.receipt_id, content_base64="A" * 1_333_335)
    with pytest.raises(ValueError, match="per-receipt encoded bound"):
        _verify(verifier, oversized, review, venue, scope, decided_ms)


def test_aggregate_body_limit_is_checked_before_full_envelope_validation():
    verifier, proof, _context, review, venue, scope, decided_ms = _signed_fixture()
    oversized = []
    for index, stage in enumerate(proof.stages):
        if index < 5:
            stage = stage.model_copy(update={"content_base64": "A" * 1_200_000})
        oversized.append(stage)
    too_large = proof.model_copy(update={"stages": tuple(oversized)})
    with pytest.raises(ValueError, match="aggregate encoded bound"):
        _verify(verifier, too_large, review, venue, scope, decided_ms)


def test_context_source_timestamps_are_preserved_without_retiming():
    verifier, proof, context, review, venue, scope, decided_ms = _signed_fixture()
    text_source = next(source for source in context.sources if source.kind == "text")
    receipt = text_source.receipts[0]
    assert context.captured_at_ms == 1_800_000_060_050
    assert receipt.event_at_ms == 1_800_000_059_990
    assert receipt.received_at_ms == 1_800_000_060_025
    assert proof.context == context
    assert _verify(verifier, proof, review, venue, scope, decided_ms).observed_at_ms == proof.observed_at_ms


def _with_text_model_calls(proof, *, output_digest=None, duplicate_prompt=False, call_count=1):
    text_stage = next(stage for stage in proof.stages if stage.stage == "TEXT_AGGREGATE")
    output_digest = output_digest or text_stage.content_sha256
    model_stages = []
    for index in range(call_count):
        call_id = f"text-call-{index}"
        request_id = f"text-request-{index}"
        model_stages.extend(
            [
                _model_artifact(
                    "MODEL_PROMPT",
                    receipt_id=f"fixture-prompt-{index}",
                    call_id=call_id,
                    request_id=request_id,
                    output_sha256=output_digest,
                ),
                _model_artifact(
                    "MODEL_RESPONSE",
                    receipt_id=f"fixture-response-{index}",
                    call_id=call_id,
                    request_id=request_id,
                    output_sha256=output_digest,
                ),
            ]
        )
    if duplicate_prompt:
        duplicate = model_stages[0].model_copy(update={"receipt_id": "fixture-duplicate-prompt"})
        model_stages.append(duplicate)
    stages = tuple(
        stage.model_copy(update={"output_origin": "NATIVE_MODEL"})
        if stage.stage == "TEXT_AGGREGATE"
        else stage
        for stage in proof.stages
    )
    return _resign(proof.model_copy(update={"stages": stages + tuple(model_stages)}))


def test_multiple_model_calls_are_distinctly_bound_to_native_text_output():
    verifier, proof, _context, review, venue, scope, decided_ms = _signed_fixture()
    with_two_calls = _with_text_model_calls(proof, call_count=2)
    _verify(verifier, with_two_calls, review, venue, scope, decided_ms)


def test_duplicate_model_artifact_for_same_workload_call_is_rejected():
    verifier, proof, _context, review, venue, scope, decided_ms = _signed_fixture()
    duplicated = _with_text_model_calls(proof, duplicate_prompt=True)
    with pytest.raises(ValueError, match="duplicate model artifact"):
        _verify(verifier, duplicated, review, venue, scope, decided_ms)


def test_model_call_bound_to_another_output_is_rejected():
    verifier, proof, _context, review, venue, scope, decided_ms = _signed_fixture()
    wrong_output = _with_text_model_calls(proof, output_digest="f" * 64)
    with pytest.raises(ValueError, match="complete model calls bound to its output"):
        _verify(verifier, wrong_output, review, venue, scope, decided_ms)


def test_native_model_output_without_model_call_is_rejected():
    verifier, proof, _context, review, venue, scope, decided_ms = _signed_fixture()
    text_stage = next(stage for stage in proof.stages if stage.stage == "TEXT_AGGREGATE")
    model_output_without_call = _resign(
        proof.model_copy(
            update={
                "stages": tuple(
                    stage.model_copy(update={"output_origin": "NATIVE_MODEL"})
                    if stage.receipt_id == text_stage.receipt_id
                    else stage
                    for stage in proof.stages
                )
            }
        )
    )
    with pytest.raises(ValueError, match="requires complete model calls"):
        _verify(verifier, model_output_without_call, review, venue, scope, decided_ms)


def test_deterministic_fallback_cannot_claim_model_call_artifacts():
    verifier, proof, _context, review, venue, scope, decided_ms = _signed_fixture()
    model_proof = _with_text_model_calls(proof)
    fallback_with_model_artifact = _resign(
        model_proof.model_copy(
            update={
                "stages": tuple(
                    stage.model_copy(update={"output_origin": "NATIVE_DETERMINISTIC_FALLBACK"})
                    if stage.stage == "TEXT_AGGREGATE"
                    else stage
                    for stage in model_proof.stages
                )
            }
        )
    )
    with pytest.raises(ValueError, match="fallback cannot claim model-call artifacts"):
        _verify(verifier, fallback_with_model_artifact, review, venue, scope, decided_ms)


def _with_native_review_model_call(proof, review):
    prompt = b"synthetic native review prompt"
    response = b"synthetic native review response"
    provenance = ModelProvenanceV1(
        provider="synthetic-provider",
        model="synthetic-model",
        reasoning_effort="medium",
        request_id="review-request-1",
        prompt_sha256=hashlib.sha256(prompt).hexdigest(),
        response_sha256=hashlib.sha256(response).hexdigest(),
        budget_reservation_id="review-reservation-1",
        latency_ms=20,
        cost_usd=0.0,
    )
    review_data = review.model_dump(mode="python")
    review_data.update(reviewer="LLM", model_provenance=provenance, review_id=None)
    llm_review = CandidateReviewV1.model_validate(review_data)
    prompt_stage = LiveInputStageReceiptV1(
        stage="MODEL_PROMPT",
        receipt_id="fixture-review-prompt",
        workload_id="CANDIDATE_REVIEW",
        call_id="review-call-1",
        provider=provenance.provider,
        model=provenance.model,
        reasoning_effort=provenance.reasoning_effort,
        request_id=provenance.request_id,
        budget_reservation_id=provenance.budget_reservation_id,
        status="CAPTURED",
        source_timestamp_ms=1_800_000_060_049,
        captured_at_ms=1_800_000_060_050,
        content_sha256=hashlib.sha256(prompt).hexdigest(),
        content_base64=base64.b64encode(prompt).decode("ascii"),
    )
    response_stage = prompt_stage.model_copy(
        update={
            "stage": "MODEL_RESPONSE",
            "receipt_id": "fixture-review-response",
            "content_sha256": hashlib.sha256(response).hexdigest(),
            "content_base64": base64.b64encode(response).decode("ascii"),
        }
    )
    changed_stages = []
    for stage in proof.stages:
        if stage.stage == "REVIEW_OUTPUT":
            body = canonical_json_bytes(llm_review)
            stage = stage.model_copy(
                update={
                    "content_base64": base64.b64encode(body).decode("ascii"),
                    "content_sha256": hashlib.sha256(body).hexdigest(),
                }
            )
        changed_stages.append(stage)
    signed = _resign(
        proof.model_copy(
            update={"review": llm_review, "stages": tuple(changed_stages) + (prompt_stage, response_stage)}
        )
    )
    return signed, llm_review, response_stage


def test_review_model_provenance_joins_exact_signed_prompt_response_pair():
    verifier, proof, _context, review, venue, scope, decided_ms = _signed_fixture()
    proof, llm_review, _response_stage = _with_native_review_model_call(proof, review)
    _verify(verifier, proof, llm_review, venue, scope, decided_ms)


def test_review_model_response_substitution_fails_native_provenance_join():
    verifier, proof, _context, review, venue, scope, decided_ms = _signed_fixture()
    proof, llm_review, response_stage = _with_native_review_model_call(proof, review)
    wrong_body = b"substituted signed model response"
    changed = _with_stage(
        proof,
        response_stage.receipt_id,
        content_base64=base64.b64encode(wrong_body).decode("ascii"),
        content_sha256=hashlib.sha256(wrong_body).hexdigest(),
    )
    with pytest.raises(ValueError, match="one exact prompt/response call pair"):
        _verify(verifier, changed, llm_review, venue, scope, decided_ms)
