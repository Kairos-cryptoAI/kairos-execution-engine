"""Offline native instrument HTTP capture -> signed verifier -> actual Risk."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from decimal import Decimal

import pytest
from kairos_core.contracts import (
    CandidateReviewV1,
    DecisionContextReceiptV1,
    DecisionContextSourceV1,
    DecisionContextV1,
    canonical_json_bytes,
    canonical_sha256,
)
from kairos_core.enums import SystemMode
from kairos_core.topics import Topics
from kairos_risk.live import LiveRiskEvaluator

from kairos_execution.production_input_risk import build_opt_in_production_live_risk_evaluator
from kairos_execution.production_inputs import LiveInputStageReceiptV1
from tests.test_production_input_risk import _public_key
from tests.test_production_inputs import (
    _envelope,
    _native_context_and_review,
    _resign,
    _signed_fixture,
    _verifier,
    _verify,
)
from tests.test_production_risk import SOURCE, _inputs


def _iso(ms):
    return datetime.fromtimestamp(ms / 1_000, tz=UTC).isoformat(timespec="milliseconds")


def _instrument(**overrides):
    value = {
        "name": "BTCUSD",
        "trading": "all",
        "visibility": "all",
        "marketState": "OPEN",
        "updatedAt": "2020-01-01T00:00:00.000Z",
        "priceIncrement": "0.01",
        "quantityIncrement": "0.1",
        "minPrice": "1",
        "maxPrice": "1000000",
        "minQuantity": "0.1",
        "maxQuantity": "1000",
        "minVolume": "5",
        "lotSize": "1",
        "multiplier": "1",
    }
    value.update(overrides)
    return value


def _capture(decided_ms, *, body=None, **updates):
    body = body if body is not None else json.dumps([_instrument()]).encode()
    capture = {
        "source": "instruments",
        "path": "/api/market/instrument",
        "query_json": '{"fields":"metrics"}',
        "status": 200,
        "requested_at": _iso(decided_ms - 200),
        "received_at": _iso(decided_ms - 150),
        "body_bytes": len(body),
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "body_base64": base64.b64encode(body).decode("ascii"),
    }
    capture.update(updates)
    return capture


def _with_instrument(proof, decided_ms, *, capture=None, raw=None, **stage_updates):
    raw = raw if raw is not None else canonical_json_bytes(capture or _capture(decided_ms))
    receipt = LiveInputStageReceiptV1(
        stage="EVEDEX_INSTRUMENT",
        receipt_id="fixture-evedex-instrument",
        source_name="instruments",
        status="CAPTURED",
        source_timestamp_ms=decided_ms - 150,
        requested_at_ms=decided_ms - 200,
        received_at_ms=decided_ms - 150,
        persisted_at_ms=decided_ms - 125,
        captured_at_ms=decided_ms - 110,
        content_sha256=hashlib.sha256(raw).hexdigest(),
        content_base64=base64.b64encode(raw).decode("ascii"),
    ).model_copy(update=stage_updates)
    return _resign(proof.model_copy(update={"stages": (*proof.stages, receipt)}))


def test_signed_native_http_capture_derives_exact_rules_without_retiming_old_rule_change():
    verifier, proof, _context, review, venue, scope, decided_ms = _signed_fixture()
    native = _with_instrument(proof, decided_ms)
    verified = _verify(verifier, native, review, venue, scope, decided_ms)
    rules = verified.instrument_rules
    assert rules is not None
    assert rules.source_id == verified.source_id == native.source_id
    assert rules.scope_sha256 == verified.scope_sha256 == scope.scope_sha256
    assert rules.evidence_sha256 == verified.evidence_sha256
    assert rules.venue_symbol == venue.symbol
    assert rules.observed_at_ms == decided_ms - 150 < verified.observed_at_ms
    assert rules.rules_updated_at_ms == 1_577_836_800_000
    assert rules.quantity_increment == Decimal("0.1")
    assert rules.price_increment == Decimal("0.01")
    assert rules.min_price == Decimal("1") and rules.max_price == Decimal("1000000")
    assert rules.min_quantity == Decimal("0.1") and rules.max_quantity == Decimal("1000")
    assert rules.min_notional_usd == Decimal("5")
    assert rules.lot_size == rules.multiplier == Decimal("1")
    assert rules.max_notional_usd is None


def test_native_json_numeric_rule_precision_is_lossless():
    verifier, proof, _context, review, venue, scope, decided_ms = _signed_fixture()
    body = json.dumps([_instrument(quantityIncrement="0.1234567890123456789")]).encode()
    body = body.replace(b'"0.1234567890123456789"', b"0.1234567890123456789")
    native = _with_instrument(proof, decided_ms, capture=_capture(decided_ms, body=body))
    verified = _verify(verifier, native, review, venue, scope, decided_ms)
    assert verified.instrument_rules.quantity_increment == Decimal("0.1234567890123456789")


def test_unknown_max_volume_field_never_creates_an_inferred_notional_ceiling():
    verifier, proof, _context, review, venue, scope, decided_ms = _signed_fixture()
    body = json.dumps([_instrument(maxVolume="not-a-documented-notional-rule")]).encode()
    native = _with_instrument(proof, decided_ms, capture=_capture(decided_ms, body=body))
    assert (
        _verify(verifier, native, review, venue, scope, decided_ms).instrument_rules.max_notional_usd is None
    )


@pytest.mark.parametrize(
    "updates",
    [
        {"source": "positions"},
        {"path": "/api/market/other"},
        {"query_json": "{}"},
        {"query_json": '{"fields":"metrics","fields":"metrics"}'},
        {"status": 503},
        {"status": True},
        {"body_sha256": "f" * 64},
        {"body_bytes": 1},
        {"body_base64": "not-base64!"},
        {"received_at": "2020-01-01T00:00:00Z"},
        {"requested_at": "2020-01-01T00:00:00Z"},
    ],
)
def test_signed_bad_original_http_metadata_cannot_become_verified_rules(updates):
    verifier, proof, _context, review, venue, scope, decided_ms = _signed_fixture()
    native = _with_instrument(proof, decided_ms, capture=_capture(decided_ms, **updates))
    with pytest.raises((ValueError, RuntimeError)):
        _verify(verifier, native, review, venue, scope, decided_ms)


@pytest.mark.parametrize(
    "updates",
    [
        {"source_name": "caller-verified-rules"},
        {"source_timestamp_ms": 1_800_000_000_000},
        {"requested_at_ms": 1_800_000_000_000},
        {"received_at_ms": 1_800_000_000_000},
        {"persisted_at_ms": 1_800_000_000_000},
    ],
)
def test_original_request_receive_persist_chain_cannot_be_relabelled(updates):
    verifier, proof, _context, review, venue, scope, decided_ms = _signed_fixture()
    native = _with_instrument(proof, decided_ms, **updates)
    with pytest.raises(ValueError):
        _verify(verifier, native, review, venue, scope, decided_ms)


@pytest.mark.parametrize(
    "updates",
    [
        {"name": "ETHUSD"},
        {"name": "btcusd"},
        {"trading": "disabled"},
        {"visibility": "none"},
        {"marketState": "CLOSED"},
        {"updatedAt": "2099-01-01T00:00:00Z"},
        {"quantityIncrement": True},
        {"quantityIncrement": "NaN"},
        {"priceIncrement": "0"},
        {"lotSize": "2"},
        {"multiplier": "2"},
        {"minQuantity": "1001"},
        {"minVolume": None},
    ],
)
def test_signed_native_instrument_must_be_exact_tradeable_and_supported(updates):
    verifier, proof, _context, review, venue, scope, decided_ms = _signed_fixture()
    body = json.dumps([_instrument(**updates)]).encode()
    native = _with_instrument(proof, decided_ms, capture=_capture(decided_ms, body=body))
    with pytest.raises(ValueError):
        _verify(verifier, native, review, venue, scope, decided_ms)


@pytest.mark.parametrize(
    "body",
    [
        b"[]",
        json.dumps([_instrument(), _instrument()]).encode(),
        b'{"quantity_increment":"0.1","verified":true}',
        b'[{"name":"BTCUSD","name":"BTCUSD"}]',
        b"[null]",
    ],
)
def test_duplicate_missing_or_normalized_caller_metadata_is_rejected(body):
    verifier, proof, _context, review, venue, scope, decided_ms = _signed_fixture()
    native = _with_instrument(proof, decided_ms, capture=_capture(decided_ms, body=body))
    with pytest.raises((ValueError, RuntimeError)):
        _verify(verifier, native, review, venue, scope, decided_ms)


def test_duplicate_outer_http_wrapper_keys_are_not_silently_collapsed():
    verifier, proof, _context, review, venue, scope, decided_ms = _signed_fixture()
    native = _with_instrument(proof, decided_ms, raw=b'{"source":"instruments","source":"instruments"}')
    with pytest.raises(ValueError, match="duplicate raw HTTP capture"):
        _verify(verifier, native, review, venue, scope, decided_ms)


def test_fresh_signed_wrapper_cannot_refresh_old_original_instrument_capture():
    verifier, proof, _context, review, venue, scope, decided_ms = _signed_fixture()
    old = decided_ms - 5_001
    capture = _capture(decided_ms, requested_at=_iso(old - 10), received_at=_iso(old))
    native = _with_instrument(
        proof,
        decided_ms,
        capture=capture,
        requested_at_ms=old - 10,
        received_at_ms=old,
        source_timestamp_ms=old,
    )
    with pytest.raises(ValueError, match="original HTTP clocks"):
        _verify(verifier, native, review, venue, scope, decided_ms)


def test_optional_stage_is_singleton_and_cannot_be_unavailable_when_present():
    verifier, proof, _context, review, venue, scope, decided_ms = _signed_fixture()
    native = _with_instrument(proof, decided_ms)
    duplicate = native.stages[-1].model_copy(update={"receipt_id": "other-instrument"})
    duplicated = _resign(native.model_copy(update={"stages": (*native.stages, duplicate)}))
    with pytest.raises(ValueError, match="at most one"):
        _verify(verifier, duplicated, review, venue, scope, decided_ms)
    unavailable = LiveInputStageReceiptV1(
        stage="EVEDEX_INSTRUMENT",
        receipt_id="unavailable-instrument",
        source_name="instruments",
        status="UNAVAILABLE",
        reason_code="SOURCE_UNAVAILABLE",
        captured_at_ms=decided_ms - 110,
    )
    missing = _resign(proof.model_copy(update={"stages": (*proof.stages, unavailable)}))
    with pytest.raises(ValueError, match="present instrument stage"):
        _verify(verifier, missing, review, venue, scope, decided_ms)


def test_http_body_tampering_without_new_envelope_signature_fails_authentication():
    verifier, proof, _context, review, venue, scope, decided_ms = _signed_fixture()
    native = _with_instrument(proof, decided_ms)
    changed = _with_instrument(proof, decided_ms, capture=_capture(decided_ms, status=201))
    tampered = native.model_copy(update={"stages": changed.stages})
    with pytest.raises(ValueError, match="signature"):
        _verify(verifier, tampered, review, venue, scope, decided_ms)


def test_old_signed_manifests_stay_verifier_compatible_but_production_requires_rules():
    verifier, proof, _context, review, venue, scope, decided_ms = _signed_fixture()
    assert _verify(verifier, proof, review, venue, scope, decided_ms).instrument_rules is None
    *_, publisher, _production_context, _scope = _inputs()
    evaluator = build_opt_in_production_live_risk_evaluator(
        scope=scope,
        limits=publisher.evaluator.limits,
        producer_trust=verifier.trust,
        producer_public_key=_public_key(),
    )
    result = evaluator.evaluate(
        object(),
        source_id="not-registered",
        review=review,
        venue=venue,
        allocation=None,
        decided_at_ms=decided_ms,
        raw_inputs_evidence=proof,
    )
    assert not result.decision.approved
    assert "instrument_rules_missing" in result.decision.rejection_reasons


def test_raw_signed_instrument_rules_join_real_risk_exact_step_sizing():
    _review, venue, allocation, account_verifier, _writer, _binding, publisher, _context, scope = _inputs()
    context, review = _native_context_and_review(scope, venue)
    produced_ms = int(allocation.produced_at.timestamp() * 1_000)
    macro = DecisionContextSourceV1(
        kind="macro",
        availability="AVAILABLE",
        receipts=(
            DecisionContextReceiptV1(
                message_id=allocation.message_id,
                source=allocation.source,
                topic=Topics.STRATEGIC_ALLOCATION,
                content_sha256=canonical_sha256(allocation),
                event_at_ms=produced_ms,
                produced_at_ms=produced_ms,
                received_at_ms=context.knowledge_cutoff_ms,
                ttl_ms=26 * 60 * 60 * 1_000,
            ),
        ),
        payloads_json=canonical_json_bytes({"items": [allocation.model_dump(mode="json")]}).decode(),
    )
    context = DecisionContextV1.model_validate(
        context.model_copy(
            update={
                "sources": tuple(macro if source.kind == "macro" else source for source in context.sources),
                "context_id": None,
            }
        ).model_dump(mode="json")
    )
    review = CandidateReviewV1.model_validate(
        review.model_copy(
            update={
                "evidence": context.evidence_references(),
                "review_id": None,
            }
        ).model_dump(mode="json")
    )
    decided_ms = venue.observed_at_ms + 100
    proof = _envelope(review, context, venue, allocation, scope, decided_ms)
    native = _with_instrument(proof, decided_ms)
    evaluator = LiveRiskEvaluator(
        scope,
        publisher.evaluator.limits,
        account_verifiers={SOURCE: account_verifier},
        input_verifier=_verifier(scope),
        require_instrument_rules=True,
    )
    result = evaluator.evaluate(
        "synthetic-proof",
        source_id=SOURCE,
        review=review,
        venue=venue,
        allocation=allocation,
        decided_at_ms=decided_ms,
        system_mode=SystemMode.NORMAL,
        raw_inputs_evidence=native,
    )
    assert result.decision.approved, result.decision.rejection_reasons
    baseline = (
        LiveRiskEvaluator(
            scope,
            publisher.evaluator.limits,
            account_verifiers={SOURCE: account_verifier},
            input_verifier=_verifier(scope),
        )
        .evaluate(
            "synthetic-proof",
            source_id=SOURCE,
            review=review,
            venue=venue,
            allocation=allocation,
            decided_at_ms=decided_ms,
            system_mode=SystemMode.NORMAL,
            raw_inputs_evidence=proof,
        )
        .decision
    )
    assert baseline.approved
    expected_lots = Decimal(str(baseline.quantity)) // Decimal("0.1")
    assert Decimal(str(result.decision.quantity)) == expected_lots * Decimal("0.1")
    assert result.instrument_rules.observed_at_ms == decided_ms - 150
    assert Decimal(str(result.decision.quantity)) % Decimal("0.1") == 0
    assert result.decision.worst_case_loss_usd <= result.decision.loss_budget_usd <= 25
    assert result.decision.notional_usd <= 1_000
    assert result.decision.intent == review.intent
