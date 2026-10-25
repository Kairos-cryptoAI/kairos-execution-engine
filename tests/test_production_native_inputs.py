"""Synthetic offline boundary tests, never producer/venue qualification."""

from __future__ import annotations

import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from kairos_core.contracts import CandidateReviewV1, EvidenceReferenceV1, canonical_json_bytes

from kairos_execution.production_native_inputs import (
    NativeCallRecordPair,
    native_call_receipts,
    native_input_signing_bytes,
    prepare_native_input_envelope,
    read_native_budgeted_call,
    verify_native_call_receipts,
    verify_signed_native_input_envelope,
)
from tests.test_production_inputs import TEST_SEED, _envelope, _signed_fixture, _verify


def _encoded(raw):
    return {"base64": base64.b64encode(raw).decode("ascii"), "sha256": hashlib.sha256(raw).hexdigest()}


def _records(
    *,
    workload="text_scouts",
    call_id="1" * 32,
    reservation="synthetic-reservation",
    request_id="synthetic-request",
    cached=False,
):
    # Exact d91566b native call_evidence wire schema. These bytes are synthetic,
    # not a provider call or proof of a persisted budget transaction.
    attempt = canonical_json_bytes(
        {
            "version": "kairos.llm-application-call-evidence.v1",
            "capture_scope": "application-boundary-not-provider-http",
            "phase": "ATTEMPT_STARTED",
            "call_id": call_id,
            "workload": workload,
            "effort": "medium",
            "request": {
                "system_utf8": _encoded("Synthetic system Я".encode()),
                "user_utf8": _encoded(b'{"synthetic":"untrusted text"}'),
                "schema_canonical_json_utf8": _encoded(b'{"type":"object"}'),
            },
            "provider_call": {"provider": "openai", "model": "synthetic-alias", "attempt_started_at_ms": 100},
            "budget": {"reservation_id": reservation, "status": "RESERVED", "reserved_microusd": 100},
        }
    )
    completion = canonical_json_bytes(
        {
            "version": "kairos.llm-application-call-evidence.v1",
            "capture_scope": "application-boundary-not-provider-http",
            "phase": "COMPLETED",
            "call_id": call_id,
            "attempt_record_sha256": hashlib.sha256(attempt).hexdigest(),
            "response": {"content_utf8": _encoded(b'{"synthetic":true}')},
            "token_usage": {
                "input_tokens": 20,
                "output_tokens": 5,
                "cached_input_tokens": 10,
                "cache_write_tokens": 0,
            },
            "provider_call": {
                "provider": "openai",
                "model": "synthetic-alias",
                "resolved_model": "synthetic-resolved",
                "request_id": request_id,
                "cached": cached,
                "cache_scope": "PROVIDER_INPUT_TOKENS_NOT_RESPONSE_REUSE",
                "attempt_started_at_ms": 100,
                "response_observed_at_ms": 200,
            },
            "budget": {
                "reservation_id": reservation,
                "status": "COMMITTED",
                "reserved_microusd": 100,
                "actual_microusd": 40,
                "commit_observed_at_ms": 210,
            },
        }
    )
    return attempt, completion


def _changed(raw, path, value):
    payload = json.loads(raw)
    target = payload
    for name in path[:-1]:
        target = target[name]
    target[path[-1]] = value
    return canonical_json_bytes(payload)


def test_native_records_keep_exact_unicode_prompt_reply_schema_budget_and_original_clocks():
    attempt, completion = _records(cached=True)
    call = read_native_budgeted_call(attempt, completion)
    assert call.attempt_record is attempt
    assert call.completion_record is completion
    assert call.prompt == canonical_json_bytes(
        {
            "system": "Synthetic system Я",
            "user": '{"synthetic":"untrusted text"}',
        }
    )
    assert call.response == b'{"synthetic":true}'
    assert call.model == "synthetic-resolved"
    assert (call.started_at_ms, call.response_at_ms, call.committed_at_ms) == (100, 200, 210)
    assert (call.reserved_microusd, call.actual_microusd) == (100, 40)
    receipts = native_call_receipts(
        attempt_record=attempt, completion_record=completion, captured_at_ms=220, bound_output_sha256="a" * 64
    )
    assert len(receipts) == 4
    verify_native_call_receipts(receipts)
    assert [item.source_timestamp_ms for item in receipts] == [100, 200, 100, 210]


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("call_id",), "2" * 32),
        (("attempt_record_sha256",), "b" * 64),
        (("provider_call", "provider"), "unknown"),
        (("provider_call", "attempt_started_at_ms"), True),
        (("provider_call", "response_observed_at_ms"), 99),
        (("provider_call", "cached"), 1),
        (("provider_call", "cache_scope"), "WHOLE_RESPONSE_CACHE"),
        (("budget", "status"), "RESERVED"),
        (("budget", "reservation_id"), "foreign-reservation"),
        (("budget", "actual_microusd"), 101),
        (("budget", "reserved_microusd"), True),
        (("budget", "commit_observed_at_ms"), 199),
        (("response", "content_utf8", "sha256"), "c" * 64),
        (("token_usage", "cached_input_tokens"), 21),
    ],
)
def test_native_record_substitution_and_unknown_budget_outcomes_refuse(path, value):
    attempt, completion = _records()
    with pytest.raises(ValueError):
        read_native_budgeted_call(attempt, _changed(completion, path, value))


def test_missing_started_unknown_workload_noncanonical_duplicate_and_oversize_refuse():
    attempt, completion = _records()
    for invalid in (b"", attempt + b" ", b'{"phase":1,"phase":2}', b" " * 1_000_001):
        with pytest.raises(ValueError):
            read_native_budgeted_call(invalid, completion)
    attempt, completion = _records(workload="simulated_chain")
    with pytest.raises(ValueError, match="unknown native workload"):
        read_native_budgeted_call(attempt, completion)


def test_native_artifact_rewrite_duplicate_identity_or_premature_capture_refuses():
    attempt, completion = _records()
    with pytest.raises(ValueError, match="predates"):
        native_call_receipts(
            attempt_record=attempt,
            completion_record=completion,
            captured_at_ms=209,
            bound_output_sha256="a" * 64,
        )
    receipts = native_call_receipts(
        attempt_record=attempt, completion_record=completion, captured_at_ms=220, bound_output_sha256="a" * 64
    )
    with pytest.raises(ValueError, match="all four"):
        verify_native_call_receipts(receipts[:-1])
    tampered = (receipts[0].model_copy(update={"request_id": "foreign"}), *receipts[1:])
    with pytest.raises(ValueError, match="differ from original"):
        verify_native_call_receipts(tampered)
    attempt2, completion2 = _records(call_id="2" * 32, request_id="different")
    second = native_call_receipts(
        attempt_record=attempt2,
        completion_record=completion2,
        captured_at_ms=220,
        bound_output_sha256="a" * 64,
    )
    with pytest.raises(ValueError, match="reused"):
        verify_native_call_receipts((*receipts, *second))


def test_unsigned_native_composition_requires_external_signature_and_preserves_source_clocks():
    verifier, proof, _context, review, venue, scope, now = _signed_fixture()
    payload = proof.model_dump(mode="json")
    text = next(stage for stage in payload["stages"] if stage["stage"] == "TEXT_AGGREGATE")
    text["output_origin"] = "NATIVE_MODEL"
    attempt, completion = _records()
    prepared = prepare_native_input_envelope(
        retained_manifest=canonical_json_bytes(payload),
        calls=(NativeCallRecordPair(attempt, completion, text["content_sha256"], proof.observed_at_ms),),
    )
    assert prepared.observed_at_ms == proof.observed_at_ms
    assert prepared.context == proof.context
    assert prepared.stages[0] == proof.stages[0]
    with pytest.raises(ValueError, match="signature"):
        _verify(verifier, prepared, review, venue, scope, now)
    signature = Ed25519PrivateKey.from_private_bytes(TEST_SEED).sign(native_input_signing_bytes(prepared))
    signed = verify_signed_native_input_envelope(
        prepared=prepared,
        signature=signature,
        verifier=verifier,
        scope=scope,
        decided_at_ms=now,
    )
    assert _verify(verifier, signed, review, venue, scope, now).source_id == "synthetic-source"
    with pytest.raises(ValueError, match="replace or renew"):
        prepare_native_input_envelope(retained_manifest=canonical_json_bytes(signed), calls=())


def test_model_output_cannot_be_prepared_without_original_call_record_or_with_future_capture():
    _verifier, proof, *_rest = _signed_fixture()
    payload = proof.model_dump(mode="json")
    text = next(stage for stage in payload["stages"] if stage["stage"] == "TEXT_AGGREGATE")
    text["output_origin"] = "NATIVE_MODEL"
    with pytest.raises(ValueError, match="complete model calls"):
        prepare_native_input_envelope(retained_manifest=canonical_json_bytes(payload), calls=())
    attempt, completion = _records()
    with pytest.raises(ValueError, match="later than"):
        prepare_native_input_envelope(
            retained_manifest=canonical_json_bytes(payload),
            calls=(
                NativeCallRecordPair(
                    attempt,
                    completion,
                    text["content_sha256"],
                    proof.observed_at_ms + 1,
                ),
            ),
        )


def test_actual_native_context_plus_sentiment_review_references_are_not_legacy_context_only():
    verifier, _proof, context, review, venue, scope, now = _signed_fixture()
    text = next(source for source in context.sources if source.kind == "text")
    receipt = text.receipts[0]
    native_ref = EvidenceReferenceV1(
        kind="sentiment",
        reference=receipt.message_id,
        content_sha256=receipt.content_sha256,
        observed_at_ms=receipt.produced_at_ms,
    )
    data = review.model_dump(mode="python")
    data.update(evidence=(*context.evidence_references(), native_ref), review_id=None)
    native_review = CandidateReviewV1.model_validate(data)
    proof = _envelope(native_review, context, venue, None, scope, now)
    assert _verify(verifier, proof, native_review, venue, scope, now).review_sha256
    data.update(
        evidence=(
            *context.evidence_references(),
            native_ref.model_copy(
                update={
                    "reference": "foreign-sentiment",
                }
            ),
        ),
        review_id=None,
    )
    foreign = CandidateReviewV1.model_validate(data)
    with pytest.raises(ValueError, match="exact native DecisionContext"):
        _envelope(foreign, context, venue, None, scope, now)
