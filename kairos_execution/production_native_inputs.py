"""Native application-call evidence adapter, not a qualified capture producer.

Consumes original create-only ``kairos_llm.call_evidence`` records. It never
reconstructs a call from a DTO, invokes a model, reads a key, or supplies source
truth. Source-body retention and independent producer acceptance remain mandatory
deployment prerequisites. The caller's output binding is a capture-process
statement, not proof that the model output was correctly transformed.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import inspect
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal, Protocol, cast

from kairos_core.contracts import canonical_json_bytes, canonical_sha256
from kairos_core.enums import SystemMode
from kairos_risk.live import LiveRiskScopeV1  # type: ignore[import-untyped]

from .production_inputs import (
    _DOMAIN,
    LiveInputsSourceVerifier,
    LiveInputStageReceiptV1,
    SignedLiveInputsEnvelopeV1,
)

_VERSION = "kairos.llm-application-call-evidence.v1"
_CAPTURE_SCOPE = "application-boundary-not-provider-http"
_MAX_RECORD_BYTES = 1_000_000  # Existing signed envelope's per-receipt bound.
_WorkloadId = Literal["TEXT_AGGREGATION", "MACRO_ALLOCATION", "CANDIDATE_REVIEW"]
_ModelStage = Literal["MODEL_PROMPT", "MODEL_RESPONSE", "MODEL_ATTEMPT_RECORD", "MODEL_COMPLETION_RECORD"]
_WORKLOADS: dict[str, _WorkloadId] = {
    "text_scouts": "TEXT_AGGREGATION",
    "macro_strategist": "MACRO_ALLOCATION",
    "aggregator_normal": "CANDIDATE_REVIEW",
    "aggregator_conflict": "CANDIDATE_REVIEW",
}
_MODEL_STAGES = frozenset(
    {
        "MODEL_PROMPT",
        "MODEL_RESPONSE",
        "MODEL_ATTEMPT_RECORD",
        "MODEL_COMPLETION_RECORD",
    }
)


class _NativeSessionSink(Protocol):
    def create_only(self, observation_id: str, record: bytes) -> None: ...


class NativeLLMCallSinkAdapter:
    """Retain original three-argument gateway writes in the native session.

    The deterministic ID is only a create-only transport key, never a new call,
    reservation, receipt time or authority. Unknown writes remain fenced by the
    original gateway's durable budget reservation.
    """

    def __init__(self, sink: _NativeSessionSink) -> None:
        if not callable(getattr(sink, "create_only", None)):
            raise TypeError("an explicit create-only native session sink is required")
        self.sink = sink

    def create_only(self, call_id: str, phase: str, record: bytes) -> None:
        payload = _json(record)
        if (
            phase not in {"started", "completed"}
            or not re.fullmatch(r"[a-f0-9]{32}", call_id)
            or payload.get("call_id") != call_id
            or payload.get("version") != _VERSION
            or payload.get("phase") != {"started": "ATTEMPT_STARTED", "completed": "COMPLETED"}[phase]
        ):
            raise ValueError("native gateway write has foreign call/phase identity")
        observation_id = hashlib.sha256(f"llm:{call_id}:{phase}".encode()).hexdigest()[:32]
        writer = cast(Callable[..., object], self.sink.create_only)
        acknowledgement = writer(observation_id, record)
        if inspect.iscoroutine(acknowledgement):
            acknowledgement.close()
        if acknowledgement is not None:
            raise ValueError("native session must synchronously acknowledge original gateway records")


def _json(raw: bytes, *, max_bytes: int = _MAX_RECORD_BYTES) -> dict:
    if not isinstance(raw, bytes) or not raw or len(raw) > max_bytes:
        raise ValueError("original bounded native application-call record bytes are required")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("native call evidence has duplicate fields")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: None)
        if not isinstance(value, dict) or canonical_json_bytes(value) != raw:
            raise ValueError("native call record is not exact canonical JSON")
        return value
    except (UnicodeError, json.JSONDecodeError, TypeError) as exc:
        raise ValueError("native call record is not valid bounded JSON") from exc


def _fields(value: object, names: set[str]) -> dict:
    if not isinstance(value, dict) or set(value) != names:
        raise ValueError("native call record has missing or unknown fields")
    return value


def _identifier(value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > 256:
        raise ValueError("native call identity is absent or not normalized")
    return value


def _integer(value: object) -> int:
    if type(value) is not int or value < 0:
        raise ValueError("native budget and clock fields require exact non-negative integers")
    return value


def _decode(value: object, *, utf8: bool = True) -> bytes:
    encoded = _fields(value, {"sha256", "base64"})
    try:
        raw = base64.b64decode(encoded["base64"], validate=True)
        if utf8:
            raw.decode("utf-8", errors="strict")
    except (binascii.Error, ValueError, TypeError, UnicodeError) as exc:
        raise ValueError("native call content is not exact UTF-8/base64") from exc
    if hashlib.sha256(raw).hexdigest() != encoded["sha256"]:
        raise ValueError("native call content digest mismatch")
    return raw


@dataclass(frozen=True, slots=True)
class NativeBudgetedCall:
    """Validated original records and exact legacy prompt/reply representations."""

    call_id: str
    workload_id: _WorkloadId
    native_workload: str
    provider: str
    model: str
    reasoning_effort: str
    request_id: str
    reservation_id: str
    started_at_ms: int
    response_at_ms: int
    committed_at_ms: int
    reserved_microusd: int
    actual_microusd: int
    attempt_record: bytes
    completion_record: bytes
    prompt: bytes
    response: bytes


def read_native_budgeted_call(attempt_record: bytes, completion_record: bytes) -> NativeBudgetedCall:
    """Join d91566b started/completed records; missing/unknown outcomes refuse.

    ``cached`` means provider input-token caching, not response reuse. Preserve
    that meaning rather than incorrectly refusing genuine uncached responses.
    No durable acknowledgement is manufactured by this read-only parser.
    """
    attempt = _fields(
        _json(attempt_record),
        {
            "version",
            "capture_scope",
            "phase",
            "call_id",
            "workload",
            "effort",
            "request",
            "provider_call",
            "budget",
        },
    )
    completion = _fields(
        _json(completion_record),
        {
            "version",
            "capture_scope",
            "phase",
            "call_id",
            "attempt_record_sha256",
            "response",
            "token_usage",
            "provider_call",
            "budget",
        },
    )
    if any(
        record["version"] != _VERSION or record["capture_scope"] != _CAPTURE_SCOPE
        for record in (attempt, completion)
    ):
        raise ValueError("not native application-boundary call evidence")
    call_id = _identifier(attempt["call_id"])
    if not re.fullmatch(r"[a-f0-9]{32}", call_id) or completion["call_id"] != call_id:
        raise ValueError("native attempt/completion call identity differs")
    if (
        attempt["phase"] != "ATTEMPT_STARTED"
        or completion["phase"] != "COMPLETED"
        or completion["attempt_record_sha256"] != hashlib.sha256(attempt_record).hexdigest()
    ):
        raise ValueError("completion does not bind exact original started record")
    native_workload = _identifier(attempt["workload"])
    if native_workload not in _WORKLOADS:
        raise ValueError("unknown native workload cannot be relabelled as a production input")
    effort = _identifier(attempt["effort"])
    request = _fields(attempt["request"], {"system_utf8", "user_utf8", "schema_canonical_json_utf8"})
    system = _decode(request["system_utf8"])
    user = _decode(request["user_utf8"])
    # Validate and retain schema bytes, even though native review provenance
    # deliberately hashes only {system,user}. It remains in attempt_record.
    schema = _decode(request["schema_canonical_json_utf8"])
    _json(schema)
    response = _decode(_fields(completion["response"], {"content_utf8"})["content_utf8"])
    started_call = _fields(attempt["provider_call"], {"provider", "model", "attempt_started_at_ms"})
    ended_call = _fields(
        completion["provider_call"],
        {
            "provider",
            "model",
            "resolved_model",
            "request_id",
            "cached",
            "cache_scope",
            "attempt_started_at_ms",
            "response_observed_at_ms",
        },
    )
    _integer(ended_call["attempt_started_at_ms"])
    if any(started_call[name] != ended_call[name] for name in started_call):
        raise ValueError("native provider attempt identity or original clock differs")
    if (
        type(ended_call["cached"]) is not bool
        or ended_call["cache_scope"] != "PROVIDER_INPUT_TOKENS_NOT_RESPONSE_REUSE"
    ):
        raise ValueError("native call cache semantics are unknown")
    provider = _identifier(started_call["provider"])
    requested_model = _identifier(started_call["model"])
    resolved = ended_call["resolved_model"]
    model = _identifier(resolved) if resolved is not None else requested_model
    request_id = _identifier(ended_call["request_id"])
    started_budget = _fields(attempt["budget"], {"reservation_id", "status", "reserved_microusd"})
    committed = _fields(
        completion["budget"],
        {
            "reservation_id",
            "status",
            "reserved_microusd",
            "actual_microusd",
            "commit_observed_at_ms",
        },
    )
    reservation = _identifier(started_budget["reservation_id"])
    reserved = _integer(started_budget["reserved_microusd"])
    actual = _integer(committed["actual_microusd"])
    if (
        started_budget["status"] != "RESERVED"
        or committed["status"] != "COMMITTED"
        or committed["reservation_id"] != reservation
        or type(committed["reserved_microusd"]) is not int
        or committed["reserved_microusd"] != reserved
        or actual > reserved
    ):
        raise ValueError("native call lacks the exact committed original budget hold")
    started = _integer(started_call["attempt_started_at_ms"])
    observed = _integer(ended_call["response_observed_at_ms"])
    committed_ms = _integer(committed["commit_observed_at_ms"])
    if not started <= observed <= committed_ms:
        raise ValueError("native provider/budget clocks are not causal")
    usage = _fields(
        completion["token_usage"],
        {
            "input_tokens",
            "output_tokens",
            "cached_input_tokens",
            "cache_write_tokens",
        },
    )
    for value in usage.values():
        _integer(value)
    if usage["cached_input_tokens"] > usage["input_tokens"]:
        raise ValueError("cached input tokens exceed total native input tokens")
    return NativeBudgetedCall(
        call_id,
        _WORKLOADS[native_workload],
        native_workload,
        provider,
        model,
        effort,
        request_id,
        reservation,
        started,
        observed,
        committed_ms,
        reserved,
        actual,
        attempt_record,
        completion_record,
        canonical_json_bytes({"system": system.decode("utf-8"), "user": user.decode("utf-8")}),
        response,
    )


def native_call_receipts(
    *,
    attempt_record: bytes,
    completion_record: bytes,
    captured_at_ms: int,
    bound_output_sha256: str,
) -> tuple[LiveInputStageReceiptV1, ...]:
    """Adapt retained native records, without inventing/renewing original clocks."""
    call = read_native_budgeted_call(attempt_record, completion_record)
    if _integer(captured_at_ms) < call.committed_at_ms:
        raise ValueError("capture predates native durable budget commit")
    stages: tuple[tuple[_ModelStage, bytes, int], ...] = (
        ("MODEL_PROMPT", call.prompt, call.started_at_ms),
        ("MODEL_RESPONSE", call.response, call.response_at_ms),
        ("MODEL_ATTEMPT_RECORD", attempt_record, call.started_at_ms),
        ("MODEL_COMPLETION_RECORD", completion_record, call.committed_at_ms),
    )
    return tuple(
        LiveInputStageReceiptV1(
            stage=stage,
            receipt_id=f"native-{call.call_id}-{stage.lower()}",
            workload_id=call.workload_id,
            call_id=call.call_id,
            provider=call.provider,
            model=call.model,
            reasoning_effort=call.reasoning_effort,
            request_id=call.request_id,
            budget_reservation_id=call.reservation_id,
            bound_output_sha256=bound_output_sha256,
            status="CAPTURED",
            source_timestamp_ms=clock,
            captured_at_ms=captured_at_ms,
            content_sha256=hashlib.sha256(body).hexdigest(),
            content_base64=base64.b64encode(body).decode("ascii"),
        )
        for stage, body, clock in stages
    )


def verify_native_call_receipts(stages: tuple[LiveInputStageReceiptV1, ...]) -> None:
    """Independent envelope-side exact native-record join, when records exist.

    Legacy signed fixtures may lack these optional records. A native production
    composer must require them; their absence is never source qualification.
    """
    groups: dict[str, list[LiveInputStageReceiptV1]] = {}
    for stage in stages:
        if stage.stage in _MODEL_STAGES:
            groups.setdefault(stage.call_id or "", []).append(stage)
    reservations: set[str] = set()
    requests: set[tuple[str | None, str | None]] = set()
    for group in groups.values():
        by_stage = {stage.stage: stage for stage in group}
        if not ({"MODEL_ATTEMPT_RECORD", "MODEL_COMPLETION_RECORD"} & by_stage.keys()):
            continue
        if len(by_stage) != len(group) or set(by_stage) != _MODEL_STAGES:
            raise ValueError("native model call requires all four exact artifact stages")
        raw = {
            name: base64.b64decode(stage.content_base64 or "", validate=True)
            for name, stage in by_stage.items()
        }
        call = read_native_budgeted_call(raw["MODEL_ATTEMPT_RECORD"], raw["MODEL_COMPLETION_RECORD"])
        expected = native_call_receipts(
            attempt_record=call.attempt_record,
            completion_record=call.completion_record,
            captured_at_ms=by_stage["MODEL_COMPLETION_RECORD"].captured_at_ms,
            bound_output_sha256=by_stage["MODEL_COMPLETION_RECORD"].bound_output_sha256 or "",
        )
        for receipt in expected:
            original = by_stage[receipt.stage]
            # Receipt names are transport-local; all substantive bytes/identity/
            # clocks must come directly from the original native evidence.
            if original.model_dump(exclude={"receipt_id"}) != receipt.model_dump(exclude={"receipt_id"}):
                raise ValueError("model artifacts differ from original native budgeted call records")
        if call.reservation_id in reservations or (call.provider, call.request_id) in requests:
            raise ValueError("native call reservation or provider request was reused")
        reservations.add(call.reservation_id)
        requests.add((call.provider, call.request_id))


@dataclass(frozen=True, slots=True)
class NativeCallRecordPair:
    """Original records joined to one exact native output, never a fresh call."""

    attempt_record: bytes
    completion_record: bytes
    bound_output_sha256: str
    captured_at_ms: int


def prepare_native_input_envelope(
    *,
    retained_manifest: bytes,
    calls: tuple[NativeCallRecordPair, ...],
) -> SignedLiveInputsEnvelopeV1:
    """Prepare exact bytes for an external, independently accepted producer.

    The retained source/native stage receipts are never regenerated from DTOs.
    The old signature is intentionally cleared: adding call evidence changes
    the signed payload. This returns an UNSIGNED preparation only; it cannot
    pass LiveInputsSourceVerifier or register a capture implementation. The
    source/native emission witness is still the accepted producer's duty.
    """
    payload = _json(retained_manifest)
    source_stages = payload.get("stages")
    if not isinstance(source_stages, list) or not 7 <= len(source_stages) <= 32:
        raise ValueError("retained native capture manifest requires bounded original stage receipts")
    if any(not isinstance(stage, dict) or stage.get("stage") in _MODEL_STAGES for stage in source_stages):
        raise ValueError("native preparation cannot replace or renew existing model artifacts")
    if not isinstance(calls, tuple) or len(calls) > 5:
        raise ValueError("native preparation requires a bounded immutable call tuple")
    receipts = tuple(
        receipt
        for pair in calls
        for receipt in native_call_receipts(
            attempt_record=pair.attempt_record,
            completion_record=pair.completion_record,
            captured_at_ms=pair.captured_at_ms,
            bound_output_sha256=pair.bound_output_sha256,
        )
    )
    observed_at_ms = _integer(payload.get("observed_at_ms"))
    if any(receipt.captured_at_ms > observed_at_ms for receipt in receipts):
        raise ValueError("native call capture is later than the original envelope observation")
    payload["stages"] = [*source_stages, *(receipt.model_dump(mode="json") for receipt in receipts)]
    payload["signature_base64"] = base64.b64encode(bytes(64)).decode("ascii")
    prepared = SignedLiveInputsEnvelopeV1.model_validate_json(canonical_json_bytes(payload))
    # Every model-origin output must join original native records, not generic
    # MODEL_PROMPT/RESPONSE placeholders. Review provenance is equally mandatory.
    for stage, workload in (("TEXT_AGGREGATE", "TEXT_AGGREGATION"), ("MACRO_ALLOCATION", "MACRO_ALLOCATION")):
        output = next(item for item in prepared.stages if item.stage == stage)
        selected = [item for item in receipts if item.workload_id == workload]
        if output.output_origin == "NATIVE_MODEL" and not selected:
            raise ValueError("model output has no retained original native call records")
    if prepared.review.model_provenance is not None and not any(
        item.workload_id == "CANDIDATE_REVIEW" for item in receipts
    ):
        raise ValueError("native model review lacks its original budgeted call records")
    review_digest = canonical_sha256(prepared.review)
    if any(
        item.workload_id == "CANDIDATE_REVIEW" and item.bound_output_sha256 != review_digest
        for item in receipts
    ):
        raise ValueError("native review call must bind the exact emitted review bytes")
    LiveInputsSourceVerifier._preflight(prepared)
    return prepared


def native_input_signing_bytes(prepared: SignedLiveInputsEnvelopeV1) -> bytes:
    """External signing request only; this module never handles producer keys."""
    checked = SignedLiveInputsEnvelopeV1.model_validate(prepared)
    return _DOMAIN + checked.signed_payload()


def verify_signed_native_input_envelope(
    *,
    prepared: SignedLiveInputsEnvelopeV1,
    signature: bytes,
    verifier: LiveInputsSourceVerifier,
    scope: LiveRiskScopeV1,
    decided_at_ms: int,
) -> SignedLiveInputsEnvelopeV1:
    """Finalize external signature through the same actual LIVE inputs verifier.

    This is not registration or producer acceptance. Only the independently
    configured verifier's pinned identity/key is used. Cancellation, durable
    entry dedup and account/owner/operator/Risk authority remain in the existing
    publisher/coordinator; no asynchronous effect or retry happens here.
    """
    if (
        type(verifier) is not LiveInputsSourceVerifier
        or not isinstance(signature, bytes)
        or len(signature) != 64
    ):
        raise ValueError("concrete pinned input verifier and exact external Ed25519 signature required")
    payload = prepared.model_dump(mode="python")
    payload["signature_base64"] = base64.b64encode(signature).decode("ascii")
    envelope = SignedLiveInputsEnvelopeV1.model_validate(payload)
    verifier.verify(
        envelope,
        expected_scope=scope,
        review=envelope.review,
        venue=envelope.venue,
        allocation=envelope.allocation,
        system_mode=SystemMode(envelope.system_mode),
        decided_at_ms=decided_at_ms,
    )
    return envelope


__all__ = [
    "NativeBudgetedCall",
    "NativeCallRecordPair",
    "NativeLLMCallSinkAdapter",
    "read_native_budgeted_call",
    "native_call_receipts",
    "prepare_native_input_envelope",
    "native_input_signing_bytes",
    "verify_signed_native_input_envelope",
]
