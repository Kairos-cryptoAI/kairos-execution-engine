"""Opt-in signed upstream-input envelope for the pure LIVE Risk verifier.

The Ed25519 signature proves that the holder of an independently pinned
producer key signed this exact capture manifest and native decision inputs. It
does not prove that an upstream provider signed its response, that the capture
process is correctly implemented, that a signal has alpha, or that trading is
authorized. No producer is registered by default; deployment must inject a
reviewed trust policy with a dedicated producer key (never an owner-arm or
custody key) and an independently qualified capture implementation.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Iterable, Mapping
from typing import Literal

from kairos_core.contracts import (
    CandidateReviewV1,
    CandidateRouteV1,
    SentimentSignal,
    StrategicAllocation,
    VenueQualityV1,
    canonical_json_bytes,
    canonical_sha256,
)
from kairos_core.contracts.decision_context import DecisionContextV1
from kairos_core.enums import SystemMode
from kairos_risk.live import LiveRiskScopeV1, VerifiedLiveInputsV1  # type: ignore[import-untyped]
from pydantic import Field, model_validator

from .production_readiness import StrictRecord

_DOMAIN = b"kairos.live-inputs-producer-envelope.v1\x00"
_MAX_RECEIPTS = 32
_MAX_RECEIPT_BYTES = 1_000_000
_MAX_TOTAL_BYTES = 4_000_000
_MAX_TOTAL_BASE64_CHARS = (_MAX_TOTAL_BYTES * 4 + 2) // 3
_MAX_CONTEXT_BYTES = _MAX_RECEIPT_BYTES
_FIVE_SECONDS_MS = 5_000
_VENUE_TTL_MS = 2_000
_TEXT_TTL_MS = 30 * 60 * 1_000
_TEXT_PLANNING_TTL_MS = 10 * 60 * 1_000
_ALLOCATION_TTL_MS = 26 * 60 * 60 * 1_000
_REQUIRED_STAGES = {
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
_SINGLETON_STAGES = _REQUIRED_STAGES - {"TEXT_SOURCE", "MACRO_SOURCE"}


class LiveInputProducerTrustV1(StrictRecord):
    """Externally pinned producer identity; there is intentionally no default."""

    producer_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    source_id: str = Field(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9_.:-]+$")
    purpose: Literal["LIVE_UPSTREAM_INPUT_CAPTURE"]
    source_set_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    policy_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    expected_text_source_names: tuple[str, ...] = Field(min_length=1, max_length=2)
    capture_implementation_id: str = Field(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9_.:-]+$")
    capture_implementation_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    registration_id: str = Field(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9_.:-]+$")

    @model_validator(mode="after")
    def validate_text_sources(self) -> LiveInputProducerTrustV1:
        if any(not value or value != value.strip() for value in self.expected_text_source_names):
            raise ValueError("pinned Text source names must be normalized")
        if len(set(self.expected_text_source_names)) != len(self.expected_text_source_names):
            raise ValueError("pinned Text source names cannot repeat")
        return self


class LiveInputStageReceiptV1(StrictRecord):
    """One explicit stage result; captured data is re-hashed from its bytes."""

    stage: Literal[
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
        "MODEL_PROMPT",
        "MODEL_RESPONSE",
    ]
    receipt_id: str = Field(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9_.:-]+$")
    source_name: str | None = Field(default=None, min_length=1, max_length=160)
    workload_id: Literal["TEXT_AGGREGATION", "MACRO_ALLOCATION", "CANDIDATE_REVIEW"] | None = None
    output_origin: Literal["NATIVE_MODEL", "NATIVE_DETERMINISTIC_FALLBACK"] | None = None
    call_id: str | None = Field(default=None, min_length=1, max_length=256)
    provider: str | None = Field(default=None, min_length=1, max_length=64)
    model: str | None = Field(default=None, min_length=1, max_length=128)
    reasoning_effort: str | None = Field(default=None, max_length=32)
    request_id: str | None = Field(default=None, min_length=1, max_length=256)
    budget_reservation_id: str | None = Field(default=None, min_length=1, max_length=128)
    bound_output_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    status: Literal["CAPTURED", "UNAVAILABLE"]
    reason_code: str | None = Field(default=None, min_length=1, max_length=128)
    source_timestamp_ms: int | None = Field(default=None, ge=0, strict=True)
    requested_at_ms: int | None = Field(default=None, ge=0, strict=True)
    received_at_ms: int | None = Field(default=None, ge=0, strict=True)
    persisted_at_ms: int | None = Field(default=None, ge=0, strict=True)
    captured_at_ms: int = Field(ge=0, strict=True)
    content_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    content_base64: str | None = Field(default=None, max_length=1_400_000)
    parent_receipt_ids: tuple[str, ...] = Field(default_factory=tuple, max_length=8)

    @model_validator(mode="after")
    def validate_content(self) -> LiveInputStageReceiptV1:
        for name in ("call_id", "source_name", "provider", "model", "request_id", "budget_reservation_id"):
            value = getattr(self, name)
            if value is not None and (not value or value != value.strip()):
                raise ValueError(f"{name} must be a normalized non-empty identifier")
        if len(set(self.parent_receipt_ids)) != len(self.parent_receipt_ids):
            raise ValueError("parent receipt IDs cannot repeat")
        if self.status == "CAPTURED":
            if self.content_sha256 is None or self.content_base64 is None:
                raise ValueError("captured stages require raw bytes and their content digest")
            if self.stage in {"TEXT_SOURCE", "MACRO_SOURCE", "BINANCE_REFERENCE", "EVEDEX_BOOK"}:
                requested = self.requested_at_ms
                received = self.received_at_ms
                persisted = self.persisted_at_ms
                source_timestamp = self.source_timestamp_ms
                if any(clock is None for clock in (requested, received, persisted, source_timestamp)):
                    raise ValueError(
                        "captured upstream source bytes require original request/receive/persist clocks"
                    )
                if requested is None or received is None or persisted is None or source_timestamp is None:
                    raise ValueError("captured source timestamps are required")
                if (
                    not requested <= received <= persisted <= self.captured_at_ms
                    or source_timestamp > received
                ):
                    raise ValueError("source request/receive/persist clocks are inconsistent")
        elif (
            self.content_sha256 is not None
            or self.content_base64 is not None
            or self.source_timestamp_ms is not None
            or self.requested_at_ms is not None
            or self.received_at_ms is not None
            or self.persisted_at_ms is not None
            or self.reason_code is None
            or self.parent_receipt_ids
        ):
            raise ValueError("unavailable stages cannot invent a source clock, digest, or bytes")
        elif self.reason_code != self.reason_code.strip():
            raise ValueError("unavailable stage reason must be normalized")
        if self.status == "CAPTURED" and self.reason_code is not None:
            raise ValueError("captured stages cannot carry an unavailable reason")
        native_output = self.stage in {"TEXT_AGGREGATE", "MACRO_ALLOCATION"}
        if native_output:
            if self.status == "CAPTURED" and self.output_origin is None:
                raise ValueError(
                    "captured native outputs require explicit model or deterministic-fallback origin"
                )
            if self.status == "UNAVAILABLE" and self.output_origin is not None:
                raise ValueError("unavailable native outputs cannot claim an output origin")
        elif self.output_origin is not None:
            raise ValueError("only native Text/Macro outputs can carry an output origin")
        model_stage = self.stage in {"MODEL_PROMPT", "MODEL_RESPONSE"}
        if model_stage:
            if (
                self.workload_id is None
                or self.call_id is None
                or self.provider is None
                or self.model is None
                or self.request_id is None
                or self.budget_reservation_id is None
                or self.source_name is not None
            ):
                raise ValueError(
                    "model artifacts require workload, call, request, and reservation identities"
                )
            if self.status != "CAPTURED":
                raise ValueError("model artifact calls cannot be represented as empty placeholders")
            if self.workload_id != "CANDIDATE_REVIEW" and self.bound_output_sha256 is None:
                raise ValueError("non-review model calls must bind their native workload output digest")
        elif any(
            value is not None
            for value in (
                self.workload_id,
                self.call_id,
                self.provider,
                self.model,
                self.reasoning_effort,
                self.request_id,
                self.budget_reservation_id,
                self.bound_output_sha256,
                self.reasoning_effort,
            )
        ):
            raise ValueError("non-model stages cannot carry model-call metadata")
        if self.stage not in {"TEXT_AGGREGATE", "MACRO_ALLOCATION"} and self.parent_receipt_ids:
            raise ValueError("only aggregate/allocation stages can reference source receipt parents")
        return self


class SignedLiveInputsEnvelopeV1(StrictRecord):
    """Canonical signed manifest consumed by :class:`LiveInputsSourceVerifier`."""

    version: Literal["kairos.live-inputs-producer-envelope.v1"] = "kairos.live-inputs-producer-envelope.v1"
    producer_id: str = Field(min_length=1, max_length=128)
    source_id: str = Field(min_length=1, max_length=160)
    purpose: Literal["LIVE_UPSTREAM_INPUT_CAPTURE"]
    registration_id: str = Field(min_length=1, max_length=160)
    capture_implementation_id: str = Field(min_length=1, max_length=160)
    capture_implementation_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_set_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    policy_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    scope_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    observed_at_ms: int = Field(ge=0, strict=True)
    route: CandidateRouteV1
    review: CandidateReviewV1
    context: DecisionContextV1
    venue: VenueQualityV1
    allocation: StrategicAllocation | None
    system_mode: SystemMode
    stages: tuple[LiveInputStageReceiptV1, ...] = Field(min_length=7, max_length=_MAX_RECEIPTS)
    signature_base64: str = Field(min_length=80, max_length=100)

    @model_validator(mode="after")
    def validate_manifest_shape(self) -> SignedLiveInputsEnvelopeV1:
        receipts = [stage.receipt_id for stage in self.stages]
        if len(receipts) != len(set(receipts)):
            raise ValueError("duplicate stage receipt IDs are not permitted")
        names = {stage.stage for stage in self.stages}
        if not _REQUIRED_STAGES.issubset(names):
            raise ValueError("required upstream stages must be explicit")
        for stage in ("TEXT_AGGREGATE", "MACRO_ALLOCATION"):
            matches = [receipt for receipt in self.stages if receipt.stage == stage]
            if len(matches) != 1:
                raise ValueError(f"{stage} must have exactly one explicit stage receipt")
        text_sources = [receipt for receipt in self.stages if receipt.stage == "TEXT_SOURCE"]
        if not 1 <= len(text_sources) <= 2 or any(receipt.source_name is None for receipt in text_sources):
            raise ValueError("one or two identified configured Text source receipts are required")
        if len({receipt.source_name for receipt in text_sources}) != len(text_sources):
            raise ValueError("Text source identities cannot be duplicated")
        macro_sources = [receipt for receipt in self.stages if receipt.stage == "MACRO_SOURCE"]
        if len(macro_sources) != 1:
            raise ValueError("macro source evidence must be one explicit raw source receipt")
        if macro_sources[0].source_name is None:
            raise ValueError("raw Macro source receipt requires its source identity")
        for child_stage, parent_stage in (
            ("TEXT_AGGREGATE", "TEXT_SOURCE"),
            ("MACRO_ALLOCATION", "MACRO_SOURCE"),
        ):
            child = next(receipt for receipt in self.stages if receipt.stage == child_stage)
            parents = [
                receipt.receipt_id
                for receipt in self.stages
                if receipt.stage == parent_stage and receipt.status == "CAPTURED"
            ]
            if child.status == "CAPTURED" and tuple(sorted(child.parent_receipt_ids)) != tuple(
                sorted(parents)
            ):
                raise ValueError(f"{child_stage} must join all exact {parent_stage} receipt IDs")
        for stage in _SINGLETON_STAGES:
            if sum(receipt.stage == stage for receipt in self.stages) != 1:
                raise ValueError(f"{stage} must have exactly one explicit stage receipt")
        model_artifacts = [
            stage for stage in self.stages if stage.stage in {"MODEL_PROMPT", "MODEL_RESPONSE"}
        ]
        call_pairs: dict[tuple[str, str], list[LiveInputStageReceiptV1]] = {}
        for receipt in model_artifacts:
            key = (receipt.workload_id or "", receipt.call_id or "")
            pair = call_pairs.setdefault(key, [])
            if any(existing.stage == receipt.stage for existing in pair):
                raise ValueError("duplicate model artifact for the same workload call")
            pair.append(receipt)
        for pair in call_pairs.values():
            if {item.stage for item in pair} != {"MODEL_PROMPT", "MODEL_RESPONSE"}:
                raise ValueError("each workload model call needs exactly one prompt and response artifact")
            if (
                len(
                    {
                        (
                            item.provider,
                            item.model,
                            item.reasoning_effort,
                            item.request_id,
                            item.budget_reservation_id,
                            item.bound_output_sha256,
                        )
                        for item in pair
                    }
                )
                != 1
            ):
                raise ValueError(
                    "model prompt and response must share exact call identity and output binding"
                )
        # These envelope workload IDs name native component outputs: the Text
        # Scout aggregation and Macro Strategist allocation respectively.
        for output_stage, workload in (
            ("TEXT_AGGREGATE", "TEXT_AGGREGATION"),
            ("MACRO_ALLOCATION", "MACRO_ALLOCATION"),
        ):
            output = next(receipt for receipt in self.stages if receipt.stage == output_stage)
            if output.status != "CAPTURED":
                continue
            calls = [pair for pair in call_pairs.values() if pair[0].workload_id == workload]
            if output.output_origin == "NATIVE_DETERMINISTIC_FALLBACK" and calls:
                raise ValueError(f"{output_stage} deterministic fallback cannot claim model-call artifacts")
            if output.output_origin == "NATIVE_MODEL":
                if not calls or any(pair[0].bound_output_sha256 != output.content_sha256 for pair in calls):
                    raise ValueError(
                        f"{output_stage} model origin requires complete model calls bound to its output"
                    )
        if canonical_json_bytes(self.route) != canonical_json_bytes(self.review.route):
            raise ValueError("envelope route must equal the native review route")
        self.context.validate_for_route(self.route)
        if self.review.evidence != self.context.evidence_references():
            raise ValueError("review evidence must equal the exact native DecisionContext reference")
        return self

    def signed_payload(self) -> bytes:
        return canonical_json_bytes(self.model_dump(mode="json", exclude={"signature_base64"}))


class LiveInputsSourceVerifier:
    """Concrete, opt-in Ed25519 verifier for exact signed upstream inputs.

    Trust policy and raw 32-byte public key are constructor-only trusted
    configuration. Raw proof cannot supply or replace a key. A successful
    result authenticates the capture-process statement and exact bytes/DTOs;
    it is not provider-level authentication or permission to trade. Risk's
    existing ``SIM_ONLY_INTENT`` rejection remains independently authoritative.
    """

    def __init__(self, *, trust: LiveInputProducerTrustV1, public_key: bytes) -> None:
        self.trust = LiveInputProducerTrustV1.model_validate(trust.model_dump(mode="python"))
        if not isinstance(public_key, bytes) or len(public_key) != 32:
            raise ValueError("an independently pinned Ed25519 producer public key is required")
        self._public_key = public_key

    def verify(
        self,
        raw_proof: object,
        *,
        expected_scope: LiveRiskScopeV1,
        review: CandidateReviewV1,
        venue: VenueQualityV1,
        allocation: StrategicAllocation | None,
        system_mode: SystemMode,
        decided_at_ms: int,
    ) -> VerifiedLiveInputsV1:
        self._preflight(raw_proof)
        envelope = SignedLiveInputsEnvelopeV1.model_validate(raw_proof)
        if isinstance(decided_at_ms, bool) or not isinstance(decided_at_ms, int) or decided_at_ms < 0:
            raise ValueError("decided_at_ms must be a non-negative integer")
        trust = self.trust
        if (
            envelope.producer_id != trust.producer_id
            or envelope.source_id != trust.source_id
            or envelope.purpose != trust.purpose
            or envelope.registration_id != trust.registration_id
            or envelope.capture_implementation_id != trust.capture_implementation_id
            or envelope.capture_implementation_sha256 != trust.capture_implementation_sha256
            or envelope.source_set_sha256 != trust.source_set_sha256
            or envelope.policy_sha256 != trust.policy_sha256
            or envelope.source_set_sha256 != expected_scope.source_set_sha256
            or envelope.policy_sha256 != expected_scope.policy_sha256
            or envelope.scope_sha256 != expected_scope.scope_sha256
            or tuple(
                sorted(
                    name
                    for stage in envelope.stages
                    if stage.stage == "TEXT_SOURCE"
                    for name in (stage.source_name,)
                    if name is not None
                )
            )
            != tuple(sorted(trust.expected_text_source_names))
        ):
            raise ValueError("producer, qualified implementation, policy, or source-set identity mismatch")
        if (
            canonical_json_bytes(envelope.review) != canonical_json_bytes(review)
            or envelope.context.evidence_references() != review.evidence
            or canonical_json_bytes(envelope.venue) != canonical_json_bytes(venue)
            or (envelope.allocation is None) != (allocation is None)
            or (
                envelope.allocation is not None
                and allocation is not None
                and canonical_json_bytes(envelope.allocation) != canonical_json_bytes(allocation)
            )
            or envelope.system_mode is not system_mode
        ):
            raise ValueError("signed envelope does not bind the exact Risk input DTOs")
        if envelope.context.missing_required_sources():
            raise ValueError("native DecisionContext is missing an originally required source")
        intent = review.intent
        if (
            intent.strategy_id != expected_scope.strategy_id
            or intent.strategy_revision != expected_scope.strategy_revision
            or expected_scope.venue_symbol_for(intent.symbol) != venue.symbol
        ):
            raise ValueError("signed route/review is outside the exact frozen Risk scope")
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

            signature = base64.b64decode(envelope.signature_base64, validate=True)
            if len(signature) != 64:
                raise ValueError("invalid Ed25519 signature length")
            Ed25519PublicKey.from_public_bytes(self._public_key).verify(
                signature, _DOMAIN + envelope.signed_payload()
            )
        except Exception as exc:
            raise ValueError("producer envelope signature verification failed") from exc

        by_stage: dict[str, list[LiveInputStageReceiptV1]] = {}
        for stage in envelope.stages:
            by_stage.setdefault(stage.stage, []).append(stage)
        required_captured = _REQUIRED_STAGES - (
            {"MACRO_SOURCE", "MACRO_ALLOCATION"} if allocation is None else set()
        )
        context_text = next(source for source in envelope.context.sources if source.kind == "text")
        if context_text.availability == "UNAVAILABLE":
            required_captured = required_captured - {"TEXT_AGGREGATE"}
            if by_stage["TEXT_AGGREGATE"][0].status != "UNAVAILABLE":
                raise ValueError("unavailable native Text context must remain explicitly unavailable")
            text_output_ids: tuple[str, ...] | None = ()
        else:
            if by_stage["TEXT_AGGREGATE"][0].status != "CAPTURED":
                raise ValueError("available native Text context requires its exact aggregate payload")
            text_output_ids = None
        for stage_name in required_captured:
            if not any(item.status == "CAPTURED" for item in by_stage[stage_name]):
                raise ValueError(f"required stage is unavailable: {stage_name}")
        macro_source = by_stage["MACRO_SOURCE"][0]
        macro_allocation = by_stage["MACRO_ALLOCATION"][0]
        if allocation is None and macro_allocation.status != "UNAVAILABLE":
            raise ValueError("an absent macro allocation must be explicitly unavailable")
        if allocation is not None and (
            macro_source.status != "CAPTURED" or macro_allocation.status != "CAPTURED"
        ):
            raise ValueError("macro allocation requires separate raw-source and native-allocation provenance")

        total_size = 0
        content_by_stage_id: dict[str, bytes] = {}
        for stage in envelope.stages:
            if stage.status != "CAPTURED":
                continue
            try:
                raw = base64.b64decode(stage.content_base64 or "", validate=True)
            except (ValueError, binascii.Error) as exc:
                raise ValueError("stage content is not valid base64") from exc
            if not raw or len(raw) > _MAX_RECEIPT_BYTES:
                raise ValueError("stage content is empty or exceeds per-receipt bounds")
            total_size += len(raw)
            if hashlib.sha256(raw).hexdigest() != stage.content_sha256:
                raise ValueError("stage raw bytes do not match their signed content digest")
            if stage.source_timestamp_ms is None or stage.source_timestamp_ms > stage.captured_at_ms:
                raise ValueError("captured source stage lacks a valid source clock")
            if stage.captured_at_ms > envelope.observed_at_ms:
                raise ValueError("stage receipt postdates the signed envelope observation")
            if stage.source_timestamp_ms > decided_at_ms:
                raise ValueError("source stage clock is future-dated")
            ttl_ms = {
                "TEXT_SOURCE": _TEXT_TTL_MS,
                "TEXT_AGGREGATE": _TEXT_PLANNING_TTL_MS,
                "MACRO_SOURCE": _ALLOCATION_TTL_MS,
                "MACRO_ALLOCATION": _ALLOCATION_TTL_MS,
            }.get(stage.stage)
            if ttl_ms is not None and stage.captured_at_ms - stage.source_timestamp_ms > ttl_ms:
                raise ValueError(f"{stage.stage} exceeds its existing source/planning TTL at capture")
            if stage.stage in {"VENUE_QUALITY", "BINANCE_REFERENCE", "EVEDEX_BOOK"}:
                if decided_at_ms - stage.source_timestamp_ms > _VENUE_TTL_MS:
                    raise ValueError("venue/source clock exceeds the unchanged two-second TTL")
            native_clock = {
                "ROUTER_OUTPUT": envelope.route.routed_at_ms,
                "REVIEW_OUTPUT": envelope.review.reviewed_at_ms,
                "DECISION_CONTEXT": envelope.context.captured_at_ms,
                "VENUE_QUALITY": envelope.venue.observed_at_ms,
                "BINANCE_REFERENCE": envelope.venue.reference_timestamp_ms,
                "EVEDEX_BOOK": envelope.venue.book_timestamp_ms,
            }.get(stage.stage)
            if native_clock is not None and stage.source_timestamp_ms != native_clock:
                raise ValueError(f"{stage.stage} source clock differs from its native DTO")
            expected_payloads = {
                "ROUTER_OUTPUT": canonical_json_bytes(envelope.route),
                "REVIEW_OUTPUT": canonical_json_bytes(envelope.review),
                "VENUE_QUALITY": canonical_json_bytes(envelope.venue),
                "MACRO_ALLOCATION": canonical_json_bytes(envelope.allocation)
                if envelope.allocation
                else None,
                "DECISION_CONTEXT": canonical_json_bytes(envelope.context),
            }
            if (
                stage.stage in expected_payloads
                and expected_payloads[stage.stage] is not None
                and raw != expected_payloads[stage.stage]
            ):
                raise ValueError(f"native stage bytes do not equal signed {stage.stage} DTO")
            if stage.stage == "TEXT_AGGREGATE":
                try:
                    payload = json.loads(raw)
                    if (
                        not isinstance(payload, dict)
                        or set(payload) != {"items"}
                        or not isinstance(payload["items"], list)
                    ):
                        raise ValueError("text aggregate must be a native items payload")
                    signals = tuple(SentimentSignal.model_validate(item) for item in payload["items"])
                    if (
                        canonical_json_bytes({"items": [item.model_dump(mode="json") for item in signals]})
                        != raw
                    ):
                        raise ValueError("text aggregate must preserve canonical native Text DTO bytes")
                    message_ids = [signal.message_id for signal in signals]
                    if len(message_ids) != len(set(message_ids)):
                        raise ValueError("text aggregate cannot repeat native signal identities")
                    text_output_ids = tuple(sorted(message_ids))
                    if any(
                        int(signal.produced_at.timestamp() * 1000) > stage.source_timestamp_ms
                        for signal in signals
                    ):
                        raise ValueError("Text aggregate clock predates a native Text signal")
                    if (
                        context_text.availability != "AVAILABLE"
                        or context_text.payloads_json is None
                        or context_text.payloads_json.encode("utf-8") != raw
                    ):
                        raise ValueError(
                            "Text aggregate differs from the exact native DecisionContext payload"
                        )
                except (TypeError, json.JSONDecodeError) as exc:
                    raise ValueError("text aggregate is not a valid native Text output") from exc
            content_by_stage_id[stage.receipt_id] = raw
        context_macro = next(source for source in envelope.context.sources if source.kind == "macro")
        if allocation is None:
            if context_macro.availability != "UNAVAILABLE":
                raise ValueError("absent macro allocation conflicts with native DecisionContext availability")
        elif (
            context_macro.availability != "AVAILABLE"
            or len(context_macro.payloads()) != 1
            or canonical_json_bytes(context_macro.payloads()[0]) != canonical_json_bytes(allocation)
        ):
            raise ValueError("macro allocation differs from the exact native DecisionContext payload")
        if total_size > _MAX_TOTAL_BYTES:
            raise ValueError("signed stage manifest exceeds the aggregate byte bound")
        if text_output_ids != envelope.route.evidence_ids:
            raise ValueError("native Router evidence IDs must exactly match the captured Text aggregate")
        if review.model_provenance is not None:
            provenance = review.model_provenance
            review_calls: dict[str, dict[str, LiveInputStageReceiptV1]] = {}
            for stage in envelope.stages:
                if stage.workload_id == "CANDIDATE_REVIEW":
                    review_calls.setdefault(stage.call_id or "", {})[stage.stage] = stage
            matching = [
                call
                for call in review_calls.values()
                if call.get("MODEL_PROMPT") is not None
                and call.get("MODEL_RESPONSE") is not None
                and call["MODEL_PROMPT"].request_id == provenance.request_id
                and call["MODEL_RESPONSE"].request_id == provenance.request_id
                and call["MODEL_PROMPT"].budget_reservation_id == provenance.budget_reservation_id
                and call["MODEL_RESPONSE"].budget_reservation_id == provenance.budget_reservation_id
                and call["MODEL_PROMPT"].provider == provenance.provider
                and call["MODEL_RESPONSE"].provider == provenance.provider
                and call["MODEL_PROMPT"].model == provenance.model
                and call["MODEL_RESPONSE"].model == provenance.model
                and call["MODEL_PROMPT"].reasoning_effort == provenance.reasoning_effort
                and call["MODEL_RESPONSE"].reasoning_effort == provenance.reasoning_effort
                and hashlib.sha256(content_by_stage_id[call["MODEL_PROMPT"].receipt_id]).hexdigest()
                == provenance.prompt_sha256
                and hashlib.sha256(content_by_stage_id[call["MODEL_RESPONSE"].receipt_id]).hexdigest()
                == provenance.response_sha256
            ]
            if len(matching) != 1:
                raise ValueError("review ModelProvenance requires one exact prompt/response call pair")
        elif any(stage.workload_id == "CANDIDATE_REVIEW" for stage in envelope.stages):
            raise ValueError("candidate-review model calls require native review ModelProvenance")
        output_digests = {
            "TEXT_AGGREGATION": by_stage["TEXT_AGGREGATE"][0].content_sha256,
            "MACRO_ALLOCATION": by_stage["MACRO_ALLOCATION"][0].content_sha256,
        }
        for stage in envelope.stages:
            if stage.stage in {"MODEL_PROMPT", "MODEL_RESPONSE"} and stage.workload_id in output_digests:
                if (
                    by_stage[stage.workload_id.replace("AGGREGATION", "AGGREGATE")][0].status != "CAPTURED"
                    or stage.bound_output_sha256 != output_digests[stage.workload_id]
                ):
                    raise ValueError("workload model call is not bound to its native output artifact")
        captured_digests = {stage.content_sha256 for stage in envelope.stages if stage.status == "CAPTURED"}
        captured_digests.update(
            receipt.content_sha256 for source in envelope.context.sources for receipt in source.receipts
        )
        if any(
            evidence.content_sha256 is None or evidence.content_sha256 not in captured_digests
            for evidence in (*review.intent.evidence, *review.evidence)
        ):
            raise ValueError("intent/review evidence references must join captured source content digests")
        observed_at = envelope.observed_at_ms
        if observed_at > decided_at_ms or decided_at_ms - observed_at > _FIVE_SECONDS_MS:
            raise ValueError("signed input envelope is future-dated or older than five seconds")
        intent = review.intent
        if decided_at_ms < intent.decision_ts_ms or decided_at_ms > intent.entry_expires_ts_ms:
            raise ValueError("native intent is outside its original decision/expiry window")
        if review.reviewed_at_ms > decided_at_ms or review.reviewed_at_ms > review.route.review_deadline_ms:
            raise ValueError("native review is future-dated or past its original route deadline")
        venue_clocks = (venue.observed_at_ms, venue.reference_timestamp_ms, venue.book_timestamp_ms)
        if any(clock > decided_at_ms or decided_at_ms - clock > _VENUE_TTL_MS for clock in venue_clocks):
            raise ValueError("native venue/reference/book clocks exceed the unchanged two-second TTL")
        evidence_sha256 = hashlib.sha256(_DOMAIN + envelope.signed_payload()).hexdigest()
        return VerifiedLiveInputsV1(
            source_id=trust.source_id,
            scope_sha256=expected_scope.scope_sha256,
            evidence_sha256=evidence_sha256,
            review_sha256=canonical_sha256(review.model_dump(mode="json")),
            venue_sha256=canonical_sha256(venue.model_dump(mode="json")),
            allocation_sha256=canonical_sha256(allocation.model_dump(mode="json")) if allocation else None,
            system_mode=system_mode,
            observed_at_ms=observed_at,
        )

    @staticmethod
    def _preflight(raw_proof: object) -> None:
        """Reject oversized wire envelopes before full Pydantic/signature work."""
        content_values: Iterable[str | None]
        source_payloads: list[str | None]
        if isinstance(raw_proof, SignedLiveInputsEnvelopeV1):
            stages = raw_proof.stages
            content_values = [stage.content_base64 for stage in stages]
            source_payloads = [
                source.payloads_json
                for source in raw_proof.context.sources
                if source.payloads_json is not None
            ]
        elif isinstance(raw_proof, Mapping):
            if set(raw_proof) - set(SignedLiveInputsEnvelopeV1.model_fields):
                raise ValueError("signed envelope has fields outside its bounded contract")
            stage_items = raw_proof.get("stages")
            if not isinstance(stage_items, (tuple, list)) or len(stage_items) > _MAX_RECEIPTS:
                raise ValueError("signed source manifest exceeds the bounded stage count")
            content_values = [item.get("content_base64") for item in stage_items if isinstance(item, Mapping)]
            context = raw_proof.get("context")
            if not isinstance(context, Mapping):
                raise ValueError("signed source manifest requires a bounded native DecisionContext")
            sources = context.get("sources")
            if not isinstance(sources, (tuple, list)) or len(sources) != 4:
                raise ValueError("native DecisionContext must contain its four explicit source slots")
            source_payloads = [
                source.get("payloads_json") for source in sources if isinstance(source, Mapping)
            ]
        else:
            raise ValueError("signed upstream proof must be a native envelope or mapping")
        context_chars = 0
        for payloads_json in source_payloads:
            if payloads_json is None:
                continue
            if not isinstance(payloads_json, str):
                raise ValueError("native context payloads must be bounded canonical JSON text")
            context_chars += len(payloads_json.encode("utf-8"))
            if context_chars > _MAX_CONTEXT_BYTES:
                raise ValueError("native DecisionContext exceeds its aggregate payload bound")
        total_chars = 0
        for content in content_values:
            if content is None:
                continue
            if not isinstance(content, str):
                raise ValueError("signed stage content must be bounded base64 text")
            if len(content) > (_MAX_RECEIPT_BYTES * 4 + 2) // 3:
                raise ValueError("stage content exceeds the per-receipt encoded bound")
            total_chars += len(content)
            if total_chars > _MAX_TOTAL_BASE64_CHARS:
                raise ValueError("signed source manifest exceeds the aggregate encoded bound")
