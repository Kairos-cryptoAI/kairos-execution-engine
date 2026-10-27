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
import re
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from typing import Literal

from kairos_core.contracts import (
    CandidateReviewV1,
    CandidateRouteV1,
    ClosedBarEventV1,
    EvidenceReferenceV1,
    MarketSnapshot,
    SentimentSignal,
    StrategicAllocation,
    VenueQualityV1,
    canonical_json_bytes,
    canonical_sha256,
)
from kairos_core.contracts.decision_context import DecisionContextV1
from kairos_core.enums import EvedexProfile, SystemMode
from kairos_core.topics import Topics
from kairos_risk.live import (  # type: ignore[import-untyped]
    LiveRiskScopeV1,
    VerifiedLiveInputsV1,
    VerifiedLiveInstrumentRulesV1,
)
from pydantic import Field, model_validator

from .production_readiness import StrictRecord
from .production_transport import parse_raw_response_capture

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
_NATIVE_QUANT_REPLAY_PROFILE_FIELDS = {
    "price_window",
    "depth_levels",
    "snapshot_interval_ms",
    "kline_finality_delay_ms",
    "maximum_binance_future_skew_ms",
    "book_stale_after_ms",
    "kline_stale_after_ms",
    "derivatives_stale_after_ms",
}
_QUANT_RAW_DOMAIN = b"kairos.quant-source-capture.v1\x00"
_QUANT_OUTPUT_DOMAIN = b"kairos.quant-derived-market-event.v1\x00"
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


def _review_evidence_matches_context(review: CandidateReviewV1, context: DecisionContextV1) -> bool:
    """Join native review's exact sentiment + context refs, without arbitrary extras.

    Older signed engineering callers used context-only references. Those remain
    compatible, but neither form can introduce content outside the actual cut.
    """
    context_refs = context.evidence_references()
    text = next(source for source in context.sources if source.kind == "text")
    signals = tuple(SentimentSignal.model_validate(payload) for payload in text.payloads())
    sentiment_refs = tuple(
        EvidenceReferenceV1(
            kind="sentiment",
            reference=signal.message_id,
            content_sha256=canonical_sha256(signal),
            observed_at_ms=int(signal.produced_at.timestamp() * 1_000),
        )
        for signal in signals
    )
    native_refs = tuple(sorted((*sentiment_refs, *context_refs), key=canonical_json_bytes))
    return review.evidence in (context_refs, native_refs)


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
    # Historical v1 source profiles retain their existing contract. New native
    # Quant capture profiles must explicitly require and pin this lineage.
    native_market_sources_required: bool = False
    native_quant_replay_profile: dict[str, int] | None = None

    @model_validator(mode="after")
    def validate_text_sources(self) -> LiveInputProducerTrustV1:
        if any(not value or value != value.strip() for value in self.expected_text_source_names):
            raise ValueError("pinned Text source names must be normalized")
        if len(set(self.expected_text_source_names)) != len(self.expected_text_source_names):
            raise ValueError("pinned Text source names cannot repeat")
        if self.native_market_sources_required != (self.native_quant_replay_profile is not None):
            raise ValueError("native market source requirement and replay profile must be paired")
        profile = self.native_quant_replay_profile
        if profile is not None and (
            set(profile) != _NATIVE_QUANT_REPLAY_PROFILE_FIELDS
            or any(type(value) is not int or value < 0 for value in profile.values())
            or any(
                profile[key] <= 0
                for key in (
                    "price_window",
                    "depth_levels",
                    "snapshot_interval_ms",
                    "book_stale_after_ms",
                    "kline_stale_after_ms",
                    "derivatives_stale_after_ms",
                )
            )
        ):
            raise ValueError("pinned native Quant replay profile is malformed")
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
        "EVEDEX_INSTRUMENT",
        "MODEL_PROMPT",
        "MODEL_RESPONSE",
        "MODEL_ATTEMPT_RECORD",
        "MODEL_COMPLETION_RECORD",
        # Optional native-only lineage stages. Historical v1 envelopes remain
        # valid without them; NativeProductionInputPreparer requires them before
        # it creates any new preparation from Quant captures.
        "MARKET_SOURCE",
        "CLOSED_BAR_SOURCE",
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
            if self.stage in {
                "TEXT_SOURCE",
                "MACRO_SOURCE",
                "BINANCE_REFERENCE",
                "EVEDEX_BOOK",
                "EVEDEX_INSTRUMENT",
            }:
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
        model_stage = self.stage in {
            "MODEL_PROMPT",
            "MODEL_RESPONSE",
            "MODEL_ATTEMPT_RECORD",
            "MODEL_COMPLETION_RECORD",
        }
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


def _validate_native_market_source_stages(
    *,
    envelope: SignedLiveInputsEnvelopeV1,
    by_stage: Mapping[str, list[LiveInputStageReceiptV1]],
    content_by_stage_id: Mapping[str, bytes],
    trust: LiveInputProducerTrustV1,
) -> None:
    """Require current native Quant profile stages and exact context linkage.

    The producer-side NativeCaptureSessionReader performs full raw-parent replay
    before signing. This downstream check independently binds those replay
    outputs and their declared ancestry to the exact first-received consumer
    DTOs; the pinned trust profile keeps historical v1 registrations intact.
    """
    names = {"MARKET_SOURCE", "CLOSED_BAR_SOURCE"}
    if not trust.native_market_sources_required:
        if any(stage.stage in names for stage in envelope.stages):
            raise ValueError("native market stages require an explicitly pinned native source profile")
        return
    if trust.native_quant_replay_profile is None:
        raise ValueError("current native source profile lacks its pinned Quant replay settings")

    def unique_object(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate native market lineage field")
            value[key] = item
        return value

    def stage_bundle(name: str) -> tuple[LiveInputStageReceiptV1, dict[str, object]]:
        values = by_stage.get(name, [])
        if len(values) != 1 or values[0].status != "CAPTURED":
            raise ValueError(f"current native source profile requires exactly one captured {name} stage")
        receipt = values[0]
        if receipt.source_name != "BINANCE_UM_NATIVE_REPLAY":
            raise ValueError(f"{name} source identity differs from the fixed native Quant replay")
        raw = content_by_stage_id[receipt.receipt_id]
        try:
            bundle = json.loads(raw, object_pairs_hook=unique_object)
        except (TypeError, ValueError, UnicodeError) as exc:
            raise ValueError(f"{name} lineage bundle is malformed") from exc
        if (
            not isinstance(bundle, dict)
            or canonical_json_bytes(bundle) != raw
            or set(bundle) != {"version", "outputs", "parent_records", "consumer_receipts"}
            or bundle.get("version") != "kairos.native-market-bar-lineage.v1"
            or not isinstance(bundle.get("outputs"), list)
            or not isinstance(bundle.get("parent_records"), list)
            or not isinstance(bundle.get("consumer_receipts"), list)
            or receipt.receipt_id != f"native-{name.lower()}-{hashlib.sha256(raw).hexdigest()[:32]}"
        ):
            raise ValueError(f"{name} lineage bundle identity/schema is invalid")
        return receipt, bundle

    def source_record_map(bundle: dict[str, object]) -> dict[str, dict[str, object]]:
        parent_records = bundle.get("parent_records")
        if not isinstance(parent_records, list) or len(parent_records) > 2_000:
            raise ValueError("native Quant source closure is missing or exceeds its fixed bound")
        result: dict[str, dict[str, object]] = {}
        for item in parent_records:
            if (
                not isinstance(item, dict)
                or set(item) != {"observation_id", "record", "persistence_witness"}
                or not isinstance(item["observation_id"], str)
                or re.fullmatch(r"[a-f0-9]{32}", item["observation_id"]) is None
                or not isinstance(item["record"], dict)
                or not isinstance(item["persistence_witness"], dict)
            ):
                raise ValueError("native Quant parent evidence has an unexpected shape")
            observation_id, record, witness = (
                item["observation_id"],
                item["record"],
                item["persistence_witness"],
            )
            schema = record.get("schema_version")
            if schema == "kairos.quant-source-capture.v1":
                expected_id = hashlib.sha256(_QUANT_RAW_DOMAIN + canonical_json_bytes(record)).hexdigest()[
                    :32
                ]
                received_at = record.get("received_at_ms")
                expected_ack = received_at
            elif schema == "kairos.quant-derived-market-event.v1":
                kind, event_id = record.get("event_kind"), record.get("event_id")
                expected_id = (
                    hashlib.sha256(_QUANT_OUTPUT_DOMAIN + f"{kind}:{event_id}".encode()).hexdigest()[:32]
                    if isinstance(kind, str) and isinstance(event_id, str)
                    else ""
                )
                expected_ack = record.get("output_observed_at_ms")
            else:
                raise ValueError("native Quant parent has an unsupported record schema")
            encoded = canonical_json_bytes(record)
            if (
                expected_id != observation_id
                or set(witness)
                != {
                    "version",
                    "purpose",
                    "storage_layout",
                    "observation_id",
                    "record_sha256",
                    "record_bytes",
                    "acknowledged_at_ms",
                }
                or witness.get("observation_id") != observation_id
                or witness.get("record_sha256") != hashlib.sha256(encoded).hexdigest()
                or witness.get("record_bytes") != len(encoded)
                or type(witness.get("acknowledged_at_ms")) is not int
                or type(expected_ack) is not int
                or witness["acknowledged_at_ms"] < expected_ack
                or observation_id in result
            ):
                raise ValueError("native Quant parent identity or local persistence witness is invalid")
            result[observation_id] = record
        return result

    def source_items(kind: str) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
        source = next(item for item in envelope.context.sources if item.kind == kind)
        if source.availability != "AVAILABLE" or source.payloads_json is None:
            raise ValueError(f"current native source profile requires available {kind} consumer inputs")
        try:
            payload = json.loads(source.payloads_json, object_pairs_hook=unique_object)
        except (TypeError, ValueError, UnicodeError) as exc:
            raise ValueError(f"native DecisionContext {kind} payload is malformed") from exc
        if (
            not isinstance(payload, dict)
            or set(payload) != {"items"}
            or not isinstance(payload["items"], list)
        ):
            raise ValueError(f"native DecisionContext {kind} payload has an unexpected shape")
        if canonical_json_bytes(payload).decode("utf-8") != source.payloads_json:
            raise ValueError(f"native DecisionContext {kind} payload is not canonical JSON")
        if len(payload["items"]) != len(source.receipts):
            raise ValueError(f"native DecisionContext {kind} receipts do not cover its DTOs")
        return payload["items"], [receipt.model_dump(mode="json") for receipt in source.receipts]

    def receipt_received_at(receipt: dict[str, object]) -> int:
        value = receipt.get("received_at_ms")
        if type(value) is not int:
            raise ValueError("native consumer receipt receive clock is malformed")
        return value

    def output_record(entry: object) -> dict[str, object]:
        if not isinstance(entry, dict) or not isinstance(entry.get("record"), dict):
            raise ValueError("native market output record is malformed")
        return entry["record"]

    def output_observed_at(record: dict[str, object]) -> int:
        value = record.get("output_observed_at_ms")
        if type(value) is not int:
            raise ValueError("native Quant output clock is malformed")
        return value

    def parent_records(bundle: dict[str, object]) -> list[dict[str, object]]:
        values = bundle.get("parent_records")
        if not isinstance(values, list) or any(not isinstance(value, dict) for value in values):
            raise ValueError("native Quant parent records are malformed")
        return values

    def parent_witness(item: dict[str, object]) -> tuple[str, int]:
        observation_id = item.get("observation_id")
        witness = item.get("persistence_witness")
        if not isinstance(observation_id, str) or not isinstance(witness, dict):
            raise ValueError("native Quant parent persistence witness is malformed")
        acknowledged_at = witness.get("acknowledged_at_ms")
        if type(acknowledged_at) is not int:
            raise ValueError("native Quant parent acknowledgement clock is malformed")
        return observation_id, acknowledged_at

    def verify_output(
        entry: object,
        *,
        event_kind: str,
        expected_payload: dict[str, object],
        consumer_receipt: dict[str, object],
    ) -> str:
        if not isinstance(entry, dict) or set(entry) != {"observation_id", "record", "persistence_witness"}:
            raise ValueError("native market output proof has an unexpected shape")
        observation_id = entry["observation_id"]
        record = entry["record"]
        witness = entry["persistence_witness"]
        output_observed_at_ms = record.get("output_observed_at_ms") if isinstance(record, dict) else None
        consumer_received_at_ms = consumer_receipt.get("received_at_ms")
        if (
            not isinstance(observation_id, str)
            or re.fullmatch(r"[a-f0-9]{32}", observation_id) is None
            or not isinstance(record, dict)
            or not isinstance(witness, dict)
            or set(record)
            != {
                "schema_version",
                "capture_scope",
                "event_kind",
                "event_id",
                "event_sha256",
                "event_payload",
                "output_observed_at_ms",
                "parents",
                "replay_profile",
            }
            or record["schema_version"] != "kairos.quant-derived-market-event.v1"
            or record["capture_scope"] != "native-quant-derived-output-not-authority"
            or record["event_kind"] != event_kind
            or record["event_payload"] != expected_payload
            or record["event_sha256"] != hashlib.sha256(canonical_json_bytes(expected_payload)).hexdigest()
            or type(output_observed_at_ms) is not int
            or type(consumer_received_at_ms) is not int
            or consumer_received_at_ms < output_observed_at_ms
        ):
            raise ValueError("Quant output does not bind the exact original consumer DTO/receive receipt")
        event_id = (
            expected_payload.get("message_id")
            if event_kind == "MARKET_SNAPSHOT"
            else expected_payload.get("bar_sha256")
        )
        if (
            not isinstance(event_id, str)
            or record["event_id"] != event_id
            or observation_id
            != hashlib.sha256(_QUANT_OUTPUT_DOMAIN + f"{event_kind}:{event_id}".encode()).hexdigest()[:32]
        ):
            raise ValueError("Quant output ID differs from its exact native event identity")
        message: MarketSnapshot | ClosedBarEventV1
        if event_kind == "MARKET_SNAPSHOT":
            message = MarketSnapshot.model_validate(expected_payload)
            event_at_ms = int(message.produced_at.timestamp() * 1_000)
        else:
            message = ClosedBarEventV1.model_validate(expected_payload)
            event_at_ms = message.close_time_ms
        produced_at_ms = int(message.produced_at.timestamp() * 1_000)
        expected_topic = Topics.MARKET_SNAPSHOT if event_kind == "MARKET_SNAPSHOT" else Topics.CLOSED_BAR
        consumer_ttl_ms = consumer_receipt.get("ttl_ms", 0)
        if (
            consumer_receipt.get("message_id") != message.message_id
            or consumer_receipt.get("source") != message.source
            or consumer_receipt.get("topic") != expected_topic
            or consumer_receipt.get("content_sha256") != canonical_sha256(message)
            or consumer_receipt.get("event_at_ms") != event_at_ms
            or consumer_receipt.get("produced_at_ms") != produced_at_ms
            or event_at_ms > produced_at_ms
            or type(consumer_received_at_ms) is not int
            or produced_at_ms > consumer_received_at_ms
            or consumer_received_at_ms > envelope.context.captured_at_ms
            or type(consumer_ttl_ms) is not int
            or consumer_ttl_ms <= 0
        ):
            raise ValueError("native consumer receipt does not bind the exact original Quant DTO clocks")
        if record["replay_profile"] != trust.native_quant_replay_profile:
            raise ValueError("Quant output transform profile differs from pinned producer trust")
        parents = record["parents"]
        expected_parent_keys = (
            {"depth_frame", "funding_source", "open_interest_source", "force_order_frames", "confirmed_bars"}
            if event_kind == "MARKET_SNAPSHOT"
            else {"rest_confirmations"}
        )
        if not isinstance(parents, dict) or set(parents) != expected_parent_keys:
            raise ValueError("Quant output lacks its exact declared raw-source parent set")
        if event_kind == "CLOSED_BAR":
            confirmations = parents["rest_confirmations"]
            if (
                not isinstance(confirmations, list)
                or len(confirmations) != 2
                or len(set(confirmations)) != 2
                or any(
                    not isinstance(value, str) or re.fullmatch(r"[a-f0-9]{32}", value) is None
                    for value in confirmations
                )
            ):
                raise ValueError("closed-bar output does not retain two exact source confirmations")
        else:

            def ids(value: object, *, allow_empty: bool = False) -> list[str]:
                values = [value] if isinstance(value, str) else value
                if (
                    not isinstance(values, list)
                    or (not allow_empty and not values)
                    or len(values) > 2_000
                    or any(
                        not isinstance(item, str) or re.fullmatch(r"[a-f0-9]{32}", item) is None
                        for item in values
                    )
                    or len(values) != len(set(values))
                ):
                    raise ValueError("market output has malformed source parent IDs")
                return values

            ids(parents["depth_frame"])
            ids(parents["funding_source"])
            ids(parents["open_interest_source"])
            ids(parents["force_order_frames"], allow_empty=True)
            ids(parents["confirmed_bars"])
        if (
            set(witness)
            != {
                "version",
                "purpose",
                "storage_layout",
                "observation_id",
                "record_sha256",
                "record_bytes",
                "acknowledged_at_ms",
            }
            or witness["observation_id"] != observation_id
            or witness["record_sha256"] != hashlib.sha256(canonical_json_bytes(record)).hexdigest()
            or witness["record_bytes"] != len(canonical_json_bytes(record))
            or type(witness["acknowledged_at_ms"]) is not int
            or witness["acknowledged_at_ms"] < record["output_observed_at_ms"]
            or type(consumer_received_at_ms) is not int
            or witness["acknowledged_at_ms"] > consumer_received_at_ms
        ):
            raise ValueError("Quant output persistence witness is invalid")
        return observation_id

    market_source, market_bundle = stage_bundle("MARKET_SOURCE")
    bar_source, bar_bundle = stage_bundle("CLOSED_BAR_SOURCE")
    market_items, market_receipts = source_items("market")
    bar_items, bar_receipts = source_items("closed_bars")
    if (
        market_bundle["consumer_receipts"] != market_receipts
        or bar_bundle["consumer_receipts"] != bar_receipts
    ):
        raise ValueError("native source stages do not preserve the first consumer receipt clocks")
    market_outputs = market_bundle["outputs"]
    bar_outputs = bar_bundle["outputs"]
    if (
        not isinstance(market_outputs, list)
        or not isinstance(bar_outputs, list)
        or len(market_items) != 1
        or len(market_outputs) != 1
        or len(bar_items) != len(bar_outputs)
    ):
        raise ValueError("native source stages do not cover the exact market/bar context inputs")
    market_id = verify_output(
        market_outputs[0],
        event_kind="MARKET_SNAPSHOT",
        expected_payload=market_items[0],
        consumer_receipt=market_receipts[0],
    )
    bar_ids = tuple(
        verify_output(
            entry,
            event_kind="CLOSED_BAR",
            expected_payload=payload,
            consumer_receipt=receipt,
        )
        for entry, payload, receipt in zip(bar_outputs, bar_items, bar_receipts, strict=True)
    )
    market_output_entry = market_outputs[0]
    if not isinstance(market_output_entry, dict) or not isinstance(market_output_entry.get("record"), dict):
        raise ValueError("native market output record is malformed")
    market_record = market_output_entry["record"]
    market_parents = market_record.get("parents")
    if not isinstance(market_parents, dict):
        raise ValueError("native market output parents are malformed")
    confirmed = market_parents.get("confirmed_bars")
    if (
        not isinstance(confirmed, list)
        or len(bar_ids) > len(confirmed)
        or confirmed[-len(bar_ids) :] != list(bar_ids)
    ):
        raise ValueError("market source parent history does not end with the exact consumer bar tail")
    if (
        market_source.received_at_ms != max(receipt_received_at(receipt) for receipt in market_receipts)
        or bar_source.received_at_ms != max(receipt_received_at(receipt) for receipt in bar_receipts)
        or market_source.source_timestamp_ms != market_record["output_observed_at_ms"]
        or market_source.source_name != "BINANCE_UM_NATIVE_REPLAY"
    ):
        raise ValueError("native source stage clocks differ from original outputs/consumer receipts")
    # Replay the same read-only Quant pipeline from the signed, create-only
    # parent records. This means a valid producer signature alone cannot hide
    # an omitted or substituted source capture under the current pinned profile.
    try:
        from kairos_quant.native_replay import (  # type: ignore[import-not-found,import-untyped]
            replay_native_quant_event,
        )

        market_output = market_record
        market_sources = source_record_map(market_bundle)
        if any(
            acknowledged_at > output_observed_at(market_output)
            for item in parent_records(market_bundle)
            for _observation_id, acknowledged_at in (parent_witness(item),)
        ):
            raise ValueError("native market ancestry was not durably persisted before snapshot publication")
        market_sources[market_id] = market_output
        if (
            replay_native_quant_event(
                event_kind="MARKET_SNAPSHOT",
                expected_payload=market_items[0],
                source_records=market_sources,
                output_record=market_output,
            )
            != market_items[0]
        ):
            raise ValueError("native Quant market replay differs from its consumer DTO")
        for item, payload in zip(bar_outputs, bar_items, strict=True):
            output = output_record(item)
            if not isinstance(item, dict) or not isinstance(item.get("observation_id"), str):
                raise ValueError("native closed-bar output identity is malformed")
            output_id = item["observation_id"]
            bar_sources = source_record_map(bar_bundle)
            output_parents = output.get("parents")
            if not isinstance(output_parents, dict):
                raise ValueError("native closed-bar output parents are malformed")
            confirmation_ids = output_parents.get("rest_confirmations")
            if not isinstance(confirmation_ids, list) or any(
                not isinstance(value, str) for value in confirmation_ids
            ):
                raise ValueError("native closed-bar confirmation IDs are malformed")
            parent_witnesses = {
                observation_id: acknowledged_at
                for parent in parent_records(bar_bundle)
                for observation_id, acknowledged_at in (parent_witness(parent),)
            }
            if any(
                parent_witnesses.get(parent_id, output_observed_at(output) + 1) > output_observed_at(output)
                for parent_id in confirmation_ids
            ):
                raise ValueError("native closed-bar confirmations were not durable before publication")
            bar_sources[output_id] = output
            if (
                replay_native_quant_event(
                    event_kind="CLOSED_BAR",
                    expected_payload=payload,
                    source_records=bar_sources,
                    output_record=output,
                )
                != payload
            ):
                raise ValueError("native Quant closed-bar replay differs from its consumer DTO")
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError("current native Quant sources could not be independently replayed") from exc


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
        if sum(receipt.stage == "EVEDEX_INSTRUMENT" for receipt in self.stages) > 1:
            raise ValueError("EVEDEX_INSTRUMENT may have at most one explicit stage receipt")
        model_artifacts = [
            stage
            for stage in self.stages
            if stage.stage
            in {
                "MODEL_PROMPT",
                "MODEL_RESPONSE",
                "MODEL_ATTEMPT_RECORD",
                "MODEL_COMPLETION_RECORD",
            }
        ]
        call_pairs: dict[tuple[str, str], list[LiveInputStageReceiptV1]] = {}
        for receipt in model_artifacts:
            key = (receipt.workload_id or "", receipt.call_id or "")
            pair = call_pairs.setdefault(key, [])
            if any(existing.stage == receipt.stage for existing in pair):
                raise ValueError("duplicate model artifact for the same workload call")
            pair.append(receipt)
        for pair in call_pairs.values():
            names = {item.stage for item in pair}
            expected_names = {"MODEL_PROMPT", "MODEL_RESPONSE"}
            if names & {"MODEL_ATTEMPT_RECORD", "MODEL_COMPLETION_RECORD"}:
                expected_names |= {"MODEL_ATTEMPT_RECORD", "MODEL_COMPLETION_RECORD"}
            if names != expected_names:
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
        if not _review_evidence_matches_context(self.review, self.context):
            raise ValueError("review evidence must equal the exact native DecisionContext reference")
        from .production_native_inputs import verify_native_call_receipts

        verify_native_call_receipts(self.stages)
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
            or not _review_evidence_matches_context(review, envelope.context)
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
        _validate_native_market_source_stages(
            envelope=envelope,
            by_stage=by_stage,
            content_by_stage_id=content_by_stage_id,
            trust=trust,
        )
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
            if (
                stage.stage
                in {
                    "MODEL_PROMPT",
                    "MODEL_RESPONSE",
                    "MODEL_ATTEMPT_RECORD",
                    "MODEL_COMPLETION_RECORD",
                }
                and stage.workload_id in output_digests
            ):
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
        instrument_rules = None
        if "EVEDEX_INSTRUMENT" in by_stage:
            receipt = by_stage["EVEDEX_INSTRUMENT"][0]
            if receipt.status != "CAPTURED":
                raise ValueError("present instrument stage must contain original raw HTTP capture")
            instrument_rules = self._instrument_rules(
                content_by_stage_id[receipt.receipt_id],
                receipt=receipt,
                envelope=envelope,
                expected_scope=expected_scope,
                evidence_sha256=evidence_sha256,
                decided_at_ms=decided_at_ms,
            )
        return VerifiedLiveInputsV1(
            source_id=trust.source_id,
            scope_sha256=expected_scope.scope_sha256,
            evidence_sha256=evidence_sha256,
            review_sha256=canonical_sha256(review.model_dump(mode="json")),
            venue_sha256=canonical_sha256(venue.model_dump(mode="json")),
            allocation_sha256=canonical_sha256(allocation.model_dump(mode="json")) if allocation else None,
            system_mode=system_mode,
            observed_at_ms=observed_at,
            instrument_rules=instrument_rules,
        )

    @staticmethod
    def _instrument_rules(
        raw: bytes,
        *,
        receipt: LiveInputStageReceiptV1,
        envelope: SignedLiveInputsEnvelopeV1,
        expected_scope: LiveRiskScopeV1,
        evidence_sha256: str,
        decided_at_ms: int,
    ) -> VerifiedLiveInstrumentRulesV1:
        """Derive exact rule facts from authenticated original HTTP bytes only."""

        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate raw HTTP capture object key")
                result[key] = value
            return result

        capture = json.loads(raw, object_pairs_hook=unique_object)
        payload = parse_raw_response_capture(
            capture, source="instruments", expected_query={"fields": "metrics"}
        )
        if receipt.source_name != "instruments" or not 200 <= capture["status"] < 300:
            raise ValueError("instrument HTTP capture identity/status is invalid")

        def timestamp_ms(value):
            if not isinstance(value, str):
                raise ValueError("instrument source timestamp must be original ISO UTC text")
            stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if stamp.utcoffset() != UTC.utcoffset(stamp) or stamp.microsecond % 1_000:
                raise ValueError("instrument source timestamp must be exact UTC milliseconds")
            delta = stamp - datetime(1970, 1, 1, tzinfo=UTC)
            return (delta.days * 86_400 + delta.seconds) * 1_000 + delta.microseconds // 1_000

        requested_ms = timestamp_ms(capture["requested_at"])
        received_ms = timestamp_ms(capture["received_at"])
        if (
            receipt.requested_at_ms != requested_ms
            or receipt.received_at_ms != received_ms
            or receipt.source_timestamp_ms != received_ms
            or not 0 <= decided_at_ms - received_ms <= _FIVE_SECONDS_MS
            or received_ms > envelope.observed_at_ms
        ):
            raise ValueError("instrument original HTTP clocks differ, are future-dated, or stale")
        instruments = payload.get("list") if isinstance(payload, dict) else payload
        if not isinstance(instruments, list) or any(not isinstance(item, dict) for item in instruments):
            raise ValueError("instrument source must preserve the native list response")
        matches = [item for item in instruments if item.get("name") == envelope.venue.symbol]
        if len(matches) != 1:
            raise ValueError("instrument metadata is missing or duplicated for the exact PROD symbol")
        instrument = matches[0]
        if (
            instrument.get("trading") != "all"
            or instrument.get("visibility") != "all"
            or instrument.get("marketState") != "OPEN"
        ):
            raise ValueError("instrument is not open, visible, and tradeable")
        updated_ms = timestamp_ms(instrument.get("updatedAt"))
        if updated_ms > received_ms:
            raise ValueError("instrument rule-change timestamp postdates original capture")
        return VerifiedLiveInstrumentRulesV1(
            source_id=envelope.source_id,
            scope_sha256=expected_scope.scope_sha256,
            evidence_sha256=evidence_sha256,
            venue_symbol=envelope.venue.symbol,
            profile=EvedexProfile.PROD,
            observed_at_ms=received_ms,
            rules_updated_at_ms=updated_ms,
            price_increment=instrument.get("priceIncrement"),
            quantity_increment=instrument.get("quantityIncrement"),
            min_price=instrument.get("minPrice"),
            max_price=instrument.get("maxPrice"),
            min_quantity=instrument.get("minQuantity"),
            max_quantity=instrument.get("maxQuantity"),
            min_notional_usd=instrument.get("minVolume"),
            # No maximum-notional meaning is inferred from an undocumented field.
            max_notional_usd=None,
            lot_size=instrument.get("lotSize"),
            multiplier=instrument.get("multiplier"),
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
