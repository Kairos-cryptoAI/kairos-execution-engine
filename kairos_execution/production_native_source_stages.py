"""Project native create-only captures into existing LIVE input stage receipts.

This module is deliberately partial: it projects only source bytes and native
outputs that already exist in the native capture session. It does not mint a
producer manifest, fill absent venue/Binance/Macro-source evidence, sign, or
register a producer.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Literal, cast

from kairos_core.contracts import SentimentSignal, StrategicAllocation, canonical_json_bytes
from kairos_core.enums import StrategicTrigger

from .production_inputs import LiveInputStageReceiptV1
from .production_native_capture_store import (
    NativeCaptureSessionReader,
    NativeCaptureStoredObservation,
)
from .production_native_inputs import NativeCallRecordPair, read_native_budgeted_call
from .production_native_text import read_native_rss_response, read_native_sentiment_extraction
from .production_transport import parse_raw_response_capture

_StageName = Literal[
    "TEXT_SOURCE",
    "TEXT_AGGREGATE",
    "MACRO_SOURCE",
    "MACRO_ALLOCATION",
    "ROUTER_OUTPUT",
    "REVIEW_OUTPUT",
    "DECISION_CONTEXT",
    "EVEDEX_BOOK",
    "EVEDEX_INSTRUMENT",
    "BINANCE_REFERENCE",
]
_OutputOrigin = Literal["NATIVE_MODEL", "NATIVE_DETERMINISTIC_FALLBACK"]


class NativeStageProjectionError(ValueError):
    """The requested projection is not backed by exact retained native bytes."""


@dataclass(frozen=True, slots=True)
class NativeSourceStageProjection:
    stages: tuple[LiveInputStageReceiptV1, ...]
    # Partial source projection is never accepted producer evidence by itself.
    live_ready: bool = False


@dataclass(frozen=True, slots=True)
class NativeMacroStageProjection:
    """Macro stage receipts plus the exact native call pair when model-origin."""

    stages: tuple[LiveInputStageReceiptV1, LiveInputStageReceiptV1]
    calls: tuple[NativeCallRecordPair, ...]
    live_ready: bool = False


def _capture(reader: NativeCaptureSessionReader, observation_id: str) -> NativeCaptureStoredObservation:
    stored = reader.read(observation_id)
    if type(stored) is not NativeCaptureStoredObservation:
        raise NativeStageProjectionError("native capture reader returned an unexpected observation")
    witness = stored.witness
    if (
        witness.observation_id != observation_id
        or witness.record_bytes != len(stored.record)
        or witness.record_sha256 != hashlib.sha256(stored.record).hexdigest()
    ):
        raise NativeStageProjectionError("native persistence witness does not bind the exact source bytes")
    return stored


def _receipt(
    *,
    stage: _StageName,
    observation_id: str,
    content: bytes,
    source_timestamp_ms: int,
    requested_at_ms: int | None = None,
    received_at_ms: int | None = None,
    source_name: str | None = None,
    persisted_at_ms: int,
    output_origin: _OutputOrigin | None = None,
    parent_receipt_ids: tuple[str, ...] = (),
) -> LiveInputStageReceiptV1:
    if not content or len(content) > 1_000_000:
        raise NativeStageProjectionError("projected native stage bytes are empty or exceed their bound")
    if (
        type(source_timestamp_ms) is not int
        or source_timestamp_ms < 0
        or type(persisted_at_ms) is not int
        or persisted_at_ms < source_timestamp_ms
    ):
        raise NativeStageProjectionError("native source/persistence clocks are invalid")
    if requested_at_ms is not None and received_at_ms is not None:
        if not requested_at_ms <= received_at_ms <= persisted_at_ms:
            raise NativeStageProjectionError("native request/receive/persist clocks are inconsistent")
    return LiveInputStageReceiptV1(
        stage=stage,
        receipt_id=f"native-{stage.lower()}-{observation_id}",
        source_name=source_name,
        status="CAPTURED",
        output_origin=output_origin,
        source_timestamp_ms=source_timestamp_ms,
        requested_at_ms=requested_at_ms,
        received_at_ms=received_at_ms,
        persisted_at_ms=persisted_at_ms,
        # The session witness is a real lower-bound persistence clock sampled
        # after the original raw-record fsync; no projection-time clock is read.
        captured_at_ms=persisted_at_ms,
        content_sha256=hashlib.sha256(content).hexdigest(),
        content_base64=base64.b64encode(content).decode("ascii"),
        parent_receipt_ids=parent_receipt_ids,
    )


def _unavailable(
    stage: Literal["TEXT_AGGREGATE", "MACRO_SOURCE", "MACRO_ALLOCATION"],
    reason: str,
    *,
    source_name: str | None = None,
) -> LiveInputStageReceiptV1:
    if not isinstance(reason, str) or not reason or reason != reason.strip() or len(reason) > 128:
        raise NativeStageProjectionError("unavailable native stage needs its original reason")
    return LiveInputStageReceiptV1(
        stage=stage,
        receipt_id=f"native-{stage.lower()}-unavailable",
        source_name=source_name,
        status="UNAVAILABLE",
        reason_code=reason,
        captured_at_ms=0,
    )


def _unique_json(raw: bytes) -> dict[str, Any]:
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError("duplicate JSON field")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=pairs)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise NativeStageProjectionError("retained native capture is not unique-key JSON") from exc
    if not isinstance(value, dict) or canonical_json_bytes(value) != raw:
        raise NativeStageProjectionError("retained native capture is not canonical JSON")
    return value


def _decoded_unique_json(raw: bytes) -> dict[str, Any]:
    """Parse original source JSON with duplicate-key rejection, without re-encoding it."""

    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError("duplicate JSON field")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=pairs)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise NativeStageProjectionError("source response is not unique-key JSON") from exc
    if not isinstance(value, dict):
        raise NativeStageProjectionError("source response root must be a JSON object")
    return value


def project_native_source_stages(
    *,
    reader: NativeCaptureSessionReader,
    rss_observation_ids: tuple[str, ...],
    evedex_instrument_observation_id: str,
    evedex_book_observation_id: str,
    venue_symbol: str,
) -> NativeSourceStageProjection:
    """Project exact original RSS, EVEDEX instrument and depth captures.

    RSS application captures are reparsed by the actual native Text parser.
    Instrument/depth captures are checked against the existing fixed EVEDEX
    routes and body digests. Their session witness supplies only the original
    local persistence lower bound; it is not provider/producer qualification.
    """
    if type(reader) is not NativeCaptureSessionReader:
        raise TypeError("the read-only native capture session reader is required")
    if (
        not isinstance(rss_observation_ids, tuple)
        or not 1 <= len(rss_observation_ids) <= 2
        or len(set(rss_observation_ids)) != len(rss_observation_ids)
        or not isinstance(venue_symbol, str)
        or re.fullmatch(r"[A-Z0-9]{1,32}", venue_symbol) is None
    ):
        raise NativeStageProjectionError("bounded exact source identities and venue symbol are required")

    receipts: list[LiveInputStageReceiptV1] = []
    text_sources: set[str] = set()
    for observation_id in rss_observation_ids:
        stored = _capture(reader, observation_id)
        parsed = read_native_rss_response(stored.record)
        if stored.witness.acknowledged_at_ms < parsed.captured_at_ms:
            raise NativeStageProjectionError("RSS persistence witness predates its original capture")
        if parsed.source_name in text_sources:
            raise NativeStageProjectionError("native RSS source identity is duplicated")
        text_sources.add(parsed.source_name)
        receipts.append(
            _receipt(
                stage="TEXT_SOURCE",
                observation_id=observation_id,
                content=stored.record,
                source_timestamp_ms=parsed.received_at_ms,
                requested_at_ms=parsed.requested_at_ms,
                received_at_ms=parsed.received_at_ms,
                source_name=parsed.source_name,
                persisted_at_ms=stored.witness.acknowledged_at_ms,
            )
        )

    instrument = _capture(reader, evedex_instrument_observation_id)
    instrument_capture = _unique_json(instrument.record)
    try:
        instrument_payload = parse_raw_response_capture(
            instrument_capture,
            source="instruments",
            expected_query={"fields": "metrics"},
        )
    except Exception as exc:
        raise NativeStageProjectionError(
            "EVEDEX instrument capture fails its exact fixed-route parser"
        ) from exc
    if not 200 <= instrument_capture["status"] < 300:
        raise NativeStageProjectionError("EVEDEX instrument source returned a non-success status")
    instruments = (
        instrument_payload.get("list") if isinstance(instrument_payload, dict) else instrument_payload
    )
    if (
        not isinstance(instruments, list)
        or sum(isinstance(item, dict) and item.get("name") == venue_symbol for item in instruments) != 1
    ):
        raise NativeStageProjectionError(
            "captured EVEDEX instrument list does not uniquely bind venue symbol"
        )
    requested_ms, received_ms = _http_clocks(instrument_capture)
    receipts.append(
        _receipt(
            stage="EVEDEX_INSTRUMENT",
            observation_id=evedex_instrument_observation_id,
            content=instrument.record,
            source_timestamp_ms=received_ms,
            requested_at_ms=requested_ms,
            received_at_ms=received_ms,
            source_name="instruments",
            persisted_at_ms=instrument.witness.acknowledged_at_ms,
        )
    )

    book = _capture(reader, evedex_book_observation_id)
    book_capture = _unique_json(book.record)
    try:
        depth = parse_raw_response_capture(
            book_capture,
            source="depth",
            expected_query={"maxLevel": _depth_max_level(book_capture)},
            instrument=venue_symbol,
        )
    except Exception as exc:
        raise NativeStageProjectionError("EVEDEX depth capture fails its exact fixed-route parser") from exc
    if not 200 <= book_capture["status"] < 300 or not isinstance(depth, dict):
        raise NativeStageProjectionError("captured EVEDEX depth is unavailable or malformed")
    timestamp = depth.get("t")
    if isinstance(timestamp, Decimal) and timestamp == timestamp.to_integral_value():
        timestamp = int(timestamp)
    if type(timestamp) is not int or timestamp < 0:
        raise NativeStageProjectionError("EVEDEX depth has no exact original venue timestamp")
    requested_ms, received_ms = _http_clocks(book_capture)
    receipts.append(
        _receipt(
            stage="EVEDEX_BOOK",
            observation_id=evedex_book_observation_id,
            content=book.record,
            source_timestamp_ms=timestamp,
            requested_at_ms=requested_ms,
            received_at_ms=received_ms,
            source_name="depth",
            persisted_at_ms=book.witness.acknowledged_at_ms,
        )
    )
    return NativeSourceStageProjection(tuple(receipts))


def project_native_composition_stages(
    *,
    composition: object,
    reader: NativeCaptureSessionReader,
    source_stages: tuple[LiveInputStageReceiptV1, ...],
    macro_stages: tuple[LiveInputStageReceiptV1, ...] = (),
) -> NativeSourceStageProjection:
    """Project exact persisted native emissions into existing native output stages.

    Every composition emission must still be present byte-for-byte in the same
    read-only session and bound by its original fsync witness. DTO bytes are
    projected only after equality with the exact original emitted payload.
    """
    from .production_native_composition import NativeUpstreamCompositionResult

    if type(composition) is not NativeUpstreamCompositionResult:
        raise TypeError("the exact native upstream composition result is required")
    if type(reader) is not NativeCaptureSessionReader:
        raise TypeError("the read-only native capture session reader is required")
    if not isinstance(source_stages, tuple):
        raise TypeError("the exact typed source-stage projection is required")
    if not isinstance(macro_stages, tuple):
        raise TypeError("Macro stages must be a typed tuple")

    intent = composition.review.intent
    records_by_stage: dict[str, tuple[str, dict[str, Any], NativeCaptureStoredObservation]] = {}
    text_extractions: list[NativeCaptureStoredObservation] = []
    calls_by_id: dict[str, dict[str, bytes]] = {}
    expected_raw = set(composition.emission_records)
    found_raw: set[bytes] = set()
    for observation_id in reader.observation_ids():
        stored = _capture(reader, observation_id)
        try:
            record = _unique_json(stored.record)
        except NativeStageProjectionError:
            # Other native capture formats in the same session are not upstream
            # emissions; their own parsers own their schema.
            continue
        if record.get("version") != "kairos.native-upstream-emission.v1":
            if record.get("kind") == "SENTIMENT_EXTRACTION":
                text_extractions.append(stored)
            if record.get("version") == "kairos.llm-application-call-evidence.v1":
                call_id, phase = record.get("call_id"), record.get("phase")
                if isinstance(call_id, str) and phase in {"ATTEMPT_STARTED", "COMPLETED"}:
                    calls_by_id.setdefault(call_id, {})[phase] = stored.record
            continue
        if set(record) != {"version", "capture_scope", "intent_id", "stage", "observed_at_ms", "payload"}:
            raise NativeStageProjectionError("native upstream emission has unknown or missing fields")
        if (
            record["capture_scope"] != "native-output-not-authority"
            or record["intent_id"] != intent.intent_id
        ):
            continue
        stage = record["stage"]
        if not isinstance(stage, str) or stage in records_by_stage:
            raise NativeStageProjectionError("native upstream emission stage is absent or duplicated")
        expected_id = hashlib.sha256(f"{intent.intent_id}:{stage}".encode()).hexdigest()[:32]
        if expected_id != observation_id:
            raise NativeStageProjectionError(
                "native upstream emission ID does not bind its original intent/stage"
            )
        records_by_stage[stage] = (observation_id, record, stored)
        found_raw.add(stored.record)
    if found_raw != expected_raw:
        raise NativeStageProjectionError(
            "composition emissions differ from exact persisted create-only records"
        )

    def emission(stage: str) -> tuple[str, dict[str, Any], NativeCaptureStoredObservation]:
        try:
            observation_id, record, stored = records_by_stage[stage]
        except KeyError as exc:
            raise NativeStageProjectionError(f"persisted native emission is missing: {stage}") from exc
        if type(record["observed_at_ms"]) is not int or record["observed_at_ms"] < 0:
            raise NativeStageProjectionError("native emission observation clock is invalid")
        if stored.witness.acknowledged_at_ms < record["observed_at_ms"]:
            raise NativeStageProjectionError("native emission witness predates its original observation")
        return observation_id, record, stored

    projected: list[LiveInputStageReceiptV1] = []
    text_source_ids = tuple(
        sorted(stage.receipt_id for stage in source_stages if stage.stage == "TEXT_SOURCE")
    )
    context_text = next(source for source in composition.context.sources if source.kind == "text")
    if context_text.availability == "UNAVAILABLE":
        projected.append(_unavailable("TEXT_AGGREGATE", context_text.reason_code or "TEXT_UNAVAILABLE"))
    else:
        observation_id, record, stored = emission("TEXT_OUTPUT")
        expected_items = [signal.model_dump(mode="json") for signal in composition.text_signals]
        payload = record["payload"]
        if payload != {"items": expected_items} or context_text.payloads_json is None:
            raise NativeStageProjectionError(
                "persisted Text emission differs from native composition/context"
            )
        content = canonical_json_bytes(payload)
        if context_text.payloads_json.encode("utf-8") != content:
            raise NativeStageProjectionError(
                "native Text output differs from exact DecisionContext source bytes"
            )
        output_origin = _text_output_origin(
            text_extractions=text_extractions,
            calls_by_id=calls_by_id,
            expected_signals=composition.text_signals,
        )
        projected.append(
            _receipt(
                stage="TEXT_AGGREGATE",
                observation_id=observation_id,
                content=content,
                source_timestamp_ms=composition.context.captured_at_ms,
                persisted_at_ms=stored.witness.acknowledged_at_ms,
                output_origin=output_origin,
                parent_receipt_ids=text_source_ids,
            )
        )

    route_id, route_record, route_stored = emission("ROUTER_OUTPUT")
    route_bytes = canonical_json_bytes(composition.route)
    if canonical_json_bytes(route_record["payload"]) != route_bytes:
        raise NativeStageProjectionError("persisted Router output differs from composed route DTO")
    projected.append(
        _receipt(
            stage="ROUTER_OUTPUT",
            observation_id=route_id,
            content=route_bytes,
            source_timestamp_ms=composition.route.routed_at_ms,
            persisted_at_ms=route_stored.witness.acknowledged_at_ms,
        )
    )

    review_id, review_record, review_stored = emission("REVIEW_OUTPUT")
    review_bytes = canonical_json_bytes(composition.review)
    if canonical_json_bytes(review_record["payload"]) != review_bytes:
        raise NativeStageProjectionError("persisted review output differs from composed review DTO")
    projected.append(
        _receipt(
            stage="REVIEW_OUTPUT",
            observation_id=review_id,
            content=review_bytes,
            source_timestamp_ms=composition.review.reviewed_at_ms,
            persisted_at_ms=review_stored.witness.acknowledged_at_ms,
        )
    )

    context_id, context_record, context_stored = emission("DECISION_CONTEXT")
    context_bytes = canonical_json_bytes(composition.context)
    if canonical_json_bytes(context_record["payload"]) != context_bytes:
        raise NativeStageProjectionError("persisted DecisionContext differs from composed context DTO")
    projected.append(
        _receipt(
            stage="DECISION_CONTEXT",
            observation_id=context_id,
            content=context_bytes,
            source_timestamp_ms=composition.context.captured_at_ms,
            persisted_at_ms=context_stored.witness.acknowledged_at_ms,
        )
    )

    context_macro = next(source for source in composition.context.sources if source.kind == "macro")
    if composition.allocation is None:
        if context_macro.availability != "UNAVAILABLE":
            raise NativeStageProjectionError("absent allocation conflicts with native Macro context")
        if macro_stages:
            raise NativeStageProjectionError("absent allocation cannot carry captured Macro stages")
        unavailable_reason = context_macro.reason_code or "MACRO_UNAVAILABLE"
        projected.extend(
            (
                _unavailable(
                    "MACRO_SOURCE",
                    unavailable_reason,
                    source_name="application-context:unavailable",
                ),
                _unavailable("MACRO_ALLOCATION", unavailable_reason),
            )
        )
    else:
        if context_macro.availability != "AVAILABLE" or len(context_macro.payloads()) != 1:
            raise NativeStageProjectionError(
                "native allocation is not joined to one original Macro context item"
            )
        if (
            sum(stage.stage == "MACRO_SOURCE" and stage.status == "CAPTURED" for stage in macro_stages) != 1
            or sum(stage.stage == "MACRO_ALLOCATION" and stage.status == "CAPTURED" for stage in macro_stages)
            != 1
        ):
            raise NativeStageProjectionError(
                "captured Macro allocation requires its exact application-input/output capture pair"
            )
        macro_source = next(stage for stage in macro_stages if stage.stage == "MACRO_SOURCE")
        macro_allocation = next(stage for stage in macro_stages if stage.stage == "MACRO_ALLOCATION")
        if macro_allocation.content_sha256 != hashlib.sha256(
            canonical_json_bytes(composition.allocation)
        ).hexdigest() or macro_allocation.parent_receipt_ids != (macro_source.receipt_id,):
            raise NativeStageProjectionError(
                "captured Macro stages differ from composed allocation provenance"
            )
        macro_id, macro_record, _macro_stored = emission("MACRO_CONTEXT_SELECTION")
        macro_payload = macro_record["payload"]
        if canonical_json_bytes(macro_payload.get("allocation")) != canonical_json_bytes(
            composition.allocation
        ) or canonical_json_bytes(context_macro.payloads()[0]) != canonical_json_bytes(
            composition.allocation
        ):
            raise NativeStageProjectionError("persisted Macro selection differs from exact native allocation")
        if canonical_json_bytes(macro_payload.get("allocation")) != canonical_json_bytes(
            composition.allocation
        ):
            raise NativeStageProjectionError("persisted Macro selection differs from composed allocation")

    return NativeSourceStageProjection((*source_stages, *macro_stages, *projected))


def project_native_macro_stages(
    *,
    reader: NativeCaptureSessionReader,
    input_observation_id: str,
    output_observation_id: str,
    expected_allocation: StrategicAllocation,
) -> NativeMacroStageProjection:
    """Join Macro's original application context and allocation captures.

    The Macro boundary explicitly records application input, not provider HTTP
    or underlying market/account truth. Model call receipts remain a separate
    projection from the retained budgeted gateway records.
    """
    input_stored = _capture(reader, input_observation_id)
    output_stored = _capture(reader, output_observation_id)
    input_record = _unique_json(input_stored.record)
    output_record = _unique_json(output_stored.record)
    if set(input_record) != {
        "version",
        "capture_scope",
        "capture_id",
        "accepted_at_ms",
        "trigger",
        "source",
        "identity",
        "context_utf8",
    }:
        raise NativeStageProjectionError("Macro application-input capture shape is invalid")
    if set(output_record) != {
        "version",
        "capture_scope",
        "capture_id",
        "input_record_sha256",
        "observed_at_ms",
        "output_origin",
        "allocation",
        "allocation_sha256",
    }:
        raise NativeStageProjectionError("Macro application-output capture shape is invalid")
    capture_id = input_record["capture_id"]
    if (
        input_record["version"] != "kairos.native-macro-application-input.v1"
        or input_record["capture_scope"] != "EXACT_APPLICATION_CONTEXT_NOT_PROVIDER_HTTP"
        or output_record["version"] != "kairos.native-macro-application-output.v1"
        or output_record["capture_scope"] != "EXACT_APPLICATION_OUTPUT_NOT_PROVIDER_HTTP"
        or not isinstance(capture_id, str)
        or not re.fullmatch(r"[a-f0-9]{32}", capture_id)
        or output_record["capture_id"] != capture_id
        or output_observation_id
        != hashlib.sha256((capture_id + ":allocation").encode("ascii")).hexdigest()[:32]
        or output_record["input_record_sha256"] != hashlib.sha256(input_stored.record).hexdigest()
        or input_observation_id != capture_id
    ):
        raise NativeStageProjectionError("Macro input/output captures do not form one original causal pair")
    accepted = input_record["accepted_at_ms"]
    observed = output_record["observed_at_ms"]
    if (
        type(accepted) is not int
        or type(observed) is not int
        or accepted < 0
        or observed < accepted
        or input_stored.witness.acknowledged_at_ms < accepted
        or output_stored.witness.acknowledged_at_ms < observed
    ):
        raise NativeStageProjectionError("Macro application/persistence clocks are invalid or out of order")
    source, trigger, identity = (
        input_record.get("source"),
        input_record.get("trigger"),
        input_record.get("identity"),
    )
    context_obj = input_record.get("context_utf8")
    if not isinstance(source, str) or not isinstance(trigger, str) or not isinstance(identity, dict):
        raise NativeStageProjectionError("Macro application source/trigger/identity is malformed")
    allowed_identity = {"message_id", "correlation_id", "causation_id"}
    if (
        set(identity) - allowed_identity
        or not isinstance(identity.get("message_id"), str)
        or not identity["message_id"]
        or identity["message_id"] != identity["message_id"].strip()
        or len(identity["message_id"]) > 512
        or any(
            not isinstance(value, str) or not value or value != value.strip() or len(value) > 512
            for value in identity.values()
        )
        or not source
        or source != source.strip()
        or len(source) > 160
        or trigger not in {item.value for item in StrategicTrigger}
    ):
        raise NativeStageProjectionError("Macro application identity/source/trigger is not allowed")
    if not isinstance(context_obj, dict) or set(context_obj) != {"base64", "sha256"}:
        raise NativeStageProjectionError("Macro original application context bytes are absent")
    try:
        context_bytes = base64.b64decode(context_obj["base64"], validate=True)
        context_bytes.decode("utf-8", errors="strict")
    except (ValueError, TypeError, UnicodeError) as exc:
        raise NativeStageProjectionError("Macro original context is not exact UTF-8/base64") from exc
    if (
        not context_bytes
        or len(context_bytes) > 1_000_000
        or hashlib.sha256(context_bytes).hexdigest() != context_obj["sha256"]
    ):
        raise NativeStageProjectionError("Macro original context digest or size differs")
    try:
        allocation = StrategicAllocation.model_validate(output_record["allocation"])
    except Exception as exc:
        raise NativeStageProjectionError("Macro output capture lacks its native allocation DTO") from exc
    allocation_bytes = canonical_json_bytes(allocation)
    if (
        canonical_json_bytes(allocation) != canonical_json_bytes(expected_allocation)
        or hashlib.sha256(allocation_bytes).hexdigest() != output_record["allocation_sha256"]
        or canonical_json_bytes(allocation.model_dump(mode="json"))
        != canonical_json_bytes(output_record["allocation"])
        or any(getattr(allocation, key) != value for key, value in identity.items())
        or allocation.source != source
        or allocation.triggered_by.value != trigger
        or int(allocation.produced_at.timestamp() * 1_000) < accepted
        or int(allocation.produced_at.timestamp() * 1_000) > observed
    ):
        raise NativeStageProjectionError(
            "Macro allocation differs from its original application context identity"
        )
    if output_record["output_origin"] not in {"NATIVE_MODEL", "NATIVE_DETERMINISTIC_FALLBACK"}:
        raise NativeStageProjectionError("Macro capture has an unknown native output origin")
    model_calls: tuple[NativeCallRecordPair, ...] = ()
    if output_record["output_origin"] == "NATIVE_MODEL":
        model_calls = _persisted_macro_call_pair(
            reader=reader,
            context_bytes=context_bytes,
            input_witness_ms=input_stored.witness.acknowledged_at_ms,
            output_observed_ms=observed,
            output_witness_ms=output_stored.witness.acknowledged_at_ms,
            output_sha256=hashlib.sha256(allocation_bytes).hexdigest(),
            expected_allocation=allocation,
        )
    source_name = f"application-context:{source}:{trigger}"
    if len(source_name) > 160:
        raise NativeStageProjectionError("Macro application source identity exceeds its stage bound")
    source_receipt = _receipt(
        stage="MACRO_SOURCE",
        observation_id=input_observation_id,
        content=context_bytes,
        source_timestamp_ms=accepted,
        requested_at_ms=accepted,
        received_at_ms=accepted,
        source_name=source_name,
        persisted_at_ms=input_stored.witness.acknowledged_at_ms,
    )
    allocation_receipt = _receipt(
        stage="MACRO_ALLOCATION",
        observation_id=output_observation_id,
        content=allocation_bytes,
        source_timestamp_ms=int(allocation.produced_at.timestamp() * 1_000),
        persisted_at_ms=output_stored.witness.acknowledged_at_ms,
        output_origin=cast(_OutputOrigin, output_record["output_origin"]),
        parent_receipt_ids=(source_receipt.receipt_id,),
    )
    return NativeMacroStageProjection((source_receipt, allocation_receipt), model_calls)


def _persisted_macro_call_pair(
    *,
    reader: NativeCaptureSessionReader,
    context_bytes: bytes,
    input_witness_ms: int,
    output_observed_ms: int,
    output_witness_ms: int,
    output_sha256: str,
    expected_allocation: StrategicAllocation,
) -> tuple[NativeCallRecordPair, ...]:
    """Find and validate exactly the persisted Macro workload call for an output."""
    grouped: dict[str, dict[str, tuple[str, bytes, int]]] = {}
    for observation_id in reader.observation_ids():
        stored = _capture(reader, observation_id)
        try:
            record = _unique_json(stored.record)
        except NativeStageProjectionError:
            continue
        if record.get("version") != "kairos.llm-application-call-evidence.v1":
            continue
        workload, call_id, phase = record.get("workload"), record.get("call_id"), record.get("phase")
        if phase == "COMPLETED":
            workload = "macro_strategist"  # completed wire record binds workload via its attempt
        if isinstance(call_id, str) and phase in {"ATTEMPT_STARTED", "COMPLETED"}:
            grouped.setdefault(call_id, {})[phase] = (
                observation_id,
                stored.record,
                stored.witness.acknowledged_at_ms,
            )
            if phase == "ATTEMPT_STARTED" and workload != "macro_strategist":
                grouped[call_id]["not_macro"] = (
                    observation_id,
                    stored.record,
                    stored.witness.acknowledged_at_ms,
                )

    candidates: list[tuple[NativeCallRecordPair, int]] = []
    for call_id, parts in grouped.items():
        started = parts.get("ATTEMPT_STARTED")
        completed = parts.get("COMPLETED")
        if started is None or completed is None or "not_macro" in parts:
            continue
        try:
            call = read_native_budgeted_call(started[1], completed[1])
        except ValueError:
            continue
        if call.native_workload != "macro_strategist":
            continue
        try:
            from kairos_macro.strategist import (  # type: ignore[import-not-found,import-untyped]
                AllocationOutput,
            )

            model_output = AllocationOutput.model_validate_json(call.response)
        except Exception as exc:
            raise NativeStageProjectionError(
                "persisted Macro call response is not its native output schema"
            ) from exc
        expected_started_id = hashlib.sha256(f"llm:{call_id}:started".encode()).hexdigest()[:32]
        expected_completed_id = hashlib.sha256(f"llm:{call_id}:completed".encode()).hexdigest()[:32]
        prompt = _unique_json(call.prompt)
        if (
            started[0] != expected_started_id
            or completed[0] != expected_completed_id
            or set(prompt) != {"system", "user"}
            or not isinstance(prompt.get("user"), str)
            or prompt["user"].encode("utf-8") != context_bytes
            or model_output.regime != expected_allocation.regime
            or model_output.stable_reserve_pct != expected_allocation.stable_reserve_pct
            or {item.strategy_name: item.weight for item in model_output.strategy_weights}
            != expected_allocation.strategy_weights
            or model_output.max_gross_leverage != expected_allocation.max_gross_leverage
            or model_output.rationale != expected_allocation.rationale
            or input_witness_ms > call.started_at_ms
            or call.committed_at_ms > output_observed_ms
            or started[2] > output_observed_ms
            or completed[2] > output_observed_ms
            or completed[2] < call.committed_at_ms
        ):
            continue
        pair = NativeCallRecordPair(
            attempt_record=started[1],
            completion_record=completed[1],
            bound_output_sha256=output_sha256,
            captured_at_ms=completed[2],
        )
        candidates.append((pair, call.started_at_ms))
    if len(candidates) != 1:
        raise NativeStageProjectionError(
            "native Macro model output requires one persisted call pair bound to the exact input/output"
        )
    return (candidates[0][0],)


def project_native_binance_reference_stage(
    *,
    reader: NativeCaptureSessionReader,
    observation_id: str,
    expected_symbol: str,
) -> LiveInputStageReceiptV1:
    """Project one retained fixed-host Binance depth response, without I/O."""
    from .production_binance_capture import BINANCE_DEPTH_URL, BinanceDepthCaptureV1

    if not isinstance(expected_symbol, str) or expected_symbol not in {
        "BTCUSDT",
        "ETHUSDT",
        "SOLUSDT",
        "BNBUSDT",
        "XRPUSDT",
    }:
        raise NativeStageProjectionError("Binance reference symbol is outside the fixed source universe")
    stored = _capture(reader, observation_id)
    raw_record = _unique_json(stored.record)
    try:
        capture = BinanceDepthCaptureV1.model_validate(raw_record)
    except Exception as exc:
        raise NativeStageProjectionError("retained Binance capture does not match its strict schema") from exc
    if canonical_json_bytes(capture) != stored.record:
        raise NativeStageProjectionError("retained Binance capture is not the exact canonical wrapper")
    expected_query = {"limit": "100", "symbol": expected_symbol}
    if (
        capture.source != "BINANCE_REFERENCE"
        or capture.method != "GET"
        or capture.url != BINANCE_DEPTH_URL
        or capture.symbol != expected_symbol
        or capture.request_query_json != json.dumps(expected_query, sort_keys=True, separators=(",", ":"))
        or capture.requested_url != f"{BINANCE_DEPTH_URL}?symbol={expected_symbol}&limit=100"
        or capture.status != 200
        or not capture.requested_at_ms <= capture.received_at_ms
        or capture.received_at_ms < capture.source_timestamp_ms
        or stored.witness.acknowledged_at_ms < capture.received_at_ms
    ):
        raise NativeStageProjectionError("Binance capture route, symbol, or source/persistence clocks differ")
    try:
        body = base64.b64decode(capture.body_base64, validate=True)
    except (ValueError, TypeError) as exc:
        raise NativeStageProjectionError("Binance capture body is not exact base64") from exc
    if not body or len(body) != capture.body_bytes or hashlib.sha256(body).hexdigest() != capture.body_sha256:
        raise NativeStageProjectionError("Binance original body size or digest differs")
    payload = _decoded_unique_json(body)
    observed_field = "T" if payload.get("T") else "E"
    observed_timestamp = payload.get(observed_field)
    if (
        observed_field != capture.source_timestamp_field
        or type(observed_timestamp) is not int
        or observed_timestamp != capture.source_timestamp_ms
    ):
        raise NativeStageProjectionError("Binance source timestamp is not the exact original T/E field")
    try:
        from kairos_quant.venue_comparison import (  # type: ignore[import-not-found,import-untyped]
            parse_binance_book,
        )

        book = parse_binance_book(expected_symbol, payload, latency_ms=0.0)
    except Exception as exc:
        raise NativeStageProjectionError("Binance original depth body fails the native Quant parser") from exc
    if getattr(book, "timestamp_ms", None) != capture.source_timestamp_ms:
        raise NativeStageProjectionError("Binance parsed book clock differs from its original T/E timestamp")
    return _receipt(
        stage="BINANCE_REFERENCE",
        observation_id=observation_id,
        content=stored.record,
        source_timestamp_ms=capture.source_timestamp_ms,
        requested_at_ms=capture.requested_at_ms,
        received_at_ms=capture.received_at_ms,
        source_name="BINANCE_REFERENCE",
        persisted_at_ms=stored.witness.acknowledged_at_ms,
    )


def _http_clocks(capture: dict[str, Any]) -> tuple[int, int]:
    from datetime import UTC, datetime

    def ms(value: object) -> int:
        if not isinstance(value, str):
            raise NativeStageProjectionError("native HTTP capture lacks its original UTC clock")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise NativeStageProjectionError("native HTTP capture clock is malformed") from exc
        if parsed.utcoffset() != UTC.utcoffset(parsed) or parsed.microsecond % 1_000:
            raise NativeStageProjectionError("native HTTP capture clock is not exact UTC milliseconds")
        delta = parsed - datetime(1970, 1, 1, tzinfo=UTC)
        return (delta.days * 86_400 + delta.seconds) * 1_000 + delta.microseconds // 1_000

    requested, received = ms(capture.get("requested_at")), ms(capture.get("received_at"))
    if received < requested:
        raise NativeStageProjectionError("native HTTP capture clocks moved backwards")
    return requested, received


def _text_output_origin(
    *,
    text_extractions: list[NativeCaptureStoredObservation],
    calls_by_id: dict[str, dict[str, bytes]],
    expected_signals: tuple[SentimentSignal, ...],
) -> _OutputOrigin:
    """Re-run the native extraction parser and preserve its actual output origin."""
    expected = [signal.model_dump(mode="json") for signal in expected_signals]
    matching: list[tuple[NativeCaptureStoredObservation, dict[str, Any]]] = []
    for stored in text_extractions:
        record = _unique_json(stored.record)
        encoded = record.get("output")
        if not isinstance(encoded, dict) or not isinstance(encoded.get("base64"), str):
            continue
        try:
            output = _unique_json(base64.b64decode(encoded["base64"], validate=True))
        except (ValueError, TypeError):
            continue
        if output.get("signals") == expected:
            matching.append((stored, record))
    if len(matching) != 1:
        raise NativeStageProjectionError("native Text output lacks one exact persisted extraction capture")

    stored, record = matching[0]
    origin = record.get("output_origin")
    attempt = completion = None
    if origin == "NATIVE_MODEL":
        model_result = record.get("model_result")
        request_id = model_result.get("request_id") if isinstance(model_result, dict) else None
        candidates = []
        from .production_native_inputs import read_native_budgeted_call

        for phases in calls_by_id.values():
            started = phases.get("ATTEMPT_STARTED")
            completed = phases.get("COMPLETED")
            if started is None or completed is None:
                continue
            try:
                call = read_native_budgeted_call(started, completed)
            except ValueError:
                continue
            if call.request_id == request_id and call.native_workload == "text_scouts":
                candidates.append((started, completed))
        if len(candidates) != 1:
            raise NativeStageProjectionError("native Text model output lacks one exact persisted call pair")
        attempt, completion = candidates[0]
    try:
        parsed = read_native_sentiment_extraction(
            stored.record,
            attempt_record=attempt,
            completion_record=completion,
        )
    except ValueError as exc:
        raise NativeStageProjectionError(
            "persisted native Text extraction does not reproduce its output"
        ) from exc
    if tuple(parsed.signals) != expected_signals:
        raise NativeStageProjectionError("native Text extraction output differs from composition")
    return cast(_OutputOrigin, parsed.output_origin)


def _depth_max_level(capture: dict[str, Any]) -> int:
    try:
        query = json.loads(capture["query_json"])
        value = int(query["maxLevel"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise NativeStageProjectionError("EVEDEX depth capture lacks its exact fixed query") from exc
    if str(value) != query.get("maxLevel") or not 1 <= value <= 100:
        raise NativeStageProjectionError("EVEDEX depth query is outside its fixed bound")
    return value


__all__ = [
    "NativeStageProjectionError",
    "NativeSourceStageProjection",
    "project_native_source_stages",
    "project_native_composition_stages",
    "project_native_macro_stages",
    "project_native_binance_reference_stage",
]
