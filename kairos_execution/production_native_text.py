"""Read the actual native Text observations; never fabricate persistence clocks.

These parsers establish exact original-body/native-parse and native model-call
joins. A source/capture process still requires independent signed acceptance;
neither a schema nor this replay check makes caller-created bytes authoritative.
Native Text dependencies are loaded only when a parser is explicitly invoked.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlsplit

from kairos_core.contracts import SentimentSignal, canonical_json_bytes

from .production_native_inputs import (
    NativeBudgetedCall,
    _decode,
    _fields,
    _identifier,
    _integer,
    _json,
    read_native_budgeted_call,
)

_BASE_FIELDS = {"version", "observation_id", "kind", "capture_scope", "captured_at_ms"}


def _record(raw: bytes, kind: str, extra_fields: set[str]) -> dict:
    payload = _fields(_json(raw, max_bytes=4_000_000), _BASE_FIELDS | extra_fields)
    if (
        payload["version"] != "kairos.text-native-evidence.v1"
        or payload["capture_scope"] != "application-boundary"
        or payload["kind"] != kind
        or not re.fullmatch(r"[a-f0-9]{32}", _identifier(payload["observation_id"]))
    ):
        raise ValueError("not the original native Text observation schema")
    _integer(payload["captured_at_ms"])
    return payload


@dataclass(frozen=True, slots=True)
class NativeRssResponse:
    record: bytes
    observation_id: str
    source_name: str
    requested_at_ms: int
    received_at_ms: int
    captured_at_ms: int
    response_body: bytes
    parsed_items: bytes
    # Deliberately no persisted_at_ms: only the session store can witness it.


def read_native_rss_response(raw: bytes) -> NativeRssResponse:
    """Verify exact native parser bytes from the retained decompressed RSS body."""
    payload = _record(
        raw,
        "RSS_RESPONSE",
        {
            "source_name",
            "source_kind",
            "method",
            "response_status",
            "response_encoding",
            "body_representation",
            "requested_at_ms",
            "received_at_ms",
            "response_body",
            "parsed_items",
        },
    )
    source = _identifier(payload["source_name"])
    url = urlsplit(source)
    if (
        url.scheme != "https"
        or not url.hostname
        or url.username is not None
        or url.password is not None
        or payload["source_kind"] != "rss"
        or payload["method"] != "GET"
        or type(payload["response_status"]) is not int
        or payload["response_status"] != 200
        or payload["body_representation"] != "decompressed-http-response-before-text-decoding"
    ):
        raise ValueError("native RSS source is unavailable or not the configured original HTTPS GET")
    requested = _integer(payload["requested_at_ms"])
    received = _integer(payload["received_at_ms"])
    captured = _integer(payload["captured_at_ms"])
    if not requested <= received <= captured:
        raise ValueError("original native RSS capture clocks moved backwards")
    body = _decode(payload["response_body"], utf8=False)
    if len(body) > 1_000_000:
        raise ValueError("original native RSS body exceeds its bound")
    items = _decode(payload["parsed_items"])
    encoding = _identifier(payload["response_encoding"])
    from kairos_text.native_capture import news_items_bytes  # type: ignore[import-not-found,import-untyped]
    from kairos_text.sources.rss import RSSSource  # type: ignore[import-not-found,import-untyped]

    parsed = RSSSource._parse(body.decode(encoding, errors="strict"), source)
    if news_items_bytes(parsed) != items:
        raise ValueError("retained RSS parsed items differ from actual native source-body parsing")
    # A publication clock is source data; it must not be substituted by request
    # or capture time. Old publications remain old and downstream TTLs still apply.
    if any(int(item.published_at.timestamp() * 1_000) > received for item in parsed):
        raise ValueError("native RSS publication is future-dated at original response receipt")
    return NativeRssResponse(
        raw, payload["observation_id"], source, requested, received, captured, body, items
    )


@dataclass(frozen=True, slots=True)
class NativeSentimentExtraction:
    record: bytes
    observation_id: str
    captured_at_ms: int
    input_items: bytes
    output: bytes
    signals: tuple[SentimentSignal, ...]
    model_call: NativeBudgetedCall | None
    output_origin: str


def read_native_sentiment_extraction(
    raw: bytes,
    *,
    attempt_record: bytes | None = None,
    completion_record: bytes | None = None,
) -> NativeSentimentExtraction:
    """Join exact Text prompt/schema/result/output capture to native budgeted records.

    Deterministic failure remains explicit and cannot claim a successful call.
    Failed/unknown reservations are never released, reconstructed or relabelled.
    The capture records preserve the native output transform, not a new model call.
    """
    payload = _record(
        raw,
        "SENTIMENT_EXTRACTION",
        {
            "input_items",
            "prompt",
            "output",
            "output_origin",
            "extractor_source",
            "model_result",
            "fallback_reason_code",
        },
    )
    input_items = _decode(payload["input_items"])
    output = _decode(payload["output"])
    from kairos_text.models import NewsItem  # type: ignore[import-not-found,import-untyped]
    from kairos_text.native_capture import news_items_bytes  # type: ignore[import-not-found,import-untyped]
    from kairos_text.prompts import SENTIMENT_SYSTEM  # type: ignore[import-not-found,import-untyped]
    from kairos_text.schemas import SentimentBatch  # type: ignore[import-not-found,import-untyped]
    from kairos_text.sentiment import SentimentExtractor  # type: ignore[import-not-found,import-untyped]

    try:
        decoded_inputs = _fields(_json(input_items), {"items"})
        input_values = decoded_inputs["items"]
        if not isinstance(input_values, list) or not 1 <= len(input_values) <= 512:
            raise ValueError("bounded native input NewsItems are required")
        native_items = []
        for value in input_values:
            fields = dict(value)
            fields["published_at"] = datetime.fromisoformat(fields["published_at"])
            fields["provenance"] = tuple(fields["provenance"])
            native_items.append(NewsItem(**fields))
        if news_items_bytes(native_items) != input_items:
            raise ValueError("native Text input capture differs from exact NewsItem bytes")
    except (json.JSONDecodeError, TypeError, KeyError, UnicodeError) as exc:
        raise ValueError("invalid native Text NewsItem capture") from exc
    try:
        decoded_output = _fields(_json(output), {"signals"})
        values = decoded_output["signals"]
        if not isinstance(values, list) or len(values) > 512:
            raise ValueError("bounded original native Text output items are required")
        signals = tuple(SentimentSignal.model_validate(value) for value in values)
        serialized_values = [signal.model_dump(mode="json") for signal in signals]
        expected_output = canonical_json_bytes({"signals": serialized_values})
        if output != expected_output or len({signal.message_id for signal in signals}) != len(signals):
            raise ValueError("native Text output bytes or identities differ from retained exact DTOs")
    except (json.JSONDecodeError, TypeError, UnicodeError) as exc:
        raise ValueError("invalid native Text output capture") from exc
    captured = payload["captured_at_ms"]
    if any(int(signal.produced_at.timestamp() * 1_000) > captured for signal in signals):
        raise ValueError("native Text event clock postdates its original extraction capture")
    prompt = _fields(payload["prompt"], {"system_utf8", "user_utf8", "schema_json"})
    system, user, schema = (_decode(prompt[name]) for name in ("system_utf8", "user_utf8", "schema_json"))
    _json(schema)
    if (
        system != SENTIMENT_SYSTEM.encode("utf-8")
        or user != SentimentExtractor(None)._format_batch(native_items).encode("utf-8")
        or schema != canonical_json_bytes(SentimentBatch.model_json_schema())
    ):
        raise ValueError("native Text prompt/schema does not equal its actual native input formatting")
    call = None
    extractor_source = _identifier(payload["extractor_source"])
    if payload["output_origin"] == "NATIVE_DETERMINISTIC_FALLBACK":
        if (
            payload["model_result"] is not None
            or payload["fallback_reason_code"] != "PROVIDER_OR_SCHEMA_FAILURE"
            or attempt_record is not None
            or completion_record is not None
        ):
            raise ValueError("native fallback cannot claim a completed model call")
        from kairos_text.local import local_sentiment  # type: ignore[import-not-found,import-untyped]

        native_output = local_sentiment(native_items, source=f"{extractor_source}:local")
    elif payload["output_origin"] == "NATIVE_MODEL":
        if payload["fallback_reason_code"] is not None or attempt_record is None or completion_record is None:
            raise ValueError("native model extraction requires its actual original completed call records")
        call = read_native_budgeted_call(attempt_record, completion_record)
        result = _fields(
            payload["model_result"],
            {
                "provider",
                "model",
                "resolved_model",
                "request_id",
                "budget_reservation_id",
                "effort",
                "cached",
                "cache_scope",
                "content_utf8",
                "usage",
                "attempt_started_at_ts_ms",
                "response_observed_at_ts_ms",
            },
        )
        attempt = _json(attempt_record)
        completion = _json(completion_record)
        native_provider = completion["provider_call"]
        expected_result = {
            "provider": native_provider["provider"],
            "model": native_provider["model"],
            "resolved_model": native_provider["resolved_model"],
            "request_id": call.request_id,
            "budget_reservation_id": call.reservation_id,
            "effort": call.reasoning_effort,
            "cached": native_provider["cached"],
            "cache_scope": native_provider["cache_scope"],
            "content_utf8": completion["response"]["content_utf8"],
            "usage": completion["token_usage"],
            "attempt_started_at_ts_ms": call.started_at_ms,
            "response_observed_at_ts_ms": call.response_at_ms,
        }
        if (
            call.native_workload != "text_scouts"
            or canonical_json_bytes(result) != canonical_json_bytes(expected_result)
            or call.prompt != canonical_json_bytes({"system": system.decode(), "user": user.decode()})
            or schema != _decode(attempt["request"]["schema_canonical_json_utf8"])
            or call.committed_at_ms > captured
        ):
            raise ValueError("native Text capture differs from its exact original budgeted model call")
        batch = SentimentBatch.model_validate_json(call.response)
        native_output = SentimentExtractor(None, source=extractor_source)._signals_from_batch(
            native_items, batch
        )
    else:
        raise ValueError("unknown native Text output origin")
    if (
        canonical_json_bytes({"signals": [signal.model_dump(mode="json") for signal in native_output]})
        != output
    ):
        raise ValueError("native Text output differs from actual unchanged model/fallback transformation")
    return NativeSentimentExtraction(
        raw, payload["observation_id"], captured, input_items, output, signals, call, payload["output_origin"]
    )


__all__ = [
    "NativeRssResponse",
    "NativeSentimentExtraction",
    "read_native_rss_response",
    "read_native_sentiment_extraction",
]
