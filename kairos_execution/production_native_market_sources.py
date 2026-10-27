"""Replay original Quant market/bar captures before native input preparation.

These receipts join the actual retained raw public inputs to the exact
``DecisionContext`` deliveries. They are producer-side source lineage, not
Binance authentication, strategy authority, or producer qualification.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import parse_qs, urlsplit

from kairos_core.contracts import ClosedBarEventV1, MarketSnapshot, canonical_json_bytes, canonical_sha256
from kairos_core.contracts.decision_context import DecisionContextV1
from kairos_core.topics import Topics

from .production_inputs import LiveInputStageReceiptV1
from .production_native_capture_store import NativeCaptureSessionReader, NativeCaptureStoredObservation
from .production_native_source_stages import NativeStageProjectionError

_RAW_DOMAIN = b"kairos.quant-source-capture.v1\x00"
_OUTPUT_DOMAIN = b"kairos.quant-derived-market-event.v1\x00"
_BINANCE_REST = "https://fapi.binance.com"
_BINANCE_WS = "wss://fstream.binance.com"
_HEX32 = re.compile(r"^[a-f0-9]{32}$")
_RAW_FIELDS = {
    "schema_version",
    "capture_scope",
    "kind",
    "source",
    "method",
    "url",
    "query_json",
    "route",
    "stream_epoch",
    "requested_at_ms",
    "received_at_ms",
    "status",
    "body_bytes",
    "body_sha256",
    "body_base64",
    "capture_epoch",
    "capture_sequence",
}
_OUTPUT_FIELDS = {
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


class NativeMarketLineageError(NativeStageProjectionError):
    """Original market/bar source lineage is missing, changed, or non-replayable."""


@dataclass(frozen=True, slots=True)
class NativeMarketBarStageProjection:
    stages: tuple[LiveInputStageReceiptV1, LiveInputStageReceiptV1]
    selection_sha256: str
    live_ready: bool = False


def _unique_json(raw: bytes, *, what: str) -> dict[str, Any]:
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
        raise NativeMarketLineageError(f"{what} is not unique-key JSON") from exc
    if not isinstance(value, dict) or canonical_json_bytes(value) != raw:
        raise NativeMarketLineageError(f"{what} is not a canonical JSON object")
    return value


def _output_id(event_kind: str, event_id: str) -> str:
    return hashlib.sha256(_OUTPUT_DOMAIN + f"{event_kind}:{event_id}".encode()).hexdigest()[:32]


def _raw(
    reader: NativeCaptureSessionReader, observation_id: str
) -> tuple[NativeCaptureStoredObservation, dict[str, Any]]:
    stored = reader.read(observation_id)
    if type(stored) is not NativeCaptureStoredObservation:
        raise NativeMarketLineageError("native capture reader returned an unexpected observation")
    if (
        stored.witness.observation_id != observation_id
        or stored.witness.record_bytes != len(stored.record)
        or stored.witness.record_sha256 != hashlib.sha256(stored.record).hexdigest()
    ):
        raise NativeMarketLineageError("native persistence witness does not bind exact Quant source bytes")
    record = _unique_json(stored.record, what="Quant raw source record")
    if set(record) != _RAW_FIELDS:
        raise NativeMarketLineageError("Quant raw source record has unknown or missing fields")
    if (
        record["schema_version"] != "kairos.quant-source-capture.v1"
        or record["capture_scope"] != "public-source-bytes-not-authority"
        or record["source"] != "BINANCE_UM"
        or record["capture_epoch"] == ""
        or not isinstance(record["capture_epoch"], str)
        or _HEX32.fullmatch(record["capture_epoch"]) is None
        or type(record["capture_sequence"]) is not int
        or record["capture_sequence"] < 1
        or type(record["received_at_ms"]) is not int
        or record["received_at_ms"] < 0
        or stored.witness.acknowledged_at_ms < record["received_at_ms"]
        or type(record["body_bytes"]) is not int
        or not 0 < record["body_bytes"] <= 1_000_000
        or not isinstance(record["body_sha256"], str)
        or re.fullmatch(r"[a-f0-9]{64}", record["body_sha256"]) is None
    ):
        raise NativeMarketLineageError(
            "Quant source identity or original receive/persistence clock is invalid"
        )
    expected_id = hashlib.sha256(_RAW_DOMAIN + stored.record).hexdigest()[:32]
    if expected_id != observation_id:
        raise NativeMarketLineageError("Quant raw source identity does not bind its exact retained bytes")
    try:
        body = base64.b64decode(record["body_base64"], validate=True)
    except (ValueError, TypeError) as exc:
        raise NativeMarketLineageError("Quant raw body is not exact base64") from exc
    if len(body) != record["body_bytes"] or hashlib.sha256(body).hexdigest() != record["body_sha256"]:
        raise NativeMarketLineageError("Quant raw body size or digest differs")
    _validate_route(record, body)
    return stored, record


def _validate_route(record: dict[str, Any], body: bytes) -> None:
    kind = record["kind"]
    if kind == "BINANCE_WS_FRAME":
        if (
            record["method"] != "WS"
            or record["route"] not in {"public", "market"}
            or not isinstance(record["stream_epoch"], str)
            or _HEX32.fullmatch(record["stream_epoch"]) is None
            or record["requested_at_ms"] is not None
            or record["query_json"] is not None
            or record["status"] is not None
            or not isinstance(record["url"], str)
        ):
            raise NativeMarketLineageError("Quant WebSocket capture fields differ from the fixed schema")
        parsed = urlsplit(record["url"])
        query = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
        if (
            parsed.scheme != "wss"
            or parsed.netloc != "fstream.binance.com"
            or parsed.path != f"/{record['route']}/stream"
            or set(query) != {"streams"}
            or len(query["streams"]) != 1
        ):
            raise NativeMarketLineageError("Quant WebSocket capture differs from official routed Binance")
        try:
            frame = _unique_json(body, what="Binance WebSocket frame")
        except NativeMarketLineageError:
            raise
        stream = frame.get("stream")
        if not isinstance(stream, str) or stream not in query["streams"][0].split("/"):
            raise NativeMarketLineageError("Binance WebSocket frame is not bound to its routed subscription")
        symbol, _, suffix = stream.partition("@")
        expected_route = "public" if suffix.startswith("depth") else "market"
        if (
            record["route"] != expected_route
            or not re.fullmatch(r"[a-z0-9]{1,32}", symbol)
            or not isinstance(frame.get("data"), dict)
        ):
            raise NativeMarketLineageError("Binance WebSocket frame has an invalid route or stream identity")
        return

    fixed = {
        "BINANCE_KLINES_REST": ("/fapi/v1/klines", {"interval", "limit", "symbol"}),
        "BINANCE_OPEN_INTEREST_REST": ("/futures/data/openInterestHist", {"limit", "period", "symbol"}),
        "BINANCE_PREMIUM_INDEX_REST": ("/fapi/v1/premiumIndex", set()),
    }
    if kind not in fixed:
        raise NativeMarketLineageError("Quant capture kind is outside the fixed Binance public allowlist")
    path, query_fields = fixed[kind]
    if (
        record["method"] != "GET"
        or record["route"] is not None
        or record["stream_epoch"] is not None
        or record["status"] != 200
        or type(record["requested_at_ms"]) is not int
        or not 0 <= record["requested_at_ms"] <= record["received_at_ms"]
        or record["url"] != _BINANCE_REST + path
        or not isinstance(record["query_json"], str)
    ):
        raise NativeMarketLineageError("Quant REST capture differs from the fixed official Binance route")
    query = _unique_json(record["query_json"].encode("utf-8"), what="Binance REST query")
    if set(query) != query_fields or any(not isinstance(value, str) for value in query.values()):
        raise NativeMarketLineageError("Binance REST query differs from its fixed route schema")


def _read_output(
    reader: NativeCaptureSessionReader,
    *,
    event_kind: str,
    event_id: str,
) -> tuple[str, NativeCaptureStoredObservation, dict[str, Any]]:
    observation_id = _output_id(event_kind, event_id)
    stored = reader.read(observation_id)
    if type(stored) is not NativeCaptureStoredObservation:
        raise NativeMarketLineageError("native capture reader returned an unexpected derived output")
    record = _unique_json(stored.record, what="Quant derived output record")
    if (
        set(record) != _OUTPUT_FIELDS
        or record["schema_version"] != "kairos.quant-derived-market-event.v1"
        or record["capture_scope"] != "native-quant-derived-output-not-authority"
        or record["event_kind"] != event_kind
        or record["event_id"] != event_id
        or type(record["output_observed_at_ms"]) is not int
        or record["output_observed_at_ms"] < 0
        or stored.witness.acknowledged_at_ms < record["output_observed_at_ms"]
        or not isinstance(record["parents"], dict)
    ):
        raise NativeMarketLineageError("Quant derived output identity/clock/schema differs")
    payload = record["event_payload"]
    if (
        not isinstance(payload, dict)
        or hashlib.sha256(canonical_json_bytes(payload)).hexdigest() != record["event_sha256"]
    ):
        raise NativeMarketLineageError("Quant derived output digest does not bind its exact DTO")
    return observation_id, stored, record


def _as_ids(value: object, *, minimum: int = 1, maximum: int = 2_000) -> tuple[str, ...]:
    values = (value,) if isinstance(value, str) else value
    if (
        not isinstance(values, (tuple, list))
        or not minimum <= len(values) <= maximum
        or any(not isinstance(item, str) or _HEX32.fullmatch(item) is None for item in values)
        or len(set(values)) != len(values)
    ):
        raise NativeMarketLineageError("Quant derived output parent identities are malformed")
    return tuple(values)


def _source_payloads(context: DecisionContextV1, kind: str) -> tuple[tuple[dict[str, Any], Any], ...]:
    source = next(item for item in context.sources if item.kind == kind)
    if source.availability != "AVAILABLE" or source.payloads_json is None:
        raise NativeMarketLineageError(f"native DecisionContext has no available original {kind} input")
    try:
        payload = json.loads(source.payloads_json)
    except (TypeError, ValueError) as exc:
        raise NativeMarketLineageError("native DecisionContext source payload is malformed") from exc
    if not isinstance(payload, dict) or set(payload) != {"items"} or not isinstance(payload["items"], list):
        raise NativeMarketLineageError("native DecisionContext source payload has an unexpected shape")
    if len(source.receipts) != len(payload["items"]):
        raise NativeMarketLineageError("native DecisionContext source receipts do not cover each DTO")
    return tuple(zip(payload["items"], source.receipts, strict=True))


def _assert_context_receipt(
    *,
    kind: str,
    payload: dict[str, Any],
    receipt: Any,
    output_observed_at_ms: int,
    captured_at_ms: int,
) -> None:
    message: MarketSnapshot | ClosedBarEventV1
    if kind == "market":
        message = MarketSnapshot.model_validate(payload)
        produced_at_ms = int(message.produced_at.timestamp() * 1_000)
        event_at_ms = produced_at_ms
    else:
        message = ClosedBarEventV1.model_validate(payload)
        produced_at_ms = int(message.produced_at.timestamp() * 1_000)
        event_at_ms = message.close_time_ms
    expected_topic = Topics.MARKET_SNAPSHOT if kind == "market" else Topics.CLOSED_BAR
    if (
        canonical_json_bytes(message.model_dump(mode="json")) != canonical_json_bytes(payload)
        or receipt.message_id != message.message_id
        or receipt.source != message.source
        or receipt.topic != expected_topic
        or receipt.content_sha256 != canonical_sha256(message)
        or receipt.event_at_ms != event_at_ms
        or receipt.produced_at_ms != produced_at_ms
        or receipt.event_at_ms > receipt.produced_at_ms
        or receipt.produced_at_ms > receipt.received_at_ms
        or receipt.received_at_ms < output_observed_at_ms
        or receipt.received_at_ms > captured_at_ms
        or receipt.ttl_ms <= 0
    ):
        raise NativeMarketLineageError(
            "exact original Quant DTO differs from its first consumer receipt or source output clock"
        )


def _profile(value: Mapping[str, int]) -> dict[str, int]:
    expected = {
        "price_window",
        "depth_levels",
        "snapshot_interval_ms",
        "kline_finality_delay_ms",
        "maximum_binance_future_skew_ms",
        "book_stale_after_ms",
        "kline_stale_after_ms",
        "derivatives_stale_after_ms",
    }
    if (
        not isinstance(value, Mapping)
        or set(value) != expected
        or any(type(item) is not int or item <= 0 for item in value.values())
    ):
        raise NativeMarketLineageError("exact bounded Quant replay configuration is required")
    return dict(value)


def _selection_sha256(
    *,
    market_output_id: str,
    bar_output_ids: tuple[str, ...],
    market_receipt: Any,
    bar_receipts: tuple[Any, ...],
    replay_profile: Mapping[str, int],
) -> str:
    return canonical_sha256(
        {
            "market_output_id": market_output_id,
            "bar_output_ids": bar_output_ids,
            "market_receipt": market_receipt.model_dump(mode="json"),
            "bar_receipts": tuple(receipt.model_dump(mode="json") for receipt in bar_receipts),
            "replay_profile": dict(replay_profile),
        }
    )


def verify_native_market_bar_selection(
    *,
    reader: NativeCaptureSessionReader,
    market: MarketSnapshot,
    bars: tuple[ClosedBarEventV1, ...],
    market_receipt: Any,
    bar_receipts: tuple[Any, ...],
    captured_at_ms: int,
    expected_replay_profile: Mapping[str, int],
) -> str:
    """Replay exact original market/bar inputs before downstream model work.

    The return is a deterministic selection digest, not a readiness or
    authority receipt. Callers should retain it only to bind the later context
    to this preflight; the final preparer repeats the replay before signing.
    """
    if (
        type(reader) is not NativeCaptureSessionReader
        or type(market) is not MarketSnapshot
        or not isinstance(bars, tuple)
        or not 1 <= len(bars) <= 1_440
        or any(type(bar) is not ClosedBarEventV1 for bar in bars)
        or not isinstance(bar_receipts, tuple)
        or len(bar_receipts) != len(bars)
        or type(captured_at_ms) is not int
        or captured_at_ms < 0
    ):
        raise NativeMarketLineageError("exact original market/bar selection and bounded clock are required")
    profile = _profile(expected_replay_profile)
    market_payload = market.model_dump(mode="json")
    market_id, market_stored, market_record = _read_output(
        reader, event_kind="MARKET_SNAPSHOT", event_id=market.message_id
    )
    if (
        market_record["event_payload"] != market_payload
        or market_record["replay_profile"] != profile
        or market_record["event_sha256"] != hashlib.sha256(canonical_json_bytes(market_payload)).hexdigest()
    ):
        raise NativeMarketLineageError("Quant market output does not equal the exact pre-model DTO/profile")
    _assert_context_receipt(
        kind="market",
        payload=market_payload,
        receipt=market_receipt,
        output_observed_at_ms=market_record["output_observed_at_ms"],
        captured_at_ms=captured_at_ms,
    )
    market_closure = _raw_parent_closure(
        reader=reader, output_record=market_record, expected_kind="MARKET_SNAPSHOT"
    )
    try:
        from kairos_quant.native_replay import (  # type: ignore[import-not-found,import-untyped]
            replay_native_quant_event,
        )

        replayed_market = replay_native_quant_event(
            event_kind="MARKET_SNAPSHOT",
            expected_payload=market_payload,
            source_records={**market_closure, market_id: market_stored.record},
            output_record=market_stored.record,
        )
    except Exception as exc:
        raise NativeMarketLineageError("original Quant market source chain failed pre-model replay") from exc
    if replayed_market != market_payload:
        raise NativeMarketLineageError("original Quant market sources differ from the exact pre-model DTO")

    bar_ids: list[str] = []
    for bar, receipt in zip(bars, bar_receipts, strict=True):
        payload = bar.model_dump(mode="json")
        if not isinstance(bar.bar_sha256, str):
            raise NativeMarketLineageError("pre-model consumer bar lacks its stable economic identity")
        observation_id, stored, record = _read_output(
            reader, event_kind="CLOSED_BAR", event_id=bar.bar_sha256
        )
        if (
            record["event_payload"] != payload
            or record["replay_profile"] != profile
            or record["event_sha256"] != hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
        ):
            raise NativeMarketLineageError(
                "Quant closed-bar output differs from the exact pre-model DTO/profile"
            )
        _assert_context_receipt(
            kind="closed_bars",
            payload=payload,
            receipt=receipt,
            output_observed_at_ms=record["output_observed_at_ms"],
            captured_at_ms=captured_at_ms,
        )
        closure = _raw_parent_closure(reader=reader, output_record=record, expected_kind="CLOSED_BAR")
        try:
            replayed_bar = replay_native_quant_event(
                event_kind="CLOSED_BAR",
                expected_payload=payload,
                source_records={**closure, observation_id: stored.record},
                output_record=stored.record,
            )
        except Exception as exc:
            raise NativeMarketLineageError("original Binance kline failed pre-model replay") from exc
        if replayed_bar != payload:
            raise NativeMarketLineageError("original Binance kline does not match the exact pre-model DTO")
        bar_ids.append(observation_id)
    confirmed = _as_ids(market_record["parents"].get("confirmed_bars"))
    if len(bar_ids) > len(confirmed) or confirmed[-len(bar_ids) :] != tuple(bar_ids):
        raise NativeMarketLineageError("pre-model market history does not end with exact selected bars")
    if any(bar.symbol != market.symbol for bar in bars):
        raise NativeMarketLineageError("pre-model market/bar symbols differ")
    return _selection_sha256(
        market_output_id=market_id,
        bar_output_ids=tuple(bar_ids),
        market_receipt=market_receipt,
        bar_receipts=bar_receipts,
        replay_profile=profile,
    )


def make_native_market_bar_preflight(
    *, reader: NativeCaptureSessionReader, replay_profile: Mapping[str, int]
):
    """Bind the exact read-only session/profile into a composer preflight hook."""
    if type(reader) is not NativeCaptureSessionReader:
        raise TypeError("exact read-only native capture reader is required")
    profile = _profile(replay_profile)

    def preflight(market, bars, market_receipt, bar_receipts, captured_at_ms) -> str:
        return verify_native_market_bar_selection(
            reader=reader,
            market=market,
            bars=bars,
            market_receipt=market_receipt,
            bar_receipts=bar_receipts,
            captured_at_ms=captured_at_ms,
            expected_replay_profile=profile,
        )

    return preflight


def _raw_parent_closure(
    *,
    reader: NativeCaptureSessionReader,
    output_record: dict[str, Any],
    expected_kind: str,
) -> dict[str, bytes]:
    parents = output_record["parents"]
    expected_keys = (
        {"rest_confirmations"}
        if expected_kind == "CLOSED_BAR"
        else {
            "depth_frame",
            "funding_source",
            "open_interest_source",
            "force_order_frames",
            "confirmed_bars",
        }
    )
    if set(parents) != expected_keys:
        raise NativeMarketLineageError("Quant output parent set is incomplete or contains unknown sources")
    if expected_kind == "CLOSED_BAR":
        raw_ids = _as_ids(parents["rest_confirmations"], minimum=2, maximum=2)
        bar_closure: dict[str, bytes] = {}
        bar_receive_times: list[int] = []
        bar_epochs: set[str] = set()
        bar_sequences: set[int] = set()
        for raw_id in raw_ids:
            stored, raw = _raw(reader, raw_id)
            if raw["kind"] != "BINANCE_KLINES_REST":
                raise NativeMarketLineageError(
                    "closed bar is not bound to two original Binance REST confirmations"
                )
            if stored.witness.acknowledged_at_ms > output_record["output_observed_at_ms"]:
                raise NativeMarketLineageError(
                    "closed-bar raw source was not persisted before output publication"
                )
            bar_closure[raw_id] = stored.record
            bar_receive_times.append(raw["received_at_ms"])
            bar_epochs.add(raw["capture_epoch"])
            bar_sequences.add(raw["capture_sequence"])
        if (
            len(bar_epochs) != 1
            or len(bar_sequences) != 2
            or max(bar_receive_times) > output_record["output_observed_at_ms"]
        ):
            raise NativeMarketLineageError("closed-bar confirmation clocks/session ordering are invalid")
        return bar_closure

    direct_ids = [
        *_as_ids(parents["depth_frame"]),
        *_as_ids(parents["funding_source"]),
        *_as_ids(parents["open_interest_source"]),
        *_as_ids(parents["force_order_frames"], minimum=0),
    ]
    if len(direct_ids) != len(set(direct_ids)):
        raise NativeMarketLineageError("market snapshot reuses one source observation for different inputs")
    bar_ids = _as_ids(parents["confirmed_bars"])
    closure: dict[str, bytes] = {}
    ws_epochs: dict[str, set[str]] = {"public": set(), "market": set()}
    sequences: dict[str, list[int]] = {"public": [], "market": []}
    receive_times: list[int] = []
    for raw_id in direct_ids:
        stored, raw = _raw(reader, raw_id)
        parent_key = next(
            key
            for key in ("depth_frame", "funding_source", "open_interest_source", "force_order_frames")
            if raw_id in _as_ids(parents[key], minimum=0)
        )
        allowed = {
            "depth_frame": {"BINANCE_WS_FRAME"},
            "funding_source": {"BINANCE_WS_FRAME", "BINANCE_PREMIUM_INDEX_REST"},
            "open_interest_source": {"BINANCE_OPEN_INTEREST_REST"},
            "force_order_frames": {"BINANCE_WS_FRAME"},
        }[parent_key]
        if raw["kind"] not in allowed:
            raise NativeMarketLineageError("market snapshot input parent has the wrong exact source kind")
        if stored.witness.acknowledged_at_ms > output_record["output_observed_at_ms"]:
            raise NativeMarketLineageError("market raw source was not persisted before snapshot publication")
        closure[raw_id] = stored.record
        receive_times.append(raw["received_at_ms"])
        if raw["kind"] == "BINANCE_WS_FRAME":
            route = raw["route"]
            if route not in ws_epochs:
                raise NativeMarketLineageError("WebSocket parent has an unknown Binance stream route")
            ws_epochs[route].add(raw["stream_epoch"])
            sequences[route].append(raw["capture_sequence"])
    if any(len(epochs) != 1 for epochs in ws_epochs.values() if epochs):
        raise NativeMarketLineageError("market snapshot crosses a Binance WebSocket reconnect epoch")
    if any(len(values) != len(set(values)) for values in sequences.values()):
        raise NativeMarketLineageError("market snapshot WebSocket parent sequence is duplicated")
    force_ids = _as_ids(parents["force_order_frames"], minimum=0)
    force_sequences = [_raw(reader, raw_id)[1]["capture_sequence"] for raw_id in force_ids]
    if force_sequences != sorted(force_sequences):
        raise NativeMarketLineageError("market snapshot force-order parents are reordered")
    if max(receive_times, default=0) > output_record["output_observed_at_ms"]:
        raise NativeMarketLineageError("market snapshot output predates an original source receive")

    for bar_id in bar_ids:
        _bar_observation_id, bar_stored, bar_record = _read_output(
            reader, event_kind="CLOSED_BAR", event_id=_output_event_id(reader, bar_id)
        )
        raw_closure = _raw_parent_closure(reader=reader, output_record=bar_record, expected_kind="CLOSED_BAR")
        closure[bar_id] = bar_stored.record
        closure.update(raw_closure)
        if bar_stored.witness.acknowledged_at_ms > output_record["output_observed_at_ms"]:
            raise NativeMarketLineageError("confirmed bar was not persisted before snapshot publication")
    capture_epochs = set()
    for _observation_id, raw_bytes in closure.items():
        raw_record = _unique_json(raw_bytes, what="Quant lineage parent")
        if raw_record.get("schema_version") == "kairos.quant-source-capture.v1":
            capture_epochs.add(raw_record.get("capture_epoch"))
    if len(capture_epochs) != 1 or len(closure) > 2_000:
        raise NativeMarketLineageError(
            "market lineage crosses capture epochs or exceeds its fixed closure bound"
        )
    return closure


def _output_event_id(reader: NativeCaptureSessionReader, observation_id: str) -> str:
    stored = reader.read(observation_id)
    if type(stored) is not NativeCaptureStoredObservation:
        raise NativeMarketLineageError("native capture reader returned an unexpected confirmed bar")
    record = _unique_json(stored.record, what="confirmed closed-bar output")
    if record.get("event_kind") != "CLOSED_BAR" or not isinstance(record.get("event_id"), str):
        raise NativeMarketLineageError("snapshot confirmed-bars parent is not a closed-bar output")
    if _output_id("CLOSED_BAR", record["event_id"]) != observation_id:
        raise NativeMarketLineageError("confirmed closed-bar output ID differs from its event identity")
    return record["event_id"]


def _stage(
    *,
    name: Literal["MARKET_SOURCE", "CLOSED_BAR_SOURCE"],
    output_records: tuple[tuple[str, NativeCaptureStoredObservation, dict[str, Any]], ...],
    context_receipts: tuple[Any, ...],
    parent_records: tuple[dict[str, Any], ...],
) -> LiveInputStageReceiptV1:
    bundle = {
        "version": "kairos.native-market-bar-lineage.v1",
        "outputs": [
            {
                "observation_id": observation_id,
                "record": record,
                "persistence_witness": stored.witness.model_dump(mode="json"),
            }
            for observation_id, stored, record in output_records
        ],
        "parent_records": list(parent_records),
        "consumer_receipts": [receipt.model_dump(mode="json") for receipt in context_receipts],
    }
    content = canonical_json_bytes(bundle)
    if not 0 < len(content) <= 1_000_000:
        raise NativeMarketLineageError("native market/bar lineage bundle exceeds its fixed stage bound")
    first = min(record["output_observed_at_ms"] for _id, _stored, record in output_records)
    last_persisted = max(stored.witness.acknowledged_at_ms for _id, stored, _record in output_records)
    received = max(receipt.received_at_ms for receipt in context_receipts)
    return LiveInputStageReceiptV1(
        stage=name,
        receipt_id=f"native-{name.lower()}-{hashlib.sha256(content).hexdigest()[:32]}",
        source_name="BINANCE_UM_NATIVE_REPLAY",
        status="CAPTURED",
        source_timestamp_ms=first,
        received_at_ms=received,
        persisted_at_ms=last_persisted,
        captured_at_ms=last_persisted,
        content_sha256=hashlib.sha256(content).hexdigest(),
        content_base64=base64.b64encode(content).decode("ascii"),
    )


def _parent_evidence(
    reader: NativeCaptureSessionReader,
    closure: Mapping[str, bytes],
) -> tuple[dict[str, Any], ...]:
    evidence = []
    for observation_id, expected_record in sorted(closure.items()):
        stored = reader.read(observation_id)
        if (
            type(stored) is not NativeCaptureStoredObservation
            or stored.record != expected_record
            or stored.witness.observation_id != observation_id
            or stored.witness.record_sha256 != hashlib.sha256(stored.record).hexdigest()
            or stored.witness.record_bytes != len(stored.record)
        ):
            raise NativeMarketLineageError("Quant parent bytes/witness changed during source projection")
        evidence.append(
            {
                "observation_id": observation_id,
                "record": _unique_json(stored.record, what="Quant source parent record"),
                "persistence_witness": stored.witness.model_dump(mode="json"),
            }
        )
    return tuple(evidence)


def project_native_market_bar_stages(
    *,
    reader: NativeCaptureSessionReader,
    context: DecisionContextV1,
    expected_replay_profile: Mapping[str, int],
) -> NativeMarketBarStageProjection:
    """Read and replay the exact Quant ancestry for current context inputs.

    Only the output IDs referenced by the real context DTOs and their declared
    parents are opened; the session is never inventoried or repaired. Quant's
    unchanged offline collector/builder replay is required and any incomplete
    reset/history/connection lineage refuses this new native preparation.
    """
    if type(reader) is not NativeCaptureSessionReader or type(context) is not DecisionContextV1:
        raise TypeError("exact read-only capture reader and native DecisionContext are required")
    profile = _profile(expected_replay_profile)

    market_values = _source_payloads(context, "market")
    bar_values = _source_payloads(context, "closed_bars")
    if len(market_values) != 1 or not 1 <= len(bar_values) <= context.maximum_closed_bars:
        raise NativeMarketLineageError("native context must retain one market and its exact closed-bar tail")

    market_payload, market_receipt = market_values[0]
    market = MarketSnapshot.model_validate(market_payload)
    market_id, market_stored, market_record = _read_output(
        reader, event_kind="MARKET_SNAPSHOT", event_id=market.message_id
    )
    if (
        market_record["event_payload"] != market.model_dump(mode="json")
        or market_record["replay_profile"] != profile
        or market_record["event_sha256"] != hashlib.sha256(canonical_json_bytes(market)).hexdigest()
    ):
        raise NativeMarketLineageError(
            "Quant market output does not equal the exact context DTO/configuration"
        )
    _assert_context_receipt(
        kind="market",
        payload=market_payload,
        receipt=market_receipt,
        output_observed_at_ms=market_record["output_observed_at_ms"],
        captured_at_ms=context.captured_at_ms,
    )

    market_closure = _raw_parent_closure(
        reader=reader, output_record=market_record, expected_kind="MARKET_SNAPSHOT"
    )
    try:
        from kairos_quant.native_replay import (
            replay_native_quant_event,  # type: ignore[import-not-found,import-untyped]
        )

        replayed_market = replay_native_quant_event(
            event_kind="MARKET_SNAPSHOT",
            expected_payload=market_payload,
            source_records={**market_closure, market_id: market_stored.record},
            output_record=market_stored.record,
        )
    except Exception as exc:
        raise NativeMarketLineageError("original Quant market source chain failed offline replay") from exc
    if replayed_market != market_payload:
        raise NativeMarketLineageError("original Quant sources do not replay to the exact MarketSnapshot DTO")

    output_bars = []
    selected_bar_closure: dict[str, bytes] = {}
    for payload, receipt in bar_values:
        bar = ClosedBarEventV1.model_validate(payload)
        if not isinstance(bar.bar_sha256, str):
            raise NativeMarketLineageError("consumer closed bar lacks its stable economic identity")
        bar_id, bar_stored, bar_record = _read_output(
            reader, event_kind="CLOSED_BAR", event_id=bar.bar_sha256
        )
        if (
            bar_record["event_payload"] != bar.model_dump(mode="json")
            or bar_record["replay_profile"] != profile
            or bar_record["event_sha256"] != hashlib.sha256(canonical_json_bytes(bar)).hexdigest()
        ):
            raise NativeMarketLineageError(
                "Quant closed-bar output differs from its exact original context DTO"
            )
        _assert_context_receipt(
            kind="closed_bars",
            payload=payload,
            receipt=receipt,
            output_observed_at_ms=bar_record["output_observed_at_ms"],
            captured_at_ms=context.captured_at_ms,
        )
        closure = _raw_parent_closure(reader=reader, output_record=bar_record, expected_kind="CLOSED_BAR")
        selected_bar_closure.update(closure)
        selected_bar_closure[bar_id] = bar_stored.record
        try:
            replayed_bar = replay_native_quant_event(
                event_kind="CLOSED_BAR",
                expected_payload=bar.model_dump(mode="json"),
                source_records={**closure, bar_id: bar_stored.record},
                output_record=bar_stored.record,
            )
        except Exception as exc:
            raise NativeMarketLineageError(
                "original Binance closed-bar inputs failed offline replay"
            ) from exc
        if replayed_bar != bar.model_dump(mode="json"):
            raise NativeMarketLineageError(
                "original Binance kline bytes do not replay to the exact ClosedBar DTO"
            )
        output_bars.append((bar_id, bar_stored, bar_record, receipt))

    confirmed_ids = _as_ids(market_record["parents"].get("confirmed_bars"))
    selected_bar_ids = tuple(item[0] for item in output_bars)
    if (
        len(selected_bar_ids) > len(confirmed_ids)
        or confirmed_ids[-len(selected_bar_ids) :] != selected_bar_ids
    ):
        raise NativeMarketLineageError("market replay history does not end with the exact consumer bar tail")
    if any(ClosedBarEventV1.model_validate(payload).symbol != market.symbol for payload, _ in bar_values):
        raise NativeMarketLineageError("native context market/bar symbols differ")

    market_stage = _stage(
        name="MARKET_SOURCE",
        output_records=((market_id, market_stored, market_record),),
        context_receipts=(market_receipt,),
        parent_records=_parent_evidence(reader, market_closure),
    )
    bar_stage = _stage(
        name="CLOSED_BAR_SOURCE",
        output_records=tuple((bar_id, stored, record) for bar_id, stored, record, _receipt in output_bars),
        context_receipts=tuple(receipt for _bar_id, _stored, _record, receipt in output_bars),
        parent_records=_parent_evidence(reader, selected_bar_closure),
    )
    selection_sha256 = _selection_sha256(
        market_output_id=market_id,
        bar_output_ids=selected_bar_ids,
        market_receipt=market_receipt,
        bar_receipts=tuple(receipt for _bar_id, _stored, _record, receipt in output_bars),
        replay_profile=profile,
    )
    return NativeMarketBarStageProjection((market_stage, bar_stage), selection_sha256)


__all__ = [
    "NativeMarketBarStageProjection",
    "NativeMarketLineageError",
    "make_native_market_bar_preflight",
    "project_native_market_bar_stages",
    "verify_native_market_bar_selection",
]
