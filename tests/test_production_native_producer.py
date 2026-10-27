"""Concrete unsigned producer preparation from original native capture records."""

from __future__ import annotations

import base64
import hashlib
import itertools
import json
import time
from datetime import UTC, datetime

import pytest
from kairos_core.contracts import canonical_json_bytes
from kairos_core.enums import SystemMode
from kairos_risk.live import LiveRiskScopeV1

pytest.importorskip("kairos_text.native_capture", reason="requires native producer dependencies")
pytest.importorskip("kairos_llm.call_evidence", reason="requires native producer dependencies")
pytest.importorskip("kairos_quant.runtime_venue_gate", reason="requires native producer dependencies")

from kairos_quant.runtime_venue_gate import VenueGatePolicy  # noqa: E402

from kairos_execution.production_binance_capture import (  # noqa: E402
    BINANCE_DEPTH_URL,
    BinanceDepthCaptureV1,
)
from kairos_execution.production_inputs import LiveInputProducerTrustV1  # noqa: E402
from kairos_execution.production_native_capture_store import (  # noqa: E402
    NativeCaptureSessionReader,
    NativeCaptureSessionSink,
)
from kairos_execution.production_native_inputs import NativeCallRecordPair  # noqa: E402
from kairos_execution.production_native_producer import (  # noqa: E402
    NativeCaptureSelection,
    NativeProducerPreparationError,
    NativeProductionInputPreparer,
)
from tests.test_native_upstream_composition import _native, _native_calls  # noqa: E402
from tests.test_production_binance_capture import BODY as BINANCE_BODY  # noqa: E402


def _iso(ms: int) -> str:
    return (
        datetime.fromtimestamp(ms / 1_000, tz=UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    )


def _http_capture(source: str, path: str, query: str, body: bytes, *, requested: int, received: int) -> bytes:
    return canonical_json_bytes(
        {
            "source": source,
            "path": path,
            "query_json": query,
            "status": 200,
            "requested_at": _iso(requested),
            "received_at": _iso(received),
            "body_bytes": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "body_base64": base64.b64encode(body).decode("ascii"),
        }
    )


async def _case(tmp_path, monkeypatch, *, policy=None):
    composer, kwargs, source_sink, *_ = _native(monkeypatch)
    composition = await composer.compose(**kwargs)
    retained_times = [
        value
        for raw in source_sink.records.values()
        for record in (json.loads(raw),)
        for value in (record.get("captured_at_ms"), record.get("observed_at_ms"))
        if type(value) is int
    ]
    base = max(time.time_ns() // 1_000_000 + 10_000, max(retained_times, default=0) + 100)
    tick = itertools.count(base)
    session = NativeCaptureSessionSink(tmp_path / "native-producer", clock_ms=lambda: next(tick))
    for observation_id, raw in source_sink.records.items():
        session.create_only(observation_id, raw)

    instrument_id, evedex_id, binance_id = "a" * 32, "b" * 32, "c" * 32
    instrument = b'[{"name":"BTCUSD","trading":"all","visibility":"all","marketState":"OPEN"}]'
    evedex_body = json.dumps(
        {
            "t": base - 6,
            "asks": [{"price": "100.20", "quantity": "100"}],
            "bids": [{"price": "100.10", "quantity": "100"}],
        },
        separators=(",", ":"),
    ).encode()
    session.create_only(
        instrument_id,
        _http_capture(
            "instruments",
            "/api/market/instrument",
            '{"fields":"metrics"}',
            instrument,
            requested=base - 8,
            received=base - 7,
        ),
    )
    session.create_only(
        evedex_id,
        _http_capture(
            "depth",
            "/api/market/BTCUSD/deep",
            '{"maxLevel":"50"}',
            evedex_body,
            requested=base - 6,
            received=base - 5,
        ),
    )
    binance_payload = json.loads(BINANCE_BODY)
    capture = BinanceDepthCaptureV1(
        symbol="BTCUSDT",
        requested_url=f"{BINANCE_DEPTH_URL}?symbol=BTCUSDT&limit=100",
        request_query_json='{"limit":"100","symbol":"BTCUSDT"}',
        requested_at_ms=base - 6,
        received_at_ms=base - 4,
        source_timestamp_ms=binance_payload["T"],
        source_timestamp_field="T",
        body_bytes=len(BINANCE_BODY),
        body_sha256=hashlib.sha256(BINANCE_BODY).hexdigest(),
        body_base64=base64.b64encode(BINANCE_BODY).decode("ascii"),
    )
    session.create_only(binance_id, canonical_json_bytes(capture))
    rss_ids = tuple(
        key for key, raw in source_sink.records.items() if json.loads(raw).get("kind") == "RSS_RESPONSE"
    )
    selection = NativeCaptureSelection(rss_ids, instrument_id, evedex_id, binance_id)

    # Bind already persisted native model calls to the exact outputs they produced.
    from kairos_execution.production_native_source_stages import (
        project_native_composition_stages,
        project_native_source_stages,
    )

    reader = NativeCaptureSessionReader(session.directory)
    source_stages = project_native_source_stages(
        reader=reader,
        rss_observation_ids=rss_ids,
        evedex_instrument_observation_id=instrument_id,
        evedex_book_observation_id=evedex_id,
        venue_symbol="BTCUSD",
    )
    partial = project_native_composition_stages(
        composition=composition, reader=reader, source_stages=source_stages.stages
    )
    aggregate = next(stage for stage in partial.stages if stage.stage == "TEXT_AGGREGATE")
    pairs = []
    calls = _native_calls(source_sink)
    for _call_id, phases in calls.items():
        started, completed = phases["started"], phases["completed"]
        workload = json.loads(started)["workload"]
        bound = (
            aggregate.content_sha256
            if workload == "text_scouts"
            else hashlib.sha256(canonical_json_bytes(composition.review)).hexdigest()
        )
        pairs.append(NativeCallRecordPair(started, completed, bound, 0))

    intent = composition.review.intent
    scope = LiveRiskScopeV1(
        context_sha256="1" * 64,
        source_set_sha256="4" * 64,
        policy_sha256="5" * 64,
        risk_limits_sha256="2" * 64,
        account_id="fixture-account",
        strategy_id="fixture-strategy",
        strategy_revision=intent.strategy_revision,
        approved_prod_symbols=((intent.symbol, "BTCUSD"),),
    )
    trust = LiveInputProducerTrustV1(
        producer_id="fixture-producer",
        source_id="fixture-source",
        purpose="LIVE_UPSTREAM_INPUT_CAPTURE",
        source_set_sha256=scope.source_set_sha256,
        policy_sha256=scope.policy_sha256,
        expected_text_source_names=("https://fixture.invalid/feed",),
        capture_implementation_id="fixture-capture",
        capture_implementation_sha256="3" * 64,
        registration_id="fixture-registration",
    )
    preparer = NativeProductionInputPreparer(
        sink=session,
        reader=reader,
        trust=trust,
        scope=scope,
        venue_policy=policy or VenueGatePolicy(),
        clock_ms=lambda: next(tick),
    )
    return preparer, composition, selection, tuple(pairs), reader


async def test_prepares_unsigned_native_input_from_original_sources(tmp_path, monkeypatch):
    preparer, composition, selection, calls, reader = await _case(tmp_path, monkeypatch)
    prepared = preparer.prepare(
        composition=composition,
        selection=selection,
        system_mode=SystemMode.NORMAL,
        calls=calls,
    )
    assert prepared.live_ready is False and prepared.registered is False
    assert prepared.envelope.signature_base64 == base64.b64encode(bytes(64)).decode("ascii")
    assert prepared.envelope.review == composition.review
    assert prepared.envelope.context == composition.context
    assert prepared.envelope.allocation is None
    assert prepared.envelope.venue.profile.value == "PROD"
    assert any(
        stage.stage == "MACRO_SOURCE" and stage.status == "UNAVAILABLE" for stage in prepared.envelope.stages
    )
    venue_capture = reader.read(prepared.venue_capture_id)
    wrapper = json.loads(venue_capture.record)
    assert wrapper["capture_scope"] == "NATIVE_DERIVED_MEASUREMENT_NOT_AUTHORITY"
    assert len(wrapper["parents"]) == 2


async def test_rejects_policy_that_relaxes_existing_venue_ceiling(tmp_path, monkeypatch):
    with pytest.raises(NativeProducerPreparationError, match="loosens"):
        await _case(tmp_path, monkeypatch, policy=VenueGatePolicy(maximum_book_age_ms=6_000))


async def test_missing_persisted_model_pairs_refuse_before_derived_measurement_write(tmp_path, monkeypatch):
    preparer, composition, selection, _calls, reader = await _case(tmp_path, monkeypatch)
    with pytest.raises(
        NativeProducerPreparationError, match="native model output lacks its exact persisted call pair"
    ):
        preparer.prepare(
            composition=composition,
            selection=selection,
            system_mode=SystemMode.NORMAL,
            calls=(),
        )
    assert all(
        json.loads(reader.read(observation_id).record).get("version")
        != "kairos.native-venue-quality-measurement.v1"
        for observation_id in reader.observation_ids()
    )


async def test_requires_explicit_mode_and_rejects_foreign_binance_symbol(tmp_path, monkeypatch):
    preparer, composition, selection, calls, _reader = await _case(tmp_path, monkeypatch)
    with pytest.raises(TypeError):
        preparer.prepare(composition=composition, selection=selection, system_mode="NORMAL", calls=calls)  # type: ignore[arg-type]
    wrong = NativeCaptureSelection(
        selection.text_source_observation_ids,
        selection.evedex_instrument_observation_id,
        selection.evedex_book_observation_id,
        selection.binance_observation_id,
    )
    preparer.scope = preparer.scope.model_copy(update={"approved_prod_symbols": (("ETHUSDT", "ETHUSD"),)})
    with pytest.raises(NativeProducerPreparationError):
        preparer.prepare(composition=composition, selection=wrong, system_mode=SystemMode.NORMAL, calls=calls)
