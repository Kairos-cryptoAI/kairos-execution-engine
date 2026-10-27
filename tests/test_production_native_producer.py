"""Concrete unsigned producer preparation from original native capture records."""

from __future__ import annotations

import base64
import hashlib
import json
import time
from collections import deque
from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from kairos_core.contracts import canonical_json_bytes
from kairos_core.enums import SystemMode
from kairos_risk.live import LiveRiskScopeV1

pytest.importorskip("kairos_text.native_capture", reason="requires native producer dependencies")
pytest.importorskip("kairos_llm.call_evidence", reason="requires native producer dependencies")
pytest.importorskip("kairos_quant.runtime_venue_gate", reason="requires native producer dependencies")

from kairos_quant.native_capture import NativeQuantCapture  # noqa: E402
from kairos_quant.runtime_venue_gate import VenueGatePolicy  # noqa: E402

from kairos_execution.production_binance_capture import (  # noqa: E402
    BINANCE_DEPTH_URL,
    BinanceDepthCaptureV1,
)
from kairos_execution.production_inputs import (  # noqa: E402
    _DOMAIN,
    LiveInputProducerTrustV1,
    LiveInputsSourceVerifier,
)
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
from tests.test_production_inputs import TEST_SEED  # noqa: E402


def _iso(ms: int) -> str:
    return (
        datetime.fromtimestamp(ms / 1_000, tz=UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    )


_REPLAY_PROFILE = {
    "price_window": 200,
    "depth_levels": 10,
    "snapshot_interval_ms": 5_000,
    "kline_finality_delay_ms": 5_000,
    "maximum_binance_future_skew_ms": 2_000,
    "book_stale_after_ms": 10_000,
    "kline_stale_after_ms": 90_000,
    "derivatives_stale_after_ms": 180_000,
}


class _FixtureSessionClock:
    def __init__(self, *, background_floor_ms: int) -> None:
        self.background_floor_ms = background_floor_ms
        self.value = 0
        self._next = deque()

    def acknowledge_at(self, target_ms: int) -> None:
        if target_ms < self.value:
            raise AssertionError("synthetic capture persistence clock moved backwards")
        self._next.extend((target_ms, target_ms))

    def __call__(self) -> int:
        value = self._next.popleft() if self._next else max(self.background_floor_ms, self.value + 1)
        if value < self.value:
            raise AssertionError("synthetic session clock moved backwards")
        self.value = value
        return value


class _RecordingSessionSink:
    def __init__(self, session, clock) -> None:
        self.session = session
        self.clock = clock
        self.records = {}

    def create_only(self, observation_id, record):
        value = json.loads(record)
        schema = value.get("schema_version")
        if schema == "kairos.quant-source-capture.v1":
            target_ms = value["received_at_ms"]
        elif schema == "kairos.quant-derived-market-event.v1":
            target_ms = value["output_observed_at_ms"]
        else:
            observed = max(
                (value.get(key, 0) for key in ("captured_at_ms", "observed_at_ms", "received_at_ms")),
                default=0,
            )
            if isinstance(value.get("received_at"), str):
                received = datetime.fromisoformat(value["received_at"].replace("Z", "+00:00"))
                observed = max(observed, int(received.timestamp() * 1_000))
            target_ms = max(self.clock.background_floor_ms, self.clock.value + 1, observed)
        self.clock.acknowledge_at(target_ms)
        self.session.create_only(observation_id, record)
        self.records[observation_id] = record


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


def _add_synthetic_quant_lineage(source_sink, market, bar):
    """Synthetic offline source bytes; replay is monkeypatched in these unit tests."""
    capture = NativeQuantCapture(source_sink, capture_epoch="d" * 32)
    from kairos_core.contracts import ClosedBarEventV1, MarketSnapshot

    market = MarketSnapshot.model_validate(market)
    bar = ClosedBarEventV1.model_validate(bar)
    market_at = int(market.produced_at.timestamp() * 1_000)
    bar_at = bar.close_time_ms
    symbol = market.symbol.lower()
    stream_names = {
        "depth": f"{symbol}@depth10@100ms",
        "funding": f"{symbol}@markPrice@1s",
    }

    def capture_ws(route, stream, received_at_ms, *, data):
        raw = canonical_json_bytes({"stream": stream, "data": data})
        url = f"wss://fstream.binance.com/{route}/stream?streams={stream}"
        return capture.capture_source(
            kind="BINANCE_WS_FRAME",
            url=url,
            raw_body=raw,
            received_at_ms=received_at_ms,
            route=route,
            stream_epoch=("e" if route == "public" else "f") * 32,
        )

    depth_id = capture_ws(
        "public",
        stream_names["depth"],
        market_at - 100,
        data={"e": "depthUpdate", "E": market_at - 101, "s": market.symbol, "U": 1, "u": 1, "b": [], "a": []},
    )
    funding_id = capture_ws(
        "market",
        stream_names["funding"],
        market_at - 90,
        data={"e": "markPriceUpdate", "E": market_at - 91, "s": market.symbol, "r": "0", "p": "1"},
    )
    oi_query = json.dumps(
        {"limit": "13", "period": "5m", "symbol": market.symbol}, sort_keys=True, separators=(",", ":")
    )
    oi_id = capture.capture_source(
        kind="BINANCE_OPEN_INTEREST_REST",
        url="https://fapi.binance.com/futures/data/openInterestHist",
        raw_body=b"[]",
        received_at_ms=market_at - 80,
        requested_at_ms=market_at - 81,
        query_json=oi_query,
        status=200,
    )

    kline_query = json.dumps(
        {"interval": "1m", "limit": "200", "symbol": bar.symbol}, sort_keys=True, separators=(",", ":")
    )
    bar_raw_ids = tuple(
        capture.capture_source(
            kind="BINANCE_KLINES_REST",
            url="https://fapi.binance.com/fapi/v1/klines",
            raw_body=b"[]",
            received_at_ms=bar_at - offset,
            requested_at_ms=bar_at - offset - 1,
            query_json=kline_query,
            status=200,
        )
        for offset in (100, 50)
    )
    profile = _REPLAY_PROFILE
    bar_id = capture.capture_derived_payload(
        event_kind="CLOSED_BAR",
        event_id=bar.bar_sha256,
        event_payload=bar.model_dump(mode="json"),
        # The publication clock follows both original REST receives, but the
        # market publication remains the consumer's original upper bound.
        output_observed_at_ms=bar_at + 1,
        parents={"rest_confirmations": bar_raw_ids},
        replay_profile=profile,
    )
    capture.capture_derived_event(
        event_kind="MARKET_SNAPSHOT",
        event=market,
        output_observed_at_ms=bar_at + 2,
        parents={
            "depth_frame": depth_id,
            "funding_source": funding_id,
            "open_interest_source": oi_id,
            "force_order_frames": (),
            "confirmed_bars": (bar_id,),
        },
        replay_profile=profile,
    )
    return profile


async def _case(tmp_path, monkeypatch, *, policy=None):
    session_clock = _FixtureSessionClock(background_floor_ms=time.time_ns() // 1_000_000 + 70_000)
    session = NativeCaptureSessionSink(tmp_path / "native-producer", clock_ms=session_clock)
    source_sink = _RecordingSessionSink(session, session_clock)
    reader = NativeCaptureSessionReader(session.directory)
    import kairos_quant.native_replay

    monkeypatch.setattr(
        kairos_quant.native_replay,
        "replay_native_quant_event",
        lambda *, event_kind, expected_payload, source_records, output_record: dict(expected_payload),
    )
    from kairos_execution.production_native_market_sources import make_native_market_bar_preflight

    preflight = make_native_market_bar_preflight(reader=reader, replay_profile=_REPLAY_PROFILE)
    composer, kwargs, source_sink, claims, gateway, _interlock = _native(
        monkeypatch,
        emission_sink=source_sink,
        market_bar_preflight=preflight,
    )
    replay_profile = _add_synthetic_quant_lineage(source_sink, kwargs["market"], kwargs["bars"][0])
    preflight_calls = []
    actual_preflight = composer.market_bar_preflight

    def tracked_preflight(*args):
        # The configured source replay must finish before either durable
        # analytical claims or model/provider work begins.
        assert not claims.claimed and not gateway.calls
        preflight_calls.append(True)
        return actual_preflight(*args)

    composer.market_bar_preflight = tracked_preflight
    composition = await composer.compose(**kwargs)
    assert preflight_calls == [True]
    retained_times = [
        value
        for raw in source_sink.records.values()
        for record in (json.loads(raw),)
        for value in (record.get("captured_at_ms"), record.get("observed_at_ms"))
        if type(value) is int
    ]
    base = max(
        session_clock.background_floor_ms + 20,
        max(retained_times, default=0) + 100,
    )

    instrument_id, evedex_id, binance_id = "a" * 32, "b" * 32, "c" * 32
    instrument = json.dumps(
        [
            {
                "name": "BTCUSD",
                "trading": "all",
                "visibility": "all",
                "marketState": "OPEN",
                "updatedAt": _iso(base - 10),
                "priceIncrement": "0.01",
                "quantityIncrement": "0.001",
                "minPrice": "0.01",
                "maxPrice": "1000000",
                "minQuantity": "0.001",
                "maxQuantity": "100000",
                "minVolume": "1",
                "lotSize": "1",
                "multiplier": "1",
            }
        ],
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    evedex_body = json.dumps(
        {
            "t": base - 6,
            "asks": [{"price": "100.20", "quantity": "100"}],
            "bids": [{"price": "100.10", "quantity": "100"}],
        },
        separators=(",", ":"),
    ).encode()
    source_sink.create_only(
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
    source_sink.create_only(
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
    binance_payload["E"] = base - 4
    binance_payload["T"] = base - 4
    binance_body = json.dumps(binance_payload, separators=(",", ":")).encode()
    capture = BinanceDepthCaptureV1(
        symbol="BTCUSDT",
        requested_url=f"{BINANCE_DEPTH_URL}?symbol=BTCUSDT&limit=100",
        request_query_json='{"limit":"100","symbol":"BTCUSDT"}',
        requested_at_ms=base - 6,
        received_at_ms=base - 4,
        source_timestamp_ms=binance_payload["T"],
        source_timestamp_field="T",
        body_bytes=len(binance_body),
        body_sha256=hashlib.sha256(binance_body).hexdigest(),
        body_base64=base64.b64encode(binance_body).decode("ascii"),
    )
    source_sink.create_only(binance_id, canonical_json_bytes(capture))
    rss_ids = tuple(
        key for key, raw in source_sink.records.items() if json.loads(raw).get("kind") == "RSS_RESPONSE"
    )
    selection = NativeCaptureSelection(rss_ids, instrument_id, evedex_id, binance_id)

    # Bind already persisted native model calls to the exact outputs they produced.
    from kairos_execution.production_native_source_stages import (
        project_native_composition_stages,
        project_native_source_stages,
    )

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
        strategy_id=intent.strategy_id,
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
        native_market_sources_required=True,
        native_quant_replay_profile=replay_profile,
    )
    preparer = NativeProductionInputPreparer(
        sink=session,
        reader=reader,
        trust=trust,
        scope=scope,
        venue_policy=policy or VenueGatePolicy(),
        quant_replay_profile=replay_profile,
        clock_ms=session_clock,
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
    private = Ed25519PrivateKey.from_private_bytes(TEST_SEED)
    unsigned = prepared.envelope.model_copy(
        update={"signature_base64": base64.b64encode(bytes(64)).decode("ascii")}
    )
    signed = unsigned.model_copy(
        update={
            "signature_base64": base64.b64encode(private.sign(_DOMAIN + unsigned.signed_payload())).decode(
                "ascii"
            )
        }
    )
    public_key = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    verified = LiveInputsSourceVerifier(trust=preparer.trust, public_key=public_key).verify(
        signed,
        expected_scope=preparer.scope,
        review=signed.review,
        venue=signed.venue,
        allocation=signed.allocation,
        system_mode=signed.system_mode,
        decided_at_ms=signed.observed_at_ms,
    )
    assert verified
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
