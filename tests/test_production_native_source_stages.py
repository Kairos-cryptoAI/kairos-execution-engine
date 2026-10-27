"""Offline projection of original native source records into existing stages."""

from __future__ import annotations

import base64
import hashlib
import itertools
import json
from dataclasses import replace
from datetime import UTC, datetime

import pytest
from kairos_core.contracts import StrategicAllocation, canonical_json_bytes
from kairos_core.enums import MarketRegime, StrategicTrigger

pytest.importorskip("kairos_llm.call_evidence", reason="requires genuine optional native-inputs extra")
pytest.importorskip("kairos_text.native_capture", reason="requires genuine optional native-inputs extra")

from kairos_execution.production_binance_capture import (  # noqa: E402
    BINANCE_DEPTH_URL,
    BinanceDepthCaptureV1,
)
from kairos_execution.production_native_capture_store import (  # noqa: E402
    NativeCaptureSessionReader,
    NativeCaptureSessionSink,
)
from kairos_execution.production_native_inputs import read_native_budgeted_call  # noqa: E402
from kairos_execution.production_native_source_stages import (  # noqa: E402
    NativeStageProjectionError,
    project_native_binance_reference_stage,
    project_native_composition_stages,
    project_native_macro_stages,
    project_native_source_stages,
)
from tests.test_native_upstream_composition import _native  # noqa: E402
from tests.test_production_binance_capture import (  # noqa: E402
    BODY as BINANCE_BODY,
)
from tests.test_production_binance_capture import (
    SYMBOL as BINANCE_SYMBOL,
)
from tests.test_production_binance_capture import (
    install_fake_quant_normalizer,
)
from tests.test_production_native_inputs import _records as _native_call_records  # noqa: E402


def _iso(ms: int) -> str:
    return (
        datetime.fromtimestamp(ms / 1_000, tz=UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    )


def _http_capture(source: str, path: str, query: str, body: bytes, *, received_ms: int) -> bytes:
    return canonical_json_bytes(
        {
            "source": source,
            "path": path,
            "query_json": query,
            "status": 200,
            "requested_at": _iso(received_ms - 20),
            "received_at": _iso(received_ms),
            "body_bytes": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "body_base64": base64.b64encode(body).decode("ascii"),
        }
    )


def _persisted_macro_model_case(tmp_path, mutation=None):
    accepted_at_ms = 59_000
    call_started_ms = 59_010
    output_observed_ms = 59_020
    if mutation == "call_before_input_persist":
        call_started_ms = 59_001
    if mutation == "output_before_input":
        output_observed_ms = 58_999
    ticks = iter((59_001, 59_002, 59_011, 59_012, 59_017, 59_018, 59_021, 59_022))
    session = NativeCaptureSessionSink(tmp_path / "native-macro-model", clock_ms=lambda: next(ticks))
    capture_id = "4" * 32
    input_id = "3" * 32 if mutation == "wrong_physical_id" else capture_id
    output_id = hashlib.sha256((capture_id + ":allocation").encode("ascii")).hexdigest()[:32]
    allocation = StrategicAllocation(
        message_id="macro-model-id",
        correlation_id="macro-model-correlation",
        source="macro-model-service",
        produced_at=datetime.fromtimestamp(59_019 / 1_000, tz=UTC),
        regime=MarketRegime.CHOP,
        stable_reserve_pct=1.0,
        strategy_weights={},
        max_gross_leverage=1.0,
        triggered_by=StrategicTrigger.SHOCK_EVENT,
        rationale="persisted macro model fixture",
    )
    context_bytes = b'{"original":"macro-model-context"}'
    identity = {"message_id": allocation.message_id, "correlation_id": allocation.correlation_id}
    if mutation == "missing_stable_id":
        identity.pop("message_id")
    input_record = canonical_json_bytes(
        {
            "version": "kairos.native-macro-application-input.v1",
            "capture_scope": "EXACT_APPLICATION_CONTEXT_NOT_PROVIDER_HTTP",
            "capture_id": capture_id,
            "accepted_at_ms": accepted_at_ms,
            "trigger": "shock_event",
            "source": allocation.source,
            "identity": identity,
            "context_utf8": {
                "base64": base64.b64encode(context_bytes).decode("ascii"),
                "sha256": hashlib.sha256(context_bytes).hexdigest(),
            },
        }
    )
    session.create_only(input_id, input_record)
    attempt, completion = _native_call_records(
        workload="macro_strategist",
        call_id="2" * 32,
        reservation="macro-test-reservation",
        request_id="macro-test-request",
    )
    attempt_payload, completion_payload = json.loads(attempt), json.loads(completion)

    def encoded(raw):
        return {"base64": base64.b64encode(raw).decode("ascii"), "sha256": hashlib.sha256(raw).hexdigest()}

    prompt_user = b'{"substituted":"wrong prompt"}' if mutation == "wrong_prompt" else context_bytes
    attempt_payload["request"]["user_utf8"] = encoded(prompt_user)
    attempt_payload["provider_call"]["attempt_started_at_ms"] = call_started_ms
    model_regime = "BEAR" if mutation == "changed_model_economics" else "CHOP"
    macro_model_response = canonical_json_bytes(
        {
            "regime": model_regime,
            "stable_reserve_pct": 1.0,
            "strategy_weights": [],
            "max_gross_leverage": 1.0,
            "rationale": allocation.rationale,
        }
    )
    completion_payload["response"]["content_utf8"] = encoded(macro_model_response)
    completion_payload["attempt_record_sha256"] = hashlib.sha256(
        canonical_json_bytes(attempt_payload)
    ).hexdigest()
    completion_payload["provider_call"]["attempt_started_at_ms"] = call_started_ms
    completion_payload["provider_call"]["response_observed_at_ms"] = 59_015
    completion_payload["budget"]["commit_observed_at_ms"] = 59_016
    attempt = canonical_json_bytes(attempt_payload)
    completion = canonical_json_bytes(completion_payload)
    call_id = "2" * 32
    session.create_only(hashlib.sha256(f"llm:{call_id}:started".encode()).hexdigest()[:32], attempt)
    session.create_only(hashlib.sha256(f"llm:{call_id}:completed".encode()).hexdigest()[:32], completion)
    allocation_bytes = canonical_json_bytes(allocation)
    output_record = canonical_json_bytes(
        {
            "version": "kairos.native-macro-application-output.v1",
            "capture_scope": "EXACT_APPLICATION_OUTPUT_NOT_PROVIDER_HTTP",
            "capture_id": capture_id,
            "input_record_sha256": hashlib.sha256(input_record).hexdigest(),
            "observed_at_ms": output_observed_ms,
            "output_origin": "NATIVE_MODEL",
            "allocation": allocation.model_dump(mode="json"),
            "allocation_sha256": hashlib.sha256(allocation_bytes).hexdigest(),
        }
    )
    session.create_only(output_id, output_record)
    return (
        NativeCaptureSessionReader(session.directory),
        input_id,
        output_id,
        allocation,
        input_id == capture_id,
    )


def test_macro_model_projection_returns_only_exact_persisted_call_pair(tmp_path):
    reader, input_id, output_id, allocation, _same_physical_id = _persisted_macro_model_case(tmp_path)
    projection = project_native_macro_stages(
        reader=reader,
        input_observation_id=input_id,
        output_observation_id=output_id,
        expected_allocation=allocation,
    )
    assert len(projection.calls) == 1
    pair = projection.calls[0]
    assert pair.bound_output_sha256 == hashlib.sha256(canonical_json_bytes(allocation)).hexdigest()
    completed_id = hashlib.sha256(f"llm:{'2' * 32}:completed".encode()).hexdigest()[:32]
    assert pair.captured_at_ms == reader.read(completed_id).witness.acknowledged_at_ms
    parsed = read_native_budgeted_call(pair.attempt_record, pair.completion_record)
    assert parsed.native_workload == "macro_strategist"
    assert json.loads(parsed.prompt)["user"].encode("utf-8") == b'{"original":"macro-model-context"}'


@pytest.mark.parametrize(
    "mutation",
    [
        "wrong_prompt",
        "changed_model_economics",
        "missing_stable_id",
        "wrong_physical_id",
        "call_before_input_persist",
        "output_before_input",
    ],
)
def test_macro_model_projection_rejects_wrong_prompt_identity_or_causal_order(tmp_path, mutation):
    reader, input_id, output_id, allocation, _same_physical_id = _persisted_macro_model_case(
        tmp_path, mutation=mutation
    )
    with pytest.raises(NativeStageProjectionError):
        project_native_macro_stages(
            reader=reader,
            input_observation_id=input_id,
            output_observation_id=output_id,
            expected_allocation=allocation,
        )


async def test_projects_exact_persisted_rss_instrument_and_depth_without_renewing_clocks(
    tmp_path, monkeypatch
):
    composer, kwargs, memory_sink, *_ = _native(monkeypatch)
    result = await composer.compose(**kwargs)

    latest_capture = max(json.loads(raw).get("captured_at_ms", 0) for raw in memory_sink.records.values())
    base_time = latest_capture + 100
    ticks = itertools.count(base_time + 100)
    session = NativeCaptureSessionSink(tmp_path / "native-session", clock_ms=lambda: next(ticks))
    for observation_id, raw in memory_sink.records.items():
        session.create_only(observation_id, raw)
    instrument_id = "a" * 32
    book_id = "b" * 32
    instrument_body = json.dumps(
        [{"name": "BTCUSD", "trading": "all", "visibility": "all", "marketState": "OPEN"}],
        separators=(",", ":"),
    ).encode()
    book_body = b'{"t":19950,"asks":[{"price":"101","quantity":"1"}],"bids":[{"price":"100","quantity":"1"}]}'
    session.create_only(
        instrument_id,
        _http_capture(
            "instruments",
            "/api/market/instrument",
            '{"fields":"metrics"}',
            instrument_body,
            received_ms=base_time,
        ),
    )
    session.create_only(
        book_id,
        _http_capture(
            "depth",
            "/api/market/BTCUSD/deep",
            '{"maxLevel":"50"}',
            book_body,
            received_ms=base_time + 10,
        ),
    )

    rss_ids = tuple(
        observation_id
        for observation_id, raw in memory_sink.records.items()
        if json.loads(raw).get("kind") == "RSS_RESPONSE"
    )
    reader = NativeCaptureSessionReader(session.directory)
    projection = project_native_source_stages(
        reader=reader,
        rss_observation_ids=rss_ids,
        evedex_instrument_observation_id=instrument_id,
        evedex_book_observation_id=book_id,
        venue_symbol="BTCUSD",
    )
    by_name = {stage.stage: stage for stage in projection.stages}
    assert projection.live_ready is False
    assert len([stage for stage in projection.stages if stage.stage == "TEXT_SOURCE"]) == 1
    rss = next(stage for stage in projection.stages if stage.stage == "TEXT_SOURCE")
    original_rss = reader.read(rss_ids[0])
    assert base64.b64decode(rss.content_base64) == original_rss.record
    assert rss.persisted_at_ms == original_rss.witness.acknowledged_at_ms
    assert rss.captured_at_ms == original_rss.witness.acknowledged_at_ms
    assert rss.source_timestamp_ms == rss.received_at_ms < rss.persisted_at_ms
    assert by_name["EVEDEX_INSTRUMENT"].source_timestamp_ms == base_time
    assert by_name["EVEDEX_BOOK"].source_timestamp_ms == 19_950
    assert by_name["EVEDEX_BOOK"].received_at_ms == base_time + 10
    assert by_name["EVEDEX_BOOK"].persisted_at_ms > by_name["EVEDEX_BOOK"].received_at_ms

    complete_partial = project_native_composition_stages(
        composition=result,
        reader=reader,
        source_stages=projection.stages,
    )
    output_by_name = {stage.stage: stage for stage in complete_partial.stages}
    assert {"TEXT_AGGREGATE", "ROUTER_OUTPUT", "REVIEW_OUTPUT", "DECISION_CONTEXT"} <= set(output_by_name)
    assert output_by_name["TEXT_AGGREGATE"].parent_receipt_ids == (rss.receipt_id,)
    assert output_by_name["MACRO_SOURCE"].status == "UNAVAILABLE"
    assert output_by_name["MACRO_ALLOCATION"].status == "UNAVAILABLE"
    assert complete_partial.live_ready is False
    with pytest.raises(NativeStageProjectionError, match="context"):
        false_macro_context = result.context.model_copy(
            update={
                "sources": tuple(
                    source.model_copy(update={"availability": "AVAILABLE", "reason_code": None})
                    if source.kind == "macro"
                    else source
                    for source in result.context.sources
                )
            }
        )
        project_native_composition_stages(
            composition=replace(result, context=false_macro_context),
            reader=reader,
            source_stages=projection.stages,
        )
    with pytest.raises(NativeStageProjectionError, match="emissions"):
        project_native_composition_stages(
            composition=replace(result, emission_records=(*result.emission_records, b"{}")),
            reader=reader,
            source_stages=projection.stages,
        )


async def test_rejects_foreign_instrument_or_reused_text_source_identity(tmp_path, monkeypatch):
    composer, kwargs, memory_sink, *_ = _native(monkeypatch)
    await composer.compose(**kwargs)
    latest_capture = max(json.loads(raw).get("captured_at_ms", 0) for raw in memory_sink.records.values())
    base_time = latest_capture + 100
    ticks = itertools.count(base_time + 100)
    session = NativeCaptureSessionSink(tmp_path / "native-session", clock_ms=lambda: next(ticks))
    rss_ids = []
    for observation_id, raw in memory_sink.records.items():
        session.create_only(observation_id, raw)
        if json.loads(raw).get("kind") == "RSS_RESPONSE":
            rss_ids.append(observation_id)
    instrument_id, book_id = "c" * 32, "d" * 32
    instrument = _http_capture(
        "instruments",
        "/api/market/instrument",
        '{"fields":"metrics"}',
        b'[{"name":"ETHUSD"}]',
        received_ms=base_time,
    )
    book = _http_capture(
        "depth",
        "/api/market/BTCUSD/deep",
        '{"maxLevel":"50"}',
        b'{"t":' + str(base_time + 5).encode() + b',"asks":[],"bids":[]}',
        received_ms=base_time + 10,
    )
    session.create_only(instrument_id, instrument)
    session.create_only(book_id, book)
    with pytest.raises(NativeStageProjectionError, match="uniquely bind venue symbol"):
        project_native_source_stages(
            reader=NativeCaptureSessionReader(session.directory),
            rss_observation_ids=(rss_ids[0],),
            evedex_instrument_observation_id=instrument_id,
            evedex_book_observation_id=book_id,
            venue_symbol="BTCUSD",
        )


def test_projects_macro_application_input_output_pair_without_http_claim(tmp_path):
    ticks = itertools.count(50_030)
    session = NativeCaptureSessionSink(tmp_path / "native-macro-session", clock_ms=lambda: next(ticks))
    capture_id = "e" * 32
    input_id = capture_id
    output_id = hashlib.sha256((capture_id + ":allocation").encode("ascii")).hexdigest()[:32]
    accepted_at_ms = 50_000
    context_bytes = b'{"account":"retained-native-context","market":"original-input"}'
    identity = {"message_id": "native-macro-allocation", "correlation_id": "native-macro-correlation"}
    input_record = canonical_json_bytes(
        {
            "version": "kairos.native-macro-application-input.v1",
            "capture_scope": "EXACT_APPLICATION_CONTEXT_NOT_PROVIDER_HTTP",
            "capture_id": capture_id,
            "accepted_at_ms": accepted_at_ms,
            "trigger": "shock_event",
            "source": "native-macro-service",
            "identity": identity,
            "context_utf8": {
                "base64": base64.b64encode(context_bytes).decode("ascii"),
                "sha256": hashlib.sha256(context_bytes).hexdigest(),
            },
        }
    )
    session.create_only(input_id, input_record)
    allocation = StrategicAllocation(
        message_id="native-macro-allocation",
        correlation_id="native-macro-correlation",
        source="native-macro-service",
        produced_at=datetime.fromtimestamp(50_010 / 1_000, tz=UTC),
        regime=MarketRegime.CHOP,
        stable_reserve_pct=1.0,
        strategy_weights={},
        max_gross_leverage=1.0,
        triggered_by=StrategicTrigger.SHOCK_EVENT,
        rationale="offline native capture test",
    )
    allocation_bytes = canonical_json_bytes(allocation)
    output_record = canonical_json_bytes(
        {
            "version": "kairos.native-macro-application-output.v1",
            "capture_scope": "EXACT_APPLICATION_OUTPUT_NOT_PROVIDER_HTTP",
            "capture_id": capture_id,
            "input_record_sha256": hashlib.sha256(input_record).hexdigest(),
            "observed_at_ms": 50_020,
            "output_origin": "NATIVE_DETERMINISTIC_FALLBACK",
            "allocation": allocation.model_dump(mode="json"),
            "allocation_sha256": hashlib.sha256(allocation_bytes).hexdigest(),
        }
    )
    session.create_only(output_id, output_record)
    stages = project_native_macro_stages(
        reader=NativeCaptureSessionReader(session.directory),
        input_observation_id=input_id,
        output_observation_id=output_id,
        expected_allocation=allocation,
    )
    raw_context = context_bytes
    assert [stage.stage for stage in stages.stages] == ["MACRO_SOURCE", "MACRO_ALLOCATION"]
    assert base64.b64decode(stages.stages[0].content_base64) == raw_context
    assert stages.stages[0].requested_at_ms == stages.stages[0].received_at_ms == accepted_at_ms
    assert stages.stages[0].source_name == "application-context:native-macro-service:shock_event"
    assert "http" not in stages.stages[0].source_name.lower()
    assert stages.stages[1].parent_receipt_ids == (stages.stages[0].receipt_id,)
    assert stages.stages[1].output_origin == "NATIVE_DETERMINISTIC_FALLBACK"
    assert (
        hashlib.sha256(base64.b64decode(stages.stages[1].content_base64)).hexdigest()
        == stages.stages[1].content_sha256
    )
    assert stages.calls == ()
    assert output_record


def test_projects_fixed_binance_depth_capture_with_exact_T_timestamp_and_fsync_witness(tmp_path, monkeypatch):
    calls = []
    install_fake_quant_normalizer(monkeypatch, calls)
    ticks = itertools.count(2_000)
    session = NativeCaptureSessionSink(tmp_path / "native-binance-session", clock_ms=lambda: next(ticks))
    payload = json.loads(BINANCE_BODY)
    requested_url = f"{BINANCE_DEPTH_URL}?symbol={BINANCE_SYMBOL}&limit=100"
    capture = BinanceDepthCaptureV1(
        symbol=BINANCE_SYMBOL,
        requested_url=requested_url,
        request_query_json='{"limit":"100","symbol":"BTCUSDT"}',
        requested_at_ms=1_000,
        received_at_ms=1_020,
        source_timestamp_ms=payload["T"],
        source_timestamp_field="T",
        body_bytes=len(BINANCE_BODY),
        body_sha256=hashlib.sha256(BINANCE_BODY).hexdigest(),
        body_base64=base64.b64encode(BINANCE_BODY).decode("ascii"),
    )
    observation_id = "f" * 32
    session.create_only(observation_id, canonical_json_bytes(capture))
    stage = project_native_binance_reference_stage(
        reader=NativeCaptureSessionReader(session.directory),
        observation_id=observation_id,
        expected_symbol=BINANCE_SYMBOL,
    )
    assert stage.stage == "BINANCE_REFERENCE"
    assert stage.source_timestamp_ms == payload["T"]
    assert stage.requested_at_ms == 1_000 and stage.received_at_ms == 1_020
    assert stage.persisted_at_ms == stage.captured_at_ms == 2_001
    assert calls == [(BINANCE_SYMBOL, payload, 0.0)]


@pytest.mark.parametrize(
    "mutation",
    [
        "wrong_symbol",
        "wrong_T_timestamp",
        "receive_before_request",
        "fsync_before_receive",
        "duplicate_body",
    ],
)
def test_binance_stage_projection_rejects_route_symbol_clock_and_body_substitution(
    tmp_path, monkeypatch, mutation
):
    calls = []
    install_fake_quant_normalizer(monkeypatch, calls)
    body = b'{"lastUpdateId":42,"E":1010,"T":1011,"bids":[["100.10","2.000"]],"asks":[["100.20","3.000"]]}'
    if mutation == "duplicate_body":
        body = b'{"E":1010,"T":1011,"T":1012,"bids":[],"asks":[]}'
    symbol = "ETHUSDT" if mutation == "wrong_symbol" else BINANCE_SYMBOL
    requested_at, received_at, source_at = 1_000, 1_020, 1_011
    if mutation == "wrong_T_timestamp":
        source_at = 1_010
    elif mutation == "receive_before_request":
        requested_at = 1_021
    elif mutation == "fsync_before_receive":
        requested_at, received_at, source_at = 1_000, 2_020, 1_011
    capture = BinanceDepthCaptureV1(
        symbol=symbol,
        requested_url=f"{BINANCE_DEPTH_URL}?symbol={symbol}&limit=100",
        request_query_json=json.dumps(
            {"limit": "100", "symbol": symbol}, sort_keys=True, separators=(",", ":")
        ),
        requested_at_ms=requested_at,
        received_at_ms=received_at,
        source_timestamp_ms=source_at,
        source_timestamp_field="T",
        body_bytes=len(body),
        body_sha256=hashlib.sha256(body).hexdigest(),
        body_base64=base64.b64encode(body).decode("ascii"),
    )
    first_tick = 1_010 if mutation == "fsync_before_receive" else 2_000
    ticks = itertools.count(first_tick)
    session = NativeCaptureSessionSink(tmp_path / "native-binance-negative", clock_ms=lambda: next(ticks))
    observation_id = "5" * 32
    session.create_only(observation_id, canonical_json_bytes(capture))
    with pytest.raises(NativeStageProjectionError):
        project_native_binance_reference_stage(
            reader=NativeCaptureSessionReader(session.directory),
            observation_id=observation_id,
            expected_symbol=BINANCE_SYMBOL,
        )


@pytest.mark.parametrize(
    "mutation",
    ["transplanted_output", "source_mismatch", "trigger_mismatch", "changed_allocation", "duplicate_json"],
)
def test_macro_input_output_join_rejects_transplants_and_changed_provenance(tmp_path, mutation):
    ticks = itertools.count(60_030)
    session = NativeCaptureSessionSink(tmp_path / "native-macro-session", clock_ms=lambda: next(ticks))
    capture_id = "9" * 32
    input_id = capture_id
    output_id = hashlib.sha256((capture_id + ":allocation").encode("ascii")).hexdigest()[:32]
    allocation = StrategicAllocation(
        message_id="macro-id",
        correlation_id="macro-correlation",
        source="macro-service",
        produced_at=datetime.fromtimestamp(60_010 / 1_000, tz=UTC),
        regime=MarketRegime.CHOP,
        stable_reserve_pct=1.0,
        strategy_weights={},
        max_gross_leverage=1.0,
        triggered_by=StrategicTrigger.SHOCK_EVENT,
        rationale="negative fixture",
    )
    context_bytes = b'{"original":"application-context"}'
    source = "macro-service"
    trigger = "shock_event"
    if mutation == "source_mismatch":
        source = "foreign-source"
    elif mutation == "trigger_mismatch":
        trigger = "schedule"
    input_record = canonical_json_bytes(
        {
            "version": "kairos.native-macro-application-input.v1",
            "capture_scope": "EXACT_APPLICATION_CONTEXT_NOT_PROVIDER_HTTP",
            "capture_id": capture_id,
            "accepted_at_ms": 60_000,
            "trigger": trigger,
            "source": source,
            "identity": {"message_id": allocation.message_id},
            "context_utf8": {
                "base64": base64.b64encode(context_bytes).decode("ascii"),
                "sha256": hashlib.sha256(context_bytes).hexdigest(),
            },
        }
    )
    changed = allocation
    observed_at = 60_020
    if mutation == "changed_allocation":
        changed = allocation.model_copy(update={"rationale": "substituted output"})
    elif mutation == "transplanted_output":
        capture_id = "8" * 32
    allocation_bytes = canonical_json_bytes(changed)
    output_record = canonical_json_bytes(
        {
            "version": "kairos.native-macro-application-output.v1",
            "capture_scope": "EXACT_APPLICATION_OUTPUT_NOT_PROVIDER_HTTP",
            "capture_id": capture_id,
            "input_record_sha256": hashlib.sha256(input_record).hexdigest(),
            "observed_at_ms": observed_at,
            "output_origin": "NATIVE_MODEL",
            "allocation": changed.model_dump(mode="json"),
            "allocation_sha256": hashlib.sha256(allocation_bytes).hexdigest(),
        }
    )
    if mutation == "duplicate_json":
        input_record = b'{"source":"one","source":"two"}'
        output_record = b"{}"
    session.create_only(input_id, input_record)
    session.create_only(output_id, output_record)
    with pytest.raises(NativeStageProjectionError):
        project_native_macro_stages(
            reader=NativeCaptureSessionReader(session.directory),
            input_observation_id=input_id,
            output_observation_id=output_id,
            expected_allocation=allocation,
        )


@pytest.mark.parametrize("mutation", ["duplicate_json", "request_after_receive", "fsync_before_receive"])
async def test_evedex_stage_projection_rejects_duplicate_or_noncausal_source_clocks(
    tmp_path, monkeypatch, mutation
):
    composer, kwargs, memory_sink, *_ = _native(monkeypatch)
    await composer.compose(**kwargs)
    latest_capture = max(json.loads(raw).get("captured_at_ms", 0) for raw in memory_sink.records.values())
    base_time = latest_capture + 100
    fsync_clock = base_time + 100 if mutation != "fsync_before_receive" else base_time + 100
    ticks = itertools.count(fsync_clock)
    session = NativeCaptureSessionSink(tmp_path / "native-session", clock_ms=lambda: next(ticks))
    for observation_id, raw in memory_sink.records.items():
        session.create_only(observation_id, raw)
    rss_ids = tuple(
        identity
        for identity, raw in memory_sink.records.items()
        if json.loads(raw).get("kind") == "RSS_RESPONSE"
    )
    instrument_id, book_id = "6" * 32, "7" * 32
    instrument_body = b'[{"name":"BTCUSD","trading":"all","visibility":"all","marketState":"OPEN"}]'
    capture = _http_capture(
        "instruments",
        "/api/market/instrument",
        '{"fields":"metrics"}',
        instrument_body,
        received_ms=base_time + 1_000 if mutation == "fsync_before_receive" else base_time,
    )
    if mutation == "request_after_receive":
        decoded = json.loads(capture)
        decoded["requested_at"] = _iso(base_time + 1)
        capture = canonical_json_bytes(decoded)
    if mutation == "duplicate_json":
        capture = b'{"source":"instruments","source":"depth"}'
    session.create_only(instrument_id, capture)
    session.create_only(
        book_id,
        _http_capture(
            "depth",
            "/api/market/BTCUSD/deep",
            '{"maxLevel":"50"}',
            b'{"t":1,"asks":[],"bids":[]}',
            received_ms=base_time,
        ),
    )
    with pytest.raises(NativeStageProjectionError):
        project_native_source_stages(
            reader=NativeCaptureSessionReader(session.directory),
            rss_observation_ids=rss_ids,
            evedex_instrument_observation_id=instrument_id,
            evedex_book_observation_id=book_id,
            venue_symbol="BTCUSD",
        )
