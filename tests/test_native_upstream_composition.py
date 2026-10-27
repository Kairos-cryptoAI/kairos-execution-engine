"""Real native classes with synthetic offline transport/model replies only.

The optional native-inputs CI job must install the genuine component extra and
run this module without skips. These tests do not accept a producer or venue.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import time
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from types import SimpleNamespace

import pytest
from kairos_core.contracts import (
    ClosedBarEventV1,
    MarketSnapshot,
    StrategyIntentV1,
    canonical_json_bytes,
    canonical_sha256,
)
from kairos_core.enums import StrategicTrigger

pytest.importorskip("kairos_text.native_capture", reason="requires genuine optional native-inputs extra")
pytest.importorskip("kairos_macro")
pytest.importorskip("kairos_router")
pytest.importorskip("kairos_aggregator")

from kairos_aggregator.candidate_review import CandidateReviewBrain  # noqa: E402
from kairos_aggregator.config import AggregatorSettings  # noqa: E402
from kairos_aggregator.decision_context import CandidateContextStore  # noqa: E402
from kairos_llm.budget import BudgetedLLMGateway  # noqa: E402
from kairos_llm.models import ModelRouter  # noqa: E402
from kairos_llm.pricing import PriceTable  # noqa: E402
from kairos_llm.schemas import LLMResult, TokenUsage  # noqa: E402
from kairos_macro.strategist import MacroStrategist  # noqa: E402
from kairos_router.aggregation import SignalWindow  # noqa: E402
from kairos_router.candidate import CandidateRouterPolicy  # noqa: E402
from kairos_text.dedup import EventDeduplicator  # noqa: E402
from kairos_text.filter import LocalRelevanceFilter  # noqa: E402
from kairos_text.freshness import EventFreshnessFilter  # noqa: E402
from kairos_text.normalize import EventNormalizer  # noqa: E402
from kairos_text.sentiment import SentimentExtractor  # noqa: E402
from kairos_text.sources.rss import RSSSource  # noqa: E402

from kairos_execution.production_native_composition import (  # noqa: E402
    NativeCompositionRefused,
    NativeUpstreamComponents,
    NativeUpstreamComposer,
)
from kairos_execution.production_native_inputs import (  # noqa: E402
    NativeLLMCallSinkAdapter,
    native_call_receipts,
    read_native_budgeted_call,
    verify_native_call_receipts,
)
from kairos_execution.production_native_text import (  # noqa: E402
    read_native_rss_response,
    read_native_sentiment_extraction,
)
from tests.test_production_inputs import _signed_fixture  # noqa: E402


class _Sink:
    def __init__(self):
        self.records = {}
        self.fail = False

    def create_only(self, observation_id, record):
        if self.fail:
            raise OSError("synthetic offline persistence failure")
        if observation_id in self.records:
            assert self.records[observation_id] == record
        self.records[observation_id] = record


class _Claims:
    def __init__(self):
        self.claimed = set()
        self.completed = set()

    async def claim_batch(self, scope, keys, attempt):
        result = tuple(key for key in keys if (scope, key) not in self.claimed)
        self.claimed.update((scope, key) for key in result)
        return result

    async def complete_batch(self, scope, keys, attempt):
        self.completed.update((scope, key) for key in keys)


class _ScriptedGateway:
    def __init__(self):
        self.calls = []
        self.pause = False
        self.fail_text = False
        self.entered = asyncio.Event()
        self.settings = SimpleNamespace(max_retries=0, max_output_tokens=8_192)
        self.router = ModelRouter()
        self.prices = PriceTable()

    async def complete(self, **kwargs):
        self.calls.append(kwargs)
        self.entered.set()
        if self.pause:
            await asyncio.Event().wait()
        if kwargs["workload"].value == "text_scouts":
            if self.fail_text:
                raise RuntimeError("synthetic provider failure after original budget reservation")
            payload = {
                "signals": [
                    {
                        "topic": "BTCUSDT",
                        "sentiment": 0.8,
                        "impact": "bullish",
                        "confidence": 0.8,
                        "summary": "Synthetic offline rally.",
                        "item_ids": [1],
                    }
                ]
            }
        elif kwargs["workload"].value == "macro_strategist":
            payload = {
                "regime": "CHOP",
                "stable_reserve_pct": 1.0,
                "strategy_weights": [],
                "max_gross_leverage": 1.0,
                "rationale": "Synthetic native capital preservation.",
            }
        else:
            payload = {"decision": "ALLOW", "priority": 5, "reason_codes": ["SYNTHETIC_OFFLINE"]}
        route = self.router.resolve(kwargs.get("effort"), workload=kwargs["workload"])
        usage = TokenUsage(input_tokens=20, output_tokens=5)
        return LLMResult(
            content=json.dumps(payload),
            parsed=kwargs["schema"].model_validate(payload),
            model=route.choice.model,
            effort=route.effort.value,
            usage=usage,
            cost_usd=self.prices.cost(route.choice.model, usage),
            latency_s=0.001,
            provider=route.choice.provider.value,
            request_id=f"synthetic-{len(self.calls)}",
            budget_reservation_id=f"synthetic-reservation-{len(self.calls)}",
        )


class _SyntheticBudget:
    def __init__(self):
        self.reserved = {}
        self.committed = {}

    async def reserve(self, **kwargs):
        self.reserved[kwargs["reservation_id"]] = kwargs

    async def commit(self, **kwargs):
        self.committed[kwargs["reservation_id"]] = kwargs


def _native_calls(sink):
    groups = {}
    for raw in sink.records.values():
        value = json.loads(raw)
        if value.get("version") == "kairos.llm-application-call-evidence.v1":
            phase = {"ATTEMPT_STARTED": "started", "COMPLETED": "completed"}[value["phase"]]
            groups.setdefault(value["call_id"], {})[phase] = raw
    return groups


def _native(monkeypatch, *, news_after_intent=False, market_bar_preflight=None, emission_sink=None):
    _verifier, _proof, original_context, review, _venue, _scope, _old_now = _signed_fixture()
    # Explicit synthetic closed-minute clock: native intent/context contracts
    # require the decision to be the exact minute close, never a made-up tail.
    decision_ms = (time.time_ns() // 1_000_000 // 60_000 + 1) * 60_000 - 1
    now = decision_ms + 101
    monkeypatch.setattr("kairos_llm.budget.time", SimpleNamespace(time_ns=lambda: now * 1_000_000))
    market_source = next(source for source in original_context.sources if source.kind == "market")
    bar_source = next(source for source in original_context.sources if source.kind == "closed_bars")
    market_data = market_source.payloads()[0]
    market_data["produced_at"] = datetime.fromtimestamp((decision_ms - 20) / 1_000, tz=UTC)
    market = MarketSnapshot.model_validate(market_data)
    bar_data = bar_source.payloads()[0]
    bar_close_ms = decision_ms
    bar_data.update(
        open_time_ms=bar_close_ms - 59_999,
        close_time_ms=bar_close_ms,
        produced_at=datetime.fromtimestamp(bar_close_ms / 1_000, tz=UTC),
        bar_sha256=None,
    )
    bars = (ClosedBarEventV1.model_validate(bar_data),)
    intent_data = review.intent.model_dump(mode="python")
    provenance = intent_data["provenance"]
    provenance["input_bar_sha256s"] = (bars[0].bar_sha256,)
    intent_data.update(
        decision_ts_ms=decision_ms,
        entry_eligible_ts_ms=(decision_ms // 60_000 + 1) * 60_000,
        entry_expires_ts_ms=decision_ms + 120_000,
        intent_id=None,
    )
    intent = StrategyIntentV1.model_validate(intent_data)
    event = datetime.fromtimestamp(
        (decision_ms + 1 if news_after_intent else decision_ms - 1_000) / 1_000, tz=UTC
    )
    body = (
        "<rss><channel><item><title>Bitcoin BTC ETF approval rally</title>"
        "<description>Bitcoin ETF bullish rally</description><link>https://fixture.invalid/news</link>"
        f"<pubDate>{format_datetime(event)}</pubDate></item></channel></rss>"
    ).encode()

    class Content:
        def __init__(self):
            self.offset = 0

        async def read(self, size=-1):
            stop = len(body) if size < 0 else self.offset + size
            chunk = body[self.offset : stop]
            self.offset += len(chunk)
            return chunk

        async def iter_chunked(self, size):
            while chunk := await self.read(size):
                yield chunk

    class Response:
        status = 200
        charset = "utf-8"
        headers = {"Content-Type": "application/rss+xml; charset=utf-8"}

        def __init__(self):
            self.content = Content()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def read(self):
            return await self.content.read()

        async def text(self):
            return body.decode()

        def get_encoding(self):
            return "utf-8"

    class Session:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        def get(self, *_args, **_kwargs):
            return Response()

    monkeypatch.setattr("kairos_text.sources.rss.aiohttp.ClientSession", Session)
    sink, claims, gateway = emission_sink or _Sink(), _Claims(), _ScriptedGateway()

    def clock():
        return now

    budgeted = BudgetedLLMGateway(gateway, _SyntheticBudget(), evidence_sink=NativeLLMCallSinkAdapter(sink))
    source = RSSSource(["https://fixture.invalid/feed"], capture_sink=sink, clock_ms=clock)
    extractor = SentimentExtractor(budgeted, capture_sink=sink, clock_ms=clock)
    settings = AggregatorSettings(trading_symbols=["BTCUSDT"], candidate_context_max_bars=1)
    components = NativeUpstreamComponents(
        text_sources=(source,),
        normalizer=EventNormalizer(),
        freshness=EventFreshnessFilter(
            1_800, 0, clock=lambda: datetime.fromtimestamp(clock() / 1_000, tz=UTC)
        ),
        dedup=EventDeduplicator(),
        relevance=LocalRelevanceFilter(),
        extractor=extractor,
        macro=MacroStrategist(budgeted, allowed_strategy_ids=("synthetic-native-fixture",)),
        window=SignalWindow(),
        router=CandidateRouterPolicy("native-test-router"),
        context_store=CandidateContextStore(settings),
        reviewer=CandidateReviewBrain(budgeted, clock_ms=clock),
    )
    # Explicit synthetic original source deliveries, retained before composition.
    # Composition may select these receipts, never manufacture new receive times.
    components.context_store.ingest("market", market.model_dump(mode="json"), received_at_ms=now - 50)
    for bar in bars:
        components.context_store.ingest("closed_bars", bar.model_dump(mode="json"), received_at_ms=now - 40)
    interlock = [True]
    composer = NativeUpstreamComposer(
        components=components,
        claims=claims,
        emission_sink=sink,
        clock_ms=clock,
        entry_interlock=lambda: interlock[0],
        market_bar_preflight=market_bar_preflight,
        composition_scope="synthetic-composition",
        text_scope="synthetic-text",
    )
    kwargs = dict(
        intent=intent,
        market=market,
        bars=bars,
        macro_context_json=None,
        macro_trigger=next(iter(StrategicTrigger)),
    )
    return composer, kwargs, sink, claims, gateway, interlock


@pytest.mark.parametrize("change", ["missing", "market-substitution", "bar-substitution", "quarantine"])
async def test_unretained_or_changed_market_bars_refuse_before_claims_or_models(monkeypatch, change):
    composer, kwargs, sink, claims, gateway, _interlock = _native(monkeypatch)
    if change == "missing":
        composer.components.context_store._entries.clear()
    elif change == "market-substitution":
        kwargs["market"] = MarketSnapshot.model_validate(
            {**kwargs["market"].model_dump(mode="json"), "mid_price": 101.0}
        )
    elif change == "bar-substitution":
        data = kwargs["bars"][0].model_dump(mode="json")
        data.update(quote_volume=data["quote_volume"] + 1.0, bar_sha256=None)
        kwargs["bars"] = (ClosedBarEventV1.model_validate(data),)
    else:
        composer.components.context_store.quarantined_kinds.add("market")
    with pytest.raises(NativeCompositionRefused, match="original retained"):
        await composer.compose(**kwargs)
    assert not claims.claimed and not gateway.calls and not sink.records


async def test_native_market_bar_selection_preserves_original_receive_receipts(monkeypatch):
    composer, kwargs, sink, _claims, _gateway, _interlock = _native(monkeypatch)
    original_market_time = composer.clock_ms() - 50
    original_bar_time = composer.clock_ms() - 40
    result = await composer.compose(**kwargs)
    selection = next(
        json.loads(raw)["payload"]
        for raw in sink.records.values()
        if json.loads(raw).get("stage") == "MARKET_BAR_CONTEXT_SELECTION"
    )
    assert selection["market_receipt"]["received_at_ms"] == original_market_time
    assert selection["bar_receipts"][0]["received_at_ms"] == original_bar_time
    for kind, original_time in (("market", original_market_time), ("closed_bars", original_bar_time)):
        source = next(source for source in result.context.sources if source.kind == kind)
        assert source.receipts[0].received_at_ms == original_time


async def test_market_source_preflight_refusal_happens_before_claims_or_model_calls(monkeypatch):
    def refuse_preflight(*_args):
        raise NativeCompositionRefused("synthetic raw-source lineage refusal")

    composer, kwargs, sink, claims, gateway, _interlock = _native(
        monkeypatch, market_bar_preflight=refuse_preflight
    )
    with pytest.raises(NativeCompositionRefused, match="synthetic raw-source lineage refusal"):
        await composer.compose(**kwargs)
    assert not claims.claimed and not gateway.calls and not sink.records


async def test_actual_native_sequence_retains_sources_outputs_and_never_promotes_live(monkeypatch):
    composer, kwargs, sink, claims, gateway, _interlock = _native(monkeypatch)
    result = await composer.compose(**kwargs)
    assert len(gateway.calls) == 2
    assert result.review.intent.canonical_intent_bytes() == kwargs["intent"].canonical_intent_bytes()
    assert result.review.route == result.route
    assert result.context.missing_required_sources() == ()
    assert result.text_signals
    assert result.allocation is None
    assert result.live_ready is False and result.policy == "REJECT_ALL"
    records = [json.loads(raw) for raw in sink.records.values()]
    assert {record.get("kind") for record in records} >= {"RSS_RESPONSE", "SENTIMENT_EXTRACTION"}
    assert {record.get("stage") for record in records} >= {
        "INTENT_INPUT",
        "TEXT_OUTPUT",
        "MACRO_CONTEXT_SELECTION",
        "ROUTER_OUTPUT",
        "DECISION_CONTEXT",
        "REVIEW_OUTPUT",
    }
    assert claims.completed == claims.claimed
    original_rss = next(raw for raw in sink.records.values() if json.loads(raw).get("kind") == "RSS_RESPONSE")
    source = read_native_rss_response(original_rss)
    assert source.response_body.startswith(b"<rss>")
    assert source.source_name == "https://fixture.invalid/feed"
    assert not hasattr(source, "persisted_at_ms")
    extraction_raw = next(
        raw for raw in sink.records.values() if json.loads(raw).get("kind") == "SENTIMENT_EXTRACTION"
    )
    calls = _native_calls(sink)
    extraction_request = json.loads(extraction_raw)["model_result"]["request_id"]
    text_call = next(
        pair
        for pair in calls.values()
        if json.loads(pair["completed"])["provider_call"]["request_id"] == extraction_request
    )
    extraction = read_native_sentiment_extraction(
        extraction_raw,
        attempt_record=text_call["started"],
        completion_record=text_call["completed"],
    )
    assert extraction.signals == result.text_signals
    assert extraction.model_call is not None
    assert extraction.model_call.response == base64.b64decode(
        json.loads(extraction_raw)["model_result"]["content_utf8"]["base64"],
    )
    review_pair = next(
        pair for pair in calls.values() if json.loads(pair["started"])["workload"] == "aggregator_normal"
    )
    review_call = read_native_budgeted_call(review_pair["started"], review_pair["completed"])
    assert hashlib.sha256(review_call.prompt).hexdigest() == result.review.model_provenance.prompt_sha256
    verify_native_call_receipts(
        native_call_receipts(
            attempt_record=review_pair["started"],
            completion_record=review_pair["completed"],
            captured_at_ms=composer.clock_ms(),
            bound_output_sha256=canonical_sha256(result.review),
        )
    )
    with pytest.raises(NativeCompositionRefused, match="already claimed"):
        await composer.compose(**kwargs)
    assert len(gateway.calls) == 2


async def test_cancelled_native_call_keeps_durable_claim_and_cannot_retry(monkeypatch):
    composer, kwargs, _sink, claims, gateway, _interlock = _native(monkeypatch)
    gateway.pause = True
    task = asyncio.create_task(composer.compose(**kwargs))
    await asyncio.wait_for(gateway.entered.wait(), timeout=2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert claims.claimed and not claims.completed
    with pytest.raises(NativeCompositionRefused, match="already claimed"):
        await composer.compose(**kwargs)
    assert len(gateway.calls) == 1


async def test_native_output_sink_failure_and_closed_interlock_prevent_model_calls(monkeypatch):
    composer, kwargs, sink, _claims, gateway, interlock = _native(monkeypatch)
    interlock[0] = False
    with pytest.raises(NativeCompositionRefused, match="cancelled"):
        await composer.compose(**kwargs)
    assert gateway.calls == []
    interlock[0] = True
    sink.fail = True
    with pytest.raises(OSError):
        await composer.compose(**kwargs)
    assert gateway.calls == []


async def test_same_intent_fresh_macro_is_refused_before_sources_claims_or_model_cost(monkeypatch):
    composer, kwargs, sink, claims, gateway, _interlock = _native(monkeypatch)
    kwargs["macro_context_json"] = '{"explicitly_synthetic_offline_context":true}'
    with pytest.raises(NativeCompositionRefused, match="fresh Macro work"):
        await composer.compose(**kwargs)
    assert gateway.calls == [] and sink.records == {} and claims.claimed == set()
    assert composer.components.extractor.gateway.budget.reserved == {}


async def test_causal_previously_retained_native_macro_is_reused_without_a_new_macro_call(monkeypatch):
    composer, kwargs, sink, _claims, gateway, _interlock = _native(monkeypatch)
    # Genuine native defensive output with its DEFAULT actual creation clock,
    # retained before the explicit synthetic next-minute fixture intent.
    original = composer.components.macro.defensive(kwargs["macro_trigger"])
    original_received = int(datetime.now(UTC).timestamp() * 1_000)
    composer.components.context_store.ingest("macro", original.to_payload(), received_at_ms=original_received)
    result = await composer.compose(**kwargs)
    assert result.allocation == original
    macro_source = next(source for source in result.context.sources if source.kind == "macro")
    assert macro_source.availability == "AVAILABLE"
    assert macro_source.receipts[0].received_at_ms == original_received
    assert result.allocation.produced_at == original.produced_at
    assert [call["workload"].value for call in gateway.calls] == ["text_scouts", "aggregator_normal"]
    selection = next(
        json.loads(raw)
        for raw in sink.records.values()
        if json.loads(raw).get("stage") == "MACRO_CONTEXT_SELECTION"
    )
    assert selection["payload"]["original_receipts"] == [macro_source.receipts[0].model_dump(mode="json")]


def test_actual_default_clock_macro_created_after_real_decision_cut_is_not_causal(monkeypatch):
    composer, kwargs, _sink, _claims, gateway, _interlock = _native(monkeypatch)
    actual_now = int(datetime.now(UTC).timestamp() * 1_000)
    real_decision_close = actual_now // 60_000 * 60_000 - 1
    values = kwargs["intent"].model_dump(mode="python")
    values.update(
        decision_ts_ms=real_decision_close,
        entry_eligible_ts_ms=real_decision_close + 1,
        entry_expires_ts_ms=real_decision_close + 120_000,
        intent_id=None,
    )
    intent = StrategyIntentV1.model_validate(values)
    text = SignalWindow().aggregate(
        intent.symbol, as_of=datetime.fromtimestamp(real_decision_close / 1_000, tz=UTC)
    )
    route = composer.components.router.build(intent, text)
    allocation = composer.components.macro.defensive(kwargs["macro_trigger"])
    received = int(datetime.now(UTC).timestamp() * 1_000)
    composer.components.context_store.ingest("macro", allocation.to_payload(), received_at_ms=received)
    source = composer.components.context_store._snapshot("macro", route, received, received)
    assert int(allocation.produced_at.timestamp() * 1_000) > route.routed_at_ms
    assert source.availability == "UNAVAILABLE"
    assert gateway.calls == []


def test_native_text_default_output_clock_is_original_publication_not_extractor_time():
    from kairos_text.models import NewsItem
    from kairos_text.schemas import SentimentBatch

    published = datetime.now(UTC) - timedelta(seconds=10)
    item = NewsItem(
        title="Bitcoin ETF rally",
        source="https://fixture.invalid/feed",
        source_kind="rss",
        url="https://fixture.invalid/news",
        published_at=published,
        timestamp_is_estimated=False,
    )
    batch = SentimentBatch.model_validate(
        {
            "signals": [
                {
                    "topic": "BTCUSDT",
                    "sentiment": 0.8,
                    "impact": "bullish",
                    "confidence": 0.8,
                    "summary": "Synthetic native source evidence.",
                    "item_ids": [1],
                }
            ]
        }
    )
    extractor = SentimentExtractor(None)
    signals = extractor._signals_from_batch((item,), batch)
    assert signals and signals[0].produced_at == published
    assert int(signals[0].produced_at.timestamp() * 1_000) < extractor._clock_ms()


async def test_post_intent_news_remains_retained_but_does_not_spend_text_budget(monkeypatch):
    composer, kwargs, sink, _claims, gateway, _interlock = _native(monkeypatch, news_after_intent=True)
    result = await composer.compose(**kwargs)
    assert result.text_signals == ()
    assert [call["workload"].value for call in gateway.calls] == ["aggregator_normal"]
    assert any(json.loads(raw).get("kind") == "RSS_RESPONSE" for raw in sink.records.values())
    assert not any(json.loads(raw).get("kind") == "SENTIMENT_EXTRACTION" for raw in sink.records.values())


async def test_native_text_failure_keeps_unknown_reservation_and_explicit_local_fallback(monkeypatch):
    composer, kwargs, sink, _claims, gateway, _interlock = _native(monkeypatch)
    gateway.fail_text = True
    result = await composer.compose(**kwargs)
    extraction_raw = next(
        raw for raw in sink.records.values() if json.loads(raw).get("kind") == "SENTIMENT_EXTRACTION"
    )
    extraction = read_native_sentiment_extraction(extraction_raw)
    assert extraction.output_origin == "NATIVE_DETERMINISTIC_FALLBACK"
    assert extraction.model_call is None
    assert extraction.signals == result.text_signals
    calls = _native_calls(sink)
    text_pair = next(
        pair for pair in calls.values() if json.loads(pair["started"])["workload"] == "text_scouts"
    )
    assert set(text_pair) == {"started"}
    budget = composer.components.extractor.gateway.budget
    assert len(budget.reserved) == 2 and len(budget.committed) == 1
    assert result.live_ready is False


async def test_native_empty_relevance_makes_no_text_provider_call(monkeypatch):
    composer, kwargs, sink, _claims, gateway, _interlock = _native(monkeypatch)
    composer.components.relevance.threshold = 10_000
    result = await composer.compose(**kwargs)
    assert [call["workload"].value for call in gateway.calls] == ["aggregator_normal"]
    assert result.text_signals == ()
    assert not any(json.loads(raw).get("kind") == "SENTIMENT_EXTRACTION" for raw in sink.records.values())


@pytest.mark.parametrize("substitution", ["response_body", "parsed_items", "persisted_at_ms"])
async def test_native_source_substitution_or_invented_persistence_clock_refuses(monkeypatch, substitution):
    composer, kwargs, sink, _claims, _gateway, _interlock = _native(monkeypatch)
    await composer.compose(**kwargs)
    source = next(
        json.loads(raw) for raw in sink.records.values() if json.loads(raw).get("kind") == "RSS_RESPONSE"
    )
    if substitution == "persisted_at_ms":
        source["persisted_at_ms"] = source["captured_at_ms"]
    else:
        body = (
            b"<rss><channel/></rss>"
            if substitution == "response_body"
            else canonical_json_bytes({"items": []})
        )
        source[substitution] = {
            "base64": base64.b64encode(body).decode(),
            "sha256": hashlib.sha256(body).hexdigest(),
        }
    with pytest.raises(ValueError):
        read_native_rss_response(canonical_json_bytes(source))


@pytest.mark.parametrize("substitution", ["model_result", "output", "input_items"])
async def test_native_text_result_output_or_input_substitution_refuses(monkeypatch, substitution):
    composer, kwargs, sink, _claims, _gateway, _interlock = _native(monkeypatch)
    await composer.compose(**kwargs)
    captured = next(
        json.loads(raw)
        for raw in sink.records.values()
        if json.loads(raw).get("kind") == "SENTIMENT_EXTRACTION"
    )
    text_pair = next(
        pair
        for pair in _native_calls(sink).values()
        if json.loads(pair["started"])["workload"] == "text_scouts"
    )
    if substitution == "model_result":
        captured["model_result"]["request_id"] = "foreign-request"
    else:
        decoded = json.loads(base64.b64decode(captured[substitution]["base64"]))
        if substitution == "output":
            decoded["signals"][0]["summary"] = "Foreign output, not the original model transformation."
        else:
            decoded["items"][0]["title"] = "Foreign source item, not the prompt input."
        body = canonical_json_bytes(decoded)
        captured[substitution] = {
            "base64": base64.b64encode(body).decode(),
            "sha256": hashlib.sha256(body).hexdigest(),
        }
    with pytest.raises(ValueError):
        read_native_sentiment_extraction(
            canonical_json_bytes(captured),
            attempt_record=text_pair["started"],
            completion_record=text_pair["completed"],
        )
