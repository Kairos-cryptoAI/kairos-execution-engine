"""Explicit native component orchestration, never a LIVE admission mechanism.

No imports of observed/current-chain SIM wrappers, source clients, model gateways,
or persistence connections are constructed here. Deployment supplies the actual
native instances, capture sinks, original source inputs and durable claim store.
This API is absent from the default service/factory and cannot register itself.
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib
import inspect
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal, Protocol, cast

from kairos_core.contracts import (
    CandidateReviewV1,
    CandidateRouteV1,
    ClosedBarEventV1,
    DecisionContextV1,
    MarketSnapshot,
    SentimentSignal,
    StrategicAllocation,
    StrategyIntentV1,
    canonical_json_bytes,
    canonical_sha256,
)
from kairos_core.enums import StrategicTrigger


class NativeCompositionRefused(PermissionError):
    """Missing capture, cancellation, time, dedup or a native boundary refused."""


class NativeEmissionSink(Protocol):
    """Synchronously persist exact immutable native observations, create-only."""

    def create_only(self, observation_id: str, record: bytes) -> None: ...


class NativeProcessingClaims(Protocol):
    """Existing Text processing repository seam; unknown attempts stay fenced."""

    async def claim_batch(
        self,
        scope_key: str,
        event_keys: tuple[str, ...],
        attempt_id: str,
    ) -> tuple[str, ...]: ...

    async def complete_batch(
        self,
        scope_key: str,
        event_keys: tuple[str, ...],
        attempt_id: str,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class NativeUpstreamComponents:
    """Actual native analytical components, with their existing budgets/policies."""

    text_sources: tuple[Any, ...]
    normalizer: Any
    freshness: Any
    dedup: Any
    relevance: Any
    extractor: Any
    macro: Any
    window: Any
    router: Any
    context_store: Any
    reviewer: Any


@dataclass(frozen=True, slots=True)
class NativeUpstreamCompositionResult:
    route: CandidateRouteV1
    review: CandidateReviewV1
    context: DecisionContextV1
    allocation: StrategicAllocation | None
    text_signals: tuple[SentimentSignal, ...]
    emission_records: tuple[bytes, ...]
    # Exact raw Quant source replay performed before claims/model work; not a
    # readiness or authority receipt.
    native_market_bar_preflight_sha256: str | None = None
    # Engineering composition is not producer acceptance or execution authority.
    live_ready: Literal[False] = field(default=False, init=False)
    policy: Literal["REJECT_ALL"] = field(default="REJECT_ALL", init=False)


def _concrete(value: object, module: str, name: str) -> None:
    expected = getattr(importlib.import_module(module), name)
    if type(value) is not expected:
        raise TypeError(f"the actual native {module}.{name} instance is required")


def _allocation_from_context(context: DecisionContextV1) -> StrategicAllocation | None:
    """Project only the native store's original causal Macro observation.

    This is not qualification of Macro's raw source or model call. Deployment
    must still join this exact identity/digest/receipt to its retained source
    session before preparing a signed input envelope.
    """
    source = next(slot for slot in context.sources if slot.kind == "macro")
    if source.availability == "UNAVAILABLE":
        return None
    payloads = source.payloads()
    if len(payloads) != 1 or len(source.receipts) != 1:
        raise NativeCompositionRefused("native Macro context requires one exact original observation")
    allocation = StrategicAllocation.model_validate(payloads[0])
    receipt = source.receipts[0]
    produced = int(allocation.produced_at.timestamp() * 1_000)
    if (
        canonical_json_bytes(allocation) != canonical_json_bytes(payloads[0])
        or canonical_sha256(allocation) != receipt.content_sha256
        or allocation.message_id != receipt.message_id
        or allocation.source != receipt.source
        or produced != receipt.event_at_ms
        or produced != receipt.produced_at_ms
        or produced > context.event_as_of_ms
        or receipt.received_at_ms > context.knowledge_cutoff_ms
    ):
        raise NativeCompositionRefused("native Macro context lost its original causal identity or receipt")
    return allocation


class NativeUpstreamComposer:
    """Invoke native Text/Router/context/review with only causal retained Macro.

    Both source and extractor must already have independently configured native
    capture sinks. The emission sink adds output witnesses but does not replace
    original source bodies or immutable gateway call records. Durable claims
    happen before source/model work. Cancellation never releases an unknown
    attempt and no local cache is substituted for that fence.
    """

    def __init__(
        self,
        *,
        components: NativeUpstreamComponents,
        claims: NativeProcessingClaims,
        emission_sink: NativeEmissionSink,
        clock_ms: Callable[[], int],
        entry_interlock: Callable[[], bool],
        market_bar_preflight: Callable[..., str] | None = None,
        composition_scope: str,
        text_scope: str,
    ) -> None:
        specs = (
            (components.normalizer, "kairos_text.normalize", "EventNormalizer"),
            (components.freshness, "kairos_text.freshness", "EventFreshnessFilter"),
            (components.dedup, "kairos_text.dedup", "EventDeduplicator"),
            (components.relevance, "kairos_text.filter", "LocalRelevanceFilter"),
            (components.extractor, "kairos_text.sentiment", "SentimentExtractor"),
            (components.macro, "kairos_macro.strategist", "MacroStrategist"),
            (components.window, "kairos_router.aggregation", "SignalWindow"),
            (components.router, "kairos_router.candidate", "CandidateRouterPolicy"),
            (components.context_store, "kairos_aggregator.decision_context", "CandidateContextStore"),
            (components.reviewer, "kairos_aggregator.candidate_review", "CandidateReviewBrain"),
        )
        for value, module, name in specs:
            _concrete(value, module, name)
        from .production_native_inputs import NativeLLMCallSinkAdapter

        for component in (components.extractor, components.macro, components.reviewer):
            _concrete(component.gateway, "kairos_llm.budget", "BudgetedLLMGateway")
            adapter = component.gateway.evidence_sink
            if type(adapter) is not NativeLLMCallSinkAdapter or adapter.sink is not emission_sink:
                raise ValueError("native workloads require original budgeted call records in this session")
        if not isinstance(components.text_sources, tuple) or not 1 <= len(components.text_sources) <= 2:
            raise ValueError("one or two explicitly captured native Text sources are required")
        for source in components.text_sources:
            # Only RSS has a retained original-body capture seam at present.
            _concrete(source, "kairos_text.sources.rss", "RSSSource")
            if not source.enabled:
                raise ValueError("native captured Text source is disabled")
            if getattr(source, "capture_sink", None) is not emission_sink:
                raise ValueError("native Text source must retain original responses in this capture session")
            if getattr(source, "_clock_ms", None) is not clock_ms:
                raise ValueError("native source capture must share the exact composition clock")
        if getattr(components.extractor, "capture_sink", None) is not emission_sink:
            raise ValueError("native Text extractor must retain original input/model/output in this session")
        if (
            getattr(components.extractor, "_clock_ms", None) is not clock_ms
            or getattr(components.reviewer, "_clock_ms", None) is not clock_ms
        ):
            raise ValueError("native extraction/review must share the exact composition clock")
        feeds = tuple(feed for source in components.text_sources for feed in source.feeds)
        if not 1 <= len(feeds) <= 2 or len(set(feeds)) != len(feeds):
            raise ValueError("one or two distinct explicitly retained native RSS feed identities required")
        if (
            not composition_scope
            or not text_scope
            or composition_scope == text_scope
            or not callable(clock_ms)
            or not callable(entry_interlock)
            or (market_bar_preflight is not None and not callable(market_bar_preflight))
            or not callable(getattr(claims, "claim_batch", None))
            or not callable(getattr(claims, "complete_batch", None))
            or not callable(getattr(emission_sink, "create_only", None))
        ):
            raise ValueError("explicit independent claims, capture sink, scopes and clock/interlock required")
        if (
            components.freshness.max_age_s > 1_800
            or components.freshness.max_future_skew_s != 0
            or components.freshness.allow_estimated_timestamps
            or components.window.sentiment_ttl_s > 600
            or components.context_store.settings.sentiment_ttl_s > 600
        ):
            raise ValueError("native Text source/planning clock limits cannot be relaxed")
        self.components = components
        self.claims = claims
        self.sink = emission_sink
        self.clock_ms = clock_ms
        self.interlock = entry_interlock
        self.market_bar_preflight = market_bar_preflight
        self.composition_scope = composition_scope
        self.text_scope = text_scope
        self._previous_ms: int | None = None
        self._active = False

    def _check(self, deadline: int) -> int:
        now = self.clock_ms()
        if type(now) is not int or now < 0 or (self._previous_ms is not None and now < self._previous_ms):
            raise NativeCompositionRefused("native composition clock moved backwards or is invalid")
        self._previous_ms = now
        result = self.interlock()
        if inspect.iscoroutine(result):
            result.close()
        if result is not True or now >= deadline:
            raise NativeCompositionRefused("native composition cancelled or original deadline expired")
        return now

    def _emit(self, intent: StrategyIntentV1, stage: str, payload: object, *, deadline: int) -> bytes:
        observed = self._check(deadline)
        record = canonical_json_bytes(
            {
                "version": "kairos.native-upstream-emission.v1",
                "capture_scope": "native-output-not-authority",
                "intent_id": intent.intent_id,
                "stage": stage,
                "observed_at_ms": observed,
                "payload": payload,
            }
        )
        if len(record) > 1_000_000:
            raise NativeCompositionRefused("native emitted observation exceeds the retained byte bound")
        observation_id = hashlib.sha256(f"{intent.intent_id}:{stage}".encode()).hexdigest()[:32]
        writer = cast(Callable[..., object], self.sink.create_only)
        acknowledgement = writer(observation_id, record)
        if inspect.iscoroutine(acknowledgement):
            acknowledgement.close()
        if acknowledgement is not None:
            raise NativeCompositionRefused("native output persistence was not synchronously acknowledged")
        self._check(deadline)
        return record

    async def _claim(self, scope: str, keys: tuple[str, ...], attempt: str, deadline: int) -> tuple[str, ...]:
        self._check(deadline)
        claimed = await self.claims.claim_batch(scope, keys, attempt)
        self._check(deadline)
        if (
            not isinstance(claimed, tuple)
            or len(set(claimed)) != len(claimed)
            or any(key not in keys for key in claimed)
        ):
            raise NativeCompositionRefused("native durable processing repository returned foreign claims")
        return claimed

    async def compose(
        self,
        *,
        intent: StrategyIntentV1,
        market: MarketSnapshot,
        bars: tuple[ClosedBarEventV1, ...],
        macro_context_json: str | None,
        macro_trigger: StrategicTrigger,
    ) -> NativeUpstreamCompositionResult:
        """Serialize one native pipeline; do not queue or renew an old attempt."""
        if self._active:
            raise NativeCompositionRefused("native analytical composition is already in progress")
        self._active = True
        try:
            return await self._compose(
                intent=intent,
                market=market,
                bars=bars,
                macro_context_json=macro_context_json,
                macro_trigger=macro_trigger,
            )
        finally:
            self._active = False

    async def _compose(
        self,
        *,
        intent: StrategyIntentV1,
        market: MarketSnapshot,
        bars: tuple[ClosedBarEventV1, ...],
        macro_context_json: str | None,
        macro_trigger: StrategicTrigger,
    ) -> NativeUpstreamCompositionResult:
        """One bounded native composition; partial/unknown calls cannot be retried.

        Market/bars must already have exact original receipts in the native
        context store, before any claims/source/model work. Independent raw
        source witnesses remain required. This method does not qualify their contents or invent
        an account, strategy intent, route override, model result or geometry.
        ``macro_context_json`` is retained only as a fail-closed compatibility
        argument: non-None refuses before spending. ``macro_trigger`` cannot
        create a new allocation or promote a new trigger in this entry path.
        """
        c = self.components
        if macro_context_json is not None:
            # A fresh allocation created after this original intent cannot be
            # causal at its event cut. Refuse before claims, sources or spending;
            # never retime it, reroute the intent, or widen the review deadline.
            raise NativeCompositionRefused(
                "fresh Macro work cannot run inside an original intent; retained causal context required"
            )
        intent = StrategyIntentV1.model_validate(intent.model_dump(mode="json"))
        market = MarketSnapshot.model_validate(market.model_dump(mode="json"))
        if not isinstance(bars, tuple) or not 1 <= len(bars) <= 1_440:
            raise NativeCompositionRefused("bounded original native closed bars are required")
        bars = tuple(ClosedBarEventV1.model_validate(bar.model_dump(mode="json")) for bar in bars)
        deadline = min(intent.entry_expires_ts_ms, intent.decision_ts_ms + c.router.review_timeout_ms)
        now = self._check(deadline)
        if intent.decision_ts_ms > now:
            raise NativeCompositionRefused("native strategy intent postdates composition")
        if market.symbol != intent.symbol or any(bar.symbol != intent.symbol for bar in bars):
            raise NativeCompositionRefused("native market/bar symbol differs from immutable strategy intent")
        try:
            market_receipt = c.context_store.require_retained_observation(
                "market", market.model_dump(mode="json"), at_ms=now
            )
            bar_receipts = tuple(
                c.context_store.require_retained_observation(
                    "closed_bars", bar.model_dump(mode="json"), at_ms=now
                )
                for bar in bars
            )
        except (ValueError, AttributeError):
            raise NativeCompositionRefused(
                "original retained market/bar observations are missing, changed or expired"
            ) from None
        preflight_sha256 = None
        if self.market_bar_preflight is not None:
            preflight_sha256 = self.market_bar_preflight(
                market,
                bars,
                market_receipt,
                bar_receipts,
                now,
            )
            if inspect.isawaitable(preflight_sha256):
                close = getattr(preflight_sha256, "close", None)
                if callable(close):
                    close()
                raise NativeCompositionRefused("native Quant source preflight must be local and synchronous")
            if (
                not isinstance(preflight_sha256, str)
                or len(preflight_sha256) != 64
                or any(character not in "0123456789abcdef" for character in preflight_sha256)
            ):
                raise NativeCompositionRefused(
                    "native Quant source preflight returned no exact selection digest"
                )
            self._check(deadline)
        attempt = hashlib.sha256(intent.canonical_intent_bytes()).hexdigest()
        async with asyncio.timeout((deadline - now) / 1_000):
            if await self._claim(self.composition_scope, (attempt,), attempt, deadline) != (attempt,):
                raise NativeCompositionRefused("native composition already claimed; no blind renewal")
            records = [self._emit(intent, "INTENT_INPUT", intent.model_dump(mode="json"), deadline=deadline)]
            records.append(
                self._emit(
                    intent,
                    "MARKET_BAR_CONTEXT_SELECTION",
                    {
                        "market_receipt": market_receipt.model_dump(mode="json"),
                        "bar_receipts": [receipt.model_dump(mode="json") for receipt in bar_receipts],
                    },
                    deadline=deadline,
                )
            )
            raw = []
            for source in c.text_sources:
                self._check(deadline)
                raw.extend(await source.fetch())
                self._check(deadline)
            timely = c.freshness.select(c.normalizer.normalize(raw))
            if any(item.published_at.utcoffset() is None for item in timely):
                raise NativeCompositionRefused("native news publication needs an original aware event clock")
            causal_items = [
                item for item in timely if int(item.published_at.timestamp() * 1_000) <= intent.decision_ts_ms
            ]
            selected = c.relevance.select(c.dedup.filter_unseen(c.dedup.collapse_batch(causal_items)))
            from kairos_text.dedup import dedup_key  # type: ignore[import-not-found,import-untyped]

            by_key = {hashlib.sha256(dedup_key(item).encode("utf-8")).hexdigest(): item for item in selected}
            event_keys = tuple(sorted(by_key))
            claimed = await self._claim(self.text_scope, event_keys, attempt, deadline) if event_keys else ()
            selected = [by_key[key] for key in claimed]
            signals = tuple(await c.extractor.extract(selected)) if selected else ()
            self._check(deadline)
            records.append(
                self._emit(
                    intent,
                    "TEXT_OUTPUT",
                    {
                        "items": [signal.model_dump(mode="json") for signal in signals],
                    },
                    deadline=deadline,
                )
            )
            for signal in signals:
                topic = signal.topic.strip().upper()
                symbol = topic if c.context_store.settings.symbol_allowed(signal.topic) else "*"
                c.window.add_sentiment(
                    symbol,
                    message_id=signal.message_id,
                    produced_at=signal.produced_at,
                    sentiment=signal.sentiment,
                    impact=signal.impact,
                    confidence=signal.confidence,
                )
                c.context_store.ingest(
                    "text", signal.model_dump(mode="json"), received_at_ms=self._check(deadline)
                )
            as_of = datetime.fromtimestamp(intent.decision_ts_ms / 1_000, tz=UTC)
            text = c.window.aggregate(intent.symbol, as_of=as_of)
            if not text.has_relevant_evidence:
                text = c.window.aggregate("*", as_of=as_of)
            route = c.router.build(intent, text)
            records.append(
                self._emit(intent, "ROUTER_OUTPUT", route.model_dump(mode="json"), deadline=deadline)
            )
            captured = self._check(deadline)
            context = c.context_store.build(route, cutoff_ms=captured, captured_at_ms=captured)
            allocation = _allocation_from_context(context)
            macro_source = next(slot for slot in context.sources if slot.kind == "macro")
            records.append(
                self._emit(
                    intent,
                    "MACRO_CONTEXT_SELECTION",
                    {
                        "availability": macro_source.availability,
                        "allocation": allocation.model_dump(mode="json") if allocation is not None else None,
                        "original_receipts": [
                            receipt.model_dump(mode="json") for receipt in macro_source.receipts
                        ],
                        "reason_code": macro_source.reason_code,
                    },
                    deadline=deadline,
                )
            )
            records.append(
                self._emit(intent, "DECISION_CONTEXT", context.model_dump(mode="json"), deadline=deadline)
            )
            self._check(deadline)
            review = await c.reviewer.review_with_context(route, context)
            self._check(deadline)
            records.append(
                self._emit(intent, "REVIEW_OUTPUT", review.model_dump(mode="json"), deadline=deadline)
            )
            # Actual native calls own immutable intent/route/context validation.
            # The final assertion prevents a replacement analytical component
            # from modifying Strategy-owned geometry through this boundary.
            if (
                review.intent.canonical_intent_bytes() != intent.canonical_intent_bytes()
                or canonical_json_bytes(review.route) != canonical_json_bytes(route)
            ):
                raise NativeCompositionRefused("native review changed immutable strategy/route authority")
            if claimed:
                await self.claims.complete_batch(self.text_scope, claimed, attempt)
                self._check(deadline)
            await self.claims.complete_batch(self.composition_scope, (attempt,), attempt)
            self._check(deadline)
            published_refs = {reference for signal in signals for reference in signal.sources}
            c.dedup.remember(item for item in selected if published_refs.intersection(item.provenance_refs))
            return NativeUpstreamCompositionResult(
                route,
                review,
                context,
                allocation,
                signals,
                tuple(records),
                preflight_sha256,
            )


__all__ = ["NativeUpstreamComponents", "NativeUpstreamComposer", "NativeUpstreamCompositionResult"]
