"""Original native intent deadline fixtures, not reviewed-plan/new-trigger promotion."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

pytest.importorskip("kairos_text.native_capture", reason="requires genuine optional native-inputs extra")

from kairos_execution.production_native_composition import NativeCompositionRefused  # noqa: E402
from tests.test_native_upstream_composition import _native  # noqa: E402


async def test_original_deadline_refuses_before_source_or_model_work(monkeypatch):
    composer, kwargs, sink, claims, gateway, _interlock = _native(monkeypatch)
    intent = kwargs["intent"]
    deadline = min(
        intent.entry_expires_ts_ms, intent.decision_ts_ms + composer.components.router.review_timeout_ms
    )
    composer.clock_ms = lambda: deadline
    with pytest.raises(NativeCompositionRefused, match="original deadline"):
        await composer.compose(**kwargs)
    assert gateway.calls == []
    assert claims.claimed == set()
    assert sink.records == {}


async def test_late_native_text_reply_cannot_retime_intent_market_or_start_review(monkeypatch):
    composer, kwargs, _sink, claims, gateway, _interlock = _native(monkeypatch)
    intent = kwargs["intent"]
    deadline = min(
        intent.entry_expires_ts_ms, intent.decision_ts_ms + composer.components.router.review_timeout_ms
    )
    state = [composer.clock_ms()]

    def clock():
        return state[0]

    composer.clock_ms = clock
    for component in (
        *composer.components.text_sources,
        composer.components.extractor,
        composer.components.reviewer,
    ):
        component._clock_ms = clock
    composer.components.freshness._clock = lambda: datetime.fromtimestamp(clock() / 1_000, tz=UTC)
    monkeypatch.setattr("kairos_llm.budget.time", SimpleNamespace(time_ns=lambda: clock() * 1_000_000))
    original_provider = gateway.complete

    async def delayed_provider(**options):
        reply = await original_provider(**options)
        state[0] = deadline
        return reply

    monkeypatch.setattr(gateway, "complete", delayed_provider)
    before_intent = intent.canonical_intent_bytes()
    before_market = kwargs["market"].model_dump(mode="json")
    with pytest.raises(NativeCompositionRefused, match="original deadline"):
        await composer.compose(**kwargs)
    assert [call["workload"].value for call in gateway.calls] == ["text_scouts"]
    assert kwargs["intent"].canonical_intent_bytes() == before_intent
    assert kwargs["market"].model_dump(mode="json") == before_market
    assert claims.claimed and not claims.completed
    # A later independent quote/reference is a different required boundary,
    # never permission to renew this original analytical attempt.
    assert composer.components.extractor.gateway.budget.committed
