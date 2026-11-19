"""Native GTC contract tests; synthetic data and no venue mutations."""

from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from kairos_execution.limit_gtc_contract import LIMIT_GTC_ENTRY_CONTRACT, LimitGtcEntryV1
from kairos_execution.paper_engine import PaperExecutionSafetyError
from kairos_execution.production_cancellation import (
    ProductionCancellationError,
    ProductionCancellationVerifier,
)
from kairos_execution.production_dispatch import production_wire_body
from kairos_execution.production_lifecycle import ProductionLifecycleEngine
from kairos_execution.production_lifecycle_binding import build_production_lifecycle_binding
from kairos_execution.production_lifecycle_store import PostgresLifecycleBindingStore
from kairos_execution.production_transport import ProductionTransportError, _validate_signed_post
from tests.test_production_lifecycle_binding import _build, _decision, _scope


def _gtc_binding(*, deadline_delta=2_000):
    decision = _decision()
    context, custody = _scope(decision)
    legacy, now, expiry = _build(decision, context, custody, expiry_delta=timedelta(seconds=1))
    entry = LimitGtcEntryV1(cancel_after_ms=int(now.timestamp() * 1000) + deadline_delta)
    bound = build_production_lifecycle_binding(
        decision=decision,
        context=context,
        custody_binding=custody,
        role="ENTRY",
        lifecycle_effect_id=legacy.lifecycle_effect_id,
        client_order_id=__import__("json").loads(legacy.request.message_json)["id"],
        manual_request_sha256=legacy.request.manual_request_sha256,
        expires_at=expiry,
        now=now,
        limit_gtc_entry=entry,
    )
    return decision, legacy, bound, now


def test_native_gtc_wire_has_fixed_qty_price_and_no_unsupported_tif_override():
    message = {
        "id": "00474:ABCDEF0123456789ABCDEF0123",
        "instrument": "BTCUSD",
        "side": "BUY",
        "leverage": 1,
        "quantity": 1_000_000,
        "limitPrice": 10_000_000_000,
        "chainId": 42161,
    }
    native = production_wire_body("New limit order", message, "0x" + "11" * 65, limit_time_in_force="GTC")
    assert native["quantity"] == "0.01" and native["limitPrice"] == "100"
    assert "timeInForce" not in native
    _validate_signed_post("POST", "/api/v2/order/limit", native)
    legacy = production_wire_body("New limit order", message, "0x" + "11" * 65)
    assert legacy["timeInForce"] == "IOC"
    with pytest.raises(ProductionTransportError, match="limit orders are GTC"):
        _validate_signed_post("POST", "/api/v2/order/limit", legacy)


def test_deadline_is_persisted_in_canonical_request_identity_without_rewriting_legacy():
    decision, legacy, bound, _ = _gtc_binding()
    assert "limit_gtc_entry" not in legacy.model_dump(mode="json")
    assert bound.limit_gtc_entry.contract == LIMIT_GTC_ENTRY_CONTRACT
    assert legacy.request.request_id != bound.request.request_id
    _, _, changed, _ = _gtc_binding(deadline_delta=3_000)
    assert changed.request.request_id != bound.request.request_id
    store = object.__new__(PostgresLifecycleBindingStore)
    store.context = bound.context
    from kairos_execution.production_readiness import canonical_digest

    store.context_sha256 = canonical_digest(bound.context)
    store._validate_binding(bound)
    assert bound.decision_id == decision.decision_id


@pytest.mark.parametrize("delta", [-1, 0, 999, 5_001])
def test_deadline_cannot_expire_before_signing_or_exceed_five_seconds(delta):
    with pytest.raises(ValueError):
        _gtc_binding(deadline_delta=delta)


@pytest.mark.asyncio
async def test_native_gtc_waits_only_original_deadline_then_shared_cancel_proves_no_exposure():
    decision, _, binding, now = _gtc_binding()
    time = [now]
    engine = object.__new__(ProductionLifecycleEngine)
    engine.clock = lambda: time[0]
    engine._limit_gtc_entry_bindings = {decision.trade_id: binding}
    engine.adapter = SimpleNamespace(fetch_paper_state=AsyncMock(return_value={}))
    engine._settled_entry_projection = lambda *_: (None, False)
    engine._position_quantity_for_trade = lambda *_: 0
    engine._find_order = lambda *_: None
    engine._cancel_entry_effect = AsyncMock(return_value={"id": "exact-entry", "status": "CANCELED"})

    async def sleep(seconds):
        time[0] += timedelta(seconds=seconds)

    engine._sleep = sleep
    trade = SimpleNamespace(trade_id=decision.trade_id, entry_client_order_id="exact-entry")
    engine._validate_entry_response = lambda *_, **__: ("exact-entry", "NEW", 0, 0)
    engine._transition_with_event = AsyncMock(return_value=(trade, None))
    result = await engine._settle_or_cancel_ioc_entry(decision, trade, {"id": "exact-entry", "status": "NEW"})
    assert result["status"] == "CANCELED"
    assert int(time[0].timestamp() * 1000) >= binding.limit_gtc_entry.cancel_after_ms
    engine._cancel_entry_effect.assert_awaited_once()


@pytest.mark.asyncio
async def test_partial_fill_is_returned_immediately_to_protection_not_waited_until_deadline():
    decision, _, binding, now = _gtc_binding()
    engine = object.__new__(ProductionLifecycleEngine)
    engine.clock = lambda: now
    engine._limit_gtc_entry_bindings = {decision.trade_id: binding}
    partial = {"id": "exact-entry", "status": "PARTIALLY_FILLED"}
    engine.adapter = SimpleNamespace(fetch_paper_state=AsyncMock(return_value={}))
    engine._settled_entry_projection = lambda *_: (partial, True)
    engine._sleep = AsyncMock()
    engine._cancel_entry_effect = AsyncMock()
    trade = SimpleNamespace(trade_id=decision.trade_id, entry_client_order_id="exact-entry")
    engine._validate_entry_response = lambda *_, **__: ("exact-entry", "NEW", 0, 0)
    engine._transition_with_event = AsyncMock(return_value=(trade, None))
    result = await engine._settle_or_cancel_ioc_entry(decision, trade, {"status": "NEW"})
    assert result is partial
    engine._sleep.assert_not_awaited()
    engine._cancel_entry_effect.assert_not_awaited()


@pytest.mark.asyncio
async def test_unknown_gtc_cancel_does_not_report_remainder_absent():
    engine = object.__new__(ProductionLifecycleEngine)
    engine.adapter = SimpleNamespace(fetch_paper_state=AsyncMock(return_value={}))
    engine._find_order = lambda *_: {"status": "NEW"}
    engine._cancel_entry_effect = AsyncMock(return_value={"id": "exact-entry", "status": "NEW"})
    with pytest.raises(PaperExecutionSafetyError, match="not confirmed"):
        await engine._cancel_gtc_remainder(SimpleNamespace(entry_client_order_id="exact-entry"))


@pytest.mark.asyncio
async def test_confirmed_gtc_cancel_still_refuses_surviving_remainder():
    engine = object.__new__(ProductionLifecycleEngine)
    engine.adapter = SimpleNamespace(fetch_paper_state=AsyncMock(return_value={}))
    engine._find_order = lambda *_: {"status": "NEW"}
    engine._cancel_entry_effect = AsyncMock(return_value={"id": "exact-entry", "status": "CANCELLED"})
    with pytest.raises(PaperExecutionSafetyError, match="still open"):
        await engine._cancel_gtc_remainder(SimpleNamespace(entry_client_order_id="exact-entry"))


@pytest.mark.parametrize(
    "fault", ["legacy_ioc_binding", "market", "filled_remainder", "partial_zero", "chain"]
)
def test_recovered_gtc_record_is_not_a_legacy_or_incoherent_geometry_fallback(fault):
    import json

    _, legacy, binding, _ = _gtc_binding()
    message = json.loads(binding.request.message_json)
    record = {
        "id": message["id"],
        "instrument": message["instrument"],
        "side": message["side"],
        "type": "LIMIT",
        "quantity": message["quantity"] / 100_000_000,
        "unFilledQuantity": message["quantity"] / 200_000_000,
        "limitPrice": message["limitPrice"] / 100_000_000,
        "filledAvgPrice": message["limitPrice"] / 100_000_000,
        "leverage": message["leverage"],
        "status": "PARTIALLY_FILLED",
    }
    if fault == "legacy_ioc_binding":
        binding = legacy
    elif fault == "market":
        record["type"] = "MARKET"
    elif fault == "filled_remainder":
        record["status"] = "FILLED"
    elif fault == "partial_zero":
        record["unFilledQuantity"] = 0
    elif fault == "chain":
        record["chainId"] = 1
    with pytest.raises(ProductionCancellationError, match="positive signed order geometry"):
        ProductionCancellationVerifier._validate_recovered_gtc_record(binding, record)
