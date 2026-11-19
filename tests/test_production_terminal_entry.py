"""Offline terminal-entry fence; absence and unknown cancellation grant no close."""

import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from kairos_core.enums import OrderRole
from kairos_persistence import EffectStatus, EffectType, TradeState

from kairos_execution.managed_signer import reviewed_schema_sha256
from kairos_execution.market_ioc_admission import MARKET_IOC_ENTRY_CONTRACT, MarketIocEntryRequestV1
from kairos_execution.paper_engine import PaperExecutionSafetyError, _EvedexProtectedExecutionEngine
from kairos_execution.production_lifecycle_binding import build_production_lifecycle_binding
from kairos_execution.production_readiness import canonical_digest
from kairos_execution.state_machine import client_order_id
from tests.test_market_ioc_admission import DynamicSyntheticEnvelopeVerifier
from tests.test_production_lifecycle import _bare_engine, _config
from tests.test_production_lifecycle_binding import _decision


def fixture(*, market=True):
    decision = _decision()
    config = _config()
    custody = config.custody_binding.model_copy(
        update={"chain_id": 42161, "schema_sha256": reviewed_schema_sha256(42161)}
    )
    config = config.model_copy(update={"custody_binding": custody})
    engine = _bare_engine(config)
    original_ms = max(decision.decided_at_ms, decision.intent.entry_eligible_ts_ms) + 100
    original_now = datetime.fromtimestamp(original_ms / 1000, UTC)
    entry_id = client_order_id(
        f"{decision.trade_id}:ENTRY",
        "evedex",
        occurred_at=datetime.fromtimestamp(decision.decided_at_ms / 1000, UTC),
    )
    trade = SimpleNamespace(
        trade_id=decision.trade_id,
        risk_decision_id=decision.decision_id,
        risk_decision_payload=decision.to_payload(),
        strategy_intent_id=decision.intent.intent_id,
        symbol=decision.intent.symbol,
        venue_symbol=decision.venue_symbol,
        side="BUY",
        leverage=1,
        quantity=decision.quantity,
        filled_quantity=0.05,
        state=TradeState.PROTECTING,
        environment=engine._environment,
        account_id=decision.account_id,
        exchange="evedex",
        entry_client_order_id=entry_id,
    )
    effect_id = engine._effect_id(trade.trade_id, OrderRole.ENTRY, "place")
    request = None
    envelope = None
    payload = {
        "trade_id": trade.trade_id,
        "intent_id": trade.strategy_intent_id,
        "client_order_id": entry_id,
        "venue_symbol": trade.venue_symbol,
        "side": trade.side,
        "leverage_hex": float(1).hex(),
    }
    if market:
        request = MarketIocEntryRequestV1(
            source_id=DynamicSyntheticEnvelopeVerifier.source_id,
            proof_sha256="a" * 64,
            cash_quantity_e8=1_000_000_000,
        )
        envelope = DynamicSyntheticEnvelopeVerifier(original_ms).verify(
            request,
            context=config.context,
            decision=decision,
            now_ms=original_ms,
        )
        payload.update(
            entry_contract=MARKET_IOC_ENTRY_CONTRACT,
            cash_quantity_e8=request.cash_quantity_e8,
            market_envelope_sha256=canonical_digest(envelope),
            quantity_cap_hex=float(decision.quantity).hex(),
        )
    else:
        payload.update(
            quantity_hex=float(decision.quantity).hex(),
            limit_price_hex=float(decision.worst_entry_price).hex(),
        )
    binding = build_production_lifecycle_binding(
        decision=decision,
        context=config.context,
        custody_binding=custody,
        role="ENTRY",
        lifecycle_effect_id=effect_id,
        client_order_id=entry_id,
        manual_request_sha256="a" * 64,
        expires_at=original_now + timedelta(seconds=1),
        now=original_now,
        market_ioc_entry=request,
        market_ioc_envelope=envelope,
    )
    effect = SimpleNamespace(
        effect_type=EffectType.PLACE_ORDER,
        status=EffectStatus.PREPARED,
        trade_id=trade.trade_id,
        client_order_id=entry_id,
        environment=trade.environment,
        account_id=trade.account_id,
        exchange=trade.exchange,
        symbol=trade.symbol,
        order_role="ENTRY",
        request_payload=payload,
    )
    engine.adapter = SimpleNamespace(bindings=SimpleNamespace(get=AsyncMock(return_value=binding)))
    engine.effects = SimpleNamespace(
        get=AsyncMock(return_value=effect), verify_chain=AsyncMock(return_value=True)
    )
    engine.trades = SimpleNamespace(verify_chain=AsyncMock(return_value=True))
    # Historical terminal proof remains usable after its original entry lease.
    engine.clock = lambda: original_now + timedelta(days=1)
    history = {
        "id": entry_id,
        "instrument": trade.venue_symbol,
        "side": "BUY",
        "type": "MARKET" if market else "LIMIT",
        "status": "CANCELED",
        "quantity": "0.1",
        "unFilledQuantity": "0.05",
    }
    if market:
        history["timeInForce"] = "IOC"
    venue = {
        "account": {"exchangeId": trade.account_id},
        "orders": [],
        "order_history": [history],
        "positions": [{"instrument": trade.venue_symbol, "side": "BUY", "leverage": 1, "quantity": "0.05"}],
    }
    return engine, decision, trade, effect, venue


@pytest.mark.asyncio
@pytest.mark.parametrize("market", [False, True])
async def test_exact_terminal_owned_partial_allows_only_later_independent_close(market):
    engine, decision, trade, _effect, venue = fixture(market=market)
    # Missing fee/cash fields do not become an economically accepted entry ACK.
    await engine._assert_terminal_entry_before_close(decision, trade, venue)


@pytest.mark.asyncio
async def test_terminal_fence_checks_signed_ioc_if_order_history_omits_tif():
    engine, decision, trade, _effect, venue = fixture()
    del venue["order_history"][0]["timeInForce"]
    await engine._assert_terminal_entry_before_close(decision, trade, venue)
    venue["order_history"][0]["timeInForce"] = "FOK"
    with pytest.raises(PaperExecutionSafetyError):
        await engine._assert_terminal_entry_before_close(decision, trade, venue)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault",
    [
        "absence_only",
        "unknown_cancel_marker",
        "open_entry",
        "nonterminal",
        "rejected_fill",
        "filled_remainder",
        "missing_type",
        "other_type",
        "other_side",
        "other_account",
        "unknown_quantity",
        "unowned_quantity",
        "wrong_prepared_cash",
        "bad_chain",
    ],
)
async def test_unknown_or_incoherent_entry_terminal_facts_do_not_allow_close(fault):
    engine, decision, trade, effect, venue = fixture()
    record = venue["order_history"][0]
    if fault in {"absence_only", "unknown_cancel_marker"}:
        venue["order_history"] = []
        if fault == "unknown_cancel_marker":
            # The shared recovery marker cannot replace original terminal proof.
            effect.status = EffectStatus.RECONCILED
            effect.response_payload = {"active": False}
    elif fault == "open_entry":
        venue["orders"] = [record]
    elif fault == "nonterminal":
        record["status"] = "PARTIALLY_FILLED"
    elif fault == "rejected_fill":
        record["status"] = "REJECTED"
    elif fault == "filled_remainder":
        record["status"] = "FILLED"
    elif fault == "missing_type":
        record.pop("type")
    elif fault == "other_type":
        record["type"] = "LIMIT"
    elif fault == "other_side":
        record["side"] = "SELL"
    elif fault == "other_account":
        venue["account"]["exchangeId"] = "other"
    elif fault == "unknown_quantity":
        record.pop("quantity")
    elif fault == "unowned_quantity":
        record["unFilledQuantity"] = "0.06"
    elif fault == "wrong_prepared_cash":
        effect.request_payload["cash_quantity_e8"] += 1
    else:
        engine.effects.verify_chain.return_value = False
    with pytest.raises(PaperExecutionSafetyError):
        await engine._assert_terminal_entry_before_close(decision, trade, venue)


@pytest.mark.asyncio
async def test_absence_after_unknown_cancel_cannot_reach_shared_close_path(monkeypatch):
    engine, decision, trade, _effect, venue = fixture()
    venue["order_history"] = []
    engine.adapter.fetch_paper_state = AsyncMock(return_value=venue)
    shared = AsyncMock()
    monkeypatch.setattr(_EvedexProtectedExecutionEngine, "_cancel_entry_and_measure_position", shared)
    with pytest.raises(PaperExecutionSafetyError, match="absence is insufficient"):
        await engine._cancel_entry_and_measure_position(decision, trade)
    shared.assert_not_awaited()


@pytest.mark.asyncio
async def test_positive_cancel_waits_for_exact_terminal_history_before_shared_close_path(monkeypatch):
    engine, decision, trade, _effect, terminal = fixture()
    before = {**terminal, "orders": [{**terminal["order_history"][0], "status": "PARTIALLY_FILLED"}]}
    engine.adapter.fetch_paper_state = AsyncMock(side_effect=[before, terminal])
    engine._cancel_entry_effect = AsyncMock(
        return_value={"id": trade.entry_client_order_id, "status": "CANCELED"}
    )
    shared = AsyncMock(return_value=(trade, 0.05, []))
    monkeypatch.setattr(_EvedexProtectedExecutionEngine, "_cancel_entry_and_measure_position", shared)
    assert await engine._cancel_entry_and_measure_position(decision, trade) == (trade, 0.05, [])
    engine._cancel_entry_effect.assert_awaited_once_with(trade)
    shared.assert_awaited_once_with(decision, trade)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure", [PaperExecutionSafetyError("unknown STOP cleanup"), asyncio.CancelledError()]
)
async def test_unknown_emergency_cleanup_blocks_direct_engine_and_preserves_failure(monkeypatch, failure):
    engine, decision, trade, _effect, _venue = fixture()
    engine._block_entries_unlocked = AsyncMock()
    monkeypatch.setattr(_EvedexProtectedExecutionEngine, "_emergency_close", AsyncMock(side_effect=failure))
    with pytest.raises(type(failure)):
        await engine._emergency_close(decision, trade, "first STOP failed")
    assert engine.recovery_blocked
    engine._block_entries_unlocked.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "pending_role, action", [(OrderRole.STOP_LOSS, "create"), (OrderRole.ENTRY, "cancel")]
)
async def test_protection_ambiguity_grace_does_not_postpone_fenced_owned_reduction(
    monkeypatch, pending_role, action
):
    engine, decision, trade, _effect, venue = fixture()
    pending = engine._effect_id(trade.trade_id, pending_role, action)
    monkeypatch.setattr(_EvedexProtectedExecutionEngine, "_unripe_effects", AsyncMock(return_value=[pending]))
    engine._recovered_events = []
    engine.adapter.fetch_paper_state = AsyncMock(return_value=venue)
    # Preserve the production exception wrapper at the new recovery hook;
    # terminal fact validation is covered independently above and in native PG.
    shared_close = AsyncMock(return_value=["reduced"])
    monkeypatch.setattr(_EvedexProtectedExecutionEngine, "_emergency_close", shared_close)
    result = await engine._unripe_effects(trade, eligible_effect_keys=set())
    assert result == [pending]
    assert engine._recovered_events == ["reduced"]
    shared_close.assert_awaited_once()


@pytest.mark.asyncio
async def test_pending_unknown_close_itself_is_not_reissued_from_ambiguity_grace(monkeypatch):
    engine, _decision, trade, _effect, _venue = fixture()
    trade.state = TradeState.EXITING_EMERGENCY
    pending = engine._effect_id(trade.trade_id, OrderRole.EMERGENCY_EXIT, "close")
    monkeypatch.setattr(_EvedexProtectedExecutionEngine, "_unripe_effects", AsyncMock(return_value=[pending]))
    engine._emergency_close = AsyncMock()
    assert await engine._unripe_effects(trade, eligible_effect_keys=set()) == [pending]
    engine._emergency_close.assert_not_awaited()
