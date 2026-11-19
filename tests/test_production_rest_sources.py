"""EVEDEX PROD REST sources under the single-position trust model (synthetic data only)."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from kairos_core.contracts import AccountSnapshotV2
from kairos_core.enums import EvedexProfile, TradingMode
from kairos_persistence import TradeState

from kairos_execution.production_readiness import canonical_digest
from kairos_execution.production_reconciliation import ReservationTradeBindingV1, VenueTerminalEvidenceV2
from kairos_execution.production_rest_sources import (
    SOURCE_ID,
    RestCancellationVenueSource,
    RestLiveAccountVerifier,
    RestLiveExitVerifier,
    RestLiveInputsVerifier,
    RestSourceError,
    RestTerminalEvidenceVerifier,
    state_projection,
)
from tests.test_production_exit_risk import NOW, _setup
from tests.test_production_inputs import _signed_fixture
from tests.test_production_instrument_inputs import _capture


def _state(*, positions=(), orders=(), tpsl=(), balance="100.5"):
    return {
        "balance": {"funding": {"currency": "USDT", "balance": balance}, "availableBalance": balance},
        "positions": list(positions),
        "orders": list(orders),
        "tpsl": list(tpsl),
        "instruments": [{"name": "BTCUSD", "metrics": {"markPrice": Decimal("101")}}],
    }


def _scope_and_account(**updates):
    _verifier, _proof, _context, _review, _venue, scope, decided_ms = _signed_fixture()
    values = dict(
        trading_mode=TradingMode.LIVE,
        evedex_profile=EvedexProfile.PROD,
        source="kairos-production-execution",
        account_id=scope.account_id,
        equity_usd=100.0,
        available_balance_usd=100.0,
        margin_used_usd=0.0,
        durable_day_start_equity_usd=104.0,
        durable_peak_equity_usd=104.0,
        captured_at_ms=decided_ms - 300,
        reconciliation_seq=3,
        reconciled=True,
        reconciliation_detail="reconciled",
    )
    values.update(updates)
    return scope, AccountSnapshotV2(**values)


def _account_evidence(account, **updates):
    projection = state_projection(_state())
    evidence = {
        "version": "kairos.evedex-rest-account-evidence.v1",
        "before": projection,
        "after": projection,
        "snapshot": account.model_dump(mode="json"),
        "open_trade_ids": [],
        "captured_at": NOW.isoformat(),
    }
    evidence.update(updates)
    return evidence


def test_flat_stable_account_is_verified_with_day_loss_from_durable_day_start():
    scope, account = _scope_and_account()
    verified = RestLiveAccountVerifier().verify(
        _account_evidence(account), source_id=SOURCE_ID, expected_scope=scope
    )
    assert verified.source_id == SOURCE_ID and verified.scope_sha256 == scope.scope_sha256
    assert verified.as_of_ms == account.captured_at_ms
    assert verified.daily_adverse_loss_usd == pytest.approx(4.0)
    assert verified.aggregate_open_notional_usd == verified.reserved_open_risk_usd == 0.0


@pytest.mark.parametrize(
    "updates",
    [
        {"after": state_projection(_state(balance="99"))},
        {"after": state_projection(_state(orders=[{"id": "o", "status": "NEW", "unFilledQuantity": "1"}]))},
        {"open_trade_ids": ["a" * 64]},
        {"extra": 1},
    ],
)
def test_account_refuses_unstable_non_flat_or_unexpected_evidence(updates):
    scope, account = _scope_and_account()
    evidence = _account_evidence(account, **updates)
    if "unFilledQuantity" in json.dumps(updates):
        evidence["before"] = evidence["after"]
    with pytest.raises(RestSourceError):
        RestLiveAccountVerifier().verify(evidence, source_id=SOURCE_ID, expected_scope=scope)


def test_account_refuses_foreign_account_and_wrong_source():
    scope, account = _scope_and_account(account_id="someone-else")
    with pytest.raises(RestSourceError, match="scope account"):
        RestLiveAccountVerifier().verify(
            _account_evidence(account), source_id=SOURCE_ID, expected_scope=scope
        )
    with pytest.raises(RestSourceError, match="identity"):
        RestLiveAccountVerifier().verify({}, source_id="other", expected_scope=scope)


def test_inputs_carry_authenticated_instrument_rules_from_the_original_capture():
    _verifier, _proof, _context, review, venue, scope, decided_ms = _signed_fixture()
    proof = {
        "version": "kairos.evedex-rest-input-evidence.v1",
        "venue_measurement_id": venue.measurement_id,
        "instruments_capture": _capture(decided_ms),
    }
    verified = RestLiveInputsVerifier().verify(
        proof,
        expected_scope=scope,
        review=review,
        venue=venue,
        allocation=None,
        system_mode=review.context.system_mode if hasattr(review, "context") else _system_mode(),
        decided_at_ms=decided_ms,
    )
    rules = verified.instrument_rules
    assert rules is not None and rules.source_id == SOURCE_ID == verified.source_id
    assert rules.evidence_sha256 == verified.evidence_sha256 and rules.venue_symbol == venue.symbol
    assert rules.price_increment == Decimal("0.01") and rules.observed_at_ms == decided_ms - 150
    with pytest.raises(RestSourceError, match="another venue measurement"):
        RestLiveInputsVerifier().verify(
            {**proof, "venue_measurement_id": "other"},
            expected_scope=scope,
            review=review,
            venue=venue,
            allocation=None,
            system_mode=_system_mode(),
            decided_at_ms=decided_ms,
        )


def _system_mode():
    from kairos_core.enums import SystemMode

    return SystemMode.NORMAL


def _exit_evidence(effect, trade, **updates):
    evidence = {
        "version": "kairos.evedex-rest-exit-evidence.v1",
        "effect_id": effect.effect_key,
        "instrument": trade.venue_symbol,
        "positions": [
            {"instrument": trade.venue_symbol, "side": "BUY", "quantity": "0.1", "avgPrice": "100"}
        ],
        "mark": "101",
        "balance": "100.5",
        "best_bid": "100.9",
        "best_ask": "101.1",
        "day_start_equity": "104",
        "observed_at": (NOW - timedelta(milliseconds=300)).isoformat(),
    }
    evidence.update(updates)
    return evidence


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["STOP_LOSS", "TAKE_PROFIT", "TIMEOUT_EXIT", "EMERGENCY_EXIT"])
async def test_exit_evidence_passes_the_real_exit_risk_publisher(role):
    publisher, _verifier, *_rest, decision, trade, effect = _setup(role)
    publisher.verifier = RestLiveExitVerifier(
        exit_fee_rate=Decimal("0.0005"), adverse_slippage_rate=Decimal("0.001")
    )
    receipt = await publisher.stage_prepared_exit(
        effect_id=effect.effect_key,
        raw_evidence=_exit_evidence(effect, trade),
        manual_request_sha256="5" * 64,
        expires_at=NOW + timedelta(seconds=1),
        now=NOW,
    )
    assert receipt.source_id == SOURCE_ID
    assert receipt.exposure.remaining_quantity == 10_000_000
    assert receipt.exposure.parent_order_id == trade.entry_client_order_id


@pytest.mark.parametrize(
    "updates",
    [
        {"positions": []},
        {"positions": [{"instrument": "BTCUSD", "side": "SELL", "quantity": "0.1", "avgPrice": "100"}]},
        {
            "positions": [
                {"instrument": "BTCUSD", "side": "BUY", "quantity": "0.000000001", "avgPrice": "100"}
            ]
        },
        {"effect_id": "0" * 64},
        {"best_bid": "102"},
    ],
)
def test_exit_refuses_missing_foreign_inexact_or_crossed_facts(updates):
    _publisher, _verifier, *_rest, decision, trade, effect = _setup("TIMEOUT_EXIT")
    verifier = RestLiveExitVerifier(exit_fee_rate=Decimal("0.0005"), adverse_slippage_rate=Decimal("0.001"))
    with pytest.raises(RestSourceError):
        verifier.verify_exit(
            _exit_evidence(effect, trade, **updates),
            expected_context=_publisher.context,
            trade=trade,
            decision=decision,
            effect=effect,
            role="TIMEOUT_EXIT",
            now=NOW,
        )


def _cancellation(trade, **updates):
    raw = {
        "version": "kairos.evedex-rest-cancellation-evidence.v1",
        "account_id": trade.account_id,
        "instrument": trade.venue_symbol,
        "positions": [{"instrument": "BTCUSD", "side": "BUY", "quantity": "0.04"}],
        "orders": [
            {
                "id": trade.entry_client_order_id,
                "status": "PARTIALLY_FILLED",
                "side": "BUY",
                "unFilledQuantity": "0.06",
                "instrument": "BTCUSD",
            }
        ],
        "tpsl": [
            {"id": "sl", "type": "stop-loss", "status": "active", "order": trade.entry_client_order_id},
            {"id": "tp", "type": "take-profit", "status": "waitOrder", "order": trade.entry_client_order_id},
        ],
        "trade": {
            "entry": trade.entry_client_order_id,
            "close": trade.close_client_order_id,
            "side": "BUY",
            "quantity": "0.1",
        },
        "open_trades": 1,
        "observed_at": NOW.isoformat(),
    }
    raw.update(updates)
    return raw


def test_cancellation_snapshot_assigns_roles_and_parents_from_kairos_ids():
    publisher, _verifier, *_rest, _decision, trade, _effect = _setup("STOP_LOSS")
    source = RestCancellationVenueSource(reads=None, trades=None, clock=lambda: NOW)  # type: ignore[arg-type]
    snapshot = source.verify_cancellation_snapshot(
        _cancellation(trade), context=publisher.context, account_id=trade.account_id, instrument="BTCUSD"
    )
    assert [order.role for order in snapshot.orders] == ["ENTRY"]
    assert snapshot.orders[0].remaining_quantity == Decimal("0.06") and not snapshot.orders[0].reduce_only
    assert [(p.protection_type, p.parent_order_id) for p in snapshot.protections] == [
        ("STOP_LOSS", trade.entry_client_order_id)
    ]
    assert snapshot.position_quantity == Decimal("0.04") and snapshot.position_side == "BUY"
    assert snapshot.valid_until - snapshot.observed_at == timedelta(seconds=5)


@pytest.mark.parametrize(
    "updates",
    [
        {"orders": [{"id": "foreign", "status": "NEW", "side": "BUY", "unFilledQuantity": "1"}]},
        {"tpsl": [{"id": "sl", "type": "stop-loss", "status": "active"}]},
        {"open_trades": 2},
        {"account_id": "other"},
    ],
)
def test_cancellation_refuses_unowned_orders_parentless_protection_and_ambiguity(updates):
    publisher, _verifier, *_rest, _decision, trade, _effect = _setup("STOP_LOSS")
    source = RestCancellationVenueSource(reads=None, trades=None, clock=lambda: NOW)  # type: ignore[arg-type]
    with pytest.raises(RestSourceError):
        source.verify_cancellation_snapshot(
            _cancellation(trade, **updates),
            context=publisher.context,
            account_id=trade.account_id,
            instrument="BTCUSD",
        )


def _binding():
    return ReservationTradeBindingV1(
        trade_id="a" * 64,
        decision_id="decision-1",
        effect_id="b" * 64,
        lifecycle_entry_effect_id="c" * 64,
        signing_request_id="request-1",
        client_order_id="00384:ABCDEF0123456789ABCDEF0123",
        exchange_parent_order_id="00384:ABCDEF0123456789ABCDEF0123",
    )


def _terminal(**updates):
    started = NOW - timedelta(seconds=3)
    raw = {
        "version": "kairos.evedex-rest-terminal-evidence.v1",
        "trade_id": "a" * 64,
        "instrument": "BTCUSD",
        "entry_side": "BUY",
        "entry_fills": [
            {
                "id": "f1",
                "fillQuantity": Decimal("0.1"),
                "fillPrice": Decimal("100"),
                "fee": [{"coin": "usdt", "quantity": Decimal("0.005")}],
                "createdAt": (NOW - timedelta(hours=1)).isoformat(),
            }
        ],
        "exit_fills": {
            "exit-1": [
                {
                    "id": "f2",
                    "fillQuantity": Decimal("0.1"),
                    "fillPrice": Decimal("102"),
                    "fee": [{"coin": "usdt", "quantity": Decimal("0.0051")}],
                    "createdAt": (NOW - timedelta(minutes=5)).isoformat(),
                }
            ]
        },
        "funding": [{"type": "fundingRate", "coin": "usdt", "quantity": Decimal("-0.01")}],
        "positions": [],
        "orders": [],
        "tpsl": [],
        "foreign_positions": 0,
        "owner_arm_sha256": "d" * 64,
        "reservation_request_sha256": "e" * 64,
        "collection_started_at": started.isoformat(),
        "collection_finished_at": NOW.isoformat(),
    }
    raw.update(updates)
    return raw


def test_terminal_evidence_sums_fills_fees_and_funding_for_the_one_position():
    publisher, *_ = _setup("TIMEOUT_EXIT")
    evidence = RestTerminalEvidenceVerifier().verify_terminal_evidence(
        _terminal(), context=publisher.context, binding=_binding()
    )
    assert isinstance(evidence, VenueTerminalEvidenceV2)
    assert evidence.complete and evidence.terminal and evidence.funding_complete
    assert evidence.entry_notional_usd == Decimal("10.0") and evidence.exit_notional_usd == Decimal("10.2")
    assert evidence.entry_fees_usd == Decimal("0.005") and evidence.exit_fees_usd == Decimal("0.0051")
    assert evidence.funding_cost_usd == Decimal("0.01")
    assert evidence.settled_at == NOW - timedelta(minutes=5)
    assert evidence.context_sha256 == canonical_digest(publisher.context)
    assert (
        evidence.source_evidence_sha256
        == hashlib.sha256(
            json.dumps(_terminal(), sort_keys=True, separators=(",", ":"), default=str).encode()
        ).hexdigest()
    )


def test_terminal_evidence_is_not_terminal_with_a_residual_or_partial_close():
    publisher, *_ = _setup("TIMEOUT_EXIT")
    verifier = RestTerminalEvidenceVerifier()
    partial = _terminal()
    partial["exit_fills"]["exit-1"][0]["fillQuantity"] = Decimal("0.05")
    assert not verifier.verify_terminal_evidence(
        partial, context=publisher.context, binding=_binding()
    ).terminal
    residual = _terminal(positions=[{"instrument": "BTCUSD", "side": "BUY", "quantity": "0.1"}])
    assert not verifier.verify_terminal_evidence(
        residual, context=publisher.context, binding=_binding()
    ).terminal
    with pytest.raises(RestSourceError, match="USD"):
        verifier.verify_terminal_evidence(
            _terminal(funding=[{"type": "fundingRate", "coin": "btc", "quantity": "1"}]),
            context=publisher.context,
            binding=_binding(),
        )
    with pytest.raises(RestSourceError, match="another trade"):
        verifier.verify_terminal_evidence(
            _terminal(trade_id="f" * 64), context=publisher.context, binding=_binding()
        )


def test_state_projection_ignores_marks_and_keeps_orders_positions_and_live_protections():
    base = _state(tpsl=[{"id": "done", "status": "done"}])
    moved = json.loads(json.dumps(base, default=str))
    moved["instruments"][0]["metrics"]["markPrice"] = "999"
    assert state_projection(base) == state_projection(moved)
    assert state_projection(base)["tpsl"] == []
    assert TradeState.FLAT  # imported enum is the persistence one used by providers
    assert datetime.now(UTC) > NOW - timedelta(days=36_500)


def test_rest_account_and_inputs_join_the_real_live_risk_evaluator_with_instrument_rules():
    """The REST verifiers admit a real entry through LiveRiskEvaluator in instrument-rules mode."""
    from kairos_core.contracts import (
        CandidateReviewV1,
        DecisionContextReceiptV1,
        DecisionContextSourceV1,
        DecisionContextV1,
        canonical_json_bytes,
        canonical_sha256,
    )
    from kairos_core.enums import SystemMode
    from kairos_core.topics import Topics
    from kairos_risk.live import LiveRiskEvaluator

    from tests.test_production_inputs import _native_context_and_review
    from tests.test_production_risk import _inputs

    _review, venue, allocation, _account_verifier, _writer, _binding, publisher, _context, scope = _inputs()
    context, review = _native_context_and_review(scope, venue)
    produced_ms = int(allocation.produced_at.timestamp() * 1_000)
    macro = DecisionContextSourceV1(
        kind="macro",
        availability="AVAILABLE",
        receipts=(
            DecisionContextReceiptV1(
                message_id=allocation.message_id,
                source=allocation.source,
                topic=Topics.STRATEGIC_ALLOCATION,
                content_sha256=canonical_sha256(allocation),
                event_at_ms=produced_ms,
                produced_at_ms=produced_ms,
                received_at_ms=context.knowledge_cutoff_ms,
                ttl_ms=26 * 60 * 60 * 1_000,
            ),
        ),
        payloads_json=canonical_json_bytes({"items": [allocation.model_dump(mode="json")]}).decode(),
    )
    context = DecisionContextV1.model_validate(
        context.model_copy(
            update={
                "sources": tuple(macro if source.kind == "macro" else source for source in context.sources),
                "context_id": None,
            }
        ).model_dump(mode="json")
    )
    review = CandidateReviewV1.model_validate(
        review.model_copy(update={"evidence": context.evidence_references(), "review_id": None}).model_dump(
            mode="json"
        )
    )
    decided_ms = venue.observed_at_ms + 100
    account = AccountSnapshotV2(
        trading_mode=TradingMode.LIVE,
        evedex_profile=EvedexProfile.PROD,
        source="kairos-production-execution",
        account_id=scope.account_id,
        equity_usd=10_000.0,
        available_balance_usd=10_000.0,
        margin_used_usd=0.0,
        durable_day_start_equity_usd=10_000.0,
        durable_peak_equity_usd=10_000.0,
        captured_at_ms=decided_ms - 200,
        reconciliation_seq=2,
        reconciled=True,
        reconciliation_detail="reconciled",
    )
    evaluator = LiveRiskEvaluator(
        scope,
        publisher.evaluator.limits,
        account_verifiers={SOURCE_ID: RestLiveAccountVerifier()},
        input_verifier=RestLiveInputsVerifier(),
        require_instrument_rules=True,
    )
    result = evaluator.evaluate(
        _account_evidence(account),
        source_id=SOURCE_ID,
        review=review,
        venue=venue,
        allocation=allocation,
        decided_at_ms=decided_ms,
        system_mode=SystemMode.NORMAL,
        raw_inputs_evidence={
            "version": "kairos.evedex-rest-input-evidence.v1",
            "venue_measurement_id": venue.measurement_id,
            "instruments_capture": _capture(decided_ms),
        },
    )
    assert result.decision.approved, result.decision.rejection_reasons
    assert Decimal(str(result.decision.quantity)) % Decimal("0.1") == 0
    assert result.instrument_rules.source_id == SOURCE_ID
