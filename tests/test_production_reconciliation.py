"""Unit checks use synthetic, explicitly non-production fixtures only."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import UUID

import pytest
from kairos_core.contracts import TradeExecutionEventV1
from kairos_core.enums import (
    EvedexProfile,
    OrderRole,
    TradeExecutionEventType,
    TradeExitReason,
    TradeLifecycleState,
    TradingMode,
)
from kairos_persistence.trade_lifecycle import TradeRecord, TradeState, validate_trade_transition
from pydantic import ValidationError

from kairos_execution.production_readiness import ProductionContextV1, canonical_digest
from kairos_execution.production_reconciliation import (
    ProductionReconciliationError,
    ProductionReservationReconciler,
    ReservationTradeBindingV1,
    VenueTerminalEvidenceV1,
    provision_production_reconciliation_schema,
)

NOW = datetime(2026, 10, 23, 10, 0, tzinfo=UTC)
DB_UUID = UUID("31da18d5-2b77-407d-b0dc-5366f03ae10a")


def _context():
    return ProductionContextV1(
        remote_account_id="synthetic-account",
        adaptive_system_id="synthetic-system",
        frozen_policy_sha256="b" * 64,
        source_set_sha256="c" * 64,
    )


def _binding():
    return ReservationTradeBindingV1(
        trade_id="e" * 64,
        decision_id="f" * 64,
        effect_id="a" * 64,
        lifecycle_entry_effect_id="b" * 64,
        signing_request_id="request-synthetic-01",
        client_order_id="client-order-synthetic-01",
        exchange_parent_order_id="venue-order-synthetic-01",
    )


def _evidence(**changes):
    context = _context()
    binding = _binding()
    payload = {
        "source_id": "synthetic-fixture-verifier",
        "source_evidence_sha256": "d" * 64,
        "context_sha256": canonical_digest(context),
        "account_id": context.remote_account_id,
        "trade_id": binding.trade_id,
        "decision_id": binding.decision_id,
        "effect_id": binding.effect_id,
        "lifecycle_entry_effect_id": binding.lifecycle_entry_effect_id,
        "signing_request_id": binding.signing_request_id,
        "client_order_id": binding.client_order_id,
        "exchange_parent_order_id": binding.exchange_parent_order_id,
        "collection_started_at": NOW - timedelta(seconds=3),
        "collection_finished_at": NOW - timedelta(seconds=2),
        "observed_at": NOW - timedelta(seconds=1),
        "complete": True,
        "terminal": True,
        "entry_filled_quantity": Decimal("2"),
        "closed_quantity": Decimal("2"),
        "entry_notional_usd": Decimal("100"),
        "exit_notional_usd": Decimal("101"),
        "entry_fees_usd": Decimal("0.1"),
        "exit_fees_usd": Decimal("0.1"),
        "residual_position_quantity": Decimal("0"),
        "residual_order_count": 0,
        "residual_protection_count": 0,
        "unowned_exposure_count": 0,
    }
    payload.update(changes)
    return VenueTerminalEvidenceV1(**payload)


class _SyntheticVerifier:
    """Test fixture: never connected to a venue and not production authority."""

    def verify_terminal_evidence(self, raw, *, context, binding):
        assert raw == "synthetic-fixture-proof"
        return _evidence()


def _reconciler(*, verifiers=None, trades=None, effects=None):
    return ProductionReservationReconciler(
        pool=object(),
        expected_database="synthetic_production_db",
        database_uuid=DB_UUID,
        policy_namespace="synthetic:namespace",
        context=_context(),
        expected_role="synthetic_reconciler",
        source_verifiers=verifiers or {"synthetic-fixture-verifier": _SyntheticVerifier()},
        trades=trades or object(),
        effects=effects or object(),
        clock=lambda: NOW,
    )


def test_synthetic_verified_terminal_evidence_has_exact_zero_residuals():
    reconciler = _reconciler()
    reconciler._verify_venue_evidence(_evidence(), _binding(), NOW)


@pytest.mark.parametrize(
    "changes",
    [
        {"complete": False},
        {"terminal": False},
        {"unowned_exposure_count": 1},
        {"residual_position_quantity": Decimal("0.01")},
        {"residual_order_count": 1},
        {"residual_protection_count": 1},
        {"closed_quantity": Decimal("1.99")},
    ],
)
def test_incomplete_or_nonflat_venue_evidence_refuses_release(changes):
    with pytest.raises(ProductionReconciliationError):
        _reconciler()._verify_venue_evidence(_evidence(**changes), _binding(), NOW)


def test_stale_or_conflicting_source_evidence_refuses_release():
    stale = _evidence(
        collection_started_at=NOW - timedelta(minutes=5, seconds=3),
        collection_finished_at=NOW - timedelta(minutes=5, seconds=2),
        observed_at=NOW - timedelta(minutes=5, seconds=1),
    )
    with pytest.raises(ProductionReconciliationError, match="stale"):
        _reconciler()._verify_venue_evidence(stale, _binding(), NOW)
    conflict = _evidence(exchange_parent_order_id="different-parent")
    with pytest.raises(ProductionReconciliationError, match="identity"):
        _reconciler()._verify_venue_evidence(conflict, _binding(), NOW)


def test_zero_entry_fill_cannot_be_constructed_as_terminal_evidence():
    with pytest.raises(ValidationError):
        _evidence(entry_filled_quantity=Decimal("0"))


def _event(event_type: TradeExecutionEventType, *, role: OrderRole, quantity: float):
    binding = _binding()
    is_entry = role is OrderRole.ENTRY
    client_id = binding.client_order_id if is_entry else "close-client-order-01"
    exchange_id = binding.exchange_parent_order_id if is_entry else "close-venue-order-01"
    return TradeExecutionEventV1(
        source="execution-engine",
        event_seq=1 if is_entry else 2,
        occurred_at_ms=int(NOW.timestamp() * 1000),
        event_type=event_type,
        lifecycle_state=TradeLifecycleState.FLAT,
        trading_mode=TradingMode.LIVE,
        evedex_profile=EvedexProfile.PROD,
        account_id="synthetic-account",
        venue_symbol="BTCUSDT",
        strategy_id="synthetic-strategy",
        strategy_revision="synthetic-revision",
        intent_id="1" * 64,
        risk_decision_id=binding.decision_id,
        trade_id=binding.trade_id,
        order_role=role,
        client_order_id=client_id,
        exchange_order_id=exchange_id,
        requested_quantity=quantity,
        filled_quantity=quantity,
        position_quantity=0,
        average_price=50.0,
        fee_usd=0.1,
        exit_reason=None if is_entry else TradeExitReason.TIMEOUT,
    )


@pytest.mark.asyncio
async def test_real_trade_execution_dto_requires_entry_and_filled_exit_facts():
    binding = _binding()
    trade = TradeRecord(
        trade_id=binding.trade_id,
        strategy_intent_id="1" * 64,
        risk_decision_id=binding.decision_id,
        risk_decision_payload={},
        strategy_id="synthetic-strategy",
        strategy_revision="synthetic-revision",
        trading_mode="LIVE",
        environment=f"PROD:{canonical_digest(_context())}:LIVE",
        profile="PROD",
        exchange="evedex",
        account_id="synthetic-account",
        symbol="BTCUSDT",
        venue_symbol="BTCUSDT",
        side="BUY",
        quantity=2,
        leverage=1,
        stop_price=40,
        target_price=60,
        entry_eligible_at=NOW - timedelta(minutes=1),
        entry_expires_at=NOW + timedelta(minutes=1),
        max_holding_ms=60_000,
        state=TradeState.FLAT,
        entry_client_order_id=binding.client_order_id,
        entry_exchange_order_id=binding.exchange_parent_order_id,
        stop_client_order_id="stop-client-order-01",
        stop_exchange_order_id="stop-venue-order-01",
        target_client_order_id="target-client-order-01",
        target_exchange_order_id="target-venue-order-01",
        close_client_order_id="close-client-order-01",
        close_exchange_order_id="close-venue-order-01",
        filled_quantity=2,
        first_fill_at=NOW - timedelta(seconds=30),
        timeout_at=None,
        last_reconciled_at=NOW,
        reconciliation_detail=None,
        state_version=1,
        journal_head_sha256="9" * 64,
    )
    entry = _event(TradeExecutionEventType.ENTRY_FILLED, role=OrderRole.ENTRY, quantity=2)
    exit_fill = _event(TradeExecutionEventType.EXIT_FILLED, role=OrderRole.TIMEOUT_EXIT, quantity=2)
    await ProductionReservationReconciler._verify_facts([entry, exit_fill], binding, trade, _evidence())
    reconciler = _reconciler(trades=_ValidTradeChain())
    await reconciler._verify_trade(trade, binding, _evidence())
    triggered_only = _event(TradeExecutionEventType.EXIT_TRIGGERED, role=OrderRole.TIMEOUT_EXIT, quantity=2)
    with pytest.raises(ProductionReconciliationError, match="exit fill"):
        await ProductionReservationReconciler._verify_facts(
            [entry, triggered_only], binding, trade, _evidence()
        )

    with pytest.raises(ProductionReconciliationError, match="not FLAT"):
        await reconciler._verify_trade(replace(trade, state=TradeState.ACTIVE), binding, _evidence())
    with pytest.raises(ProductionReconciliationError, match="identity"):
        await reconciler._verify_trade(replace(trade, account_id="another-account"), binding, _evidence())


class _ValidTradeChain:
    async def verify_chain(self, trade_id):
        return trade_id == _binding().trade_id


class _ValidEffectChain:
    async def verify_chain(self, effect_key):
        return True


@pytest.mark.asyncio
async def test_signing_effect_and_lifecycle_entry_effect_are_not_conflated():
    binding = _binding()
    trade = TradeRecord(
        trade_id=binding.trade_id,
        strategy_intent_id="1" * 64,
        risk_decision_id=binding.decision_id,
        risk_decision_payload={},
        strategy_id="synthetic-strategy",
        strategy_revision="synthetic-revision",
        trading_mode="LIVE",
        environment=f"PROD:{canonical_digest(_context())}:LIVE",
        profile="PROD",
        exchange="evedex",
        account_id="synthetic-account",
        symbol="BTCUSDT",
        venue_symbol="BTCUSDT",
        side="BUY",
        quantity=2,
        leverage=1,
        stop_price=40,
        target_price=60,
        entry_eligible_at=NOW - timedelta(minutes=1),
        entry_expires_at=NOW + timedelta(minutes=1),
        max_holding_ms=60_000,
        state=TradeState.FLAT,
        entry_client_order_id=binding.client_order_id,
        entry_exchange_order_id=binding.exchange_parent_order_id,
        stop_client_order_id=None,
        stop_exchange_order_id=None,
        target_client_order_id=None,
        target_exchange_order_id=None,
        close_client_order_id=None,
        close_exchange_order_id=None,
        filled_quantity=2,
        first_fill_at=NOW - timedelta(seconds=30),
        timeout_at=None,
        last_reconciled_at=NOW,
        reconciliation_detail=None,
        state_version=4,
        journal_head_sha256="9" * 64,
    )
    reconciler = _reconciler(effects=_ValidEffectChain())
    lifecycle_effect = {
        "effect_key": binding.lifecycle_entry_effect_id,
        "status": "RECONCILED",
        "trade_id": binding.trade_id,
        "account_id": _context().remote_account_id,
        "environment": f"PROD:{canonical_digest(_context())}:LIVE",
        "exchange": "evedex",
        "client_order_id": binding.client_order_id,
        "exchange_effect_id": binding.exchange_parent_order_id,
    }
    await reconciler._verify_effects([lifecycle_effect], binding, trade)
    with pytest.raises(ProductionReconciliationError, match="absent"):
        await reconciler._verify_effects(
            [dict(lifecycle_effect, effect_key=binding.effect_id)], binding, trade
        )


def test_notional_and_fee_fields_are_side_neutral_for_short_fills():
    # The contract records gross notionals and fees, never signed proceeds/PnL.
    short_entry = _evidence(entry_notional_usd=Decimal("100"), entry_fees_usd=Decimal("0.2"))
    short_close = _evidence(exit_notional_usd=Decimal("90"), exit_fees_usd=Decimal("0.3"))
    assert short_entry.entry_notional_usd == Decimal("100")
    assert short_entry.entry_fees_usd == Decimal("0.2")
    assert short_close.exit_notional_usd == Decimal("90")
    assert short_close.exit_fees_usd == Decimal("0.3")


def test_strict_model_rejects_observation_payload_as_terminal_evidence():
    with pytest.raises(ValidationError):
        VenueTerminalEvidenceV1.model_validate({"authoritative_reconciliation": False, "readiness": False})


def test_durable_flat_state_is_terminal_in_trade_lifecycle_contract():
    with pytest.raises(ValueError, match="invalid trade transition"):
        validate_trade_transition(TradeState.FLAT, TradeState.ACTIVE)


class _MismatchedIdentityVerifier(_SyntheticVerifier):
    def verify_terminal_evidence(self, raw, *, context, binding):
        return _evidence(source_id="other-registered-source")


@pytest.mark.asyncio
async def test_selected_registered_verifier_cannot_claim_another_registered_source():
    reconciler = _reconciler(
        verifiers={
            "selected-source": _MismatchedIdentityVerifier(),
            "other-registered-source": _SyntheticVerifier(),
        }
    )
    with pytest.raises(ProductionReconciliationError, match="different source identity"):
        await reconciler.reconcile_terminal(
            binding=_binding(), raw_venue_evidence="synthetic-fixture-proof", source_id="selected-source"
        )


def test_reconciler_requires_a_registered_verifier_not_a_boolean_flag():
    with pytest.raises(ProductionReconciliationError, match="verifiers"):
        _reconciler(verifiers={"fixture": True})


@pytest.mark.asyncio
async def test_unregistered_source_is_refused_before_repository_or_database_access():
    reconciler = _reconciler()
    with pytest.raises(ProductionReconciliationError, match="not registered"):
        await reconciler.reconcile_terminal(
            binding=_binding(), raw_venue_evidence={"authoritative": True}, source_id="caller-asserted"
        )


class _WrongOwnerConnection:
    async def fetchrow(self, query, *args):
        if "current_database()" in query:
            return {"db": "wrong_db", "role": "not_owner"}
        raise AssertionError("identity failure must occur before schema reads")

    async def fetchval(self, query, *args):
        raise AssertionError("DDL must not run for a wrong owner/database")

    async def execute(self, query, *args):
        raise AssertionError("DDL must not run for a wrong owner/database")

    def transaction(self):
        raise AssertionError("transaction must not start for a wrong owner/database")


@pytest.mark.asyncio
async def test_provisioning_checks_explicit_owner_and_database_before_ddl():
    with pytest.raises(ProductionReconciliationError, match="owner/database mismatch"):
        await provision_production_reconciliation_schema(
            _WrongOwnerConnection(),  # type: ignore[arg-type]
            expected_database="synthetic_production_db",
            database_uuid=DB_UUID,
            policy_namespace="synthetic:namespace",
            context=_context(),
            owner_role="state_owner",
            reconciler_role="state_reconciler",
        )
