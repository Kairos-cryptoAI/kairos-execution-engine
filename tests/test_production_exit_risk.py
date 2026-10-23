"""Synthetic-only validation of independent LIVE exit-risk staging."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import UUID

import pytest
from kairos_core.contracts import RiskTradeDecisionV1, VenueQualityV1
from kairos_core.enums import EvedexProfile, TradingMode
from kairos_persistence import (
    EffectStatus,
    EffectType,
    ExecutionEffect,
    ExecutionJournalRepository,
    TradeLifecycleRepository,
    TradeRecord,
    TradeState,
)

from kairos_execution.managed_signer import CustodyBindingV1
from kairos_execution.production_exit_risk import (
    PinnedEvedexLiveExitVerifier,
    ProductionExitRiskError,
    ProductionLiveExitRiskPublisher,
    VerifiedLiveExitEvidenceV1,
)
from kairos_execution.production_exposure import GAPS
from kairos_execution.production_history import ProductionHistoryCaptureV1, ProductionHistoryComponentV1
from kairos_execution.production_lifecycle_store import PostgresLifecycleBindingStore
from kairos_execution.production_readiness import ProductionContextV1, canonical_digest
from kairos_execution.production_state import PostgresExposureStateWriter, PostgresRiskStateWriter
from kairos_execution.signing_authorization import ExposureSnapshotV1
from kairos_execution.state_machine import client_order_id
from tests.paper_fixtures import T0, approved_decision

NOW = datetime.fromtimestamp((T0 + 3_600_000) / 1_000, tz=UTC)
DB = "kairos_exit_risk_fixture"
DB_UUID = UUID("43c6e339-797f-4f87-a659-4d4a410a0ef2")
POLICY = "fixture:exit-risk"


def _live_decision() -> RiskTradeDecisionV1:
    payload = approved_decision().model_dump(mode="python")
    venue_data = payload["venue_quality"]
    venue_data.update(profile=EvedexProfile.PROD, symbol="BTCUSD", measurement_id=None)
    venue = VenueQualityV1.model_validate(venue_data)
    payload["venue_quality"] = venue.model_dump(mode="python")
    payload.update(
        evedex_profile=EvedexProfile.PROD,
        trading_mode=TradingMode.LIVE,
        venue_symbol="BTCUSD",
        account_id="synthetic-live-account",
        decision_id=None,
        trade_id=None,
    )
    payload["worst_entry_price"] = venue.best_ask
    payload["notional_usd"] = payload["quantity"] * venue.best_ask
    payload["estimated_slippage_usd"] = (
        payload["quantity"] * venue.venue_mid_price * venue.buy_slippage_bps / 10_000
    )
    payload["estimated_fees_usd"] = (
        payload["quantity"]
        * (venue.best_ask + payload["exit_plan"]["stop_price"])
        * venue.taker_fee_bps
        / 10_000
    )
    payload["worst_case_loss_usd"] = (
        payload["quantity"] * abs(venue.best_ask - payload["exit_plan"]["stop_price"])
        + payload["estimated_fees_usd"]
        + payload["estimated_slippage_usd"]
    )
    payload["loss_budget_usd"] = max(payload["loss_budget_usd"], payload["worst_case_loss_usd"])
    return RiskTradeDecisionV1.model_validate(payload)


class MemoryTradeRepository(TradeLifecycleRepository):
    def __init__(self, trade):
        self.trade = trade
        self.chain_valid = True

    async def get(self, trade_id):
        return self.trade if trade_id == self.trade.trade_id else None

    async def verify_chain(self, trade_id):
        return self.chain_valid and trade_id == self.trade.trade_id


class MemoryEffectRepository(ExecutionJournalRepository):
    def __init__(self, effect):
        self.effect = effect
        self.chain_valid = True

    async def get(self, effect_id):
        return self.effect if effect_id == self.effect.effect_key else None

    async def verify_chain(self, effect_id):
        return self.chain_valid and effect_id == self.effect.effect_key


class MemoryRiskWriter(PostgresRiskStateWriter):
    def __init__(self, context):
        self.context = context
        self.database_uuid = DB_UUID
        self.policy_namespace = POLICY
        self.state_schema_version = 3
        self.expected_database = DB
        self.expected_role = "risk_writer"
        self.rows = {}

    async def append_risk_decision_async(self, value):
        previous = self.rows.get(value.signing_request_id)
        if previous is not None and previous != value:
            raise RuntimeError("risk row conflict")
        self.rows[value.signing_request_id] = value


class MemoryExposureWriter(PostgresExposureStateWriter):
    def __init__(self, context):
        self.context = context
        self.database_uuid = DB_UUID
        self.policy_namespace = POLICY
        self.state_schema_version = 3
        self.expected_database = DB
        self.expected_role = "exposure_writer"
        self.rows = []

    async def append_exposure_async(self, value):
        self.rows.append(value)


class MemoryBindingStore(PostgresLifecycleBindingStore):
    def __init__(self, context):
        self.context = context
        self.expected_database = DB
        self.expected_role = "binding_writer"
        self.rows = {}

    async def put(self, value):
        prior = self.rows.get(value.lifecycle_effect_id)
        if prior is not None and prior != value:
            raise RuntimeError("binding conflict")
        self.rows[value.lifecycle_effect_id] = value
        return prior is None


class SyntheticExitVerifier:
    """Explicit test verifier, never suitable as source qualification."""

    source_id = "synthetic-qualified-exit-source"

    def __init__(self):
        self.bad_field = None

    def verify_exit(self, raw_evidence, *, expected_context, trade, decision, effect, role, now):
        if raw_evidence != "synthetic-qualified-proof":
            raise ValueError("fixture proof mismatch")
        side = trade.side
        exposure = ExposureSnapshotV1(
            context=expected_context,
            instrument=trade.venue_symbol,
            position_side=side,
            remaining_quantity=getattr(
                self, "remaining_quantity", int(Decimal(str(trade.filled_quantity)) * Decimal(10**8))
            ),
            parent_order_id=trade.entry_client_order_id,
            observed_at=NOW - timedelta(milliseconds=200),
            valid_until=NOW + timedelta(seconds=4),
        )
        fields = {
            "source_id": "synthetic-qualified-exit-source",
            "evidence_sha256": "a" * 64,
            "context_sha256": canonical_digest(expected_context),
            "trade_id": trade.trade_id,
            "original_decision_id": decision.decision_id,
            "original_decision_sha256": canonical_digest(decision),
            "effect_id": effect.effect_key,
            "effect_request_sha256": effect.request_sha256,
            "role": role,
            "exposure": exposure,
            "account_equity_usd": Decimal("10000"),
            "daily_realized_loss_usd": Decimal("3"),
            "aggregate_open_risk_usd": Decimal("25"),
            "aggregate_open_notional_usd": Decimal("400"),
            "position_entry_price_usd": Decimal(str(decision.worst_entry_price)),
            "reference_price_usd": Decimal("100.5"),
            "executable_exit_price_usd": Decimal("100.49"),
            "exit_fee_rate": Decimal("0.0005"),
            "adverse_slippage_rate": Decimal("0.001"),
            "observed_at": NOW - timedelta(milliseconds=200),
            "valid_until": NOW + timedelta(seconds=4),
        }
        if getattr(self, "no_cost", False):
            fields.update(
                reference_price_usd=Decimal("101"),
                executable_exit_price_usd=Decimal("101"),
                exit_fee_rate=Decimal("0"),
                adverse_slippage_rate=Decimal("0"),
            )
        if self.bad_field:
            fields[self.bad_field[0]] = self.bad_field[1]
        return VerifiedLiveExitEvidenceV1(**fields)


def _setup(role="TIMEOUT_EXIT", *, state=None, quantity=0.05, filled_quantity=0.1):
    decision = _live_decision()
    context = ProductionContextV1(
        remote_account_id=decision.account_id,
        adaptive_system_id=decision.intent.strategy_id,
        frozen_policy_sha256="b" * 64,
        source_set_sha256="c" * 64,
    )
    environment = f"PROD:{canonical_digest(context)}:LIVE"
    operation = "create" if role in {"STOP_LOSS", "TAKE_PROFIT"} else "close"
    effect_id = hashlib.sha256(
        f"prod.v1:{canonical_digest(context)}:{decision.trade_id}:{role}:{operation}".encode()
    ).hexdigest()
    entry_id = client_order_id(
        f"{decision.trade_id}:ENTRY",
        "evedex",
        occurred_at=datetime.fromtimestamp(decision.decided_at_ms / 1_000, tz=UTC),
    )
    close_id = client_order_id(f"{decision.trade_id}:{role}", "evedex", occurred_at=NOW)
    stop_id = client_order_id(f"{decision.trade_id}:STOP_LOSS", "evedex", occurred_at=NOW)
    target_id = client_order_id(f"{decision.trade_id}:TAKE_PROFIT", "evedex", occurred_at=NOW)
    trade = TradeRecord(
        trade_id=decision.trade_id,
        strategy_intent_id=decision.intent.intent_id,
        risk_decision_id=decision.decision_id,
        risk_decision_payload=decision.model_dump(mode="json"),
        strategy_id=decision.intent.strategy_id,
        strategy_revision=decision.intent.strategy_revision,
        trading_mode="LIVE",
        environment=environment,
        profile="PROD",
        exchange="evedex",
        account_id=decision.account_id,
        symbol=decision.intent.symbol,
        venue_symbol=decision.venue_symbol,
        side="BUY",
        quantity=decision.quantity,
        leverage=1,
        stop_price=decision.exit_plan.stop_price,
        target_price=decision.exit_plan.target_price,
        entry_eligible_at=NOW - timedelta(hours=1),
        entry_expires_at=NOW - timedelta(minutes=1),
        max_holding_ms=decision.exit_plan.max_holding_ms,
        state=state
        or {
            "STOP_LOSS": TradeState.PROTECTING,
            "TAKE_PROFIT": TradeState.PROTECTING,
            "TIMEOUT_EXIT": TradeState.EXITING_TIMEOUT,
            "EMERGENCY_EXIT": TradeState.EXITING_EMERGENCY,
        }[role],
        entry_client_order_id=entry_id,
        entry_exchange_order_id="venue-parent-01",
        stop_client_order_id=stop_id,
        stop_exchange_order_id="venue-stop-01",
        target_client_order_id=target_id,
        target_exchange_order_id="venue-target-01",
        close_client_order_id=close_id,
        close_exchange_order_id=None,
        filled_quantity=filled_quantity,
        first_fill_at=NOW - timedelta(hours=1),
        timeout_at=NOW - timedelta(seconds=1),
        last_reconciled_at=NOW - timedelta(milliseconds=400),
        reconciliation_detail=None,
        state_version=10,
        journal_head_sha256="f" * 64,
    )
    effect_type = {
        "STOP_LOSS": EffectType.PROTECTIVE_STOP,
        "TAKE_PROFIT": EffectType.TAKE_PROFIT,
        "TIMEOUT_EXIT": EffectType.TIMEOUT_CLOSE,
        "EMERGENCY_EXIT": EffectType.EMERGENCY_CLOSE,
    }[role]
    client_id = stop_id if role == "STOP_LOSS" else target_id if role == "TAKE_PROFIT" else close_id
    if role in {"STOP_LOSS", "TAKE_PROFIT"}:
        request = {
            "trade_id": trade.trade_id,
            "client_order_id": client_id,
            "parent_order_id": entry_id,
            "venue_symbol": trade.venue_symbol,
            "side": trade.side,
            "tpsl_type": role,
            "quantity_hex": float(0).hex(),
            "price_hex": float(trade.stop_price if role == "STOP_LOSS" else trade.target_price).hex(),
        }
    else:
        request = {
            "trade_id": trade.trade_id,
            "client_order_id": client_id,
            "venue_symbol": trade.venue_symbol,
            "quantity_hex": float(quantity).hex(),
            "leverage_hex": float(1).hex(),
        }
    from kairos_persistence import canonical_payload

    request_sha = canonical_payload(request)[1]
    effect = ExecutionEffect(
        effect_key=effect_id,
        effect_type=effect_type,
        exchange="evedex",
        symbol=trade.symbol,
        client_order_id=client_id,
        request_sha256=request_sha,
        request_payload=request,
        status=EffectStatus.PREPARED,
        exchange_effect_id=None,
        response_payload=None,
        error=None,
        journal_head_sha256="e" * 64,
        environment=environment,
        account_id=trade.account_id,
        trade_id=trade.trade_id,
        order_role=role,
    )
    custody = CustodyBindingV1(
        context=context,
        custody_reference="fixture:exit-risk",
        wallet_address="0x" + "12" * 20,
        chain_id=161803,
        schema_sha256="3" * 64,
        approved_instruments=("BTCUSD", "ETHUSD", "SOLUSD", "BNBUSD", "XRPUSD"),
        custody_receipt_sha256="4" * 64,
    )
    trades = MemoryTradeRepository(trade)
    effects = MemoryEffectRepository(effect)
    risk_writer = MemoryRiskWriter(context)
    exposure_writer = MemoryExposureWriter(context)
    bindings = MemoryBindingStore(context)
    verifier = SyntheticExitVerifier()
    publisher = ProductionLiveExitRiskPublisher(
        verifier=verifier,
        trades=trades,  # type: ignore[arg-type]
        effects=effects,  # type: ignore[arg-type]
        risk_writer=risk_writer,
        exposure_writer=exposure_writer,
        lifecycle_bindings=bindings,
        custody_binding=custody,
        database_uuid=DB_UUID,
        policy_namespace=POLICY,
    )
    return (
        publisher,
        verifier,
        trades,
        effects,
        risk_writer,
        exposure_writer,
        bindings,
        decision,
        trade,
        effect,
    )


async def _stage(publisher, effect):
    return await publisher.stage_prepared_exit(
        effect_id=effect.effect_key,
        raw_evidence="synthetic-qualified-proof",
        manual_request_sha256="5" * 64,
        expires_at=NOW + timedelta(seconds=1),
        now=NOW,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["STOP_LOSS", "TAKE_PROFIT", "TIMEOUT_EXIT", "EMERGENCY_EXIT"])
async def test_exact_prepared_exit_stages_independent_per_effect_risk(role):
    publisher, _verifier, _trades, _effects, risks, exposures, bindings, decision, _trade, effect = _setup(
        role
    )

    receipt = await _stage(publisher, effect)

    assert receipt.lifecycle_binding.role == role
    assert receipt.lifecycle_binding.risk_decision_id != decision.decision_id
    assert receipt.risk_geometry.decision_id == receipt.lifecycle_binding.risk_decision_id
    assert receipt.risk_geometry.effect_id == receipt.lifecycle_binding.signing_effect_id
    assert receipt.risk_geometry.worst_case_loss_usd > 0
    if role == "STOP_LOSS":
        assert receipt.risk_geometry.worst_case_loss_usd == Decimal("0.565245250")
    assert receipt.risk_geometry.worst_case_loss_usd < receipt.risk_geometry.account_equity_usd
    assert receipt.risk_geometry.parent_order_id == receipt.exposure.parent_order_id
    assert receipt.risk_geometry.valid_until <= receipt.exposure.valid_until
    assert len(risks.rows) == len(exposures.rows) == len(bindings.rows) == 1


@pytest.mark.asyncio
async def test_protection_loss_envelopes_full_approved_order_across_partial_fills():
    partial = _setup("STOP_LOSS", filled_quantity=0.04)
    partial_publisher, _verifier, _trades, _effects, _risks, partial_exposures, *_ = partial
    partial_receipt = await _stage(partial_publisher, partial[-1])

    full = _setup("STOP_LOSS", filled_quantity=0.1)
    full_publisher, _verifier, _trades, _effects, _risks, full_exposures, *_ = full
    full_receipt = await _stage(full_publisher, full[-1])

    assert partial_receipt.exposure.remaining_quantity == 4_000_000
    assert full_receipt.exposure.remaining_quantity == 10_000_000
    assert partial_receipt.risk_geometry.worst_case_loss_usd == full_receipt.risk_geometry.worst_case_loss_usd
    assert partial_exposures.rows[0].remaining_quantity == 4_000_000
    assert full_exposures.rows[0].remaining_quantity == 10_000_000


@pytest.mark.asyncio
async def test_protection_loss_uses_worse_source_entry_and_rejects_overfilled_trade():
    publisher, verifier, trades, effects, risks, exposures, bindings, decision, _trade, effect = _setup(
        "STOP_LOSS"
    )
    verifier.bad_field = ("position_entry_price_usd", Decimal(str(decision.worst_entry_price)) + 1)

    receipt = await _stage(publisher, effect)
    assert receipt.risk_geometry.worst_case_loss_usd > Decimal("0.565245250")

    publisher, _verifier, trades, effects, risks, exposures, bindings, decision, trade, effect = _setup(
        "STOP_LOSS"
    )
    trades.trade = replace(trade, filled_quantity=decision.quantity + 0.001)
    with pytest.raises(ProductionExitRiskError, match="durable PREPARED"):
        await _stage(publisher, effect)
    assert not risks.rows and not exposures.rows and not bindings.rows


@pytest.mark.asyncio
async def test_source_facts_with_no_price_loss_or_cost_refuse_instead_of_using_epsilon():
    publisher, verifier, _trades, effects, risks, exposures, bindings, *_ = _setup("TIMEOUT_EXIT")
    # A long position can exit above entry without loss; with zero fee and
    # slippage this evidence cannot justify a positive conservative risk row.
    verifier.no_cost = True

    with pytest.raises(ProductionExitRiskError, match="no positive conservative"):
        await _stage(publisher, effects.effect)

    assert not risks.rows and not exposures.rows and not bindings.rows


@pytest.mark.asyncio
async def test_unconfigured_returned_source_id_refuses_without_writes():
    publisher, verifier, _trades, effects, risks, exposures, bindings, *_ = _setup("TIMEOUT_EXIT")
    verifier.source_id = "different-source"

    with pytest.raises(ProductionExitRiskError, match="not bound to exact effect/exposure"):
        await _stage(publisher, effects.effect)

    assert not risks.rows and not exposures.rows and not bindings.rows


@pytest.mark.asyncio
async def test_valid_reduction_does_not_depend_on_expired_entry_window_or_entry_mode():
    publisher, _verifier, _trades, _effects, risks, exposures, _bindings, decision, _trade, effect = _setup(
        "TIMEOUT_EXIT"
    )
    assert NOW.timestamp() * 1_000 > decision.intent.entry_expires_ts_ms

    await _stage(publisher, effect)

    assert risks.rows and exposures.rows


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("bad_field", "bad_value", "message"),
    [
        ("original_decision_id", "9" * 64, "not bound to exact effect/exposure"),
        ("role", "STOP_LOSS", "not bound to exact effect/exposure"),
        ("effect_request_sha256", "8" * 64, "not bound to exact effect/exposure"),
        ("observed_at", NOW - timedelta(seconds=6), "stale or not bound"),
        ("valid_until", NOW + timedelta(seconds=7), "stale or not bound"),
    ],
)
async def test_mismatched_or_stale_source_evidence_refuses_without_writes(bad_field, bad_value, message):
    publisher, verifier, _trades, effect_repo, risks, exposures, bindings, *_ = _setup("TIMEOUT_EXIT")
    verifier.bad_field = (bad_field, bad_value)

    with pytest.raises(ProductionExitRiskError, match=message):
        await _stage(publisher, effect_repo.effect)

    assert not risks.rows and not exposures.rows and not bindings.rows


@pytest.mark.asyncio
async def test_bad_chain_parent_side_role_or_overclose_refuses_before_persistence():
    publisher, verifier, trades, effects, risks, exposures, bindings, _decision, trade, effect = _setup(
        "TIMEOUT_EXIT", quantity=0.2
    )
    with pytest.raises(ProductionExitRiskError, match="durable PREPARED"):
        await _stage(publisher, effect)
    assert not risks.rows and not exposures.rows and not bindings.rows

    publisher, verifier, trades, effects, risks, exposures, bindings, _decision, _trade, effect = _setup(
        "TIMEOUT_EXIT"
    )
    effects.chain_valid = False
    with pytest.raises(ProductionExitRiskError, match="durable PREPARED"):
        await _stage(publisher, effect)
    assert not risks.rows and not exposures.rows and not bindings.rows

    publisher, verifier, trades, effects, risks, exposures, bindings, _decision, _trade, effect = _setup(
        "TIMEOUT_EXIT"
    )
    verifier.bad_field = (
        "exposure",
        ExposureSnapshotV1(
            context=publisher.context,
            instrument="BTCUSD",
            position_side="SELL",
            remaining_quantity=10_000_000,
            parent_order_id="wrong-parent",
            observed_at=NOW - timedelta(milliseconds=200),
            valid_until=NOW + timedelta(seconds=4),
        ),
    )
    with pytest.raises(ProductionExitRiskError, match="not bound to exact effect/exposure"):
        await _stage(publisher, effect)
    assert not risks.rows and not exposures.rows and not bindings.rows


def test_pinned_source_refuses_before_any_writer_can_be_called():
    publisher, _verifier, _trades, _effects, risks, exposures, bindings, _decision, trade, effect = _setup(
        "TIMEOUT_EXIT"
    )
    started = NOW - timedelta(seconds=1)
    payload = "{}"
    component = ProductionHistoryComponentV1(
        path="/fixture/history",
        query_json="{}",
        payload_json=payload,
        payload_sha256=hashlib.sha256(payload.encode()).hexdigest(),
        started_at=started,
        finished_at=NOW,
    )
    capture = ProductionHistoryCaptureV1(
        context=publisher.context,
        account_id=trade.account_id,
        collection_started_at=started,
        collection_finished_at=NOW,
        components=(component,),
        order_count=0,
        protection_count=0,
    )
    verifier = PinnedEvedexLiveExitVerifier()
    with pytest.raises(PermissionError, match="cannot authorize an exposure write"):
        verifier.verify_exit(
            capture,
            expected_context=publisher.context,
            trade=trade,
            decision=_decision,
            effect=effect,
            role="TIMEOUT_EXIT",
            now=NOW,
        )
    assert GAPS and not risks.rows and not exposures.rows and not bindings.rows
