"""Synthetic-only tests for optional LIVE risk evidence staging."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import UUID

import pytest
from kairos_core.contracts import AccountSnapshotV2, StrategicAllocation, VenueQualityV1, canonical_sha256
from kairos_core.enums import EvedexProfile, MarketRegime, StrategicTrigger, SystemMode, TradingMode
from kairos_risk.live import (
    LiveRiskEvaluator,
    LiveRiskLimitsV1,
    LiveRiskScopeV1,
    VerifiedLiveAccountV1,
    VerifiedLiveInputsV1,
)

from kairos_execution.managed_signer import CustodyBindingV1
from kairos_execution.production_exposure import GAPS
from kairos_execution.production_history import ProductionHistoryCaptureV1, ProductionHistoryComponentV1
from kairos_execution.production_lifecycle_store import PostgresLifecycleBindingStore
from kairos_execution.production_readiness import ProductionContextV1, canonical_digest
from kairos_execution.production_risk import (
    PinnedEvedexLiveAccountVerifier,
    ProductionLiveRiskError,
    ProductionLiveRiskPublisher,
)
from kairos_execution.production_state import PostgresRiskStateWriter
from tests.paper_fixtures import T0, approved_decision

SOURCE = "synthetic-live-account-fixture"
DATABASE = "kairos_production_state_test"
DATABASE_UUID = UUID("f3fbe25f-6af9-4c51-9fe1-4cd84737b8a2")
POLICY_NAMESPACE = "fixture:production-live-risk"
NOW = datetime.fromtimestamp((T0 + 60_400) / 1_000, tz=UTC)
EXPIRY = NOW + timedelta(milliseconds=1_500)


class SyntheticAccountVerifier:
    """Explicit test-only source, not a real account verifier."""

    def __init__(self) -> None:
        self.metrics: dict[str, float] = {}

    def verify(self, raw_evidence, *, source_id, expected_scope):
        if raw_evidence != "synthetic-proof":
            raise ValueError("unexpected fixture proof")
        account = AccountSnapshotV2(
            trading_mode=TradingMode.LIVE,
            evedex_profile=EvedexProfile.PROD,
            source="synthetic-test-only",
            account_id=expected_scope.account_id,
            equity_usd=10_000.0,
            available_balance_usd=9_000.0,
            margin_used_usd=0.0,
            durable_day_start_equity_usd=10_000.0,
            durable_peak_equity_usd=10_000.0,
            captured_at_ms=T0 + 60_200,
            reconciliation_seq=1,
            reconciled=True,
            reconciliation_detail="synthetic test fixture",
        )
        facts: dict[str, float] = {
            "aggregate_open_risk_usd": 0.0,
            "aggregate_open_notional_usd": 0.0,
            "reserved_open_risk_usd": 0.0,
            "reserved_open_notional_usd": 0.0,
            "strategy_open_notional_usd": 0.0,
            "strategy_reserved_notional_usd": 0.0,
            "daily_adverse_loss_usd": 0.0,
        }
        facts.update(self.metrics)
        return VerifiedLiveAccountV1(
            source_id=source_id,
            scope_sha256=expected_scope.scope_sha256,
            evidence_sha256="a" * 64,
            as_of_ms=account.captured_at_ms,
            account=account,
            **facts,
        )


class SyntheticInputsVerifier:
    """Test-only upstream-input proof verifier bound to the actual inputs."""

    def verify(
        self,
        raw_proof,
        *,
        expected_scope,
        review,
        venue,
        allocation,
        system_mode,
        decided_at_ms,
    ):
        if raw_proof != "synthetic-input-proof":
            raise ValueError("unexpected synthetic input proof")
        return VerifiedLiveInputsV1(
            source_id="synthetic-upstream-inputs-v1",
            scope_sha256=expected_scope.scope_sha256,
            evidence_sha256="d" * 64,
            review_sha256=canonical_sha256(review.model_dump(mode="json")),
            venue_sha256=canonical_sha256(venue.model_dump(mode="json")),
            allocation_sha256=(
                canonical_sha256(allocation.model_dump(mode="json")) if allocation is not None else None
            ),
            system_mode=system_mode,
            observed_at_ms=decided_at_ms - 500,
        )


class MemoryRiskWriter(PostgresRiskStateWriter):
    """Typed store fake with create-only exact replay/conflict semantics."""

    def __init__(self, context: ProductionContextV1) -> None:
        self.context = context
        self.database_uuid = DATABASE_UUID
        self.policy_namespace = POLICY_NAMESPACE
        self.state_schema_version = 3
        self.expected_database = DATABASE
        self.expected_role = "risk_writer_fixture"
        self.rows = {}

    async def append_risk_decision_async(self, risk) -> None:
        previous = self.rows.get(risk.signing_request_id)
        if previous is not None and previous != risk:
            raise RuntimeError("create-only conflict")
        self.rows[risk.signing_request_id] = risk


class MemoryBindingStore(PostgresLifecycleBindingStore):
    """Typed passive binding store fake; it grants no execution capability."""

    def __init__(self, context: ProductionContextV1) -> None:
        self.context = context
        self.expected_database = DATABASE
        self.expected_role = "binding_writer_fixture"
        self.rows = {}

    async def put(self, binding) -> bool:
        previous = self.rows.get(binding.lifecycle_effect_id)
        if previous is not None and previous != binding:
            raise RuntimeError("binding conflict")
        self.rows[binding.lifecycle_effect_id] = binding
        return previous is None


def _inputs():
    paper = approved_decision()
    context = ProductionContextV1(
        remote_account_id=paper.account_id,
        adaptive_system_id=paper.intent.strategy_id,
        frozen_policy_sha256="c" * 64,
        source_set_sha256="b" * 64,
    )
    venue_data = paper.venue_quality.model_dump(mode="python")
    venue_data.update(
        profile=EvedexProfile.PROD,
        symbol="BTCUSD",
        observed_at_ms=T0 + 60_300,
        expires_at_ms=T0 + 65_400,
        reference_timestamp_ms=T0 + 60_000,
        book_timestamp_ms=T0 + 60_100,
        measurement_id=None,
        entry_allowed=True,
    )
    venue = VenueQualityV1.model_validate(venue_data)
    limits = LiveRiskLimitsV1(
        per_trade_risk_fraction=0.0025,
        aggregate_open_risk_fraction=0.01,
        max_leverage=1.0,
        per_trade_dollar_cap_usd=500.0,
        aggregate_dollar_cap_usd=3_000.0,
        daily_loss_cap_usd=1_000.0,
        max_account_equity_usd=20_000.0,
        max_position_notional_usd=2_000.0,
        min_notional_usd=5.0,
    )
    scope = LiveRiskScopeV1(
        context_sha256=canonical_digest(context),
        source_set_sha256=context.source_set_sha256,
        policy_sha256=context.frozen_policy_sha256,
        risk_limits_sha256=canonical_sha256(limits.model_dump(mode="json")),
        account_id=context.remote_account_id,
        strategy_id=context.adaptive_system_id,
        strategy_revision=paper.intent.strategy_revision,
        approved_prod_symbols=((paper.intent.symbol, venue.symbol),),
    )
    verifier = SyntheticAccountVerifier()
    evaluator = LiveRiskEvaluator(
        scope,
        limits,
        account_verifiers={SOURCE: verifier},
        input_verifier=SyntheticInputsVerifier(),
    )
    allocation = StrategicAllocation(
        source="synthetic-macro-fixture",
        regime=MarketRegime.BULL,
        stable_reserve_pct=0.2,
        strategy_weights={paper.intent.strategy_id: 0.8},
        max_gross_leverage=1.0,
        triggered_by=StrategicTrigger.SCHEDULE,
        produced_at=datetime.fromtimestamp((T0 + 60_000) / 1_000, tz=UTC),
    )
    custody = CustodyBindingV1(
        context=context,
        custody_reference="fixture:custody",
        wallet_address="0x" + "12" * 20,
        chain_id=161803,
        schema_sha256="3" * 64,
        approved_instruments=("BTCUSD", "ETHUSD", "SOLUSD", "BNBUSD", "XRPUSD"),
        custody_receipt_sha256="4" * 64,
    )
    writer = MemoryRiskWriter(context)
    bindings = MemoryBindingStore(context)
    publisher = ProductionLiveRiskPublisher(
        evaluator=evaluator,
        risk_writer=writer,
        lifecycle_bindings=bindings,
        custody_binding=custody,
        database_uuid=DATABASE_UUID,
        policy_namespace=POLICY_NAMESPACE,
    )
    return paper.review, venue, allocation, verifier, writer, bindings, publisher, context, scope


async def _stage(publisher, review, venue, allocation, system_mode=SystemMode.NORMAL):
    return await publisher.evaluate_and_stage_entry(
        "synthetic-proof",
        "synthetic-input-proof",
        SOURCE,
        review,
        venue,
        allocation,
        "5" * 64,
        EXPIRY,
        NOW,
        system_mode,
    )


@pytest.mark.asyncio
async def test_concrete_evaluator_stages_exact_geometry_and_full_provenance():
    review, venue, allocation, _verifier, writer, bindings, publisher, _context, scope = _inputs()

    receipt = await _stage(publisher, review, venue, allocation)

    decision = receipt.evaluation.decision
    request = receipt.lifecycle_binding.request
    message = json.loads(request.message_json)
    risk = receipt.risk_geometry
    assert decision.approved and decision.trading_mode is TradingMode.LIVE
    assert decision.evedex_profile is EvedexProfile.PROD
    assert receipt.evaluation.scope_sha256 == scope.scope_sha256
    assert receipt.evaluation.evidence_sha256 == "a" * 64
    assert receipt.evaluation.account_snapshot_sha256
    assert receipt.evaluation.inputs_source_id == "synthetic-upstream-inputs-v1"
    assert receipt.evaluation.inputs_evidence_sha256 == "d" * 64
    assert message["instrument"] == decision.venue_symbol == risk.instrument
    assert message["quantity"] == risk.quantity
    assert message["limitPrice"] == risk.price
    assert message["side"] == risk.side
    assert risk.effect_id == receipt.lifecycle_binding.signing_effect_id
    assert risk.decision_id == decision.decision_id
    assert risk.worst_case_loss_usd == Decimal(str(decision.worst_case_loss_usd))
    assert risk.account_equity_usd == Decimal("10000.0")
    assert risk.valid_until == EXPIRY
    assert len(writer.rows) == len(bindings.rows) == 1
    assert receipt.binding_inserted


@pytest.mark.asyncio
async def test_exact_stage_replay_is_create_only_and_changed_economics_conflict():
    review, venue, allocation, verifier, writer, bindings, publisher, *_ = _inputs()

    first = await _stage(publisher, review, venue, allocation)
    second = await _stage(publisher, review, venue, allocation)
    assert first.risk_geometry == second.risk_geometry
    assert second.binding_inserted is False
    assert len(writer.rows) == len(bindings.rows) == 1

    verifier.metrics["aggregate_open_risk_usd"] = 1.0
    with pytest.raises(ProductionLiveRiskError, match="risk write failed or is unresolved"):
        await _stage(publisher, review, venue, allocation)
    assert len(writer.rows) == len(bindings.rows) == 1


@pytest.mark.asyncio
async def test_reserved_risk_is_evaluated_and_never_defaulted_to_zero():
    review, venue, allocation, verifier, writer, bindings, publisher, *_ = _inputs()
    verifier.metrics["reserved_open_risk_usd"] = 250.0

    with pytest.raises(ProductionLiveRiskError, match="rejected or outside"):
        await _stage(publisher, review, venue, allocation)
    assert not writer.rows and not bindings.rows


@pytest.mark.asyncio
async def test_non_normal_observed_system_mode_refuses_before_persistence():
    review, venue, allocation, _verifier, writer, bindings, publisher, *_ = _inputs()

    with pytest.raises(ProductionLiveRiskError, match="rejected or outside"):
        await _stage(publisher, review, venue, allocation, SystemMode.LOCAL_QUANT_MODE)
    assert not writer.rows and not bindings.rows


@pytest.mark.asyncio
async def test_nearly_stale_verified_inputs_cannot_gain_a_fresh_five_second_lease():
    review, venue, allocation, verifier, writer, bindings, base, *_ = _inputs()

    class NearlyStaleInputsVerifier(SyntheticInputsVerifier):
        def verify(self, raw_proof, **kwargs):
            verified = super().verify(raw_proof, **kwargs)
            return verified.model_copy(update={"observed_at_ms": kwargs["decided_at_ms"] - 4_999})

    evaluator = LiveRiskEvaluator(
        base.scope,
        base.evaluator.limits,
        account_verifiers={SOURCE: verifier},
        input_verifier=NearlyStaleInputsVerifier(),
    )
    publisher = ProductionLiveRiskPublisher(
        evaluator=evaluator,
        risk_writer=writer,
        lifecycle_bindings=bindings,
        custody_binding=base.custody_binding,
        database_uuid=DATABASE_UUID,
        policy_namespace=POLICY_NAMESPACE,
    )

    with pytest.raises(ProductionLiveRiskError):
        await _stage(publisher, review, venue, allocation)

    assert not writer.rows and not bindings.rows


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("changed", "message"),
    [
        ({"manual_request_sha256": "bad"}, "geometry could not be bound"),
        ({"expires_at": NOW + timedelta(seconds=6)}, "five-second evidence lease"),
        ({"expires_at": NOW + timedelta(milliseconds=2_100)}, "two-second quote TTL"),
        ({"expires_at": NOW + timedelta(milliseconds=1_800)}, "two-second market-data TTL"),
    ],
)
async def test_bad_identity_or_overlong_lease_refuses_before_persistence(changed, message):
    review, venue, allocation, _verifier, writer, bindings, publisher, *_ = _inputs()
    args = {
        "raw_account_evidence": "synthetic-proof",
        "raw_inputs_evidence": "synthetic-input-proof",
        "source_id": SOURCE,
        "review": review,
        "venue": venue,
        "allocation": allocation,
        "manual_request_sha256": "5" * 64,
        "expires_at": EXPIRY,
        "now": NOW,
        "system_mode": SystemMode.NORMAL,
    }
    args.update(changed)
    with pytest.raises(ProductionLiveRiskError, match=message):
        await publisher.evaluate_and_stage_entry(**args)
    assert not writer.rows and not bindings.rows


def test_current_pinned_evedex_history_refuses_before_any_verified_account_return():
    _review, _venue, _allocation, _verifier, _writer, _bindings, _publisher, context, scope = _inputs()
    started = NOW - timedelta(milliseconds=1)
    finished = NOW
    payload = "{}"
    component = ProductionHistoryComponentV1(
        path="/fixture/history",
        query_json="{}",
        payload_json=payload,
        payload_sha256=hashlib.sha256(payload.encode()).hexdigest(),
        started_at=started,
        finished_at=finished,
    )
    capture = ProductionHistoryCaptureV1(
        context=context,
        account_id=context.remote_account_id,
        collection_started_at=started,
        collection_finished_at=finished,
        components=(component,),
        order_count=0,
        protection_count=0,
    )
    verifier = PinnedEvedexLiveAccountVerifier()
    with pytest.raises(PermissionError, match="cannot authorize an exposure write"):
        verifier.verify(capture, source_id=verifier.source_id, expected_scope=scope)
    assert GAPS


def test_evaluator_or_scope_substitutes_are_refused_at_construction():
    review, venue, allocation, _verifier, writer, bindings, publisher, context, _scope = _inputs()
    with pytest.raises(TypeError, match="concrete fail-closed LiveRiskEvaluator"):
        ProductionLiveRiskPublisher(
            evaluator=object(),  # type: ignore[arg-type]
            risk_writer=writer,
            lifecycle_bindings=bindings,
            custody_binding=publisher.custody_binding,
            database_uuid=DATABASE_UUID,
            policy_namespace=POLICY_NAMESPACE,
        )
    wrong_context = context.model_copy(update={"source_set_sha256": "e" * 64})
    with pytest.raises(ValueError, match="scope differ"):
        ProductionLiveRiskPublisher(
            evaluator=publisher.evaluator,
            risk_writer=MemoryRiskWriter(wrong_context),
            lifecycle_bindings=bindings,
            custody_binding=publisher.custody_binding,
            database_uuid=DATABASE_UUID,
            policy_namespace=POLICY_NAMESPACE,
        )
    writer.state_schema_version = 2
    with pytest.raises(ValueError, match="scope differ"):
        ProductionLiveRiskPublisher(
            evaluator=publisher.evaluator,
            risk_writer=writer,
            lifecycle_bindings=bindings,
            custody_binding=publisher.custody_binding,
            database_uuid=DATABASE_UUID,
            policy_namespace=POLICY_NAMESPACE,
        )
