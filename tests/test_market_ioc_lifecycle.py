"""Offline market-IOC Risk staging with synthetic sources and in-memory stores."""

import json
from datetime import timedelta
from types import MappingProxyType

import pytest
from kairos_core.enums import SystemMode

from kairos_execution import market_ioc_admission as module
from kairos_execution.market_ioc_admission import MarketIocAdmission, MarketIocEntryRequestV1
from kairos_execution.production_lifecycle_binding import (
    ProductionLifecycleBindingV1,
    compare_entry_risk_to_decision,
)
from kairos_execution.production_risk import ProductionLiveRiskError, ProductionLiveRiskPublisher
from tests.test_market_ioc_admission import DynamicSyntheticEnvelopeVerifier
from tests.test_production_risk import DATABASE_UUID, EXPIRY, NOW, POLICY_NAMESPACE, SOURCE, _inputs
from tests.test_signing_authorization import fixture as signing_fixture


def _market_publisher(base, writer, bindings, verifier, *, clock=None):
    return ProductionLiveRiskPublisher(
        evaluator=base.evaluator,
        risk_writer=writer,
        lifecycle_bindings=bindings,
        custody_binding=base.custody_binding.model_copy(update={"chain_id": 42161}),
        database_uuid=DATABASE_UUID,
        policy_namespace=POLICY_NAMESPACE,
        market_ioc_admission=MarketIocAdmission(verifier),
        clock=clock or (lambda: NOW),
    )


def _entry():
    return MarketIocEntryRequestV1(
        source_id=DynamicSyntheticEnvelopeVerifier.source_id,
        proof_sha256="a" * 64,
        cash_quantity_e8=1_000_000_000,
    )


async def _stage(publisher, review, venue, allocation, *, now=NOW, expiry=EXPIRY, entry=None):
    return await publisher.evaluate_and_stage_entry(
        "synthetic-proof",
        "synthetic-input-proof",
        SOURCE,
        review,
        venue,
        allocation,
        "5" * 64,
        expiry,
        now,
        SystemMode.NORMAL,
        market_ioc_entry=entry or _entry(),
    )


@pytest.mark.asyncio
async def test_market_risk_stages_explicit_cash_and_preserves_binding(monkeypatch):
    review, venue, allocation, _, writer, bindings, base, _, _ = _inputs()
    verifier = DynamicSyntheticEnvelopeVerifier(int(NOW.timestamp() * 1000))
    monkeypatch.setattr(
        module,
        "_QUALIFIED_MARKET_IOC_SOURCE_TYPES",
        MappingProxyType({verifier.source_id: type(verifier)}),
    )
    publisher = _market_publisher(base, writer, bindings, verifier)
    receipt = await _stage(publisher, review, venue, allocation)
    binding = receipt.lifecycle_binding
    message = json.loads(binding.request.message_json)
    assert receipt.evaluation.decision.approved
    assert binding.request.operation == "New market order"
    assert message["cashQuantity"] == 1_000_000_000
    assert message["timeInForce"] == "IOC"
    assert "quantity" not in message and "limitPrice" not in message
    assert receipt.risk_geometry.cash_quantity == message["cashQuantity"]
    assert receipt.risk_geometry.quantity == 0
    assert receipt.risk_geometry.price is None
    assert len(writer.rows) == len(bindings.rows) == 1
    assert ProductionLifecycleBindingV1.model_validate_json(binding.model_dump_json()) == binding
    _, _, _, evidence, _ = signing_fixture()
    matching = evidence.model_copy(update={"risk": receipt.risk_geometry})
    compare_entry_risk_to_decision(decision=receipt.evaluation.decision, lifecycle=binding, evidence=matching)
    changed = matching.model_copy(
        update={"risk": receipt.risk_geometry.model_copy(update={"cash_quantity": 1})}
    )
    with pytest.raises(ValueError):
        compare_entry_risk_to_decision(
            decision=receipt.evaluation.decision, lifecycle=binding, evidence=changed
        )
    replay = await _stage(publisher, review, venue, allocation)
    assert replay.binding_inserted is False
    assert len(writer.rows) == len(bindings.rows) == 1


@pytest.mark.asyncio
async def test_fake_verifier_unregistered_fails_before_any_stage_write():
    review, venue, allocation, _, writer, bindings, base, _, _ = _inputs()
    verifier = DynamicSyntheticEnvelopeVerifier(int(NOW.timestamp() * 1000))
    publisher = _market_publisher(base, writer, bindings, verifier)
    with pytest.raises(ProductionLiveRiskError):
        await _stage(publisher, review, venue, allocation)
    assert not writer.rows and not bindings.rows


@pytest.mark.asyncio
async def test_expired_market_proof_fails_before_any_stage_write(monkeypatch):
    review, venue, allocation, _, writer, bindings, base, _, _ = _inputs()
    verifier = DynamicSyntheticEnvelopeVerifier(int(NOW.timestamp() * 1000) - 2_000)
    monkeypatch.setattr(
        module,
        "_QUALIFIED_MARKET_IOC_SOURCE_TYPES",
        MappingProxyType({verifier.source_id: type(verifier)}),
    )
    publisher = _market_publisher(base, writer, bindings, verifier)
    with pytest.raises(ProductionLiveRiskError):
        await _stage(publisher, review, venue, allocation)
    assert not writer.rows and not bindings.rows


@pytest.mark.asyncio
async def test_signing_deadline_cannot_outlive_market_proof(monkeypatch):
    review, venue, allocation, _, writer, bindings, base, _, _ = _inputs()
    verifier = DynamicSyntheticEnvelopeVerifier(int(NOW.timestamp() * 1000))
    monkeypatch.setattr(
        module,
        "_QUALIFIED_MARKET_IOC_SOURCE_TYPES",
        MappingProxyType({verifier.source_id: type(verifier)}),
    )
    publisher = _market_publisher(base, writer, bindings, verifier)
    with pytest.raises(ProductionLiveRiskError):
        await _stage(publisher, review, venue, allocation, expiry=NOW + timedelta(milliseconds=2_001))
    assert not writer.rows and not bindings.rows


@pytest.mark.asyncio
async def test_source_proof_observed_after_risk_uses_current_staging_clock(monkeypatch):
    review, venue, allocation, _, writer, bindings, base, _, _ = _inputs()
    observed_at = NOW + timedelta(milliseconds=100)
    verifier = DynamicSyntheticEnvelopeVerifier(int(observed_at.timestamp() * 1000))
    monkeypatch.setattr(
        module, "_QUALIFIED_MARKET_IOC_SOURCE_TYPES", MappingProxyType({verifier.source_id: type(verifier)})
    )
    current = NOW + timedelta(milliseconds=150)
    publisher = _market_publisher(base, writer, bindings, verifier, clock=lambda: current)
    receipt = await _stage(publisher, review, venue, allocation)
    assert (
        receipt.evaluation.decision.decided_at_ms
        < receipt.lifecycle_binding.market_ioc_envelope.observed_at_ms
    )
    assert receipt.staged_at == current
    assert receipt.lifecycle_binding.request.expires_at == EXPIRY
    assert len(writer.rows) == len(bindings.rows) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ["before_risk", "rollback", "expire_during_verify"])
async def test_market_staging_clock_rollback_or_expiry_never_writes(monkeypatch, fault):
    review, venue, allocation, _, writer, bindings, base, _, _ = _inputs()
    verifier = DynamicSyntheticEnvelopeVerifier(int(NOW.timestamp() * 1000))
    monkeypatch.setattr(
        module, "_QUALIFIED_MARKET_IOC_SOURCE_TYPES", MappingProxyType({verifier.source_id: type(verifier)})
    )
    times = {
        "before_risk": [NOW - timedelta(milliseconds=1)],
        "rollback": [NOW + timedelta(milliseconds=150), NOW + timedelta(milliseconds=100)],
        "expire_during_verify": [NOW, NOW + timedelta(seconds=2)],
    }[fault]
    values = iter(times)
    publisher = _market_publisher(base, writer, bindings, verifier, clock=lambda: next(values))
    with pytest.raises(ProductionLiveRiskError):
        await _stage(publisher, review, venue, allocation)
    assert not writer.rows and not bindings.rows
