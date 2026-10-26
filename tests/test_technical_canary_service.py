"""Offline startup checks only: synthetic receipts, owner key, clocks and claims.

No real account, venue, database, signing custody or service is qualified here.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace
from uuid import UUID

import pytest
from kairos_core.enums import SystemMode

from kairos_execution.production_claims import PostgresProductionClaims
from kairos_execution.production_path import ProductionLiveLifecycleCoordinator
from kairos_execution.production_readiness import ManualArmRequestV1, canonical_digest
from kairos_execution.production_service import ProductionEntryEnvelope, ProductionServiceError
from kairos_execution.signing_authorization import ProductionSigningAuthorizationVerifier
from kairos_execution.technical_canary_service import (
    TechnicalCanaryServiceError,
    start_technical_canary_service,
)
from tests.production_evidence_fixtures import NOW
from tests.test_production_path import Clock
from tests.test_production_readiness import _signed_arm
from tests.test_technical_canary_readiness import _setup_canary


def setup_session(monkeypatch, *, nonce_outcome=True, commit_delay=timedelta(0), recovery=()):
    verifier, refs, _, context, *_ = _setup_canary()
    preconditions = verifier.verify(context, refs, now=NOW).preconditions
    request = ManualArmRequestV1(
        context=context,
        preconditions_sha256=canonical_digest(preconditions),
        nonce="synthetic-canary-nonce",
        owner_identity="owner",
        created_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        dollar_cap=preconditions.dollar_cap,
        daily_stop_loss_usd=preconditions.daily_stop_loss_usd,
    )
    arm, key, _ = _signed_arm(request=request)
    key = key.model_copy(update={"context": context})
    clock = Clock(NOW)
    database_uuid = UUID("a2de07a0-2a8c-42e7-9ff8-c9d8ffb75613")
    claims = object.__new__(PostgresProductionClaims)
    claims.database_uuid = database_uuid
    claims.context_sha256 = canonical_digest(context)
    calls = []
    used = set()

    async def consume(_self, owner_identity, nonce, request_sha256):
        assert _self is claims
        calls.append(("nonce", owner_identity, nonce, request_sha256))
        clock.now += commit_delay
        if isinstance(nonce_outcome, Exception):
            raise nonce_outcome
        if nonce in used:
            return False
        used.add(nonce)
        return nonce_outcome

    monkeypatch.setattr(PostgresProductionClaims, "consume_once_async", consume)
    authorization = ProductionSigningAuthorizationVerifier(
        source=object(),
        preconditions=preconditions,
        owner_key=key,
        expected_owner_key_sha256=canonical_digest(key),
        expected_owner_identity="owner",
        expected_claim_database_uuid=database_uuid,
        maximum_arm_lifetime=timedelta(minutes=5),
        clock_probe=clock,
    )
    coordinator = object.__new__(ProductionLiveLifecycleCoordinator)
    coordinator.runtime = SimpleNamespace(
        authorization=authorization,
        claims=claims,
        context=context,
        database_uuid=database_uuid,
        _clock=clock,
    )
    coordinator.engine = SimpleNamespace(clock=clock, recovery_blocked=bool(recovery))

    async def recover():
        calls.append(("recovery",))
        return recovery

    async def reconcile():
        calls.append(("maintenance",))
        return []

    async def entry(**_kwargs):
        calls.append(("entry",))
        raise AssertionError("synthetic startup tests must never reach real entry")

    coordinator.initialize_recovery = recover
    coordinator.reconcile_once = reconcile
    coordinator.admit_and_handle_entry = entry
    kwargs = dict(coordinator=coordinator, verifier=verifier, references=refs, owner_arm=arm)
    return kwargs, clock, calls


@pytest.mark.asyncio
async def test_seven_proofs_signed_arm_and_shared_nonce_precede_recovery(monkeypatch):
    kwargs, _, calls = setup_session(monkeypatch)
    driver = await start_technical_canary_service(**kwargs)
    try:
        assert [call[0] for call in calls[:2]] == ["nonce", "recovery"]
        assert driver.status.recovery_complete and not driver.status.entries_blocked
        assert driver.status.readiness is False
        assert driver._maximum_admissions == 1 and driver._queue.maxsize == 1
        assert driver._bound_owner_arm_sha256 == canonical_digest(kwargs["owner_arm"])
        with pytest.raises(TechnicalCanaryServiceError, match="do not retry"):
            await start_technical_canary_service(**kwargs)
        assert sum(call[0] == "recovery" for call in calls) == 1
    finally:
        await driver.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["proofs", "preconditions", "signature", "claims", "clock"])
async def test_invalid_startup_never_consumes_nonce_or_starts_worker(monkeypatch, mutation):
    kwargs, clock, calls = setup_session(monkeypatch)
    runtime = kwargs["coordinator"].runtime
    if mutation == "proofs":
        kwargs["references"] = kwargs["references"][:-1]
    elif mutation == "preconditions":
        runtime.authorization._preconditions = runtime.authorization._preconditions.model_copy(
            update={"evidence_sha256": "f" * 64}
        )
    elif mutation == "signature":
        kwargs["owner_arm"] = kwargs["owner_arm"].model_copy(update={"key_id": "wrong-key"})
    elif mutation == "claims":
        runtime.authorization._claim_database_uuid = UUID(int=1)
    else:
        clock.now = NOW + timedelta(hours=1)
    with pytest.raises((ValueError, TechnicalCanaryServiceError)):
        await start_technical_canary_service(**kwargs)
    assert calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", [False, RuntimeError("PRIVATE DATABASE DETAIL")])
async def test_nonce_refusal_or_unknown_is_not_retried_or_released(monkeypatch, outcome):
    kwargs, _, calls = setup_session(monkeypatch, nonce_outcome=outcome)
    with pytest.raises(TechnicalCanaryServiceError, match="do not retry") as error:
        await start_technical_canary_service(**kwargs)
    assert "PRIVATE" not in str(error.value)
    assert [call[0] for call in calls] == ["nonce"]


@pytest.mark.asyncio
async def test_expiry_during_nonce_commit_does_not_start_or_renew_session(monkeypatch):
    kwargs, _, calls = setup_session(monkeypatch, commit_delay=timedelta(minutes=5))
    with pytest.raises(TechnicalCanaryServiceError, match="expired during nonce"):
        await start_technical_canary_service(**kwargs)
    assert [call[0] for call in calls] == ["nonce"]


@pytest.mark.asyncio
async def test_expiry_blocks_entry_but_leaves_reconciliation_available(monkeypatch):
    kwargs, clock, calls = setup_session(monkeypatch)
    driver = await start_technical_canary_service(**kwargs)
    clock.now += timedelta(minutes=5)
    arm = kwargs["owner_arm"]
    envelope = ProductionEntryEnvelope(
        envelope_id="synthetic-expired",
        raw_account_evidence=object(),
        raw_inputs_evidence=object(),
        source_id="synthetic-source",
        review=object(),
        venue=object(),
        allocation=None,
        owner_arm=arm,
        expires_at=clock.now + timedelta(seconds=1),
        system_mode=SystemMode.NORMAL,
    )
    try:
        with pytest.raises(ProductionServiceError):
            await driver.submit(envelope)
        assert driver.status.entries_blocked
        await driver.reconcile_once()
        assert ("maintenance",) in calls and ("entry",) not in calls
    finally:
        await driver.close()


@pytest.mark.asyncio
async def test_another_arm_cannot_be_swapped_into_admitted_session(monkeypatch):
    kwargs, clock, calls = setup_session(monkeypatch)
    driver = await start_technical_canary_service(**kwargs)
    arm = kwargs["owner_arm"].model_copy(update={"key_id": "substituted"})
    item = ProductionEntryEnvelope(
        envelope_id="synthetic-substitution",
        raw_account_evidence=object(),
        raw_inputs_evidence=object(),
        source_id="synthetic-source",
        review=object(),
        venue=object(),
        allocation=None,
        owner_arm=arm,
        expires_at=clock.now + timedelta(seconds=1),
        system_mode=SystemMode.NORMAL,
    )
    try:
        with pytest.raises(ProductionServiceError):
            await driver.submit(item)
        with pytest.raises(ProductionServiceError):
            await driver.submit(replace(item, envelope_id="second-attempt"))
        assert ("entry",) not in calls
    finally:
        await driver.close()


@pytest.mark.asyncio
async def test_recovery_blocker_preserves_maintenance_not_entry_permission(monkeypatch):
    kwargs, _, calls = setup_session(monkeypatch, recovery=("synthetic-account-conflict",))
    driver = await start_technical_canary_service(**kwargs)
    try:
        assert driver.status.entries_blocked and not driver.status.recovery_complete
        assert driver.status.readiness is False
        await driver.reconcile_once()
        assert ("entry",) not in calls and ("maintenance",) in calls
    finally:
        await driver.close()
