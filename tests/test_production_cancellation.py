"""Synthetic unit tests for the narrow one-shot cancellation safety seam."""

from __future__ import annotations

import hashlib
from datetime import timedelta
from decimal import Decimal
from types import SimpleNamespace

import pytest

from kairos_execution.production_cancellation import (
    CancellationOrderFactV1,
    CancellationProtectionFactV1,
    ProductionCancellationError,
    ProductionCancellationVenueSnapshotV1,
    ProductionCancellationVerifier,
    _CancellationPlan,
)
from kairos_execution.production_readiness import canonical_digest
from tests.test_production_claims import DATABASE_UUID
from tests.test_signing_authorization import fixture as signing_fixture


class FakeClaims:
    def __init__(self):
        self.claims = []
        self.terminals = []

    async def claim_wire_once_async(self, **kwargs):
        self.claims.append(kwargs)
        return True

    async def finish_wire_async(self, **kwargs):
        self.terminals.append(kwargs)


class FakeTransport:
    def __init__(self, error=None):
        self.calls = []
        self.error = error

    async def cancel_order(self, *, effect_id, instrument, order_id):
        self.calls.append(("order", effect_id, instrument, order_id))
        if self.error:
            raise self.error
        return {"id": order_id, "status": "CANCELED"}

    async def cancel_tpsl(self, *, effect_id, instrument, protection_id):
        self.calls.append(("tpsl", effect_id, instrument, protection_id))
        if self.error:
            raise self.error
        return {"id": protection_id, "status": "CANCELED"}


class FakeEffects:
    def __init__(self, effect):
        self.effect = effect
        self.confirmed = []

    async def get(self, key):
        return self.effect if key == self.effect.effect_key else None

    async def confirm(self, *args, **kwargs):
        self.confirmed.append((args, kwargs))


def _verifier(*, role="ENTRY", transport_error=None):
    _, _, _, evidence, now = signing_fixture("Position close order")
    context = evidence.owner_arm.request.context
    effect_id = hashlib.sha256(
        f"prod.v1:{canonical_digest(context)}:trade-1:{role}:cancel".encode()
    ).hexdigest()
    effect = SimpleNamespace(
        effect_key=effect_id,
        trade_id="trade-1",
        order_role=role,
    )
    verifier = object.__new__(ProductionCancellationVerifier)
    verifier.context = context
    verifier.database_uuid = DATABASE_UUID
    verifier.clock = lambda: now
    verifier.claims = FakeClaims()
    verifier.effects = FakeEffects(effect)
    verifier.transport = FakeTransport(transport_error)
    verifier._prove_calls = 0
    owner_hash = canonical_digest(evidence.owner_arm.request)
    plan = _CancellationPlan(
        context=context,
        database_uuid=DATABASE_UUID,
        trade_id="trade-1",
        decision_id="decision-1",
        effect_id=effect.effect_key,
        cancellation_type="CANCEL_ORDER" if role == "ENTRY" else "CANCEL_TPSL",
        role=role,
        instrument="BTCUSD",
        target_id="order-1" if role == "ENTRY" else "protection-1",
        origin_effect_id="b" * 64,
        manual_request_sha256=owner_hash,
        request_sha256="c" * 64,
    )
    trade = SimpleNamespace(trade_id="trade-1")

    async def prove(**kwargs):
        verifier._prove_calls += 1
        return plan, trade, effect, None, SimpleNamespace(source_id="synthetic")

    verifier._prove = prove
    return verifier, evidence, now


def _venue(context, now, *, position="0", orders=(), protections=()):
    quantity = Decimal(position)
    return ProductionCancellationVenueSnapshotV1(
        context=context,
        source_id="synthetic",
        account_id=context.remote_account_id,
        instrument="BTCUSD",
        observed_at=now - timedelta(milliseconds=100),
        valid_until=now + timedelta(seconds=2),
        position_side=None if quantity == 0 else "BUY",
        position_quantity=quantity,
        entry_parent_order_id="entry-1",
        orders=tuple(orders),
        protections=tuple(protections),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("clock_delta_ms", "snapshot_delta_ms", "error"),
    [(200, 200, None), (-1, 0, "backwards"), (200, 1_000, "stale"), (200, -6_000, "stale")],
)
async def test_fresh_venue_capture_uses_post_io_time_without_retiming(
    clock_delta_ms, snapshot_delta_ms, error
):
    verifier, _, started_at = _verifier()
    clock_value = [started_at]
    verifier.clock = lambda: clock_value[0]
    snapshot = _venue(verifier.context, started_at + timedelta(milliseconds=snapshot_delta_ms))

    class CapturingSource:
        source_id = "synthetic"

        async def read_cancellation_snapshot_async(self, **kwargs):
            clock_value[0] = started_at + timedelta(milliseconds=clock_delta_ms)
            return snapshot

        def verify_cancellation_snapshot(self, raw, **kwargs):
            return raw

    source = CapturingSource()
    verifier.venue_sources = {source.source_id: source}
    if error is None:
        _, captured = await verifier._read_venue(instrument="BTCUSD", now=started_at)
        assert captured == snapshot
        assert captured.observed_at > started_at
    else:
        with pytest.raises(ProductionCancellationError, match=error):
            await verifier._read_venue(instrument="BTCUSD", now=started_at)


@pytest.mark.asyncio
async def test_entry_cancel_claims_once_rechecks_and_uses_only_exact_cancel_transport():
    verifier, _, _ = _verifier()

    result = await verifier.cancel_entry(
        effect_id=verifier.effects.effect.effect_key,
        symbol="BTCUSD",
        client_order_id="order-1",
    )

    assert result == {"id": "order-1", "status": "CANCELED"}
    assert verifier._prove_calls == 2
    expected_effect_id = verifier.effects.effect.effect_key
    assert verifier.transport.calls == [("order", expected_effect_id, "BTCUSD", "order-1")]
    assert verifier.claims.claims[0]["effect_id"] == expected_effect_id
    assert verifier.claims.terminals[0]["terminal_status"] == "COMPLETED"
    assert verifier.effects.confirmed


@pytest.mark.asyncio
async def test_transport_timeout_is_terminal_unknown_and_never_retried():
    verifier, _, _ = _verifier(transport_error=TimeoutError())
    with pytest.raises(ProductionCancellationError, match="do not retry"):
        await verifier.cancel_entry(
            effect_id=verifier.effects.effect.effect_key,
            symbol="BTCUSD",
            client_order_id="order-1",
        )
    assert len(verifier.transport.calls) == 1
    assert verifier.claims.terminals[0]["terminal_status"] == "UNRESOLVED"
    assert not verifier.effects.confirmed


@pytest.mark.asyncio
async def test_owned_tpsl_uses_only_the_typed_tpsl_cancel_operation():
    verifier, _, _ = _verifier(role="STOP_LOSS")

    result = await verifier.cancel_tpsl(
        effect_id=verifier.effects.effect.effect_key,
        symbol="BTCUSD",
        tpsl_id="protection-1",
    )

    assert result == {"id": "protection-1", "status": "CANCELED"}
    assert verifier.transport.calls == [
        ("tpsl", verifier.effects.effect.effect_key, "BTCUSD", "protection-1")
    ]


@pytest.mark.asyncio
async def test_final_lineage_change_after_claim_fails_closed_without_transport():
    verifier, _, _ = _verifier()
    original_prove = verifier._prove

    async def changed_on_second_proof(**kwargs):
        plan, trade, effect, origin, source = await original_prove(**kwargs)
        if verifier._prove_calls == 2:
            plan = plan.model_copy(update={"manual_request_sha256": "f" * 64})
        return plan, trade, effect, origin, source

    verifier._prove = changed_on_second_proof
    with pytest.raises(ProductionCancellationError, match="do not retry"):
        await verifier.cancel_entry(
            effect_id=verifier.effects.effect.effect_key,
            symbol="BTCUSD",
            client_order_id="order-1",
        )
    assert verifier.transport.calls == []
    assert verifier.claims.terminals[0]["terminal_status"] == "UNRESOLVED"


def test_partial_entry_cancellation_requires_both_live_protections_in_same_snapshot():
    verifier, evidence, now = _verifier()
    trade = SimpleNamespace(
        side="BUY",
        account_id=evidence.owner_arm.request.context.remote_account_id,
        quantity=Decimal("10"),
        entry_client_order_id="entry-1",
        stop_exchange_order_id="stop-1",
        target_exchange_order_id="target-1",
    )
    entry = CancellationOrderFactV1(
        order_id="entry-1",
        instrument="BTCUSD",
        role="ENTRY",
        status="PARTIALLY_FILLED",
        side="BUY",
        remaining_quantity=Decimal("6"),
        reduce_only=False,
    )
    stop = CancellationProtectionFactV1(
        protection_id="stop-1",
        instrument="BTCUSD",
        protection_type="STOP_LOSS",
        status="ACTIVE",
        parent_order_id="entry-1",
        covered_quantity=Decimal("4"),
    )
    incomplete = _venue(
        evidence.owner_arm.request.context,
        now,
        position="4",
        orders=(entry,),
        protections=(stop,),
    )
    with pytest.raises(ProductionCancellationError, match="both active protections"):
        verifier._validate_venue(
            incomplete,
            trade=trade,
            instrument="BTCUSD",
            target_id="entry-1",
            role="ENTRY",
            source_id="synthetic",
            now=now,
        )


def test_active_stop_requires_flat_or_authoritative_competing_exit():
    verifier, evidence, now = _verifier(role="STOP_LOSS")
    trade = SimpleNamespace(
        side="BUY",
        account_id=evidence.owner_arm.request.context.remote_account_id,
        entry_client_order_id="entry-1",
        stop_exchange_order_id="stop-1",
        target_exchange_order_id="target-1",
    )
    stop = CancellationProtectionFactV1(
        protection_id="stop-1",
        instrument="BTCUSD",
        protection_type="STOP_LOSS",
        status="ACTIVE",
        parent_order_id="entry-1",
        covered_quantity=Decimal("4"),
    )
    unsafe = _venue(evidence.owner_arm.request.context, now, position="4", protections=(stop,))
    with pytest.raises(ProductionCancellationError, match="active stop cannot be cancelled"):
        verifier._validate_venue(
            unsafe,
            trade=trade,
            instrument="BTCUSD",
            target_id="stop-1",
            role="STOP_LOSS",
            source_id="synthetic",
            now=now,
        )


def test_historical_owner_arm_must_have_exact_signed_nonce_and_database_lineage():
    authorization, _, _, evidence, now = signing_fixture("Position close order")
    verifier = object.__new__(ProductionCancellationVerifier)
    verifier.context = evidence.owner_arm.request.context
    verifier.database_uuid = DATABASE_UUID
    verifier.preconditions = authorization._preconditions
    verifier.owner_key = authorization._owner_key
    verifier.expected_owner_key_sha256 = authorization._owner_key_sha256
    verifier.expected_owner_identity = authorization._owner
    verifier.maximum_arm_lifetime = authorization._arm_lifetime
    nonce = evidence.owner_nonce_claim.model_copy(update={"database_uuid": DATABASE_UUID})
    digest = canonical_digest(evidence.owner_arm.request)

    verifier._verify_owner_lineage(evidence.owner_arm, nonce, expected_digest=digest, now=now)
    with pytest.raises(ProductionCancellationError, match="exact accepted PROD nonce lineage"):
        verifier._verify_owner_lineage(evidence.owner_arm, nonce, expected_digest="f" * 64, now=now)
