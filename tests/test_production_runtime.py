"""Synthetic composition tests; no production venue, DB, key, or LIVE claim."""

import asyncio
import json
from datetime import timedelta
from decimal import Decimal
from uuid import UUID

import pytest

from kairos_execution.managed_signer import ManagedSignerBoundary, ManagedSigningError
from kairos_execution.production_claims import PostgresProductionClaims
from kairos_execution.production_dispatch import ProductionDispatchError, ProductionEffectDispatcher
from kairos_execution.production_runtime import ProductionExecutionRuntime
from kairos_execution.production_state import AsyncPostgresProductionSigningStateSource
from tests.test_managed_signer import Backend, setup_signer
from tests.test_production_dispatch import SyntheticSignatureVerifier
from tests.test_signing_authorization import fixture


class SyntheticPostgresStateSource(AsyncPostgresProductionSigningStateSource):
    """Use the real source type boundary with synthetic evidence only."""

    async def resolve_signing_evidence_async(self, *, request, binding, now):
        del request, binding, now
        return self.evidence

    async def reserve_entry_async(self, **kwargs):
        self.reservations.append(kwargs)


class SyntheticPostgresClaims(PostgresProductionClaims):
    """In-memory one-use semantics behind the production claims type boundary."""

    def __init__(self, *, database_uuid, context):
        super().__init__(
            object(),
            expected_database="kairos_production_evidence_synthetic_runtime",
            database_uuid=database_uuid,
            policy_namespace="synthetic-policy",
            runtime_role="synthetic-runtime",
            context=context,
        )
        self.claims = {}
        self.terminals = {}
        self.wire_calls = 0

    async def claim(self, kind, namespace, identity, request_sha256):
        key = (kind, namespace, identity)
        if key in self.claims:
            return False
        self.claims[key] = {
            "request_sha256": request_sha256,
            "context_sha256": self.context_sha256,
        }
        return True

    async def claim_once_async(self, *, custody_reference, request_id, request_sha256):
        return await self.claim("TYPED_SIGNING", custody_reference, request_id, request_sha256)

    async def finish_signing_async(
        self, *, custody_reference, request_id, request_sha256, terminal_status, result_sha256
    ):
        key = ("TYPED_SIGNING", custody_reference, request_id)
        assert self.claims[key]["request_sha256"] == request_sha256
        self.terminals[key] = {
            "terminal_status": terminal_status,
            "result_sha256": result_sha256,
        }

    async def claim_wire_once_async(self, *, namespace, effect_id, request_sha256):
        self.wire_calls += 1
        return await self.claim("WIRE_DISPATCH", namespace, effect_id, request_sha256)

    async def finish_wire_async(
        self, *, namespace, effect_id, request_sha256, terminal_status, response_sha256
    ):
        key = ("WIRE_DISPATCH", namespace, effect_id)
        assert self.claims[key]["request_sha256"] == request_sha256
        self.terminals[key] = {
            "terminal_status": terminal_status,
            "result_sha256": response_sha256,
        }

    async def load_claim(self, *, kind, namespace, identity):
        key = (kind, namespace, identity)
        claim = self.claims.get(key)
        if claim is None:
            return None
        return {**claim, **self.terminals.get(key, {})}


def runtime_fixture(*, sender=None):
    authorization, request, binding, evidence, now = fixture()
    authorization._clock = lambda: now
    database_uuid = evidence.owner_nonce_claim.database_uuid
    source = object.__new__(SyntheticPostgresStateSource)
    source.evidence = evidence
    source.reservations = []
    source.pool = object()
    source.expected_database = "kairos_production_evidence_synthetic_runtime"
    source.database_uuid = database_uuid
    source.policy_namespace = "synthetic-policy"
    source.context = request.context
    from kairos_execution.production_readiness import canonical_digest

    source.context_sha256 = canonical_digest(request.context)
    source.role_field = "runtime_role"
    source.expected_role = "synthetic-runtime"
    source.runtime_role = "synthetic-runtime"
    authorization._source = source

    claims = SyntheticPostgresClaims(database_uuid=database_uuid, context=request.context)
    _, _, backend, typed_verifier, _ = setup_signer()
    signer = ManagedSignerBoundary(
        binding,
        backend=backend,
        verifier=typed_verifier,
        claims=claims,
        authorization=authorization,
    )
    sends = []

    async def default_sender(**kwargs):
        sends.append(kwargs)
        return {"id": json.loads(request.message_json)["id"], "status": "NEW"}

    dispatcher = ProductionEffectDispatcher(
        authorization=authorization,
        signature_verifier=SyntheticSignatureVerifier(),
        claims=claims,
        database_uuid=database_uuid,
        context=request.context,
        clock=lambda: now,
        sender=sender or default_sender,
    )
    runtime = ProductionExecutionRuntime(
        signer=signer,
        authorization=authorization,
        claims=claims,
        state_source=source,
        dispatcher=dispatcher,
        database_uuid=database_uuid,
        context=request.context,
        clock=lambda: now,
    )
    return runtime, request, source, claims, backend, sends, evidence, now


@pytest.mark.asyncio
async def test_composition_inspects_then_signs_and_dispatches_exactly_once_without_lifecycle_claim():
    runtime, request, source, claims, backend, sends, _, _ = runtime_fixture()
    inspection = await runtime.inspect_authority(request)
    assert inspection.dollar_cap > 0
    assert inspection.daily_stop_loss_usd > 0
    assert not hasattr(inspection, "live_ready")
    assert not backend.calls and not claims.claims
    assert not source.reservations

    result = await runtime.dispatch_one(request)
    assert result.status == "TRANSPORT_RESPONSE_UNRECONCILED"
    assert result.lifecycle_complete is False
    assert len(backend.calls) == len(sends) == 1
    assert sends[0]["method"] == "POST"
    assert sends[0]["path"] == "/api/v2/order/limit"
    assert sends[0]["body"]["signature"]
    assert len(claims.claims) == 2  # signing and distinct wire claims


@pytest.mark.asyncio
async def test_inspection_deadline_is_bounded_without_claim_or_key_access():
    runtime, request, source, claims, backend, sends, _, now = runtime_fixture()
    request = request.model_copy(update={"expires_at": now + timedelta(milliseconds=30)})

    async def stalled_inspection(*_):
        await asyncio.Event().wait()

    runtime.authorization.inspect_request_async = stalled_inspection
    with pytest.raises(PermissionError, match="authority"):
        await asyncio.wait_for(runtime.inspect_authority(request), timeout=2)
    assert not source.reservations and not backend.calls and not claims.claims and not sends


@pytest.mark.asyncio
async def test_inspection_cancellation_is_not_converted_into_a_retry():
    runtime, request, source, claims, backend, sends, _, _ = runtime_fixture()
    entered = asyncio.Event()

    async def stalled_inspection(*_):
        entered.set()
        await asyncio.Event().wait()

    runtime.authorization.inspect_request_async = stalled_inspection
    task = asyncio.create_task(runtime.inspect_authority(request))
    await asyncio.wait_for(entered.wait(), timeout=2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not source.reservations and not backend.calls and not claims.claims and not sends


@pytest.mark.asyncio
async def test_missing_or_stale_authoritative_state_refuses_before_key_use():
    runtime, request, source, claims, backend, sends, evidence, now = runtime_fixture()
    source.evidence = evidence.model_copy(update={"resolved_at": now - timedelta(seconds=10)})
    with pytest.raises(PermissionError, match="authority"):
        await runtime.dispatch_one(request)
    assert not backend.calls and not sends and not claims.claims


@pytest.mark.asyncio
async def test_owner_cap_mismatch_refuses_before_key_use():
    runtime, request, _, claims, backend, sends, _, _ = runtime_fixture()
    runtime.authorization._preconditions = runtime.authorization._preconditions.model_copy(
        update={"dollar_cap": Decimal("101")}
    )
    with pytest.raises(PermissionError, match="authority"):
        await runtime.dispatch_one(request)
    assert not backend.calls and not sends and not claims.claims


@pytest.mark.asyncio
async def test_disarm_after_signing_is_refused_by_dispatch_and_leaves_one_use_claims():
    runtime, request, source, claims, backend, sends, evidence, _ = runtime_fixture()

    def sign_and_disarm(**kwargs):
        signature = Backend.sign_typed_data(backend, **kwargs)
        source.evidence = evidence.model_copy(
            update={"operator": evidence.operator.model_copy(update={"state": "DISARMED"})}
        )
        return signature

    backend.sign_typed_data = sign_and_disarm
    with pytest.raises(ProductionDispatchError, match="wire-time state check failed"):
        await runtime.dispatch_one(request)
    assert len(backend.calls) == 1
    assert not sends
    # Pre-wire disarm is observed before the wire claim; the typed-signing
    # claim remains terminal and prevents any second signing attempt.
    assert len(claims.claims) == 1
    assert len(claims.terminals) == 1
    with pytest.raises(PermissionError, match="authority"):
        await runtime.dispatch_one(request)
    assert len(backend.calls) == 1 and not sends


@pytest.mark.asyncio
async def test_ambiguous_transport_outcome_is_not_retried_or_reported_as_fill():
    sends = []

    async def uncertain_sender(**kwargs):
        sends.append(kwargs)
        raise TimeoutError("remote outcome unknown")

    runtime, request, _, claims, backend, _, _, _ = runtime_fixture(sender=uncertain_sender)
    with pytest.raises(ProductionDispatchError, match="wire outcome is unresolved"):
        await runtime.dispatch_one(request)
    assert len(sends) == len(backend.calls) == 1
    assert len(claims.claims) == 2
    with pytest.raises(ManagedSigningError):
        await runtime.dispatch_one(request)
    assert len(sends) == len(backend.calls) == 1


def test_constructor_rejects_mixed_context_or_database_scope():
    runtime, _, _, claims, _, _, _, _ = runtime_fixture()
    with pytest.raises(ValueError, match="context"):
        ProductionExecutionRuntime(
            signer=runtime.signer,
            authorization=runtime.authorization,
            claims=claims,
            state_source=runtime.state_source,
            dispatcher=runtime.dispatcher,
            database_uuid=UUID(int=1),
            context=runtime.context,
            clock=runtime._clock,
        )


@pytest.mark.asyncio
async def test_cancellation_during_dispatch_preserves_claim_and_never_retries():
    entered = asyncio.Event()
    never = asyncio.Event()
    sends = []

    async def blocked_sender(**kwargs):
        sends.append(kwargs)
        entered.set()
        await never.wait()

    runtime, request, _, claims, backend, _, _, _ = runtime_fixture(sender=blocked_sender)
    task = asyncio.create_task(runtime.dispatch_one(request))
    await asyncio.wait_for(entered.wait(), timeout=2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert len(sends) == len(backend.calls) == 1
    assert len(claims.claims) == 2
    with pytest.raises(ManagedSigningError):
        await runtime.dispatch_one(request)
    assert len(sends) == len(backend.calls) == 1
