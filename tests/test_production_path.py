"""Unit coverage for explicit LIVE Risk/FSM composition using synthetic sources only."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta
from decimal import Decimal
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from kairos_core.enums import EvedexProfile, SystemMode

from kairos_execution.paper_engine import _EvedexProtectedExecutionEngine
from kairos_execution.production_exit_risk import ProductionExitRiskError, ProductionLiveExitRiskPublisher
from kairos_execution.production_lifecycle import (
    ProductionLifecycleConfigV1,
    ProductionLifecycleEngine,
    ProductionVenueHealthV1,
)
from kairos_execution.production_lifecycle_adapter import ManagedProductionLifecycleAdapter
from kairos_execution.production_observation import PROD_EXCHANGE_ORIGIN
from kairos_execution.production_path import (
    ProductionLiveEntryRefusal,
    ProductionLiveLifecycleCoordinator,
    ProductionPathError,
    ProductionPreparedExitRiskStager,
)
from kairos_execution.production_readiness import (
    ManualArmRequestV1,
    OwnerArmKeyV1,
    PreconditionsV1,
    ProductionContextV1,
    SignedManualArmRequestV1,
    canonical_digest,
)
from kairos_execution.production_risk import ProductionLiveRiskEntryRefused, ProductionLiveRiskPublisher
from kairos_execution.production_runtime import ProductionExecutionRuntime
from kairos_execution.profiles import profile_params
from tests.test_production_exit_risk import NOW as EXIT_NOW
from tests.test_production_exit_risk import _setup as _exit_setup
from tests.test_production_risk import (
    DATABASE_UUID,
    NOW,
    POLICY_NAMESPACE,
    SOURCE,
    _inputs,
)


class Clock:
    def __init__(self, now: datetime = NOW) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now


class CaptureProvider:
    source_id = "synthetic-qualified-exit-source"

    def __init__(self, raw: object, *, clock: Clock | None = None, on_capture=None) -> None:
        self.raw = raw
        self.clock = clock
        self.on_capture = on_capture
        self.calls = 0

    async def capture_prepared_exit(self, *, context, effect_id, now):
        self.calls += 1
        if self.on_capture is not None:
            self.on_capture()
        return self.raw


def _owner_arm(
    context: ProductionContextV1, *, valid_signature: bool
) -> tuple[SignedManualArmRequestV1, object]:
    private_key = Ed25519PrivateKey.generate()
    preconditions = PreconditionsV1(
        context=context,
        evidence_sha256="a" * 64,
        verified_at=NOW - timedelta(minutes=1),
        valid_until=NOW + timedelta(minutes=10),
        owner_identity="synthetic-owner",
        dollar_cap=Decimal("500"),
        daily_stop_loss_usd=Decimal("100"),
    )
    request = ManualArmRequestV1(
        context=context,
        preconditions_sha256=canonical_digest(preconditions),
        nonce="synthetic-one-use-nonce",
        owner_identity="synthetic-owner",
        created_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        dollar_cap=Decimal("500"),
        daily_stop_loss_usd=Decimal("100"),
    )
    payload = json.dumps(request.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode()
    signature = private_key.sign(b"kairos.signed-manual-arm-request.v1\x00" + payload)
    if not valid_signature:
        signature = bytes(64)
    signed = SignedManualArmRequestV1(
        request=request,
        key_id="synthetic-owner-key",
        signature_base64=base64.b64encode(signature).decode(),
    )
    public = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key = OwnerArmKeyV1(
        owner_identity="synthetic-owner",
        key_id="synthetic-owner-key",
        public_key_base64=base64.b64encode(public).decode(),
        context=context,
        valid_from=NOW - timedelta(days=1),
        valid_until=NOW + timedelta(days=1),
    )
    auth = SimpleNamespace(
        _preconditions=preconditions,
        _owner_key=key,
        _owner_key_sha256=canonical_digest(key),
        _owner="synthetic-owner",
        _arm_lifetime=timedelta(minutes=5),
    )
    return signed, auth


def _coordinator_shell(*, wrong_scope: bool = False, missing_stager: bool = False):
    review, venue, allocation, _verifier, writer, bindings, entry, context, scope = _inputs()
    runtime = object.__new__(ProductionExecutionRuntime)
    runtime.context = context
    runtime.binding = entry.custody_binding
    runtime.database_uuid = DATABASE_UUID
    clock = Clock()
    runtime._clock = clock
    runtime.state_source = SimpleNamespace(
        policy_namespace=POLICY_NAMESPACE,
        expected_database="kairos_production_state_test",
        runtime_role="runtime_fixture",
    )
    owner_arm, auth = _owner_arm(context, valid_signature=True)
    runtime.authorization = auth

    exit_pub = object.__new__(ProductionLiveExitRiskPublisher)
    exit_pub.context = context
    exit_pub.custody_binding = entry.custody_binding
    exit_pub.database_uuid = DATABASE_UUID
    exit_pub.policy_namespace = POLICY_NAMESPACE
    exit_pub.risk_writer = writer
    exit_pub.lifecycle_bindings = bindings
    exit_pub.verifier = SimpleNamespace(source_id="synthetic-qualified-exit-source")
    exit_pub.trades = object()
    exit_pub.effects = object()
    stager = object.__new__(ProductionPreparedExitRiskStager)
    stager.runtime = runtime
    stager.publisher = exit_pub
    stager.clock = clock

    engine = object.__new__(ProductionLifecycleEngine)
    engine.prepared_exit_risk = None if missing_stager else stager
    engine.production_runtime = runtime
    engine.adapter = SimpleNamespace(bindings=bindings)
    engine.production_settings = SimpleNamespace(strategy_revision=scope.strategy_revision)
    engine.clock = clock
    engine.handle_calls = 0

    async def handle(_decision):
        engine.handle_calls += 1
        return SimpleNamespace(events=())

    engine.handle = handle
    if wrong_scope:
        entry.context = context.model_copy(update={"source_set_sha256": "e" * 64})
    coordinator = ProductionLiveLifecycleCoordinator(engine=engine, entry_risk=entry)
    return coordinator, owner_arm, review, venue, allocation, writer, bindings, runtime, engine


def test_composition_rejects_wrong_scope_and_missing_exit_stager():
    with pytest.raises(ValueError, match="unified LIVE path"):
        _coordinator_shell(wrong_scope=True)
    with pytest.raises(ValueError, match="unified LIVE path"):
        _coordinator_shell(missing_stager=True)


@pytest.mark.asyncio
async def test_invalid_signed_owner_arm_refuses_before_any_risk_write():
    coordinator, _owner, review, venue, allocation, writer, bindings, _runtime, engine = _coordinator_shell()
    invalid_arm, invalid_auth = _owner_arm(coordinator.runtime.context, valid_signature=False)
    coordinator.runtime.authorization = invalid_auth

    with pytest.raises(ProductionPathError, match="owner signature/scope is invalid"):
        await coordinator.admit_and_handle_entry(
            raw_account_evidence="synthetic-proof",
            raw_inputs_evidence="synthetic-input-proof",
            source_id=SOURCE,
            review=review,
            venue=venue,
            allocation=allocation,
            owner_arm=invalid_arm,
            expires_at=NOW + timedelta(milliseconds=1_500),
            system_mode=SystemMode.NORMAL,
        )
    assert not writer.rows and not bindings.rows
    assert engine.handle_calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("account_proof", "inputs_proof"),
    [("wrong-account-proof", "synthetic-input-proof"), ("synthetic-proof", "wrong-input-proof")],
)
async def test_account_or_upstream_proof_refusal_never_reaches_engine(account_proof, inputs_proof):
    coordinator, owner, review, venue, allocation, writer, bindings, _runtime, engine = _coordinator_shell()
    result = await coordinator.admit_and_handle_entry(
        raw_account_evidence=account_proof,
        raw_inputs_evidence=inputs_proof,
        source_id=SOURCE,
        review=review,
        venue=venue,
        allocation=allocation,
        owner_arm=owner,
        expires_at=NOW + timedelta(milliseconds=1_500),
        system_mode=SystemMode.NORMAL,
    )
    assert isinstance(result, ProductionLiveEntryRefusal)
    assert result.mutation_started is False
    assert not result.evaluation.decision.approved
    assert not writer.rows and not bindings.rows
    assert engine.handle_calls == 0


@pytest.mark.asyncio
async def test_normal_risk_no_entry_never_inspects_or_enters_execution():
    coordinator, owner, review, venue, allocation, writer, bindings, runtime, engine = _coordinator_shell()

    async def forbidden_inspection(_request):
        raise AssertionError("negative Risk must not reach managed authorization")

    runtime.inspect_authority = forbidden_inspection
    result = await coordinator.admit_and_handle_entry(
        raw_account_evidence="synthetic-proof",
        raw_inputs_evidence="synthetic-input-proof",
        source_id=SOURCE,
        review=review,
        venue=venue,
        allocation=allocation,
        owner_arm=owner,
        expires_at=NOW + timedelta(milliseconds=1_500),
        system_mode=SystemMode.LOCAL_QUANT_MODE,
    )
    assert isinstance(result, ProductionLiveEntryRefusal)
    assert result.evaluation.decision.rejection_reasons
    assert result.mutation_started is False
    assert not writer.rows and not bindings.rows and engine.handle_calls == 0


@pytest.mark.asyncio
async def test_unreviewed_publisher_cannot_hide_a_write_behind_no_entry():
    coordinator, owner, review, venue, allocation, writer, bindings, _runtime, engine = _coordinator_shell()

    class UnreviewedPublisher(ProductionLiveRiskPublisher):
        async def evaluate_and_stage_entry(self, **kwargs):
            try:
                return await super().evaluate_and_stage_entry(**kwargs)
            except ProductionLiveRiskEntryRefused:
                writer.rows["synthetic-partial-write"] = object()
                raise

    substitute = object.__new__(UnreviewedPublisher)
    substitute.__dict__.update(coordinator.entry_risk.__dict__)
    coordinator.entry_risk = substitute
    with pytest.raises(ProductionPathError, match="cannot attest a no-effect refusal"):
        await coordinator.admit_and_handle_entry(
            raw_account_evidence="synthetic-proof",
            raw_inputs_evidence="synthetic-input-proof",
            source_id=SOURCE,
            review=review,
            venue=venue,
            allocation=allocation,
            owner_arm=owner,
            expires_at=NOW + timedelta(milliseconds=1_500),
            system_mode=SystemMode.LOCAL_QUANT_MODE,
        )
    assert "synthetic-partial-write" in writer.rows
    assert not bindings.rows and engine.handle_calls == 0


@pytest.mark.asyncio
async def test_entry_expiry_after_authority_await_never_handles_or_dispatches():
    coordinator, owner, review, venue, allocation, writer, bindings, runtime, engine = _coordinator_shell()
    runtime.wire_calls = 0
    runtime.inspect_calls = 0

    async def dispatch_one_response(_request):
        runtime.wire_calls += 1
        raise AssertionError("expired staged evidence must never reach wire dispatch")

    async def expired_inspect(request):
        runtime.inspect_calls += 1
        binding = next(item for item in bindings.rows.values() if item.request == request)
        runtime.__dict__["_test_clock"].now = request.expires_at
        return SimpleNamespace(
            request_id=request.request_id,
            decision_id=binding.risk_decision_id,
            effect_id=binding.signing_effect_id,
            valid_until=binding.request.expires_at,
        )

    runtime._test_clock = engine.clock
    runtime.inspect_authority = expired_inspect
    runtime.dispatch_one_response = dispatch_one_response
    with pytest.raises(ProductionPathError, match="expired"):
        await coordinator.admit_and_handle_entry(
            raw_account_evidence="synthetic-proof",
            raw_inputs_evidence="synthetic-input-proof",
            source_id=SOURCE,
            review=review,
            venue=venue,
            allocation=allocation,
            owner_arm=owner,
            expires_at=NOW + timedelta(milliseconds=1_500),
            system_mode=SystemMode.NORMAL,
        )
    assert writer.rows and bindings.rows  # Staging completed, but authorization expired on await.
    assert engine.handle_calls == 0
    assert runtime.inspect_calls == 1
    assert runtime.wire_calls == 0  # Inspection only; no dispatch method was called.


@pytest.mark.asyncio
async def test_entry_interlock_closing_during_authority_read_prevents_engine_handoff():
    coordinator, owner, review, venue, allocation, writer, bindings, runtime, engine = _coordinator_shell()
    allowed = True

    async def inspected(request):
        nonlocal allowed
        binding = next(item for item in bindings.rows.values() if item.request == request)
        allowed = False
        return SimpleNamespace(
            request_id=request.request_id,
            decision_id=binding.risk_decision_id,
            effect_id=binding.signing_effect_id,
            valid_until=binding.request.expires_at,
        )

    runtime.inspect_authority = inspected
    with pytest.raises(ProductionPathError, match="interlock closed"):
        await coordinator.admit_and_handle_entry(
            raw_account_evidence="synthetic-proof",
            raw_inputs_evidence="synthetic-input-proof",
            source_id=SOURCE,
            review=review,
            venue=venue,
            allocation=allocation,
            owner_arm=owner,
            expires_at=NOW + timedelta(milliseconds=1_500),
            system_mode=SystemMode.NORMAL,
            entry_interlock=lambda: allowed,
        )
    assert writer.rows and bindings.rows  # Partial proofs remain, never renewed.
    assert engine.handle_calls == 0


def _exit_stager(provider: CaptureProvider, clock: Clock):
    publisher, _verifier, _trades, _effects, _risks, _exposures, _bindings, *_rest, effect = _exit_setup(
        "TIMEOUT_EXIT"
    )
    runtime = object.__new__(ProductionExecutionRuntime)
    runtime.context = publisher.context
    runtime.binding = publisher.custody_binding
    runtime.database_uuid = publisher.database_uuid
    runtime.state_source = SimpleNamespace(
        policy_namespace=publisher.policy_namespace,
        expected_database=publisher.risk_writer.expected_database,
        runtime_role=publisher.lifecycle_bindings.expected_role,
    )
    runtime._clock = clock
    stager = ProductionPreparedExitRiskStager(
        publisher=publisher,
        runtime=runtime,
        evidence_provider=provider,
        clock=clock,
    )
    return stager, publisher, effect


@pytest.mark.asyncio
async def test_capture_error_is_sanitized_and_cannot_be_retried():
    class FailingProvider(CaptureProvider):
        async def capture_prepared_exit(self, **kwargs):
            self.calls += 1
            raise RuntimeError("SYNTHETIC_PRIVATE_DIAGNOSTIC")

    provider = FailingProvider("unused")
    stager, publisher, effect = _exit_stager(provider, Clock(EXIT_NOW))
    with pytest.raises(ProductionPathError, match="capture failed") as failure:
        await stager.stage(effect.effect_key)
    assert "SYNTHETIC_PRIVATE_DIAGNOSTIC" not in str(failure.value)
    with pytest.raises(ProductionPathError, match="already exists"):
        await stager.stage(effect.effect_key)
    assert provider.calls == 1
    assert not publisher.risk_writer.rows


def test_exit_stager_rejects_wrong_source_identity_at_construction():
    clock = Clock(EXIT_NOW)
    provider = CaptureProvider("synthetic-qualified-proof")
    provider.source_id = "another-source"
    publisher, *_ = _exit_setup("TIMEOUT_EXIT")
    runtime = object.__new__(ProductionExecutionRuntime)
    runtime.context = publisher.context
    runtime.binding = publisher.custody_binding
    runtime.database_uuid = publisher.database_uuid
    runtime.state_source = SimpleNamespace(
        policy_namespace=publisher.policy_namespace,
        expected_database=publisher.risk_writer.expected_database,
        runtime_role=publisher.lifecycle_bindings.expected_role,
    )
    runtime._clock = clock
    with pytest.raises(ValueError, match="source, database, custody, or policy scope differs"):
        ProductionPreparedExitRiskStager(
            publisher=publisher,
            runtime=runtime,
            evidence_provider=provider,
            clock=clock,
        )


def test_exit_stager_rejects_runtime_clock_mismatch():
    clock = Clock(EXIT_NOW)
    provider = CaptureProvider("synthetic-qualified-proof")
    publisher, *_ = _exit_setup("TIMEOUT_EXIT")
    runtime = object.__new__(ProductionExecutionRuntime)
    runtime.context = publisher.context
    runtime.binding = publisher.custody_binding
    runtime.database_uuid = publisher.database_uuid
    runtime.state_source = SimpleNamespace(
        policy_namespace=publisher.policy_namespace,
        expected_database=publisher.risk_writer.expected_database,
        runtime_role=publisher.lifecycle_bindings.expected_role,
    )
    runtime._clock = Clock(EXIT_NOW)
    with pytest.raises(ValueError, match="source, database, custody, or policy scope differs"):
        ProductionPreparedExitRiskStager(
            publisher=publisher,
            runtime=runtime,
            evidence_provider=provider,
            clock=clock,
        )


def test_engine_without_clock_adopts_stager_clock(monkeypatch):
    review, _venue, _allocation, _verifier, _writer, bindings, entry, context, _scope = _inputs()
    clock = Clock()
    runtime = object.__new__(ProductionExecutionRuntime)
    runtime.context = context
    runtime.binding = entry.custody_binding
    runtime._clock = clock
    runtime.database_uuid = DATABASE_UUID

    from kairos_execution.production_path import ProductionPreparedExitRiskStager

    trades = SimpleNamespace(pool=object())
    effects = object()
    publisher = object.__new__(ProductionLiveExitRiskPublisher)
    publisher.trades = trades
    publisher.effects = effects
    publisher.lifecycle_bindings = bindings
    stager = object.__new__(ProductionPreparedExitRiskStager)
    stager.runtime = runtime
    stager.publisher = publisher
    stager.clock = clock

    adapter = object.__new__(ManagedProductionLifecycleAdapter)
    adapter.runtime = runtime
    adapter.trades = trades
    adapter.effects = effects
    adapter.bindings = bindings
    adapter.name = "evedex"
    params = profile_params(EvedexProfile.PROD)
    settings = ProductionLifecycleConfigV1(
        context=context,
        custody_binding=entry.custody_binding,
        strategy_revision=entry.scope.strategy_revision,
        expected_health=ProductionVenueHealthV1(
            chain_id=entry.custody_binding.chain_id,
            exchange_url=PROD_EXCHANGE_ORIGIN,
            auth_url=params.auth_url,
            sdk_version="1.2.11",
        ),
        service_name="synthetic-clock-test",
        symbol_map={
            "BTCUSDT": "BTCUSD",
            "ETHUSDT": "ETHUSD",
            "SOLUSDT": "SOLUSD",
            "BNBUSDT": "BNBUSD",
            "XRPUSDT": "XRPUSD",
        },
    )

    def fake_super_init(
        self,
        _adapter,
        _trades,
        _effects,
        _settings,
        *,
        lifecycle_policy,
        clock=None,
        **_kwargs,
    ):
        self.clock = clock
        self._lifecycle_policy = lifecycle_policy

    monkeypatch.setattr(_EvedexProtectedExecutionEngine, "__init__", fake_super_init)
    engine = ProductionLifecycleEngine(
        adapter,
        trades,
        effects,
        settings,
        runtime,
        prepared_exit_risk=stager,
    )
    assert engine.clock is clock
    assert runtime._clock is stager.clock is engine.clock


@pytest.mark.asyncio
async def test_refused_exit_proof_is_one_shot_and_never_recalled_on_retry():
    clock = Clock(EXIT_NOW)
    provider = CaptureProvider("refused-raw-proof")
    stager, publisher, effect = _exit_stager(provider, clock)
    with pytest.raises(ProductionExitRiskError, match="verifier refused"):
        await stager.stage(effect.effect_key)
    with pytest.raises(ProductionPathError, match="attempt already exists"):
        await stager.stage(effect.effect_key)
    assert provider.calls == 1
    assert not publisher.risk_writer.rows
    assert not publisher.exposure_writer.rows


@pytest.mark.asyncio
async def test_expiry_after_exit_authority_await_refuses_staged_result():
    clock = Clock(EXIT_NOW)
    provider = CaptureProvider("synthetic-qualified-proof")
    stager, publisher, effect = _exit_stager(provider, clock)
    inspected = 0

    async def expired_inspect(request):
        nonlocal inspected
        inspected += 1
        clock.now = EXIT_NOW + timedelta(seconds=4)
        return SimpleNamespace(
            request_id=request.request_id,
            decision_id=stager.publisher.risk_writer.rows[request.request_id].decision_id,
            effect_id=stager.publisher.risk_writer.rows[request.request_id].effect_id,
            valid_until=request.expires_at,
        )

    stager.runtime.inspect_authority = expired_inspect
    with pytest.raises(ProductionPathError, match="expired"):
        await stager.stage(effect.effect_key)
    assert provider.calls == 1
    assert inspected == 1
    assert publisher.exposure_writer.rows and publisher.risk_writer.rows
