"""Construct the real PROD object graph without DB/SDK/provider operations.

Only pool handles, custody callbacks and evidence providers are synthetic. No
production class is allocated with object.__new__ or monkeypatched to bypass
its constructor. Successful construction does not qualify any live source.
"""

from dataclasses import replace
from pathlib import Path
from uuid import UUID

import pytest
from kairos_persistence import ExecutionJournalRepository, TradeLifecycleRepository
from kairos_risk.live import LiveRiskEvaluator, LiveRiskScopeV1

from kairos_execution.managed_signer import CustodyBindingV1, ManagedSignerBoundary, reviewed_schema_sha256
from kairos_execution.production_assembly import (
    ProductionAssemblyError,
    ProductionAssemblyResources,
    ProductionAssemblyStatus,
    build_production_assembly,
)
from kairos_execution.production_claims import PostgresProductionClaims
from kairos_execution.production_dispatch import ProductionEffectDispatcher
from kairos_execution.production_host import ProductionHost, build_production_host
from kairos_execution.production_readiness import canonical_digest
from kairos_execution.production_runtime import ProductionExecutionRuntime
from kairos_execution.production_state import (
    AsyncPostgresProductionSigningStateSource,
    PostgresExposureStateWriter,
    PostgresRiskStateWriter,
)
from kairos_execution.production_transport import ProductionEvedexSdkClient, ProductionEvedexTransport
from kairos_execution.signing_authorization import ProductionSigningAuthorizationVerifier
from tests.test_managed_signer import Backend, Verifier
from tests.test_production_dispatch import SyntheticSignatureVerifier
from tests.test_production_lifecycle import _config
from tests.test_production_path import Clock
from tests.test_production_risk import _inputs
from tests.test_signing_authorization import fixture
from tests.test_technical_canary_readiness import _setup_canary


class NoIOPool:
    """Existing role-pool handle whose first use fails the offline test."""

    def __init__(self):
        self.calls = []

    def acquire(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        raise AssertionError("assembly construction must not acquire a DB connection")


class NoIOProvider:
    source_id = "synthetic-no-io-source"

    def __init__(self):
        self.calls = []

    def _refuse(self, operation):
        self.calls.append(operation)
        raise AssertionError("assembly construction must not read or verify venue evidence")

    def verify_exit(self, *args, **kwargs):
        self._refuse("exit")

    async def capture_prepared_exit(self, *args, **kwargs):
        self._refuse("capture-exit")

    async def read_cancellation_snapshot_async(self, *args, **kwargs):
        self._refuse("read-cancel")

    def verify_cancellation_snapshot(self, *args, **kwargs):
        self._refuse("verify-cancel")

    def verify_terminal_evidence(self, *args, **kwargs):
        self._refuse("terminal")


def concrete_resources(*, require_instrument_rules=True, approved_symbols=None):
    config = _config()
    custody = CustodyBindingV1.model_validate(
        config.custody_binding.model_copy(
            update={
                "chain_id": 42161,
                "schema_sha256": reviewed_schema_sha256(42161),
            }
        ).model_dump(mode="python")
    )
    config = type(config).model_validate(
        config.model_copy(
            update={
                "custody_binding": custody,
                "expected_health": config.expected_health.model_copy(update={"chain_id": 42161}),
            }
        ).model_dump(mode="python")
    )
    template_auth, _request, _binding, _evidence, now = fixture()
    context = config.context
    clock = Clock(now)
    pools = [NoIOPool() for _ in range(5)]
    runtime_pool, risk_pool, exposure_pool, reconciliation_pool, accounting_pool = pools
    database_uuid = UUID("f3fbe25f-6af9-4c51-9fe1-4cd84737b8a2")
    common = {
        "expected_database": "kairos_production_evidence_synthetic_assembly",
        "database_uuid": database_uuid,
        "policy_namespace": "synthetic:assembly",
        "context": context,
        "state_schema_version": 3,
    }
    state = AsyncPostgresProductionSigningStateSource(
        runtime_pool, runtime_role="assembly_runtime", clock_probe=clock, **common
    )
    claims = PostgresProductionClaims(
        runtime_pool,
        runtime_role="assembly_runtime",
        **{key: value for key, value in common.items() if key != "state_schema_version"},
    )
    owner_key = template_auth._owner_key.model_copy(update={"context": context})
    authorization = ProductionSigningAuthorizationVerifier(
        source=state,
        preconditions=template_auth._preconditions.model_copy(update={"context": context}),
        owner_key=owner_key,
        expected_owner_key_sha256=canonical_digest(owner_key),
        expected_owner_identity=template_auth._owner,
        expected_claim_database_uuid=database_uuid,
        maximum_arm_lifetime=template_auth._arm_lifetime,
        clock_probe=clock,
    )
    backend = Backend()
    signer = ManagedSignerBoundary(
        config.custody_binding,
        backend=backend,
        verifier=Verifier(),
        claims=claims,
        authorization=authorization,
    )
    client = ProductionEvedexSdkClient(
        node_executable=Path(__file__).resolve().parent / "fixtures" / "node.exe",
        api_key_file=Path(__file__).resolve().parent / "fixtures" / "must-not-be-read.key",
        expected_account_id=context.remote_account_id,
    )
    transport = ProductionEvedexTransport(
        context=context, custody_binding=config.custody_binding, client=client
    )
    dispatcher = ProductionEffectDispatcher(
        authorization=authorization,
        signature_verifier=SyntheticSignatureVerifier(),
        claims=claims,
        database_uuid=database_uuid,
        context=context,
        clock=clock,
        sender=transport.send_signed_post,
    )
    runtime = ProductionExecutionRuntime(
        signer=signer,
        authorization=authorization,
        claims=claims,
        state_source=state,
        dispatcher=dispatcher,
        database_uuid=database_uuid,
        context=context,
        clock=clock,
    )
    risk_writer = PostgresRiskStateWriter(risk_pool, expected_role="assembly_risk", **common)
    exposure_writer = PostgresExposureStateWriter(exposure_pool, expected_role="assembly_exposure", **common)
    *_, publisher, _production_context, _scope = _inputs()
    limits = publisher.evaluator.limits
    scope = LiveRiskScopeV1(
        context_sha256=canonical_digest(context),
        source_set_sha256=context.source_set_sha256,
        policy_sha256=context.frozen_policy_sha256,
        risk_limits_sha256=_scope.risk_limits_sha256,
        account_id=context.remote_account_id,
        strategy_id=context.adaptive_system_id,
        strategy_revision=config.strategy_revision,
        approved_prod_symbols=approved_symbols or tuple(config.symbol_map.items()),
    )
    risk = LiveRiskEvaluator(scope, limits, require_instrument_rules=require_instrument_rules)
    provider = NoIOProvider()
    resources = ProductionAssemblyResources(
        runtime=runtime,
        risk_evaluator=risk,
        risk_writer=risk_writer,
        exposure_writer=exposure_writer,
        exit_verifier=provider,
        exit_evidence_provider=provider,
        cancellation_sources={provider.source_id: provider},
        terminal_verifiers={provider.source_id: provider},
        trades=TradeLifecycleRepository(runtime_pool),
        effects=ExecutionJournalRepository(runtime_pool),
        lifecycle_settings=config,
        reconciliation_pool=reconciliation_pool,
        reconciler_role="assembly_reconciler",
        accounting_pool=accounting_pool,
        accounting_role="assembly_accounting",
        canary_verifier=_setup_canary()[0],
        clock=clock,
    )
    return resources, pools, provider, backend, client, transport


def test_actual_concrete_constructor_graph_builds_without_source_or_store_io():
    resources, pools, provider, backend, client, transport = concrete_resources()
    assembly = build_production_assembly(resources)

    assert assembly.status == ProductionAssemblyStatus()
    assert assembly.runtime is resources.runtime
    assert assembly.reads.client is transport.client is client
    assert assembly.entry_risk.evaluator is resources.risk_evaluator
    assert assembly.entry_risk.lifecycle_bindings is assembly.lifecycle_adapter.bindings
    assert assembly.exit_risk.lifecycle_bindings is assembly.lifecycle_adapter.bindings
    assert assembly.exit_risk.risk_writer is resources.risk_writer
    assert assembly.exit_risk.exposure_writer is resources.exposure_writer
    assert assembly.engine.trades is resources.trades
    assert assembly.engine.effects is resources.effects
    assert assembly.engine.mutation_budget.pool is resources.trades.pool
    assert assembly.engine.runtime_health.pool is resources.trades.pool
    assert assembly.engine.clock is resources.clock
    assert assembly.reconciler._clock is resources.clock
    assert assembly.coordinator.runtime is resources.runtime
    assert all(pool.calls == [] for pool in pools)
    assert provider.calls == backend.calls == []
    assert client._process is None and not client._preflight_complete
    assert not transport._preflight_complete


def test_canonical_host_frontdoor_builds_the_exact_concrete_graph_without_start_or_io():
    resources, pools, provider, backend, client, transport = concrete_resources()

    async def original_entry_provider():
        raise AssertionError("host construction must not invoke the original-entry provider")

    async def terminal_evidence_provider(_trade_id, _source_id):
        raise AssertionError("host construction must not request terminal evidence")

    host = build_production_host(
        resources,
        entry_provider=original_entry_provider,
        terminal_evidence_provider=terminal_evidence_provider,
        terminal_source_id=provider.source_id,
    )

    assert type(host) is ProductionHost
    assembly = host.assembly
    assert assembly.status == ProductionAssemblyStatus()
    assert host.status.started is False
    assert host.status.start_attempted is False
    assert host.status.readiness is False
    assert assembly.runtime is resources.runtime
    assert assembly.coordinator.runtime is assembly.runtime
    assert assembly.engine.production_runtime is assembly.runtime
    assert assembly.reads.client is transport.client is client
    assert assembly.entry_risk.evaluator is resources.risk_evaluator
    assert assembly.entry_risk.lifecycle_bindings is assembly.lifecycle_adapter.bindings
    assert assembly.exit_risk.lifecycle_bindings is assembly.lifecycle_adapter.bindings
    assert assembly.engine.trades is resources.trades
    assert assembly.engine.effects is resources.effects
    assert assembly.engine.trades.pool is assembly.engine.effects.pool is resources.runtime.state_source.pool
    assert assembly.engine.clock is assembly.reconciler._clock is resources.clock
    assert assembly.reconciler.pool is resources.reconciliation_pool
    assert assembly.accounting.pool is resources.accounting_pool
    assert all(pool.calls == [] for pool in pools)
    assert provider.calls == backend.calls == []
    assert client._process is None and not client._preflight_complete
    assert not transport._preflight_complete


@pytest.mark.parametrize("corruption", ["clock", "symbols"])
def test_canonical_host_frontdoor_rejects_bad_resources_before_host_or_provider_effects(
    monkeypatch,
    corruption,
):
    resources, pools, provider, backend, *_ = concrete_resources()
    if corruption == "clock":
        resources = replace(resources, clock=Clock(resources.clock()))
    else:
        resources = replace(
            resources,
            risk_evaluator=LiveRiskEvaluator(
                LiveRiskScopeV1.model_validate(
                    resources.risk_evaluator.scope.model_dump()
                    | {"approved_prod_symbols": (("BTCUSDT", "ETHUSD"),)}
                ),
                resources.risk_evaluator.limits,
                require_instrument_rules=True,
            ),
        )

    def forbidden_host_constructor(*_args, **_kwargs):
        raise AssertionError("invalid resources must fail before the host is constructed")

    monkeypatch.setattr("kairos_execution.production_host.ProductionHost", forbidden_host_constructor)

    with pytest.raises(ProductionAssemblyError):
        build_production_host(
            resources,
            entry_provider=lambda: None,
            terminal_evidence_provider=lambda _trade_id, _source_id: None,
            terminal_source_id=provider.source_id,
        )

    assert all(pool.calls == [] for pool in pools)
    assert provider.calls == backend.calls == []


def test_different_clock_instance_is_rejected_with_actual_constructor_resources():
    resources, pools, provider, backend, _client, _transport = concrete_resources()
    altered = replace(resources, clock=Clock(resources.clock()))
    with pytest.raises(ProductionAssemblyError, match="monotone clock"):
        build_production_assembly(altered)
    assert all(pool.calls == [] for pool in pools)
    assert provider.calls == backend.calls == []


def test_legacy_risk_without_required_instrument_proof_cannot_be_assembled():
    resources, *_ = concrete_resources(require_instrument_rules=False)
    with pytest.raises(ProductionAssemblyError, match="instrument"):
        build_production_assembly(resources)


def test_risk_symbol_subset_must_not_remap_the_frozen_lifecycle_symbol():
    resources, *_ = concrete_resources(approved_symbols=(("BTCUSDT", "ETHUSD"),))
    with pytest.raises(ProductionAssemblyError, match="symbol"):
        build_production_assembly(resources)
