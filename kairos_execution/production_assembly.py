"""Narrow explicit assembly for the existing managed EVEDEX PROD path.

This module joins pre-provisioned, caller-owned stores and independently
implemented evidence providers. It performs no provisioning, credential reads,
network calls, evidence enrollment, automatic arming, or readiness promotion.
Successful assembly is engineering composition only; the returned status stays
``REJECT_ALL`` until an explicitly invoked manual technical-canary start.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Literal

import asyncpg  # type: ignore[import-untyped]  # Upstream ships no typing marker/stubs.
from kairos_persistence import ExecutionJournalRepository, TradeLifecycleRepository
from kairos_risk.live import LiveRiskEvaluator  # type: ignore[import-untyped]

from .managed_signer import ManagedSignerBoundary
from .production_accounting import PostgresProductionAccounting
from .production_cancellation import (
    ProductionCancellationVenueSource,
    ProductionCancellationVerifier,
)
from .production_claims import PostgresProductionClaims
from .production_exit_risk import (
    ProductionExitEvidenceVerifier,
    ProductionLiveExitRiskPublisher,
)
from .production_lifecycle import ProductionLifecycleConfigV1, ProductionLifecycleEngine
from .production_lifecycle_adapter import ManagedProductionLifecycleAdapter
from .production_lifecycle_store import PostgresLifecycleBindingStore
from .production_path import (
    PreparedExitEvidenceProvider,
    ProductionLiveEntryRefusal,
    ProductionLiveEntryResult,
    ProductionLiveLifecycleCoordinator,
    ProductionPreparedExitRiskStager,
)
from .production_readiness import (
    ReceiptReferenceV1,
    SignedManualArmRequestV1,
    canonical_digest,
)
from .production_reads import ProductionEvedexReads
from .production_reconciliation import (
    ProductionReservationReconciler,
    VenueTerminalEvidenceVerifier,
)
from .production_risk import ProductionLiveRiskPublisher
from .production_runtime import ProductionExecutionRuntime
from .production_service import ProductionEntryEnvelope, ProductionServiceDriver
from .production_state import (
    AsyncPostgresProductionSigningStateSource,
    PostgresExposureStateWriter,
    PostgresRiskStateWriter,
)
from .production_transport import ProductionEvedexSdkClient, ProductionEvedexTransport
from .signing_authorization import ProductionSigningAuthorizationVerifier
from .technical_canary_readiness import TechnicalCanaryPreconditionsVerifier
from .technical_canary_service import start_technical_canary_service


class ProductionAssemblyError(RuntimeError):
    """The supplied reviewed resources cannot form one exact PROD scope."""


@dataclass(frozen=True, slots=True)
class ProductionAssemblyResources:
    """Existing concrete providers and role-scoped pools required for assembly.

    Pools are already provisioned and connected by deployment. The two venue
    verifier maps are explicit trust boundaries, not proof that their sources
    are qualified. Their actual reads occur only after a canary is manually
    started and a lifecycle effect reaches the corresponding boundary.
    """

    runtime: ProductionExecutionRuntime
    risk_evaluator: LiveRiskEvaluator
    risk_writer: PostgresRiskStateWriter
    exposure_writer: PostgresExposureStateWriter
    exit_verifier: ProductionExitEvidenceVerifier
    exit_evidence_provider: PreparedExitEvidenceProvider
    cancellation_sources: Mapping[str, ProductionCancellationVenueSource]
    terminal_verifiers: Mapping[str, VenueTerminalEvidenceVerifier]
    trades: TradeLifecycleRepository
    effects: ExecutionJournalRepository
    lifecycle_settings: ProductionLifecycleConfigV1
    reconciliation_pool: asyncpg.Pool
    reconciler_role: str
    accounting_pool: asyncpg.Pool
    accounting_role: str
    canary_verifier: TechnicalCanaryPreconditionsVerifier
    clock: Callable[[], datetime]
    sleeper: Callable[[float], Awaitable[None]] | None = None


@dataclass(frozen=True, slots=True)
class ProductionAssemblyStatus:
    technical_paper_ready: Literal[False] = False
    paper_qualified: Literal[False] = False
    alpha_ready: Literal[False] = False
    live_ready: Literal[False] = False
    policy: Literal["REJECT_ALL"] = "REJECT_ALL"
    start_attempted: bool = False
    service_started: bool = False
    recovery_complete: bool = False


@dataclass(slots=True)
class ProductionAssembly:
    """Joined production objects with a one-shot explicit canary start."""

    runtime: ProductionExecutionRuntime
    reads: ProductionEvedexReads
    entry_risk: ProductionLiveRiskPublisher
    exit_risk: ProductionLiveExitRiskPublisher
    cancellation_verifier: ProductionCancellationVerifier
    lifecycle_adapter: ManagedProductionLifecycleAdapter
    engine: ProductionLifecycleEngine
    coordinator: ProductionLiveLifecycleCoordinator
    reconciler: ProductionReservationReconciler
    accounting: PostgresProductionAccounting
    canary_verifier: TechnicalCanaryPreconditionsVerifier
    _start_attempted: bool = field(default=False, init=False, repr=False)
    _driver: ProductionServiceDriver | None = field(default=None, init=False, repr=False)

    @property
    def status(self) -> ProductionAssemblyStatus:
        driver = self._driver
        driver_status = getattr(driver, "status", None)
        return ProductionAssemblyStatus(
            start_attempted=self._start_attempted,
            service_started=bool(getattr(driver_status, "started", False)),
            recovery_complete=bool(getattr(driver_status, "recovery_complete", False)),
        )

    async def start_technical_canary(
        self,
        *,
        references: Sequence[ReceiptReferenceV1],
        owner_arm: SignedManualArmRequestV1,
    ) -> ProductionServiceDriver:
        """Start exactly one manually armed session; a failed attempt is final.

        The latch is set before the first await. No second arm, nonce, driver or
        recovery attempt can be adopted by this assembly after failure/cancel.
        """
        if self._start_attempted:
            raise ProductionAssemblyError("canary start already attempted; no new arm or driver is allowed")
        self._start_attempted = True
        driver = await start_technical_canary_service(
            coordinator=self.coordinator,
            verifier=self.canary_verifier,
            references=references,
            owner_arm=owner_arm,
        )
        if type(driver) is not ProductionServiceDriver:
            raise ProductionAssemblyError("technical-canary service returned an unexpected driver")
        self._driver = driver
        return driver

    async def submit_entry(
        self, envelope: ProductionEntryEnvelope
    ) -> ProductionLiveEntryResult | ProductionLiveEntryRefusal:
        """Submit one immutable envelope to the manually armed one-entry driver."""
        if type(self._driver) is not ProductionServiceDriver or not self._driver.status.started:
            raise ProductionAssemblyError("entry submission requires the explicitly armed service driver")
        return await self._driver.submit(envelope)

    async def run(self, *, stop: asyncio.Event) -> None:
        """Wait for shutdown of the already-started driver; never start it again."""
        driver = self._driver
        if type(driver) is not ProductionServiceDriver or not driver.status.started:
            raise ProductionAssemblyError("the explicitly armed service driver has not started")
        if not isinstance(stop, asyncio.Event):
            try:
                await driver.close()
            except Exception as exc:
                raise ProductionAssemblyError(
                    "invalid stop signal and service shutdown is unresolved"
                ) from exc
            raise TypeError("an asyncio.Event stop signal is required")
        try:
            await stop.wait()
        finally:
            await driver.close()

    async def reconcile_closed_account(
        self,
        *,
        trade_id: str,
        source_id: str,
        raw_venue_evidence: object,
    ) -> dict[str, object]:
        """Reconcile through the running driver's account lock with accounting.

        The reconciler and accounting objects are fixed by this assembly and
        cannot be omitted or substituted by the caller. A non-accepted release
        is not returned as successful reconciliation.
        """
        driver = self._driver
        if type(driver) is not ProductionServiceDriver or not driver.status.started:
            raise ProductionAssemblyError("closed-account reconciliation requires the started service driver")
        result = await driver.reconcile_closed_account(
            trade_id=trade_id,
            reconciler=self.reconciler,
            source_id=source_id,
            raw_venue_evidence=raw_venue_evidence,
            accounting=self.accounting,
        )
        if result.get("reservation_released") is not True or not isinstance(
            result.get("accounting_receipt"), dict
        ):
            raise ProductionAssemblyError(
                "terminal receipt was not accepted by the attached accounting store"
            )
        return result


def _require_provider_map(name: str, providers: Mapping[str, object], method: str) -> None:
    if not isinstance(providers, Mapping) or not providers:
        raise ProductionAssemblyError(f"explicit registered {name} providers are required")
    for source_id, provider in providers.items():
        if (
            not isinstance(source_id, str)
            or not source_id
            or getattr(provider, "source_id", None) != source_id
            or not callable(getattr(provider, method, None))
        ):
            raise ProductionAssemblyError(f"{name} provider registration is malformed")


def _validate_resources(resources: ProductionAssemblyResources) -> tuple[ProductionEvedexTransport, str]:
    if type(resources) is not ProductionAssemblyResources:
        raise TypeError("the typed ProductionAssemblyResources value is required")
    runtime = resources.runtime
    if type(runtime) is not ProductionExecutionRuntime:
        raise TypeError("the exact ProductionExecutionRuntime is required")
    if type(runtime.authorization) is not ProductionSigningAuthorizationVerifier:
        raise TypeError("the exact production authorization verifier is required")
    if type(runtime.signer) is not ManagedSignerBoundary:
        raise TypeError("the exact managed signer boundary is required")
    if (
        type(runtime.claims) is not PostgresProductionClaims
        or type(runtime.state_source) is not AsyncPostgresProductionSigningStateSource
    ):
        raise TypeError("the PostgreSQL claims and state-source adapters are required")
    dispatcher = runtime.dispatcher
    sender = dispatcher.sender
    transport = getattr(sender, "__self__", None)
    if (
        type(transport) is not ProductionEvedexTransport
        or getattr(sender, "__func__", None) is not ProductionEvedexTransport.send_signed_post
        or type(transport.client) is not ProductionEvedexSdkClient
    ):
        raise ProductionAssemblyError("runtime sender must be the exact typed PROD EVEDEX transport")
    if (
        runtime.context.environment != "PROD"
        or runtime.context.exchange != "EVEDEX"
        or transport.context != runtime.context
        or transport.custody_binding != runtime.binding
        or runtime.authorization._preconditions.context != runtime.context
        or runtime.state_source.context != runtime.context
        or runtime.claims.context_sha256 != canonical_digest(runtime.context)
    ):
        raise ProductionAssemblyError("runtime, transport, custody and authority scopes differ")
    if (
        runtime.state_source.database_uuid != runtime.database_uuid
        or runtime.claims.database_uuid != runtime.database_uuid
        or runtime.authorization._claim_database_uuid != runtime.database_uuid
        or runtime.dispatcher.database_uuid != runtime.database_uuid
        or runtime.dispatcher.context != runtime.context
        or runtime.state_source.state_schema_version != 3
    ):
        raise ProductionAssemblyError("runtime UUID differs across claims, state, authority and dispatcher")
    runtime_pool = runtime.state_source.pool
    runtime_role = runtime.state_source.runtime_role
    database = runtime.state_source.expected_database
    namespace = runtime.state_source.policy_namespace
    if (
        runtime.claims.pool is not runtime_pool
        or runtime.claims.runtime_role != runtime_role
        or runtime.claims.expected_database != database
        or runtime.claims.policy_namespace != namespace
        or runtime.dispatcher.claims is not runtime.claims
        or runtime.dispatcher.authorization is not runtime.authorization
        or runtime.signer._authorization is not runtime.authorization
        or runtime.signer._claims is not runtime.claims
        or runtime.signer.binding != runtime.binding
        or runtime.authorization._source is not runtime.state_source
        or runtime.authorization._clock is not resources.clock
        or runtime._clock is not resources.clock
        or runtime.state_source._clock_probe is not resources.clock
        or dispatcher.clock is not resources.clock
    ):
        raise ProductionAssemblyError("runtime stores or monotone clock are not the same exact instances")
    if type(resources.risk_evaluator) is not LiveRiskEvaluator:
        raise TypeError("the existing concrete LIVE Risk evaluator is required")
    if resources.risk_evaluator._require_instrument_rules is not True:
        raise ProductionAssemblyError("PROD Risk evaluation must require captured venue instrument rules")
    if (
        type(resources.risk_writer) is not PostgresRiskStateWriter
        or type(resources.exposure_writer) is not PostgresExposureStateWriter
    ):
        raise TypeError("the existing PostgreSQL Risk and exposure writers are required")
    if (
        resources.risk_writer.state_schema_version != 3
        or resources.exposure_writer.state_schema_version != 3
        or resources.risk_writer.expected_database != database
        or resources.exposure_writer.expected_database != database
        or resources.risk_writer.database_uuid != runtime.database_uuid
        or resources.exposure_writer.database_uuid != runtime.database_uuid
        or resources.risk_writer.policy_namespace != namespace
        or resources.exposure_writer.policy_namespace != namespace
        or resources.risk_writer.context != runtime.context
        or resources.exposure_writer.context != runtime.context
        or resources.risk_writer.pool is runtime_pool
        or resources.exposure_writer.pool is runtime_pool
        or resources.risk_writer.pool is resources.exposure_writer.pool
    ):
        raise ProductionAssemblyError("Risk/exposure writers do not match exact state-v3 scope")
    config = resources.lifecycle_settings
    if (
        type(config) is not ProductionLifecycleConfigV1
        or config.context != runtime.context
        or config.custody_binding != runtime.binding
    ):
        raise ProductionAssemblyError("lifecycle settings differ from exact PROD runtime scope")
    if any(
        config.symbol_map.get(signal_symbol) != venue_symbol
        for signal_symbol, venue_symbol in resources.risk_evaluator.scope.approved_prod_symbols
    ):
        raise ProductionAssemblyError("LIVE Risk approved instruments differ from the lifecycle symbol map")
    if (
        type(resources.trades) is not TradeLifecycleRepository
        or type(resources.effects) is not ExecutionJournalRepository
    ):
        raise TypeError("native durable trade and execution-journal repositories are required")
    if resources.trades.pool is not runtime_pool or resources.effects.pool is not runtime_pool:
        raise ProductionAssemblyError("native trade/effect repositories must share the runtime pool")
    if not callable(resources.clock):
        raise TypeError("one shared monotone UTC clock is required")
    instant = resources.clock()
    if (
        not isinstance(instant, datetime)
        or instant.tzinfo is None
        or instant.utcoffset() != UTC.utcoffset(instant)
    ):
        raise ProductionAssemblyError("the shared production clock must return an aware UTC datetime")
    _require_provider_map(
        "cancellation venue",
        resources.cancellation_sources,
        "read_cancellation_snapshot_async",
    )
    if any(
        not callable(getattr(provider, "verify_cancellation_snapshot", None))
        for provider in resources.cancellation_sources.values()
    ):
        raise ProductionAssemblyError("cancellation providers need typed independent snapshot verification")
    _require_provider_map("terminal venue", resources.terminal_verifiers, "verify_terminal_evidence")
    if (
        getattr(resources.exit_verifier, "source_id", None) is None
        or not callable(getattr(resources.exit_verifier, "verify_exit", None))
        or getattr(resources.exit_evidence_provider, "source_id", None) != resources.exit_verifier.source_id
        or not callable(getattr(resources.exit_evidence_provider, "capture_prepared_exit", None))
    ):
        raise ProductionAssemblyError("prepared-exit evidence provider and independent verifier differ")
    roles = (
        runtime.state_source.runtime_role,
        resources.risk_writer.expected_role,
        resources.exposure_writer.expected_role,
        resources.reconciler_role,
        resources.accounting_role,
    )
    if not all(isinstance(role, str) and role for role in roles) or len(set(roles)) != len(roles):
        raise ProductionAssemblyError(
            "runtime, Risk, exposure, reconciler and accounting roles must be distinct"
        )
    if resources.reconciler_role == resources.accounting_role:
        raise ProductionAssemblyError("reconciler and accounting use separate least-privilege roles")
    if (
        resources.reconciliation_pool is None
        or resources.accounting_pool is None
        or resources.reconciliation_pool is runtime_pool
        or resources.accounting_pool is runtime_pool
        or resources.reconciliation_pool is resources.accounting_pool
        or resources.reconciliation_pool is resources.risk_writer.pool
        or resources.reconciliation_pool is resources.exposure_writer.pool
        or resources.accounting_pool is resources.risk_writer.pool
        or resources.accounting_pool is resources.exposure_writer.pool
    ):
        raise ProductionAssemblyError("isolated runtime, reconciler and accounting role pools are required")
    if type(resources.canary_verifier) is not TechnicalCanaryPreconditionsVerifier:
        raise TypeError("the exact seven-gate technical-canary verifier is required")
    return transport, runtime_role


def build_production_assembly(resources: ProductionAssemblyResources) -> ProductionAssembly:
    """Join existing components without touching any external source or store."""
    transport, runtime_role = _validate_resources(resources)
    runtime = resources.runtime
    runtime_pool = runtime.state_source.pool
    context = runtime.context
    database = runtime.state_source.expected_database
    namespace = runtime.state_source.policy_namespace

    # The PROD REST reader and signed transport must share this exact client.
    reads = ProductionEvedexReads(transport.client, symbol_map=resources.lifecycle_settings.symbol_map)
    bindings = PostgresLifecycleBindingStore(
        runtime_pool,
        context=context,
        expected_database=database,
        expected_role=runtime_role,
    )
    entry_risk = ProductionLiveRiskPublisher(
        evaluator=resources.risk_evaluator,
        risk_writer=resources.risk_writer,
        lifecycle_bindings=bindings,
        custody_binding=runtime.binding,
        database_uuid=runtime.database_uuid,
        policy_namespace=namespace,
    )
    trades = resources.trades
    effects = resources.effects
    exit_risk = ProductionLiveExitRiskPublisher(
        verifier=resources.exit_verifier,
        trades=trades,
        effects=effects,
        risk_writer=resources.risk_writer,
        exposure_writer=resources.exposure_writer,
        lifecycle_bindings=bindings,
        custody_binding=runtime.binding,
        database_uuid=runtime.database_uuid,
        policy_namespace=namespace,
    )
    exit_stager = ProductionPreparedExitRiskStager(
        publisher=exit_risk,
        runtime=runtime,
        evidence_provider=resources.exit_evidence_provider,
        clock=resources.clock,
    )
    authorization = runtime.authorization
    cancellations = ProductionCancellationVerifier(
        claims=runtime.claims,
        state_source=runtime.state_source,
        bindings=bindings,
        custody_binding=runtime.binding,
        trades=trades,
        effects=effects,
        venue_sources=resources.cancellation_sources,
        transport=transport,
        database_uuid=runtime.database_uuid,
        context=context,
        preconditions=authorization._preconditions,
        owner_key=authorization._owner_key,
        expected_owner_key_sha256=authorization._owner_key_sha256,
        expected_owner_identity=authorization._owner,
        maximum_arm_lifetime=authorization._arm_lifetime,
        clock=resources.clock,
    )
    lifecycle_adapter = ManagedProductionLifecycleAdapter(
        runtime=runtime,
        reads=reads,
        bindings=bindings,
        trades=trades,
        effects=effects,
        cancellations=cancellations,
        clock=resources.clock,
    )
    engine = ProductionLifecycleEngine(
        lifecycle_adapter,
        trades,
        effects,
        resources.lifecycle_settings,
        runtime,
        clock=resources.clock,
        sleeper=resources.sleeper,
        prepared_exit_risk=exit_stager,
    )
    coordinator = ProductionLiveLifecycleCoordinator(engine=engine, entry_risk=entry_risk)
    reconciler = ProductionReservationReconciler(
        pool=resources.reconciliation_pool,
        expected_database=database,
        database_uuid=runtime.database_uuid,
        policy_namespace=namespace,
        context=context,
        expected_role=resources.reconciler_role,
        source_verifiers=resources.terminal_verifiers,
        trades=trades,
        effects=effects,
        clock=resources.clock,
        schema_version=2,
    )
    accounting = PostgresProductionAccounting(
        resources.accounting_pool,
        expected_database=database,
        database_uuid=runtime.database_uuid,
        policy_namespace=namespace,
        context=context,
        accounting_role=resources.accounting_role,
    )
    # No preflight, schema provisioning, source I/O, or driver start occurs here.
    return ProductionAssembly(
        runtime=runtime,
        reads=reads,
        entry_risk=entry_risk,
        exit_risk=exit_risk,
        cancellation_verifier=cancellations,
        lifecycle_adapter=lifecycle_adapter,
        engine=engine,
        coordinator=coordinator,
        reconciler=reconciler,
        accounting=accounting,
        canary_verifier=resources.canary_verifier,
    )
