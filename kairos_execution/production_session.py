"""One automatically armed EVEDEX PROD trade through the production path.

The production path admits one entry per owner-signed arm and per start
(``ProductionHost``). The owner chose on 2026-11-14 to arm each trade automatically:
``AutoArmSigner`` signs one arm per trade with the owner's key, and the arm carries
exactly the dollar cap and daily stop the owner attested in the PRODUCTION_LIMITS
receipt, so automatic arming can never exceed them. The seven signed receipts, Risk
Manager, the account lock, reconciliation and accounting all still decide.

A session: verify the receipts, sign one arm, build the graph with the EVEDEX REST
sources (``production_rest_sources``), start, admit one bounded LIMIT_GTC entry from
the candidate, and keep the lifecycle running until the trade is FLAT and its terminal
accounting is accepted, or until the host latches a failure.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any, Literal
from uuid import UUID

import asyncpg  # type: ignore[import-untyped]  # Upstream ships no typing marker/stubs.
from kairos_core.contracts import CandidateReviewV1, StrategicAllocation, VenueQualityV1
from kairos_core.enums import SystemMode
from kairos_persistence import ExecutionJournalRepository, TradeLifecycleRepository
from kairos_risk.live import (  # type: ignore[import-untyped]
    LiveRiskEvaluator,
    LiveRiskLimitsV1,
    LiveRiskScopeV1,
)

from .limit_gtc_contract import LimitGtcEntryV1
from .managed_signer import CustodyBindingV1, ManagedCustodyBackend, SignatureVerifier
from .production_assembly import ProductionAssemblyResources
from .production_dispatch import ProductionSignatureVerifier
from .production_host import ProductionHost, build_production_host
from .production_lifecycle import ProductionLifecycleConfigV1
from .production_owner import sign_manual_arm
from .production_readiness import (
    OwnerArmKeyV1,
    PreconditionsV1,
    ProductionContextV1,
    ReceiptReferenceV1,
    SignedManualArmRequestV1,
    canonical_digest,
)
from .production_reads import ProductionEvedexReads
from .production_rest_sources import (
    SOURCE_ID,
    RestCancellationVenueSource,
    RestEntryEvidenceProvider,
    RestLiveAccountVerifier,
    RestLiveExitVerifier,
    RestLiveInputsVerifier,
    RestPreparedExitEvidenceProvider,
    RestTerminalEvidenceProvider,
    RestTerminalEvidenceVerifier,
)
from .production_runtime_builder import build_clocked_production_runtime
from .production_service import ProductionEntryEnvelope
from .production_state import (
    PostgresExposureStateWriter,
    PostgresOperatorStateWriter,
    PostgresRiskStateWriter,
    resume_operator_after_kill_async,
)
from .production_transport import ProductionEvedexTransport
from .signing_authorization import LiveOperatorStateV1
from .technical_canary_readiness import TechnicalCanaryPreconditionsVerifier

_ENTRY_LEASE = timedelta(seconds=4)
_QUOTE_MARGIN = timedelta(milliseconds=20)
# Operator observations must be strictly before the database clock; a small margin
# absorbs the host/database clock difference without dating anything in the future.
_DB_CLOCK_MARGIN = timedelta(milliseconds=250)


class ProductionSessionError(RuntimeError):
    """The trade session refused or ended without accepted terminal accounting."""


class AutoArmSigner:
    """Sign one bounded arm per trade with the owner's key, never beyond the attested limits."""

    def __init__(
        self, key_path: Path, owner_key: OwnerArmKeyV1, *, lifetime: timedelta = timedelta(minutes=9)
    ):
        if not timedelta(0) < lifetime <= timedelta(minutes=10):
            raise ValueError("an automatic arm lives at most the ten-minute canary entry window")
        self.key_path = Path(key_path)
        self.owner_key = OwnerArmKeyV1.model_validate(owner_key)
        self.lifetime = lifetime

    def sign(self, preconditions: PreconditionsV1, *, now: datetime) -> SignedManualArmRequestV1:
        return sign_manual_arm(self.key_path, self.owner_key, preconditions, lifetime=self.lifetime, now=now)


class OperatorLatch:
    """The global operator latch: DISARMED, ARMED for one owner arm, or KILLED by the owner.

    Entries need a fresh ARMED observation bound to the exact owner arm (exits do not).
    The session arms only if the owner has not set KILLED, refreshes the observation
    right before the entry and disarms right after it. ``kill`` is the owner's global
    stop; nothing in this module ever leaves KILLED.
    """

    def __init__(
        self, writer: PostgresOperatorStateWriter, context: ProductionContextV1, clock: Callable[[], datetime]
    ):
        self.writer = writer
        self.context = context
        self.clock = clock

    def _stamp(self) -> datetime:
        return self.clock() - _DB_CLOCK_MARGIN

    @staticmethod
    def _command(
        state: str, version: int, nonce: str | None, request: str | None, expires: datetime | None
    ) -> str:
        return hashlib.sha256(
            json.dumps(
                {
                    "state": state,
                    "version": version,
                    "arm_nonce": nonce,
                    "arm_request_sha256": request,
                    "expires_at": None if expires is None else expires.isoformat(),
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()

    async def _next(
        self,
        state: Literal["ARMED", "DISARMED", "KILLED"],
        *,
        nonce: str | None = None,
        request: str | None = None,
        expires: datetime | None = None,
    ) -> LiveOperatorStateV1:
        latest = await self.writer.latest_operator_state_async()
        if latest is not None and latest.state == "KILLED" and state != "KILLED":
            raise ProductionSessionError("the owner's global stop (KILLED) is set")
        version = 1 if latest is None else latest.version + 1
        if latest is None and state != "DISARMED":
            await self._next("DISARMED")
            return await self._next(state, nonce=nonce, request=request, expires=expires)
        stamp = self._stamp()
        observation = LiveOperatorStateV1(
            context=self.context,
            version=version,
            state=state,
            arm_nonce=nonce,
            arm_request_sha256=request,
            observed_at=stamp,
            changed_at=stamp,
            expires_at=expires,
            command_sha256=self._command(state, version, nonce, request, expires),
            previous_command_sha256="0" * 64 if latest is None else latest.command_sha256,
        )
        await self.writer.append_operator_observation_async(observation)
        return observation

    async def arm(self, arm: SignedManualArmRequestV1) -> LiveOperatorStateV1:
        latest = await self.writer.latest_operator_state_async()
        if latest is not None and latest.state == "KILLED":
            raise ProductionSessionError("the owner's global stop (KILLED) is set")
        await self.writer.append_owner_arm_async(arm)
        return await self._next(
            "ARMED",
            nonce=arm.request.nonce,
            request=canonical_digest(arm.request),
            expires=arm.request.expires_at,
        )

    async def refresh(self) -> None:
        """Re-observe the unchanged current state so that it is fresh for the entry."""
        latest = await self.writer.latest_operator_state_async()
        if latest is None or latest.state != "ARMED":
            raise ProductionSessionError("the operator latch is not ARMED")
        await self.writer.append_operator_observation_async(
            latest.model_copy(update={"observed_at": self._stamp()})
        )

    async def disarm(self) -> None:
        latest = await self.writer.latest_operator_state_async()
        if latest is not None and latest.state == "ARMED":
            await self._next("DISARMED")

    async def kill(self) -> LiveOperatorStateV1:
        """The owner's global stop: no entry is armed again until the owner resolves it."""
        return await self._next("KILLED")

    async def resume(self, *, owner_pool: asyncpg.Pool, owner_role: str) -> LiveOperatorStateV1:
        """Resume one exact KILLED command using the separate database-owner LOGIN."""
        latest = await self.writer.latest_operator_state_async()
        if latest is None or latest.state != "KILLED":
            raise ProductionSessionError("only a KILLED latch can be resumed")
        return await resume_operator_after_kill_async(
            owner_pool,
            expected_database=self.writer.expected_database,
            database_uuid=self.writer.database_uuid,
            policy_namespace=self.writer.policy_namespace,
            context=self.context,
            owner_role=owner_role,
            expected_version=latest.version,
            expected_command_sha256=latest.command_sha256,
        )


@dataclass(frozen=True, slots=True)
class RolePools:
    """The five connected role pools of one provisioned database and their role names."""

    runtime: asyncpg.Pool
    operator: asyncpg.Pool
    risk: asyncpg.Pool
    exposure: asyncpg.Pool
    reconciliation: asyncpg.Pool
    accounting: asyncpg.Pool
    roles: Mapping[str, str]
    database: str
    database_uuid: UUID
    policy_namespace: str


VenueProvider = Callable[[CandidateReviewV1], Awaitable[VenueQualityV1]]


@dataclass(frozen=True, slots=True)
class TradeCandidate:
    """What the runner decided upstream: the reviewed intent and the strategic allocation.

    The venue measurement lives five seconds, so it is not part of the candidate: the
    session asks ``venue_provider`` for a fresh one immediately before the entry.
    """

    review: CandidateReviewV1
    allocation: StrategicAllocation | None
    system_mode: SystemMode = SystemMode.NORMAL


@dataclass(slots=True)
class RestSession:
    """The assembled resources plus the REST pieces the host and entry provider need."""

    resources: ProductionAssemblyResources
    reads: ProductionEvedexReads
    trades: TradeLifecycleRepository
    terminal: RestTerminalEvidenceProvider
    operator: OperatorLatch
    preconditions: PreconditionsV1
    references: tuple[ReceiptReferenceV1, ...]
    clock: Callable[[], datetime]
    log: list[dict[str, Any]] = field(default_factory=list)


def build_rest_session(
    *,
    pools: RolePools,
    settings: ProductionLifecycleConfigV1,
    references: Sequence[ReceiptReferenceV1],
    canary_verifier: TechnicalCanaryPreconditionsVerifier,
    owner_key: OwnerArmKeyV1,
    custody_backend: ManagedCustodyBackend,
    custody_signature_verifier: SignatureVerifier,
    wire_signature_verifier: ProductionSignatureVerifier,
    transport: ProductionEvedexTransport,
    limits: LiveRiskLimitsV1,
    exit_fee_rate: Decimal,
    adverse_slippage_rate: Decimal,
    clock: Callable[[], datetime],
    maximum_arm_lifetime: timedelta = timedelta(minutes=10),
) -> RestSession:
    """Verify the seven receipts now and build the exact production graph with REST sources."""
    if settings.entry_order_type != "LIMIT_GTC":
        raise ProductionSessionError("the REST session enters only with the bounded LIMIT_GTC contract")
    context = settings.context
    custody: CustodyBindingV1 = settings.custody_binding
    verified = canary_verifier.verify(context, tuple(references), now=clock())
    preconditions = verified.preconditions
    common: dict[str, Any] = {
        "expected_database": pools.database,
        "database_uuid": pools.database_uuid,
        "policy_namespace": pools.policy_namespace,
        "context": context,
        "state_schema_version": 3,
    }
    runtime = build_clocked_production_runtime(
        pool=pools.runtime,
        expected_database=pools.database,
        database_uuid=pools.database_uuid,
        policy_namespace=pools.policy_namespace,
        runtime_role=pools.roles["runtime"],
        context=context,
        custody_binding=custody,
        preconditions=preconditions,
        owner_key=owner_key,
        expected_owner_key_sha256=canonical_digest(owner_key),
        expected_owner_identity=owner_key.owner_identity,
        maximum_arm_lifetime=maximum_arm_lifetime,
        custody_backend=custody_backend,
        custody_signature_verifier=custody_signature_verifier,
        wire_signature_verifier=wire_signature_verifier,
        transport=transport,
        clock=clock,
        limit_time_in_force="GTC",
    )
    reads = ProductionEvedexReads(transport.client, symbol_map=settings.symbol_map)
    trades = TradeLifecycleRepository(pools.runtime)
    effects = ExecutionJournalRepository(pools.runtime)
    scope = LiveRiskScopeV1(
        context_sha256=canonical_digest(context),
        source_set_sha256=context.source_set_sha256,
        policy_sha256=context.frozen_policy_sha256,
        risk_limits_sha256=_limits_sha256(limits),
        account_id=context.remote_account_id,
        strategy_id=context.adaptive_system_id,
        strategy_revision=settings.strategy_revision,
        approved_prod_symbols=tuple(settings.symbol_map.items()),
    )
    evaluator = LiveRiskEvaluator(
        scope,
        limits,
        account_verifiers={SOURCE_ID: RestLiveAccountVerifier()},
        input_verifier=RestLiveInputsVerifier(),
        require_instrument_rules=True,
    )
    exits = RestPreparedExitEvidenceProvider(
        reads=reads, effects=effects, trades=trades, pool=pools.runtime, clock=clock
    )
    cancellation = RestCancellationVenueSource(reads=reads, trades=trades, clock=clock)
    terminal_verifier = RestTerminalEvidenceVerifier()
    resources = ProductionAssemblyResources(
        runtime=runtime,
        risk_evaluator=evaluator,
        risk_writer=PostgresRiskStateWriter(pools.risk, expected_role=pools.roles["risk"], **common),
        exposure_writer=PostgresExposureStateWriter(
            pools.exposure, expected_role=pools.roles["exposure"], **common
        ),
        exit_verifier=RestLiveExitVerifier(
            exit_fee_rate=exit_fee_rate, adverse_slippage_rate=adverse_slippage_rate
        ),
        exit_evidence_provider=exits,
        cancellation_sources={SOURCE_ID: cancellation},
        terminal_verifiers={SOURCE_ID: terminal_verifier},
        trades=trades,
        effects=effects,
        lifecycle_settings=settings,
        reconciliation_pool=pools.reconciliation,
        reconciler_role=pools.roles["reconciler"],
        accounting_pool=pools.accounting,
        accounting_role=pools.roles["accounting"],
        canary_verifier=canary_verifier,
        clock=clock,
    )
    terminal = RestTerminalEvidenceProvider(
        reads=reads, trades=trades, reservations_pool=pools.reconciliation, context=context, clock=clock
    )
    operator = OperatorLatch(
        PostgresOperatorStateWriter(pools.operator, expected_role=pools.roles["operator"], **common),
        context,
        clock,
    )
    return RestSession(
        resources=resources,
        reads=reads,
        trades=trades,
        terminal=terminal,
        operator=operator,
        preconditions=preconditions,
        references=tuple(references),
        clock=clock,
    )


def _limits_sha256(limits: LiveRiskLimitsV1) -> str:
    from kairos_core.contracts import canonical_sha256

    return str(canonical_sha256(limits.model_dump(mode="json")))


@dataclass(frozen=True, slots=True)
class TradeSessionResult:
    outcome: Literal["REFUSED", "CLOSED_AND_ACCOUNTED", "UNRESOLVED"]
    trade_id: str | None
    detail: str


async def run_one_trade(
    session: RestSession,
    candidate: TradeCandidate,
    signer: AutoArmSigner,
    venue_provider: VenueProvider,
    *,
    stop: asyncio.Event | None = None,
    poll_s: float = 2.0,
    early_exit: Callable[[], str | None] | None = None,
) -> TradeSessionResult:
    """Arm, admit one entry and keep the lifecycle running until accounting or a latched failure.

    ``early_exit`` is asked on every poll while the trade is open; the first reason it
    returns closes the position at market through the engine's reviewed exit path (the
    composer's regime-change or material-event decision). Protections stay until then.
    """
    clock = session.clock
    arm = signer.sign(session.preconditions, now=clock())
    entry_evidence: RestEntryEvidenceProvider | None = None
    host: ProductionHost | None = None

    async def entry_provider() -> ProductionEntryEnvelope:
        if host is None or entry_evidence is None:
            raise ProductionSessionError("the entry was requested before the host started")
        account = await entry_evidence.capture_account()
        venue = await venue_provider(candidate.review)
        inputs = entry_evidence.inputs_for(venue)
        await session.operator.refresh()
        now = clock()
        # Risk staging refuses a signing deadline later than two seconds after the venue
        # observation and its book and reference timestamps (production_risk).
        quote_ttl = min(venue.observed_at_ms, venue.book_timestamp_ms, venue.reference_timestamp_ms) + 2_000
        expires = min(now + _ENTRY_LEASE, datetime.fromtimestamp(quote_ttl / 1_000, tz=UTC) - _QUOTE_MARGIN)
        if expires <= now:
            raise ProductionSessionError("the venue measurement aged past its quote window before the entry")
        return ProductionEntryEnvelope(
            envelope_id="entry-" + secrets.token_hex(12),
            raw_account_evidence=account,
            raw_inputs_evidence=inputs,
            source_id=SOURCE_ID,
            review=candidate.review,
            venue=venue,
            allocation=candidate.allocation,
            owner_arm=arm,
            expires_at=expires,
            system_mode=candidate.system_mode,
            limit_gtc_entry=LimitGtcEntryV1(cancel_after_ms=int(expires.timestamp() * 1000)),
        )

    host = build_production_host(
        session.resources,
        entry_provider=entry_provider,
        terminal_evidence_provider=session.terminal,
        terminal_source_id=SOURCE_ID,
    )
    await session.operator.arm(arm)
    await host.start(references=session.references, owner_arm=arm)
    await session.reads.preflight()
    entry_evidence = RestEntryEvidenceProvider(
        reads=session.reads,
        trades=session.trades,
        context=session.resources.lifecycle_settings.context,
        account_snapshot=host.assembly.engine.account_snapshot,
        clock=clock,
    )
    stop = stop or asyncio.Event()
    runner = asyncio.create_task(host.run(stop=stop))
    try:
        try:
            result = await host.submit_one()
        finally:
            await session.operator.disarm()
        if type(result).__name__ == "ProductionLiveEntryRefusal":
            reasons = getattr(
                getattr(getattr(result, "evaluation", None), "decision", None), "rejection_reasons", ()
            )
            return TradeSessionResult("REFUSED", None, ", ".join(reasons)[:500] or "refused before any order")
        exit_requested = False
        while not stop.is_set():
            status = host.status
            if early_exit is not None and not exit_requested and status.owned_trade_id is not None:
                reason = early_exit()
                if reason:
                    host.assembly.engine.request_early_exit(status.owned_trade_id, reason)
                    exit_requested = True
            if status.terminal_accounting_accepted:
                return TradeSessionResult(
                    "CLOSED_AND_ACCOUNTED", status.owned_trade_id, "terminal accounting accepted"
                )
            if status.supervisor_failure is not None:
                return TradeSessionResult("UNRESOLVED", status.owned_trade_id, status.supervisor_failure)
            await asyncio.sleep(poll_s)
        return TradeSessionResult("UNRESOLVED", host.status.owned_trade_id, "stopped by the operator")
    finally:
        stop.set()
        try:
            await runner
        finally:
            await session.reads.close()


__all__ = [
    "AutoArmSigner",
    "OperatorLatch",
    "ProductionSessionError",
    "RestSession",
    "RolePools",
    "TradeCandidate",
    "TradeSessionResult",
    "VenueProvider",
    "build_rest_session",
    "run_one_trade",
]
