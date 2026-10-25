"""Explicit LIVE Risk → protected FSM composition; no factory or LIVE switch.

Sources remain independent mandatory verifiers. Construction never supplies an
owner arm, account truth, credentials, or a qualified EVEDEX history source.
"""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Protocol

from kairos_core.contracts import CandidateReviewV1, StrategicAllocation, VenueQualityV1
from kairos_core.enums import SystemMode

from .paper_engine import PaperExecutionResult
from .production_exit_risk import ProductionExitRiskStageReceiptV1, ProductionLiveExitRiskPublisher
from .production_lifecycle import ProductionLifecycleEngine
from .production_lifecycle_binding import ProductionLifecycleBindingV1
from .production_readiness import (
    ProductionContextV1,
    SignedManualArmRequestV1,
    _verify_owner_signed_arm,
)
from .production_risk import ProductionLiveRiskPublisher, ProductionLiveRiskStageReceiptV1
from .production_runtime import ProductionExecutionRuntime


class ProductionPathError(PermissionError):
    """The composed path failed closed; partial evidence must not be renewed."""


def _check_entry_interlock(interlock: Callable[[], bool] | None) -> None:
    """Additional cancellation interlock, never a replacement for authority."""
    if interlock is None:
        return
    try:
        result = interlock()
        if inspect.isawaitable(result):
            if inspect.iscoroutine(result):
                result.close()
            raise ValueError
        if result is not True:
            raise ValueError
    except Exception:
        raise ProductionPathError("entry was cancelled or its execution interlock closed") from None


class PreparedExitEvidenceProvider(Protocol):
    """Capture raw evidence only; never call back into the locked lifecycle FSM."""

    source_id: str

    async def capture_prepared_exit(
        self, *, context: ProductionContextV1, effect_id: str, now: datetime
    ) -> object: ...


def _time(clock: Callable[[], datetime], after: datetime | None = None) -> datetime:
    now = clock()
    if (
        not isinstance(now, datetime)
        or now.tzinfo is None
        or now.utcoffset() != timedelta(0)
        or (after is not None and now < after)
    ):
        raise ProductionPathError("production clock is not monotone explicit UTC")
    return now


async def _inspect_staged(
    runtime: ProductionExecutionRuntime,
    binding: ProductionLifecycleBindingV1,
    *,
    clock: Callable[[], datetime],
    started_at: datetime,
    valid_until: datetime,
) -> None:
    before = _time(clock, started_at)
    if not before < min(valid_until, binding.request.expires_at):
        raise ProductionPathError("staged evidence expired before independent authorization")
    inspected = await runtime.inspect_authority(binding.request)
    after = _time(clock, before)
    if (
        inspected.request_id != binding.request.request_id
        or inspected.decision_id != binding.risk_decision_id
        or inspected.effect_id != binding.signing_effect_id
        or not after < min(valid_until, binding.request.expires_at, inspected.valid_until)
    ):
        raise ProductionPathError("independent authorization scope changed or evidence expired")


class ProductionPreparedExitRiskStager:
    """Called only by the FSM's newly-created PREPARED exit boundary.

    The durable journal's atomic ``created`` guard owns cross-process admission.
    A crash/unknown PREPARED is recovery-only, never a fresh staging opportunity.
    The local attempt set additionally prevents direct retries on this instance;
    it is not a signing claim or substitute for the durable journal.
    """

    def __init__(
        self,
        *,
        publisher: ProductionLiveExitRiskPublisher,
        runtime: ProductionExecutionRuntime,
        evidence_provider: PreparedExitEvidenceProvider,
        clock: Callable[[], datetime],
    ) -> None:
        if not isinstance(publisher, ProductionLiveExitRiskPublisher) or not isinstance(
            runtime, ProductionExecutionRuntime
        ):
            raise TypeError("concrete independent exit Risk publisher and runtime are required")
        if (
            publisher.context != runtime.context
            or publisher.custody_binding != runtime.binding
            or publisher.database_uuid != runtime.database_uuid
            or publisher.policy_namespace != runtime.state_source.policy_namespace
            or publisher.risk_writer.expected_database != runtime.state_source.expected_database
            or publisher.lifecycle_bindings.expected_role != runtime.state_source.runtime_role
            or getattr(evidence_provider, "source_id", None) != publisher.verifier.source_id
            or not callable(getattr(evidence_provider, "capture_prepared_exit", None))
            or not callable(clock)
            or runtime._clock is not clock
        ):
            raise ValueError("exit source, database, custody, or policy scope differs")
        self.publisher = publisher
        self.runtime = runtime
        self.evidence_provider = evidence_provider
        self.clock = clock
        self._attempted: set[str] = set()

    async def stage(self, effect_id: str) -> ProductionExitRiskStageReceiptV1:
        if effect_id in self._attempted:
            raise ProductionPathError("exit staging attempt already exists; authoritative recovery required")
        # Mark before the first await. Unknown source/writes are not retryable.
        self._attempted.add(effect_id)
        started = _time(self.clock)
        await self.publisher._load_exact_prepared(effect_id)
        if await self.publisher.lifecycle_bindings.get(effect_id) is not None:
            raise ProductionPathError("exit binding already exists; it cannot be renewed")
        before_capture = _time(self.clock, started)
        try:
            async with asyncio.timeout(5):
                raw = await self.evidence_provider.capture_prepared_exit(
                    context=self.publisher.context, effect_id=effect_id, now=before_capture
                )
        except Exception:
            raise ProductionPathError(
                "exit evidence capture failed or is unresolved; authoritative recovery required"
            ) from None
        now = _time(self.clock, before_capture)
        receipt = await self.publisher.stage_prepared_exit(
            effect_id=effect_id, raw_evidence=raw, now=now, expires_at=now + timedelta(seconds=5)
        )
        binding = receipt.lifecycle_binding
        if binding.lifecycle_effect_id != effect_id or binding.role == "ENTRY":
            raise ProductionPathError("staged exit differs from the exact PREPARED effect")
        await _inspect_staged(
            self.runtime,
            binding,
            clock=self.clock,
            started_at=now,
            valid_until=min(receipt.risk_geometry.valid_until, receipt.exposure.valid_until),
        )
        return receipt


@dataclass(frozen=True, slots=True)
class ProductionLiveEntryResult:
    risk_stage: ProductionLiveRiskStageReceiptV1
    execution_result: PaperExecutionResult


class ProductionLiveLifecycleCoordinator:
    """Single raw-proof entry API using actual Risk and the protected PROD FSM."""

    def __init__(self, *, engine: ProductionLifecycleEngine, entry_risk: ProductionLiveRiskPublisher):
        if not isinstance(engine, ProductionLifecycleEngine) or not isinstance(
            entry_risk, ProductionLiveRiskPublisher
        ):
            raise TypeError("concrete PROD lifecycle and independent LIVE Risk publisher are required")
        exit_risk = engine.prepared_exit_risk
        runtime = engine.production_runtime
        if (
            not isinstance(exit_risk, ProductionPreparedExitRiskStager)
            or exit_risk.runtime is not runtime
            or exit_risk.publisher.risk_writer is not entry_risk.risk_writer
            or exit_risk.publisher.lifecycle_bindings is not entry_risk.lifecycle_bindings
            or entry_risk.lifecycle_bindings is not engine.adapter.bindings
            or entry_risk.context != runtime.context
            or entry_risk.custody_binding != runtime.binding
            or entry_risk.database_uuid != runtime.database_uuid
            or entry_risk.policy_namespace != runtime.state_source.policy_namespace
            or entry_risk.scope.strategy_revision != engine.production_settings.strategy_revision
            or exit_risk.clock is not engine.clock
        ):
            raise ValueError("unified LIVE path requires exact shared Risk/FSM/runtime/exit resources")
        self.engine = engine
        self.entry_risk = entry_risk
        self.runtime = runtime

    async def admit_and_handle_entry(
        self,
        *,
        raw_account_evidence: object,
        raw_inputs_evidence: object,
        source_id: str,
        review: CandidateReviewV1,
        venue: VenueQualityV1,
        allocation: StrategicAllocation | None,
        owner_arm: SignedManualArmRequestV1,
        expires_at: datetime,
        system_mode: SystemMode,
        entry_interlock: Callable[[], bool] | None = None,
    ) -> ProductionLiveEntryResult:
        now = _time(self.engine.clock)
        _check_entry_interlock(entry_interlock)
        auth = self.runtime.authorization
        try:
            _, owner_digest = _verify_owner_signed_arm(
                owner_arm,
                auth._preconditions,
                owner_key=auth._owner_key,
                expected_owner_key_sha256=auth._owner_key_sha256,
                expected_owner_identity=auth._owner,
                now=now,
                maximum_lifetime=auth._arm_lifetime,
            )
        except Exception:
            raise ProductionPathError("owner signature/scope is invalid for this entry") from None
        receipt = await self.entry_risk.evaluate_and_stage_entry(
            raw_account_evidence=raw_account_evidence,
            raw_inputs_evidence=raw_inputs_evidence,
            source_id=source_id,
            review=review,
            venue=venue,
            allocation=allocation,
            manual_request_sha256=owner_digest,
            expires_at=expires_at,
            now=now,
            system_mode=system_mode,
        )
        _check_entry_interlock(entry_interlock)
        await _inspect_staged(
            self.runtime,
            receipt.lifecycle_binding,
            clock=self.engine.clock,
            started_at=now,
            valid_until=receipt.risk_geometry.valid_until,
        )
        _check_entry_interlock(entry_interlock)
        # handle owns its own account/trade locks. Never reacquire them here.
        result = await self.engine.handle(receipt.evaluation.decision)
        return ProductionLiveEntryResult(risk_stage=receipt, execution_result=result)

    async def initialize_recovery(self) -> tuple[str, ...]:
        return await self.engine.initialize_recovery()

    async def reconcile_once(self) -> list[Any]:
        return await self.engine.reconcile_once()

    async def reconcile_closed_account(self, **kwargs: Any) -> dict[str, Any]:
        return await self.engine.reconcile_closed_account(**kwargs)
