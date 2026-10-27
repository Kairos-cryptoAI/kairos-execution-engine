"""Explicit single-account lifecycle driver; never a LIVE authority issuer.

The default rejects entries. An admission callback is an additional deployment
interlock, not evidence. Independent source/owner/operator/Risk checks remain in
the concrete coordinator. Envelope IDs fence only this process; existing durable
decision/effect/signing claims own restart idempotency.
"""

from __future__ import annotations

import asyncio
import inspect
import math
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from kairos_core.contracts import CandidateReviewV1, StrategicAllocation, VenueQualityV1
from kairos_core.enums import SystemMode

from .production_path import (
    ProductionLiveEntryRefusal,
    ProductionLiveEntryResult,
    ProductionLiveLifecycleCoordinator,
)
from .production_readiness import SignedManualArmRequestV1, canonical_digest


class ProductionServiceError(RuntimeError):
    """Sanitized failure; unknown effects must not be retried blindly."""


@dataclass(frozen=True, slots=True)
class ProductionEntryEnvelope:
    envelope_id: str
    raw_account_evidence: object
    raw_inputs_evidence: object
    source_id: str
    review: CandidateReviewV1
    venue: VenueQualityV1
    allocation: StrategicAllocation | None
    owner_arm: SignedManualArmRequestV1
    expires_at: datetime
    system_mode: SystemMode

    def __post_init__(self) -> None:
        for value in (self.envelope_id, self.source_id):
            if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", value) is None:
                raise ValueError("entry envelope identities must be bounded normalized identifiers")
        if (
            not isinstance(self.expires_at, datetime)
            or self.expires_at.tzinfo is None
            or self.expires_at.utcoffset() != UTC.utcoffset(self.expires_at)
            or not isinstance(self.system_mode, SystemMode)
        ):
            raise ValueError("entry envelope requires an original explicit UTC deadline and native mode")


@dataclass(frozen=True, slots=True)
class ProductionServiceStatus:
    started: bool
    recovery_complete: bool
    recovery_blockers: tuple[str, ...]
    entries_blocked: bool
    entry_policy: Literal["REJECT_ALL", "EXTERNAL_ADMISSION_REQUIRED"]
    cleanup_unresolved: bool
    readiness: Literal[False] = False
    entry_worker_running: bool = False
    lifecycle_worker_running: bool = False
    closing: bool = False


@dataclass(slots=True)
class _QueuedEntry:
    envelope: ProductionEntryEnvelope
    result: asyncio.Future[ProductionLiveEntryResult | ProductionLiveEntryRefusal]


def _bounded_seconds(value: float, *, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("service time bounds must be finite positive numbers")
    if not math.isfinite(value) or not 0 < value <= maximum:
        raise ValueError("service time bounds exceed the finite service contract")
    return float(value)


class ProductionServiceDriver:
    """Recover before entry and serialize one account without renewing proofs.

    Maintenance while service-local admission is closed delegates to the FSM.
    It never bypasses the FSM's own recovery-blocked state: that condition needs
    authoritative recovery and may prevent protective effects. No automatic
    recovery retry, state reset or readiness promotion is provided here.
    """

    def __init__(
        self,
        coordinator: ProductionLiveLifecycleCoordinator,
        *,
        entry_admission: Callable[[], bool] | None = None,
        queue_capacity: int = 8,
        operation_timeout_s: float = 10.0,
        reconciliation_interval_s: float = 2.0,
        maximum_admissions: int = 10_000,
        shutdown_timeout_s: float = 5.0,
        bound_owner_arm_sha256: str | None = None,
    ) -> None:
        if not isinstance(coordinator, ProductionLiveLifecycleCoordinator):
            raise TypeError("an explicitly composed production lifecycle coordinator is required")
        if type(queue_capacity) is not int or not 1 <= queue_capacity <= 128:
            raise ValueError("entry queue capacity must be an integer from one to 128")
        if type(maximum_admissions) is not int or not 1 <= maximum_admissions <= 100_000:
            raise ValueError("finite process admission capacity is required")
        if entry_admission is not None and not callable(entry_admission):
            raise TypeError("entry admission must be a synchronous deployment interlock")
        if bound_owner_arm_sha256 is not None and (
            not isinstance(bound_owner_arm_sha256, str)
            or re.fullmatch(r"[a-f0-9]{64}", bound_owner_arm_sha256) is None
        ):
            raise ValueError("a bound owner arm must be an exact SHA-256 digest")
        self.coordinator = coordinator
        self._entry_admission = entry_admission
        self._queue: asyncio.Queue[_QueuedEntry] = asyncio.Queue(maxsize=queue_capacity)
        self._operation_timeout_s = _bounded_seconds(operation_timeout_s, maximum=30)
        self._reconciliation_interval_s = _bounded_seconds(reconciliation_interval_s, maximum=60)
        self._shutdown_timeout_s = _bounded_seconds(shutdown_timeout_s, maximum=5)
        self._maximum_admissions = maximum_admissions
        self._bound_owner_arm_sha256 = bound_owner_arm_sha256
        self._account_lock = asyncio.Lock()
        self._worker_task: asyncio.Task[None] | None = None
        self._lifecycle_task: asyncio.Task[None] | None = None
        self._started = False
        self._closing = False
        self._recovery_complete = False
        self._recovery_blockers: tuple[str, ...] = ("STARTUP_RECOVERY_REQUIRED",)
        self._entries_blocked = True
        self._cleanup_unresolved = False
        self._seen_envelope_ids: set[str] = set()

    @property
    def status(self) -> ProductionServiceStatus:
        return ProductionServiceStatus(
            started=self._started,
            recovery_complete=self._recovery_complete,
            recovery_blockers=self._recovery_blockers,
            entries_blocked=self._entries_blocked,
            entry_policy="REJECT_ALL" if self._entries_blocked else "EXTERNAL_ADMISSION_REQUIRED",
            cleanup_unresolved=self._cleanup_unresolved,
            entry_worker_running=self._worker_task is not None and not self._worker_task.done(),
            lifecycle_worker_running=self._lifecycle_task is not None and not self._lifecycle_task.done(),
            closing=self._closing,
        )

    def block_new_entries(self, reason_code: str) -> ProductionServiceStatus:
        """One-way host interlock; never stop protective maintenance or rearm.

        Only bounded public reason codes are accepted. Raw exception or source
        payloads do not belong in service status. Closing admission cannot make
        an unknown operation safe, cancel an existing position or release risk.
        """
        if not isinstance(reason_code, str) or re.fullmatch(r"[A-Z][A-Z0-9_]{0,95}", reason_code) is None:
            raise ValueError("a bounded public uppercase reason code is required")
        self._unknown(reason_code)
        return self.status

    def check_health(self) -> ProductionServiceStatus:
        """Latch new entries closed if a background worker has disappeared.

        A `started` flag alone is not proof that execution maintenance is alive.
        This check never replaces a task or retries recovery and deliberately
        leaves any surviving protective maintenance running.
        """
        current = self.status
        if (
            current.started
            and not current.closing
            and (not current.entry_worker_running or not current.lifecycle_worker_running)
        ):
            self._unknown("SERVICE_BACKGROUND_WORKER_STOPPED")
        return self.status

    def _unknown(self, reason: str) -> None:
        self._entries_blocked = True
        self._recovery_complete = False
        self._recovery_blockers = (reason,)

    async def start(self) -> ProductionServiceStatus:
        if self._started or self._closing:
            raise ProductionServiceError("service cannot be started in its current state")
        self._started = True
        try:
            async with asyncio.timeout(self._operation_timeout_s), self._account_lock:
                blockers = await self.coordinator.initialize_recovery()
            self._recovery_complete = not blockers
            self._recovery_blockers = () if not blockers else ("AUTHORITATIVE_RECOVERY_BLOCKED",)
            self._entries_blocked = bool(blockers) or self._entry_admission is None
        except asyncio.CancelledError:
            self._unknown("STARTUP_RECOVERY_CANCELLED")
            self._started = False
            self._closing = True
            raise
        except Exception:
            self._unknown("STARTUP_RECOVERY_UNRESOLVED")
        self._worker_task = asyncio.create_task(self._entry_worker(), name="production-entry-driver")
        self._lifecycle_task = asyncio.create_task(
            self._lifecycle_loop(), name="production-lifecycle-maintenance"
        )
        return self.status

    async def submit(
        self, envelope: ProductionEntryEnvelope
    ) -> ProductionLiveEntryResult | ProductionLiveEntryRefusal:
        if not isinstance(envelope, ProductionEntryEnvelope):
            raise TypeError("the exact production entry envelope is required")
        if not self._started or self._closing or self._entries_blocked:
            raise ProductionServiceError("entries are blocked; recovery and admission are required")
        if envelope.envelope_id in self._seen_envelope_ids:
            raise ProductionServiceError("entry envelope identity was already seen in this process")
        if len(self._seen_envelope_ids) >= self._maximum_admissions:
            self._entries_blocked = True
            raise ProductionServiceError("process admission capacity exhausted; no identities are evicted")
        self._seen_envelope_ids.add(envelope.envelope_id)
        future: asyncio.Future[ProductionLiveEntryResult | ProductionLiveEntryRefusal] = (
            asyncio.get_running_loop().create_future()
        )
        try:
            self._queue.put_nowait(_QueuedEntry(envelope, future))
        except asyncio.QueueFull:
            raise ProductionServiceError("entry queue is full; refused identity remains fenced") from None
        try:
            async with asyncio.timeout(self._operation_timeout_s):
                return await future
        except TimeoutError:
            self._unknown("ENTRY_OUTCOME_TIMEOUT")
            if self._worker_task is not None:
                self._worker_task.cancel()
            raise ProductionServiceError("entry outcome unknown; authoritative recovery required") from None
        except asyncio.CancelledError:
            self._unknown("ENTRY_OUTCOME_CANCELLED")
            if self._worker_task is not None:
                self._worker_task.cancel()
            raise

    def _admitted(self, item: _QueuedEntry) -> bool:
        # Under the account lock, immediately before the coordinator.
        if item.result.done() or self._closing or self._entries_blocked:
            return False
        if self.coordinator.engine.recovery_blocked:
            self._unknown("AUTHORITATIVE_RECOVERY_BLOCKED")
            return False
        if self._entry_admission is None:
            self._entries_blocked = True
            return False
        allowed = self._entry_admission()
        if inspect.isawaitable(allowed):
            if inspect.iscoroutine(allowed):
                allowed.close()
            raise ProductionServiceError("entry admission must be synchronous and exactly true")
        if allowed is not True:
            self._entries_blocked = True
            return False
        return True

    async def _entry_worker(self) -> None:
        while True:
            item = await self._queue.get()
            try:
                if item.result.done():
                    continue
                try:
                    async with asyncio.timeout(self._operation_timeout_s), self._account_lock:
                        if not self._admitted(item):
                            raise ProductionServiceError("entry admission is blocked or cancelled")
                        if self._bound_owner_arm_sha256 is not None and (
                            not isinstance(item.envelope.owner_arm, SignedManualArmRequestV1)
                            or canonical_digest(item.envelope.owner_arm) != self._bound_owner_arm_sha256
                        ):
                            raise ProductionServiceError("entry differs from the session's exact owner arm")
                        now = self.coordinator.engine.clock()
                        if (
                            not isinstance(now, datetime)
                            or now.tzinfo is None
                            or now.utcoffset() != UTC.utcoffset(now)
                            or now >= item.envelope.expires_at
                        ):
                            raise ProductionServiceError("original entry envelope deadline expired")

                        def entry_interlock(queued: _QueuedEntry = item) -> bool:
                            return (
                                not queued.result.done() and not self._closing and not self._entries_blocked
                            )

                        result = await self.coordinator.admit_and_handle_entry(
                            raw_account_evidence=item.envelope.raw_account_evidence,
                            raw_inputs_evidence=item.envelope.raw_inputs_evidence,
                            source_id=item.envelope.source_id,
                            review=item.envelope.review,
                            venue=item.envelope.venue,
                            allocation=item.envelope.allocation,
                            owner_arm=item.envelope.owner_arm,
                            expires_at=item.envelope.expires_at,
                            system_mode=item.envelope.system_mode,
                            entry_interlock=entry_interlock,
                        )
                        if (
                            isinstance(result, ProductionLiveEntryRefusal)
                            and type(self.coordinator) is not ProductionLiveLifecycleCoordinator
                        ):
                            raise ProductionServiceError("unreviewed coordinator cannot attest no effects")
                except asyncio.CancelledError:
                    self._unknown("ENTRY_WORKER_CANCELLED")
                    if not item.result.done():
                        item.result.set_exception(
                            ProductionServiceError("entry outcome unknown; recovery required")
                        )
                    raise
                except Exception:
                    self._unknown("ENTRY_PROCESSING_UNRESOLVED")
                    if not item.result.done():
                        item.result.set_exception(
                            ProductionServiceError("entry outcome unresolved; recovery required")
                        )
                else:
                    if not item.result.done():
                        item.result.set_result(result)
            finally:
                self._queue.task_done()

    async def reconcile_once(self) -> list[Any]:
        if not self._started or self._closing:
            raise ProductionServiceError("service is not running")
        try:
            async with asyncio.timeout(self._operation_timeout_s), self._account_lock:
                result = await self.coordinator.reconcile_once()
                if self.coordinator.engine.recovery_blocked:
                    self._unknown("AUTHORITATIVE_RECOVERY_BLOCKED")
                return result
        except asyncio.CancelledError:
            self._unknown("MAINTENANCE_CANCELLED")
            raise
        except Exception:
            self._unknown("MAINTENANCE_UNRESOLVED")
            raise ProductionServiceError("lifecycle maintenance unresolved") from None

    async def _lifecycle_loop(self) -> None:
        while True:
            try:
                await self.reconcile_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                self._unknown("MAINTENANCE_UNRESOLVED")
            await asyncio.sleep(self._reconciliation_interval_s)

    async def reconcile_closed_account(self, **kwargs: Any) -> dict[str, Any]:
        if not self._started or self._closing:
            raise ProductionServiceError("service is not running")
        try:
            async with asyncio.timeout(self._operation_timeout_s), self._account_lock:
                return await self.coordinator.reconcile_closed_account(**kwargs)
        except asyncio.CancelledError:
            self._unknown("CLOSED_RECONCILIATION_CANCELLED")
            raise
        except Exception:
            self._unknown("CLOSED_RECONCILIATION_UNRESOLVED")
            raise ProductionServiceError("closed-account reconciliation unresolved") from None

    async def close(self) -> None:
        self._closing = True
        self._entries_blocked = True
        tasks = [task for task in (self._worker_task, self._lifecycle_task) if task is not None]
        for task in tasks:
            task.cancel()
        if tasks:
            done, pending = await asyncio.wait(tasks, timeout=self._shutdown_timeout_s)
            for task in done:
                if not task.cancelled():
                    task.exception()  # Retrieve failures without logging payloads.
            if pending:
                self._cleanup_unresolved = True
                self._unknown("SHUTDOWN_UNRESOLVED")
                raise ProductionServiceError("shutdown unresolved; do not replace this process or resources")
        while not self._queue.empty():
            item = self._queue.get_nowait()
            if not item.result.done():
                item.result.set_exception(
                    ProductionServiceError("service stopped before envelope processing")
                )
            self._queue.task_done()
        self._cleanup_unresolved = False
        self._started = False

    async def run(self, stop: asyncio.Event) -> None:
        try:
            await self.start()
            await stop.wait()
        finally:
            await self.close()
