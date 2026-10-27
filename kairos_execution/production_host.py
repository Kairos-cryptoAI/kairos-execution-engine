"""Opt-in supervisor for one already-composed, manually armed PROD session.

This host does not build resources, discover evidence, run native producers, or
grant readiness. Callers supply the exact assembly, proof references, owner arm,
and narrowly scoped input/evidence providers. Every uncertain attempt is latched
and requires authoritative external recovery rather than an automatic retry.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

from kairos_persistence import TradeState

from .production_assembly import (
    ProductionAssembly,
    ProductionAssemblyResources,
    build_production_assembly,
)
from .production_path import ProductionLiveEntryRefusal, ProductionLiveEntryResult
from .production_readiness import ReceiptReferenceV1, SignedManualArmRequestV1, canonical_digest
from .production_service import ProductionEntryEnvelope, ProductionServiceDriver


class ProductionHostError(RuntimeError):
    """Sanitized host failure; an unresolved attempt cannot be retried here."""


EntryProvider = Callable[[], Awaitable[ProductionEntryEnvelope]]
TerminalEvidenceProvider = Callable[[str, str], Awaitable[object]]


@dataclass(frozen=True, slots=True)
class PendingTerminalEvidence:
    """Read-only not-ready result; never accepted as venue evidence or authority."""

    trade_id: str
    source_id: str
    observed_at: datetime
    status: Literal["PENDING"] = "PENDING"

    def __post_init__(self) -> None:
        if (
            not isinstance(self.trade_id, str)
            or not self.trade_id
            or not isinstance(self.source_id, str)
            or not self.source_id
            or not isinstance(self.observed_at, datetime)
            or self.observed_at.tzinfo is None
            or self.observed_at.utcoffset() != UTC.utcoffset(self.observed_at)
            or self.status != "PENDING"
        ):
            raise ValueError("pending terminal evidence must be bound, explicit UTC, and non-authorizing")


@dataclass(frozen=True, slots=True)
class ProductionHostStatus:
    started: bool = False
    start_attempted: bool = False
    recovery_complete: bool = False
    entries_blocked: bool = True
    admission_attempted: bool = False
    cleanup_unresolved: bool = False
    supervisor_failure: str | None = None
    entry_worker_running: bool = False
    lifecycle_worker_running: bool = False
    owned_trade_id: str | None = None
    terminal_evidence_pending: bool = False
    terminal_accounting_accepted: bool = False
    readiness: Literal[False] = False


class ProductionHost:
    """Supervise a single assembly/arm and at most one original native entry.

    ``entry_provider`` must return an already-qualified immutable native
    envelope. It is never asked to synthesize or project an entry from an
    unqualified composer result. The service driver remains the owner of the
    account lock, lifecycle maintenance and terminal accounting.
    """

    def __init__(
        self,
        assembly: ProductionAssembly,
        *,
        entry_provider: EntryProvider,
        terminal_evidence_provider: TerminalEvidenceProvider,
        terminal_source_id: str,
        terminal_poll_interval_s: float = 2.0,
        terminal_wait_timeout_s: float = 600.0,
        shutdown_timeout_s: float = 6.0,
    ) -> None:
        if type(assembly) is not ProductionAssembly:
            raise TypeError("the exact typed ProductionAssembly is required")
        if not callable(entry_provider) or not callable(terminal_evidence_provider):
            raise TypeError("explicit original-entry and terminal-evidence providers are required")
        if (
            not isinstance(terminal_source_id, str)
            or not terminal_source_id
            or terminal_source_id not in assembly.reconciler.source_verifiers
        ):
            raise ValueError("terminal evidence source must be registered with this exact assembly")
        if (
            isinstance(shutdown_timeout_s, bool)
            or not isinstance(shutdown_timeout_s, (int, float))
            or not 0 < shutdown_timeout_s <= 10
        ):
            raise ValueError("host shutdown bound must be finite and no greater than ten seconds")
        if (
            isinstance(terminal_poll_interval_s, bool)
            or not isinstance(terminal_poll_interval_s, (int, float))
            or not 2 <= terminal_poll_interval_s <= 30
            or isinstance(terminal_wait_timeout_s, bool)
            or not isinstance(terminal_wait_timeout_s, (int, float))
            or not 2 <= terminal_wait_timeout_s <= 600
        ):
            raise ValueError("terminal polling needs a finite 2-30s cadence and a 2-600s bound")
        self.assembly = assembly
        self._entry_provider = entry_provider
        self._terminal_evidence_provider = terminal_evidence_provider
        self._terminal_source_id = terminal_source_id
        self._terminal_poll_interval_s = float(terminal_poll_interval_s)
        self._terminal_wait_timeout_s = float(terminal_wait_timeout_s)
        self._shutdown_timeout_s = float(shutdown_timeout_s)
        self._start_attempted = False
        self._admission_attempted = False
        self._arm_digest: str | None = None
        self._driver: ProductionServiceDriver | None = None
        self._started = False
        self._closing = False
        self._cleanup_unresolved = False
        self._supervisor_failure: str | None = None
        self._reconcile_lock = asyncio.Lock()
        self._owned_trade_id: str | None = None
        self._terminal_accounting_accepted = False
        self._terminal_attempted = False
        self._terminal_provider_failed = False
        self._terminal_wait_started: float | None = None
        self._terminal_next_poll: float | None = None

    @property
    def status(self) -> ProductionHostStatus:
        driver_status = self._driver.status if self._driver is not None else None
        return ProductionHostStatus(
            started=self._started and bool(driver_status and driver_status.started),
            start_attempted=self._start_attempted,
            recovery_complete=bool(driver_status and driver_status.recovery_complete),
            entries_blocked=(
                True
                if driver_status is None or self._supervisor_failure is not None or self._closing
                else driver_status.entries_blocked or not driver_status.recovery_complete
            ),
            admission_attempted=self._admission_attempted,
            cleanup_unresolved=self._cleanup_unresolved
            or bool(driver_status and driver_status.cleanup_unresolved),
            supervisor_failure=self._supervisor_failure,
            entry_worker_running=bool(driver_status and driver_status.entry_worker_running),
            lifecycle_worker_running=bool(driver_status and driver_status.lifecycle_worker_running),
            owned_trade_id=self._owned_trade_id,
            terminal_evidence_pending=self._terminal_wait_started is not None
            and not self._terminal_accounting_accepted
            and not self._terminal_provider_failed,
            terminal_accounting_accepted=self._terminal_accounting_accepted,
        )

    async def start(
        self,
        *,
        references: Sequence[ReceiptReferenceV1],
        owner_arm: SignedManualArmRequestV1,
    ) -> ProductionHostStatus:
        """Consume exactly one proof/arm start attempt; never retry on failure."""
        if self._start_attempted:
            raise ProductionHostError("host start already attempted; no replacement arm or driver is allowed")
        self._start_attempted = True
        try:
            arm = SignedManualArmRequestV1.model_validate_json(owner_arm.model_dump_json())
            self._arm_digest = canonical_digest(arm)
            driver = await self.assembly.start_technical_canary(
                references=references,
                owner_arm=arm,
            )
            if type(driver) is not ProductionServiceDriver:
                raise ProductionHostError("assembly returned an unexpected driver; start is unresolved")
            if not driver.status.started:
                raise ProductionHostError("production driver did not start; start is unresolved")
            self._driver = driver
            self._started = True
            return self.status
        except asyncio.CancelledError:
            self._supervisor_failure = "START_CANCELLED_UNKNOWN"
            raise
        except Exception:
            self._supervisor_failure = "START_REFUSED_OR_UNKNOWN"
            raise ProductionHostError("manual production start was refused or is unresolved") from None

    async def submit_one(self) -> ProductionLiveEntryResult | ProductionLiveEntryRefusal:
        """Request and submit one exact-arm envelope, with no retry or promotion."""
        if self._admission_attempted:
            raise ProductionHostError("the single host admission was already attempted")
        self._admission_attempted = True
        driver = self._require_driver()
        if self._closing:
            raise ProductionHostError("host is closing")
        runtime_status = driver.check_health()
        if not runtime_status.entry_worker_running or not runtime_status.lifecycle_worker_running:
            self._supervisor_failure = "DRIVER_BACKGROUND_TASK_EXITED"
            driver.block_new_entries("HOST_DRIVER_HEALTH_LOST")
            raise ProductionHostError("production driver task health does not permit entry")
        if (
            not runtime_status.started
            or not runtime_status.recovery_complete
            or runtime_status.entries_blocked
        ):
            raise ProductionHostError("runtime recovery/status does not permit the one entry")
        if self._arm_digest is None:
            raise ProductionHostError("the host has no bound manual owner arm")
        try:
            async with asyncio.timeout(10):
                envelope = await self._entry_provider()
            if type(envelope) is not ProductionEntryEnvelope:
                raise ProductionHostError("entry provider did not return an exact native envelope")
            if canonical_digest(envelope.owner_arm) != self._arm_digest:
                driver.block_new_entries("HOST_ENTRY_ARM_MISMATCH")
                raise ProductionHostError("entry envelope differs from the exact host owner arm")
            if envelope.expires_at <= driver.coordinator.engine.clock():
                driver.block_new_entries("HOST_ENTRY_ENVELOPE_EXPIRED")
                raise ProductionHostError("original entry envelope expired before admission")
            result = await self.assembly.submit_entry(envelope)
            if type(result) is ProductionLiveEntryRefusal:
                return result
            if type(result) is not ProductionLiveEntryResult:
                driver.block_new_entries("HOST_ENTRY_RESULT_UNEXPECTED")
                raise ProductionHostError("production driver returned an unexpected entry result")
            trade_id = result.risk_stage.lifecycle_binding.trade_id
            if not isinstance(trade_id, str) or not trade_id:
                driver.block_new_entries("HOST_ENTRY_TRADE_BINDING_MISSING")
                raise ProductionHostError("accepted entry result has no exact durable trade binding")
            self._owned_trade_id = trade_id
            return result
        except asyncio.CancelledError:
            self._supervisor_failure = "ENTRY_CANCELLED_UNKNOWN"
            driver.block_new_entries("HOST_ENTRY_OUTCOME_UNKNOWN")
            raise
        except Exception:
            self._supervisor_failure = "ENTRY_REFUSED_OR_UNKNOWN"
            driver.block_new_entries("HOST_ENTRY_OUTCOME_UNKNOWN")
            raise ProductionHostError("one-entry attempt was refused or is unresolved") from None

    async def reconcile_owned_if_closed(self) -> bool:
        """Poll one owned FLAT trade until final evidence is available or bounded expiry.

        A pending result is an explicitly read-only provider response and does
        not consume the one reconciliation attempt. Any provider failure or
        final-proof/accounting ambiguity is latched and never retried.
        """
        self._require_driver()
        if self._closing:
            raise ProductionHostError("host is closing")
        trade_id = self._owned_trade_id
        source_id = self._terminal_source_id
        if trade_id is None:
            return False
        async with self._reconcile_lock:
            if self._terminal_accounting_accepted:
                return True
            if self._terminal_attempted or self._terminal_provider_failed:
                return False
            try:
                monotonic_now = asyncio.get_running_loop().time()
                if self._terminal_next_poll is not None and monotonic_now < self._terminal_next_poll:
                    return False
                trades = self.assembly.engine.trades
                if trades is not self.assembly.coordinator.engine.trades:
                    raise ProductionHostError("host trade repository differs from the exact lifecycle engine")
                trade = await trades.get(trade_id)
                if trade is None or trade.trade_id != trade_id:
                    raise ProductionHostError("owned durable trade is missing or mismatched")
                if trade.state is not TradeState.FLAT:
                    self._terminal_next_poll = monotonic_now + self._terminal_poll_interval_s
                    return False
                if self._terminal_wait_started is None:
                    self._terminal_wait_started = monotonic_now
                    self._terminal_next_poll = monotonic_now
                if monotonic_now - self._terminal_wait_started >= self._terminal_wait_timeout_s:
                    self._terminal_provider_failed = True
                    self._supervisor_failure = "TERMINAL_EVIDENCE_PENDING_TIMEOUT"
                    self._require_driver().block_new_entries("HOST_TERMINAL_EVIDENCE_TIMEOUT")
                    return False
                if self._terminal_next_poll is not None and monotonic_now < self._terminal_next_poll:
                    return False
                try:
                    async with asyncio.timeout(10):
                        evidence = await self._terminal_evidence_provider(trade_id, source_id)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    self._terminal_provider_failed = True
                    self._supervisor_failure = "TERMINAL_EVIDENCE_PROVIDER_FAILED"
                    self._require_driver().block_new_entries("HOST_TERMINAL_PROVIDER_FAILED")
                    raise ProductionHostError(
                        "terminal evidence provider failed; no retry is allowed"
                    ) from None
                if type(evidence) is PendingTerminalEvidence:
                    if evidence.trade_id != trade_id or evidence.source_id != source_id:
                        raise ProductionHostError(
                            "pending terminal result differs from the owned trade/source"
                        )
                    now = self.assembly.engine.clock()
                    if (
                        not isinstance(now, datetime)
                        or now.tzinfo is None
                        or now.utcoffset() != UTC.utcoffset(now)
                        or evidence.observed_at > now
                    ):
                        raise ProductionHostError(
                            "pending terminal result has an invalid UTC observation time"
                        )
                    self._terminal_next_poll = monotonic_now + self._terminal_poll_interval_s
                    return False
                # Once any final evidence is returned, accounting is an exact
                # one-shot operation. Unknown results never permit a new proof.
                self._terminal_attempted = True
                result = await self.assembly.reconcile_closed_account(
                    trade_id=trade_id,
                    source_id=source_id,
                    raw_venue_evidence=evidence,
                )
                if result.get("reservation_released") is not True or not isinstance(
                    result.get("accounting_receipt"), dict
                ):
                    raise ProductionHostError("terminal evidence lacks accepted accounting receipt")
                self._terminal_accounting_accepted = True
                return True
            except asyncio.CancelledError:
                self._supervisor_failure = "TERMINAL_RECONCILIATION_CANCELLED_UNKNOWN"
                self._terminal_provider_failed = True
                self._require_driver().block_new_entries("HOST_TERMINAL_ACCOUNTING_UNKNOWN")
                raise
            except Exception as exc:
                self._supervisor_failure = "TERMINAL_RECONCILIATION_REFUSED_OR_UNKNOWN"
                self._terminal_provider_failed = True
                self._require_driver().block_new_entries("HOST_TERMINAL_RECONCILIATION_UNKNOWN")
                if isinstance(exc, ProductionHostError):
                    raise
                raise ProductionHostError(
                    "terminal reconciliation/accounting was refused or unresolved"
                ) from None

    async def reconcile_closed_account(self) -> bool:
        """Explicitly poll the same owned-trade path used automatically by ``run``."""
        return await self.reconcile_owned_if_closed()

    def _require_driver(self) -> ProductionServiceDriver:
        driver = self._driver
        if type(driver) is not ProductionServiceDriver or not driver.status.started:
            raise ProductionHostError("the one-shot manually armed production driver is not running")
        return driver

    async def run(self, *, stop: asyncio.Event) -> None:
        """Supervise actual driver tasks and perform bounded driver shutdown once."""
        if not isinstance(stop, asyncio.Event):
            raise TypeError("an asyncio.Event stop signal is required")
        driver = self._require_driver()
        if self._closing:
            raise ProductionHostError("host shutdown already started")
        try:
            status = driver.check_health()
            if not status.entry_worker_running or not status.lifecycle_worker_running:
                self._supervisor_failure = "DRIVER_TASKS_MISSING"
                driver.block_new_entries("HOST_DRIVER_HEALTH_LOST")
                await stop.wait()
            while not stop.is_set():
                try:
                    await self.reconcile_owned_if_closed()
                except ProductionHostError:
                    # The host has latched new entries closed. Keep remaining
                    # lifecycle maintenance alive until the operator stops it.
                    pass
                if stop.is_set():
                    break
                try:
                    await asyncio.wait_for(stop.wait(), timeout=0.25)
                except TimeoutError:
                    status = driver.check_health()
                    if not status.entry_worker_running or not status.lifecycle_worker_running:
                        self._supervisor_failure = "DRIVER_BACKGROUND_TASK_EXITED"
                        driver.block_new_entries("HOST_DRIVER_HEALTH_LOST")
                        # Keep any surviving protective maintenance task alive
                        # until the operator explicitly stops this host.
                        await stop.wait()
        finally:
            self._closing = True
            stop.set()
            try:
                async with asyncio.timeout(self._shutdown_timeout_s):
                    await self.assembly.run(stop=stop)
            except asyncio.CancelledError:
                self._cleanup_unresolved = True
                self._supervisor_failure = self._supervisor_failure or "SHUTDOWN_CANCELLED_UNKNOWN"
                raise
            except Exception:
                self._cleanup_unresolved = True
                self._supervisor_failure = self._supervisor_failure or "SHUTDOWN_UNRESOLVED"
                raise
            finally:
                self._started = False


def build_production_host(
    resources: ProductionAssemblyResources,
    *,
    entry_provider: EntryProvider,
    terminal_evidence_provider: TerminalEvidenceProvider,
    terminal_source_id: str,
    terminal_poll_interval_s: float = 2.0,
    terminal_wait_timeout_s: float = 600.0,
    shutdown_timeout_s: float = 6.0,
) -> ProductionHost:
    """Build the single canonical composed graph without startup or I/O.

    The returned host owns the exact Risk, lifecycle, runtime, reconciliation,
    and accounting graph created from the supplied already-provisioned resources.
    Explicit proof/arm start remains a separate one-shot operator action.
    """
    assembly = build_production_assembly(resources)
    return ProductionHost(
        assembly,
        entry_provider=entry_provider,
        terminal_evidence_provider=terminal_evidence_provider,
        terminal_source_id=terminal_source_id,
        terminal_poll_interval_s=terminal_poll_interval_s,
        terminal_wait_timeout_s=terminal_wait_timeout_s,
        shutdown_timeout_s=shutdown_timeout_s,
    )


__all__ = [
    "PendingTerminalEvidence",
    "ProductionHost",
    "ProductionHostError",
    "ProductionHostStatus",
    "build_production_host",
]
