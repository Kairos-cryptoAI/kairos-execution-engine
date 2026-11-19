"""Read-only WS/REST observation coordinator; never a LIVE account verifier.

The current PROD runtime has no private WS adapter. This module will not open
a socket or create a session; a future adapter must deliver actual channel
acknowledgements and publications through the explicit stream interface.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from typing import Literal, Protocol

from .production_reads import ProductionEvedexReads, ProductionReadUnavailable

CHANNELS = frozenset({"account", "funding", "transfer", "position", "order", "fill", "fee", "tpsl"})
MAX_PUBLICATION_BYTES = 1_000_000
MAX_CAPTURE_BYTES = 4_000_000


class WsRestObservationError(PermissionError):
    """Capture discarded; the reason contains no private payload."""


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _reject_constant(_value):
    raise ValueError("nonfinite JSON number")


def _finite_float(value):
    parsed = Decimal(value)
    if not parsed.is_finite() or abs(parsed) > Decimal(str(sys.float_info.max)):
        raise ValueError("unrepresentable JSON number")
    return parsed


def _consume_task(task):
    # A broken transport can ignore cancellation and finish later. Consume
    # its outcome without logging an external exception or private payload.
    try:
        task.exception()
    except BaseException:
        pass


async def _safe_external_call(operation, *, message, timeout_seconds):
    """Bound an external call and suppress its exception text and traceback.

    Python cannot forcibly terminate a coroutine that ignores cancellation.
    Such a task is detached with its outcome consumed; no successful result
    or cleanup guarantee is claimed for that transport.
    """

    async def invoke():
        return await operation()

    task = asyncio.create_task(invoke())
    task.add_done_callback(_consume_task)
    failed = False
    try:
        done, _ = await asyncio.wait({task}, timeout=timeout_seconds)
        if not done:
            task.cancel()
            failed = True
        else:
            try:
                return task.result()
            except asyncio.CancelledError:
                failed = True
            except Exception:
                failed = True
    except asyncio.CancelledError:
        task.cancel()
        done, _ = await asyncio.wait({task}, timeout=0.25)
        if not done:
            raise WsRestObservationError(
                "private external operation did not stop after cancellation"
            ) from None
        raise
    if not failed:
        raise RuntimeError("unreachable external call state")
    # Raise outside the except block so the external exception is not retained
    # as an implicit context even when logging inspects exception chains.
    raise WsRestObservationError(message) from None


class _SafeStreamContext:
    """Close the external stream but never allow it to suppress our errors."""

    def __init__(self, stream, *, timeout_seconds):
        self.stream = stream
        self.timeout_seconds = timeout_seconds

    async def __aenter__(self):
        await _safe_external_call(
            lambda: self.stream.__aenter__(),
            message="private WS stream could not start",
            timeout_seconds=self.timeout_seconds,
        )
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await _safe_external_call(
            lambda: self.stream.__aexit__(exc_type, exc, tb),
            message="private WS stream could not close",
            timeout_seconds=0.5,
        )
        # The transport does not get to suppress a gap, cancellation, or error.
        return False


@dataclass(frozen=True, slots=True)
class WsFrame:
    kind: Literal["SUBSCRIBED", "PUBLICATION", "DISCONNECTED", "RECOVERY_FAILED"]
    channel: str | None = None
    # Provider channel positions are optional. A missing position is UNKNOWN;
    # local arrival numbers are never a replacement for a provider cursor.
    epoch: str | None = None
    offset: int | None = None
    payload_json: str | None = field(default=None, repr=False)


class PrivateWsStream(Protocol):
    """Already configured, read-only transport; implementation is not provided."""

    def __aenter__(self) -> object: ...
    def __aexit__(self, exc_type: object, exc: object, tb: object) -> object: ...
    async def receive(self) -> WsFrame: ...


@dataclass(frozen=True, slots=True)
class ObservedSubscription:
    channel: str
    received_at: datetime
    received_monotonic_ns: int


@dataclass(frozen=True, slots=True)
class ObservedWsPublication:
    channel: str
    local_sequence: int
    received_at: datetime
    received_monotonic_ns: int
    epoch: str | None
    offset: int | None
    payload_json: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class WsRestObservation:
    started_at: datetime
    snapshot_started_at: datetime
    snapshot_finished_at: datetime
    finished_at: datetime
    started_monotonic_ns: int
    snapshot_started_monotonic_ns: int
    snapshot_finished_monotonic_ns: int
    finished_monotonic_ns: int
    # Raw account information is retained in memory only. Do not log/store this
    # object without suitable private storage and retention controls.
    snapshot: dict = field(repr=False)
    publications: tuple[ObservedWsPublication, ...] = field(repr=False)
    subscribed_channels: frozenset[str]
    acknowledgements: tuple[ObservedSubscription, ...]
    authoritative_reconciliation: Literal[False] = False
    sequence_continuity_proven: Literal[False] = False
    history_complete: None = None
    fees_final: None = None
    trading_authority: Literal[False] = False


async def capture_ws_rest_observation(
    reads: ProductionEvedexReads,
    stream: PrivateWsStream | AbstractAsyncContextManager,
    *,
    timeout_seconds: float = 30.0,
    after_snapshot_seconds: float = 0.25,
    max_publications: int = 1000,
) -> WsRestObservation:
    """Capture acknowledged subscriptions, real reader snapshot, then updates.

    All eight channel acknowledgements must arrive first. Explicit disconnect,
    failed recovery, offset gap, epoch change, malformed records, overflow or
    timeout discards the observation. Provider semantics are not yet qualified,
    so absence of these symptoms never proves a gap-free or atomic snapshot.
    """
    if type(reads) is not ProductionEvedexReads or not reads._preflight_complete:
        raise ProductionReadUnavailable("preflighted exact PROD reader required")
    # The concrete EVEDEX WS adapter must use this very reader/account; a
    # subscription on a different token scope cannot bracket this snapshot.
    from .evedex_private_ws import EvedexPrivateWsStream

    if type(stream) is EvedexPrivateWsStream:
        stream.require_reader(reads)
    try:
        receive = getattr(stream, "receive", None)
    except Exception:
        receive = None
    if not callable(receive):
        raise ValueError("a read-only private WS stream is required")
    if type(timeout_seconds) not in (int, float) or not 0 < timeout_seconds <= 30:
        raise ValueError("observation timeout must be positive and at most 30 seconds")
    if type(after_snapshot_seconds) not in (int, float) or not 0 <= after_snapshot_seconds <= 2:
        raise ValueError("post-snapshot observation must be between zero and two seconds")
    if type(max_publications) is not int or not 1 <= max_publications <= 1000:
        raise ValueError("publication budget must be an integer from 1 to 1000")

    started_at = datetime.now(UTC)
    started_monotonic = time.monotonic_ns()
    previous_at, previous_monotonic = started_at, started_monotonic

    def tick() -> tuple[datetime, int]:
        nonlocal previous_at, previous_monotonic
        current_at = datetime.now(UTC)
        current_monotonic = time.monotonic_ns()
        if current_at < previous_at or current_monotonic < previous_monotonic:
            raise WsRestObservationError("local observation clock moved backwards")
        previous_at, previous_monotonic = current_at, current_monotonic
        return current_at, current_monotonic

    subscribed: set[str] = set()
    acknowledgements: list[ObservedSubscription] = []
    publications: list[ObservedWsPublication] = []
    positions: dict[str, tuple[str, int]] = {}
    retained_bytes = 0
    ready_or_failed = asyncio.Event()
    failure: WsRestObservationError | None = None

    async def pump() -> None:
        nonlocal retained_bytes, failure
        try:
            while True:
                frame = await _safe_external_call(
                    receive, message="private WS reader failed", timeout_seconds=timeout_seconds
                )
                if type(frame) is not WsFrame:
                    raise WsRestObservationError("malformed private WS frame")
                if frame.kind in {"DISCONNECTED", "RECOVERY_FAILED"}:
                    raise WsRestObservationError("private WS disconnected or recovery failed")
                if frame.channel not in CHANNELS:
                    raise WsRestObservationError("unknown private WS channel")
                if frame.kind == "SUBSCRIBED":
                    if (
                        frame.channel in subscribed
                        or frame.payload_json is not None
                        or frame.epoch is not None
                        or frame.offset is not None
                    ):
                        raise WsRestObservationError("duplicate or malformed channel acknowledgement")
                    subscribed.add(frame.channel)
                    received_at, monotonic_now = tick()
                    acknowledgements.append(
                        ObservedSubscription(
                            channel=frame.channel,
                            received_at=received_at,
                            received_monotonic_ns=monotonic_now,
                        )
                    )
                    if subscribed == CHANNELS:
                        ready_or_failed.set()
                    continue
                if frame.kind != "PUBLICATION" or frame.channel not in subscribed:
                    raise WsRestObservationError("publication arrived without channel acknowledgement")
                if (frame.epoch is None) != (frame.offset is None):
                    raise WsRestObservationError("partial provider position is unusable")
                if frame.epoch is not None:
                    if (
                        not isinstance(frame.epoch, str)
                        or not frame.epoch
                        or len(frame.epoch) > 256
                        or type(frame.offset) is not int
                        or frame.offset < 0
                    ):
                        raise WsRestObservationError("provider position is malformed")
                    previous = positions.get(frame.channel)
                    if previous is not None and (
                        previous[0] != frame.epoch or frame.offset != previous[1] + 1
                    ):
                        raise WsRestObservationError(
                            "provider epoch changed or offset discontinuity observed"
                        )
                    positions[frame.channel] = (frame.epoch, frame.offset)
                if not isinstance(frame.payload_json, str):
                    raise WsRestObservationError("private WS publication is malformed")
                encoded_size = len(frame.payload_json.encode("utf-8"))
                retained_bytes += encoded_size
                if (
                    encoded_size > MAX_PUBLICATION_BYTES
                    or retained_bytes > MAX_CAPTURE_BYTES
                    or len(publications) >= max_publications
                ):
                    raise WsRestObservationError("private WS capture exceeded its buffer budget")
                try:
                    json.loads(
                        frame.payload_json,
                        parse_constant=_reject_constant,
                        parse_float=_finite_float,
                        object_pairs_hook=_unique_object,
                    )
                except (TypeError, ValueError):
                    raise WsRestObservationError("private WS publication JSON is malformed") from None
                received_at, current_mono = tick()
                publications.append(
                    ObservedWsPublication(
                        channel=frame.channel,
                        local_sequence=len(publications) + 1,
                        received_at=received_at,
                        received_monotonic_ns=current_mono,
                        epoch=frame.epoch,
                        offset=frame.offset,
                        payload_json=frame.payload_json,
                    )
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            failure = (
                exc
                if isinstance(exc, WsRestObservationError)
                else WsRestObservationError("private WS reader failed")
            )
            ready_or_failed.set()

    def ensure_open() -> None:
        if type(stream) is EvedexPrivateWsStream:
            stream.require_reader(reads)
        if failure is not None:
            raise failure
        if subscribed != CHANNELS:
            raise WsRestObservationError("private WS subscription acknowledgements are incomplete")

    try:
        async with asyncio.timeout(timeout_seconds):
            async with _SafeStreamContext(stream, timeout_seconds=timeout_seconds):
                task = asyncio.create_task(pump())
                try:
                    await ready_or_failed.wait()
                    ensure_open()
                    snapshot_started, snapshot_started_monotonic = tick()
                    snapshot = await _safe_external_call(
                        reads.fetch_paper_state,
                        message="private account snapshot failed",
                        timeout_seconds=timeout_seconds,
                    )
                    snapshot_finished, snapshot_finished_monotonic = tick()
                    ensure_open()
                    if after_snapshot_seconds:
                        await asyncio.sleep(after_snapshot_seconds)
                    ensure_open()
                    finished, finished_monotonic = tick()
                    if (
                        not started_at <= snapshot_started <= snapshot_finished <= finished
                        or not started_monotonic
                        <= snapshot_started_monotonic
                        <= snapshot_finished_monotonic
                        <= finished_monotonic
                        or any(
                            not started_at <= ack.received_at <= snapshot_started for ack in acknowledgements
                        )
                        or any(not started_at <= item.received_at <= finished for item in publications)
                    ):
                        raise WsRestObservationError("local UTC clock moved backwards")
                    return WsRestObservation(
                        started_at=started_at,
                        snapshot_started_at=snapshot_started,
                        snapshot_finished_at=snapshot_finished,
                        finished_at=finished,
                        started_monotonic_ns=started_monotonic,
                        snapshot_started_monotonic_ns=snapshot_started_monotonic,
                        snapshot_finished_monotonic_ns=snapshot_finished_monotonic,
                        finished_monotonic_ns=finished_monotonic,
                        snapshot=snapshot,
                        publications=tuple(publications),
                        subscribed_channels=frozenset(subscribed),
                        acknowledgements=tuple(acknowledgements),
                    )
                finally:
                    task.cancel()
                    _, pending = await asyncio.wait({task}, timeout=0.5)
                    if pending:
                        raise WsRestObservationError("private WS reader did not stop after cancellation")
                    if failure is not None:
                        raise failure
    except TimeoutError:
        raise WsRestObservationError("WS/REST observation timed out; discarded") from None
