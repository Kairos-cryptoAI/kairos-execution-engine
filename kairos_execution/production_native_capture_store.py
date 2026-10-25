"""Create-only native observations and durable local persistence witnesses.

Reuses the existing owner-only ``kairos_llm.call_evidence`` storage primitive;
there is no second ACL implementation, key, producer registration or activation.
Each session directory MUST be new. A restart may read the retained pairs but
never append to, adopt or repair that old session. Durable analytical/provider
claims remain separate and continue fencing unknown attempts across sessions.

The existing physical ``started`` suffix holds opaque original observation
bytes; ``completed`` holds the DISTINCT native persistence-witness version below.
Those are storage slots, NOT semantic LLM call phases. An LLM started/completed
record can itself occupy either observation's raw slot without being relabelled.
"""

from __future__ import annotations

import hashlib
import inspect
import os
import re
import stat
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

from kairos_core.contracts import canonical_json_bytes
from pydantic import Field

from .production_readiness import StrictRecord

_OBSERVATION_ID = re.compile(r"^[a-f0-9]{32}$")
_MAX_RECORD_BYTES = 4_000_000
_MAX_WITNESS_BYTES = 4_096
_MAX_SESSION_OBSERVATIONS = 10_000


class NativeCapturePersistenceError(ValueError):
    """A local observation cannot be acknowledged as durably retained."""


class NativeCapturePartialError(NativeCapturePersistenceError):
    """Retained partial/unknown evidence must not acquire a new witness clock."""


class NativeCaptureConflictError(NativeCapturePersistenceError):
    """One immutable observation identity names different bytes."""


def _clock_ms() -> int:
    return time.time_ns() // 1_000_000


def _identifier(value: str) -> str:
    if not isinstance(value, str) or _OBSERVATION_ID.fullmatch(value) is None:
        raise NativeCapturePersistenceError(
            "native observation ID must be exactly 32 lowercase hex characters"
        )
    return value


def _storage_class() -> Any:
    # Native dependencies remain optional for normal Execution imports.
    from kairos_llm import call_evidence  # type: ignore[import-not-found,import-untyped]

    return call_evidence.CreateOnlyDirectorySink


class NativeCapturePersistenceWitnessV1(StrictRecord):
    """Original record fsync acknowledgement, not source/provider authority.

    The timestamp is sampled AFTER the raw record's synchronous fsync returns.
    The witness is then independently fsynced before the sink acknowledges its
    caller. Thus this is a lower bound on the final sink-return time, never a
    manufactured source observation or a refreshed source/model timestamp.
    """

    version: Literal["kairos.native-capture-persistence-witness.v1"] = (
        "kairos.native-capture-persistence-witness.v1"
    )
    purpose: Literal["LOCAL_RECORD_FSYNC_ACK_ONLY"] = "LOCAL_RECORD_FSYNC_ACK_ONLY"
    storage_layout: Literal["OPAQUE_STARTED_RAW_COMPLETED_NATIVE_WITNESS"] = (
        "OPAQUE_STARTED_RAW_COMPLETED_NATIVE_WITNESS"
    )
    observation_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    record_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    record_bytes: int = Field(ge=1, le=_MAX_RECORD_BYTES, strict=True)
    acknowledged_at_ms: int = Field(ge=0, lt=2**63, strict=True)


@dataclass(frozen=True, slots=True)
class NativeCaptureStoredObservation:
    record: bytes
    witness: NativeCapturePersistenceWitnessV1
    witness_bytes: bytes


class NativeCaptureSessionReader:
    """Read-only restart inspection; cannot reopen a writer or repair a pair.

    Reuses the primitive's reparse/identity checks and additionally bounds and
    checks regular, singly linked files around each read. A valid pair proves
    retained local bytes and their witness only, not independent producer trust.
    """

    def __init__(self, directory: str | os.PathLike[str]) -> None:
        self.directory = Path(directory).absolute()
        self._primitive = _storage_class()
        self._primitive._reject_reparse_ancestors(self.directory)
        self._directory_identity = self._primitive._identity(self.directory)

    def _check_directory(self) -> None:
        self._primitive._reject_reparse_ancestors(self.directory)
        if self._primitive._identity(self.directory) != self._directory_identity:
            raise NativeCapturePersistenceError("native session directory identity changed")

    def _paths(self, observation_id: str) -> tuple[Path, Path]:
        identity = _identifier(observation_id)
        return self.directory / f"{identity}.started.json", self.directory / f"{identity}.completed.json"

    def _read_file(self, path: Path, maximum: int) -> bytes:
        self._check_directory()
        self._primitive._reject_reparse_ancestors(path)
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or self._primitive._is_reparse(before)
            or before.st_nlink != 1
            or not 0 < before.st_size <= maximum
        ):
            raise NativeCapturePersistenceError("native session artifact is not a bounded singly linked file")
        with path.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            data = handle.read(maximum + 1)
            after_read = os.fstat(handle.fileno())
        after_path = path.lstat()
        self._check_directory()
        identities = {
            (entry.st_dev, entry.st_ino, entry.st_size, entry.st_nlink)
            for entry in (before, opened, after_read, after_path)
        }
        if len(identities) != 1 or len(data) != before.st_size:
            raise NativeCapturePersistenceError("native session artifact changed while it was read")
        return data

    def read(self, observation_id: str) -> NativeCaptureStoredObservation:
        raw_path, witness_path = self._paths(observation_id)
        self._check_directory()
        present = (raw_path.exists(), witness_path.exists())
        if present == (False, False):
            raise KeyError(observation_id)
        if present != (True, True):
            raise NativeCapturePartialError(
                "partial native observation retained; no new persistence clock allowed"
            )
        try:
            raw = self._read_file(raw_path, _MAX_RECORD_BYTES)
            witness_raw = self._read_file(witness_path, _MAX_WITNESS_BYTES)
            witness = NativeCapturePersistenceWitnessV1.model_validate_json(witness_raw)
        except (OSError, ValueError) as exc:
            raise NativeCapturePartialError("invalid or partial native pair retained without repair") from exc
        if (
            canonical_json_bytes(witness) != witness_raw
            or witness.observation_id != observation_id
            or witness.record_bytes != len(raw)
            or witness.record_sha256 != hashlib.sha256(raw).hexdigest()
        ):
            raise NativeCaptureConflictError(
                "native persistence witness does not bind the exact original record"
            )
        return NativeCaptureStoredObservation(raw, witness, witness_raw)

    def observation_ids(self) -> tuple[str, ...]:
        """Bounded inventory includes partial identities so they cannot disappear."""
        self._check_directory()
        identities: set[str] = set()
        for index, path in enumerate(self.directory.iterdir()):
            if index >= _MAX_SESSION_OBSERVATIONS * 2:
                raise NativeCapturePersistenceError("native capture session exceeds its bounded inventory")
            match = re.fullmatch(r"([a-f0-9]{32})\.(started|completed)\.json", path.name)
            if match is None:
                raise NativeCapturePersistenceError(
                    "native session has an unexpected artifact; no adoption allowed"
                )
            identities.add(match.group(1))
        self._check_directory()
        return tuple(sorted(identities))


class NativeCaptureSessionSink:
    """New-session-only two-argument sink, using the existing owner-only writer.

    Exact completed replay never calls the clock or writes another byte. If
    source write succeeds but witness write fails, all retained files stay in
    place and a replay refuses; a capture timestamp is never substituted for
    the missing fsync acknowledgement. There is no automatic cleanup/recovery.
    """

    def __init__(
        self,
        directory: str | os.PathLike[str],
        *,
        clock_ms: Callable[[], int] = _clock_ms,
    ) -> None:
        if not callable(clock_ms):
            raise TypeError("an explicit synchronous local persistence clock is required")
        self._storage = _storage_class()(directory)
        self.directory = self._storage.directory
        self.reader = NativeCaptureSessionReader(self.directory)
        self._clock = clock_ms
        self._last_clock: int | None = None
        self._attempted: set[str] = set()
        self._lock = threading.Lock()

    def _time(self) -> int:
        value: object = self._clock()
        if inspect.iscoroutine(value):
            value.close()
        if (
            type(value) is not int
            or not 0 <= value < 2**63
            or (self._last_clock is not None and value < self._last_clock)
        ):
            raise NativeCapturePersistenceError(
                "native persistence clock is asynchronous, invalid or backwards"
            )
        self._last_clock = value
        return value

    def _write(self, observation_id: str, slot: str, record: bytes) -> None:
        writer = cast(Callable[..., object], self._storage.create_only)
        result = writer(observation_id, slot, record)
        if inspect.iscoroutine(result):
            result.close()
        if result is not None:
            raise NativeCapturePersistenceError("native storage did not synchronously acknowledge fsync")

    def create_only(self, observation_id: str, record: bytes) -> None:
        identity = _identifier(observation_id)
        if not isinstance(record, bytes) or not 0 < len(record) <= _MAX_RECORD_BYTES:
            raise NativeCapturePersistenceError(
                "bounded immutable original native observation bytes are required"
            )
        with self._lock:
            try:
                existing = self.reader.read(identity)
            except KeyError:
                existing = None
            if existing is not None:
                if existing.record != record:
                    raise NativeCaptureConflictError(
                        "native observation ID already names different original bytes"
                    )
                return
            if identity in self._attempted:
                raise NativeCapturePartialError("native persistence attempt is unresolved; no blind retry")
            if len(self._attempted) >= _MAX_SESSION_OBSERVATIONS:
                raise NativeCapturePersistenceError(
                    "native capture session reached its bounded observation limit"
                )
            self._attempted.add(identity)
            self._time()
            self._write(identity, "started", record)
            acknowledged_at = self._time()  # AFTER original record fsync, before witness fsync.
            witness = NativeCapturePersistenceWitnessV1(
                observation_id=identity,
                record_sha256=hashlib.sha256(record).hexdigest(),
                record_bytes=len(record),
                acknowledged_at_ms=acknowledged_at,
            )
            self._write(identity, "completed", canonical_json_bytes(witness))
            retained = self.reader.read(identity)
            if retained.record != record or retained.witness != witness:
                raise NativeCaptureConflictError(
                    "native persisted pair differs after synchronous acknowledgement"
                )


__all__ = [
    "NativeCaptureSessionSink",
    "NativeCaptureSessionReader",
    "NativeCaptureStoredObservation",
    "NativeCapturePersistenceWitnessV1",
    "NativeCapturePersistenceError",
    "NativeCapturePartialError",
    "NativeCaptureConflictError",
]
