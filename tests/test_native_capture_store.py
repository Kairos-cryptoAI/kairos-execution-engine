"""Real owner-only filesystem storage; explicit offline records/fault fixtures."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import stat
import subprocess

import pytest
from kairos_core.contracts import canonical_json_bytes

pytest.importorskip("kairos_llm.call_evidence", reason="requires genuine optional native-inputs extra")

from kairos_llm.call_evidence import CreateOnlyDirectorySink  # noqa: E402

from kairos_execution.production_native_capture_store import (  # noqa: E402
    NativeCaptureConflictError,
    NativeCapturePartialError,
    NativeCapturePersistenceError,
    NativeCaptureSessionReader,
    NativeCaptureSessionSink,
)
from kairos_execution.production_native_inputs import read_native_budgeted_call  # noqa: E402

ID = "a" * 32
BODY = b'{"version":"synthetic-offline-native-observation.v1","captured_at_ms":50}'


def test_actual_owner_only_storage_records_original_fsync_ack_and_exact_replay(tmp_path, monkeypatch):
    clock_values = iter((100, 110))
    calls = []

    def clock():
        calls.append("clock")
        return next(clock_values)

    sink = NativeCaptureSessionSink(tmp_path / "new-native-session", clock_ms=clock)
    assert type(sink._storage) is CreateOnlyDirectorySink
    original_write = sink._storage.create_only

    def write(identity, slot, record):
        original_write(identity, slot, record)  # Genuine owner-only creation and fsync.
        calls.append(slot + "-fsynced")

    monkeypatch.setattr(sink._storage, "create_only", write)
    assert sink.create_only(ID, BODY) is None
    assert calls == ["clock", "started-fsynced", "clock", "completed-fsynced"]
    result = sink.reader.read(ID)
    assert result.record == BODY
    assert result.witness.acknowledged_at_ms == 110
    assert result.witness.record_sha256 == hashlib.sha256(BODY).hexdigest()
    assert result.witness.record_bytes == len(BODY)
    assert result.witness.purpose == "LOCAL_RECORD_FSYNC_ACK_ONLY"
    assert not hasattr(result.witness, "source_timestamp_ms")
    original_file_times = {path.name: path.stat().st_mtime_ns for path in sink.directory.iterdir()}
    sink.create_only(ID, BODY)  # Exhausted clock proves replay does not refresh or re-write.
    assert calls == ["clock", "started-fsynced", "clock", "completed-fsynced"]
    assert sink.reader.read(ID) == result
    assert original_file_times == {path.name: path.stat().st_mtime_ns for path in sink.directory.iterdir()}
    assert sink.reader.observation_ids() == (ID,)
    if os.name != "nt":
        assert stat.S_IMODE(sink.directory.stat().st_mode) == 0o700
        assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in sink.directory.iterdir())


def test_restart_is_read_only_and_new_writer_refuses_existing_session(tmp_path):
    directory = tmp_path / "native-session"
    sink = NativeCaptureSessionSink(directory, clock_ms=lambda: 100)
    sink.create_only(ID, BODY)
    first = sink.reader.read(ID)
    del sink
    reader = NativeCaptureSessionReader(directory)
    assert reader.read(ID) == first
    assert reader.observation_ids() == (ID,)
    assert not hasattr(reader, "create_only")
    with pytest.raises(FileExistsError):
        NativeCaptureSessionSink(directory)
    with pytest.raises(KeyError):
        reader.read("b" * 32)


@pytest.mark.skipif(os.name != "nt", reason="read-only Windows DACL inspection; POSIX modes checked above")
def test_existing_primitive_really_creates_protected_owner_only_windows_acls(tmp_path):
    sink = NativeCaptureSessionSink(tmp_path / "protected-native-session", clock_ms=lambda: 100)
    sink.create_only(ID, BODY)
    # Read the real primitive's DACLs; no ACL creation/manipulation is duplicated.
    paths = (sink.directory, *sink.directory.iterdir())
    targets = ",".join("'" + str(path).replace("'", "''") + "'" for path in paths)
    script = (
        f"@({targets}) | ForEach-Object {{ "
        "$acl = Get-Acl -LiteralPath $_; $rules = @($acl.Access); "
        "[pscustomobject]@{ Protected = $acl.AreAccessRulesProtected; Count = $rules.Count; "
        "Sid = $rules[0].IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value; "
        "Rights = [string]$rules[0].FileSystemRights; Type = [string]$rules[0].AccessControlType } "
        "} | ConvertTo-Json -Compress"
    )
    output = subprocess.run(
        [
            shutil.which("pwsh.exe") or "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            base64.b64encode(script.encode("utf-16-le")).decode("ascii"),
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    assert output.stdout.strip(), output.stderr
    records = json.loads(output.stdout)
    assert len(records) == 3
    assert all(
        record == {"Protected": True, "Count": 1, "Sid": "S-1-3-4", "Rights": "FullControl", "Type": "Allow"}
        for record in records
    )


def test_different_bytes_conflict_without_rewriting_original_pair(tmp_path):
    sink = NativeCaptureSessionSink(tmp_path / "native-session", clock_ms=lambda: 100)
    sink.create_only(ID, BODY)
    before = sink.reader.read(ID)
    with pytest.raises(NativeCaptureConflictError):
        sink.create_only(ID, BODY + b" ")
    assert sink.reader.read(ID) == before


@pytest.mark.parametrize("partial_witness", [False, True])
def test_witness_failure_retains_source_and_partial_is_never_repaired(tmp_path, monkeypatch, partial_witness):
    values = iter((100, 110))
    sink = NativeCaptureSessionSink(tmp_path / "native-session", clock_ms=lambda: next(values))
    original_write = sink._storage.create_only

    def write(identity, slot, record):
        if slot == "completed":
            if partial_witness:
                original_write(identity, slot, b"{")
            raise OSError("synthetic witness storage failure")
        original_write(identity, slot, record)

    monkeypatch.setattr(sink._storage, "create_only", write)
    with pytest.raises(OSError):
        sink.create_only(ID, BODY)
    assert (sink.directory / f"{ID}.started.json").read_bytes() == BODY
    before = {path.name: path.read_bytes() for path in sink.directory.iterdir()}
    with pytest.raises(NativeCapturePartialError):
        sink.create_only(ID, BODY)
    reader = NativeCaptureSessionReader(sink.directory)
    assert reader.observation_ids() == (ID,)
    with pytest.raises(NativeCapturePartialError):
        reader.read(ID)
    assert before == {path.name: path.read_bytes() for path in sink.directory.iterdir()}


def test_source_write_failure_has_no_ack_and_unknown_local_attempt_is_not_retried(tmp_path, monkeypatch):
    sink = NativeCaptureSessionSink(tmp_path / "native-session", clock_ms=lambda: 100)
    writes = []

    def write(*args):
        writes.append(args)
        raise OSError("synthetic original record failure")

    monkeypatch.setattr(sink._storage, "create_only", write)
    with pytest.raises(OSError):
        sink.create_only(ID, BODY)
    with pytest.raises(NativeCapturePartialError, match="unresolved"):
        sink.create_only(ID, BODY)
    assert len(writes) == 1
    assert list(sink.directory.iterdir()) == []


def test_backward_post_fsync_clock_preserves_raw_record_without_inventing_witness(tmp_path):
    values = iter((100, 99))
    sink = NativeCaptureSessionSink(tmp_path / "native-session", clock_ms=lambda: next(values))
    with pytest.raises(NativeCapturePersistenceError, match="backwards"):
        sink.create_only(ID, BODY)
    assert (sink.directory / f"{ID}.started.json").read_bytes() == BODY
    assert not (sink.directory / f"{ID}.completed.json").exists()
    with pytest.raises(NativeCapturePartialError):
        sink.create_only(ID, BODY)


@pytest.mark.parametrize("value", [True, -1, 2**63, 100.5, None])
def test_invalid_clock_cannot_become_an_acknowledgement(tmp_path, value):
    sink = NativeCaptureSessionSink(tmp_path / "native-session", clock_ms=lambda: value)
    with pytest.raises(NativeCapturePersistenceError):
        sink.create_only(ID, BODY)
    assert list(sink.directory.iterdir()) == []


def test_async_clock_and_async_persistence_are_refused_synchronously(tmp_path, monkeypatch):
    async def clock():
        return 100

    sink = NativeCaptureSessionSink(tmp_path / "async-clock-session", clock_ms=clock)
    with pytest.raises(NativeCapturePersistenceError, match="asynchronous"):
        sink.create_only(ID, BODY)

    sink2 = NativeCaptureSessionSink(tmp_path / "async-writer-session", clock_ms=lambda: 100)

    async def writer(*_args):
        return None

    monkeypatch.setattr(sink2._storage, "create_only", writer)
    with pytest.raises(NativeCapturePersistenceError, match="synchronously"):
        sink2.create_only(ID, BODY)
    assert list(sink2.directory.iterdir()) == []


def test_storage_witness_is_not_semantic_model_completion_or_source_authority(tmp_path):
    sink = NativeCaptureSessionSink(tmp_path / "native-session", clock_ms=lambda: 100)
    semantic_model_started = canonical_json_bytes(
        {
            "version": "kairos.llm-application-call-evidence.v1",
            "phase": "ATTEMPT_STARTED",
            "call_id": "b" * 32,
        }
    )
    sink.create_only(ID, semantic_model_started)
    result = sink.reader.read(ID)
    assert result.record == semantic_model_started
    assert result.witness.observation_id == ID
    assert result.witness.version != "kairos.llm-application-call-evidence.v1"
    with pytest.raises(ValueError):
        read_native_budgeted_call(result.record, result.witness_bytes)


def test_retained_pair_tampering_or_foreign_witness_is_detected(tmp_path):
    sink = NativeCaptureSessionSink(tmp_path / "native-session", clock_ms=lambda: 100)
    sink.create_only(ID, BODY)
    # Explicit fault injection only: use the actual primitive to produce a raw
    # observation with a foreign witness under a fresh identity, never overwrite.
    foreign_id = "b" * 32
    sink._storage.create_only(foreign_id, "started", BODY)
    sink._storage.create_only(foreign_id, "completed", sink.reader.read(ID).witness_bytes)
    with pytest.raises(NativeCaptureConflictError):
        NativeCaptureSessionReader(sink.directory).read(foreign_id)


@pytest.mark.parametrize("identity", ["", "../escape", "A" * 32, "a" * 31])
def test_storage_identity_is_bounded_and_cannot_escape_session(tmp_path, identity):
    sink = NativeCaptureSessionSink(tmp_path / "native-session")
    with pytest.raises(NativeCapturePersistenceError):
        sink.create_only(identity, BODY)
    assert list(sink.directory.iterdir()) == []
