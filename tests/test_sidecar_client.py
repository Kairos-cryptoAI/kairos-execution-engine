"""Offline tests for the no-retry NDJSON child-process boundary."""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path
from typing import Any

import pytest

from kairos_execution.sidecar import (
    EvedexSidecarClient,
    SidecarError,
    SidecarMutationError,
)

_FAKE_SIDECAR = r"""
import { createInterface } from "node:readline";

const input = createInterface({ input: process.stdin, terminal: false });
input.on("line", (line) => {
  const request = JSON.parse(line);
  if (request.operation === "hang") return;
  if (request.operation === "malformed_result") {
    process.stdout.write(JSON.stringify({ id: request.id, ok: true, result: 7 }) + "\n");
    return;
  }
  if (request.operation === "reject") {
    process.stdout.write(JSON.stringify({
      id: request.id,
      ok: false,
      error: { message: "venue rejected mutation" },
    }) + "\n");
    return;
  }
  const effect = request.operation === "wrong_effect"
    ? "different-effect"
    : (request.payload.effect_id ?? null);
  process.stdout.write(JSON.stringify({
    id: request.id,
    ok: true,
    result: { accepted: true },
    effect_id: effect,
  }) + "\n");
});
"""


def _node_runtime() -> Path:
    executable = shutil.which("node")
    if executable is None:
        pytest.skip("Node.js is required for the sidecar client contract tests")
    return Path(executable).resolve(strict=True)


class _FakeVersionProcess:
    def __init__(self, stdout: bytes, *, returncode: int = 0) -> None:
        self._stdout = stdout
        self.returncode = returncode

    async def communicate(self) -> tuple[bytes, None]:
        return self._stdout, None


def _client(
    tmp_path: Path,
    *,
    timeout_s: float = 1.0,
    bypass_node_version: bool = True,
) -> EvedexSidecarClient:
    script = tmp_path / "fake-sidecar.mjs"
    script.write_text(_FAKE_SIDECAR, encoding="utf-8")
    client = EvedexSidecarClient(
        node_executable=_node_runtime(),
        script=script,
        api_key_file=tmp_path / "api.secret",
        private_key_file=tmp_path / "signing.secret",
        expected_account_id="paper-account",
        timeout_s=timeout_s,
    )
    if bypass_node_version:

        async def supported_node(_executable: str) -> None:
            return None

        client._assert_supported_node = supported_node  # type: ignore[method-assign]
    return client


@pytest.mark.asyncio
async def test_mutation_effect_identity_is_verified(tmp_path: Path) -> None:
    client = _client(tmp_path)
    try:
        result = await client.call(
            "echo",
            {"effect_id": "effect-1"},
            mutation=True,
        )
        assert result == {"data": {"accepted": True}, "effect_id": "effect-1"}

        with pytest.raises(SidecarMutationError, match="mismatched effect identity"):
            await client.call(
                "wrong_effect",
                {"effect_id": "effect-2"},
                mutation=True,
            )
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_mutation_rejection_is_returned_without_wrapper_retry(tmp_path: Path) -> None:
    client = _client(tmp_path)
    calls = 0
    original_start = client.start

    async def counted_start() -> None:
        nonlocal calls
        calls += 1
        await original_start()

    client.start = counted_start  # type: ignore[method-assign]
    try:
        with pytest.raises(SidecarMutationError, match="venue rejected mutation"):
            await client.call("reject", {"effect_id": "effect-1"}, mutation=True)
        assert calls == 1
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_ambiguous_timeout_kills_the_desynchronised_child(tmp_path: Path) -> None:
    client = _client(tmp_path, timeout_s=0.05)

    with pytest.raises(SidecarMutationError, match="reconciliation required"):
        await client.call("hang", {"effect_id": "effect-timeout"}, mutation=True)

    assert client._process is None


@pytest.mark.asyncio
async def test_non_object_result_is_rejected(tmp_path: Path) -> None:
    client = _client(tmp_path)
    try:
        with pytest.raises(SidecarError, match="JSON object or list"):
            await client.call("malformed_result")
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_unsupported_node_is_rejected_before_authenticated_sidecar_spawn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[tuple[object, ...], dict[str, Any]]] = []

    async def spawn(*command: object, **kwargs: Any) -> _FakeVersionProcess:
        calls.append((command, kwargs))
        return _FakeVersionProcess(b"v24.19.0\n")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
    client = _client(tmp_path, bypass_node_version=False)

    with pytest.raises(SidecarError, match=r"requires Node\.js 22\.x; found major 24"):
        await client.start()

    assert len(calls) == 1
    command, kwargs = calls[0]
    assert command[1:] == ("--version",)
    assert not any(key.startswith("EVEDEX_") for key in kwargs["env"])
    assert client._process is None


def test_relative_node_runtime_is_rejected_before_path_resolution(tmp_path: Path) -> None:
    script = tmp_path / "fake-sidecar.mjs"
    script.write_text(_FAKE_SIDECAR, encoding="utf-8")

    with pytest.raises(ValueError, match="absolute deployment-controlled path"):
        EvedexSidecarClient(
            node_executable=Path("node"),
            script=script,
            api_key_file=tmp_path / "api.secret",
            private_key_file=tmp_path / "signing.secret",
            expected_account_id="paper-account",
        )
