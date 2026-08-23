"""Async NDJSON child-process client for the internal EVEDEX SDK sidecar."""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
from pathlib import Path
from typing import Any
from uuid import uuid4

_NODE_VERSION_PATTERN = re.compile(r"v(?P<major>0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")
_SUPPORTED_NODE_MAJOR = 22
_NODE_VERSION_TIMEOUT_S = 5.0


class SidecarError(RuntimeError):
    """The sidecar rejected a request or returned malformed data."""


class SidecarMutationError(SidecarError):
    """A mutation failed and must be reconciled; it is never retried."""


class EvedexSidecarClient:
    """Own one SDK process and serialize all commands over stdin/stdout."""

    def __init__(
        self,
        *,
        node_executable: str,
        script: Path,
        api_key_file: Path,
        private_key_file: Path,
        expected_account_id: str,
        timeout_s: float = 20.0,
    ) -> None:
        if timeout_s <= 0:
            raise ValueError("sidecar timeout must be positive")
        if api_key_file == private_key_file:
            raise ValueError("API and signing key files must be distinct")
        if not expected_account_id.strip():
            raise ValueError("expected EVEDEX account ID must not be empty")
        self.node_executable = node_executable
        self.script = script
        self.api_key_file = api_key_file
        self.private_key_file = private_key_file
        self.expected_account_id = expected_account_id
        self.timeout_s = timeout_s
        self._process: asyncio.subprocess.Process | None = None
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        if self._process is not None and self._process.returncode is None:
            return
        executable = shutil.which(self.node_executable)
        if executable is None:
            raise SidecarError(f"Node executable {self.node_executable!r} was not found")
        if not self.script.is_file():
            raise SidecarError(f"EVEDEX sidecar script does not exist: {self.script}")
        await self._assert_supported_node(executable)
        # Python passes secret *paths* only. Values are opened exclusively by
        # the Node child and are never loaded into Python settings or logs.
        child_env = {
            "NODE_ENV": "production",
            "EVEDEX_DEV_API_KEY_FILE": str(self.api_key_file),
            "EVEDEX_DEV_PRIVATE_KEY_FILE": str(self.private_key_file),
            "EVEDEX_DEV_EXPECTED_ACCOUNT_ID": self.expected_account_id,
        }
        if os.name == "nt" and "SYSTEMROOT" in os.environ:
            child_env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
        self._process = await asyncio.create_subprocess_exec(
            executable,
            str(self.script),
            cwd=str(self.script.parents[1]),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            # The child must never fill an unread stderr pipe or surface SDK
            # diagnostics that could include authenticated request metadata.
            stderr=asyncio.subprocess.DEVNULL,
            env=child_env,
            limit=1024 * 1024,
        )

    async def _assert_supported_node(self, executable: str) -> None:
        """Fail closed before giving an unsupported runtime authenticated context."""
        probe_env: dict[str, str] = {}
        if os.name == "nt" and "SYSTEMROOT" in os.environ:
            probe_env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
        try:
            process = await asyncio.create_subprocess_exec(
                executable,
                "--version",
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
                env=probe_env,
                limit=128,
            )
        except OSError as exc:
            raise SidecarError("Node.js version preflight could not start") from exc
        try:
            stdout, _ = await asyncio.wait_for(
                process.communicate(),
                timeout=_NODE_VERSION_TIMEOUT_S,
            )
        except asyncio.CancelledError:
            await self._terminate_process(process)
            raise
        except TimeoutError as exc:
            await self._terminate_process(process)
            raise SidecarError("Node.js version preflight timed out") from exc
        if process.returncode != 0:
            raise SidecarError("Node.js version preflight failed")
        try:
            version = stdout.decode("ascii").strip()
        except UnicodeDecodeError as exc:
            raise SidecarError("Node.js version preflight returned malformed output") from exc
        match = _NODE_VERSION_PATTERN.fullmatch(version)
        if match is None:
            raise SidecarError("Node.js version preflight returned malformed output")
        major = int(match.group("major"))
        if major != _SUPPORTED_NODE_MAJOR:
            raise SidecarError(f"PAPER requires Node.js {_SUPPORTED_NODE_MAJOR}.x; found major {major}")

    async def call(
        self,
        operation: str,
        payload: dict[str, Any] | None = None,
        *,
        mutation: bool = False,
    ) -> dict[str, Any]:
        async with self._lock:
            await self.start()
            process = self._process
            if process is None or process.stdin is None or process.stdout is None:
                raise SidecarError("sidecar process streams are unavailable")
            if process.returncode is not None:
                raise SidecarError(f"sidecar exited with status {process.returncode}")
            request_id = uuid4().hex
            request = {"id": request_id, "operation": operation, "payload": payload or {}}
            try:
                encoded = json.dumps(
                    request,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                    allow_nan=False,
                ).encode()
            except (TypeError, ValueError) as exc:
                raise SidecarError("sidecar request is not canonical JSON") from exc
            if len(encoded) > 1024 * 1024:
                raise SidecarError("sidecar request exceeds the 1 MiB protocol limit")
            process.stdin.write(encoded + b"\n")
            error_type = SidecarMutationError if mutation else SidecarError
            try:
                await asyncio.wait_for(process.stdin.drain(), timeout=self.timeout_s)
                response_line = await asyncio.wait_for(process.stdout.readline(), timeout=self.timeout_s)
            except asyncio.CancelledError:
                await self._abort_process(process)
                raise
            except TimeoutError as exc:
                await self._abort_process(process)
                raise error_type(f"EVEDEX sidecar {operation} timed out; reconciliation required") from exc
            except ValueError as exc:
                await self._abort_process(process)
                raise error_type("EVEDEX sidecar response exceeded the protocol limit") from exc
            if not response_line:
                raise error_type(f"EVEDEX sidecar closed during {operation}; reconciliation required")
            try:
                response = json.loads(response_line)
            except json.JSONDecodeError as exc:
                await self._abort_process(process)
                raise error_type("sidecar returned malformed JSON; reconciliation required") from exc
            if not isinstance(response, dict) or response.get("id") != request_id:
                await self._abort_process(process)
                raise error_type("sidecar response identity does not match the request")
            if response.get("ok") is not True:
                error = response.get("error")
                detail = error.get("message") if isinstance(error, dict) else "unknown sidecar error"
                raise error_type(f"EVEDEX sidecar {operation} failed: {detail}")
            expected_effect = (payload or {}).get("effect_id") if mutation else None
            if mutation and response.get("effect_id") != expected_effect:
                await self._abort_process(process)
                raise SidecarMutationError(
                    f"EVEDEX sidecar {operation} returned a mismatched effect identity"
                )
            result = response.get("result")
            if not isinstance(result, dict) and not isinstance(result, list):
                await self._abort_process(process)
                raise error_type("sidecar result must be a JSON object or list")
            return {"data": result, "effect_id": response.get("effect_id")}

    async def _abort_process(self, process: asyncio.subprocess.Process) -> None:
        """Discard a desynchronised protocol stream after an ambiguous timeout."""
        if self._process is process:
            self._process = None
        await self._terminate_process(process)

    @staticmethod
    async def _terminate_process(process: asyncio.subprocess.Process) -> None:
        if process.returncode is None:
            process.kill()
            await process.wait()

    async def close(self) -> None:
        process = self._process
        self._process = None
        if process is None:
            return
        if process.stdin is not None:
            process.stdin.close()
            try:
                await process.stdin.wait_closed()
            except (BrokenPipeError, ConnectionResetError):
                pass
        try:
            await asyncio.wait_for(process.wait(), timeout=5)
        except TimeoutError:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=5)
            except TimeoutError:
                process.kill()
                await process.wait()
