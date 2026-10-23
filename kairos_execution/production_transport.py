"""Narrow PROD EVEDEX bridge over the pinned SDK API-key REST client.

This is an adapter, not an authority issuer. It never loads a wallet key,
signs requests, retries mutations, or claims that an HTTP result is a fill.
"""

from __future__ import annotations

import asyncio
import json
import math
import os
import re
from pathlib import Path
from typing import Any
from uuid import uuid4

from .managed_signer import CustodyBindingV1, reviewed_schema_sha256
from .production_readiness import ProductionContextV1

_SIGNED_PATHS = {
    "/api/v2/order/limit",
    "/api/v2/order/market",
    "/api/v2/order/stop-limit",
}
_INSTRUMENT_PATHS = (
    (re.compile(r"^/api/v2/position/([A-Z0-9]{1,32})/close$"), "close"),
    (re.compile(r"^/api/tpsl/([A-Z0-9]{1,32})$"), "tpsl"),
)
_FIELDS = {
    "/api/v2/order/limit": {
        "id",
        "instrument",
        "side",
        "leverage",
        "quantity",
        "limitPrice",
        "chainId",
        "timeInForce",
        "signature",
    },
    "/api/v2/order/market": {
        "id",
        "instrument",
        "side",
        "timeInForce",
        "leverage",
        "cashQuantity",
        "chainId",
        "signature",
    },
    "/api/v2/order/stop-limit": {
        "id",
        "instrument",
        "side",
        "leverage",
        "quantity",
        "limitPrice",
        "stopPrice",
        "chainId",
        "signature",
    },
    "close": {"id", "instrument", "leverage", "quantity", "chainId", "signature"},
    "tpsl": {"instrument", "type", "side", "quantity", "price", "order", "signature"},
}
_DECIMAL = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?$")
_SIGNATURE = re.compile(r"^0x[0-9a-fA-F]{130}$")


class ProductionTransportError(RuntimeError):
    """Fail-closed PROD SDK bridge error; mutations are not safe to retry."""


# The HTTP client permits a 4 MiB response body. The outer NDJSON result adds
# a small JSON envelope, so the IPC frame budget includes 4 KiB of overhead.
# asyncio's StreamReader limit counts the terminating newline as part of a line.
MAX_IPC_RESPONSE_BYTES = 4 * 1024 * 1024 + 4 * 1024


def _validate_signed_post(method: str, path: str, body: dict[str, Any]) -> tuple[str, str | None]:
    if method != "POST" or not isinstance(path, str) or not isinstance(body, dict):
        raise ProductionTransportError("only an exact signed EVEDEX POST is supported")
    operation = path if path in _SIGNED_PATHS else None
    instrument = None
    if operation is None:
        for pattern, name in _INSTRUMENT_PATHS:
            match = pattern.fullmatch(path)
            if match:
                operation, instrument = name, match.group(1)
                break
    if operation is None:
        raise ProductionTransportError("signed operation is outside the fixed EVEDEX PROD allowlist")
    if set(body) != _FIELDS[operation]:
        raise ProductionTransportError("signed body fields differ from the pinned EVEDEX schema")
    if not isinstance(body.get("signature"), str) or _SIGNATURE.fullmatch(body["signature"]) is None:
        raise ProductionTransportError("signed body signature is malformed")
    if "chainId" in body and body["chainId"] != 42161:
        raise ProductionTransportError(
            "signed message chain does not match the pinned EVEDEX PROD chain 42161"
        )
    body_instrument = body.get("instrument")
    if not isinstance(body_instrument, str) or re.fullmatch(r"[A-Z0-9]{1,32}", body_instrument) is None:
        raise ProductionTransportError("signed instrument is malformed")
    if instrument is not None and body_instrument != instrument:
        raise ProductionTransportError("signed instrument differs from the exact SDK route")
    if body.get("side", "BUY") not in {"BUY", "SELL"}:
        raise ProductionTransportError("signed side is malformed")
    if "timeInForce" in body and body["timeInForce"] != "IOC":
        raise ProductionTransportError("signed operation differs from the reviewed IOC dispatch policy")
    if "postOnly" in body:
        raise ProductionTransportError("unsigned postOnly metadata is not part of the reviewed wire body")
    if "type" in body and body["type"] not in {"stop-loss", "take-profit"}:
        raise ProductionTransportError("TP/SL type is unsupported")
    for name in ("quantity", "limitPrice", "stopPrice", "cashQuantity", "price"):
        if name in body and (not isinstance(body[name], str) or _DECIMAL.fullmatch(body[name]) is None):
            raise ProductionTransportError(f"{name} must remain a canonical REST decimal string")
    return operation, instrument


class ProductionEvedexTransport:
    """Typed dispatcher sender and cancellation adapter backed by one PROD SDK client."""

    def __init__(
        self,
        *,
        context: ProductionContextV1,
        custody_binding: CustodyBindingV1,
        client: Any,
    ) -> None:
        validated = ProductionContextV1.model_validate(context)
        binding = CustodyBindingV1.model_validate(custody_binding)
        if validated.environment != "PROD" or validated.exchange != "EVEDEX":
            raise ValueError("production transport is restricted to the EVEDEX PROD context")
        if binding.context != validated:
            raise ValueError("transport custody binding differs from the exact PROD context")
        if binding.chain_id != 42161:
            raise ValueError("transport custody binding must use the SDK-pinned EVEDEX PROD chain 42161")
        if binding.schema_sha256 != reviewed_schema_sha256(42161):
            raise ValueError("transport custody schema differs from the reviewed EVEDEX PROD SDK profile")
        if getattr(client, "expected_account_id", None) != validated.remote_account_id:
            raise ValueError("PROD SDK client account must exactly match the bound production context")
        self.context = validated
        self.custody_binding = binding
        self.client = client
        self._preflight_complete = False

    def require_runtime_binding(self, binding: CustodyBindingV1) -> None:
        current = CustodyBindingV1.model_validate(binding)
        if current != self.custody_binding:
            raise ProductionTransportError(
                "runtime signing binding differs from the exact transport custody binding"
            )

    @classmethod
    def from_deployment(
        cls,
        *,
        context: ProductionContextV1,
        custody_binding: CustodyBindingV1,
        node_executable: Path,
        api_key_file: Path,
        timeout_s: float = 20.0,
    ) -> ProductionEvedexTransport:
        validated = ProductionContextV1.model_validate(context)
        client = ProductionEvedexSdkClient(
            node_executable=node_executable,
            api_key_file=api_key_file,
            expected_account_id=validated.remote_account_id,
            timeout_s=timeout_s,
        )
        return cls(context=validated, custody_binding=custody_binding, client=client)

    async def preflight(self) -> dict[str, Any]:
        identity = await self.client.preflight()
        if (
            not isinstance(identity, dict)
            or str(identity.get("exchangeId", "")) != self.context.remote_account_id
        ):
            raise ProductionTransportError(
                "authenticated API-key account differs from the bound PROD context"
            )
        self._preflight_complete = True
        return identity

    def _require_preflight(self) -> None:
        if not self._preflight_complete:
            raise ProductionTransportError(
                "explicit EVEDEX PROD preflight must finish before authority checks and transport"
            )

    async def send_signed_post(self, *, method: str, path: str, body: dict[str, Any]) -> dict[str, Any]:
        self._require_preflight()
        _validate_signed_post(method, path, body)
        try:
            immutable_body = json.loads(
                json.dumps(body, sort_keys=True, separators=(",", ":"), allow_nan=False)
            )
        except (TypeError, ValueError) as exc:
            raise ProductionTransportError("signed EVEDEX body is not canonical JSON") from exc
        result = await self.client.send_signed_post(method=method, path=path, body=immutable_body)
        if not isinstance(result, dict):
            raise ProductionTransportError("EVEDEX SDK returned a malformed signed-operation response")
        return result

    async def cancel_order(self, *, effect_id: str, instrument: str, order_id: str) -> dict[str, Any]:
        self._require_preflight()
        self._validate_cancel(effect_id=effect_id, instrument=instrument, target_id=order_id)
        return await self.client.cancel_order(effect_id=effect_id, instrument=instrument, order_id=order_id)

    async def cancel_tpsl(self, *, effect_id: str, instrument: str, protection_id: str) -> dict[str, Any]:
        self._require_preflight()
        self._validate_cancel(effect_id=effect_id, instrument=instrument, target_id=protection_id)
        return await self.client.cancel_tpsl(
            effect_id=effect_id, instrument=instrument, protection_id=protection_id
        )

    async def fetch_account_identity(self) -> dict[str, Any]:
        self._require_preflight()
        identity = await self.client.fetch_account_identity()
        if str(identity.get("exchangeId", "")) != self.context.remote_account_id:
            raise ProductionTransportError(
                "authenticated API-key account changed outside the bound PROD context"
            )
        return identity

    async def fetch_order_history_page(
        self, *, version: int, limit: int, offset: int, next_cursor: str | None = None
    ) -> dict[str, Any]:
        self._require_preflight()
        return await self.client.fetch_order_history_page(
            version=version, limit=limit, offset=offset, next_cursor=next_cursor
        )

    async def fetch_tpsl_page(self, *, limit: int, offset: int) -> dict[str, Any]:
        self._require_preflight()
        return await self.client.fetch_tpsl_page(limit=limit, offset=offset)

    async def fetch_funding(self) -> dict[str, Any] | list[Any]:
        self._require_preflight()
        return await self.client.fetch_funding()

    @staticmethod
    def _validate_cancel(*, effect_id: str, instrument: str, target_id: str) -> None:
        if not isinstance(effect_id, str) or not effect_id or len(effect_id) > 160:
            raise ProductionTransportError("cancellation effect identity is malformed")
        if not isinstance(instrument, str) or re.fullmatch(r"[A-Z0-9]{1,32}", instrument) is None:
            raise ProductionTransportError("cancellation instrument is malformed")
        if not isinstance(target_id, str) or re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", target_id) is None:
            raise ProductionTransportError("cancellation target identity is malformed")


class ProductionEvedexSdkClient:
    """Single serialized PROD sidecar process; ambiguous timeouts kill, never resend."""

    def __init__(
        self,
        *,
        node_executable: Path,
        api_key_file: Path,
        expected_account_id: str,
        timeout_s: float = 20.0,
        script: Path | None = None,
    ) -> None:
        if not math.isfinite(timeout_s) or not 0 < timeout_s <= 30:
            raise ValueError("production sidecar timeout must be finite and at most thirty seconds")
        self.node_executable = Path(node_executable)
        self.api_key_file = Path(api_key_file)
        if not self.node_executable.is_absolute() or self.node_executable.name.casefold() not in {
            "node",
            "node.exe",
        }:
            raise ValueError("production sidecar requires an absolute deployment-controlled Node.js runtime")
        if not self.api_key_file.is_absolute():
            raise ValueError("production API-key file must be an absolute deployment-controlled path")
        if not isinstance(expected_account_id, str) or not expected_account_id.strip():
            raise ValueError("exact EVEDEX PROD account ID is required")
        self.expected_account_id = expected_account_id
        self.timeout_s = timeout_s
        self.script = script or Path(__file__).with_name("evedex_sidecar") / "src" / "prod_main.js"
        self._process: asyncio.subprocess.Process | None = None
        self._lock = asyncio.Lock()
        self._preflight_complete = False
        self._failed = False
        self._closed = False

    async def start(self) -> None:
        if self._failed or self._closed:
            raise ProductionTransportError(
                "EVEDEX SDK client is latched after failure/close; create a fresh client after reconciliation"
            )
        process = self._process
        if process is not None and process.returncode is None:
            return
        if process is not None and process.returncode is not None:
            self._failed = True
            raise ProductionTransportError(
                "EVEDEX SDK process exited; create a fresh client after reconciliation"
            )
        if not self.script.is_file():
            raise ProductionTransportError("EVEDEX PROD SDK sidecar is missing")
        if self.node_executable.is_symlink():
            raise ProductionTransportError("configured Node.js runtime must not be a symbolic link")
        executable = self.node_executable.resolve(strict=True)
        if (
            executable.name.casefold() not in {"node", "node.exe"}
            or not executable.is_file()
            or not os.access(executable, os.X_OK)
        ):
            raise ProductionTransportError("configured Node.js runtime is not a trusted executable")
        probe = None
        try:
            probe = await asyncio.create_subprocess_exec(
                str(executable),
                "--version",
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
                env={"SYSTEMROOT": os.environ["SYSTEMROOT"]}
                if os.name == "nt" and "SYSTEMROOT" in os.environ
                else {},
            )
            version, _ = await asyncio.wait_for(probe.communicate(), timeout=5)
        except (OSError, TimeoutError, asyncio.CancelledError) as exc:
            if probe is not None and probe.returncode is None:
                probe.kill()
                await probe.wait()
            if isinstance(exc, asyncio.CancelledError):
                raise
            raise ProductionTransportError("Node.js version preflight failed") from None
        if probe.returncode != 0 or re.fullmatch(rb"v22\.[0-9]+\.[0-9]+\s*", version) is None:
            raise ProductionTransportError("EVEDEX PROD SDK requires the reviewed Node.js 22 runtime")
        env = {
            "NODE_ENV": "production",
            "EVEDEX_PROD_API_KEY_FILE": str(self.api_key_file),
            "EVEDEX_PROD_EXPECTED_ACCOUNT_ID": self.expected_account_id,
        }
        if os.name == "nt" and "SYSTEMROOT" in os.environ:
            env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
        self._process = await asyncio.create_subprocess_exec(
            str(executable),
            str(self.script),
            cwd=str(self.script.parents[1]),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            env=env,
            limit=MAX_IPC_RESPONSE_BYTES + 1,
        )

    async def _call(self, operation: str, payload: dict[str, Any], *, mutation: bool) -> Any:
        async with self._lock:
            if self._failed or self._closed:
                raise ProductionTransportError(
                    "EVEDEX PROD SDK client is latched; use a fresh client after reconciliation"
                )
            if operation != "preflight" and not self._preflight_complete:
                raise ProductionTransportError("explicit PROD preflight is required before SDK operations")
            if operation == "preflight" and self._preflight_complete:
                return self._authenticated_identity
            await self.start()
            process = self._process
            if (
                process is None
                or process.returncode is not None
                or process.stdin is None
                or process.stdout is None
            ):
                raise ProductionTransportError(
                    "EVEDEX PROD SDK process is unavailable; reconcile before another attempt"
                )
            request_id = uuid4().hex
            try:
                encoded = json.dumps(
                    {"id": request_id, "operation": operation, "payload": payload},
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                    allow_nan=False,
                ).encode("ascii")
            except (TypeError, ValueError) as exc:
                raise ProductionTransportError("EVEDEX PROD SDK request is not canonical JSON") from exc
            if len(encoded) > 1024 * 1024:
                raise ProductionTransportError("EVEDEX PROD SDK request exceeds the protocol bound")
            try:
                async with asyncio.timeout(self.timeout_s):
                    process.stdin.write(encoded + b"\n")
                    await process.stdin.drain()
                    line = await process.stdout.readline()
            except (OSError, TimeoutError, ValueError, asyncio.CancelledError) as exc:
                await self._abort(process)
                if isinstance(exc, asyncio.CancelledError):
                    raise
                if mutation:
                    raise ProductionTransportError(
                        "EVEDEX mutation outcome may be unresolved; do not retry"
                    ) from None
                raise ProductionTransportError("EVEDEX SDK read transport failed") from None
            if not line:
                await self._abort(process)
                raise ProductionTransportError("EVEDEX SDK sidecar exited; reconcile before another attempt")
            try:
                response = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError):
                await self._abort(process)
                raise ProductionTransportError(
                    "EVEDEX SDK response is malformed; reconcile before another attempt"
                ) from None
            if not isinstance(response, dict) or response.get("id") != request_id:
                await self._abort(process)
                raise ProductionTransportError(
                    "EVEDEX SDK response identity mismatch; reconcile before another attempt"
                )
            if response.get("ok") is not True:
                if mutation or operation == "preflight":
                    await self._abort(process)
                if mutation or operation == "preflight":
                    raise ProductionTransportError(
                        "EVEDEX SDK mutation failed; reconcile before another attempt"
                    )
                raise ProductionTransportError("EVEDEX SDK read failed")
            result = response.get("result")
            if not isinstance(result, (dict, list)):
                await self._abort(process)
                raise ProductionTransportError(
                    "EVEDEX SDK result is malformed; reconcile before another attempt"
                )
            return result

    async def preflight(self) -> dict[str, Any]:
        identity = await self._call("preflight", {}, mutation=False)
        if not isinstance(identity, dict) or str(identity.get("exchangeId", "")) != self.expected_account_id:
            self._failed = True
            process = self._process
            if process is not None:
                await self._abort(process)
            raise ProductionTransportError(
                "authenticated API-key identity differs from the exact PROD account"
            )
        self._authenticated_identity = identity
        self._preflight_complete = True
        return identity

    async def send_signed_post(self, *, method: str, path: str, body: dict[str, Any]) -> dict[str, Any]:
        _validate_signed_post(method, path, body)
        return await self._call(
            "send_signed_post", {"method": method, "path": path, "body": body}, mutation=True
        )

    async def cancel_order(self, *, effect_id: str, instrument: str, order_id: str) -> dict[str, Any]:
        ProductionEvedexTransport._validate_cancel(
            effect_id=effect_id, instrument=instrument, target_id=order_id
        )
        return await self._call(
            "cancel_order",
            {"effect_id": effect_id, "instrument": instrument, "order_id": order_id},
            mutation=True,
        )

    async def cancel_tpsl(self, *, effect_id: str, instrument: str, protection_id: str) -> dict[str, Any]:
        ProductionEvedexTransport._validate_cancel(
            effect_id=effect_id, instrument=instrument, target_id=protection_id
        )
        return await self._call(
            "cancel_tpsl",
            {
                "effect_id": effect_id,
                "instrument": instrument,
                "protection_id": protection_id,
            },
            mutation=True,
        )

    async def fetch_account_identity(self) -> dict[str, Any]:
        result = await self._call("fetch_account_identity", {}, mutation=False)
        if not isinstance(result, dict):
            raise ProductionTransportError("EVEDEX account identity was not a JSON object")
        return result

    async def fetch_order_history_page(
        self, *, version: int, limit: int, offset: int, next_cursor: str | None = None
    ) -> dict[str, Any]:
        if (
            version != 2
            or not 1 <= limit <= 100
            or not 0 <= offset <= 10_000
            or (next_cursor is not None and not next_cursor)
        ):
            raise ProductionTransportError("order history page query is outside the fixed read contract")
        payload: dict[str, Any] = {"version": version, "limit": limit, "offset": offset}
        if next_cursor is not None:
            payload["next"] = next_cursor
        result = await self._call("fetch_order_history_page", payload, mutation=False)
        if not isinstance(result, dict):
            raise ProductionTransportError("EVEDEX order-history page was not a JSON object")
        return result

    async def fetch_tpsl_page(self, *, limit: int, offset: int) -> dict[str, Any]:
        if not 1 <= limit <= 100 or not 0 <= offset <= 10_000:
            raise ProductionTransportError("TP/SL page query is outside the fixed read contract")
        result = await self._call("fetch_tpsl_page", {"limit": limit, "offset": offset}, mutation=False)
        if not isinstance(result, dict):
            raise ProductionTransportError("EVEDEX TP/SL page was not a JSON object")
        return result

    async def fetch_funding(self) -> dict[str, Any] | list[Any]:
        return await self._call("fetch_funding", {}, mutation=False)

    async def _abort(self, process: asyncio.subprocess.Process) -> None:
        self._failed = True
        if self._process is process:
            self._process = None
        if process.returncode is None:
            process.kill()
            await process.wait()

    async def close(self) -> None:
        self._closed = True
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
            process.kill()
            await process.wait()
