"""Disconnected, one-effect production wire boundary.

This module is deliberately not wired by settings or factories. It composes an
already managed, independently verified typed signature with a second durable
one-use claim for the exact venue request. It does not implement a lifecycle,
promote readiness, or authorize entry/exit policy by itself.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from collections.abc import Awaitable, Callable
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, Protocol
from uuid import UUID

from pydantic import Field, model_serializer

from .crypto import build_domain
from .managed_signer import (
    CustodyBindingV1,
    ManagedSigningRequestV1,
    SignedTypedDataV1,
    _typed_message,
    production_signed_message,
)
from .production_readiness import ProductionContextV1, StrictRecord, _aware, canonical_digest
from .signing_authorization import signing_effect_id

WireMethod = Literal["POST"]
WireEffectType = Literal["PLACE_ORDER", "CLOSE_POSITION", "PROTECTIVE_STOP"]


class ProductionDispatchError(PermissionError):
    """Sanitized refusal or unresolved one-use production wire outcome."""


class ProductionWireClaimStore(Protocol):
    async def claim_wire_once_async(self, *, namespace: str, effect_id: str, request_sha256: str) -> bool: ...

    async def finish_wire_async(
        self,
        *,
        namespace: str,
        effect_id: str,
        request_sha256: str,
        terminal_status: Literal["COMPLETED", "UNRESOLVED"],
        response_sha256: str | None,
    ) -> None: ...

    async def load_claim(self, *, kind: str, namespace: str, identity: str) -> dict[str, Any] | None: ...


class ProductionEffectAuthorization(Protocol):
    async def verify_effect_async(
        self,
        request: ManagedSigningRequestV1,
        binding: CustodyBindingV1,
        *,
        decision_id: str,
        effect_id: str,
    ) -> None: ...


class ProductionSignatureVerifier(Protocol):
    def verify(
        self,
        *,
        wallet_address: str,
        domain: dict[str, Any],
        types: dict[str, Any],
        message: dict[str, Any],
        signature: str,
    ) -> bool: ...


class ProductionWireRequestV1(StrictRecord):
    """One SDK-normalized EVEDEX POST bound to signed geometry and wire policy."""

    version: Literal["kairos.production-wire-request.v1"] = "kairos.production-wire-request.v1"
    context: ProductionContextV1
    database_uuid: UUID
    decision_id: str = Field(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9_.:-]+$")
    effect_id: str = Field(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9_.:-]+$")
    effect_type: WireEffectType
    method: WireMethod
    path: str = Field(min_length=1, max_length=256)
    body: dict[str, Any]
    signing_request: ManagedSigningRequestV1
    custody_binding: CustodyBindingV1
    signed: SignedTypedDataV1
    limit_time_in_force: Literal["IOC", "GTC"] = "IOC"

    @model_serializer(mode="wrap")
    def preserve_legacy_shape(self, handler):
        payload = handler(self)
        if self.limit_time_in_force == "IOC":
            payload.pop("limit_time_in_force", None)
        return payload


class _WireToken:
    """Private one-call capability; binds one HTTP operation and expires once."""

    __slots__ = ("_seal", "_method", "_path", "_body_sha256", "_expires_at", "_used", "_ipc_used")

    def __init__(self, *, seal: object, method: str, path: str, body_sha256: str, expires_at: datetime):
        if seal is not _WIRE_SEAL:
            raise TypeError("wire token is issued only after exact durable admission")
        self._seal = seal
        self._method = method
        self._path = path
        self._body_sha256 = body_sha256
        self._expires_at = expires_at
        self._used = False
        self._ipc_used = False

    def consume(self, *, method: str, path: str, body_sha256: str, now: datetime) -> datetime:
        _aware(now)
        if (
            self._seal is not _WIRE_SEAL
            or self._used
            or method != self._method
            or path != self._path
            or body_sha256 != self._body_sha256
            or now >= self._expires_at
        ):
            raise ProductionDispatchError(
                "exact one-use wire authorization is absent, expired, or already consumed"
            )
        self._used = True
        return self._expires_at

    def consume_ipc(
        self, *, method: str, path: str, body_sha256: str, deadline_ms: int, now: datetime
    ) -> None:
        _aware(now)
        expiry_ms = (self._expires_at - datetime(1970, 1, 1, tzinfo=UTC)) // timedelta(milliseconds=1)
        if (
            self._seal is not _WIRE_SEAL
            or not self._used
            or self._ipc_used
            or method != self._method
            or path != self._path
            or body_sha256 != self._body_sha256
            or type(deadline_ms) is not int
            or deadline_ms != expiry_ms
            or now >= self._expires_at
        ):
            raise ProductionDispatchError("exact one-use market IPC authorization is absent or expired")
        self._ipc_used = True


_WIRE_SEAL = object()
_OPERATION_BINDINGS: dict[str, tuple[str, WireEffectType, str]] = {
    "New limit order": ("/api/v2/order/limit", "PLACE_ORDER", "id"),
    "New market order": ("/api/v2/order/market", "PLACE_ORDER", "id"),
    "New stop-limit order": ("/api/v2/order/stop-limit", "PLACE_ORDER", "id"),
    "Position close order": ("/api/v2/position/{instrument}/close", "CLOSE_POSITION", "id"),
    "New take-profit/stop-loss": ("/api/tpsl/{instrument}", "PROTECTIVE_STOP", "order"),
}


def production_wire_body(
    operation: str,
    message: dict[str, Any],
    signature: str,
    *,
    limit_time_in_force: Literal["IOC", "GTC"] = "IOC",
) -> dict[str, Any]:
    """Derive the pinned SDK REST representation from reviewed EIP-712 units.

    EIP quantities/prices are integers at 1e8, while exchange-crypto 1.1.0
    (SDK 1.2.11) emits canonical decimal strings on REST. Never send the scaled
    signing integers as human units. Explicit GTC uses the native limit body
    without a timeInForce override. Legacy IOC remains separately selectable
    and is rejected by the real transport. Exact bodies are wire-claim bound.
    """
    if limit_time_in_force not in {"IOC", "GTC"}:
        raise ProductionDispatchError("unsupported limit entry wire policy")
    if operation not in _OPERATION_BINDINGS:
        raise ProductionDispatchError("wire operation has no reviewed REST normalization")
    result = dict(message)
    for field in ("quantity", "limitPrice", "stopPrice", "cashQuantity", "price"):
        if field not in message:
            continue
        value = message[field]
        if type(value) is not int or value < 0:
            raise ProductionDispatchError("wire numeric geometry must use exact unsigned EIP integers")
        whole, fraction = divmod(value, 100_000_000)
        result[field] = str(whole) + ("." + f"{fraction:08d}".rstrip("0") if fraction else "")
    if operation == "New limit order" and limit_time_in_force == "IOC":
        result["timeInForce"] = "IOC"
    result["signature"] = signature
    return result


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode()


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _validate_effect(request: ProductionWireRequestV1) -> dict[str, Any]:
    if (
        request.context != request.signing_request.context
        or request.context != request.custody_binding.context
        or request.signing_request.custody_receipt_sha256 != request.custody_binding.custody_receipt_sha256
    ):
        raise ProductionDispatchError("wire context differs from the managed signing context")
    if request.signing_request.operation not in _OPERATION_BINDINGS:
        raise ProductionDispatchError("wire signing operation is unsupported")
    path_template, expected_type, identity_field = _OPERATION_BINDINGS[request.signing_request.operation]
    try:
        _, message = _typed_message(request.signing_request, request.custody_binding)
    except Exception:
        raise ProductionDispatchError("managed signing message is malformed") from None
    if not isinstance(message, dict) or request.effect_type != expected_type:
        raise ProductionDispatchError("wire effect type differs from signed operation")
    if request.effect_id != signing_effect_id(
        request=request.signing_request,
        message=message,
        decision_id=request.decision_id,
    ):
        raise ProductionDispatchError("wire effect identity differs from the authorized decision geometry")
    if identity_field not in message or not isinstance(message[identity_field], str):
        raise ProductionDispatchError("signed wire message lacks its deterministic venue identity")
    if request.signing_request.operation in {"Position close order", "New take-profit/stop-loss"}:
        instrument = message.get("instrument")
        if not isinstance(instrument, str) or re.fullmatch(r"[A-Z0-9]{1,32}", instrument) is None:
            raise ProductionDispatchError("signed instrument is malformed")
        expected_path = path_template.format(instrument=instrument)
    else:
        expected_path = path_template
    if request.path != expected_path:
        raise ProductionDispatchError("wire path differs from the signed operation")
    if request.method != "POST":
        raise ProductionDispatchError("wire method is unsupported")
    signature = request.signed.signature
    if (
        not isinstance(signature, str)
        or re.fullmatch(r"0x[0-9a-fA-F]{130}", signature) is None
        or hashlib.sha256(signature.encode()).hexdigest() != request.signed.signature_sha256
        or request.signed.wallet_address.casefold() != request.custody_binding.wallet_address.casefold()
    ):
        raise ProductionDispatchError("managed signature is malformed or changed")
    canonical = json.dumps(
        {
            **request.signing_request.model_dump(mode="json"),
            "message_json": json.dumps(message, sort_keys=True),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    if hashlib.sha256(canonical).hexdigest() != request.signed.request_sha256:
        raise ProductionDispatchError("managed signature belongs to a different signing request")
    if _canonical_bytes(request.body) != _canonical_bytes(
        production_wire_body(
            request.signing_request.operation,
            message,
            signature,
            limit_time_in_force=request.limit_time_in_force,
        )
    ):
        raise ProductionDispatchError("wire body differs from the exact independently signed message")
    return message


class ProductionEffectDispatcher:
    """One exact signed POST with state recheck and a distinct durable wire claim.

    The caller owns effect preparation/reconciliation. This boundary never
    retries a sender call and does not make partial execution lifecycle claims.
    """

    def __init__(
        self,
        *,
        authorization: ProductionEffectAuthorization,
        signature_verifier: ProductionSignatureVerifier,
        claims: ProductionWireClaimStore,
        database_uuid: UUID,
        context: ProductionContextV1,
        clock: Callable[[], datetime] | None = None,
        sender: Callable[..., Awaitable[dict[str, Any]]],
        require_session_entry_fence: bool = False,
        session_stop_boundary=None,
        session_entry_io=None,
        limit_time_in_force: Literal["IOC", "GTC"] = "IOC",
    ) -> None:
        if type(require_session_entry_fence) is not bool:
            raise TypeError("session entry fence requirement must be boolean")
        if not isinstance(database_uuid, UUID) or database_uuid.int == 0:
            raise ValueError("an explicit isolated production database UUID is required")
        self.authorization = authorization
        self.signature_verifier = signature_verifier
        self.claims = claims
        self.database_uuid = database_uuid
        self.context = ProductionContextV1.model_validate(context)
        if getattr(claims, "database_uuid", None) != database_uuid or getattr(
            claims, "context_sha256", None
        ) != canonical_digest(self.context):
            raise ValueError("wire-claim store differs from the exact production database/context")
        self.clock = clock or (lambda: datetime.now(UTC))
        self.sender = sender
        # An ACTIVE row does not prove a qualified ledger or a safe sender.
        # Attaching the experimental boundary must not enable entry.
        self._require_session_entry_fence = (
            require_session_entry_fence or session_stop_boundary is not None or session_entry_io is not None
        )
        self._session_stop_boundary = session_stop_boundary
        self._session_entry_io = session_entry_io
        if limit_time_in_force not in {"IOC", "GTC"}:
            raise ValueError("unsupported limit entry wire policy")
        self.limit_time_in_force = limit_time_in_force

    async def dispatch_one(self, request: ProductionWireRequestV1) -> dict[str, Any]:
        request = ProductionWireRequestV1.model_validate(request)
        # No qualified atomic session fence exists at the sender. A signature
        # produced before the fence was selected is not authority to submit an
        # entry. This is a static deny, not an implementation of a $5 latch:
        # it cannot cancel in-flight calls or fence older workers.
        if self._require_session_entry_fence and request.signing_request.operation not in {
            "Position close order",
            "New take-profit/stop-loss",
        }:
            raise ProductionDispatchError("atomic session entry fence is unavailable")
        loop = asyncio.get_running_loop()
        started = loop.time()
        initial_now = self.clock()
        _aware(initial_now)
        expiry = request.signing_request.expires_at
        remaining = (expiry - initial_now).total_seconds()
        if remaining <= 0:
            raise ProductionDispatchError("wire request expired before durable admission")
        if remaining > 30:
            raise ProductionDispatchError("wire request expiry exceeds the 30-second dispatch bound")
        deadline = started + min(remaining, 30.0)
        try:
            async with asyncio.timeout_at(deadline):
                return await self._dispatch_one_bounded(request, initial_now, deadline)
        except TimeoutError:
            raise ProductionDispatchError(
                "wire dispatch deadline elapsed; outcome may be unresolved; do not retry"
            ) from None

    async def _dispatch_one_bounded(
        self,
        request: ProductionWireRequestV1,
        initial_now: datetime,
        deadline: float,
    ) -> dict[str, Any]:
        if request.context != self.context or request.database_uuid != self.database_uuid:
            raise ProductionDispatchError("wire request differs from the pinned production scope")
        if request.limit_time_in_force != self.limit_time_in_force:
            raise ProductionDispatchError("wire limit policy differs from the configured runtime")
        message = _validate_effect(request)

        wall_high_water = initial_now

        def fresh_time() -> datetime:
            nonlocal wall_high_water
            now = self.clock()
            _aware(now)
            if now < wall_high_water:
                raise ProductionDispatchError("wall clock moved backwards during wire dispatch")
            wall_high_water = now
            if now >= request.signing_request.expires_at or asyncio.get_running_loop().time() >= deadline:
                raise ProductionDispatchError("wire request expired during bounded dispatch")
            return now

        if initial_now >= request.signing_request.expires_at:
            raise ProductionDispatchError("wire request expired before durable admission")

        # Derive the frozen transport body from the verified typed geometry,
        # not the caller-owned mutable body mapping after its validation.
        body = json.loads(
            _canonical_bytes(
                production_wire_body(
                    request.signing_request.operation,
                    message,
                    request.signed.signature,
                    limit_time_in_force=request.limit_time_in_force,
                )
            )
        )
        body_digest = _sha256(_canonical_bytes(body))
        context_digest = canonical_digest(self.context)
        claim_record = {
            "context_sha256": context_digest,
            "database_uuid": str(self.database_uuid),
            "effect_id": request.effect_id,
            "effect_type": request.effect_type,
            "method": request.method,
            "path": request.path,
            "body_sha256": body_digest,
            "signing_request_sha256": request.signed.request_sha256,
            "signing_signature_sha256": request.signed.signature_sha256,
            "expires_at": request.signing_request.expires_at.isoformat(),
        }
        request_sha256 = _sha256(_canonical_bytes(claim_record))
        namespace = f"wire:{context_digest}"

        try:
            signing_claim = await self.claims.load_claim(
                kind="TYPED_SIGNING",
                namespace=request.custody_binding.custody_reference,
                identity=request.signing_request.request_id,
            )
        except Exception:
            raise ProductionDispatchError("durable signing evidence is unavailable") from None
        fresh_time()
        if (
            signing_claim is None
            or signing_claim.get("request_sha256") != request.signed.request_sha256
            or signing_claim.get("context_sha256") != context_digest
            or signing_claim.get("terminal_status") != "COMPLETED"
            or signing_claim.get("result_sha256") != request.signed.signature_sha256
        ):
            raise ProductionDispatchError("signature has no exact completed durable signing claim")
        types, typed_message = _typed_message(request.signing_request, request.custody_binding)
        try:
            verified = await asyncio.to_thread(
                self.signature_verifier.verify,
                wallet_address=request.custody_binding.wallet_address,
                domain=build_domain(request.custody_binding.chain_id),
                types=types,
                message=production_signed_message(request.signing_request.operation, typed_message),
                signature=request.signed.signature,
            )
        except Exception:
            verified = False
        fresh_time()
        if verified is not True:
            raise ProductionDispatchError("managed signature failed independent wire-bound verification")

        try:
            await self.authorization.verify_effect_async(
                request.signing_request,
                request.custody_binding,
                decision_id=request.decision_id,
                effect_id=request.effect_id,
            )
        except Exception:
            raise ProductionDispatchError("authoritative wire-time state check failed") from None
        fresh_time()
        try:
            claimed = await self.claims.claim_wire_once_async(
                namespace=namespace,
                effect_id=request.effect_id,
                request_sha256=request_sha256,
            )
        except Exception:
            raise ProductionDispatchError("wire claim outcome is unresolved; do not retry") from None
        fresh_time()
        if claimed is not True:
            raise ProductionDispatchError("wire effect is already claimed or unresolved")

        try:
            # Read state again after durable claim, immediately before issuing
            # the operation-specific, one-use token and transport call.
            await self.authorization.verify_effect_async(
                request.signing_request,
                request.custody_binding,
                decision_id=request.decision_id,
                effect_id=request.effect_id,
            )
            fresh_time()
            token = _WireToken(
                seal=_WIRE_SEAL,
                method=request.method,
                path=request.path,
                body_sha256=body_digest,
                expires_at=request.signing_request.expires_at,
            )
            if request.signing_request.operation != "New market order":
                token.consume(
                    method=request.method,
                    path=request.path,
                    body_sha256=body_digest,
                    now=fresh_time(),
                )
        except asyncio.CancelledError:
            await self._finish_shielded(namespace, request, request_sha256, "UNRESOLVED", None, deadline)
            raise
        except Exception:
            await self._finish_shielded(namespace, request, request_sha256, "UNRESOLVED", None, deadline)
            raise ProductionDispatchError(
                "wire-time authorization failed; durable claim is not retryable"
            ) from None

        try:
            if self._session_entry_io is not None and request.signing_request.operation not in {
                "Position close order",
                "New take-profit/stop-loss",
            }:
                await self._session_entry_io.begin_wire(
                    custody_reference=request.custody_binding.custody_reference,
                    request_id=request.signing_request.request_id,
                    request_sha=request.signed.request_sha256,
                    signature_sha=request.signed.signature_sha256,
                    effect_id=request.effect_id,
                    wire_sha=request_sha256,
                )
            boundary = (
                self._session_stop_boundary.entry(context=request.context)
                if self._session_stop_boundary is not None
                and request.signing_request.operation
                not in {"Position close order", "New take-profit/stop-loss"}
                else nullcontext()
            )
            async with boundary as lease:
                # Lock acquisition may have waited for a STOP writer; never
                # start network I/O using a deadline that expired meanwhile.
                fresh_time()
                if lease is not None:
                    lease.assert_live()
                if request.signing_request.operation == "New market order":
                    response = await self.sender(
                        method=request.method,
                        path=request.path,
                        body=body,
                        expires_at=request.signing_request.expires_at,
                        wire_token=token,
                    )
                else:
                    response = await self.sender(method=request.method, path=request.path, body=body)
                if lease is not None:
                    lease.assert_live()
            fresh_time()
            if not isinstance(response, dict):
                raise ValueError("transport returned a malformed response")
            response_digest = _sha256(_canonical_bytes(response))
        except asyncio.CancelledError:
            await self._finish_shielded(namespace, request, request_sha256, "UNRESOLVED", None, deadline)
            raise
        except Exception:
            await self._finish_shielded(namespace, request, request_sha256, "UNRESOLVED", None, deadline)
            raise ProductionDispatchError("wire outcome is unresolved; do not retry") from None
        fresh_time()
        await self._finish_shielded(
            namespace, request, request_sha256, "COMPLETED", response_digest, deadline
        )
        fresh_time()
        return response

    async def _finish_shielded(
        self,
        namespace: str,
        request: ProductionWireRequestV1,
        request_sha256: str,
        status: Literal["COMPLETED", "UNRESOLVED"],
        response_sha256: str | None,
        deadline: float,
    ) -> None:
        loop = asyncio.get_running_loop()
        if loop.time() >= deadline:
            raise ProductionDispatchError("wire terminal outcome unresolved; do not retry")
        task = asyncio.create_task(
            self.claims.finish_wire_async(
                namespace=namespace,
                effect_id=request.effect_id,
                request_sha256=request_sha256,
                terminal_status=status,
                response_sha256=response_sha256,
            )
        )

        def consume_terminal_result(done_task: asyncio.Task[None]) -> None:
            if not done_task.cancelled():
                try:
                    done_task.exception()
                except BaseException:
                    pass

        task.add_done_callback(consume_terminal_result)
        try:
            async with asyncio.timeout_at(deadline):
                await asyncio.shield(task)
        except asyncio.CancelledError:
            # The terminal writer may finish in the background, but this
            # caller never waits beyond the one shared monotonic deadline.
            raise
        except TimeoutError:
            raise ProductionDispatchError("wire terminal outcome unresolved; do not retry") from None
        except Exception:
            raise ProductionDispatchError("wire terminal outcome unresolved; do not retry") from None
