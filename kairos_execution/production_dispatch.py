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
from datetime import UTC, datetime
from typing import Any, Literal, Protocol
from uuid import UUID

from pydantic import Field

from .crypto import build_domain
from .managed_signer import (
    CustodyBindingV1,
    ManagedSigningRequestV1,
    SignedTypedDataV1,
    _typed_message,
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
    """One already-signed EVEDEX POST, bound to exact scope/effect/body/deadline."""

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


class _WireToken:
    """Private one-call capability; binds one HTTP operation and expires once."""

    __slots__ = ("_seal", "_method", "_path", "_body_sha256", "_expires_at", "_used")

    def __init__(self, *, seal: object, method: str, path: str, body_sha256: str, expires_at: datetime):
        if seal is not _WIRE_SEAL:
            raise TypeError("wire token is issued only after exact durable admission")
        self._seal = seal
        self._method = method
        self._path = path
        self._body_sha256 = body_sha256
        self._expires_at = expires_at
        self._used = False

    def consume(self, *, method: str, path: str, body_sha256: str, now: datetime) -> None:
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


_WIRE_SEAL = object()
_OPERATION_BINDINGS: dict[str, tuple[str, WireEffectType, str]] = {
    "New limit order": ("/api/v2/order/limit", "PLACE_ORDER", "id"),
    "New market order": ("/api/v2/order/market", "PLACE_ORDER", "id"),
    "New stop-limit order": ("/api/v2/order/stop-limit", "PLACE_ORDER", "id"),
    "Position close order": ("/api/v2/position/{instrument}/close", "CLOSE_POSITION", "id"),
    "New take-profit/stop-loss": ("/api/tpsl/{instrument}", "PROTECTIVE_STOP", "order"),
}


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
    if request.body != {**message, "signature": signature}:
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
    ) -> None:
        if not isinstance(database_uuid, UUID):
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

    async def dispatch_one(self, request: ProductionWireRequestV1) -> dict[str, Any]:
        request = ProductionWireRequestV1.model_validate(request)
        if request.context != self.context or request.database_uuid != self.database_uuid:
            raise ProductionDispatchError("wire request differs from the pinned production scope")
        _validate_effect(request)
        now = self.clock()
        _aware(now)
        if now >= request.signing_request.expires_at:
            raise ProductionDispatchError("wire request expired before durable admission")

        body = json.loads(_canonical_bytes(request.body))
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
            verified = self.signature_verifier.verify(
                wallet_address=request.custody_binding.wallet_address,
                domain=build_domain(request.custody_binding.chain_id),
                types=types,
                message=typed_message,
                signature=request.signed.signature,
            )
        except Exception:
            verified = False
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
        if self.clock() >= request.signing_request.expires_at:
            raise ProductionDispatchError("wire request expired during state validation")
        try:
            claimed = await self.claims.claim_wire_once_async(
                namespace=namespace,
                effect_id=request.effect_id,
                request_sha256=request_sha256,
            )
        except Exception:
            raise ProductionDispatchError("wire claim outcome is unresolved; do not retry") from None
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
            now = self.clock()
            if now >= request.signing_request.expires_at:
                raise ProductionDispatchError("wire request expired before transport dispatch")
            token = _WireToken(
                seal=_WIRE_SEAL,
                method=request.method,
                path=request.path,
                body_sha256=body_digest,
                expires_at=request.signing_request.expires_at,
            )
            token.consume(
                method=request.method,
                path=request.path,
                body_sha256=body_digest,
                now=self.clock(),
            )
        except asyncio.CancelledError:
            await self._finish_shielded(namespace, request, request_sha256, "UNRESOLVED", None)
            raise
        except Exception:
            await self._finish_shielded(namespace, request, request_sha256, "UNRESOLVED", None)
            raise ProductionDispatchError(
                "wire-time authorization failed; durable claim is not retryable"
            ) from None

        try:
            response = await self.sender(method=request.method, path=request.path, body=body)
            if not isinstance(response, dict):
                raise ValueError("transport returned a malformed response")
            response_digest = _sha256(_canonical_bytes(response))
        except asyncio.CancelledError:
            await self._finish_shielded(namespace, request, request_sha256, "UNRESOLVED", None)
            raise
        except Exception:
            await self._finish_shielded(namespace, request, request_sha256, "UNRESOLVED", None)
            raise ProductionDispatchError("wire outcome is unresolved; do not retry") from None
        await self._finish_shielded(namespace, request, request_sha256, "COMPLETED", response_digest)
        return response

    async def _finish_shielded(
        self,
        namespace: str,
        request: ProductionWireRequestV1,
        request_sha256: str,
        status: Literal["COMPLETED", "UNRESOLVED"],
        response_sha256: str | None,
    ) -> None:
        task = asyncio.create_task(
            self.claims.finish_wire_async(
                namespace=namespace,
                effect_id=request.effect_id,
                request_sha256=request_sha256,
                terminal_status=status,
                response_sha256=response_sha256,
            )
        )
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            # The terminal writer continues despite caller cancellation.
            try:
                await asyncio.shield(task)
            except Exception:
                pass
            raise
        except Exception:
            raise ProductionDispatchError("wire terminal outcome unresolved; do not retry") from None
