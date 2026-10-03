"""Unwired managed-custody boundary for reviewed typed-data signing only.

No key loader, raw-digest signer, KMS client or production factory is provided.
Deployment must independently provision a binding, backend, signature verifier
and durable claim store. A failed/unknown dispatch is never retried here.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from datetime import datetime, timedelta
from typing import Annotated, Literal, Protocol

from pydantic import Field, field_validator

from .crypto import EIP712_SCHEMAS, build_domain
from .production_readiness import Digest, Identity, ProductionContextV1, StrictRecord, _aware
from .state_machine import is_evedex_client_order_id

SigningOperation = Literal[
    "New limit order",
    "New market order",
    "New stop-limit order",
    "Position close order",
    "New take-profit/stop-loss",
]
_OPERATIONS = frozenset(
    {
        "New limit order",
        "New market order",
        "New stop-limit order",
        "Position close order",
        "New take-profit/stop-loss",
    }
)


class ManagedSigningError(PermissionError):
    """A custody/signing precondition failed (never include backend error text)."""


class CustodyBindingV1(StrictRecord):
    version: Literal["kairos.managed-custody.v1"] = "kairos.managed-custody.v1"
    context: ProductionContextV1
    custody_reference: Identity
    wallet_address: Annotated[str, Field(pattern=r"^0x[0-9a-fA-F]{40}$")]
    chain_id: int = Field(gt=0, lt=2**256)
    schema_sha256: Digest
    approved_instruments: tuple[Identity, ...]
    custody_receipt_sha256: Digest

    @field_validator("approved_instruments")
    @classmethod
    def explicit_universe(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != 5 or len(set(value)) != 5:
            raise ValueError("five distinct owner-reviewed production instruments are required")
        return value


class ManagedSigningRequestV1(StrictRecord):
    version: Literal["kairos.managed-sign-request.v1"] = "kairos.managed-sign-request.v1"
    request_id: Identity
    context: ProductionContextV1
    manual_request_sha256: Digest
    custody_receipt_sha256: Digest
    operation: SigningOperation
    message_json: Annotated[str, Field(min_length=2, max_length=4096)]
    expires_at: datetime

    _utc = field_validator("expires_at")(_aware)


class SignedTypedDataV1(StrictRecord):
    request_sha256: Digest
    wallet_address: str
    signature_sha256: Digest
    signature: Annotated[str, Field(repr=False, exclude=True)]


class ManagedCustodyBackend(Protocol):
    def sign_typed_data(self, *, custody_reference: str, domain: dict, types: dict, message: dict) -> str: ...


class SignatureVerifier(Protocol):
    def verify(
        self, *, wallet_address: str, domain: dict, types: dict, message: dict, signature: str
    ) -> bool:
        """Independently recover/check the signer for exactly these typed bytes."""
        ...


class SigningClaimStore(Protocol):
    def claim_once(self, *, custody_reference: str, request_id: str, request_sha256: str) -> bool:
        """Durable CAS; an admitted request with unknown terminal can never be reclaimed."""
        ...


class AsyncSigningClaimStore(Protocol):
    async def claim_once_async(
        self, *, custody_reference: str, request_id: str, request_sha256: str
    ) -> bool: ...
    async def finish_signing_async(
        self,
        *,
        custody_reference: str,
        request_id: str,
        request_sha256: str,
        terminal_status: Literal["COMPLETED", "UNRESOLVED"],
        result_sha256: str | None,
    ) -> None: ...


class SigningAuthorizationVerifier(Protocol):
    def verify_request(self, request: ManagedSigningRequestV1, binding: CustodyBindingV1) -> None:
        """Resolve manual request, current operator/risk authorization and exact limits.

        A digest string alone is not authorization. Raise on absent, stale,
        revoked, unresolved or scope/geometry-mismatched underlying evidence.
        """
        ...


def reviewed_schema_sha256(chain_id: int) -> str:
    """Bind the local reviewed non-Withdraw schema/domain, not a caller's types."""
    encoded = json.dumps(
        {
            "domain": build_domain(chain_id),
            "types": {key: EIP712_SCHEMAS[key] for key in sorted(_OPERATIONS)},
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _reject_duplicate_keys(items: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate typed-message key")
        result[key] = value
    return result


def _typed_message(request: ManagedSigningRequestV1, binding: CustodyBindingV1) -> tuple[dict, dict]:
    if request.operation not in _OPERATIONS:
        raise ManagedSigningError("signing operation is not allowlisted")
    try:
        message = json.loads(request.message_json, object_pairs_hook=_reject_duplicate_keys)
    except (ValueError, TypeError):
        raise ManagedSigningError("malformed typed message") from None
    types = json.loads(json.dumps(EIP712_SCHEMAS[request.operation]))
    fields = types[request.operation]
    if type(message) is not dict or set(message) != {item["name"] for item in fields}:
        raise ManagedSigningError("typed message does not match the fixed schema")
    for field in fields:
        value = message[field["name"]]
        if field["type"].startswith("uint"):
            bits = int(field["type"][4:])
            if type(value) is not int or not 0 <= value < 2**bits:
                raise ManagedSigningError("typed integer violates the fixed schema")
        elif type(value) is not str or not 0 < len(value) <= 160 or any(ord(c) < 32 for c in value):
            raise ManagedSigningError("typed string violates the fixed schema")
    if message.get("instrument") not in binding.approved_instruments:
        raise ManagedSigningError("instrument is not in the custody-approved universe")
    if "chainId" in message and message["chainId"] != binding.chain_id:
        raise ManagedSigningError("typed message chain differs from custody binding")
    if "side" in message and message["side"] not in {"BUY", "SELL"}:
        raise ManagedSigningError("typed side is invalid")
    if "leverage" in message and message["leverage"] != 1:
        raise ManagedSigningError("initial controlled signing permits only 1x leverage")
    if "timeInForce" in message and message["timeInForce"] != "IOC":
        raise ManagedSigningError("initial controlled signing permits only IOC market orders")
    if "id" in message and not is_evedex_client_order_id(message["id"]):
        raise ManagedSigningError("typed order ID is not a deterministic EVEDEX ID")
    if "order" in message and not is_evedex_client_order_id(message["order"]):
        raise ManagedSigningError("protective request lacks an authoritative parent ID")
    if "type" in message and message["type"] not in {"stop-loss", "take-profit"}:
        raise ManagedSigningError("protective request type is not allowlisted")
    for name in ("cashQuantity", "limitPrice", "stopPrice", "price"):
        if name in message and message[name] <= 0:
            raise ManagedSigningError("price/cash quantity must be positive")
    if (
        "quantity" in message
        and message["quantity"] == 0
        and request.operation != "New take-profit/stop-loss"
    ):
        raise ManagedSigningError("entry/close quantity must be positive")
    return types, message


class ManagedSignerBoundary:
    def __init__(
        self,
        binding: CustodyBindingV1,
        *,
        backend: ManagedCustodyBackend,
        verifier: SignatureVerifier,
        claims: SigningClaimStore,
        authorization: SigningAuthorizationVerifier,
    ) -> None:
        self.binding = binding
        self._backend = backend
        self._verifier = verifier
        self._claims = claims
        self._authorization = authorization

    def _prepare(
        self, request: ManagedSigningRequestV1, now: datetime
    ) -> tuple[ManagedSigningRequestV1, CustodyBindingV1, dict, dict, str]:
        _aware(now)
        request = ManagedSigningRequestV1.model_validate(request)
        binding = CustodyBindingV1.model_validate(self.binding)
        if (
            request.context != binding.context
            or request.custody_receipt_sha256 != binding.custody_receipt_sha256
        ):
            raise ManagedSigningError("request is not bound to this production custody scope")
        if binding.schema_sha256 != reviewed_schema_sha256(binding.chain_id):
            raise ManagedSigningError("reviewed typed schema/domain digest changed")
        if not now < request.expires_at <= now + timedelta(seconds=30):
            raise ManagedSigningError("signing deadline is expired or exceeds the fixed bound")
        types, message = _typed_message(request, binding)
        try:
            self._authorization.verify_request(request, binding)
        except Exception:
            raise ManagedSigningError("independent signing authorization failed") from None
        canonical = json.dumps(
            {**request.model_dump(mode="json"), "message_json": json.dumps(message, sort_keys=True)},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        digest = hashlib.sha256(canonical).hexdigest()
        return request, binding, types, message, digest

    def sign(self, request: ManagedSigningRequestV1, *, now: datetime) -> SignedTypedDataV1:
        request, binding, types, message, digest = self._prepare(request, now)
        try:
            claimed = self._claims.claim_once(
                custody_reference=binding.custody_reference,
                request_id=request.request_id,
                request_sha256=digest,
            )
        except Exception:
            raise ManagedSigningError("signing claim outcome is unresolved; do not retry") from None
        if claimed is not True:
            raise ManagedSigningError("signing request is already claimed or unresolved")
        return self._sign_claimed(binding, types, message, digest)

    def _sign_claimed(
        self, binding: CustodyBindingV1, types: dict, message: dict, digest: str
    ) -> SignedTypedDataV1:
        domain = build_domain(binding.chain_id)
        try:
            signature = self._backend.sign_typed_data(
                custody_reference=binding.custody_reference,
                domain=json.loads(json.dumps(domain)),
                types=json.loads(json.dumps(types)),
                message=json.loads(json.dumps(message)),
            )
            if not isinstance(signature, str) or re.fullmatch(r"0x[0-9a-fA-F]{130}", signature) is None:
                raise ManagedSigningError("managed backend returned a malformed signature")
            if (
                self._verifier.verify(
                    wallet_address=binding.wallet_address,
                    domain=domain,
                    types=types,
                    message=message,
                    signature=signature,
                )
                is not True
            ):
                raise ManagedSigningError("managed signature failed independent verification")
        except Exception:
            raise ManagedSigningError(
                "managed signing outcome failed or is unresolved; do not retry"
            ) from None
        return SignedTypedDataV1(
            request_sha256=digest,
            wallet_address=binding.wallet_address,
            signature_sha256=hashlib.sha256(signature.encode()).hexdigest(),
            signature=signature,
        )

    async def sign_async(
        self, request: ManagedSigningRequestV1, *, now: datetime, claims: AsyncSigningClaimStore
    ) -> SignedTypedDataV1:
        """Durable async adapter, not a provider factory or LIVE authority issuer.

        COMMIT acknowledgment must precede the bounded caller-owned backend.
        Cancellation/process loss leaves an irrevocable claim. Native custody
        still needs its own cancellation qualification; a thread may continue
        after timeout, but no late signature is returned and no retry occurs.
        """
        loop = asyncio.get_running_loop()
        started = loop.time()
        request, binding, types, message, digest = self._prepare(request, now)
        deadline = started + min(30.0, (request.expires_at - now).total_seconds())
        try:
            # ONE deadline includes authorization preparation, durable claim,
            # backend, independent verification and terminal COMMIT. Explicit
            # checks also reject a callback that suppresses cancellation or
            # returns synchronously after its deadline.
            async with asyncio.timeout_at(deadline):
                if loop.time() >= deadline:
                    raise TimeoutError
                try:
                    admitted = await claims.claim_once_async(
                        custody_reference=binding.custody_reference,
                        request_id=request.request_id,
                        request_sha256=digest,
                    )
                except Exception:
                    raise ManagedSigningError("signing claim outcome is unresolved; do not retry") from None
                if admitted is not True:
                    raise ManagedSigningError("signing request is already claimed or unresolved")
                if loop.time() >= deadline:
                    raise TimeoutError
                try:
                    # Offloading does not make an unwired native backend
                    # killable. Timeout leaves the committed claim UNKNOWN.
                    signed = await asyncio.to_thread(self._sign_claimed, binding, types, message, digest)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    try:
                        await claims.finish_signing_async(
                            custody_reference=binding.custody_reference,
                            request_id=request.request_id,
                            request_sha256=digest,
                            terminal_status="UNRESOLVED",
                            result_sha256=None,
                        )
                    except Exception:
                        raise ManagedSigningError(
                            "managed signing and terminal outcomes unresolved; do not retry"
                        ) from None
                    raise ManagedSigningError(
                        "managed signing outcome failed or is unresolved; do not retry"
                    ) from None
                if loop.time() >= deadline:
                    raise TimeoutError
                try:
                    await claims.finish_signing_async(
                        custody_reference=binding.custody_reference,
                        request_id=request.request_id,
                        request_sha256=digest,
                        terminal_status="COMPLETED",
                        result_sha256=signed.signature_sha256,
                    )
                except Exception:
                    raise ManagedSigningError(
                        "signing terminal outcome is unresolved; do not retry"
                    ) from None
                if loop.time() >= deadline:
                    raise TimeoutError
                return signed
        except TimeoutError:
            # Do not start an unbounded terminal write after the deadline.
            # Even a late COMPLETED record does not permit signature release
            # or replay; the immutable original claim remains authoritative.
            raise ManagedSigningError(
                "end-to-end signing deadline expired; outcome unresolved; do not retry"
            ) from None
        except asyncio.CancelledError:
            raise  # Durable CLAIMED is honest UNKNOWN, not retry permission.
