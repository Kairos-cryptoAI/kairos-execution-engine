"""Narrow opt-in composition for one signed production effect.

This helper is deliberately not a factory, LIVE switch, lifecycle manager, or
reconciliation service. A successful transport response remains unresolved
until an independent authoritative venue lifecycle reconciles it.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, Literal
from uuid import UUID

from .managed_signer import (
    CustodyBindingV1,
    ManagedSignerBoundary,
    ManagedSigningRequestV1,
    SignedTypedDataV1,
)
from .production_claims import PostgresProductionClaims
from .production_dispatch import (
    ProductionEffectDispatcher,
    ProductionWireRequestV1,
    WireEffectType,
    production_wire_body,
)
from .production_readiness import ProductionContextV1, canonical_digest
from .production_state import AsyncPostgresProductionSigningStateSource
from .signing_authorization import (
    ProductionSigningAuthorizationVerifier,
    ProductionSigningEvidenceV1,
    signing_effect_id,
)


@dataclass(frozen=True, slots=True)
class ProductionAuthorityInspection:
    """Read-only request-scoped facts; intentionally contains no readiness token."""

    request_id: str
    decision_id: str
    effect_id: str
    dollar_cap: Decimal
    daily_stop_loss_usd: Decimal
    valid_until: datetime


@dataclass(frozen=True, slots=True)
class ProductionRuntimeOutcome:
    """Dispatch response receipt; never evidence of a fill or completed lifecycle."""

    request_id: str
    decision_id: str
    effect_id: str
    status: Literal["TRANSPORT_RESPONSE_UNRECONCILED"] = "TRANSPORT_RESPONSE_UNRECONCILED"
    lifecycle_complete: Literal[False] = False


@dataclass(frozen=True, slots=True)
class ProductionTransportResponse:
    """Exact transport ACK plus its receipt, not a fill/reconciliation result.

    Kept separate from the public summary so lifecycle validation can inspect
    the venue response without treating a successful POST as a closed trade.
    The response is never a signing capability and contains no request secrets.
    """

    receipt: ProductionRuntimeOutcome
    response: dict[str, Any]


_WIRE_SHAPE: dict[str, tuple[WireEffectType, str]] = {
    "New limit order": ("PLACE_ORDER", "/api/v2/order/limit"),
    "New market order": ("PLACE_ORDER", "/api/v2/order/market"),
    "New stop-limit order": ("PLACE_ORDER", "/api/v2/order/stop-limit"),
    "Position close order": ("CLOSE_POSITION", "/api/v2/position/{instrument}/close"),
    "New take-profit/stop-loss": ("PROTECTIVE_STOP", "/api/tpsl/{instrument}"),
}


class ProductionExecutionRuntime:
    """Compose the existing signer, durable stores, policy and one-shot dispatcher.

    Construction verifies exact cross-component scope and object identity. It
    does not create credentials, readiness evidence, or a venue capability.
    """

    def __init__(
        self,
        *,
        signer: ManagedSignerBoundary,
        authorization: ProductionSigningAuthorizationVerifier,
        claims: PostgresProductionClaims,
        state_source: AsyncPostgresProductionSigningStateSource,
        dispatcher: ProductionEffectDispatcher,
        database_uuid: UUID,
        context: ProductionContextV1,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(database_uuid, UUID) or database_uuid.int == 0:
            raise ValueError("an exact isolated production database UUID is required")
        context = ProductionContextV1.model_validate(context)
        binding = CustodyBindingV1.model_validate(signer.binding)
        if binding.context != context:
            raise ValueError("signer custody binding differs from production context")
        if signer._authorization is not authorization or authorization._source is not state_source:
            raise ValueError("signer and policy must share the exact production authorization source")
        if signer._claims is not claims:
            raise ValueError("signer must be bound to the exact production claims store")
        if not isinstance(claims, PostgresProductionClaims) or not isinstance(
            state_source, AsyncPostgresProductionSigningStateSource
        ):
            raise ValueError("production runtime requires PostgreSQL claims and signing-state adapters")
        if (
            claims.database_uuid != database_uuid
            or state_source.database_uuid != database_uuid
            or authorization._claim_database_uuid != database_uuid
            or claims.context_sha256 != canonical_digest(context)
            or state_source.context != context
            or claims.policy_namespace != state_source.policy_namespace
            or claims.runtime_role != state_source.runtime_role
            or claims.expected_database != state_source.expected_database
        ):
            raise ValueError("production claims/state source differ in database, role, namespace, or context")
        if (
            dispatcher.authorization is not authorization
            or dispatcher.claims is not claims
            or dispatcher.database_uuid != database_uuid
            or dispatcher.context != context
        ):
            raise ValueError("wire dispatcher differs from the exact production authorization scope")
        if authorization._preconditions.context != context:
            raise ValueError("production preconditions differ from the custody/database context")
        self._check_concrete_transport_binding(dispatcher, binding)
        self.signer = signer
        self.authorization = authorization
        self.claims = claims
        self.state_source = state_source
        self.dispatcher = dispatcher
        self.database_uuid = database_uuid
        self.context = context
        self.binding = binding
        self._clock = clock or (lambda: datetime.now(UTC))

    @staticmethod
    def _check_concrete_transport_binding(
        dispatcher: ProductionEffectDispatcher, binding: CustodyBindingV1
    ) -> None:
        # TP/SL has no chainId in the REST body: its domain is bound through
        # custody. The actual SDK sender must therefore agree with that exact
        # binding, not merely validate the other operations' body chainId.
        from .production_transport import ProductionEvedexTransport

        transport = getattr(dispatcher.sender, "__self__", None)
        if isinstance(transport, ProductionEvedexTransport):
            transport.require_runtime_binding(binding)

    async def inspect_authority(self, request: ManagedSigningRequestV1) -> ProductionAuthorityInspection:
        """Validate one exact request and return facts, not LIVE readiness/authority.

        The public inspection API returns validated decision/effect evidence
        without reserving. The signer repeats authorization and commits the
        durable reservation before claiming/signing.
        """
        request = ManagedSigningRequestV1.model_validate(request)
        self._check_concrete_transport_binding(self.dispatcher, self.binding)
        if request.context != self.context:
            raise ValueError("signing request differs from the production runtime context")
        if request.operation not in _WIRE_SHAPE:
            raise ValueError("signing operation has no production wire mapping")
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() != UTC.utcoffset(now):
            raise ValueError("runtime clock must return an explicit UTC time")
        remaining = (request.expires_at - now).total_seconds()
        if not 0 < remaining <= 30:
            raise PermissionError("production inspection requires an unexpired bounded request")
        try:
            async with asyncio.timeout(remaining):
                evidence = await self.authorization.inspect_request_async(request, self.binding)
        except Exception:
            raise PermissionError("complete current production authority is unavailable") from None
        checked_at = self._clock()
        if checked_at < now or checked_at >= request.expires_at:
            raise PermissionError("production inspection clock regressed or the request expired")
        self._check_complete_owner_limits(evidence)
        message = json.loads(request.message_json)
        decision_id = evidence.risk.decision_id
        effect_id = signing_effect_id(request=request, message=message, decision_id=decision_id)
        if evidence.risk.effect_id != effect_id:
            raise PermissionError("current risk decision differs from the exact signed effect")
        return ProductionAuthorityInspection(
            request_id=request.request_id,
            decision_id=decision_id,
            effect_id=effect_id,
            dollar_cap=evidence.owner_arm.request.dollar_cap,
            daily_stop_loss_usd=evidence.owner_arm.request.daily_stop_loss_usd,
            valid_until=evidence.risk.valid_until,
        )

    async def dispatch_one(self, request: ManagedSigningRequestV1) -> ProductionRuntimeOutcome:
        """Authorize, sign once, then dispatch one immutable exact wire request.

        Cancellation, timeout, and ambiguous outcomes propagate unchanged; the
        underlying signer/dispatcher retain their committed one-use claims.
        """
        return (await self.dispatch_one_response(request)).receipt

    async def dispatch_one_response(self, request: ManagedSigningRequestV1) -> ProductionTransportResponse:
        """Same one-shot boundary, retaining ACK for the durable lifecycle.

        This is not a second attempt or a replay facility. Both entry points
        share the same persistent signing/wire claims and unknown-outcome rule.
        """
        request = ManagedSigningRequestV1.model_validate(request)
        inspection = await self.inspect_authority(request)
        now = self._clock()
        signed = await self.signer.sign_async(request, now=now, claims=self.claims)
        wire = self._wire_request(request, signed, inspection)
        # Dispatcher performs an independent fresh state check after its own
        # durable one-use wire claim and immediately before exactly one POST.
        response = await self.dispatcher.dispatch_one(wire)
        return ProductionTransportResponse(
            receipt=ProductionRuntimeOutcome(
                request_id=request.request_id,
                decision_id=inspection.decision_id,
                effect_id=inspection.effect_id,
            ),
            response=json.loads(json.dumps(response, allow_nan=False)),
        )

    @staticmethod
    def _check_complete_owner_limits(evidence: ProductionSigningEvidenceV1) -> None:
        arm = evidence.owner_arm.request
        if (
            not arm.dollar_cap.is_finite()
            or not arm.daily_stop_loss_usd.is_finite()
            or arm.dollar_cap <= 0
            or arm.daily_stop_loss_usd <= 0
            or arm.daily_stop_loss_usd > arm.dollar_cap
            or arm.context != evidence.risk.context
        ):
            raise PermissionError("explicit owner dollar-cap and daily-loss limits are required")

    def _wire_request(
        self,
        request: ManagedSigningRequestV1,
        signed: SignedTypedDataV1,
        inspection: ProductionAuthorityInspection,
    ) -> ProductionWireRequestV1:
        shape = _WIRE_SHAPE.get(request.operation)
        if shape is None:
            raise ValueError("signing operation has no production wire mapping")
        effect_type, path = shape
        message = json.loads(request.message_json)
        if "{instrument}" in path:
            instrument = message.get("instrument")
            if not isinstance(instrument, str):
                raise ValueError("signed message lacks its bound instrument")
            path = path.format(instrument=instrument)
        return ProductionWireRequestV1(
            context=self.context,
            database_uuid=self.database_uuid,
            decision_id=inspection.decision_id,
            effect_id=inspection.effect_id,
            effect_type=effect_type,
            method="POST",
            path=path,
            body=production_wire_body(request.operation, message, signed.signature),
            signing_request=request,
            custody_binding=self.binding,
            signed=signed,
        )
