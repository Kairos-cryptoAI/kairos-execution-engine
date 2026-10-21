"""Fail-closed policy evaluator for exact production signing authorization.

This module deliberately does not provide a database adapter or production
composition. The current shipped operator-control repository is PAPER/DEV-only,
The production-claim repository has an async claim loader. A deployment must supply
an independently reviewed source that reads those authoritative stores; tests
here use synthetic data and are not production acceptance evidence.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Literal, Protocol, runtime_checkable
from uuid import UUID

from pydantic import Field, field_validator

from .managed_signer import (
    CustodyBindingV1,
    ManagedSigningError,
    ManagedSigningRequestV1,
    _typed_message,
    reviewed_schema_sha256,
)
from .production_readiness import (
    Digest,
    OwnerArmKeyV1,
    PreconditionsV1,
    ProductionContextV1,
    SignedManualArmRequestV1,
    StrictRecord,
    _aware,
    _verify_owner_signed_arm,
    canonical_digest,
)


class AcceptedManualNonceV1(StrictRecord):
    """Exact persisted claim identity; a boolean/hash-only receipt is insufficient."""

    owner_identity: str = Field(min_length=1, max_length=160)
    nonce: str = Field(min_length=1, max_length=160)
    request_sha256: Digest
    context_sha256: Digest
    database_uuid: UUID
    claimed_at: datetime

    _utc = field_validator("claimed_at")(_aware)


class LiveOperatorStateV1(StrictRecord):
    """Authenticated current operator latch with its command lineage."""

    context: ProductionContextV1
    version: int = Field(gt=0)
    state: Literal["ARMED", "DISARMED", "KILLED"]
    arm_nonce: str | None
    arm_request_sha256: Digest | None
    observed_at: datetime
    changed_at: datetime
    expires_at: datetime | None
    command_sha256: Digest
    previous_command_sha256: Digest

    _utc = field_validator("observed_at", "changed_at", "expires_at")(_aware)


class RiskGeometryV1(StrictRecord):
    """Authoritative risk sizing for one exact typed order geometry."""

    context: ProductionContextV1
    decision_id: str = Field(min_length=1, max_length=160)
    signing_request_id: str = Field(min_length=1, max_length=160)
    effect_id: Digest
    client_order_id: str | None
    operation: str = Field(min_length=1, max_length=64)
    instrument: str = Field(min_length=1, max_length=64)
    side: Literal["BUY", "SELL"] | None
    quantity: int = Field(ge=0)
    cash_quantity: int | None = Field(default=None, gt=0)
    price: int | None = Field(default=None, gt=0)
    stop_price: int | None = Field(default=None, gt=0)
    protection_type: Literal["stop-loss", "take-profit"] | None
    trigger_price: int | None = Field(default=None, gt=0)
    parent_order_id: str | None
    leverage: int = Field(ge=1, le=1)
    worst_case_loss_usd: Decimal = Field(gt=0)
    account_equity_usd: Decimal = Field(gt=0)
    daily_realized_loss_usd: Decimal = Field(ge=0)
    aggregate_open_risk_usd: Decimal = Field(ge=0)
    aggregate_open_notional_usd: Decimal = Field(ge=0)
    approved: Literal[True]
    observed_at: datetime
    valid_until: datetime

    _utc = field_validator("observed_at", "valid_until")(_aware)

    @field_validator(
        "worst_case_loss_usd",
        "account_equity_usd",
        "daily_realized_loss_usd",
        "aggregate_open_risk_usd",
        "aggregate_open_notional_usd",
    )
    @classmethod
    def finite_economics(cls, value: Decimal) -> Decimal:
        if not value.is_finite():
            raise ValueError("risk economics must be finite")
        return value


class ExposureSnapshotV1(StrictRecord):
    """Fresh authoritative remaining position and protective-parent lineage."""

    context: ProductionContextV1
    instrument: str = Field(min_length=1, max_length=64)
    position_side: Literal["BUY", "SELL"]
    remaining_quantity: int = Field(gt=0)
    parent_order_id: str = Field(min_length=1, max_length=160)
    observed_at: datetime
    valid_until: datetime

    _utc = field_validator("observed_at", "valid_until")(_aware)


class ProductionSigningEvidenceV1(StrictRecord):
    """One read transaction's typed evidence resolved from deployed stores."""

    owner_arm: SignedManualArmRequestV1
    owner_nonce_claim: AcceptedManualNonceV1
    operator: LiveOperatorStateV1 | None
    risk: RiskGeometryV1
    exposure: ExposureSnapshotV1 | None
    resolved_at: datetime

    _utc = field_validator("resolved_at")(_aware)


@runtime_checkable
class ProductionSigningStateSource(Protocol):
    def resolve_signing_evidence(
        self, *, request: ManagedSigningRequestV1, binding: CustodyBindingV1, now: datetime
    ) -> ProductionSigningEvidenceV1:
        """Read a consistent, authoritative snapshot; errors must fail closed."""
        ...


@runtime_checkable
class AsyncProductionSigningStateSource(Protocol):
    async def resolve_signing_evidence_async(
        self, *, request: ManagedSigningRequestV1, binding: CustodyBindingV1, now: datetime
    ) -> ProductionSigningEvidenceV1:
        """Read one consistent snapshot with bounded, nonblocking database I/O."""
        ...


def signing_effect_id(*, request: ManagedSigningRequestV1, message: dict, decision_id: str) -> str:
    """Deterministic risk/effect identity bound to the request and full wire geometry."""
    payload = {
        "domain": "kairos.production-sign-effect.v1",
        "context_sha256": canonical_digest(request.context),
        "request_id": request.request_id,
        "decision_id": decision_id,
        "operation": request.operation,
        "typed_message": message,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return hashlib.sha256(encoded).hexdigest()


class ProductionSigningAuthorizationVerifier:
    """Validate owner, current operator, risk geometry and exit exposure.

    The source is a security boundary, not a trusted boolean provider: it must
    resolve real deployed records in a consistent read and authenticate their
    command/audit lineage. No such PROD source exists in the current shipped
    persistence contracts, so this class is not deployable authority by itself.
    """

    def __init__(
        self,
        *,
        source: ProductionSigningStateSource | AsyncProductionSigningStateSource,
        preconditions: PreconditionsV1,
        owner_key: OwnerArmKeyV1,
        expected_owner_key_sha256: str,
        expected_owner_identity: str,
        expected_claim_database_uuid: UUID,
        maximum_arm_lifetime: timedelta,
        max_state_age: timedelta = timedelta(seconds=5),
        clock_probe: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if not timedelta(0) < maximum_arm_lifetime <= timedelta(minutes=10):
            raise ValueError("manual-arm lifetime must be positive and at most ten minutes")
        if not timedelta(0) < max_state_age <= timedelta(seconds=5):
            raise ValueError("authorization state freshness may not exceed five seconds")
        self._source = source
        self._preconditions = PreconditionsV1.model_validate(preconditions)
        self._owner_key = OwnerArmKeyV1.model_validate(owner_key)
        self._owner_key_sha256 = expected_owner_key_sha256
        self._owner = expected_owner_identity
        if expected_claim_database_uuid.int == 0:
            raise ValueError("an exact nonzero isolated claim database UUID is required")
        self._claim_database_uuid = expected_claim_database_uuid
        self._arm_lifetime = maximum_arm_lifetime
        self._max_age = max_state_age
        self._clock = clock_probe

    def verify_request(self, request: ManagedSigningRequestV1, binding: CustodyBindingV1) -> None:
        try:
            self._verify(request, binding)
        except ManagedSigningError:
            raise
        except Exception:
            raise ManagedSigningError("independent signing authorization failed") from None

    def _verify(self, request: ManagedSigningRequestV1, binding: CustodyBindingV1) -> None:
        request = ManagedSigningRequestV1.model_validate(request)
        binding = CustodyBindingV1.model_validate(binding)
        _aware(request.expires_at)
        now = self._clock()
        _aware(now)
        # Testability and reproducibility use `verify_request_at`; the signer
        # calls this live-clock entry point.
        self.verify_request_at(request, binding, now=now)

    def verify_request_at(
        self, request: ManagedSigningRequestV1, binding: CustodyBindingV1, *, now: datetime
    ) -> None:
        request, binding = self._validate_scope(request, binding, now=now)
        try:
            if not isinstance(self._source, ProductionSigningStateSource):
                raise ManagedSigningError("async state source requires async authorization")
            evidence = ProductionSigningEvidenceV1.model_validate(
                self._source.resolve_signing_evidence(request=request, binding=binding, now=now)
            )
        except Exception:
            raise ManagedSigningError(
                "owner arm or authoritative authorization state is unavailable"
            ) from None
        self._verify_evidence(request, binding, evidence, now=now)

    async def verify_request_async(self, request: ManagedSigningRequestV1, binding: CustodyBindingV1) -> None:
        await self._resolve_verify_async(request, binding)

    async def verify_effect_async(
        self,
        request: ManagedSigningRequestV1,
        binding: CustodyBindingV1,
        *,
        decision_id: str,
        effect_id: str,
    ) -> None:
        """Bind a wire envelope to the freshly resolved authoritative decision."""
        evidence = await self._resolve_verify_async(request, binding)
        if evidence.risk.decision_id != decision_id or evidence.risk.effect_id != effect_id:
            raise ManagedSigningError("wire effect differs from the authoritative risk decision")

    async def _resolve_verify_async(
        self, request: ManagedSigningRequestV1, binding: CustodyBindingV1
    ) -> ProductionSigningEvidenceV1:
        """Read native async state under the signer's single end-to-end deadline.

        Recheck the clock after I/O: neither a slow read nor an expired lease may
        authorize using the time captured before the database call.
        """
        try:
            now = self._clock()
            request, binding = self._validate_scope(request, binding, now=now)
            if isinstance(self._source, AsyncProductionSigningStateSource):
                evidence = await self._source.resolve_signing_evidence_async(
                    request=request, binding=binding, now=now
                )
            elif isinstance(self._source, ProductionSigningStateSource):
                evidence = self._source.resolve_signing_evidence(request=request, binding=binding, now=now)
            else:
                raise ManagedSigningError("authoritative authorization state is absent")
            checked_at = self._clock()
            if checked_at < now:
                raise ManagedSigningError("authorization clock moved backwards")
            request, binding = self._validate_scope(request, binding, now=checked_at)
            evidence = ProductionSigningEvidenceV1.model_validate(evidence)
            self._verify_evidence(request, binding, evidence, now=checked_at)
            return evidence
        except ManagedSigningError:
            raise
        except Exception:
            raise ManagedSigningError("independent signing authorization failed") from None

    def _validate_scope(
        self, request: ManagedSigningRequestV1, binding: CustodyBindingV1, *, now: datetime
    ) -> tuple[ManagedSigningRequestV1, CustodyBindingV1]:
        _aware(now)
        request = ManagedSigningRequestV1.model_validate(request)
        binding = CustodyBindingV1.model_validate(binding)
        if request.context != binding.context or request.context != self._preconditions.context:
            raise ManagedSigningError("authorization context differs from custody/readiness scope")
        if (
            request.custody_receipt_sha256 != binding.custody_receipt_sha256
            or binding.schema_sha256 != reviewed_schema_sha256(binding.chain_id)
        ):
            raise ManagedSigningError("custody receipt or reviewed schema binding differs")
        if not now < request.expires_at <= now + timedelta(seconds=30):
            raise ManagedSigningError("signing request is expired or exceeds the deadline bound")
        return request, binding

    def _verify_evidence(
        self,
        request: ManagedSigningRequestV1,
        binding: CustodyBindingV1,
        evidence: ProductionSigningEvidenceV1,
        *,
        now: datetime,
    ) -> None:
        try:
            is_exit = request.operation in {"Position close order", "New take-profit/stop-loss"}
            claim_time = evidence.owner_nonce_claim.claimed_at if is_exit else now
            arm, arm_digest = _verify_owner_signed_arm(
                evidence.owner_arm,
                self._preconditions,
                owner_key=self._owner_key,
                expected_owner_key_sha256=self._owner_key_sha256,
                expected_owner_identity=self._owner,
                now=claim_time,
                maximum_lifetime=self._arm_lifetime,
            )
        except Exception:
            raise ManagedSigningError(
                "owner arm or authoritative authorization state is unavailable"
            ) from None
        claim = evidence.owner_nonce_claim
        if (
            request.manual_request_sha256 != arm_digest
            or claim.owner_identity != arm.owner_identity
            or claim.nonce != arm.nonce
            or claim.request_sha256 != arm_digest
            or claim.context_sha256 != canonical_digest(arm.context)
            or claim.claimed_at > now
            or claim.claimed_at < arm.created_at
            or claim.database_uuid != self._claim_database_uuid
        ):
            raise ManagedSigningError("owner arm has no exact accepted durable nonce claim")
        try:
            _, message = _typed_message(request, binding)
        except Exception:
            raise ManagedSigningError("typed order geometry cannot be authorized") from None
        message_order_id = message.get("id")
        expected_effect_id = signing_effect_id(
            request=request,
            message=message,
            decision_id=evidence.risk.decision_id,
        )
        if (
            evidence.risk.signing_request_id != request.request_id
            or evidence.risk.effect_id != expected_effect_id
            or evidence.risk.client_order_id != message_order_id
        ):
            raise ManagedSigningError("risk decision is not bound to this exact order/request effect")
        freshness = [evidence.resolved_at, evidence.risk.observed_at]
        if not is_exit:
            if evidence.operator is None:
                raise ManagedSigningError("fresh deployed operator state is unavailable")
            freshness.append(evidence.operator.observed_at)
        if any(value > now or now - value > self._max_age for value in freshness):
            raise ManagedSigningError("operator or risk evidence is stale or future-dated")
        risk = evidence.risk
        if (
            risk.context != binding.context
            or risk.valid_until <= now
            or risk.valid_until - risk.observed_at > timedelta(seconds=30)
        ):
            raise ManagedSigningError("risk authorization is stale or outside its fixed validity bound")
        if request.expires_at > risk.valid_until:
            raise ManagedSigningError("signing deadline extends beyond the risk authorization lease")
        if risk.operation != request.operation or risk.instrument != message["instrument"]:
            raise ManagedSigningError("risk decision operation/instrument differs from typed order")
        for field, risk_value in (
            ("side", risk.side),
            ("quantity", risk.quantity),
            ("cashQuantity", risk.cash_quantity),
            ("limitPrice", risk.price),
            ("stopPrice", risk.stop_price),
            ("order", risk.parent_order_id),
        ):
            if field in message and message[field] != risk_value:
                raise ManagedSigningError("typed order geometry differs from authoritative risk sizing")
        if is_exit:
            self._verify_exit(evidence, request, message, risk, binding.context, now)
        elif evidence.operator is None:
            raise ManagedSigningError("fresh deployed operator state is unavailable")
        elif evidence.operator.context != binding.context or evidence.operator.version <= 0:
            raise ManagedSigningError("operator state scope or version is invalid")
        elif (
            evidence.operator.state != "ARMED"
            or evidence.operator.expires_at is None
            or now >= evidence.operator.expires_at
        ):
            raise ManagedSigningError("fresh deployed operator state is not armed")
        elif evidence.operator.arm_nonce != arm.nonce or evidence.operator.arm_request_sha256 != arm_digest:
            raise ManagedSigningError("operator ARM is not bound to this accepted owner request")
        elif request.expires_at > evidence.operator.expires_at:
            raise ManagedSigningError("signing deadline extends beyond the operator ARM lease")
        # USD notional bounds apply to entries only. Protective closes may
        # necessarily exceed an entry cap when reducing previously grown exposure.
        if "cashQuantity" in message:
            notional = Decimal(message["cashQuantity"]) / Decimal(10**8)
        elif "quantity" in message and ("limitPrice" in message or "price" in message):
            price = message.get("limitPrice", message.get("price"))
            if type(price) is not int:
                raise ManagedSigningError("typed order lacks an exact authoritative price")
            notional = Decimal(message["quantity"]) * Decimal(price) / Decimal(10**16)
        else:
            notional = Decimal(0)
        if not is_exit and (
            risk.worst_case_loss_usd > arm.dollar_cap
            or risk.daily_realized_loss_usd + risk.worst_case_loss_usd > arm.daily_stop_loss_usd
            or risk.worst_case_loss_usd > risk.account_equity_usd * Decimal("0.0025")
            or risk.aggregate_open_risk_usd + risk.worst_case_loss_usd
            > risk.account_equity_usd * Decimal("0.01")
            or risk.aggregate_open_notional_usd + notional > arm.dollar_cap
            or risk.leverage != 1
        ):
            raise ManagedSigningError("owner or fixed per-trade/aggregate risk limit is exceeded")

    @staticmethod
    def _verify_exit(
        evidence: ProductionSigningEvidenceV1,
        request: ManagedSigningRequestV1,
        message: dict,
        risk: RiskGeometryV1,
        expected_context: ProductionContextV1,
        now: datetime,
    ) -> None:
        exposure = evidence.exposure
        if exposure is None or exposure.context != expected_context:
            raise ManagedSigningError("protective exit lacks current authoritative exposure lineage")
        if exposure.valid_until <= now or exposure.valid_until - exposure.observed_at > timedelta(seconds=5):
            raise ManagedSigningError("protective exit exposure snapshot is stale")
        if request.expires_at > exposure.valid_until:
            raise ManagedSigningError("signing deadline extends beyond the exposure snapshot lease")
        if exposure.observed_at > now or now - exposure.observed_at > timedelta(seconds=5):
            raise ManagedSigningError("protective exit exposure snapshot is stale")
        if exposure.instrument != message["instrument"]:
            raise ManagedSigningError("exit instrument differs from authoritative exposure")
        exit_side = "SELL" if exposure.position_side == "BUY" else "BUY"
        # EVEDEX TP/SL identifies the position being protected. It is not an
        # additive BUY/SELL order: using the close-order side here would protect
        # the opposite position. A direct close still requires the reducing side.
        required_side = (
            exposure.position_side if request.operation == "New take-profit/stop-loss" else exit_side
        )
        if risk.side != required_side or (
            message.get("side") is not None and message["side"] != required_side
        ):
            if request.operation == "New take-profit/stop-loss":
                raise ManagedSigningError("protection side differs from the protected position side")
            raise ManagedSigningError("exit side is not the reducing side for authoritative exposure")
        quantity = message["quantity"]
        if quantity <= 0 or quantity > exposure.remaining_quantity:
            raise ManagedSigningError("exit quantity exceeds remaining exposure")
        if message.get("order", exposure.parent_order_id) != exposure.parent_order_id:
            raise ManagedSigningError("protective exit parent differs from authoritative exposure")
        if risk.parent_order_id != exposure.parent_order_id:
            raise ManagedSigningError("risk decision parent differs from authoritative exposure")
        if risk.operation == "New take-profit/stop-loss":
            if (
                message["type"] != risk.protection_type
                or message["price"] != risk.trigger_price
                or message["type"] not in {"stop-loss", "take-profit"}
            ):
                raise ManagedSigningError("protective trigger type/price differs from risk authorization")
