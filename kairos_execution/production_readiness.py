"""Offline production preconditions; deliberately NOT a LIVE capability issuer.

Evidence interpreters and a durable one-use nonce store must be supplied by a
separately reviewed deployment. No engineering manifest boolean is evidence.
The supported config/factory continue to reject LIVE unconditionally.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import datetime, timedelta
from decimal import Decimal
from enum import StrEnum
from typing import Annotated, Literal, Protocol, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Digest = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
Identity = Annotated[str, Field(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9_.:-]+$")]


class StrictRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, revalidate_instances="always")


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError("an explicit UTC timestamp is required")
    return value


class ProductionContextV1(StrictRecord):
    version: Literal["kairos.production-context.v1"] = "kairos.production-context.v1"
    environment: Literal["PROD"] = "PROD"
    exchange: Literal["EVEDEX"] = "EVEDEX"
    remote_account_id: Identity
    adaptive_system_id: Identity
    frozen_policy_sha256: Digest
    source_set_sha256: Digest

    @field_validator("adaptive_system_id")
    @classmethod
    def exclude_historical_baseline(cls, value: str) -> str:
        if value.casefold() in {"trial15", "trial_15", "regime_aligned_right_tail_v1"}:
            raise ValueError("the historical Trial 15 baseline is not a LIVE candidate")
        return value


class EvidenceKind(StrEnum):
    ADAPTIVE_SEALED_FORWARD = "adaptive_sealed_forward"
    ADAPTIVE_SEALED_TRADES = "adaptive_sealed_trades"
    CRASH_NET_GATE = "crash_net_gate"
    DEV_READONLY_24H = "dev_readonly_24h"
    DEV_CANARY = "dev_canary"
    DEV_SOAK_TCA = "dev_soak_tca"
    PRIMARY_RECOVERY = "primary_recovery"
    SECURITY_REVIEW = "security_review"
    MANAGED_CUSTODY = "managed_custody"
    OFFHOST_RESTORE = "offhost_restore"
    ALERT_DELIVERY = "alert_delivery"
    GLOBAL_OPERATOR_CONTROL = "global_operator_control"
    PROD_ACCOUNT_PAIRING = "prod_account_pairing"
    PRODUCTION_LIMITS = "production_limits"


class ReceiptReferenceV1(StrictRecord):
    kind: EvidenceKind
    receipt_id: Identity
    content_sha256: Digest
    issuer_id: Identity


class VerifiedEvidenceV1(StrictRecord):
    """Result of an independent, kind-specific signature/schema/data interpreter.

    This record alone is not trusted: its issuer must be registered for its kind
    and its content/scope/time/policy must exactly match the requested reference.
    The interpreter must independently check the underlying substantive gate.
    """

    reference: ReceiptReferenceV1
    context: ProductionContextV1
    outcome: Literal["SEALED_PASS"]
    verified_at: datetime
    valid_until: datetime
    complete_forward_days: int | None = Field(default=None, ge=0)
    naturally_closed_simulated_trades: int | None = Field(default=None, ge=0)

    _utc = field_validator("verified_at", "valid_until")(_aware)

    @model_validator(mode="after")
    def ordered_time(self) -> Self:
        if self.valid_until <= self.verified_at:
            raise ValueError("evidence validity interval is empty")
        return self


class EvidenceInterpreter(Protocol):
    def verify(self, reference: ReceiptReferenceV1, context: ProductionContextV1) -> VerifiedEvidenceV1: ...


class PreconditionsV1(StrictRecord):
    version: Literal["kairos.production-preconditions.v1"] = "kairos.production-preconditions.v1"
    outcome: Literal["PRECONDITIONS_VALIDATED_ONLY"] = "PRECONDITIONS_VALIDATED_ONLY"
    context: ProductionContextV1
    evidence_sha256: Digest
    verified_at: datetime
    valid_until: datetime
    live_ready: Literal[False] = False
    mutation_authority: Literal[False] = False

    _utc = field_validator("verified_at", "valid_until")(_aware)


def canonical_digest(value: BaseModel) -> str:
    return hashlib.sha256(
        json.dumps(value.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


class ProductionPreconditionsVerifier:
    def __init__(self, interpreters: Mapping[EvidenceKind, tuple[str, EvidenceInterpreter]]) -> None:
        self._interpreters = dict(interpreters)

    def verify(
        self,
        context: ProductionContextV1,
        references: tuple[ReceiptReferenceV1, ...],
        *,
        now: datetime,
    ) -> PreconditionsV1:
        _aware(now)
        context = ProductionContextV1.model_validate(context)
        references = tuple(ReceiptReferenceV1.model_validate(ref) for ref in references)
        if len(references) != len(EvidenceKind) or {ref.kind for ref in references} != set(EvidenceKind):
            raise ValueError("every independent production gate is required exactly once")
        if set(self._interpreters) != set(EvidenceKind):
            raise ValueError("production evidence interpreters are not fully provisioned")
        proofs: list[VerifiedEvidenceV1] = []
        for ref in sorted(references, key=lambda item: item.kind.value):
            issuer, interpreter = self._interpreters[ref.kind]
            if ref.issuer_id != issuer:
                raise ValueError("receipt issuer is not trusted for this gate")
            try:
                proof = interpreter.verify(ref, context)
            except Exception:
                raise ValueError("independent production evidence verification failed") from None
            if type(proof) is not VerifiedEvidenceV1 or proof.reference != ref or proof.context != context:
                raise ValueError("independent evidence identity/scope/policy mismatch")
            proof = VerifiedEvidenceV1.model_validate(proof)
            if not proof.verified_at <= now < proof.valid_until:
                raise ValueError("production evidence is stale or future-dated")
            if ref.kind is EvidenceKind.ADAPTIVE_SEALED_FORWARD and (
                proof.complete_forward_days is None or proof.complete_forward_days < 365
            ):
                raise ValueError("365 complete independent blind days are required")
            if ref.kind is EvidenceKind.ADAPTIVE_SEALED_TRADES and (
                proof.naturally_closed_simulated_trades is None
                or proof.naturally_closed_simulated_trades < 500
            ):
                raise ValueError("500 naturally closed simulated trades are required")
            proofs.append(proof)
        evidence_digest = hashlib.sha256(
            json.dumps(
                [proof.model_dump(mode="json") for proof in proofs], sort_keys=True, separators=(",", ":")
            ).encode()
        ).hexdigest()
        return PreconditionsV1(
            context=context,
            evidence_sha256=evidence_digest,
            verified_at=now,
            valid_until=min(proof.valid_until for proof in proofs),
        )


class ManualArmRequestV1(StrictRecord):
    version: Literal["kairos.manual-arm-request.v1"] = "kairos.manual-arm-request.v1"
    context: ProductionContextV1
    preconditions_sha256: Digest
    nonce: Identity
    owner_identity: Identity
    created_at: datetime
    expires_at: datetime
    dollar_cap: Decimal
    daily_stop_loss_usd: Decimal

    _utc = field_validator("created_at", "expires_at")(_aware)

    @field_validator("dollar_cap", "daily_stop_loss_usd")
    @classmethod
    def explicit_positive_limit(cls, value: Decimal) -> Decimal:
        if not value.is_finite() or value <= 0:
            raise ValueError("an explicit positive finite owner-supplied dollar limit is required")
        return value

    @model_validator(mode="after")
    def bounded(self) -> Self:
        if self.expires_at <= self.created_at or self.daily_stop_loss_usd > self.dollar_cap:
            raise ValueError("invalid manual-arm interval or stop-loss above dollar-cap")
        return self


class DurableNonceStore(Protocol):
    def consume_once(self, *, owner_identity: str, nonce: str, request_sha256: str) -> bool:
        """Atomically persist one claim; unknown outcome must never become retry permission."""
        ...


def validate_manual_arm(
    request: ManualArmRequestV1,
    preconditions: PreconditionsV1,
    *,
    expected_owner_identity: str,
    nonce_store: DurableNonceStore,
    now: datetime,
    maximum_lifetime: timedelta,
) -> Literal["MANUAL_REQUEST_VALIDATED_ONLY"]:
    """Offline validation only. No LIVE flag, capability, signer or order is created."""
    _aware(now)
    request = ManualArmRequestV1.model_validate(request)
    preconditions = PreconditionsV1.model_validate(preconditions)
    if maximum_lifetime <= timedelta(0):
        raise ValueError("reviewed manual-arm lifetime must be positive")
    if (
        request.context != preconditions.context
        or request.preconditions_sha256 != canonical_digest(preconditions)
        or request.owner_identity != expected_owner_identity
    ):
        raise ValueError("manual-arm scope, readiness digest or owner mismatch")
    if not preconditions.verified_at <= now < preconditions.valid_until:
        raise ValueError("preconditions are stale or future-dated")
    if not request.created_at <= now < request.expires_at <= preconditions.valid_until:
        raise ValueError("manual-arm request is stale, future-dated or beyond evidence validity")
    if request.expires_at - request.created_at > maximum_lifetime:
        raise ValueError("manual-arm lifetime exceeds the reviewed bound")
    try:
        admitted = nonce_store.consume_once(
            owner_identity=expected_owner_identity,
            nonce=request.nonce,
            request_sha256=canonical_digest(request),
        )
    except Exception:
        raise ValueError("manual-arm nonce outcome is unresolved; do not retry") from None
    if admitted is not True:
        raise ValueError("manual-arm nonce is already consumed or unresolved")
    return "MANUAL_REQUEST_VALIDATED_ONLY"
