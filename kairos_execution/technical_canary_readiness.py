"""Fixed technical-canary evidence profile; never grants LIVE authority.

This opt-in profile validates seven signed operational-safety gates for
preparing one short, manually armed test. It intentionally does not qualify
alpha, trading economics, account truth, signing authority, or host-loss
resilience. The full production profile and its evidence requirements remain
unchanged.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Sequence
from datetime import datetime
from decimal import Decimal
from types import MappingProxyType
from typing import Literal, Self

from pydantic import field_validator, model_validator

from .production_readiness import (
    Digest,
    EvidenceKind,
    PreconditionsV1,
    ProductionContextV1,
    ReceiptReferenceV1,
    StrictRecord,
    VerifiedEvidenceV1,
    _aware,
)
from .signed_evidence import (
    EvidenceResolver,
    IssuerPolicyV1,
    SignedReceiptInterpreter,
    SingleHostAlertReceiptInterpreter,
    canonical_bytes,
)
from .single_host_readiness import issuer_registry_sha256

TECHNICAL_CANARY_REQUIRED_KINDS: tuple[EvidenceKind, ...] = (
    EvidenceKind.PRIMARY_RECOVERY,
    EvidenceKind.SECURITY_REVIEW,
    EvidenceKind.MANAGED_CUSTODY,
    EvidenceKind.ALERT_DELIVERY,
    EvidenceKind.GLOBAL_OPERATOR_CONTROL,
    EvidenceKind.PROD_ACCOUNT_PAIRING,
    EvidenceKind.PRODUCTION_LIMITS,
)

TECHNICAL_CANARY_EXCLUDED_FULL_LIVE_GATES: tuple[EvidenceKind, ...] = (
    EvidenceKind.ADAPTIVE_SEALED_FORWARD,
    EvidenceKind.ADAPTIVE_SEALED_TRADES,
    EvidenceKind.CRASH_NET_GATE,
    EvidenceKind.DEV_READONLY_24H,
    EvidenceKind.DEV_CANARY,
    EvidenceKind.DEV_SOAK_TCA,
    EvidenceKind.OFFHOST_RESTORE,
)


class TechnicalCanaryProfileV1(StrictRecord):
    """Immutable profile constants; no caller-selectable gate or cap options."""

    version: Literal["kairos.technical-canary-profile.v1"] = "kairos.technical-canary-profile.v1"
    profile_id: Literal["technical-real-money-canary-only"] = "technical-real-money-canary-only"
    purpose: Literal["TECHNICAL_REAL_MONEY_CANARY_ONLY"] = "TECHNICAL_REAL_MONEY_CANARY_ONLY"
    required_evidence_kinds: tuple[EvidenceKind, ...] = TECHNICAL_CANARY_REQUIRED_KINDS
    excluded_full_live_gates: tuple[EvidenceKind, ...] = TECHNICAL_CANARY_EXCLUDED_FULL_LIVE_GATES
    max_entry_admissions: Literal[1] = 1
    max_entry_window_seconds: Literal[600] = 600
    manual_arm_required: Literal[True] = True
    alpha_qualified: Literal[False] = False
    live_ready: Literal[False] = False
    mutation_authority: Literal[False] = False
    host_loss_resilience: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"

    @model_validator(mode="after")
    def immutable_profile(self) -> Self:
        if self.required_evidence_kinds != TECHNICAL_CANARY_REQUIRED_KINDS:
            raise ValueError("technical canary required evidence set is fixed")
        if self.excluded_full_live_gates != TECHNICAL_CANARY_EXCLUDED_FULL_LIVE_GATES:
            raise ValueError("technical canary exclusions are fixed")
        if len(self.required_evidence_kinds) != 7 or len(set(self.required_evidence_kinds)) != 7:
            raise ValueError("technical canary requires exactly seven unique safety gates")
        if set(self.required_evidence_kinds) & set(self.excluded_full_live_gates):
            raise ValueError("technical canary cannot require excluded full-LIVE research gates")
        return self


TECHNICAL_CANARY_PROFILE = TechnicalCanaryProfileV1()


def technical_canary_profile_sha256() -> str:
    return hashlib.sha256(canonical_bytes(TECHNICAL_CANARY_PROFILE)).hexdigest()


def _limits_binding_sha256(owner_identity: str, dollar_cap: Decimal, daily_stop_loss_usd: Decimal) -> str:
    def decimal_text(value: Decimal) -> str:
        return format(value.normalize(), "f")

    return hashlib.sha256(
        canonical_bytes(
            {
                "version": "kairos.technical-canary-limits-binding.v1",
                "owner_identity": owner_identity,
                "dollar_cap": decimal_text(dollar_cap),
                "daily_stop_loss_usd": decimal_text(daily_stop_loss_usd),
            }
        )
    ).hexdigest()


class TechnicalCanaryPreconditionsV1(StrictRecord):
    """Seven-proof result, readiness-only and explicitly non-authorizing."""

    version: Literal["kairos.technical-canary-preconditions.v1"] = "kairos.technical-canary-preconditions.v1"
    outcome: Literal["TECHNICAL_CANARY_PRECONDITIONS_VALIDATED_ONLY"] = (
        "TECHNICAL_CANARY_PRECONDITIONS_VALIDATED_ONLY"
    )
    purpose: Literal["TECHNICAL_REAL_MONEY_CANARY_ONLY"] = "TECHNICAL_REAL_MONEY_CANARY_ONLY"
    profile_sha256: Digest
    issuer_registry_sha256: Digest
    limits_binding_sha256: Digest
    required_evidence_kinds: tuple[EvidenceKind, ...] = TECHNICAL_CANARY_REQUIRED_KINDS
    max_entry_admissions: Literal[1] = 1
    max_entry_window_seconds: Literal[600] = 600
    manual_arm_required: Literal[True] = True
    alpha_qualified: Literal[False] = False
    host_loss_resilience: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"
    preconditions: PreconditionsV1
    verified_at: datetime
    live_ready: Literal[False] = False
    mutation_authority: Literal[False] = False

    _utc = field_validator("verified_at")(_aware)

    @model_validator(mode="after")
    def fixed_profile_and_limits_binding(self) -> Self:
        if self.profile_sha256 != technical_canary_profile_sha256():
            raise ValueError("technical canary result is not bound to its fixed profile")
        if self.required_evidence_kinds != TECHNICAL_CANARY_REQUIRED_KINDS:
            raise ValueError("technical canary result must carry the exact seven-gate set")
        if len(set(self.required_evidence_kinds)) != 7:
            raise ValueError("technical canary result must carry seven unique safety gates")
        if self.preconditions.live_ready or self.preconditions.mutation_authority:
            raise ValueError("nested preconditions cannot grant LIVE or mutation authority")
        if self.preconditions.verified_at != self.verified_at:
            raise ValueError("nested precondition timestamp differs from its profile wrapper")
        if self.preconditions.valid_until <= self.verified_at:
            raise ValueError("technical canary evidence validity interval is empty")
        if self.preconditions.daily_stop_loss_usd > self.preconditions.dollar_cap:
            raise ValueError("signed daily stop-loss cannot exceed the signed dollar cap")
        expected_binding = _limits_binding_sha256(
            self.preconditions.owner_identity,
            self.preconditions.dollar_cap,
            self.preconditions.daily_stop_loss_usd,
        )
        if not hmac.compare_digest(self.limits_binding_sha256, expected_binding):
            raise ValueError("technical canary signed limits binding differs from nested preconditions")
        return self


class TechnicalCanaryPreconditionsVerifier:
    """Verify exactly seven signed operational gates under an independent issuer pin."""

    def __init__(
        self,
        registry: Sequence[IssuerPolicyV1],
        resolver: EvidenceResolver,
        *,
        pinned_registry_sha256: str,
    ) -> None:
        if (
            not isinstance(pinned_registry_sha256, str)
            or re.fullmatch(r"[a-f0-9]{64}", pinned_registry_sha256) is None
        ):
            raise ValueError("an independently pinned issuer-registry digest is required")
        policies = tuple(IssuerPolicyV1.model_validate(item) for item in registry)
        if not policies:
            raise ValueError("a pinned non-empty evidence issuer registry is required")
        actual_digest = issuer_registry_sha256(policies)
        if not hmac.compare_digest(actual_digest, pinned_registry_sha256):
            raise ValueError("issuer registry does not match the independently pinned digest")

        interpreters = {
            kind: (
                SingleHostAlertReceiptInterpreter(policies, resolver)
                if kind is EvidenceKind.ALERT_DELIVERY
                else SignedReceiptInterpreter(kind, policies, resolver)
            )
            for kind in TECHNICAL_CANARY_REQUIRED_KINDS
        }
        self._registry = policies
        self._registry_sha256 = actual_digest
        self._interpreters = MappingProxyType(interpreters)

    @property
    def registry_sha256(self) -> str:
        return self._registry_sha256

    def verify(
        self,
        context: ProductionContextV1,
        references: Sequence[ReceiptReferenceV1],
        *,
        now: datetime,
    ) -> TechnicalCanaryPreconditionsV1:
        _aware(now)
        context = ProductionContextV1.model_validate(context)
        refs = tuple(ReceiptReferenceV1.model_validate(ref) for ref in references)
        kinds = tuple(ref.kind for ref in refs)
        if len(refs) != 7 or set(kinds) != set(TECHNICAL_CANARY_REQUIRED_KINDS):
            raise ValueError("exactly the seven technical canary safety gates are required once each")

        proofs: list[VerifiedEvidenceV1] = []
        for kind in TECHNICAL_CANARY_REQUIRED_KINDS:
            ref = next(ref for ref in refs if ref.kind is kind)
            try:
                proof = self._interpreters[kind].verify(ref, context)
            except Exception:
                raise ValueError("independent technical canary evidence verification failed") from None
            if type(proof) is not VerifiedEvidenceV1 or proof.reference != ref or proof.context != context:
                raise ValueError("technical canary evidence identity/scope mismatch")
            proof = VerifiedEvidenceV1.model_validate(proof)
            if any(
                value is None
                for value in (proof.facts_sha256, proof.facts_schema_sha256, proof.verified_issuer_key_id)
            ):
                raise ValueError("unsigned technical canary gate assertions are not accepted")
            if not proof.verified_at <= now < proof.valid_until:
                raise ValueError("technical canary evidence is stale or future-dated")
            proofs.append(proof)

        bindings = {proof.reference.kind: json.loads(proof.binding_facts_json or "{}") for proof in proofs}
        custody = bindings[EvidenceKind.MANAGED_CUSTODY]
        pairing = bindings[EvidenceKind.PROD_ACCOUNT_PAIRING]
        limits = bindings[EvidenceKind.PRODUCTION_LIMITS]
        if (custody.get("wallet_address"), custody.get("chain_id")) != (
            pairing.get("wallet_address"),
            pairing.get("chain_id"),
        ):
            raise ValueError("custody and PROD account pairing wallet/chain mismatch")
        if not custody.get("custody_reference") or not limits.get("owner_identity"):
            raise ValueError("typed custody and signed owner limits require exact identities")

        profile_hash = technical_canary_profile_sha256()
        evidence_payload = {
            "profile_sha256": profile_hash,
            "issuer_registry_sha256": self._registry_sha256,
            "required_evidence_kinds": [kind.value for kind in TECHNICAL_CANARY_REQUIRED_KINDS],
            "proofs": [proof.model_dump(mode="json") for proof in proofs],
        }
        evidence_digest = hashlib.sha256(
            json.dumps(evidence_payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        ).hexdigest()
        dollar_cap = Decimal(limits["dollar_cap"])
        daily_stop_loss = Decimal(limits["daily_stop_loss_usd"])
        nested = PreconditionsV1(
            context=context,
            evidence_sha256=evidence_digest,
            verified_at=now,
            valid_until=min(proof.valid_until for proof in proofs),
            owner_identity=limits["owner_identity"],
            dollar_cap=dollar_cap,
            daily_stop_loss_usd=daily_stop_loss,
        )
        return TechnicalCanaryPreconditionsV1(
            profile_sha256=profile_hash,
            issuer_registry_sha256=self._registry_sha256,
            limits_binding_sha256=_limits_binding_sha256(
                limits["owner_identity"], dollar_cap, daily_stop_loss
            ),
            preconditions=nested,
            verified_at=now,
        )


__all__ = [
    "TECHNICAL_CANARY_REQUIRED_KINDS",
    "TECHNICAL_CANARY_EXCLUDED_FULL_LIVE_GATES",
    "TechnicalCanaryProfileV1",
    "TECHNICAL_CANARY_PROFILE",
    "technical_canary_profile_sha256",
    "TechnicalCanaryPreconditionsV1",
    "TechnicalCanaryPreconditionsVerifier",
]
