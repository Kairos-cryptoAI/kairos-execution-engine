"""Versioned single-host production evidence profile; never grants live authority.

This profile deliberately reuses the V1 signed receipt schemas and interpreter,
but defines a smaller, explicit gate set that does not require a demo-venue
campaign or an off-host restore.  ``MANAGED_CUSTODY`` remains a legacy evidence
kind: its existing typed-custody facts are provider-neutral and do not require a
cloud KMS literal.  The profile still requires a valid custody proof bound to
the paired production wallet and chain.

The issuer registry digest passed to the verifier must be pinned independently
by the deployment composition root.  A matching digest proves registry
identity, not producer competence or runtime authorization.  Results below are
readiness records only; there is no capability issuer, order path, or signer.
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
    SINGLE_HOST_REQUIRED_ALERT_NAMES,
    EvidenceResolver,
    IssuerPolicyV1,
    SignedReceiptInterpreter,
    SingleHostAlertReceiptInterpreter,
    canonical_bytes,
)

SINGLE_HOST_REQUIRED_KINDS: tuple[EvidenceKind, ...] = (
    EvidenceKind.ADAPTIVE_SEALED_FORWARD,
    EvidenceKind.ADAPTIVE_SEALED_TRADES,
    EvidenceKind.CRASH_NET_GATE,
    EvidenceKind.PRIMARY_RECOVERY,
    EvidenceKind.SECURITY_REVIEW,
    EvidenceKind.MANAGED_CUSTODY,
    EvidenceKind.ALERT_DELIVERY,
    EvidenceKind.GLOBAL_OPERATOR_CONTROL,
    EvidenceKind.PROD_ACCOUNT_PAIRING,
    EvidenceKind.PRODUCTION_LIMITS,
)

_EXCLUDED_KINDS = frozenset(EvidenceKind) - frozenset(SINGLE_HOST_REQUIRED_KINDS)


class SingleHostProductionProfileV1(StrictRecord):
    """Fixed profile. Callers cannot supply or edit the required gate set."""

    version: Literal["kairos.single-host-production-profile.v1"] = "kairos.single-host-production-profile.v1"
    profile_id: Literal["single-host-production"] = "single-host-production"
    required_evidence_kinds: tuple[EvidenceKind, ...] = SINGLE_HOST_REQUIRED_KINDS
    excluded_engineering_blockers: tuple[EvidenceKind, ...] = tuple(
        kind for kind in EvidenceKind if kind in _EXCLUDED_KINDS
    )
    required_local_alert_names: tuple[str, ...] = SINGLE_HOST_REQUIRED_ALERT_NAMES
    host_loss_resilience: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"
    live_ready: Literal[False] = False
    mutation_authority: Literal[False] = False

    @model_validator(mode="after")
    def fixed_contract(self) -> Self:
        if self.required_evidence_kinds != SINGLE_HOST_REQUIRED_KINDS:
            raise ValueError("single-host profile gate set is immutable")
        expected_excluded = tuple(kind for kind in EvidenceKind if kind in _EXCLUDED_KINDS)
        if self.excluded_engineering_blockers != expected_excluded:
            raise ValueError("single-host profile exclusions are immutable")
        if self.required_local_alert_names != SINGLE_HOST_REQUIRED_ALERT_NAMES:
            raise ValueError("single-host local alert set is immutable")
        return self


SINGLE_HOST_PROFILE = SingleHostProductionProfileV1()


def single_host_profile_sha256() -> str:
    return hashlib.sha256(canonical_bytes(SINGLE_HOST_PROFILE)).hexdigest()


def issuer_registry_sha256(registry: Sequence[IssuerPolicyV1]) -> str:
    """Canonical digest of the exact issuer policies a deployment pins."""

    policies = tuple(IssuerPolicyV1.model_validate(item) for item in registry)
    ordered = sorted(policies, key=lambda item: (item.issuer_id, item.key_id))
    payload = json.dumps(
        [item.model_dump(mode="json") for item in ordered],
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    return hashlib.sha256(payload).hexdigest()


class SingleHostPreconditionsV1(StrictRecord):
    """Profile-bound evidence result, explicitly not an execution authorization."""

    version: Literal["kairos.single-host-preconditions.v1"] = "kairos.single-host-preconditions.v1"
    outcome: Literal["SINGLE_HOST_PRECONDITIONS_VALIDATED_ONLY"] = "SINGLE_HOST_PRECONDITIONS_VALIDATED_ONLY"
    profile_version: Literal["kairos.single-host-production-profile.v1"] = (
        "kairos.single-host-production-profile.v1"
    )
    profile_sha256: Digest
    issuer_registry_sha256: Digest
    host_loss_resilience: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"
    preconditions: PreconditionsV1
    verified_at: datetime
    live_ready: Literal[False] = False
    mutation_authority: Literal[False] = False

    _utc = field_validator("verified_at")(_aware)

    @model_validator(mode="after")
    def bound_profile_and_nested_result(self) -> Self:
        if self.profile_sha256 != single_host_profile_sha256():
            raise ValueError("preconditions are not bound to the immutable single-host profile")
        if self.host_loss_resilience != "NOT_ESTABLISHED":
            raise ValueError("single-host preconditions cannot claim full-host-loss resilience")
        if self.preconditions.live_ready or self.preconditions.mutation_authority:
            raise ValueError("nested preconditions cannot grant live authority")
        if self.preconditions.verified_at != self.verified_at:
            raise ValueError("nested precondition timestamp differs from the profile wrapper")
        return self


class SingleHostProductionPreconditionsVerifier:
    """Verify the fixed single-host gate set using concrete signed interpreters."""

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

        # Construct every interpreter here from the exact same immutable policy
        # tuple; callers cannot inject a duck-typed or subset interpreter.
        interpreters = {
            kind: (
                SingleHostAlertReceiptInterpreter(policies, resolver)
                if kind is EvidenceKind.ALERT_DELIVERY
                else SignedReceiptInterpreter(kind, policies, resolver)
            )
            for kind in SINGLE_HOST_REQUIRED_KINDS
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
    ) -> SingleHostPreconditionsV1:
        _aware(now)
        context = ProductionContextV1.model_validate(context)
        refs = tuple(ReceiptReferenceV1.model_validate(ref) for ref in references)
        kinds = tuple(ref.kind for ref in refs)
        if len(refs) != len(SINGLE_HOST_REQUIRED_KINDS) or set(kinds) != set(SINGLE_HOST_REQUIRED_KINDS):
            raise ValueError("every single-host production gate is required exactly once")

        proofs: list[VerifiedEvidenceV1] = []
        for kind in SINGLE_HOST_REQUIRED_KINDS:
            ref = next(ref for ref in refs if ref.kind is kind)
            try:
                proof = self._interpreters[kind].verify(ref, context)
            except Exception:
                raise ValueError("independent single-host production evidence verification failed") from None
            if type(proof) is not VerifiedEvidenceV1 or proof.reference != ref or proof.context != context:
                raise ValueError("independent evidence identity/scope/policy mismatch")
            proof = VerifiedEvidenceV1.model_validate(proof)
            if any(
                value is None
                for value in (proof.facts_sha256, proof.facts_schema_sha256, proof.verified_issuer_key_id)
            ):
                raise ValueError("unsigned or uninterpreted gate assertions cannot qualify preconditions")
            if not proof.verified_at <= now < proof.valid_until:
                raise ValueError("single-host production evidence is stale or future-dated")
            if kind is EvidenceKind.ADAPTIVE_SEALED_FORWARD and (
                proof.complete_forward_days is None or proof.complete_forward_days < 365
            ):
                raise ValueError("365 complete independent blind days are required")
            if kind is EvidenceKind.ADAPTIVE_SEALED_TRADES and (
                proof.naturally_closed_simulated_trades is None
                or proof.naturally_closed_simulated_trades < 500
            ):
                raise ValueError("500 naturally closed simulated trades are required")
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
        # SignedReceiptInterpreter has already bound PairingFactsV1.remote_account_id
        # to context.remote_account_id.  That field is intentionally not copied
        # into its compact binding_facts_json projection.
        if not custody.get("custody_reference"):
            raise ValueError("typed custody proof lacks a custody identity")
        if not limits.get("owner_identity"):
            raise ValueError("production limits lack an owner identity")

        evidence_payload = {
            "profile_sha256": single_host_profile_sha256(),
            "issuer_registry_sha256": self._registry_sha256,
            "proofs": [proof.model_dump(mode="json") for proof in proofs],
        }
        evidence_digest = hashlib.sha256(
            json.dumps(evidence_payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        ).hexdigest()
        nested = PreconditionsV1(
            context=context,
            evidence_sha256=evidence_digest,
            verified_at=now,
            valid_until=min(proof.valid_until for proof in proofs),
            owner_identity=limits["owner_identity"],
            dollar_cap=Decimal(limits["dollar_cap"]),
            daily_stop_loss_usd=Decimal(limits["daily_stop_loss_usd"]),
        )
        return SingleHostPreconditionsV1(
            profile_sha256=single_host_profile_sha256(),
            issuer_registry_sha256=self._registry_sha256,
            host_loss_resilience="NOT_ESTABLISHED",
            preconditions=nested,
            verified_at=now,
        )
