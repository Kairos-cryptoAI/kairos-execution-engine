"""Offline technical-canary profile tests use synthetic signed receipts only."""

from __future__ import annotations

import base64
import hashlib
from datetime import timedelta
from decimal import Decimal

import pytest
from pydantic import ValidationError

from kairos_execution.production_readiness import EvidenceKind, ProductionPreconditionsVerifier
from kairos_execution.signed_evidence import SignedReceiptV1, canonical_bytes
from kairos_execution.single_host_readiness import (
    SINGLE_HOST_REQUIRED_KINDS,
    issuer_registry_sha256,
)
from kairos_execution.technical_canary_readiness import (
    TECHNICAL_CANARY_EXCLUDED_FULL_LIVE_GATES,
    TECHNICAL_CANARY_PROFILE,
    TECHNICAL_CANARY_REQUIRED_KINDS,
    TechnicalCanaryPreconditionsV1,
    TechnicalCanaryPreconditionsVerifier,
    TechnicalCanaryProfileV1,
    technical_canary_profile_sha256,
)
from tests.production_evidence_fixtures import NOW
from tests.test_signed_evidence import reissue
from tests.test_single_host_readiness import single_host_gate_fixture


def _setup_canary():
    single_host, all_refs, resolver, context, _private, policy = single_host_gate_fixture()
    registry = (policy,)
    refs = tuple(ref for ref in all_refs if ref.kind in TECHNICAL_CANARY_REQUIRED_KINDS)
    verifier = TechnicalCanaryPreconditionsVerifier(
        registry, resolver, pinned_registry_sha256=issuer_registry_sha256(registry)
    )
    return verifier, refs, resolver, context, registry, policy, single_host, all_refs


def test_fixed_technical_canary_profile_validates_exact_seven_signed_safety_gates_only():
    verifier, refs, _, context, registry, _, single_host, _ = _setup_canary()

    result = verifier.verify(context, refs, now=NOW)

    assert len(TECHNICAL_CANARY_REQUIRED_KINDS) == 7
    assert set(ref.kind for ref in refs) == set(TECHNICAL_CANARY_REQUIRED_KINDS)
    assert result.purpose == "TECHNICAL_REAL_MONEY_CANARY_ONLY"
    assert result.required_evidence_kinds == TECHNICAL_CANARY_REQUIRED_KINDS
    assert result.profile_sha256 == technical_canary_profile_sha256()
    assert result.issuer_registry_sha256 == issuer_registry_sha256(registry)
    assert result.preconditions.evidence_sha256
    assert result.preconditions.owner_identity == "owner"
    assert result.preconditions.dollar_cap == Decimal("10")
    assert result.preconditions.daily_stop_loss_usd == Decimal("1")
    assert result.limits_binding_sha256
    assert result.max_entry_admissions == 1
    assert result.max_entry_window_seconds == 600
    assert result.manual_arm_required is True
    assert result.alpha_qualified is False
    assert result.live_ready is False and result.mutation_authority is False
    assert result.host_loss_resilience == "NOT_ESTABLISHED"
    with pytest.raises(ValueError, match="single-host production gate"):
        single_host.verify(context, refs, now=NOW)
    assert SINGLE_HOST_REQUIRED_KINDS != TECHNICAL_CANARY_REQUIRED_KINDS


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "extra"])
def test_profile_rejects_missing_duplicate_or_extra_references(mutation: str):
    verifier, refs, _, context, _, _, _, all_refs = _setup_canary()
    if mutation == "missing":
        changed = refs[:-1]
    elif mutation == "duplicate":
        changed = (*refs[:-1], refs[0])
    else:
        excluded = next(ref for ref in all_refs if ref.kind is EvidenceKind.CRASH_NET_GATE)
        changed = (*refs, excluded)

    with pytest.raises(ValueError, match="exactly the seven"):
        verifier.verify(context, changed, now=NOW)


@pytest.mark.parametrize("now", [NOW - timedelta(seconds=1), NOW + timedelta(minutes=31)])
def test_stale_or_future_signed_proofs_are_rejected(now):
    verifier, refs, _, context, *_ = _setup_canary()
    with pytest.raises(ValueError, match="stale or future-dated"):
        verifier.verify(context, refs, now=now)


def test_pinned_registry_and_receipt_issuer_must_match():
    verifier, refs, resolver, context, registry, _policy, *_ = _setup_canary()
    with pytest.raises(ValueError, match="independently pinned"):
        TechnicalCanaryPreconditionsVerifier(registry, resolver, pinned_registry_sha256="f" * 64)

    wrong_issuer = refs[0].model_copy(update={"issuer_id": "unregistered-issuer"})
    changed = (wrong_issuer, *refs[1:])
    with pytest.raises(ValueError, match="independent technical canary evidence"):
        verifier.verify(context, changed, now=NOW)


def test_invalid_signature_is_rejected_even_when_reference_hash_is_updated():
    verifier, refs, resolver, context, *_ = _setup_canary()
    ref = refs[0]
    signed = SignedReceiptV1.model_validate_json(resolver.receipt_bytes(ref.content_sha256))
    invalid = signed.model_copy(update={"signature_base64": base64.b64encode(bytes(64)).decode()})
    raw = canonical_bytes(invalid)
    digest = hashlib.sha256(raw).hexdigest()
    resolver.receipts[digest] = raw
    changed_ref = ref.model_copy(update={"content_sha256": digest})

    with pytest.raises(ValueError, match="independent technical canary evidence"):
        verifier.verify(context, (changed_ref, *refs[1:]), now=NOW)


def test_custody_pairing_wallet_and_chain_must_match():
    bundle = single_host_gate_fixture()
    _, _, resolver, context, _, policy = bundle
    changed_refs = reissue(
        bundle,
        EvidenceKind.MANAGED_CUSTODY,
        facts_change=lambda facts: facts.update(wallet_address="0x" + "34" * 20),
    )
    refs = tuple(ref for ref in changed_refs if ref.kind in TECHNICAL_CANARY_REQUIRED_KINDS)
    registry = (policy,)
    verifier = TechnicalCanaryPreconditionsVerifier(
        registry, resolver, pinned_registry_sha256=issuer_registry_sha256(registry)
    )

    with pytest.raises(ValueError, match="wallet/chain mismatch"):
        verifier.verify(context, refs, now=NOW)


def test_limits_binding_cannot_be_rebound_and_profile_numbers_are_fixed():
    verifier, refs, _, context, *_ = _setup_canary()
    result = verifier.verify(context, refs, now=NOW)
    changed_nested = result.preconditions.model_copy(update={"dollar_cap": Decimal("11")})
    changed = result.model_copy(update={"preconditions": changed_nested})
    with pytest.raises(ValidationError, match="limits binding"):
        TechnicalCanaryPreconditionsV1.model_validate_json(changed.model_dump_json())

    with pytest.raises(ValidationError):
        TechnicalCanaryProfileV1(max_entry_admissions=2)
    with pytest.raises(ValidationError, match="fixed"):
        TechnicalCanaryProfileV1(required_evidence_kinds=tuple(reversed(TECHNICAL_CANARY_REQUIRED_KINDS)))
    assert TECHNICAL_CANARY_PROFILE.max_entry_admissions == 1
    assert TECHNICAL_CANARY_PROFILE.max_entry_window_seconds == 600
    assert set(TECHNICAL_CANARY_EXCLUDED_FULL_LIVE_GATES) == {
        EvidenceKind.ADAPTIVE_SEALED_FORWARD,
        EvidenceKind.ADAPTIVE_SEALED_TRADES,
        EvidenceKind.CRASH_NET_GATE,
        EvidenceKind.DEV_READONLY_24H,
        EvidenceKind.DEV_CANARY,
        EvidenceKind.DEV_SOAK_TCA,
        EvidenceKind.OFFHOST_RESTORE,
    }


def test_full_production_verifier_still_rejects_the_seven_gate_canary_set():
    verifier, refs, _, context, *_ = _setup_canary()
    old_full = ProductionPreconditionsVerifier({})

    with pytest.raises(ValueError, match="every independent production gate"):
        old_full.verify(context, refs, now=NOW)
    assert len(refs) == 7
