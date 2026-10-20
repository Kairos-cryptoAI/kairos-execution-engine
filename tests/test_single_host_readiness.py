import base64
import hashlib
import json
from datetime import timedelta

import pytest
from pydantic import ValidationError

from kairos_execution.production_readiness import EvidenceKind
from kairos_execution.signed_evidence import (
    SINGLE_HOST_REQUIRED_ALERT_NAMES,
    FrozenGatePolicyV1,
    SignedReceiptBodyV1,
    SignedReceiptV1,
    SingleHostAlertFactsV1,
    SingleHostAlertReceiptInterpreter,
    canonical_bytes,
)
from kairos_execution.single_host_readiness import (
    SINGLE_HOST_PROFILE,
    SINGLE_HOST_REQUIRED_KINDS,
    SingleHostPreconditionsV1,
    SingleHostProductionPreconditionsVerifier,
    SingleHostProductionProfileV1,
    issuer_registry_sha256,
    single_host_profile_sha256,
)
from tests.production_evidence_fixtures import NOW, H, signed_gate_fixture
from tests.test_signed_evidence import reissue


def single_host_gate_fixture():
    """Build test-only signatures bound to a fresh local-alert frozen policy."""

    _, all_refs, resolver, old_context, private, old_policy = signed_gate_fixture()
    original_policy = FrozenGatePolicyV1.model_validate_json(
        canonical_bytes(json.loads(resolver.artifacts[old_context.frozen_policy_sha256]))
    )
    local_policy = original_policy.model_copy(
        update={"required_alert_names": SINGLE_HOST_REQUIRED_ALERT_NAMES}
    )
    policy_bytes = canonical_bytes(local_policy)
    policy_hash = hashlib.sha256(policy_bytes).hexdigest()
    resolver.artifacts[policy_hash] = policy_bytes
    context = old_context.model_copy(update={"frozen_policy_sha256": policy_hash})
    policy = old_policy.model_copy(update={"context": context})

    restart_artifact = b"SYNTHETIC_TEST_ONLY_LOCAL_SUPERVISOR_RESTART"
    health_artifact = b"SYNTHETIC_TEST_ONLY_LOCAL_PROCESS_HEALTH"
    restart_hash = hashlib.sha256(restart_artifact).hexdigest()
    health_hash = hashlib.sha256(health_artifact).hexdigest()
    resolver.artifacts[restart_hash] = restart_artifact
    resolver.artifacts[health_hash] = health_artifact

    new_refs = []
    alert_facts_json = canonical_bytes(
        SingleHostAlertFactsV1(
            artifact_sha256s=(H, restart_hash, health_hash),
            required_alert_names=SINGLE_HOST_REQUIRED_ALERT_NAMES,
            deliveries=(
                dict(
                    alert_name=SINGLE_HOST_REQUIRED_ALERT_NAMES[0],
                    firing_event_sha256=H,
                    resolved_event_sha256=H,
                    receiver_identity="owner-alarm",
                    firing_received_at=NOW - timedelta(minutes=4),
                    resolved_received_at=NOW - timedelta(minutes=3),
                    owner_acknowledged_at=NOW - timedelta(minutes=2),
                ),
                dict(
                    alert_name=SINGLE_HOST_REQUIRED_ALERT_NAMES[1],
                    firing_event_sha256=H,
                    resolved_event_sha256=H,
                    receiver_identity="owner-alarm",
                    firing_received_at=NOW - timedelta(minutes=2),
                    resolved_received_at=NOW - timedelta(minutes=1),
                    owner_acknowledged_at=NOW,
                ),
            ),
            notifier_restart_receipt_sha256=H,
            local_supervisor_identity="local-process-supervisor",
            local_supervisor_restart_receipt_sha256=restart_hash,
            local_health_check_receipt_sha256=health_hash,
            host_loss_resilience="NOT_ESTABLISHED",
            unknown_sends=0,
        )
    ).decode()
    facts_schema_sha256 = hashlib.sha256(
        canonical_bytes(SingleHostAlertFactsV1.model_json_schema())
    ).hexdigest()

    for ref in all_refs:
        old_raw = resolver.receipts[ref.content_sha256]
        receipt = SignedReceiptV1.model_validate_json(old_raw)
        body_data = receipt.body.model_dump(mode="json")
        body_data["context"] = context.model_dump(mode="json")
        if ref.kind is EvidenceKind.ALERT_DELIVERY:
            body_data["facts_json"] = alert_facts_json
            body_data["facts_schema_sha256"] = facts_schema_sha256
        body = SignedReceiptBodyV1.model_validate_json(canonical_bytes(body_data))
        signed = SignedReceiptV1(
            body=body,
            signature_base64=base64.b64encode(
                private.sign(b"kairos.signed-production-evidence.v1\x00" + canonical_bytes(body))
            ).decode(),
        )
        raw = canonical_bytes(signed)
        digest = hashlib.sha256(raw).hexdigest()
        resolver.receipts[digest] = raw
        new_refs.append(ref.model_copy(update={"content_sha256": digest}))

    registry = (policy,)
    verifier = SingleHostProductionPreconditionsVerifier(
        registry, resolver, pinned_registry_sha256=issuer_registry_sha256(registry)
    )
    return verifier, tuple(new_refs), resolver, context, private, policy


def setup_single_host():
    verifier, all_refs, resolver, context, private, policy = single_host_gate_fixture()
    registry = (policy,)
    refs = tuple(ref for ref in all_refs if ref.kind in SINGLE_HOST_REQUIRED_KINDS)
    return verifier, refs, resolver, context, registry, policy, private, all_refs


def test_single_host_profile_is_fixed_and_does_not_grant_authority():
    verifier, refs, _, context, _, _, _, _ = setup_single_host()
    result = verifier.verify(context, refs, now=NOW)
    alert_ref = next(ref for ref in refs if ref.kind is EvidenceKind.ALERT_DELIVERY)
    alert_receipt = json.loads(
        verifier._interpreters[EvidenceKind.ALERT_DELIVERY]._resolver.receipt_bytes(alert_ref.content_sha256)
    )
    alert_facts = json.loads(alert_receipt["body"]["facts_json"])

    assert SINGLE_HOST_PROFILE.required_evidence_kinds == SINGLE_HOST_REQUIRED_KINDS
    assert set(SINGLE_HOST_REQUIRED_KINDS) == set(EvidenceKind) - {
        EvidenceKind.DEV_READONLY_24H,
        EvidenceKind.DEV_CANARY,
        EvidenceKind.DEV_SOAK_TCA,
        EvidenceKind.OFFHOST_RESTORE,
    }
    assert result.profile_sha256 == single_host_profile_sha256()
    assert result.preconditions.evidence_sha256
    assert result.preconditions.owner_identity == "owner"
    assert result.preconditions.dollar_cap > 0
    assert result.preconditions.daily_stop_loss_usd > 0
    assert result.live_ready is False and result.mutation_authority is False
    assert result.host_loss_resilience == "NOT_ESTABLISHED"
    assert alert_facts["host_loss_resilience"] == "NOT_ESTABLISHED"
    assert "independent_host_loss_receipt_sha256" not in alert_facts
    assert result.preconditions.live_ready is False
    assert result.preconditions.mutation_authority is False


@pytest.mark.parametrize(
    "change",
    [
        lambda facts: facts.update(host_loss_resilience="ESTABLISHED"),
        lambda facts: facts.pop("local_health_check_receipt_sha256"),
    ],
)
def test_single_host_alert_rejects_host_loss_claim_or_missing_local_proof(change):
    bundle = single_host_gate_fixture()
    verifier, _, _, context, _, _ = bundle
    changed_refs = reissue(bundle, EvidenceKind.ALERT_DELIVERY, facts_change=change)
    required_refs = tuple(ref for ref in changed_refs if ref.kind in SINGLE_HOST_REQUIRED_KINDS)
    with pytest.raises(ValueError, match="independent single-host production evidence"):
        verifier.verify(context, required_refs, now=NOW)


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "excluded-extra"])
def test_gate_set_requires_exactly_ten_profile_kinds(mutation):
    verifier, refs, _, context, _, _, _, _ = setup_single_host()
    if mutation == "missing":
        changed = refs[:-1]
    elif mutation == "duplicate":
        changed = (*refs[:-1], refs[0])
    else:
        _, all_refs, _, _, *_ = signed_gate_fixture()
        excluded = next(ref for ref in all_refs if ref.kind is EvidenceKind.DEV_CANARY)
        changed = (*refs, excluded)
    with pytest.raises(ValueError, match="single-host production gate"):
        verifier.verify(context, changed, now=NOW)


def test_registry_must_match_independent_pin_and_uses_one_registry_for_all_gates():
    _, refs, resolver, context, registry, policy, *_ = setup_single_host()
    pinned = issuer_registry_sha256(registry)
    with pytest.raises(ValueError, match="independently pinned"):
        SingleHostProductionPreconditionsVerifier(registry, resolver, pinned_registry_sha256="f" * 64)

    changed = (policy.model_copy(update={"key_id": "substituted-key"}),)
    with pytest.raises(ValueError, match="independently pinned"):
        SingleHostProductionPreconditionsVerifier(changed, resolver, pinned_registry_sha256=pinned)

    verifier = SingleHostProductionPreconditionsVerifier(registry, resolver, pinned_registry_sha256=pinned)
    assert verifier.registry_sha256 == pinned
    assert verifier.verify(context, refs, now=NOW).issuer_registry_sha256 == pinned


def test_signed_receipt_byte_tampering_is_rejected():
    verifier, refs, resolver, context, *_ = setup_single_host()
    ref = refs[0]
    receipt = resolver.receipts[ref.content_sha256]
    resolver.receipts[ref.content_sha256] = receipt[:-1] + bytes([receipt[-1] ^ 1])
    with pytest.raises(ValueError, match="independent single-host production evidence"):
        verifier.verify(context, refs, now=NOW)


def test_wallet_chain_custody_binding_is_cross_checked():
    _, refs, _, context, registry, _, _, _ = setup_single_host()
    bundle = single_host_gate_fixture()
    changed_refs = reissue(
        bundle,
        EvidenceKind.MANAGED_CUSTODY,
        facts_change=lambda facts: facts.update(wallet_address="0x" + "34" * 20),
    )
    changed_required = tuple(ref for ref in changed_refs if ref.kind in SINGLE_HOST_REQUIRED_KINDS)
    verifier = SingleHostProductionPreconditionsVerifier(
        registry, bundle[2], pinned_registry_sha256=issuer_registry_sha256(registry)
    )
    with pytest.raises(ValueError, match="wallet/chain mismatch"):
        verifier.verify(context, changed_required, now=NOW)


def test_legacy_custody_kind_accepts_provider_neutral_local_identity():
    bundle = single_host_gate_fixture()
    _, _, resolver, context, _, policy = bundle
    changed_refs = reissue(
        bundle,
        EvidenceKind.MANAGED_CUSTODY,
        facts_change=lambda facts: facts.update(
            custody_reference="local-encrypted-wallet",
            dev_custody_reference="isolated-dev-wallet",
        ),
    )
    required_refs = tuple(ref for ref in changed_refs if ref.kind in SINGLE_HOST_REQUIRED_KINDS)
    registry = (policy,)
    verifier = SingleHostProductionPreconditionsVerifier(
        registry, resolver, pinned_registry_sha256=issuer_registry_sha256(registry)
    )

    result = verifier.verify(context, required_refs, now=NOW)
    assert result.preconditions.owner_identity == "owner"


@pytest.mark.parametrize("now", [NOW - timedelta(seconds=1), NOW + timedelta(minutes=31)])
def test_evidence_must_be_current_and_not_future_dated(now):
    verifier, refs, _, context, *_ = setup_single_host()
    with pytest.raises(ValueError, match="stale or future-dated"):
        verifier.verify(context, refs, now=now)


def test_wrapper_cannot_be_rebound_to_another_profile_or_authority():
    verifier, refs, _, context, *_ = setup_single_host()
    result = verifier.verify(context, refs, now=NOW)
    with pytest.raises(ValidationError, match="immutable"):
        SingleHostProductionProfileV1(required_evidence_kinds=tuple(reversed(SINGLE_HOST_REQUIRED_KINDS)))
    with pytest.raises(ValidationError, match="immutable single-host profile"):
        SingleHostPreconditionsV1.model_validate(
            result.model_copy(update={"profile_sha256": "f" * 64}).model_dump()
        )


def test_v1_signed_receipt_and_preconditions_contract_remains_unchanged():
    v1_verifier, all_refs, _, context, *_ = signed_gate_fixture()
    legacy = v1_verifier.verify(context, all_refs, now=NOW)
    assert legacy.version == "kairos.production-preconditions.v1"
    assert legacy.live_ready is False and legacy.mutation_authority is False


def test_single_host_interpreter_does_not_reinterpret_v1_host_loss_receipt():
    _, refs, resolver, context, _, policy = signed_gate_fixture()
    interpreter = SingleHostAlertReceiptInterpreter((policy,), resolver)
    alert_ref = next(ref for ref in refs if ref.kind is EvidenceKind.ALERT_DELIVERY)
    with pytest.raises(ValueError, match="unreviewed substantive gate schema"):
        interpreter.verify(alert_ref, context)
