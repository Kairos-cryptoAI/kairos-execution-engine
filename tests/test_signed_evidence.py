"""Real public-key negatives using published synthetic seeds, never PROD proof."""

import base64
import hashlib
import json
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from kairos_execution.production_readiness import EvidenceKind, ProductionPreconditionsVerifier
from kairos_execution.signed_evidence import SignedReceiptInterpreter, canonical_bytes
from tests.production_evidence_fixtures import NOW, H, signed_gate_fixture


def reissue(bundle, kind, *, body_change=None, facts_change=None, signing_key=None):
    _, refs, resolver, _, private, _ = bundle
    ref = next(ref for ref in refs if ref.kind is kind)
    payload = json.loads(resolver.receipts[ref.content_sha256])
    if body_change:
        body_change(payload["body"])
    if facts_change:
        facts = json.loads(payload["body"]["facts_json"])
        facts_change(facts)
        payload["body"]["facts_json"] = canonical_bytes(facts).decode()
    payload["signature_base64"] = base64.b64encode(
        (signing_key or private).sign(
            b"kairos.signed-production-evidence.v1\x00" + canonical_bytes(payload["body"])
        )
    ).decode()
    raw = canonical_bytes(payload)
    digest = hashlib.sha256(raw).hexdigest()
    resolver.receipts[digest] = raw
    return tuple(
        ref.model_copy(update={"content_sha256": digest}) if ref.kind is kind else ref for ref in refs
    )


@pytest.mark.parametrize("kind", tuple(EvidenceKind))
def test_each_kind_real_signature_and_substantive_schema(kind):
    bundle = signed_gate_fixture()
    verifier, refs, _, scope, *_ = bundle
    issuer, interpreter = verifier._interpreters[kind]
    proof = interpreter.verify(next(r for r in refs if r.kind is kind), scope)
    assert issuer == "test-only" and proof.facts_sha256 and proof.verified_issuer_key_id
    result = verifier.verify(scope, refs, now=NOW)
    assert result.live_ready is False and result.mutation_authority is False


@pytest.mark.parametrize(
    "mutation",
    [
        "wrong-key",
        "unknown-key",
        "unknown-issuer",
        "wrong-schema",
        "wrong-account",
        "wrong-source",
        "wrong-adaptive",
        "stale",
        "future",
        "issuer-expired",
        "overlong",
        "accepted-flag",
    ],
)
def test_signature_scope_schema_and_time_not_caller_booleans(mutation):
    bundle = signed_gate_fixture()
    verifier, _, _, scope, _, policy = bundle
    kind = EvidenceKind.SECURITY_REVIEW
    key = None
    changes = {}
    if mutation == "wrong-key":
        key = Ed25519PrivateKey.from_private_bytes(bytes(reversed(range(32))))
    elif mutation == "unknown-key":
        changes["key_id"] = "unregistered"
    elif mutation == "unknown-issuer":
        changes["issuer_id"] = "unregistered"
    elif mutation == "wrong-schema":
        changes["facts_schema_sha256"] = "f" * 64
    elif mutation.startswith("wrong-"):
        field = {
            "wrong-account": "remote_account_id",
            "wrong-source": "source_set_sha256",
            "wrong-adaptive": "adaptive_system_id",
        }[mutation]
        changes["context"] = {**scope.model_dump(mode="json"), field: "f" * 64}
    elif mutation == "stale":
        changes.update(issued_at=(NOW - timedelta(hours=1)).isoformat(), valid_until=NOW.isoformat())
    elif mutation == "future":
        changes["issued_at"] = (NOW + timedelta(seconds=1)).isoformat()
    elif mutation == "issuer-expired":
        verifier._interpreters[kind] = (
            policy.issuer_id,
            SignedReceiptInterpreter(kind, (policy.model_copy(update={"valid_until": NOW}),), bundle[2]),
        )
    elif mutation == "overlong":
        changes["valid_until"] = (NOW + timedelta(hours=2)).isoformat()
    else:
        changes["accepted"] = True
    refs = reissue(bundle, kind, body_change=lambda b: b.update(changes), signing_key=key)
    with pytest.raises(ValueError):
        verifier.verify(scope, refs, now=NOW)


@pytest.mark.parametrize(
    "kind,change",
    [
        (EvidenceKind.ADAPTIVE_SEALED_FORWARD, lambda f: f["days"].pop()),
        (EvidenceKind.ADAPTIVE_SEALED_FORWARD, lambda f: f["days"][0]["symbols"].pop()),
        (EvidenceKind.ADAPTIVE_SEALED_FORWARD, lambda f: f["days"][0]["symbols"][0].update(missing_bars=1)),
        (
            EvidenceKind.ADAPTIVE_SEALED_FORWARD,
            lambda f: f.update(observation_started_at="2025-10-01T12:00:00Z"),
        ),
        (EvidenceKind.ADAPTIVE_SEALED_TRADES, lambda f: f["trades"].pop()),
        (EvidenceKind.ADAPTIVE_SEALED_TRADES, lambda f: f.update(profit_factor="1.49")),
        (EvidenceKind.ADAPTIVE_SEALED_TRADES, lambda f: f.update(maximum_drawdown_fraction="0.051")),
        (EvidenceKind.ADAPTIVE_SEALED_TRADES, lambda f: f["trades"][0].update(closure="QUOTA")),
        (EvidenceKind.CRASH_NET_GATE, lambda f: f["scenarios"][0].update(net_pnl_usd="999")),
        (EvidenceKind.DEV_READONLY_24H, lambda f: f["windows"][0].update(available_samples=1)),
        (EvidenceKind.DEV_READONLY_24H, lambda f: f["windows"][0].update(empty_required_books=1)),
        (EvidenceKind.DEV_CANARY, lambda f: f.update(attempt_count=11)),
        (EvidenceKind.DEV_SOAK_TCA, lambda f: f.update(unresolved_effect_count=1)),
        (EvidenceKind.PRIMARY_RECOVERY, lambda f: f.update(duplicate_publications=1)),
        (EvidenceKind.SECURITY_REVIEW, lambda f: f.update(unresolved_high_findings=1)),
        (EvidenceKind.MANAGED_CUSTODY, lambda f: f.update(typed_schema_sha256="f" * 64)),
        (EvidenceKind.OFFHOST_RESTORE, lambda f: f.update(restore_failure_domain=f["source_failure_domain"])),
        (EvidenceKind.ALERT_DELIVERY, lambda f: f.update(unknown_sends=1)),
        (
            EvidenceKind.ALERT_DELIVERY,
            lambda f: f["deliveries"][0].update(
                owner_acknowledged_at=(NOW + timedelta(seconds=1)).isoformat()
            ),
        ),
        (EvidenceKind.GLOBAL_OPERATOR_CONTROL, lambda f: f.update(entries_dispatched_after_kill=1)),
        (EvidenceKind.PROD_ACCOUNT_PAIRING, lambda f: f.update(remote_account_id="different")),
        (EvidenceKind.PRODUCTION_LIMITS, lambda f: f.update(risk_per_trade_fraction="0.0026")),
    ],
)
def test_valid_signature_cannot_cover_incomplete_or_failed_gate(kind, change):
    bundle = signed_gate_fixture()
    refs = reissue(bundle, kind, facts_change=change)
    with pytest.raises(ValueError):
        bundle[0].verify(bundle[3], refs, now=NOW)


@pytest.mark.parametrize(
    "kind,change",
    [
        (EvidenceKind.MANAGED_CUSTODY, lambda f: f.update(wallet_address="0x" + "34" * 20)),
        (EvidenceKind.DEV_CANARY, lambda f: f.update(dev_remote_account_id="different-dev")),
        (EvidenceKind.DEV_READONLY_24H, lambda f: f.update(dev_remote_account_id="prod-reviewed-account")),
    ],
)
def test_individually_valid_gates_cannot_rebind_custody_or_dev_identity(kind, change):
    bundle = signed_gate_fixture()
    refs = reissue(bundle, kind, facts_change=change)
    with pytest.raises(ValueError, match="mismatch|inconsistent"):
        bundle[0].verify(bundle[3], refs, now=NOW)


@pytest.mark.parametrize("mutation", ["artifact", "policy", "campaign", "evaluator", "nested", "crash-set"])
def test_exact_underlying_bytes_preregistered_policy_and_campaign(mutation):
    bundle = signed_gate_fixture()
    verifier, refs, resolver, scope, _, policy = bundle
    if mutation == "artifact":
        resolver.artifacts[H] = b"changed"
    elif mutation == "policy":
        resolver.artifacts[scope.frozen_policy_sha256] = b"changed"
    elif mutation in {"campaign", "evaluator"}:
        field = "campaign_id" if mutation == "campaign" else "evaluator_sha256"
        refs = reissue(
            bundle, EvidenceKind.ADAPTIVE_SEALED_TRADES, facts_change=lambda f: f.update({field: "f" * 64})
        )
    elif mutation == "nested":
        refs = reissue(
            bundle,
            EvidenceKind.PRIMARY_RECOVERY,
            facts_change=lambda f: f.update(native_commit_receipt_sha256="f" * 64),
        )
    else:
        # Replacing an issuer registry threshold cannot replace a preregistered policy artifact.
        replacement = policy.model_copy(update={"crash_scenario_sha256s": ("f" * 64,)})
        verifier._interpreters[EvidenceKind.CRASH_NET_GATE] = (
            policy.issuer_id,
            SignedReceiptInterpreter(EvidenceKind.CRASH_NET_GATE, (replacement,), resolver),
        )
    with pytest.raises(ValueError):
        verifier.verify(scope, refs, now=NOW)


def test_unsigned_fixture_and_duplicate_keys_fail_closed():
    bundle = signed_gate_fixture()
    verifier, refs, resolver, scope, *_ = bundle
    with pytest.raises(ValueError, match="concrete signed"):
        ProductionPreconditionsVerifier({kind: ("test-only", object()) for kind in EvidenceKind}).verify(
            scope, refs, now=NOW
        )
    ref = refs[0]
    raw = resolver.receipts[ref.content_sha256]
    payload = b'{"body":null,' + raw[1:]
    digest = hashlib.sha256(payload).hexdigest()
    resolver.receipts[digest] = payload
    with pytest.raises(ValueError):
        verifier.verify(scope, (ref.model_copy(update={"content_sha256": digest}), *refs[1:]), now=NOW)


def test_directory_resolver_rejects_escape_corruption_and_missing_file(tmp_path):
    from kairos_execution.signed_evidence import DirectoryEvidenceResolver

    resolver = DirectoryEvidenceResolver(tmp_path)
    for digest in ("../anything", "g" * 64, H):
        with pytest.raises((ValueError, FileNotFoundError)):
            resolver.artifact_bytes(digest)
