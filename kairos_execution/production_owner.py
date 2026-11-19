"""Owner-run tools: the owner arm key, signed manual arms, the evidence issuer and receipts.

Everything here creates material that only the owner may create, on the owner's own
machine and at the owner's command. Private keys are written once into new files that
only the current Windows user (and SYSTEM) can read, and are never printed. Nothing
here decides that a gate is met: a receipt states facts the owner attests, and the
production verifiers check them independently.

The record formats are exactly the ones the production path verifies:
``OwnerArmKeyV1`` / ``SignedManualArmRequestV1`` (``production_readiness``) and
``IssuerPolicyV1`` / ``SignedReceiptV1`` / ``FrozenGatePolicyV1`` in a
``DirectoryEvidenceResolver`` store (``signed_evidence``).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import sys
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pydantic import BaseModel

from .auth_orchestration import _write_new_private_file
from .production_readiness import (
    _OWNER_ARM_DOMAIN,
    EvidenceKind,
    ManualArmRequestV1,
    OwnerArmKeyV1,
    PreconditionsV1,
    ProductionContextV1,
    ReceiptReferenceV1,
    SignedManualArmRequestV1,
    canonical_digest,
)
from .signed_evidence import (
    _DOMAIN,
    FACT_SCHEMAS,
    FrozenGatePolicyV1,
    IssuerPolicyV1,
    SignedReceiptBodyV1,
    SignedReceiptV1,
    SingleHostAlertFactsV1,
    canonical_bytes,
)

OWNER_KEY_FILE = "owner-arm.ed25519"
OWNER_POLICY_FILE = "owner-arm-key.json"
ISSUER_KEY_FILE = "evidence-issuer.ed25519"


class OwnerToolError(ValueError):
    """An owner tool refused; messages never contain key material."""


def _ed25519():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return Ed25519PrivateKey


def _new_key(path: Path) -> tuple[bytes, str]:
    """Create a private Ed25519 seed file; return the seed and the public key in base64."""
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    if path.exists():
        raise OwnerToolError(f"refusing to overwrite an existing key file: {path.name}")
    path.parent.mkdir(parents=True, exist_ok=True)
    seed = secrets.token_bytes(32)
    _write_new_private_file(path, base64.b64encode(seed))
    public = _ed25519().from_private_bytes(seed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return seed, base64.b64encode(public).decode()


def _load_seed(path: Path, expected_public_base64: str):
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    if sys.platform == "win32":
        from .local_custody import _assert_private_windows_acl

        _assert_private_windows_acl(path)
    try:
        seed = base64.b64decode(path.read_bytes().strip(), validate=True)
        key = _ed25519().from_private_bytes(seed)
    except Exception:
        raise OwnerToolError("key file is unreadable or malformed") from None
    public = base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
    if public != expected_public_base64:
        raise OwnerToolError("key file does not match the pinned public key")
    return key


def _key_id(public_base64: str) -> str:
    return "ed25519-" + hashlib.sha256(base64.b64decode(public_base64)).hexdigest()[:24]


def _utc_now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


# ------------------------------------------------------------------------ owner arm


def generate_owner_key(
    directory: Path,
    *,
    owner_identity: str,
    context: ProductionContextV1,
    valid_from: datetime,
    valid_until: datetime,
) -> OwnerArmKeyV1:
    """Create the owner's arm-signing key and its pinned public policy."""
    directory = Path(directory)
    policy_path = directory / OWNER_POLICY_FILE
    if policy_path.exists():
        raise OwnerToolError("an owner key policy already exists in this directory")
    _seed, public = _new_key(directory / OWNER_KEY_FILE)
    policy = OwnerArmKeyV1(
        owner_identity=owner_identity,
        key_id=_key_id(public),
        public_key_base64=public,
        context=context,
        valid_from=valid_from,
        valid_until=valid_until,
    )
    policy_path.write_text(policy.model_dump_json(indent=2), encoding="utf-8")
    return policy


def sign_manual_arm(
    key_path: Path,
    owner_key: OwnerArmKeyV1,
    preconditions: PreconditionsV1,
    *,
    lifetime: timedelta,
    now: datetime | None = None,
    nonce: str | None = None,
) -> SignedManualArmRequestV1:
    """Sign one bounded manual arm for exactly these verified preconditions."""
    owner_key = OwnerArmKeyV1.model_validate(owner_key)
    preconditions = PreconditionsV1.model_validate(preconditions)
    created = now or _utc_now()
    expires = min(created + lifetime, preconditions.valid_until, owner_key.valid_until)
    if expires <= created:
        raise OwnerToolError("the evidence or the owner key expires before the arm could start")
    request = ManualArmRequestV1(
        context=preconditions.context,
        preconditions_sha256=canonical_digest(preconditions),
        nonce=nonce or "arm-" + secrets.token_hex(16),
        owner_identity=owner_key.owner_identity,
        created_at=created,
        expires_at=expires,
        dollar_cap=preconditions.dollar_cap,
        daily_stop_loss_usd=preconditions.daily_stop_loss_usd,
    )
    payload = json.dumps(
        request.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    signature = _load_seed(Path(key_path), owner_key.public_key_base64).sign(_OWNER_ARM_DOMAIN + payload)
    return SignedManualArmRequestV1(
        request=request, key_id=owner_key.key_id, signature_base64=base64.b64encode(signature).decode()
    )


# ------------------------------------------------------------------------ evidence


def store_artifact(evidence_dir: Path, data: bytes, *, suffix: str = ".artifact") -> str:
    """Write one immutable content-addressed file; an identical existing file is kept."""
    digest = hashlib.sha256(data).hexdigest()
    path = Path(evidence_dir) / f"{digest}{suffix}"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise OwnerToolError("an evidence file with this name has other content")
        return digest
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
    return digest


def freeze_policy(evidence_dir: Path, policy: FrozenGatePolicyV1) -> str:
    """Store the preregistered gate policy; its digest is the context's frozen_policy_sha256."""
    return store_artifact(evidence_dir, canonical_bytes(FrozenGatePolicyV1.model_validate(policy)))


def generate_issuer(
    directory: Path,
    *,
    issuer_id: str,
    frozen: FrozenGatePolicyV1,
    context: ProductionContextV1,
    allowed_kinds: Sequence[EvidenceKind],
    valid_from: datetime,
    valid_until: datetime,
    maximum_receipt_lifetime_seconds: int = 86_400,
) -> IssuerPolicyV1:
    """Create the evidence issuer key and its policy, bound to the frozen preregistration."""
    _seed, public = _new_key(Path(directory) / ISSUER_KEY_FILE)
    return IssuerPolicyV1(
        issuer_id=issuer_id,
        key_id=_key_id(public),
        public_key_base64=public,
        context=context,
        allowed_kinds=tuple(allowed_kinds),
        valid_from=valid_from,
        valid_until=valid_until,
        maximum_receipt_lifetime_seconds=maximum_receipt_lifetime_seconds,
        campaign_id=frozen.campaign_id,
        evaluator_sha256=frozen.evaluator_sha256,
        crash_scenario_sha256s=frozen.crash_scenario_sha256s,
        minimum_profit_factor=frozen.minimum_profit_factor,
        maximum_drawdown_fraction=frozen.maximum_drawdown_fraction,
    )


def issue_receipt(
    key_path: Path,
    policy: IssuerPolicyV1,
    *,
    kind: EvidenceKind,
    facts: BaseModel,
    evidence_dir: Path,
    issued_at: datetime | None = None,
    lifetime: timedelta = timedelta(hours=24),
) -> ReceiptReferenceV1:
    """Sign facts of one kind; every ``*_sha256`` they cite must already be in the store."""
    policy = IssuerPolicyV1.model_validate(policy)
    if kind not in policy.allowed_kinds:
        raise OwnerToolError("this issuer is not allowed to sign this kind")
    # The single-host profile attests ALERT_DELIVERY with its own fixed local schema.
    single_host = kind is EvidenceKind.ALERT_DELIVERY and isinstance(facts, SingleHostAlertFactsV1)
    schema: type[BaseModel] = SingleHostAlertFactsV1 if single_host else FACT_SCHEMAS[kind]
    checked = schema.model_validate_json(facts.model_dump_json())
    for digest in getattr(checked, "artifact_sha256s", ()):
        if not (Path(evidence_dir) / f"{digest}.artifact").is_file():
            raise OwnerToolError(f"facts cite an artifact that is not stored: {digest[:12]}")
    issued = issued_at or _utc_now()
    valid_until = min(
        issued + lifetime,
        issued + timedelta(seconds=policy.maximum_receipt_lifetime_seconds),
        policy.valid_until,
    )
    body = SignedReceiptBodyV1(
        kind=kind,
        receipt_id=f"{kind.value.lower()}-{secrets.token_hex(8)}",
        issuer_id=policy.issuer_id,
        key_id=policy.key_id,
        context=policy.context,
        issued_at=issued,
        valid_until=valid_until,
        facts_schema_sha256=hashlib.sha256(canonical_bytes(schema.model_json_schema())).hexdigest(),
        facts_json=canonical_bytes(checked.model_dump(mode="json")).decode(),
    )
    signature = _load_seed(Path(key_path), policy.public_key_base64).sign(_DOMAIN + canonical_bytes(body))
    receipt = SignedReceiptV1(body=body, signature_base64=base64.b64encode(signature).decode())
    digest = store_artifact(evidence_dir, canonical_bytes(receipt), suffix=".json")
    return ReceiptReferenceV1(
        kind=kind, receipt_id=body.receipt_id, content_sha256=digest, issuer_id=policy.issuer_id
    )


# ------------------------------------------------------------------------ CLI


def _context(path: Path) -> ProductionContextV1:
    return ProductionContextV1.model_validate_json(Path(path).read_text(encoding="utf-8"))


def _when(text: str | None, default: datetime) -> datetime:
    if text is None:
        return default
    value = datetime.fromisoformat(text)
    if value.tzinfo is None:
        raise OwnerToolError("times must carry an explicit UTC offset")
    return value.astimezone(UTC)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m kairos_execution.production_owner", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    keygen = sub.add_parser("owner-keygen", help="create the owner arm key and its public policy")
    keygen.add_argument("--dir", type=Path, required=True)
    keygen.add_argument("--owner-identity", required=True)
    keygen.add_argument("--context", type=Path, required=True)
    keygen.add_argument("--valid-days", type=int, default=90)

    freeze = sub.add_parser("freeze-policy", help="store the preregistered gate policy (JSON)")
    freeze.add_argument("--evidence-dir", type=Path, required=True)
    freeze.add_argument("--policy", type=Path, required=True)

    issuer = sub.add_parser("issuer-keygen", help="create the evidence issuer key and policy")
    issuer.add_argument("--dir", type=Path, required=True)
    issuer.add_argument("--issuer-id", required=True)
    issuer.add_argument("--context", type=Path, required=True)
    issuer.add_argument("--evidence-dir", type=Path, required=True)
    issuer.add_argument("--kinds", nargs="+", required=True)
    issuer.add_argument("--valid-days", type=int, default=90)

    artifact = sub.add_parser("store-artifact", help="store one file as a content-addressed artifact")
    artifact.add_argument("--evidence-dir", type=Path, required=True)
    artifact.add_argument("--file", type=Path, required=True)

    issue = sub.add_parser("issue", help="sign facts of one kind into a receipt")
    issue.add_argument("--dir", type=Path, required=True, help="directory with the issuer key and policy")
    issue.add_argument("--evidence-dir", type=Path, required=True)
    issue.add_argument("--kind", required=True)
    issue.add_argument("--facts", type=Path, required=True)
    issue.add_argument("--hours", type=float, default=24.0)

    args = parser.parse_args(argv)
    now = _utc_now()
    try:
        if args.command == "owner-keygen":
            policy = generate_owner_key(
                args.dir,
                owner_identity=args.owner_identity,
                context=_context(args.context),
                valid_from=now,
                valid_until=now + timedelta(days=args.valid_days),
            )
            print(f"owner key {policy.key_id}; pin sha256 {canonical_digest(policy)}")
        elif args.command == "freeze-policy":
            frozen = FrozenGatePolicyV1.model_validate_json(args.policy.read_text(encoding="utf-8"))
            print(f"frozen_policy_sha256 {freeze_policy(args.evidence_dir, frozen)}")
        elif args.command == "issuer-keygen":
            context = _context(args.context)
            frozen_raw = (args.evidence_dir / f"{context.frozen_policy_sha256}.artifact").read_bytes()
            issuer_policy = generate_issuer(
                args.dir,
                issuer_id=args.issuer_id,
                frozen=FrozenGatePolicyV1.model_validate_json(frozen_raw),
                context=context,
                allowed_kinds=[EvidenceKind(kind) for kind in args.kinds],
                valid_from=now,
                valid_until=now + timedelta(days=args.valid_days),
            )
            (args.dir / "evidence-issuer.json").write_text(
                issuer_policy.model_dump_json(indent=2), encoding="utf-8"
            )
            print(f"issuer {issuer_policy.issuer_id} key {issuer_policy.key_id}")
        elif args.command == "store-artifact":
            print(store_artifact(args.evidence_dir, args.file.read_bytes()))
        elif args.command == "issue":
            signing_policy = IssuerPolicyV1.model_validate_json(
                (args.dir / "evidence-issuer.json").read_text(encoding="utf-8")
            )
            kind = EvidenceKind(args.kind)
            text = args.facts.read_text(encoding="utf-8")
            single = kind is EvidenceKind.ALERT_DELIVERY and "single-host-alert-facts" in text
            facts = (SingleHostAlertFactsV1 if single else FACT_SCHEMAS[kind]).model_validate_json(text)
            reference = issue_receipt(
                args.dir / ISSUER_KEY_FILE,
                signing_policy,
                kind=kind,
                facts=facts,
                evidence_dir=args.evidence_dir,
                lifetime=timedelta(hours=args.hours),
            )
            print(reference.model_dump_json())
    except (OwnerToolError, ValueError, OSError) as exc:
        print(f"refused: {type(exc).__name__}: {str(exc)[:300]}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "OwnerToolError",
    "freeze_policy",
    "generate_issuer",
    "generate_owner_key",
    "issue_receipt",
    "sign_manual_arm",
    "store_artifact",
]
