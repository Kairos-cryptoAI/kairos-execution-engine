"""Explicit Ed25519 evidence format, not an adapter for historical GPG receipts.

The registry is deployment policy, never a caller-supplied ``accepted`` flag.
Signatures authenticate an independent producer's observations; they do not
prove that the producer or its measuring pipeline has been qualified in PROD.
No private-key loading, signing, issuer enrollment or LIVE authority exists here.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, date, datetime, time, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Annotated, Literal, Protocol, Self

from pydantic import Field, field_validator, model_validator

from .production_readiness import (
    Digest,
    EvidenceKind,
    Identity,
    ProductionContextV1,
    ReceiptReferenceV1,
    StrictRecord,
    VerifiedEvidenceV1,
    _aware,
    canonical_digest,
)

_DOMAIN = b"kairos.signed-production-evidence.v1\x00"
_UNIVERSE = frozenset({"BTC", "ETH", "SOL", "BNB", "XRP"})
_MAX_BYTES = 4 * 1024 * 1024
Positive = Annotated[Decimal, Field(gt=0, allow_inf_nan=False)]
Nonnegative = Annotated[Decimal, Field(ge=0, allow_inf_nan=False)]


def canonical_bytes(value: StrictRecord | dict) -> bytes:
    data = value.model_dump(mode="json") if isinstance(value, StrictRecord) else value
    return json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _unique_json(pairs: list[tuple[str, object]]) -> dict[str, object]:
    data: dict[str, object] = {}
    for key, value in pairs:
        if key in data:
            raise ValueError("duplicate evidence JSON key")
        data[key] = value
    return data


class EvidenceArtifactsV1(StrictRecord):
    schema_version: Literal["kairos.production-gate-facts.v1"] = "kairos.production-gate-facts.v1"
    artifact_sha256s: tuple[Digest, ...] = Field(min_length=1, max_length=10000)

    @field_validator("artifact_sha256s")
    @classmethod
    def unique_artifacts(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("duplicate independent artifact")
        return value


class SymbolDayV1(StrictRecord):
    symbol: Literal["BTC", "ETH", "SOL", "BNB", "XRP"]
    bars_sha256: Digest
    closed_one_minute_bars: Literal[1440]
    missing_bars: Literal[0]
    conflicting_bars: Literal[0]


class CompleteDayV1(StrictRecord):
    day: date
    symbols: tuple[SymbolDayV1, ...] = Field(min_length=5, max_length=5)

    @model_validator(mode="after")
    def complete(self) -> Self:
        if {item.symbol for item in self.symbols} != _UNIVERSE:
            raise ValueError("a full five-symbol day is required")
        return self


class ForwardFactsV1(EvidenceArtifactsV1):
    campaign_id: Identity
    evaluator_sha256: Digest
    observation_started_at: datetime
    sealed_at: datetime
    days: tuple[CompleteDayV1, ...] = Field(min_length=365, max_length=10000)

    _utc = field_validator("observation_started_at", "sealed_at")(_aware)

    @model_validator(mode="after")
    def actual_days(self) -> Self:
        dates = [item.day for item in self.days]
        if dates != sorted(set(dates)) or any(
            b - a != timedelta(days=1) for a, b in zip(dates, dates[1:], strict=False)
        ):
            raise ValueError("forward days must be unique, ordered and consecutive")
        if (
            datetime.combine(dates[0], time.min, tzinfo=UTC) < self.observation_started_at
            or self.sealed_at.date() <= dates[-1]
            or self.sealed_at - self.observation_started_at < timedelta(days=365)
        ):
            raise ValueError("forward evidence is not a sealed 365-day future observation")
        return self


class NaturalCloseV1(StrictRecord):
    trade_id: Identity
    intent_id: Identity
    opened_at: datetime
    closed_at: datetime
    closure: Literal["STOP", "TARGET", "TIMEOUT"]
    lifecycle_sha256: Digest

    _utc = field_validator("opened_at", "closed_at")(_aware)

    @model_validator(mode="after")
    def ordered(self) -> Self:
        if self.closed_at <= self.opened_at:
            raise ValueError("trade must naturally close after opening")
        return self


class TradesFactsV1(EvidenceArtifactsV1):
    campaign_id: Identity
    evaluator_sha256: Digest
    sealed_at: datetime
    trades: tuple[NaturalCloseV1, ...] = Field(min_length=500, max_length=100000)
    profit_factor: Positive
    maximum_drawdown_fraction: Nonnegative

    _utc = field_validator("sealed_at")(_aware)

    @model_validator(mode="after")
    def actual_closes(self) -> Self:
        if len({t.trade_id for t in self.trades}) != len(self.trades) or len(
            {t.intent_id for t in self.trades}
        ) != len(self.trades):
            raise ValueError("natural trades and intents must be unique")
        if any(t.closed_at > self.sealed_at for t in self.trades):
            raise ValueError("future or unsealed trade")
        return self


class CrashScenarioV1(StrictRecord):
    scenario_sha256: Digest
    gross_pnl_usd: Decimal = Field(allow_inf_nan=False)
    fees_usd: Nonnegative
    funding_usd: Decimal = Field(allow_inf_nan=False)
    spread_cost_usd: Nonnegative
    slippage_cost_usd: Nonnegative
    net_pnl_usd: Positive

    @model_validator(mode="after")
    def net_accounting(self) -> Self:
        if self.net_pnl_usd != (
            self.gross_pnl_usd
            - self.fees_usd
            - self.funding_usd
            - self.spread_cost_usd
            - self.slippage_cost_usd
        ):
            raise ValueError("crash net result does not reconcile all costs")
        return self


class CrashFactsV1(EvidenceArtifactsV1):
    campaign_id: Identity
    evaluator_sha256: Digest
    scenarios: tuple[CrashScenarioV1, ...] = Field(min_length=1, max_length=100)


class VenueWindowV1(StrictRecord):
    symbol: Literal["BTC", "ETH", "SOL", "BNB", "XRP"]
    expected_samples: int = Field(ge=8640)
    available_samples: int = Field(ge=0)
    p95_basis_bps: Nonnegative
    p95_spread_bps: Nonnegative
    p95_slippage_bps: Nonnegative
    maximum_book_age_ms: int = Field(ge=0, le=5000)
    maximum_skew_ms: int = Field(ge=0, le=2000)
    empty_required_books: Literal[0]
    unresolved_gaps: Literal[0]
    reconciliation_drift: Literal[0]

    @model_validator(mode="after")
    def quality(self) -> Self:
        if not self.expected_samples >= self.available_samples >= self.expected_samples * Decimal("0.99"):
            raise ValueError("venue availability is below 99 percent")
        if max(self.p95_basis_bps, self.p95_spread_bps, self.p95_slippage_bps) > 25:
            raise ValueError("venue quality exceeds 25 bps")
        return self


class ReadonlyFactsV1(EvidenceArtifactsV1):
    dev_remote_account_id: Identity
    started_at: datetime
    ended_at: datetime
    windows: tuple[VenueWindowV1, ...] = Field(min_length=5, max_length=5)
    mutation_attempts: Literal[0]

    _utc = field_validator("started_at", "ended_at")(_aware)

    @model_validator(mode="after")
    def window(self) -> Self:
        if (
            self.ended_at - self.started_at < timedelta(hours=24)
            or {w.symbol for w in self.windows} != _UNIVERSE
        ):
            raise ValueError("continuous 24-hour five-symbol window is required")
        return self


class CanaryRoundTripV1(StrictRecord):
    symbol: Literal["BTC", "ETH", "SOL", "BNB", "XRP"]
    trade_id: Identity
    entry_claim_sha256: Digest
    terminal_lifecycle_sha256: Digest
    leverage: Literal[1]
    final_position_quantity: Literal[0]
    unresolved_orders: Literal[0]


class CanaryFactsV1(EvidenceArtifactsV1):
    dev_remote_account_id: Identity
    started_at: datetime
    ended_at: datetime
    attempt_count: int = Field(ge=5, le=10)
    maximum_global_positions: Literal[1]
    minimum_quantity_rules_sha256: Digest
    round_trips: tuple[CanaryRoundTripV1, ...] = Field(min_length=5, max_length=10)
    scenario_artifacts: dict[Literal["CANCEL", "SL", "TP", "TIMEOUT", "RESTART_RECOVERY"], Digest]

    _utc = field_validator("started_at", "ended_at")(_aware)

    @model_validator(mode="after")
    def bounded(self) -> Self:
        if not timedelta(0) < self.ended_at - self.started_at <= timedelta(hours=2):
            raise ValueError("canary must be bounded to two hours")
        if {t.symbol for t in self.round_trips} != _UNIVERSE or len(
            {t.trade_id for t in self.round_trips}
        ) != len(self.round_trips):
            raise ValueError("all five instruments need independent completed round trips")
        if self.attempt_count < len(self.round_trips) or set(self.scenario_artifacts) != {
            "CANCEL",
            "SL",
            "TP",
            "TIMEOUT",
            "RESTART_RECOVERY",
        }:
            raise ValueError("canary attempt/scenario evidence is incomplete")
        return self


class SoakFactsV1(EvidenceArtifactsV1):
    dev_remote_account_id: Identity
    started_at: datetime
    ended_at: datetime
    windows: tuple[VenueWindowV1, ...] = Field(min_length=5, max_length=5)
    execution_effect_count: int = Field(gt=0)
    reconciled_effect_count: int = Field(gt=0)
    unresolved_effect_count: Literal[0]
    tca_report_sha256: Digest

    _utc = field_validator("started_at", "ended_at")(_aware)

    @model_validator(mode="after")
    def complete(self) -> Self:
        if (
            self.ended_at - self.started_at < timedelta(days=7)
            or self.execution_effect_count != (self.reconciled_effect_count)
            or {w.symbol for w in self.windows} != _UNIVERSE
        ):
            raise ValueError("seven-day reconciled five-symbol soak is incomplete")
        return self


class RecoveryFactsV1(EvidenceArtifactsV1):
    primary_database_identity: Identity
    backup_sha256: Digest
    restored_backup_sha256: Digest
    native_commit_receipt_sha256: Digest
    primary_acceptance_receipt_sha256: Digest
    before_history_sha256: Digest
    after_history_sha256: Digest
    unresolved_inbox: Literal[0]
    unresolved_outbox: Literal[0]
    duplicate_publications: Literal[0]
    unresolved_leases: Literal[0]
    bar_chain_conflicts: Literal[0]

    @model_validator(mode="after")
    def restored(self) -> Self:
        if self.backup_sha256 != self.restored_backup_sha256 or (
            self.before_history_sha256 != self.after_history_sha256
        ):
            raise ValueError("restore/history integrity mismatch")
        return self


class SecurityFactsV1(EvidenceArtifactsV1):
    threat_model_sha256: Digest
    reviewed_source_set_sha256: Digest
    independent_reviewer_identity: Identity
    reviewed_security_boundary_count: int = Field(gt=0)
    unresolved_critical_findings: Literal[0]
    unresolved_high_findings: Literal[0]
    unresolved_medium_findings: Literal[0]
    deployment_review_sha256: Digest


class CustodyFactsV1(EvidenceArtifactsV1):
    custody_reference: Identity
    wallet_address: Annotated[str, Field(pattern=r"^0x[0-9a-fA-F]{40}$")]
    chain_id: int = Field(gt=0)
    typed_schema_sha256: Digest
    independent_recovery_test_sha256: Digest
    dev_custody_reference: Identity
    successful_verified_signatures: int = Field(gt=0)
    malformed_requests_rejected: int = Field(gt=0)
    unauthorized_requests_rejected: int = Field(gt=0)
    unverified_signatures: Literal[0]

    @model_validator(mode="after")
    def separate(self) -> Self:
        if self.custody_reference == self.dev_custody_reference:
            raise ValueError("DEV and PROD custody must be separate")
        return self


class RestoreFactsV1(EvidenceArtifactsV1):
    source_failure_domain: Identity
    restore_failure_domain: Identity
    encryption: Literal["RESTIC_AUTHENTICATED_ENCRYPTION"]
    key_custody_receipt_sha256: Digest
    source_database_dump_sha256: Digest
    restored_database_dump_sha256: Digest
    encrypted_snapshot_sha256: Digest
    database_integrity_receipt_sha256: Digest
    wrong_key_rejections: int = Field(gt=0)
    authenticated_errors: Literal[0]

    @model_validator(mode="after")
    def offhost(self) -> Self:
        if self.source_failure_domain == self.restore_failure_domain or (
            self.source_database_dump_sha256 != self.restored_database_dump_sha256
        ):
            raise ValueError("off-host database restore is not proven")
        return self


class AlertDeliveryV1(StrictRecord):
    alert_name: Identity
    firing_event_sha256: Digest
    resolved_event_sha256: Digest
    receiver_identity: Identity
    firing_received_at: datetime
    resolved_received_at: datetime
    owner_acknowledged_at: datetime

    _utc = field_validator("firing_received_at", "resolved_received_at", "owner_acknowledged_at")(_aware)

    @model_validator(mode="after")
    def delivered(self) -> Self:
        if not self.firing_received_at < self.resolved_received_at <= self.owner_acknowledged_at:
            raise ValueError("firing/resolved/owner acknowledgment order mismatch")
        return self


class AlertFactsV1(EvidenceArtifactsV1):
    required_alert_names: tuple[Identity, ...] = Field(min_length=1)
    deliveries: tuple[AlertDeliveryV1, ...] = Field(min_length=1)
    notifier_restart_receipt_sha256: Digest
    independent_host_loss_receipt_sha256: Digest
    unknown_sends: Literal[0]

    @model_validator(mode="after")
    def coverage(self) -> Self:
        names = [d.alert_name for d in self.deliveries]
        if len(set(names)) != len(names) or set(names) != set(self.required_alert_names):
            raise ValueError("native delivery coverage is incomplete")
        return self


class OperatorFactsV1(EvidenceArtifactsV1):
    control_database_identity: Identity
    operator_role: Identity
    runtime_role: Identity
    operator_version: int = Field(gt=0)
    killed_at: datetime
    resumed_at: datetime
    restart_observed_version: int = Field(gt=0)
    entries_dispatched_after_kill: Literal[0]
    protected_exit_failures: Literal[0]
    duplicate_dispatches: Literal[0]
    unknown_claim_retries: Literal[0]
    denied_unsafe_privilege_count: int = Field(gt=0)

    _utc = field_validator("killed_at", "resumed_at")(_aware)

    @model_validator(mode="after")
    def durable(self) -> Self:
        if self.runtime_role == self.operator_role or self.restart_observed_version < self.operator_version:
            raise ValueError("durable ownership/version separation is not proven")
        if self.resumed_at <= self.killed_at:
            raise ValueError("operator control observations are not ordered")
        return self


class PairingFactsV1(EvidenceArtifactsV1):
    environment: Literal["PROD"]
    remote_account_id: Identity
    wallet_address: Annotated[str, Field(pattern=r"^0x[0-9a-fA-F]{40}$")]
    authenticated_read_challenge_sha256: Digest
    signing_challenge_sha256: Digest
    chain_id: int = Field(gt=0)
    credential_pairing_conflicts: Literal[0]


class LimitsFactsV1(EvidenceArtifactsV1):
    owner_identity: Identity
    dollar_cap: Positive
    daily_stop_loss_usd: Positive
    risk_per_trade_fraction: Positive
    maximum_total_open_risk_fraction: Positive
    maximum_leverage: Literal[1]
    blocked_missing_limit_count: int = Field(gt=0)
    blocked_over_cap_count: int = Field(gt=0)
    blocked_daily_stop_count: int = Field(gt=0)
    restart_accounting_receipt_sha256: Digest
    pending_risk_receipt_sha256: Digest

    @model_validator(mode="after")
    def ceilings(self) -> Self:
        if self.daily_stop_loss_usd > self.dollar_cap or self.risk_per_trade_fraction > Decimal("0.0025"):
            raise ValueError("owner limits exceed fixed risk ceiling")
        if self.maximum_total_open_risk_fraction > Decimal("0.01"):
            raise ValueError("aggregate open risk ceiling exceeded")
        return self


FACT_SCHEMAS: dict[EvidenceKind, type[EvidenceArtifactsV1]] = dict(
    zip(
        EvidenceKind,
        (
            ForwardFactsV1,
            TradesFactsV1,
            CrashFactsV1,
            ReadonlyFactsV1,
            CanaryFactsV1,
            SoakFactsV1,
            RecoveryFactsV1,
            SecurityFactsV1,
            CustodyFactsV1,
            RestoreFactsV1,
            AlertFactsV1,
            OperatorFactsV1,
            PairingFactsV1,
            LimitsFactsV1,
        ),
        strict=True,
    )
)


class SignedReceiptBodyV1(StrictRecord):
    version: Literal["kairos.signed-production-evidence.v1"] = "kairos.signed-production-evidence.v1"
    kind: EvidenceKind
    receipt_id: Identity
    issuer_id: Identity
    key_id: Identity
    context: ProductionContextV1
    issued_at: datetime
    valid_until: datetime
    facts_schema_sha256: Digest
    facts_json: str = Field(min_length=2, max_length=_MAX_BYTES)

    _utc = field_validator("issued_at", "valid_until")(_aware)

    @model_validator(mode="after")
    def valid_interval(self) -> Self:
        if self.valid_until <= self.issued_at:
            raise ValueError("empty signed receipt validity")
        return self


class SignedReceiptV1(StrictRecord):
    body: SignedReceiptBodyV1
    signature_base64: str = Field(min_length=88, max_length=88, repr=False)


class IssuerPolicyV1(StrictRecord):
    issuer_id: Identity
    key_id: Identity
    public_key_base64: str = Field(min_length=44, max_length=44)
    context: ProductionContextV1
    allowed_kinds: tuple[EvidenceKind, ...] = Field(min_length=1)
    valid_from: datetime
    valid_until: datetime
    maximum_receipt_lifetime_seconds: int = Field(gt=0, le=86400)
    campaign_id: Identity
    evaluator_sha256: Digest
    crash_scenario_sha256s: tuple[Digest, ...] = Field(min_length=1)
    minimum_profit_factor: Positive
    maximum_drawdown_fraction: Positive

    _utc = field_validator("valid_from", "valid_until")(_aware)

    @model_validator(mode="after")
    def bounds(self) -> Self:
        if self.valid_until <= self.valid_from or len(set(self.allowed_kinds)) != len(self.allowed_kinds):
            raise ValueError("invalid issuer scope/validity")
        if self.minimum_profit_factor < 1 or self.maximum_drawdown_fraction > 1:
            raise ValueError("invalid preregistered economic thresholds")
        return self


class FrozenGatePolicyV1(StrictRecord):
    """Content-addressed preregistration, not thresholds chosen after observations."""

    version: Literal["kairos.frozen-production-gates.v1"] = "kairos.frozen-production-gates.v1"
    adaptive_system_id: Identity
    source_set_sha256: Digest
    campaign_id: Identity
    evaluator_sha256: Digest
    minimum_profit_factor: Positive
    maximum_drawdown_fraction: Positive
    crash_scenario_sha256s: tuple[Digest, ...] = Field(min_length=1)
    required_alert_names: tuple[Identity, ...] = Field(min_length=1)
    minimum_forward_days: int = Field(ge=365)
    minimum_natural_closes: int = Field(ge=500)
    frozen_at: datetime

    _utc = field_validator("frozen_at")(_aware)

    @model_validator(mode="after")
    def preregistered_sets(self) -> Self:
        if len(set(self.crash_scenario_sha256s)) != len(self.crash_scenario_sha256s) or (
            len(set(self.required_alert_names)) != len(self.required_alert_names)
        ):
            raise ValueError("preregistered scenario/alert identities must be distinct")
        if self.minimum_profit_factor < 1 or self.maximum_drawdown_fraction > 1:
            raise ValueError("invalid preregistered economic thresholds")
        return self


class EvidenceResolver(Protocol):
    def receipt_bytes(self, content_sha256: str) -> bytes: ...
    def artifact_bytes(self, content_sha256: str) -> bytes: ...


class DirectoryEvidenceResolver:
    """Read only exact content-addressed regular files; never arbitrary references."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve(strict=True)
        if not self.root.is_dir():
            raise ValueError("receipt directory is absent")

    def _read(self, digest: str, suffix: str) -> bytes:
        import re

        if re.fullmatch(r"[a-f0-9]{64}", digest) is None:
            raise ValueError("invalid content digest")
        path = self.root / f"{digest}{suffix}"
        if path.is_symlink() or path.resolve(strict=True).parent != self.root or not path.is_file():
            raise ValueError("evidence reference escapes immutable store")
        with path.open("rb") as handle:
            data = handle.read(_MAX_BYTES + 1)
        if len(data) > _MAX_BYTES or hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("evidence artifact integrity mismatch")
        return data

    def receipt_bytes(self, content_sha256: str) -> bytes:
        return self._read(content_sha256, ".json")

    def artifact_bytes(self, content_sha256: str) -> bytes:
        return self._read(content_sha256, ".artifact")


class SignedReceiptInterpreter:
    """Independent public-key/schema/content interpreter for one registered kind."""

    def __init__(self, kind: EvidenceKind, registry: tuple[IssuerPolicyV1, ...], resolver: EvidenceResolver):
        self.kind = kind
        policies = tuple(IssuerPolicyV1.model_validate(p) for p in registry)
        self._registry = {(p.issuer_id, p.key_id): p for p in policies}
        if len(self._registry) != len(policies):
            raise ValueError("duplicate issuer key identity")
        self._resolver = resolver

    def verify(self, reference: ReceiptReferenceV1, context: ProductionContextV1) -> VerifiedEvidenceV1:
        reference = ReceiptReferenceV1.model_validate(reference)
        context = ProductionContextV1.model_validate(context)
        raw = self._resolver.receipt_bytes(reference.content_sha256)
        if len(raw) > _MAX_BYTES or hashlib.sha256(raw).hexdigest() != reference.content_sha256:
            raise ValueError("signed receipt hash mismatch")
        parsed = json.loads(raw, object_pairs_hook=_unique_json)
        receipt = SignedReceiptV1.model_validate_json(canonical_bytes(parsed))
        body = receipt.body
        policy = self._registry.get((body.issuer_id, body.key_id))
        if (
            policy is None
            or body.kind != self.kind
            or reference.kind != self.kind
            or (
                body.receipt_id != reference.receipt_id
                or body.issuer_id != reference.issuer_id
                or body.context != context
                or policy.context != context
                or body.kind not in policy.allowed_kinds
            )
        ):
            raise ValueError("signed receipt issuer/kind/context mismatch")
        if not policy.valid_from <= body.issued_at < body.valid_until <= policy.valid_until or (
            body.valid_until - body.issued_at > timedelta(seconds=policy.maximum_receipt_lifetime_seconds)
        ):
            raise ValueError("signed receipt exceeds issuer validity/lifetime")
        # Imports are explicit opt-in. No private key, signing or default factory.
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        public = base64.b64decode(policy.public_key_base64, validate=True)
        signature = base64.b64decode(receipt.signature_base64, validate=True)
        if len(public) != 32 or len(signature) != 64:
            raise ValueError("invalid public key or detached signature length")
        Ed25519PublicKey.from_public_bytes(public).verify(signature, _DOMAIN + canonical_bytes(body))
        schema = FACT_SCHEMAS[self.kind]
        expected_schema = hashlib.sha256(canonical_bytes(schema.model_json_schema())).hexdigest()
        if body.facts_schema_sha256 != expected_schema:
            raise ValueError("unreviewed substantive gate schema")
        facts_json = json.loads(body.facts_json, object_pairs_hook=_unique_json)
        facts = schema.model_validate_json(canonical_bytes(facts_json))
        policy_raw = self._resolver.artifact_bytes(context.frozen_policy_sha256)
        if (
            len(policy_raw) > _MAX_BYTES
            or hashlib.sha256(policy_raw).hexdigest() != context.frozen_policy_sha256
        ):
            raise ValueError("frozen policy artifact hash mismatch")
        frozen = FrozenGatePolicyV1.model_validate_json(
            canonical_bytes(json.loads(policy_raw, object_pairs_hook=_unique_json))
        )
        if (
            frozen.adaptive_system_id != context.adaptive_system_id
            or frozen.source_set_sha256 != context.source_set_sha256
            or frozen.frozen_at >= body.issued_at
            or any(
                getattr(frozen, name) != getattr(policy, name)
                for name in (
                    "campaign_id",
                    "evaluator_sha256",
                    "minimum_profit_factor",
                    "maximum_drawdown_fraction",
                    "crash_scenario_sha256s",
                )
            )
        ):
            raise ValueError("issuer thresholds are not bound to exact frozen preregistration")

        def artifact_references(value: object, name: str = "") -> set[str]:
            if isinstance(value, dict):
                return set().union(*(artifact_references(v, k) for k, v in value.items()))
            if isinstance(value, list):
                return set().union(*(artifact_references(v, name) for v in value))
            if name.endswith("_sha256") and name not in {
                "evaluator_sha256",
                "reviewed_source_set_sha256",
                "typed_schema_sha256",
            }:
                return {str(value)}
            return set()

        required_artifacts = artifact_references(facts.model_dump(mode="json"))
        # Hash labels in nested facts are not evidence until their exact bytes
        # independently resolve in the same declared immutable artifact set.
        if not required_artifacts.issubset(facts.artifact_sha256s):
            raise ValueError("gate fact references an undeclared underlying artifact")
        for digest in facts.artifact_sha256s:
            data = self._resolver.artifact_bytes(digest)
            if len(data) > _MAX_BYTES or hashlib.sha256(data).hexdigest() != digest:
                raise ValueError("independent underlying artifact hash mismatch")
        for name in ("campaign_id", "evaluator_sha256"):
            if hasattr(facts, name) and getattr(facts, name) != getattr(policy, name):
                raise ValueError("adaptive campaign/evaluator differs from frozen issuer policy")
        if isinstance(facts, ForwardFactsV1) and facts.sealed_at > body.issued_at:
            raise ValueError("forward receipt predates its seal")
        if isinstance(facts, ForwardFactsV1) and (
            len(facts.days) < frozen.minimum_forward_days or facts.observation_started_at <= frozen.frozen_at
        ):
            raise ValueError("forward campaign predates freezing or lacks preregistered days")
        if isinstance(facts, TradesFactsV1) and (
            facts.sealed_at > body.issued_at
            or facts.profit_factor < policy.minimum_profit_factor
            or facts.maximum_drawdown_fraction > policy.maximum_drawdown_fraction
            or len(facts.trades) < frozen.minimum_natural_closes
            or any(t.opened_at <= frozen.frozen_at for t in facts.trades)
        ):
            raise ValueError("sealed trade economics violate frozen gates")
        if isinstance(facts, CrashFactsV1) and sorted(s.scenario_sha256 for s in facts.scenarios) != sorted(
            policy.crash_scenario_sha256s
        ):
            raise ValueError("crash set differs from the preregistered set")
        if (
            isinstance(facts, SecurityFactsV1)
            and facts.reviewed_source_set_sha256 != context.source_set_sha256
        ):
            raise ValueError("security review is for another source set")
        if isinstance(facts, PairingFactsV1) and facts.remote_account_id != context.remote_account_id:
            raise ValueError("PROD pairing is for another remote account")
        if isinstance(facts, CustodyFactsV1):
            from .managed_signer import reviewed_schema_sha256

            if facts.typed_schema_sha256 != reviewed_schema_sha256(facts.chain_id):
                raise ValueError("custody proof uses an unreviewed local typed schema/domain")
        if isinstance(facts, AlertFactsV1) and tuple(sorted(facts.required_alert_names)) != tuple(
            sorted(frozen.required_alert_names)
        ):
            raise ValueError("alert set differs from frozen required coverage")
        if isinstance(facts, AlertFactsV1) and any(
            delivery.owner_acknowledged_at > body.issued_at for delivery in facts.deliveries
        ):
            raise ValueError("alert receipt includes a future owner acknowledgment")
        for name in ("ended_at", "resumed_at", "killed_at"):
            if hasattr(facts, name) and getattr(facts, name) > body.issued_at:
                raise ValueError("receipt includes future operational observations")
        binding_names = (
            "owner_identity",
            "dollar_cap",
            "daily_stop_loss_usd",
            "wallet_address",
            "chain_id",
            "custody_reference",
            "dev_remote_account_id",
        )
        binding_facts = {
            name: facts.model_dump(mode="json")[name] for name in binding_names if hasattr(facts, name)
        }
        return VerifiedEvidenceV1(
            reference=reference,
            context=context,
            outcome="SEALED_PASS",
            verified_at=body.issued_at,
            valid_until=body.valid_until,
            complete_forward_days=len(facts.days) if isinstance(facts, ForwardFactsV1) else None,
            naturally_closed_simulated_trades=len(facts.trades) if isinstance(facts, TradesFactsV1) else None,
            facts_sha256=canonical_digest(facts),
            facts_schema_sha256=expected_schema,
            verified_issuer_key_id=body.key_id,
            binding_facts_json=canonical_bytes(binding_facts).decode(),
        )
