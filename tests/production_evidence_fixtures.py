"""Synthetic Ed25519 producer, never deployment keys or scientific evidence."""

import base64
import hashlib
from datetime import UTC, datetime, timedelta
from decimal import Decimal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from kairos_execution.managed_signer import reviewed_schema_sha256
from kairos_execution.production_readiness import (
    EvidenceKind,
    ProductionContextV1,
    ProductionPreconditionsVerifier,
    ReceiptReferenceV1,
)
from kairos_execution.signed_evidence import (
    FACT_SCHEMAS,
    FrozenGatePolicyV1,
    IssuerPolicyV1,
    SignedReceiptBodyV1,
    SignedReceiptInterpreter,
    SignedReceiptV1,
    canonical_bytes,
)

NOW = datetime(2026, 10, 2, 20, tzinfo=UTC)
ARTIFACT = b"SYNTHETIC_NOT_NATIVE_PRODUCTION_EVIDENCE"
H = hashlib.sha256(ARTIFACT).hexdigest()


class FixtureResolver:
    def __init__(self):
        self.receipts = {}
        self.artifacts = {H: ARTIFACT}
        self.days = 365
        self.trades = 500
        self.scope = None
        self.valid_until = NOW + timedelta(minutes=30)

    def receipt_bytes(self, digest):
        if (
            self.days != 365
            or self.trades != 500
            or self.scope is not None
            or self.valid_until != (NOW + timedelta(minutes=30))
        ):
            return b"tampered fixture"
        return self.receipts[digest]

    def artifact_bytes(self, digest):
        return self.artifacts[digest]


def synthetic_facts(kind):
    base = {"artifact_sha256s": (H,)}
    window = tuple(
        dict(
            symbol=symbol,
            expected_samples=8640,
            available_samples=8640,
            p95_basis_bps=Decimal("1"),
            p95_spread_bps=Decimal("1"),
            p95_slippage_bps=Decimal("1"),
            maximum_book_age_ms=1000,
            maximum_skew_ms=1000,
            empty_required_books=0,
            unresolved_gaps=0,
            reconciliation_drift=0,
        )
        for symbol in ("BTC", "ETH", "SOL", "BNB", "XRP")
    )
    campaign = {"campaign_id": "adaptive-campaign", "evaluator_sha256": H}
    start = datetime(2025, 10, 1, tzinfo=UTC)
    if kind is EvidenceKind.ADAPTIVE_SEALED_FORWARD:
        data = dict(
            **campaign,
            observation_started_at=start,
            sealed_at=NOW,
            days=tuple(
                dict(
                    day=(start + timedelta(days=i)).date(),
                    symbols=tuple(
                        dict(
                            symbol=s,
                            bars_sha256=H,
                            closed_one_minute_bars=1440,
                            missing_bars=0,
                            conflicting_bars=0,
                        )
                        for s in ("BTC", "ETH", "SOL", "BNB", "XRP")
                    ),
                )
                for i in range(365)
            ),
        )
    elif kind is EvidenceKind.ADAPTIVE_SEALED_TRADES:
        data = dict(
            **campaign,
            sealed_at=NOW,
            profit_factor=Decimal("2"),
            maximum_drawdown_fraction=Decimal("0.02"),
            trades=tuple(
                dict(
                    trade_id=f"trade-{i}",
                    intent_id=f"intent-{i}",
                    opened_at=start + timedelta(minutes=i),
                    closed_at=start + timedelta(minutes=i + 1),
                    closure="TARGET",
                    lifecycle_sha256=H,
                )
                for i in range(500)
            ),
        )
    elif kind is EvidenceKind.CRASH_NET_GATE:
        data = dict(
            **campaign,
            scenarios=(
                dict(
                    scenario_sha256=H,
                    gross_pnl_usd=Decimal("10"),
                    fees_usd=Decimal("1"),
                    funding_usd=Decimal("1"),
                    spread_cost_usd=Decimal("1"),
                    slippage_cost_usd=Decimal("1"),
                    net_pnl_usd=Decimal("6"),
                ),
            ),
        )
    elif kind is EvidenceKind.DEV_READONLY_24H:
        data = dict(
            dev_remote_account_id="dev-account",
            started_at=NOW - timedelta(days=1),
            ended_at=NOW,
            windows=window,
            mutation_attempts=0,
        )
    elif kind is EvidenceKind.DEV_CANARY:
        data = dict(
            dev_remote_account_id="dev-account",
            started_at=NOW - timedelta(hours=1),
            ended_at=NOW,
            attempt_count=5,
            maximum_global_positions=1,
            minimum_quantity_rules_sha256=H,
            round_trips=tuple(
                dict(
                    symbol=s,
                    trade_id=f"dev-{s}",
                    entry_claim_sha256=H,
                    terminal_lifecycle_sha256=H,
                    leverage=1,
                    final_position_quantity=0,
                    unresolved_orders=0,
                )
                for s in ("BTC", "ETH", "SOL", "BNB", "XRP")
            ),
            scenario_artifacts={s: H for s in ("CANCEL", "SL", "TP", "TIMEOUT", "RESTART_RECOVERY")},
        )
    elif kind is EvidenceKind.DEV_SOAK_TCA:
        data = dict(
            dev_remote_account_id="dev-account",
            started_at=NOW - timedelta(days=7),
            ended_at=NOW,
            windows=window,
            execution_effect_count=5,
            reconciled_effect_count=5,
            unresolved_effect_count=0,
            tca_report_sha256=H,
        )
    elif kind is EvidenceKind.PRIMARY_RECOVERY:
        data = dict(
            primary_database_identity="primary-reviewed",
            backup_sha256=H,
            restored_backup_sha256=H,
            native_commit_receipt_sha256=H,
            primary_acceptance_receipt_sha256=H,
            before_history_sha256=H,
            after_history_sha256=H,
            unresolved_inbox=0,
            unresolved_outbox=0,
            duplicate_publications=0,
            unresolved_leases=0,
            bar_chain_conflicts=0,
        )
    elif kind is EvidenceKind.SECURITY_REVIEW:
        data = dict(
            threat_model_sha256=H,
            reviewed_source_set_sha256="b" * 64,
            independent_reviewer_identity="independent-auditor",
            reviewed_security_boundary_count=14,
            unresolved_critical_findings=0,
            unresolved_high_findings=0,
            unresolved_medium_findings=0,
            deployment_review_sha256=H,
        )
    elif kind is EvidenceKind.MANAGED_CUSTODY:
        data = dict(
            custody_reference="kms:prod",
            wallet_address="0x" + "12" * 20,
            chain_id=161803,
            typed_schema_sha256=reviewed_schema_sha256(161803),
            independent_recovery_test_sha256=H,
            dev_custody_reference="kms:dev",
            successful_verified_signatures=1,
            malformed_requests_rejected=1,
            unauthorized_requests_rejected=1,
            unverified_signatures=0,
        )
    elif kind is EvidenceKind.OFFHOST_RESTORE:
        data = dict(
            source_failure_domain="host-a",
            restore_failure_domain="host-b",
            encryption="RESTIC_AUTHENTICATED_ENCRYPTION",
            key_custody_receipt_sha256=H,
            source_database_dump_sha256=H,
            restored_database_dump_sha256=H,
            encrypted_snapshot_sha256=H,
            database_integrity_receipt_sha256=H,
            wrong_key_rejections=1,
            authenticated_errors=0,
        )
    elif kind is EvidenceKind.ALERT_DELIVERY:
        data = dict(
            required_alert_names=("host-loss",),
            deliveries=(
                dict(
                    alert_name="host-loss",
                    firing_event_sha256=H,
                    resolved_event_sha256=H,
                    receiver_identity="owner-alarm",
                    firing_received_at=NOW - timedelta(minutes=2),
                    resolved_received_at=NOW - timedelta(minutes=1),
                    owner_acknowledged_at=NOW,
                ),
            ),
            notifier_restart_receipt_sha256=H,
            independent_host_loss_receipt_sha256=H,
            unknown_sends=0,
        )
    elif kind is EvidenceKind.GLOBAL_OPERATOR_CONTROL:
        data = dict(
            control_database_identity="control-proof",
            operator_role="operator",
            runtime_role="runtime",
            operator_version=1,
            killed_at=NOW - timedelta(minutes=1),
            resumed_at=NOW,
            restart_observed_version=1,
            entries_dispatched_after_kill=0,
            protected_exit_failures=0,
            duplicate_dispatches=0,
            unknown_claim_retries=0,
            denied_unsafe_privilege_count=1,
        )
    elif kind is EvidenceKind.PROD_ACCOUNT_PAIRING:
        data = dict(
            environment="PROD",
            remote_account_id="prod-reviewed-account",
            wallet_address="0x" + "12" * 20,
            authenticated_read_challenge_sha256=H,
            signing_challenge_sha256=H,
            chain_id=161803,
            credential_pairing_conflicts=0,
        )
    else:
        data = dict(
            owner_identity="owner",
            dollar_cap=Decimal("10"),
            daily_stop_loss_usd=Decimal("1"),
            risk_per_trade_fraction=Decimal("0.0025"),
            maximum_total_open_risk_fraction=Decimal("0.01"),
            maximum_leverage=1,
            blocked_missing_limit_count=1,
            blocked_over_cap_count=1,
            blocked_daily_stop_count=1,
            restart_accounting_receipt_sha256=H,
            pending_risk_receipt_sha256=H,
        )
    return FACT_SCHEMAS[kind].model_validate({**base, **data})


def signed_gate_fixture():
    resolver = FixtureResolver()
    frozen = FrozenGatePolicyV1(
        adaptive_system_id="adaptive-v1",
        source_set_sha256="b" * 64,
        campaign_id="adaptive-campaign",
        evaluator_sha256=H,
        minimum_profit_factor=Decimal("1.5"),
        maximum_drawdown_fraction=Decimal("0.05"),
        crash_scenario_sha256s=(H,),
        required_alert_names=("host-loss",),
        minimum_forward_days=365,
        minimum_natural_closes=500,
        frozen_at=datetime(2025, 9, 30, tzinfo=UTC),
    )
    policy_bytes = canonical_bytes(frozen)
    policy_hash = hashlib.sha256(policy_bytes).hexdigest()
    resolver.artifacts[policy_hash] = policy_bytes
    context = ProductionContextV1(
        remote_account_id="prod-reviewed-account",
        adaptive_system_id="adaptive-v1",
        frozen_policy_sha256=policy_hash,
        source_set_sha256="b" * 64,
    )
    private = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))  # Published synthetic test seed only.
    policy = IssuerPolicyV1(
        issuer_id="test-only",
        key_id="synthetic-ed25519",
        public_key_base64=base64.b64encode(private.public_key().public_bytes_raw()).decode(),
        context=context,
        allowed_kinds=tuple(EvidenceKind),
        valid_from=NOW - timedelta(days=1),
        valid_until=NOW + timedelta(days=1),
        maximum_receipt_lifetime_seconds=3600,
        campaign_id=frozen.campaign_id,
        evaluator_sha256=frozen.evaluator_sha256,
        crash_scenario_sha256s=frozen.crash_scenario_sha256s,
        minimum_profit_factor=frozen.minimum_profit_factor,
        maximum_drawdown_fraction=frozen.maximum_drawdown_fraction,
    )
    refs = []
    for kind in EvidenceKind:
        facts = synthetic_facts(kind)
        body = SignedReceiptBodyV1(
            kind=kind,
            receipt_id=kind.value,
            issuer_id=policy.issuer_id,
            key_id=policy.key_id,
            context=context,
            issued_at=NOW,
            valid_until=NOW + timedelta(minutes=30),
            facts_schema_sha256=hashlib.sha256(
                canonical_bytes(FACT_SCHEMAS[kind].model_json_schema())
            ).hexdigest(),
            facts_json=canonical_bytes(facts).decode(),
        )
        signed = SignedReceiptV1(
            body=body,
            signature_base64=base64.b64encode(
                private.sign(b"kairos.signed-production-evidence.v1\x00" + canonical_bytes(body))
            ).decode(),
        )
        raw = canonical_bytes(signed)
        digest = hashlib.sha256(raw).hexdigest()
        resolver.receipts[digest] = raw
        refs.append(
            ReceiptReferenceV1(
                kind=kind, receipt_id=body.receipt_id, content_sha256=digest, issuer_id=body.issuer_id
            )
        )
    verifier = ProductionPreconditionsVerifier(
        {
            kind: (policy.issuer_id, SignedReceiptInterpreter(kind, (policy,), resolver))
            for kind in EvidenceKind
        }
    )
    return verifier, tuple(refs), resolver, context, private, policy
