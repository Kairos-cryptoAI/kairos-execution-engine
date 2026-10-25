"""Opt-in LIVE risk-to-signing evidence composition.

This module is not selected by any service or factory. It requires the concrete
Risk evaluator, a separately provisioned insert-only state writer, and the
existing passive lifecycle binding store. A successful result stages evidence;
it never claims, signs, dispatches, or declares PROD readiness.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any, Literal
from uuid import UUID

from kairos_core.contracts import CandidateReviewV1, StrategicAllocation, VenueQualityV1, canonical_sha256
from kairos_core.enums import EvedexProfile, Side, SystemMode, TradingMode
from kairos_risk.live import (  # type: ignore[import-untyped]
    LiveRiskEvaluationV1,
    LiveRiskEvaluator,
    LiveRiskScopeV1,
    VerifiedLiveAccountV1,
)
from pydantic import field_validator

from .managed_signer import CustodyBindingV1
from .production_exposure import require_exposure_write_authority
from .production_history import SOURCE_ID, ProductionHistoryCaptureV1
from .production_lifecycle_binding import (
    ProductionLifecycleBindingV1,
    build_production_lifecycle_binding,
)
from .production_lifecycle_store import PostgresLifecycleBindingStore
from .production_readiness import ProductionContextV1, StrictRecord, canonical_digest
from .production_reconciliation import ProductionReconciliationError
from .production_state import PostgresRiskStateWriter, RiskGeometryV1
from .state_machine import client_order_id


class ProductionLiveRiskError(PermissionError):
    """LIVE risk staging failed closed; no execution authority is implied."""


class ProductionLiveRiskEntryRefused(ProductionLiveRiskError):
    """A complete negative pure evaluation, before any staging write or effect.

    Unknown evaluation/writer outcomes and scope mismatches use the parent
    error instead. This distinction grants no authority to retry an identity.
    """

    def __init__(self, evaluation: LiveRiskEvaluationV1) -> None:
        checked = LiveRiskEvaluationV1.model_validate_json(evaluation.model_dump_json())
        if checked.decision.approved or not checked.decision.rejection_reasons:
            raise ValueError("a complete rejected LIVE Risk evaluation is required")
        self.evaluation = checked
        super().__init__("LIVE evaluation is rejected or outside the frozen PROD scope")


class ProductionLiveRiskStageReceiptV1(StrictRecord):
    """Auditable in-process receipt for exact decision and risk evidence staged."""

    version: Literal["kairos.production-live-risk-stage.v1"] = "kairos.production-live-risk-stage.v1"
    evaluation: LiveRiskEvaluationV1
    lifecycle_binding: ProductionLifecycleBindingV1
    risk_geometry: RiskGeometryV1
    staged_at: datetime
    binding_inserted: bool

    @field_validator("staged_at")
    @classmethod
    def _validate_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("stage receipt time must be explicit UTC")
        return value


class PinnedEvedexLiveAccountVerifier:
    """Fail-closed adapter for current SDK history, which cannot verify LIVE totals.

    It intentionally never constructs or returns ``VerifiedLiveAccountV1``.
    The shared production-history authority guard is invoked after exact source
    and account-scope checks and refuses the current pinned capture.
    """

    source_id = SOURCE_ID

    def verify(
        self,
        raw_evidence: object,
        *,
        source_id: str,
        expected_scope: LiveRiskScopeV1,
    ) -> VerifiedLiveAccountV1:
        if source_id != self.source_id:
            raise ProductionReconciliationError("pinned EVEDEX source identity mismatch")
        try:
            capture = ProductionHistoryCaptureV1.model_validate(raw_evidence)
        except Exception:
            raise ProductionReconciliationError("pinned EVEDEX account history is malformed") from None
        if (
            capture.context.remote_account_id != expected_scope.account_id
            or canonical_digest(capture.context) != expected_scope.context_sha256
        ):
            raise ProductionReconciliationError("pinned EVEDEX history scope/account mismatch")
        # This fixed guard always refuses the present source. In particular, do
        # not infer equity, reservations, fills, daily loss, or exposure here.
        require_exposure_write_authority(capture)
        raise ProductionReconciliationError("pinned EVEDEX history cannot verify LIVE account totals")


class ProductionLiveRiskPublisher:
    """Stage evaluator-owned LIVE risk against one deterministic ENTRY request.

    Risk computation stays in the concrete ``kairos-risk-manager`` evaluator;
    this execution-side bridge only binds its verified result to the exact
    lifecycle request and writes the typed records through existing stores.
    """

    _MAX_EVIDENCE_AGE = timedelta(seconds=5)

    def __init__(
        self,
        *,
        evaluator: LiveRiskEvaluator,
        risk_writer: PostgresRiskStateWriter,
        lifecycle_bindings: PostgresLifecycleBindingStore,
        custody_binding: CustodyBindingV1,
        database_uuid: UUID,
        policy_namespace: str,
    ) -> None:
        if not isinstance(evaluator, LiveRiskEvaluator):
            raise TypeError("the concrete fail-closed LiveRiskEvaluator is required")
        if not isinstance(risk_writer, PostgresRiskStateWriter):
            raise TypeError("the independently configured PostgresRiskStateWriter is required")
        if not isinstance(lifecycle_bindings, PostgresLifecycleBindingStore):
            raise TypeError("the existing PostgresLifecycleBindingStore is required")
        if not isinstance(database_uuid, UUID) or database_uuid.int == 0:
            raise ValueError("an exact nonzero production database UUID is required")
        context = ProductionContextV1.model_validate(risk_writer.context)
        custody_binding = CustodyBindingV1.model_validate(custody_binding)
        scope = LiveRiskScopeV1.model_validate(evaluator.scope.model_dump(mode="json"))
        if (
            lifecycle_bindings.context != context
            or custody_binding.context != context
            or scope.context_sha256 != canonical_digest(context)
            or scope.source_set_sha256 != context.source_set_sha256
            or scope.policy_sha256 != context.frozen_policy_sha256
            or scope.account_id != context.remote_account_id
            or scope.strategy_id != context.adaptive_system_id
            or risk_writer.database_uuid != database_uuid
            or risk_writer.policy_namespace != policy_namespace
            or risk_writer.state_schema_version != 3
            or lifecycle_bindings.expected_database != risk_writer.expected_database
            or lifecycle_bindings.expected_role == risk_writer.expected_role
        ):
            raise ValueError("LIVE risk evaluator, lifecycle store, writer, and production scope differ")
        self.evaluator = evaluator
        self.risk_writer = risk_writer
        self.lifecycle_bindings = lifecycle_bindings
        self.custody_binding = custody_binding
        self.database_uuid = database_uuid
        self.policy_namespace = policy_namespace
        self.context = context
        self.scope = scope

    async def evaluate_and_stage_entry(
        self,
        raw_account_evidence: object,
        raw_inputs_evidence: object,
        source_id: str,
        review: CandidateReviewV1,
        venue: VenueQualityV1,
        allocation: StrategicAllocation | None,
        manual_request_sha256: str,
        expires_at: datetime,
        now: datetime,
        system_mode: SystemMode,
    ) -> ProductionLiveRiskStageReceiptV1:
        """Evaluate verified account evidence and stage exactly one ENTRY risk row.

        ``now`` and ``expires_at`` are explicit UTC. The publication lease is
        capped at five seconds and may not outlive the Core intent, venue, or
        verified account freshness. No approval boolean is accepted as input.
        """
        now = self._utc(now, "now")
        expires_at = self._utc(expires_at, "expires_at")
        if not isinstance(system_mode, SystemMode):
            raise ProductionLiveRiskError("an observed Risk system mode is required")
        if not now < expires_at <= now + self._MAX_EVIDENCE_AGE:
            raise ProductionLiveRiskError(
                "LIVE signing deadline must be within the five-second evidence lease"
            )
        decided_at_ms = int(now.timestamp() * 1_000)
        try:
            evaluation = self.evaluator.evaluate(
                raw_account_evidence,
                source_id=source_id,
                review=review,
                venue=venue,
                allocation=allocation,
                decided_at_ms=decided_at_ms,
                system_mode=system_mode,
                raw_inputs_evidence=raw_inputs_evidence,
            )
            evaluation = LiveRiskEvaluationV1.model_validate(evaluation.model_dump(mode="json"))
        except Exception:
            raise ProductionLiveRiskError("LIVE Risk evaluation failed closed") from None

        decision = evaluation.decision
        if (
            decision.trading_mode is not TradingMode.LIVE
            or decision.evedex_profile is not EvedexProfile.PROD
            or decision.intent.contract_version == "strategy-intent.observed-sim.v2"
            or decision.intent.strategy_id != self.scope.strategy_id
            or decision.intent.strategy_revision != self.scope.strategy_revision
            or evaluation.scope_sha256 != self.scope.scope_sha256
            or evaluation.source_id != source_id
            or decision.account_id != self.context.remote_account_id
            or decision.intent.strategy_id != self.context.adaptive_system_id
            or self.scope.venue_symbol_for(decision.intent.symbol) != decision.venue_symbol
            or decision.intent.canonical_intent_bytes() != review.intent.canonical_intent_bytes()
            or canonical_sha256(decision.review) != canonical_sha256(review)
            or canonical_sha256(decision.venue_quality) != canonical_sha256(venue)
        ):
            raise ProductionLiveRiskError("LIVE evaluation is rejected or outside the frozen PROD scope")
        if not decision.approved:
            # The evaluator is pure. No Risk/binding append, signer, dispatcher
            # or reservation mutation has occurred at this boundary.
            raise ProductionLiveRiskEntryRefused(evaluation)
        if (
            decision.rejection_reasons
            or decision.decision_id is None
            or decision.trade_id is None
            or decision.leverage != 1.0
        ):
            raise ProductionLiveRiskError("LIVE evaluation is rejected or outside the frozen PROD scope")
        facts = self._verified_facts(evaluation)
        venue_quality = decision.venue_quality
        entry_expiry = datetime.fromtimestamp(decision.intent.entry_expires_ts_ms / 1_000, tz=UTC)
        quote_expiry = datetime.fromtimestamp(venue_quality.expires_at_ms / 1_000, tz=UTC)
        quote_hard_expiry = datetime.fromtimestamp((venue_quality.observed_at_ms + 2_000) / 1_000, tz=UTC)
        book_hard_expiry = datetime.fromtimestamp((venue_quality.book_timestamp_ms + 2_000) / 1_000, tz=UTC)
        reference_hard_expiry = datetime.fromtimestamp(
            (venue_quality.reference_timestamp_ms + 2_000) / 1_000, tz=UTC
        )
        account_valid_until = datetime.fromtimestamp(
            (facts["account_as_of_ms"] + int(self._MAX_EVIDENCE_AGE.total_seconds() * 1_000)) / 1_000,
            tz=UTC,
        )
        inputs_valid_until = datetime.fromtimestamp((facts["inputs_observed_at_ms"] + 5_000) / 1_000, tz=UTC)
        valid_until = min(
            now + self._MAX_EVIDENCE_AGE,
            entry_expiry,
            quote_expiry,
            quote_hard_expiry,
            book_hard_expiry,
            reference_hard_expiry,
            account_valid_until,
            inputs_valid_until,
            expires_at,
        )
        if expires_at > valid_until:
            if expires_at > quote_hard_expiry:
                raise ProductionLiveRiskError("signing deadline outlives the two-second quote TTL")
            if expires_at > min(book_hard_expiry, reference_hard_expiry):
                raise ProductionLiveRiskError("signing deadline outlives the two-second market-data TTL")
            raise ProductionLiveRiskError(
                "signing deadline outlives Core, verified account, or upstream-input evidence"
            )

        lifecycle_effect_id = self._entry_effect_id(decision.trade_id)
        client_id = client_order_id(
            f"{decision.trade_id}:ENTRY",
            "evedex",
            occurred_at=datetime.fromtimestamp(decision.decided_at_ms / 1_000, tz=UTC),
        )
        try:
            binding = build_production_lifecycle_binding(
                decision=decision,
                context=self.context,
                custody_binding=self.custody_binding,
                role="ENTRY",
                lifecycle_effect_id=lifecycle_effect_id,
                client_order_id=client_id,
                manual_request_sha256=manual_request_sha256,
                expires_at=expires_at,
                now=now,
            )
            risk = self._risk_geometry(evaluation, binding, valid_until=valid_until, observed_at=now)
        except Exception:
            raise ProductionLiveRiskError("LIVE signing request geometry could not be bound") from None

        try:
            # Risk is written first. If the second append is unresolved, the
            # orphan risk row is not executable: adapter plan lookup still fails.
            await self.risk_writer.append_risk_decision_async(risk)
        except Exception:
            raise ProductionLiveRiskError(
                "LIVE risk write failed or is unresolved; do not retry or dispatch blindly"
            ) from None
        try:
            binding_inserted = await self.lifecycle_bindings.put(binding)
        except Exception:
            raise ProductionLiveRiskError(
                "LIVE lifecycle binding write failed or is unresolved; no order may be dispatched"
            ) from None
        return ProductionLiveRiskStageReceiptV1(
            evaluation=evaluation,
            lifecycle_binding=binding,
            risk_geometry=risk,
            staged_at=now,
            binding_inserted=binding_inserted,
        )

    def _verified_facts(self, evaluation: LiveRiskEvaluationV1) -> dict[str, Any]:
        fields = (
            "source_id",
            "evidence_sha256",
            "account_snapshot_sha256",
            "account_as_of_ms",
            "aggregate_open_risk_usd",
            "aggregate_open_notional_usd",
            "reserved_open_risk_usd",
            "reserved_open_notional_usd",
            "daily_adverse_loss_usd",
            "account_equity_usd",
            "strategy_open_notional_usd",
            "strategy_reserved_notional_usd",
            "inputs_source_id",
            "inputs_evidence_sha256",
            "inputs_observed_at_ms",
        )
        facts = {name: getattr(evaluation, name) for name in fields}
        if (
            any(value is None for value in facts.values())
            or facts["source_id"] == ""
            or facts["evidence_sha256"] is None
            or facts["account_snapshot_sha256"] is None
            or facts["inputs_source_id"] == ""
            or facts["inputs_evidence_sha256"] is None
            or facts["account_as_of_ms"] < 0
            or isinstance(facts["inputs_observed_at_ms"], bool)
            or not isinstance(facts["inputs_observed_at_ms"], int)
            or facts["inputs_observed_at_ms"] < 0
            or any(not Decimal(str(facts[name])).is_finite() for name in fields[4:12])
        ):
            raise ProductionLiveRiskError("LIVE evaluation lacks independently verified account economics")
        if facts["source_id"] != evaluation.source_id:
            raise ProductionLiveRiskError("LIVE account source provenance is inconsistent")
        for digest_name in (
            "evidence_sha256",
            "account_snapshot_sha256",
            "inputs_evidence_sha256",
        ):
            digest = facts[digest_name]
            if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
                raise ProductionLiveRiskError("LIVE evaluation contains malformed proof provenance")
        if not facts["inputs_source_id"].strip():
            raise ProductionLiveRiskError("LIVE evaluation lacks verified upstream-input provenance")
        return facts

    def _risk_geometry(
        self,
        evaluation: LiveRiskEvaluationV1,
        binding: ProductionLifecycleBindingV1,
        *,
        valid_until: datetime,
        observed_at: datetime,
    ) -> RiskGeometryV1:
        decision = evaluation.decision
        message = json.loads(binding.request.message_json)
        facts = self._verified_facts(evaluation)
        if (
            binding.role != "ENTRY"
            or binding.risk_decision_id != decision.decision_id
            or binding.decision_id != decision.decision_id
            or message.get("instrument") != decision.venue_symbol
            or message.get("side") != ("BUY" if decision.intent.side is Side.LONG else "SELL")
            or message.get("quantity") is None
            or message.get("limitPrice") is None
        ):
            raise ProductionLiveRiskError("LIVE risk does not match the exact ENTRY signing request")
        return RiskGeometryV1(
            context=self.context,
            decision_id=decision.decision_id,
            signing_request_id=binding.request.request_id,
            effect_id=binding.signing_effect_id,
            client_order_id=message["id"],
            operation=binding.request.operation,
            instrument=message["instrument"],
            side=message["side"],
            quantity=message["quantity"],
            cash_quantity=None,
            price=message["limitPrice"],
            stop_price=None,
            protection_type=None,
            trigger_price=None,
            parent_order_id=None,
            leverage=1,
            worst_case_loss_usd=self._decimal(decision.worst_case_loss_usd),
            account_equity_usd=self._decimal(facts["account_equity_usd"]),
            daily_realized_loss_usd=self._decimal(facts["daily_adverse_loss_usd"]),
            aggregate_open_risk_usd=self._decimal(facts["aggregate_open_risk_usd"]),
            aggregate_open_notional_usd=self._decimal(facts["aggregate_open_notional_usd"]),
            approved=True,
            observed_at=observed_at,
            valid_until=valid_until,
        )

    def _entry_effect_id(self, trade_id: str) -> str:
        namespace = f"prod.v1:{canonical_digest(self.context)}"
        return hashlib.sha256(f"{namespace}:{trade_id}:ENTRY:place".encode()).hexdigest()

    @staticmethod
    def _decimal(value: object) -> Decimal:
        try:
            result = Decimal(str(value))
        except Exception:
            raise ProductionLiveRiskError("LIVE risk economics are not exact finite decimals") from None
        if not result.is_finite():
            raise ProductionLiveRiskError("LIVE risk economics are not exact finite decimals")
        return result

    @staticmethod
    def _utc(value: datetime, name: str) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ProductionLiveRiskError(f"{name} must be an explicit UTC timestamp")
        return value.astimezone(UTC)
