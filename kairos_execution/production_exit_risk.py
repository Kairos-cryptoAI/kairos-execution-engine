"""Independent per-effect LIVE exit-risk evidence staging.

This is a passive composition bridge, not an execution service. It can only
stage evidence for an already persisted PREPARED close/protection effect whose
trade and effect journals verify. It never signs or dispatches an order.
"""

from __future__ import annotations

import hashlib
import json
import math
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Literal, Protocol
from uuid import UUID

from kairos_core.contracts import RiskTradeDecisionV1
from kairos_core.enums import EvedexProfile, Side, TradingMode
from kairos_persistence import (
    EffectStatus,
    EffectType,
    ExecutionEffect,
    ExecutionJournalRepository,
    TradeLifecycleRepository,
    TradeRecord,
    TradeState,
    canonical_payload,
)
from pydantic import Field, field_validator

from .managed_signer import CustodyBindingV1
from .production_exposure import require_exposure_write_authority
from .production_history import SOURCE_ID, ProductionHistoryCaptureV1
from .production_lifecycle_binding import (
    LifecycleRole,
    ProductionLifecycleBindingV1,
    build_production_lifecycle_binding,
)
from .production_lifecycle_store import PostgresLifecycleBindingStore
from .production_readiness import ProductionContextV1, StrictRecord, canonical_digest
from .production_reconciliation import ProductionReconciliationError
from .production_state import (
    PostgresExposureStateWriter,
    PostgresRiskStateWriter,
)
from .signing_authorization import ExposureSnapshotV1, RiskGeometryV1

_MAX_AGE = timedelta(seconds=5)
_ROLE_CONFIG: dict[str, tuple[LifecycleRole, EffectType, str, TradeState]] = {
    "STOP_LOSS": ("STOP_LOSS", EffectType.PROTECTIVE_STOP, "create", TradeState.PROTECTING),
    "TAKE_PROFIT": ("TAKE_PROFIT", EffectType.TAKE_PROFIT, "create", TradeState.PROTECTING),
    "TIMEOUT_EXIT": ("TIMEOUT_EXIT", EffectType.TIMEOUT_CLOSE, "close", TradeState.EXITING_TIMEOUT),
    "EMERGENCY_EXIT": ("EMERGENCY_EXIT", EffectType.EMERGENCY_CLOSE, "close", TradeState.EXITING_EMERGENCY),
}


class ProductionExitRiskError(PermissionError):
    """A per-effect LIVE exit staging check refused; no dispatch is implied."""


class VerifiedLiveExitEvidenceV1(StrictRecord):
    """Output of a separately qualified verifier, bound to exact durable lineage.

    The verifier supplies authenticated position entry, fresh reference and
    executable exit prices, plus explicit upper bounds for exit fees and
    adverse slippage. The publisher calculates the loss for the exact effect;
    the verifier does not supply an approval or a precomputed loss amount.
    """

    source_id: str = Field(min_length=1, max_length=160)
    evidence_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    context_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    trade_id: str = Field(min_length=1, max_length=160)
    original_decision_id: str = Field(min_length=1, max_length=160)
    original_decision_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    effect_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    effect_request_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    role: LifecycleRole
    exposure: ExposureSnapshotV1
    account_equity_usd: Decimal = Field(gt=0)
    daily_realized_loss_usd: Decimal = Field(ge=0)
    aggregate_open_risk_usd: Decimal = Field(ge=0)
    aggregate_open_notional_usd: Decimal = Field(ge=0)
    position_entry_price_usd: Decimal = Field(gt=0)
    reference_price_usd: Decimal = Field(gt=0)
    executable_exit_price_usd: Decimal = Field(gt=0)
    exit_fee_rate: Decimal = Field(ge=0, lt=1)
    adverse_slippage_rate: Decimal = Field(ge=0, lt=1)
    observed_at: datetime
    valid_until: datetime

    @field_validator("observed_at", "valid_until")
    @classmethod
    def utc_times(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("explicit UTC timestamp required")
        return value

    @field_validator(
        "account_equity_usd",
        "daily_realized_loss_usd",
        "aggregate_open_risk_usd",
        "aggregate_open_notional_usd",
        "position_entry_price_usd",
        "reference_price_usd",
        "executable_exit_price_usd",
        "exit_fee_rate",
        "adverse_slippage_rate",
    )
    @classmethod
    def finite_economics(cls, value: Decimal) -> Decimal:
        if not value.is_finite():
            raise ValueError("verified exit economics must be finite")
        return value


class ProductionExitEvidenceVerifier(Protocol):
    """Mandatory deployment verifier for one exact exit effect and exposure."""

    source_id: str

    def verify_exit(
        self,
        raw_evidence: object,
        *,
        expected_context: ProductionContextV1,
        trade: TradeRecord,
        decision: RiskTradeDecisionV1,
        effect: ExecutionEffect,
        role: LifecycleRole,
        now: datetime,
    ) -> VerifiedLiveExitEvidenceV1: ...


class ProductionExitRiskStageReceiptV1(StrictRecord):
    version: Literal["kairos.production-exit-risk-stage.v1"] = "kairos.production-exit-risk-stage.v1"
    source_id: str
    evidence_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    lifecycle_binding: ProductionLifecycleBindingV1
    risk_geometry: RiskGeometryV1
    exposure: ExposureSnapshotV1
    staged_at: datetime
    binding_inserted: bool


class PinnedEvedexLiveExitVerifier:
    """Current pinned history adapter: validates exact scope, then always refuses."""

    source_id = SOURCE_ID

    def verify_exit(
        self,
        raw_evidence: object,
        *,
        expected_context: ProductionContextV1,
        trade: TradeRecord,
        decision: RiskTradeDecisionV1,
        effect: ExecutionEffect,
        role: LifecycleRole,
        now: datetime,
    ) -> VerifiedLiveExitEvidenceV1:
        try:
            capture = ProductionHistoryCaptureV1.model_validate(raw_evidence)
        except Exception:
            raise ProductionReconciliationError("pinned EVEDEX exit history is malformed") from None
        if capture.context != expected_context or capture.account_id != trade.account_id:
            raise ProductionReconciliationError("pinned EVEDEX exit history scope/account mismatch")
        require_exposure_write_authority(capture)
        raise ProductionReconciliationError("pinned EVEDEX history cannot verify exit exposure/economics")


class ProductionLiveExitRiskPublisher:
    """Create independent Risk/Exposure/binding records for one PREPARED exit."""

    def __init__(
        self,
        *,
        verifier: ProductionExitEvidenceVerifier,
        trades: TradeLifecycleRepository,
        effects: ExecutionJournalRepository,
        risk_writer: PostgresRiskStateWriter,
        exposure_writer: PostgresExposureStateWriter,
        lifecycle_bindings: PostgresLifecycleBindingStore,
        custody_binding: CustodyBindingV1,
        database_uuid: UUID,
        policy_namespace: str,
    ) -> None:
        if (
            verifier is None
            or not callable(getattr(verifier, "verify_exit", None))
            or not isinstance(getattr(verifier, "source_id", None), str)
            or not verifier.source_id
        ):
            raise TypeError("a mandatory qualified exit evidence verifier is required")
        if not isinstance(trades, TradeLifecycleRepository) or not isinstance(
            effects, ExecutionJournalRepository
        ):
            raise TypeError("durable TradeLifecycleRepository and ExecutionJournalRepository are required")
        if not isinstance(risk_writer, PostgresRiskStateWriter):
            raise TypeError("the production insert-only risk writer is required")
        if not isinstance(exposure_writer, PostgresExposureStateWriter):
            raise TypeError("the production insert-only exposure writer is required")
        if not isinstance(lifecycle_bindings, PostgresLifecycleBindingStore):
            raise TypeError("the existing passive lifecycle binding store is required")
        if not isinstance(database_uuid, UUID) or database_uuid.int == 0:
            raise ValueError("an exact nonzero production database UUID is required")
        context = ProductionContextV1.model_validate(risk_writer.context)
        custody = CustodyBindingV1.model_validate(custody_binding)
        writers = (risk_writer, exposure_writer)
        roles = [writer.expected_role for writer in writers] + [lifecycle_bindings.expected_role]
        if (
            custody.context != context
            or exposure_writer.context != context
            or lifecycle_bindings.context != context
            or any(writer.database_uuid != database_uuid for writer in writers)
            or any(writer.policy_namespace != policy_namespace for writer in writers)
            or any(writer.state_schema_version != 3 for writer in writers)
            or len(set(roles)) != len(roles)
            or len({writer.expected_database for writer in writers} | {lifecycle_bindings.expected_database})
            != 1
        ):
            raise ValueError("exit writers, binding store, custody and PROD scope differ")
        self.verifier = verifier
        self.trades = trades
        self.effects = effects
        self.risk_writer = risk_writer
        self.exposure_writer = exposure_writer
        self.lifecycle_bindings = lifecycle_bindings
        self.custody_binding = custody
        self.context = context
        self.database_uuid = database_uuid
        self.policy_namespace = policy_namespace

    async def stage_prepared_exit(
        self,
        *,
        effect_id: str,
        raw_evidence: object,
        manual_request_sha256: str,
        expires_at: datetime,
        now: datetime,
    ) -> ProductionExitRiskStageReceiptV1:
        now = self._utc(now, "now")
        expires_at = self._utc(expires_at, "expires_at")
        if not now < expires_at <= now + _MAX_AGE:
            raise ProductionExitRiskError("exit request lease must be positive and at most five seconds")
        effect, trade, decision, role = await self._load_exact_prepared(effect_id)
        try:
            verified = self.verifier.verify_exit(
                raw_evidence,
                expected_context=self.context,
                trade=trade,
                decision=decision,
                effect=effect,
                role=role,
                now=now,
            )
            verified = VerifiedLiveExitEvidenceV1.model_validate(verified)
        except Exception:
            raise ProductionExitRiskError("qualified per-effect exit verifier refused") from None
        self._check_verified(verified, effect=effect, trade=trade, decision=decision, role=role, now=now)

        lease = min(expires_at, now + _MAX_AGE, verified.valid_until, verified.exposure.valid_until)
        if lease <= now:
            raise ProductionExitRiskError("exit risk/exposure lease expired before staging")
        try:
            risk_loss = self._worst_case_loss(verified, effect=effect, decision=decision, role=role)
        except Exception:
            raise ProductionExitRiskError("qualified source facts cannot bound this exit loss") from None
        if risk_loss <= 0 or not risk_loss.is_finite():
            raise ProductionExitRiskError(
                "qualified source facts produce no positive conservative exit cost/loss"
            )
        verified_facts_sha256 = hashlib.sha256(
            json.dumps(
                verified.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode()
        ).hexdigest()
        risk_id = hashlib.sha256(
            json.dumps(
                {
                    "domain": "kairos.production-live-exit-risk.v1",
                    "context_sha256": canonical_digest(self.context),
                    "source_id": verified.source_id,
                    "source_evidence_sha256": verified.evidence_sha256,
                    "verified_facts_sha256": verified_facts_sha256,
                    "computed_worst_case_loss_usd": str(risk_loss),
                    "effect_id": effect.effect_key,
                    "effect_request_sha256": effect.request_sha256,
                    "effect_journal_head_sha256": effect.journal_head_sha256,
                    "trade_id": trade.trade_id,
                    "original_decision_sha256": canonical_digest(decision),
                    "role": role,
                },
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode()
        ).hexdigest()
        try:
            binding = build_production_lifecycle_binding(
                decision=decision,
                context=self.context,
                custody_binding=self.custody_binding,
                role=role,
                lifecycle_effect_id=effect.effect_key,
                client_order_id=effect.client_order_id or "",
                manual_request_sha256=manual_request_sha256,
                expires_at=lease,
                now=now,
                parent_order_id=trade.entry_client_order_id,
                close_quantity=(
                    float.fromhex(effect.request_payload["quantity_hex"])
                    if role in {"TIMEOUT_EXIT", "EMERGENCY_EXIT"}
                    else None
                ),
                risk_decision_id=risk_id,
            )
            risk = self._risk_geometry(
                binding,
                verified,
                worst_case_loss_usd=risk_loss,
                observed_at=verified.observed_at,
                valid_until=lease,
            )
        except Exception:
            raise ProductionExitRiskError(
                "exact per-effect exit request geometry could not be bound"
            ) from None

        # Re-read both durable chains after source verification so a PREPARED
        # effect cannot race into another journal state during publication.
        current = await self._load_exact_prepared(effect_id)
        if current[:3] != (effect, trade, decision) or current[3] != role:
            raise ProductionExitRiskError("PREPARED exit journal changed during source verification")

        # Persist exposure first, then request-bound risk, then passive binding.
        # Any partial result grants no dispatch authority and must not be blindly retried.
        try:
            await self.exposure_writer.append_exposure_async(verified.exposure)
        except Exception:
            raise ProductionExitRiskError(
                "exit exposure write failed or is unresolved; do not retry blindly"
            ) from None
        try:
            await self.risk_writer.append_risk_decision_async(risk)
        except Exception:
            raise ProductionExitRiskError(
                "exit risk write failed or is unresolved; do not retry blindly"
            ) from None
        try:
            inserted = await self.lifecycle_bindings.put(binding)
        except Exception:
            raise ProductionExitRiskError("exit binding write failed or is unresolved; no dispatch") from None
        return ProductionExitRiskStageReceiptV1(
            source_id=verified.source_id,
            evidence_sha256=verified.evidence_sha256,
            lifecycle_binding=binding,
            risk_geometry=risk,
            exposure=verified.exposure,
            staged_at=now,
            binding_inserted=inserted,
        )

    async def _load_exact_prepared(
        self, effect_id: str
    ) -> tuple[ExecutionEffect, TradeRecord, RiskTradeDecisionV1, LifecycleRole]:
        try:
            effect = await self.effects.get(effect_id)
            if (
                effect is None
                or effect.status is not EffectStatus.PREPARED
                or effect.trade_id is None
                or effect.account_id != self.context.remote_account_id
                or effect.environment != f"PROD:{canonical_digest(self.context)}:LIVE"
                or effect.exchange != "evedex"
                or not await self.effects.verify_chain(effect_id)
            ):
                raise ValueError
            trade = await self.trades.get(effect.trade_id)
            if (
                trade is None
                or not await self.trades.verify_chain(trade.trade_id)
                or trade.trade_id != effect.trade_id
                or trade.trading_mode != TradingMode.LIVE.value
                or trade.profile != EvedexProfile.PROD.value
                or trade.environment != effect.environment
                or trade.account_id != self.context.remote_account_id
                or trade.exchange != "evedex"
                or trade.strategy_id != self.context.adaptive_system_id
                or effect.symbol != trade.symbol
                or effect.account_id != trade.account_id
                or effect.exchange != trade.exchange
                or effect.trade_id != trade.trade_id
            ):
                raise ValueError
            decision = RiskTradeDecisionV1.model_validate(trade.risk_decision_payload)
            if (
                not decision.approved
                or decision.trading_mode is not TradingMode.LIVE
                or decision.evedex_profile is not EvedexProfile.PROD
                or decision.venue_symbol.endswith(":DEV")
                or decision.venue_symbol not in self.custody_binding.approved_instruments
                or decision.account_id != trade.account_id
                or decision.trade_id != trade.trade_id
                or decision.decision_id != trade.risk_decision_id
                or decision.venue_symbol != trade.venue_symbol
                or decision.intent.strategy_id != trade.strategy_id
                or decision.intent.strategy_revision != trade.strategy_revision
                or trade.leverage != 1
                or self._to_wire_quantity(trade.filled_quantity) > self._to_wire_quantity(decision.quantity)
                or self._to_wire_quantity(trade.quantity) != self._to_wire_quantity(decision.quantity)
                or trade.side != ("BUY" if decision.intent.side is Side.LONG else "SELL")
            ):
                raise ValueError
            config = _ROLE_CONFIG.get(effect.order_role or "")
            if config is None:
                raise ValueError
            role, expected_type, operation, expected_state = config
            if (
                effect.effect_type is not expected_type
                or trade.state is not expected_state
                or effect.effect_key
                != hashlib.sha256(
                    f"prod.v1:{canonical_digest(self.context)}:{trade.trade_id}:{role}:{operation}".encode()
                ).hexdigest()
                or effect.client_order_id is None
                or effect.request_payload.get("trade_id") != trade.trade_id
                or effect.request_payload.get("client_order_id") != effect.client_order_id
                or effect.request_payload.get("venue_symbol") != trade.venue_symbol
                or canonical_payload(effect.request_payload)[1] != effect.request_sha256
            ):
                raise ValueError
            self._check_effect_geometry(effect, trade, decision, role)
            if not await self.trades.verify_chain(trade.trade_id):
                raise ValueError
            return effect, trade, decision, role
        except Exception:
            raise ProductionExitRiskError("durable PREPARED effect/trade lineage is invalid") from None

    @staticmethod
    def _check_effect_geometry(
        effect: ExecutionEffect, trade: TradeRecord, decision: RiskTradeDecisionV1, role: LifecycleRole
    ) -> None:
        payload = effect.request_payload
        if role in {"STOP_LOSS", "TAKE_PROFIT"}:
            expected_keys = {
                "trade_id",
                "client_order_id",
                "parent_order_id",
                "venue_symbol",
                "side",
                "tpsl_type",
                "quantity_hex",
                "price_hex",
            }
            expected_price = (
                decision.exit_plan.stop_price if role == "STOP_LOSS" else decision.exit_plan.target_price
            )
            expected_tpsl = role
            if (
                set(payload) != expected_keys
                or effect.client_order_id
                != (trade.stop_client_order_id if role == "STOP_LOSS" else trade.target_client_order_id)
                or payload.get("parent_order_id") != trade.entry_client_order_id
                or payload.get("side") != trade.side
                or payload.get("tpsl_type") != expected_tpsl
                or payload.get("quantity_hex") != float(0).hex()
                or payload.get("price_hex") != float(expected_price).hex()
                or Decimal(str(expected_price))
                != Decimal(str(trade.stop_price if role == "STOP_LOSS" else trade.target_price))
            ):
                raise ValueError("protective effect differs from original exit plan")
            return
        expected_client = trade.close_client_order_id
        if set(payload) != {"trade_id", "client_order_id", "venue_symbol", "quantity_hex", "leverage_hex"}:
            raise ValueError("close effect payload fields differ from the exact close contract")
        quantity_hex = payload.get("quantity_hex")
        leverage_hex = payload.get("leverage_hex")
        try:
            quantity = float.fromhex(quantity_hex) if isinstance(quantity_hex, str) else math.nan
            leverage = float.fromhex(leverage_hex) if isinstance(leverage_hex, str) else math.nan
        except Exception:
            raise ValueError("close effect quantity/leverage encoding is invalid") from None
        if (
            effect.client_order_id != expected_client
            or not math.isfinite(quantity)
            or quantity <= 0
            or quantity > trade.filled_quantity
            or not math.isfinite(leverage)
            or leverage != 1
        ):
            raise ValueError("close effect differs from durable trade quantity/leverage")

    def _check_verified(
        self,
        value: VerifiedLiveExitEvidenceV1,
        *,
        effect: ExecutionEffect,
        trade: TradeRecord,
        decision: RiskTradeDecisionV1,
        role: LifecycleRole,
        now: datetime,
    ) -> None:
        if (
            value.source_id != self.verifier.source_id
            or value.context_sha256 != canonical_digest(self.context)
            or value.trade_id != trade.trade_id
            or value.original_decision_id != decision.decision_id
            or value.original_decision_sha256 != canonical_digest(decision)
            or value.effect_id != effect.effect_key
            or value.effect_request_sha256 != effect.request_sha256
            or value.role != role
            or value.exposure.context != self.context
            or value.exposure.instrument != trade.venue_symbol
            or value.exposure.position_side != trade.side
            or value.exposure.parent_order_id != trade.entry_client_order_id
            or value.exposure.remaining_quantity > self._to_wire_quantity(trade.filled_quantity)
            or value.exposure.remaining_quantity > self._to_wire_quantity(decision.quantity)
            or value.observed_at > now
            or now - value.observed_at > _MAX_AGE
            or value.valid_until <= now
            or value.valid_until - value.observed_at > _MAX_AGE
            or value.exposure.observed_at > now
            or now - value.exposure.observed_at > _MAX_AGE
            or value.exposure.valid_until <= now
            or value.exposure.valid_until - value.exposure.observed_at > _MAX_AGE
        ):
            raise ProductionExitRiskError(
                "verified exit evidence is stale or not bound to exact effect/exposure"
            )
        if role in {"TIMEOUT_EXIT", "EMERGENCY_EXIT"}:
            quantity = self._to_wire_quantity(float.fromhex(effect.request_payload["quantity_hex"]))
            if quantity > value.exposure.remaining_quantity:
                raise ProductionExitRiskError("prepared exit would close more than current exposure")

    def _risk_geometry(
        self,
        binding: ProductionLifecycleBindingV1,
        evidence: VerifiedLiveExitEvidenceV1,
        *,
        worst_case_loss_usd: Decimal,
        observed_at: datetime,
        valid_until: datetime,
    ) -> RiskGeometryV1:
        message = json.loads(binding.request.message_json)
        protective = binding.role in {"STOP_LOSS", "TAKE_PROFIT"}
        return RiskGeometryV1(
            context=self.context,
            decision_id=binding.risk_decision_id,
            signing_request_id=binding.request.request_id,
            effect_id=binding.signing_effect_id,
            client_order_id=message.get("id"),
            operation=binding.request.operation,
            instrument=message["instrument"],
            side=evidence.exposure.position_side
            if protective
            else self._reducing_side(evidence.exposure.position_side),
            quantity=message["quantity"],
            cash_quantity=None,
            price=None,
            stop_price=None,
            protection_type=message["type"] if protective else None,
            trigger_price=message["price"] if protective else None,
            parent_order_id=evidence.exposure.parent_order_id,
            leverage=1,
            worst_case_loss_usd=worst_case_loss_usd,
            account_equity_usd=evidence.account_equity_usd,
            daily_realized_loss_usd=evidence.daily_realized_loss_usd,
            aggregate_open_risk_usd=evidence.aggregate_open_risk_usd,
            aggregate_open_notional_usd=evidence.aggregate_open_notional_usd,
            approved=True,
            observed_at=observed_at,
            valid_until=valid_until,
        )

    @classmethod
    def _worst_case_loss(
        cls,
        evidence: VerifiedLiveExitEvidenceV1,
        *,
        effect: ExecutionEffect,
        decision: RiskTradeDecisionV1,
        role: LifecycleRole,
    ) -> Decimal:
        """Compute bounded loss + fees from qualified effect-sized price facts.

        Stops use the worse of their trigger and the verified executable exit
        quote. TP and direct-close effects use the verified executable quote.
        The source-provided slippage fraction is then applied adversely before
        calculating price loss and fee cost. No current entry budget is applied.
        """
        long_position = evidence.exposure.position_side == "BUY"
        if role in {"STOP_LOSS", "TAKE_PROFIT"}:
            # Protective wire effects use quantity=0, meaning the entire
            # same-parent position. Budget against the approved order quantity
            # so later partial fills cannot exceed this staged risk envelope.
            quantity_units = cls._to_wire_quantity(decision.quantity)
        else:
            quantity_units = cls._to_wire_quantity(float.fromhex(effect.request_payload["quantity_hex"]))
        quantity = Decimal(quantity_units) / Decimal(10**8)
        approved_entry = Decimal(str(decision.worst_entry_price))
        entry = (
            max(evidence.position_entry_price_usd, approved_entry)
            if long_position
            else min(evidence.position_entry_price_usd, approved_entry)
        )
        reference = evidence.reference_price_usd
        executable = evidence.executable_exit_price_usd
        # The executable bound must be on the conservative side of the
        # independently verified reference for the closing direction.
        if (long_position and executable > reference) or (not long_position and executable < reference):
            raise ValueError("executable exit bound is not conservative to the reference")
        base_exit = executable
        if role == "STOP_LOSS":
            trigger = Decimal(str(float.fromhex(effect.request_payload["price_hex"])))
            base_exit = min(trigger, executable) if long_position else max(trigger, executable)
        slippage = base_exit * evidence.adverse_slippage_rate
        adverse_fill = base_exit - slippage if long_position else base_exit + slippage
        price_loss_per_unit = (
            max(entry - adverse_fill, Decimal(0)) if long_position else max(adverse_fill - entry, Decimal(0))
        )
        fees_per_unit = adverse_fill * evidence.exit_fee_rate
        return quantity * (price_loss_per_unit + fees_per_unit)

    @staticmethod
    def _reducing_side(position_side: str) -> Literal["BUY", "SELL"]:
        return "SELL" if position_side == "BUY" else "BUY"

    @staticmethod
    def _to_wire_quantity(value: float) -> int:
        if not math.isfinite(value) or value <= 0:
            raise ProductionExitRiskError("position quantity is invalid")
        scaled = Decimal(str(value)) * Decimal(10**8)
        if scaled != scaled.to_integral_value():
            raise ProductionExitRiskError("position quantity is not exact at EVEDEX precision")
        return int(scaled)

    @staticmethod
    def _utc(value: datetime, name: str) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ProductionExitRiskError(f"{name} must be explicit UTC")
        return value.astimezone(UTC)
