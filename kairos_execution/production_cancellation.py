"""One-shot, journal-bound EVEDEX PROD cancellation boundary.

This module is deliberately disconnected from factories and service startup.
It accepts no URL, HTTP method, path or generic sender. Its only transport
operations are cancellation of an exact owned entry order or TP/SL identified
by the durable execution journal and trade lineage.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any, Literal, Protocol
from uuid import UUID

from kairos_core.contracts import RiskTradeDecisionV1
from kairos_core.enums import TradeLifecycleState, TradingMode
from kairos_persistence import EffectStatus, EffectType
from pydantic import Field, field_validator, model_validator

from .limit_gtc_contract import LIMIT_GTC_ENTRY_CONTRACT
from .managed_signer import CustodyBindingV1, _typed_message
from .market_ioc_admission import MARKET_IOC_ENTRY_CONTRACT
from .production_claims import PostgresProductionClaims
from .production_lifecycle_binding import ProductionLifecycleBindingV1, build_production_lifecycle_binding
from .production_readiness import (
    OwnerArmKeyV1,
    PreconditionsV1,
    ProductionContextV1,
    SignedManualArmRequestV1,
    StrictRecord,
    _verify_owner_signed_arm,
    canonical_digest,
)
from .production_state import AsyncPostgresProductionSigningStateSource
from .signing_authorization import AcceptedManualNonceV1

_IDENTITY_PATTERN = r"^[A-Za-z0-9_.:-]{1,160}$"
_MAX_AGE = timedelta(seconds=5)
_CANCEL_SCOPE = "kairos.production-cancel.v1"


class ProductionCancellationError(PermissionError):
    """Fail-closed cancellation refusal or unresolved one-shot outcome."""


class CancellationOrderFactV1(StrictRecord):
    """Normalized authoritative open-order fact from a registered EVEDEX reader."""

    order_id: str = Field(min_length=1, max_length=160, pattern=_IDENTITY_PATTERN)
    instrument: str = Field(min_length=1, max_length=64, pattern=r"^[A-Z0-9]{1,32}$")
    role: Literal["ENTRY", "EXIT"]
    status: Literal["OPEN", "PARTIALLY_FILLED"]
    side: Literal["BUY", "SELL"]
    remaining_quantity: Decimal = Field(gt=0)
    reduce_only: bool
    parent_order_id: str | None = Field(default=None, min_length=1, max_length=160)

    @field_validator("remaining_quantity")
    @classmethod
    def finite_quantity(cls, value: Decimal) -> Decimal:
        if not value.is_finite():
            raise ValueError("venue order quantity must be finite")
        return value


class CancellationProtectionFactV1(StrictRecord):
    """Normalized authoritative live protection fact tied to its entry parent."""

    protection_id: str = Field(min_length=1, max_length=160, pattern=_IDENTITY_PATTERN)
    instrument: str = Field(min_length=1, max_length=64, pattern=r"^[A-Z0-9]{1,32}$")
    protection_type: Literal["STOP_LOSS", "TAKE_PROFIT"]
    status: Literal["ACTIVE"]
    parent_order_id: str = Field(min_length=1, max_length=160, pattern=_IDENTITY_PATTERN)
    covered_quantity: Decimal = Field(gt=0)

    @field_validator("covered_quantity")
    @classmethod
    def finite_quantity(cls, value: Decimal) -> Decimal:
        if not value.is_finite():
            raise ValueError("venue protection quantity must be finite")
        return value


class ProductionCancellationVenueSnapshotV1(StrictRecord):
    """Bounded single-account/instrument view needed to prove a cancellation safe."""

    context: ProductionContextV1
    source_id: str = Field(min_length=1, max_length=160, pattern=_IDENTITY_PATTERN)
    account_id: str = Field(min_length=1, max_length=160, pattern=_IDENTITY_PATTERN)
    instrument: str = Field(min_length=1, max_length=64, pattern=r"^[A-Z0-9]{1,32}$")
    observed_at: datetime
    valid_until: datetime
    position_side: Literal["BUY", "SELL"] | None
    position_quantity: Decimal = Field(ge=0)
    entry_parent_order_id: str | None = Field(default=None, min_length=1, max_length=160)
    orders: tuple[CancellationOrderFactV1, ...] = Field(max_length=512)
    protections: tuple[CancellationProtectionFactV1, ...] = Field(max_length=512)

    @field_validator("observed_at", "valid_until")
    @classmethod
    def utc_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("venue timestamps must be explicit UTC")
        return value

    @field_validator("position_quantity")
    @classmethod
    def finite_position(cls, value: Decimal) -> Decimal:
        if not value.is_finite():
            raise ValueError("venue position quantity must be finite")
        return value

    @model_validator(mode="after")
    def position_shape(self) -> ProductionCancellationVenueSnapshotV1:
        if (self.position_quantity == 0) != (self.position_side is None):
            raise ValueError("venue position side/quantity disagree")
        if self.valid_until <= self.observed_at or self.valid_until - self.observed_at > _MAX_AGE:
            raise ValueError("venue snapshot validity is empty or exceeds five seconds")
        if len({item.order_id for item in self.orders}) != len(self.orders):
            raise ValueError("venue order facts are duplicated")
        if len({item.protection_id for item in self.protections}) != len(self.protections):
            raise ValueError("venue protection facts are duplicated")
        return self


class ProductionCancellationVenueSource(Protocol):
    """Registered reader/verifier, not a boolean callback or transport sender."""

    source_id: str

    async def read_cancellation_snapshot_async(
        self, *, context: ProductionContextV1, account_id: str, instrument: str
    ) -> Any: ...

    def verify_cancellation_snapshot(
        self,
        raw_snapshot: Any,
        *,
        context: ProductionContextV1,
        account_id: str,
        instrument: str,
    ) -> ProductionCancellationVenueSnapshotV1: ...


class EvedexCancellationTransport(Protocol):
    """Pinned operation-only SDK bridge; no generic HTTP method/path surface."""

    async def cancel_order(self, *, effect_id: str, instrument: str, order_id: str) -> dict[str, Any]: ...

    async def cancel_tpsl(self, *, effect_id: str, instrument: str, protection_id: str) -> dict[str, Any]: ...


class _CancellationPlan(StrictRecord):
    context: ProductionContextV1
    database_uuid: UUID
    trade_id: str = Field(min_length=1, max_length=160, pattern=_IDENTITY_PATTERN)
    decision_id: str = Field(min_length=1, max_length=160, pattern=_IDENTITY_PATTERN)
    effect_id: str = Field(min_length=1, max_length=160, pattern=r"^[a-f0-9]{64}$")
    cancellation_type: Literal["CANCEL_ORDER", "CANCEL_TPSL"]
    role: Literal["ENTRY", "STOP_LOSS", "TAKE_PROFIT"]
    instrument: str = Field(min_length=1, max_length=64, pattern=r"^[A-Z0-9]{1,32}$")
    target_id: str = Field(min_length=1, max_length=160, pattern=_IDENTITY_PATTERN)
    origin_effect_id: str = Field(min_length=1, max_length=160, pattern=_IDENTITY_PATTERN)
    manual_request_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    request_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class ProductionCancellationVerifier:
    """Verify durable ownership and fresh safety facts, claim once, then cancel.

    This is opt-in and not wired by a service/factory. The state source, venue
    reader and SDK bridge are explicit trust boundaries with narrow typed
    operations. Cancellation never signs typed order data.
    """

    def __init__(
        self,
        *,
        claims: PostgresProductionClaims,
        state_source: AsyncPostgresProductionSigningStateSource,
        bindings: Any,
        custody_binding: CustodyBindingV1,
        trades: Any,
        effects: Any,
        venue_sources: Mapping[str, ProductionCancellationVenueSource],
        transport: EvedexCancellationTransport,
        database_uuid: UUID,
        context: ProductionContextV1,
        preconditions: PreconditionsV1,
        owner_key: OwnerArmKeyV1,
        expected_owner_key_sha256: str,
        expected_owner_identity: str,
        maximum_arm_lifetime: timedelta = timedelta(minutes=10),
        clock: Any = None,
    ) -> None:
        if not isinstance(database_uuid, UUID) or database_uuid.int == 0:
            raise ValueError("an exact isolated production database UUID is required")
        context = ProductionContextV1.model_validate(context)
        preconditions = PreconditionsV1.model_validate(preconditions)
        owner_key = OwnerArmKeyV1.model_validate(owner_key)
        custody_binding = CustodyBindingV1.model_validate(custody_binding)
        if not timedelta(0) < maximum_arm_lifetime <= timedelta(minutes=10):
            raise ValueError("manual-arm lifetime must be positive and at most ten minutes")
        if context.environment != "PROD" or context.exchange != "EVEDEX":
            raise ValueError("cancellation is restricted to the exact EVEDEX PROD context")
        if (
            preconditions.context != context
            or owner_key.context != context
            or owner_key.owner_identity != expected_owner_identity
            or claims.database_uuid != database_uuid
            or state_source.database_uuid != database_uuid
            or claims.context_sha256 != canonical_digest(context)
            or state_source.context != context
            or custody_binding.context != context
            or getattr(bindings, "context", None) != context
            or getattr(bindings, "pool", None) is not state_source.pool
            or claims.pool is not state_source.pool
            or getattr(trades, "pool", None) is not state_source.pool
            or getattr(effects, "pool", None) is not state_source.pool
        ):
            raise ValueError("cancellation stores, owner policy, and PROD scope do not match")
        if (
            not isinstance(venue_sources, Mapping)
            or not venue_sources
            or any(
                source_id != getattr(source, "source_id", None)
                or not callable(getattr(source, "read_cancellation_snapshot_async", None))
                or not callable(getattr(source, "verify_cancellation_snapshot", None))
                for source_id, source in venue_sources.items()
            )
        ):
            raise ValueError("explicit registered typed cancellation venue sources are required")
        self.claims = claims
        self.state_source = state_source
        self.bindings = bindings
        self.custody_binding = custody_binding
        self.trades = trades
        self.effects = effects
        self.venue_sources = dict(venue_sources)
        self.transport = transport
        self.database_uuid = database_uuid
        self.context = context
        self.preconditions = preconditions
        self.owner_key = owner_key
        self.expected_owner_key_sha256 = expected_owner_key_sha256
        self.expected_owner_identity = expected_owner_identity
        self.maximum_arm_lifetime = maximum_arm_lifetime
        self.clock = clock or (lambda: datetime.now(UTC))

    async def cancel_entry_remainder(
        self, *, effect_id: str, trade_id: str, instrument: str, client_order_id: str
    ) -> dict[str, Any]:
        return await self._cancel(
            effect_id=effect_id,
            trade_id=trade_id,
            instrument=instrument,
            target_id=client_order_id,
            role="ENTRY",
        )

    async def cancel_entry(self, *, effect_id: str, symbol: str, client_order_id: str) -> dict[str, Any]:
        """Adapter-compatible entry remainder cancellation API."""
        return await self._cancel(
            effect_id=effect_id,
            trade_id=None,
            instrument=symbol,
            target_id=client_order_id,
            role=None,
        )

    async def cancel_owned_tpsl(
        self,
        *,
        effect_id: str,
        trade_id: str,
        instrument: str,
        protection_id: str,
        role: Literal["STOP_LOSS", "TAKE_PROFIT"],
    ) -> dict[str, Any]:
        return await self._cancel(
            effect_id=effect_id,
            trade_id=trade_id,
            instrument=instrument,
            target_id=protection_id,
            role=role,
        )

    async def cancel_tpsl(self, *, effect_id: str, symbol: str, tpsl_id: str) -> dict[str, Any]:
        """Adapter-compatible TP/SL cancellation API, role resolved from journal."""
        return await self._cancel(
            effect_id=effect_id,
            trade_id=None,
            instrument=symbol,
            target_id=tpsl_id,
            role=None,
        )

    async def _cancel(
        self,
        *,
        effect_id: str,
        trade_id: str | None,
        instrument: str,
        target_id: str,
        role: Literal["ENTRY", "STOP_LOSS", "TAKE_PROFIT"] | None,
    ) -> dict[str, Any]:
        if (
            not _is_digest(effect_id)
            or type(instrument) is not str
            or re.fullmatch(r"[A-Z0-9]{1,32}", instrument) is None
            or type(target_id) is not str
            or re.fullmatch(_IDENTITY_PATTERN, target_id) is None
        ):
            raise ProductionCancellationError("cancellation request identity is malformed")
        preliminary = await self.effects.get(effect_id)
        if preliminary is None:
            raise ProductionCancellationError("durable cancellation effect is absent")
        if trade_id is None:
            trade_id = preliminary.trade_id
        if role is None:
            role = preliminary.order_role
        if type(trade_id) is not str or role not in {"ENTRY", "STOP_LOSS", "TAKE_PROFIT"}:
            raise ProductionCancellationError("cancellation effect lacks exact trade/role lineage")
        cancellation_type: Literal["CANCEL_ORDER", "CANCEL_TPSL"] = (
            "CANCEL_ORDER" if role == "ENTRY" else "CANCEL_TPSL"
        )
        plan, trade, effect, _origin, source = await self._prove(
            effect_id=effect_id,
            trade_id=trade_id,
            instrument=instrument,
            target_id=target_id,
            role=role,
            cancellation_type=cancellation_type,
        )
        try:
            claimed = await self.claims.claim_wire_once_async(
                namespace=f"{_CANCEL_SCOPE}:{canonical_digest(self.context)}",
                effect_id=effect.effect_key,
                request_sha256=plan.request_sha256,
            )
        except Exception:
            raise ProductionCancellationError("cancellation claim outcome unresolved; do not retry") from None
        if claimed is not True:
            raise ProductionCancellationError("cancellation effect is already claimed or unresolved")

        try:
            # Repeat all durable and venue checks after the immutable claim and
            # immediately before the single transport operation.
            final_plan, _final_trade, _final_effect, _final_origin, _final_source = await self._prove(
                effect_id=effect_id,
                trade_id=trade_id,
                instrument=instrument,
                target_id=target_id,
                role=role,
                cancellation_type=cancellation_type,
            )
            if (
                final_plan.request_sha256 != plan.request_sha256
                or final_plan.effect_id != plan.effect_id
                or final_plan.origin_effect_id != plan.origin_effect_id
                or final_plan.manual_request_sha256 != plan.manual_request_sha256
            ):
                raise ProductionCancellationError("cancellation lineage changed after one-shot claim")
        except asyncio.CancelledError:
            await self._finish_shielded(plan, "UNRESOLVED", None)
            raise
        except Exception:
            await self._finish_shielded(plan, "UNRESOLVED", None)
            raise ProductionCancellationError(
                "post-claim cancellation authority changed; do not retry"
            ) from None

        try:
            async with asyncio.timeout(10):
                if role == "ENTRY":
                    response = await self.transport.cancel_order(
                        effect_id=effect.effect_key,
                        instrument=plan.instrument,
                        order_id=target_id,
                    )
                else:
                    response = await self.transport.cancel_tpsl(
                        effect_id=effect.effect_key,
                        instrument=plan.instrument,
                        protection_id=target_id,
                    )
            if (
                not isinstance(response, dict)
                or response.get("status") != "CANCELED"
                or response.get("id") != target_id
            ):
                raise ValueError("venue cancellation acknowledgement differs from target")
            response_sha256 = _sha256(response)
        except asyncio.CancelledError:
            await self._finish_shielded(plan, "UNRESOLVED", None)
            raise
        except Exception:
            await self._finish_shielded(plan, "UNRESOLVED", None)
            raise ProductionCancellationError("cancellation outcome unresolved; do not retry") from None

        await self._finish_shielded(plan, "COMPLETED", response_sha256)
        try:
            await self.effects.confirm(
                effect.effect_key,
                exchange_effect_id=target_id,
                response_payload=response,
            )
        except Exception:
            raise ProductionCancellationError(
                "venue cancellation completed but execution journal confirmation is unresolved"
            ) from None
        return response

    async def _prove(
        self,
        *,
        effect_id: str,
        trade_id: str,
        instrument: str,
        target_id: str,
        role: Literal["ENTRY", "STOP_LOSS", "TAKE_PROFIT"],
        cancellation_type: Literal["CANCEL_ORDER", "CANCEL_TPSL"],
    ):
        now = self._now()
        if type(effect_id) is not str or not effect_id or type(trade_id) is not str or not trade_id:
            raise ProductionCancellationError("cancellation identity is malformed")
        trade = await self.trades.get(trade_id)
        effect = await self.effects.get(effect_id)
        if trade is None or effect is None:
            raise ProductionCancellationError("durable cancellation trade/effect is absent")
        verify_trade = getattr(self.trades, "verify_chain", None)
        verify_effect = getattr(self.effects, "verify_chain", None)
        if (
            not callable(verify_trade)
            or not callable(verify_effect)
            or await verify_trade(trade_id) is not True
            or await verify_effect(effect_id) is not True
        ):
            raise ProductionCancellationError("durable trade/cancellation journal chain is invalid")
        self._validate_trade(trade, trade_id)
        # The lifecycle adapter's public argument is the logical trade symbol,
        # while the venue reader and SDK must use the durable mapped symbol.
        # Accept either representation only when it matches this exact trade.
        if instrument == trade.symbol:
            instrument = trade.venue_symbol
        elif instrument != trade.venue_symbol:
            raise ProductionCancellationError("cancellation instrument differs from exact trade")
        self._validate_effect(
            effect,
            trade=trade,
            effect_id=effect_id,
            cancellation_type=cancellation_type,
            instrument=instrument,
            target_id=target_id,
            role=role,
        )
        origin_key = self._origin_effect_key(trade, role)
        origin = await self.effects.get(origin_key)
        if origin is None or await verify_effect(origin_key) is not True:
            raise ProductionCancellationError("durable origin execution journal chain is invalid")
        binding = await self.bindings.get(origin_key)
        self._validate_origin(
            origin,
            trade=trade,
            origin_key=origin_key,
            role=role,
            target_id=target_id,
            binding=binding,
        )
        signing_claimed_at = await self._verify_completed_origin_claims(binding, origin=origin)
        owner_hash = self._verify_origin_binding(
            binding,
            trade=trade,
            origin=origin,
            origin_key=origin_key,
            role=role,
            signing_claimed_at=signing_claimed_at,
        )
        entry_key = self._origin_effect_key(trade, "ENTRY")
        if role == "ENTRY":
            entry_binding = binding
            entry_hash = owner_hash
        else:
            entry_origin = await self.effects.get(entry_key)
            if entry_origin is None or await verify_effect(entry_key) is not True:
                raise ProductionCancellationError("durable entry origin journal chain is invalid")
            entry_binding = await self.bindings.get(entry_key)
            entry_claimed_at = await self._verify_completed_origin_claims(entry_binding, origin=entry_origin)
            entry_hash = self._verify_origin_binding(
                entry_binding,
                trade=trade,
                origin=entry_origin,
                origin_key=entry_key,
                role="ENTRY",
                signing_claimed_at=entry_claimed_at,
            )
            if entry_hash != owner_hash:
                raise ProductionCancellationError("protection owner lineage differs from original entry")
        owner_arm, nonce = await self.state_source.resolve_owner_lineage_async(owner_hash)
        self._verify_owner_lineage(owner_arm, nonce, expected_digest=owner_hash, now=now)
        entry_reservation = await self.state_source.resolve_entry_reservation_async(
            entry_binding.signing_effect_id,
            entry_hash,
            entry_binding.request.request_id,
            entry_binding.risk_decision_id,
        )
        if (
            entry_reservation.effect_id != entry_binding.signing_effect_id
            or entry_reservation.owner_arm_sha256 != entry_hash
            or entry_reservation.signing_request_id != entry_binding.request.request_id
            or entry_reservation.decision_id != entry_binding.risk_decision_id
            or entry_reservation.client_order_id != trade.entry_client_order_id
            or entry_reservation.dollar_cap != owner_arm.request.dollar_cap
            or entry_reservation.daily_stop_loss_usd != owner_arm.request.daily_stop_loss_usd
        ):
            raise ProductionCancellationError("entry reservation differs from exact signed trade lineage")
        self._verify_entry_reservation_geometry(entry_reservation, entry_binding, trade)
        source, venue = await self._read_venue(instrument=instrument, now=now)
        checked_at = self._now()
        self._validate_venue(
            venue,
            trade=trade,
            instrument=instrument,
            target_id=target_id,
            role=role,
            source_id=source.source_id,
            now=checked_at,
        )
        plan_record = {
            "context_sha256": canonical_digest(self.context),
            "database_uuid": str(self.database_uuid),
            "trade_id": trade_id,
            "decision_id": trade.risk_decision_id,
            "effect_id": effect.effect_key,
            "cancellation_type": cancellation_type,
            "role": role,
            "instrument": instrument,
            "target_id": target_id,
            "origin_effect_id": origin_key,
            "manual_request_sha256": owner_hash,
            "venue_source_id": source.source_id,
        }
        request_sha256 = _sha256(plan_record)
        plan = _CancellationPlan(
            context=self.context,
            database_uuid=self.database_uuid,
            trade_id=trade_id,
            decision_id=trade.risk_decision_id,
            effect_id=effect.effect_key,
            cancellation_type=cancellation_type,
            role=role,
            instrument=instrument,
            target_id=target_id,
            origin_effect_id=origin_key,
            manual_request_sha256=owner_hash,
            request_sha256=request_sha256,
        )
        return plan, trade, effect, origin, source

    def _verify_entry_reservation_geometry(
        self, reservation: Any, binding: ProductionLifecycleBindingV1, trade: Any
    ) -> None:
        try:
            decision = RiskTradeDecisionV1.model_validate(trade.risk_decision_payload)
            risk = reservation.risk_evidence
            message = json.loads(binding.request.message_json)
        except Exception:
            raise ProductionCancellationError("entry risk reservation geometry is unavailable") from None
        expected_side = "BUY" if decision.intent.side.value == "LONG" else "SELL"
        if (
            binding.role != "ENTRY"
            or risk.context != self.context
            or risk.decision_id != decision.decision_id
            or risk.signing_request_id != binding.request.request_id
            or risk.effect_id != binding.signing_effect_id
            or risk.client_order_id != trade.entry_client_order_id
            or risk.operation != binding.request.operation
            or risk.instrument != decision.venue_symbol
            or risk.side != expected_side
            or risk.quantity != message.get("quantity", 0)
            or risk.cash_quantity != message.get("cashQuantity")
            or risk.price != message.get("limitPrice")
            or risk.leverage != 1
            or risk.worst_case_loss_usd != Decimal(str(decision.worst_case_loss_usd))
        ):
            raise ProductionCancellationError(
                "entry risk reservation differs from exact Core signing geometry"
            )

    def _validate_trade(self, trade: Any, trade_id: str) -> None:
        state = getattr(trade.state, "value", trade.state)
        if (
            trade.trade_id != trade_id
            or trade.trading_mode != TradingMode.LIVE.value
            or trade.profile != "PROD"
            or str(trade.exchange).casefold() != "evedex"
            or trade.account_id != self.context.remote_account_id
            or trade.environment != f"PROD:{canonical_digest(self.context)}:LIVE"
            or type(trade.venue_symbol) is not str
            or not trade.venue_symbol.isupper()
            or state in {TradeLifecycleState.CANCELLED.value, TradeLifecycleState.FAILED_BLOCKED.value}
        ):
            raise ProductionCancellationError("trade is outside the exact EVEDEX LIVE/PROD account scope")

    def _validate_effect(
        self,
        effect: Any,
        *,
        trade: Any,
        effect_id: str,
        cancellation_type: str,
        instrument: str,
        target_id: str,
        role: str,
    ) -> None:
        expected_type = (
            EffectType.CANCEL_ORDER if cancellation_type == "CANCEL_ORDER" else EffectType.CANCEL_TPSL
        )
        expected_client_id = (
            trade.entry_client_order_id
            if role == "ENTRY"
            else trade.stop_client_order_id
            if role == "STOP_LOSS"
            else trade.target_client_order_id
        )
        expected_effect_id = hashlib.sha256(
            f"prod.v1:{canonical_digest(self.context)}:{trade.trade_id}:{role}:cancel".encode()
        ).hexdigest()
        if (
            effect.effect_key != effect_id
            or effect.effect_key != expected_effect_id
            or effect.effect_type is not expected_type
            or effect.status is not EffectStatus.PREPARED
            or str(effect.exchange).casefold() != "evedex"
            or effect.environment != trade.environment
            or effect.account_id != trade.account_id
            or effect.trade_id != trade.trade_id
            or effect.order_role != role
            or effect.symbol != trade.symbol
            or effect.client_order_id != expected_client_id
            or instrument != trade.venue_symbol
        ):
            raise ProductionCancellationError("PREPARED cancellation effect does not match trade lineage")
        payload = effect.request_payload
        expected_payload = (
            {
                "trade_id": trade.trade_id,
                "client_order_id": trade.entry_client_order_id,
                "venue_symbol": instrument,
            }
            if role == "ENTRY"
            else {
                "trade_id": trade.trade_id,
                "client_order_id": expected_client_id,
                "tpsl_id": target_id,
                "venue_symbol": instrument,
            }
        )
        if (
            not isinstance(payload, dict)
            or set(payload) != set(expected_payload)
            or any(payload.get(key) != value for key, value in expected_payload.items())
        ):
            raise ProductionCancellationError("cancellation request payload differs from owned target")

    def _validate_origin(
        self,
        origin: Any,
        *,
        trade: Any,
        origin_key: str,
        role: str,
        target_id: str,
        binding: ProductionLifecycleBindingV1 | None = None,
    ) -> None:
        if origin is None:
            raise ProductionCancellationError("owned origin effect is absent")
        try:
            decision = RiskTradeDecisionV1.model_validate(trade.risk_decision_payload)
        except Exception:
            raise ProductionCancellationError("trade lacks its canonical original Core decision") from None
        if (
            decision.trade_id != trade.trade_id
            or decision.decision_id != trade.risk_decision_id
            or decision.intent.symbol != trade.symbol
            or decision.venue_symbol != trade.venue_symbol
        ):
            raise ProductionCancellationError("trade Core decision identity differs from durable trade")
        if role == "ENTRY":
            owned_client_id = trade.entry_client_order_id
            owned_exchange_id = trade.entry_exchange_order_id
            origin_type = EffectType.PLACE_ORDER
        elif role == "STOP_LOSS":
            owned_client_id = trade.stop_client_order_id
            owned_exchange_id = trade.stop_exchange_order_id
            origin_type = EffectType.PROTECTIVE_STOP
        else:
            owned_client_id = trade.target_client_order_id
            owned_exchange_id = trade.target_exchange_order_id
            origin_type = EffectType.TAKE_PROFIT
        if (
            origin.effect_key != origin_key
            or origin.effect_type is not origin_type
            or origin.status not in {EffectStatus.CONFIRMED, EffectStatus.RECONCILED}
            or origin.trade_id != trade.trade_id
            or origin.order_role != role
            or origin.client_order_id != owned_client_id
            or origin.exchange_effect_id != owned_exchange_id
            or origin.environment != trade.environment
            or origin.account_id != trade.account_id
            or origin.exchange.casefold() != "evedex"
            or owned_client_id is None
            or owned_exchange_id is None
            or (role == "ENTRY" and owned_client_id != target_id)
            or (role != "ENTRY" and owned_exchange_id != target_id)
            or not isinstance(origin.request_payload, dict)
        ):
            raise ProductionCancellationError("origin effect does not prove target ownership")
        expected_payload = (
            {
                "trade_id": trade.trade_id,
                "intent_id": trade.strategy_intent_id,
                "client_order_id": owned_client_id,
                "venue_symbol": trade.venue_symbol,
                "side": trade.side,
                "quantity_hex": float(trade.quantity).hex(),
                "limit_price_hex": float(decision.worst_entry_price).hex(),
                "leverage_hex": float(trade.leverage).hex(),
            }
            if role == "ENTRY"
            else {
                "trade_id": trade.trade_id,
                "client_order_id": owned_client_id,
                "parent_order_id": trade.entry_client_order_id,
                "venue_symbol": trade.venue_symbol,
                "side": trade.side,
                "tpsl_type": role,
                "quantity_hex": float(0).hex(),
                "price_hex": float(trade.stop_price if role == "STOP_LOSS" else trade.target_price).hex(),
            }
        )
        if role == "ENTRY" and binding is not None and binding.market_ioc_entry is not None:
            if binding.market_ioc_envelope is None:
                raise ProductionCancellationError("original market envelope is absent")
            expected_payload = {
                "trade_id": trade.trade_id,
                "intent_id": trade.strategy_intent_id,
                "client_order_id": owned_client_id,
                "venue_symbol": trade.venue_symbol,
                "side": trade.side,
                "entry_contract": MARKET_IOC_ENTRY_CONTRACT,
                "cash_quantity_e8": binding.market_ioc_entry.cash_quantity_e8,
                "market_envelope_sha256": canonical_digest(binding.market_ioc_envelope),
                "quantity_cap_hex": float(trade.quantity).hex(),
                "leverage_hex": float(trade.leverage).hex(),
            }
        if role == "ENTRY" and binding is not None and binding.limit_gtc_entry is not None:
            expected_payload.update(
                entry_contract=LIMIT_GTC_ENTRY_CONTRACT,
                cancel_after_ms=binding.limit_gtc_entry.cancel_after_ms,
            )
        if origin.request_payload != expected_payload:
            raise ProductionCancellationError("origin journal payload differs from exact trade geometry")

    def _origin_effect_key(self, trade: Any, role: Literal["ENTRY", "STOP_LOSS", "TAKE_PROFIT"]) -> str:
        operation = "place" if role == "ENTRY" else "create"
        namespace = f"prod.v1:{canonical_digest(self.context)}"
        return hashlib.sha256(f"{namespace}:{trade.trade_id}:{role}:{operation}".encode()).hexdigest()

    def _verify_origin_binding(
        self,
        candidate: Any,
        *,
        trade: Any,
        origin: Any,
        origin_key: str,
        role: Literal["ENTRY", "STOP_LOSS", "TAKE_PROFIT"],
        signing_claimed_at: datetime,
    ) -> str:
        if candidate is None or origin is None:
            raise ProductionCancellationError("exact durable lifecycle signing binding is absent")
        try:
            candidate = ProductionLifecycleBindingV1.model_validate(candidate)
            decision = RiskTradeDecisionV1.model_validate(trade.risk_decision_payload)
            expected_client_id = (
                trade.entry_client_order_id
                if role == "ENTRY"
                else trade.stop_client_order_id
                if role == "STOP_LOSS"
                else trade.target_client_order_id
            )
            rebuilt = build_production_lifecycle_binding(
                decision=decision,
                context=self.context,
                custody_binding=self.custody_binding,
                role=role,
                lifecycle_effect_id=origin_key,
                client_order_id=expected_client_id,
                manual_request_sha256=candidate.request.manual_request_sha256,
                expires_at=candidate.request.expires_at,
                # The original completed-signing claim timestamp is the
                # historical admission time; never renew an expired plan.
                now=signing_claimed_at,
                parent_order_id=None if role == "ENTRY" else trade.entry_client_order_id,
                # A protection is staged by the exit-risk publisher with its own
                # independent exit-risk record; the entry keeps the original decision.
                risk_decision_id=trade.risk_decision_id if role == "ENTRY" else candidate.risk_decision_id,
                market_ioc_entry=candidate.market_ioc_entry,
                market_ioc_envelope=candidate.market_ioc_envelope,
                limit_gtc_entry=candidate.limit_gtc_entry,
            )
        except Exception:
            raise ProductionCancellationError("stored lifecycle binding fails canonical rebuild") from None
        if (
            candidate != rebuilt
            or candidate.context != self.context
            or candidate.trade_id != trade.trade_id
            or candidate.decision_id != trade.risk_decision_id
            or (role == "ENTRY" and candidate.risk_decision_id != trade.risk_decision_id)
            or (role != "ENTRY" and re.fullmatch(r"[a-f0-9]{64}", candidate.risk_decision_id or "") is None)
            or candidate.role != role
            or candidate.lifecycle_effect_id != origin_key
            or origin.effect_key != origin_key
            or origin.client_order_id != expected_client_id
        ):
            raise ProductionCancellationError("stored lifecycle binding differs from exact journal origin")
        return candidate.request.manual_request_sha256

    @staticmethod
    def canonical_recovered_gtc_record(record):
        """Lossless JSON projection for native Decimal reads and PG roundtrip."""

        def normalize(value):
            if isinstance(value, Decimal):
                if not value.is_finite():
                    raise ProductionCancellationError("native GTC record has a nonfinite number")
                return format(value, "f")
            if isinstance(value, dict):
                return {key: normalize(item) for key, item in value.items()}
            if isinstance(value, list):
                return [normalize(item) for item in value]
            return value

        return normalize(record)

    @staticmethod
    def _validate_recovered_gtc_record(binding, record) -> None:
        """Positive exact-order proof, never absence or a legacy/market fallback."""
        try:
            message = json.loads(binding.request.message_json)
            total = Decimal(str(record["quantity"]))
            remaining = Decimal(str(record["unFilledQuantity"]))
            price = Decimal(str(record["limitPrice"]))
            average = Decimal(str(record["filledAvgPrice"]))
            status = str(record["status"]).upper().replace("CANCELLED", "CANCELED")
            valid = (
                binding.role == "ENTRY"
                and binding.limit_gtc_entry is not None
                and binding.market_ioc_entry is None
                and binding.request.operation == "New limit order"
                and record["id"] == message["id"]
                and record["instrument"] == message["instrument"]
                and record["side"] == message["side"]
                and record["type"] == "LIMIT"
                and Decimal(str(record["leverage"])) == Decimal(message["leverage"])
                and (
                    "chainId" not in record or Decimal(str(record["chainId"])) == Decimal(message["chainId"])
                )
                and record.get("timeInForce", "GTC") == "GTC"
                and status in {"PARTIALLY_FILLED", "FILLED", "CANCELED", "EXPIRED"}
                and (status != "FILLED" or remaining == 0)
                and (status != "PARTIALLY_FILLED" or remaining > 0)
                and all(value.is_finite() for value in (total, remaining, price, average))
                and total * 100_000_000 == message["quantity"]
                and price * 100_000_000 == message["limitPrice"]
                and 0 <= remaining < total
                and average > 0
                and (average <= price if message["side"] == "BUY" else average >= price)
            )
        except (KeyError, TypeError, ValueError, ArithmeticError):
            valid = False
        if not valid:
            raise ProductionCancellationError(
                "recovered GTC origin lacks exact positive signed order geometry"
            )

    async def recovered_gtc_entry_proof(self, *, binding, record) -> dict[str, str]:
        """Return non-authorizing lineage for an authenticated positive recovery.

        The engine must separately journal the exact native record. Cancellation
        still repeats its independent qualified current-account source checks.
        Neither signing nor original wire claims are changed here.
        """
        record = self.canonical_recovered_gtc_record(record)
        await self._verify_completed_origin_claims(binding, recovered_gtc_record=record)
        wire = await self.claims.load_claim(
            kind="WIRE_DISPATCH",
            namespace=f"wire:{canonical_digest(self.context)}",
            identity=binding.signing_effect_id,
        )
        if wire is None or not _is_digest(wire.get("request_sha256")):
            raise ProductionCancellationError("original GTC wire claim is absent")
        return {
            "version": "kairos.recovered-gtc-origin.v1",
            "wire_request_sha256": wire["request_sha256"],
            "record_sha256": _sha256(record),
        }

    async def _verify_completed_origin_claims(
        self,
        binding: ProductionLifecycleBindingV1,
        *,
        origin=None,
        recovered_gtc_record=None,
    ) -> datetime:
        request = binding.request
        expected_wire_sha = None
        if origin is not None and origin.status is EffectStatus.RECONCILED:
            payload = origin.response_payload
            if isinstance(payload, dict) and "recovered_gtc_origin" in payload:
                proof = payload["recovered_gtc_origin"]
                record = {key: value for key, value in payload.items() if key != "recovered_gtc_origin"}
                if (
                    not isinstance(proof, dict)
                    or set(proof) != {"version", "wire_request_sha256", "record_sha256"}
                    or proof["version"] != "kairos.recovered-gtc-origin.v1"
                    or proof["record_sha256"] != _sha256(record)
                    or not _is_digest(proof["wire_request_sha256"])
                ):
                    raise ProductionCancellationError(
                        "recovered GTC origin proof differs from journal record"
                    )
                recovered_gtc_record, expected_wire_sha = record, proof["wire_request_sha256"]
        if recovered_gtc_record is not None:
            self._validate_recovered_gtc_record(binding, recovered_gtc_record)
        try:
            _types, message = _typed_message(request, self.custody_binding)
            canonical = json.dumps(
                {
                    **request.model_dump(mode="json"),
                    "message_json": json.dumps(message, sort_keys=True),
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            request_sha = hashlib.sha256(canonical).hexdigest()
            signing_claim = await self.claims.load_claim(
                kind="TYPED_SIGNING",
                namespace=self.custody_binding.custody_reference,
                identity=request.request_id,
            )
            wire_claim = await self.claims.load_claim(
                kind="WIRE_DISPATCH",
                namespace=f"wire:{canonical_digest(self.context)}",
                identity=binding.signing_effect_id,
            )
        except Exception:
            raise ProductionCancellationError("durable origin signing/wire claims are unavailable") from None
        claimed_at = signing_claim.get("claimed_at") if signing_claim is not None else None
        if not isinstance(claimed_at, datetime):
            raise ProductionCancellationError("origin lacks exact completed signing and wire lineage")
        completed_wire = (
            wire_claim is not None
            and wire_claim.get("terminal_status") == "COMPLETED"
            and _is_digest(wire_claim.get("result_sha256"))
        )
        recovered_unknown_wire = (
            recovered_gtc_record is not None
            and wire_claim is not None
            and wire_claim.get("terminal_status") in {None, "UNRESOLVED"}
            and _is_digest(wire_claim.get("request_sha256"))
            and (expected_wire_sha is None or expected_wire_sha == wire_claim.get("request_sha256"))
        )
        if (
            signing_claim is None
            or signing_claim.get("claim_kind") != "TYPED_SIGNING"
            or signing_claim.get("namespace") != self.custody_binding.custody_reference
            or signing_claim.get("identity") != request.request_id
            or signing_claim.get("request_sha256") != request_sha
            or signing_claim.get("context_sha256") != canonical_digest(self.context)
            or signing_claim.get("terminal_status") != "COMPLETED"
            or not _is_digest(signing_claim.get("result_sha256"))
            or wire_claim is None
            or wire_claim.get("claim_kind") != "WIRE_DISPATCH"
            or wire_claim.get("namespace") != f"wire:{canonical_digest(self.context)}"
            or wire_claim.get("identity") != binding.signing_effect_id
            or wire_claim.get("context_sha256") != canonical_digest(self.context)
            or (expected_wire_sha is not None and expected_wire_sha != wire_claim.get("request_sha256"))
            or not (completed_wire or recovered_unknown_wire)
            or claimed_at.tzinfo is None
            or claimed_at.utcoffset() != timedelta(0)
            or claimed_at >= request.expires_at
            or request.expires_at - claimed_at > timedelta(seconds=30)
        ):
            raise ProductionCancellationError("origin lacks exact completed signing and wire lineage")
        return claimed_at.astimezone(UTC)

    def _verify_owner_lineage(
        self,
        owner_arm: SignedManualArmRequestV1,
        nonce: AcceptedManualNonceV1,
        *,
        expected_digest: str,
        now: datetime,
    ) -> None:
        try:
            claim_time = nonce.claimed_at
            arm, digest = _verify_owner_signed_arm(
                owner_arm,
                self.preconditions,
                owner_key=self.owner_key,
                expected_owner_key_sha256=self.expected_owner_key_sha256,
                expected_owner_identity=self.expected_owner_identity,
                now=claim_time,
                maximum_lifetime=self.maximum_arm_lifetime,
            )
        except Exception:
            raise ProductionCancellationError("accepted owner arm signature/lineage is invalid") from None
        if (
            digest != expected_digest
            or arm.context != self.context
            or nonce.owner_identity != arm.owner_identity
            or nonce.nonce != arm.nonce
            or nonce.request_sha256 != digest
            or nonce.context_sha256 != canonical_digest(self.context)
            or nonce.database_uuid != self.database_uuid
            or nonce.claimed_at < arm.created_at
            or nonce.claimed_at > now
        ):
            raise ProductionCancellationError("owner arm lacks the exact accepted PROD nonce lineage")

    async def _read_venue(
        self, *, instrument: str, now: datetime
    ) -> tuple[ProductionCancellationVenueSource, ProductionCancellationVenueSnapshotV1]:
        if len(self.venue_sources) != 1:
            raise ProductionCancellationError("cancellation requires one unambiguous registered venue source")
        source = next(iter(self.venue_sources.values()))
        async with asyncio.timeout(5):
            raw = await source.read_cancellation_snapshot_async(
                context=self.context,
                account_id=self.context.remote_account_id,
                instrument=instrument,
            )
        try:
            venue = ProductionCancellationVenueSnapshotV1.model_validate(
                source.verify_cancellation_snapshot(
                    raw,
                    context=self.context,
                    account_id=self.context.remote_account_id,
                    instrument=instrument,
                )
            )
        except Exception:
            raise ProductionCancellationError(
                "authoritative cancellation venue facts are unavailable"
            ) from None
        # A newly observed venue snapshot may legitimately postdate the clock
        # captured before durable lineage I/O. Validate against the current
        # post-capture time, without retiming the source or extending its lease.
        checked_at = self._now()
        if checked_at < now:
            raise ProductionCancellationError("cancellation clock moved backwards during venue capture")
        if (
            venue.source_id != source.source_id
            or venue.context != self.context
            or venue.account_id != self.context.remote_account_id
            or venue.instrument != instrument
            or venue.observed_at > checked_at
            or checked_at - venue.observed_at > _MAX_AGE
            or venue.valid_until <= checked_at
        ):
            raise ProductionCancellationError("cancellation venue snapshot is stale or out of scope")
        return source, venue

    @staticmethod
    def _validate_venue(
        venue: ProductionCancellationVenueSnapshotV1,
        *,
        trade: Any,
        instrument: str,
        target_id: str,
        role: str,
        source_id: str,
        now: datetime,
    ) -> None:
        if (
            venue.source_id != source_id
            or venue.instrument != instrument
            or venue.context.remote_account_id != trade.account_id
        ):
            raise ProductionCancellationError("venue cancellation facts differ from trade/account scope")
        if venue.observed_at > now or now - venue.observed_at > _MAX_AGE or venue.valid_until <= now:
            raise ProductionCancellationError("venue cancellation facts expired before final authorization")
        if role == "ENTRY":
            order = next((item for item in venue.orders if item.order_id == target_id), None)
            expected_remaining = Decimal(str(trade.quantity)) - venue.position_quantity
            if (
                order is None
                or order.role != "ENTRY"
                or order.instrument != instrument
                or order.side != trade.side
                or order.remaining_quantity != expected_remaining
                or order.reduce_only
                or venue.entry_parent_order_id not in {None, target_id}
            ):
                raise ProductionCancellationError("entry remainder is not authoritatively open and owned")
            if venue.position_quantity > 0:
                if venue.position_side != trade.side:
                    raise ProductionCancellationError(
                        "partial entry position side differs from durable trade"
                    )
                expected = {
                    ("STOP_LOSS", trade.stop_exchange_order_id),
                    ("TAKE_PROFIT", trade.target_exchange_order_id),
                }
                live = {
                    (item.protection_type, item.protection_id)
                    for item in venue.protections
                    if item.status == "ACTIVE"
                    and item.instrument == instrument
                    and item.parent_order_id == trade.entry_client_order_id
                    and item.covered_quantity >= venue.position_quantity
                }
                # The first protection can fail while the trade is still
                # PROTECTING. Cancelling its own proven entry remainder only
                # removes possible new exposure; requiring both protections
                # here would deadlock the subsequent independently authorized
                # emergency close. This does not authorize cancelling a stop
                # or closing a position. Exact owner/origin/claim checks above
                # remain mandatory, and the source must identify this position
                # as belonging to the same entry, not merely the same symbol.
                try:
                    recorded_fill = Decimal(str(getattr(trade, "filled_quantity", 0)))
                    protection_setup_remainder = (
                        getattr(getattr(trade, "state", None), "value", getattr(trade, "state", None))
                        == TradeLifecycleState.PROTECTING.value
                        and recorded_fill.is_finite()
                        and 0 < recorded_fill <= venue.position_quantity <= Decimal(str(trade.quantity))
                        and venue.entry_parent_order_id == target_id == trade.entry_client_order_id
                    )
                except (ValueError, ArithmeticError):
                    protection_setup_remainder = False
                if not expected.issubset(live) and not protection_setup_remainder:
                    raise ProductionCancellationError("partial entry exposure lacks both active protections")
            return

        protection = next((item for item in venue.protections if item.protection_id == target_id), None)
        expected_id = trade.stop_exchange_order_id if role == "STOP_LOSS" else trade.target_exchange_order_id
        if (
            protection is None
            or protection.protection_id != expected_id
            or protection.instrument != instrument
            or protection.parent_order_id != trade.entry_client_order_id
            or protection.protection_type != role
        ):
            raise ProductionCancellationError("TP/SL is not an active protection owned by this trade")
        if venue.position_quantity == 0:
            return
        if role == "STOP_LOSS":
            exit_side = "SELL" if venue.position_side == "BUY" else "BUY"
            competing_exit = any(
                item.role == "EXIT"
                and item.status in {"OPEN", "PARTIALLY_FILLED"}
                and item.instrument == instrument
                and item.reduce_only
                and item.side == exit_side
                and item.parent_order_id == trade.entry_client_order_id
                and item.remaining_quantity >= venue.position_quantity
                for item in venue.orders
            )
            if not competing_exit:
                raise ProductionCancellationError(
                    "active stop cannot be cancelled without flat exposure or an authoritative competing exit"
                )
        elif not any(
            item.protection_type == "STOP_LOSS"
            and item.status == "ACTIVE"
            and item.instrument == instrument
            and item.parent_order_id == trade.entry_client_order_id
            and item.protection_id == trade.stop_exchange_order_id
            and item.covered_quantity >= venue.position_quantity
            for item in venue.protections
        ):
            raise ProductionCancellationError(
                "take-profit cancellation would leave live exposure unprotected"
            )

    async def _finish_shielded(
        self,
        plan: _CancellationPlan,
        status: Literal["COMPLETED", "UNRESOLVED"],
        response_sha256: str | None,
    ) -> None:
        task = asyncio.create_task(
            self.claims.finish_wire_async(
                namespace=f"{_CANCEL_SCOPE}:{canonical_digest(self.context)}",
                effect_id=plan.effect_id,
                request_sha256=plan.request_sha256,
                terminal_status=status,
                response_sha256=response_sha256,
            )
        )
        task.add_done_callback(_consume_task_result)
        try:
            async with asyncio.timeout(10):
                await asyncio.shield(task)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise ProductionCancellationError(
                "cancellation terminal claim unresolved; do not retry"
            ) from None

    def _now(self) -> datetime:
        now = self.clock()
        if now.tzinfo is None or now.utcoffset() != timedelta(0):
            raise ProductionCancellationError("cancellation clock must return explicit UTC")
        return now.astimezone(UTC)


def _sha256(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _is_digest(value: Any) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _consume_task_result(task: asyncio.Task[None]) -> None:
    if not task.cancelled():
        try:
            task.exception()
        except BaseException:
            pass
