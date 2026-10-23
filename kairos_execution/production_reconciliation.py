"""Append-only terminal evidence for conservative PROD entry-risk reservations.

This module does not mutate schema-v2 reservations. It records a separately
verified zero-residual receipt; until cap readers explicitly join this table,
all schema-v2 reservations continue to count.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any, Protocol
from uuid import UUID, uuid4

import asyncpg  # type: ignore[import-untyped]  # Upstream ships no typing marker/stubs.
from pydantic import Field, field_validator, model_validator

from .production_readiness import Digest, ProductionContextV1, StrictRecord, canonical_digest
from .production_state import (
    _account_reservation_lock,
    _account_scope_sha256,
    _check_role_isolated,
    _identity,
    _role,
)

SCHEMA = "kairos_production_reconciliation_v1"
SCHEMA_VERSION = 1
MAX_EVIDENCE_AGE = timedelta(minutes=2)

DDL = """
CREATE SCHEMA kairos_production_reconciliation_v1;
REVOKE ALL ON SCHEMA kairos_production_reconciliation_v1 FROM PUBLIC;
CREATE TABLE kairos_production_reconciliation_v1.identity (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 database_uuid uuid NOT NULL,
 policy_namespace text NOT NULL,
 account_sha256 text NOT NULL CHECK(account_sha256 ~ '^[a-f0-9]{64}$'),
 schema_version integer NOT NULL CHECK(schema_version=1),
 owner_role name NOT NULL,
 reconciler_role name NOT NULL
);
CREATE TABLE kairos_production_reconciliation_v1.terminal_receipts (
 receipt_id uuid PRIMARY KEY,
 database_uuid uuid NOT NULL,
 context_sha256 text NOT NULL CHECK(context_sha256 ~ '^[a-f0-9]{64}$'),
 account_sha256 text NOT NULL CHECK(account_sha256 ~ '^[a-f0-9]{64}$'),
 trade_id text NOT NULL CHECK(length(trade_id) BETWEEN 1 AND 160),
 decision_id text NOT NULL CHECK(length(decision_id) BETWEEN 1 AND 160),
 effect_id text NOT NULL CHECK(effect_id ~ '^[a-f0-9]{64}$'),
 lifecycle_entry_effect_id text NOT NULL CHECK(lifecycle_entry_effect_id ~ '^[a-f0-9]{64}$'),
 signing_request_id text NOT NULL CHECK(length(signing_request_id) BETWEEN 1 AND 160),
 client_order_id text NOT NULL CHECK(length(client_order_id) BETWEEN 1 AND 160),
 exchange_parent_order_id text NOT NULL CHECK(length(exchange_parent_order_id) BETWEEN 1 AND 160),
 trade_journal_head_sha256 text NOT NULL CHECK(trade_journal_head_sha256 ~ '^[a-f0-9]{64}$'),
 execution_facts_sha256 text NOT NULL CHECK(execution_facts_sha256 ~ '^[a-f0-9]{64}$'),
 owned_effects_sha256 text NOT NULL CHECK(owned_effects_sha256 ~ '^[a-f0-9]{64}$'),
 entry_filled_quantity numeric NOT NULL CHECK(
  entry_filled_quantity > 0 AND entry_filled_quantity < 'Infinity'::numeric),
 closed_quantity numeric NOT NULL CHECK(closed_quantity > 0 AND closed_quantity < 'Infinity'::numeric),
 entry_notional_usd numeric NOT NULL CHECK(
  entry_notional_usd > 0 AND entry_notional_usd < 'Infinity'::numeric),
 exit_notional_usd numeric NOT NULL CHECK(exit_notional_usd > 0 AND exit_notional_usd < 'Infinity'::numeric),
 entry_fees_usd numeric NOT NULL CHECK(entry_fees_usd >= 0 AND entry_fees_usd < 'Infinity'::numeric),
 exit_fees_usd numeric NOT NULL CHECK(exit_fees_usd >= 0 AND exit_fees_usd < 'Infinity'::numeric),
 venue_source_id text NOT NULL CHECK(length(venue_source_id) BETWEEN 1 AND 160),
 venue_evidence_sha256 text NOT NULL CHECK(venue_evidence_sha256 ~ '^[a-f0-9]{64}$'),
 venue_complete boolean NOT NULL CHECK(venue_complete),
 venue_terminal boolean NOT NULL CHECK(venue_terminal),
 collection_started_at timestamptz NOT NULL,
 collection_finished_at timestamptz NOT NULL,
 observed_at timestamptz NOT NULL,
 residual_position_quantity numeric NOT NULL CHECK(residual_position_quantity=0),
 residual_order_count integer NOT NULL CHECK(residual_order_count=0),
 residual_protection_count integer NOT NULL CHECK(residual_protection_count=0),
 payload jsonb NOT NULL,
 payload_sha256 text NOT NULL CHECK(payload_sha256 ~ '^[a-f0-9]{64}$'),
 inserted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(account_sha256,effect_id),
 UNIQUE(account_sha256,trade_id),
 FOREIGN KEY(account_sha256,effect_id)
  REFERENCES kairos_production_state_v1.risk_reservations(account_sha256,effect_id),
 CHECK(collection_finished_at>=collection_started_at),
 CHECK(observed_at>=collection_finished_at),
 CHECK((payload->>'trade_id')=trade_id AND (payload->>'effect_id')=effect_id
   AND (payload->>'lifecycle_entry_effect_id')=lifecycle_entry_effect_id
   AND (payload->>'decision_id')=decision_id AND (payload->>'signing_request_id')=signing_request_id
   AND (payload->>'venue_evidence_sha256')=venue_evidence_sha256
   AND (payload->>'owned_effects_sha256')=owned_effects_sha256)
);
CREATE FUNCTION kairos_production_reconciliation_v1.reject_mutation() RETURNS trigger
 LANGUAGE plpgsql SET search_path=pg_catalog AS $$
 BEGIN RAISE EXCEPTION 'immutable production reconciliation record'; END $$;
CREATE TRIGGER identity_immutable BEFORE UPDATE OR DELETE
 ON kairos_production_reconciliation_v1.identity
 FOR EACH ROW EXECUTE FUNCTION kairos_production_reconciliation_v1.reject_mutation();
CREATE TRIGGER receipts_immutable BEFORE UPDATE OR DELETE
 ON kairos_production_reconciliation_v1.terminal_receipts
 FOR EACH ROW EXECUTE FUNCTION kairos_production_reconciliation_v1.reject_mutation();
"""


class ProductionReconciliationError(PermissionError):
    """A terminal reconciliation failed a fail-closed proof requirement."""


class ReservationTradeBindingV1(StrictRecord):
    """Explicit bridge from the signing reservation to durable trade lineage."""

    trade_id: Digest
    decision_id: str = Field(min_length=1, max_length=160)
    effect_id: Digest
    lifecycle_entry_effect_id: Digest
    signing_request_id: str = Field(min_length=1, max_length=160)
    client_order_id: str = Field(min_length=1, max_length=160)
    exchange_parent_order_id: str = Field(min_length=1, max_length=160)


class VenueTerminalEvidenceV1(StrictRecord):
    """Normalized verified evidence; notionals are unsigned for both sides.

    Entry/exit notionals are gross quantity-times-price values, not signed
    cashflows or PnL. Fees are represented separately to avoid treating a
    short entry's sale proceeds as a long-style purchase cost.
    """

    source_id: str = Field(min_length=1, max_length=160)
    source_evidence_sha256: Digest
    context_sha256: Digest
    account_id: str = Field(min_length=1, max_length=160)
    trade_id: Digest
    decision_id: str = Field(min_length=1, max_length=160)
    effect_id: Digest
    lifecycle_entry_effect_id: Digest
    signing_request_id: str = Field(min_length=1, max_length=160)
    client_order_id: str = Field(min_length=1, max_length=160)
    exchange_parent_order_id: str = Field(min_length=1, max_length=160)
    collection_started_at: datetime
    collection_finished_at: datetime
    observed_at: datetime
    complete: bool
    terminal: bool
    entry_filled_quantity: Decimal = Field(gt=0)
    closed_quantity: Decimal = Field(gt=0)
    entry_notional_usd: Decimal = Field(gt=0)
    exit_notional_usd: Decimal = Field(gt=0)
    entry_fees_usd: Decimal = Field(ge=0)
    exit_fees_usd: Decimal = Field(ge=0)
    residual_position_quantity: Decimal = Field(ge=0)
    residual_order_count: int = Field(ge=0)
    residual_protection_count: int = Field(ge=0)
    unowned_exposure_count: int = Field(ge=0)

    @field_validator("collection_started_at", "collection_finished_at", "observed_at")
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("venue evidence timestamps must be explicit UTC")
        return value

    @field_validator(
        "entry_filled_quantity",
        "closed_quantity",
        "entry_notional_usd",
        "exit_notional_usd",
        "entry_fees_usd",
        "exit_fees_usd",
        "residual_position_quantity",
    )
    @classmethod
    def _finite_decimals(cls, value: Decimal) -> Decimal:
        if not value.is_finite():
            raise ValueError("venue economics must be finite exact decimals")
        return value

    @model_validator(mode="after")
    def _bounds(self) -> VenueTerminalEvidenceV1:
        if (
            self.collection_finished_at < self.collection_started_at
            or self.observed_at < self.collection_finished_at
        ):
            raise ValueError("venue evidence collection bounds are reversed")
        return self


class VenueTerminalEvidenceVerifier(Protocol):
    """Registered adapter that validates venue-specific completeness/proof."""

    def verify_terminal_evidence(
        self,
        raw_evidence: Any,
        *,
        context: ProductionContextV1,
        binding: ReservationTradeBindingV1,
    ) -> VenueTerminalEvidenceV1: ...


class ProductionReservationReconciler:
    """Validate independent trade/journal/venue evidence and append one receipt."""

    def __init__(
        self,
        *,
        pool: asyncpg.Pool,
        expected_database: str,
        database_uuid: UUID,
        policy_namespace: str,
        context: ProductionContextV1,
        expected_role: str,
        source_verifiers: Mapping[str, VenueTerminalEvidenceVerifier],
        trades: Any,
        effects: Any,
        clock=None,
    ) -> None:
        if not isinstance(database_uuid, UUID) or database_uuid.int == 0:
            raise ProductionReconciliationError("nonzero production database UUID is required")
        self.pool = pool
        self.expected_database = _identity(expected_database)
        self.database_uuid = database_uuid
        self.policy_namespace = _identity(policy_namespace)
        self.context = ProductionContextV1.model_validate(context)
        self.expected_role = _role(expected_role)
        self.context_sha256 = canonical_digest(self.context)
        self.account_sha256 = _account_scope_sha256(self.context)
        self.source_verifiers = dict(source_verifiers)
        if not self.source_verifiers or any(
            not key or not callable(getattr(value, "verify_terminal_evidence", None))
            for key, value in self.source_verifiers.items()
        ):
            raise ProductionReconciliationError("registered venue terminal-evidence verifiers are required")
        self.trades = trades
        self.effects = effects
        self._clock = clock or (lambda: datetime.now(UTC))

    async def reconcile_terminal(
        self, *, binding: ReservationTradeBindingV1, raw_venue_evidence: Any, source_id: str
    ) -> dict[str, Any]:
        binding = ReservationTradeBindingV1.model_validate(binding)
        verifier = self.source_verifiers.get(source_id)
        if verifier is None:
            raise ProductionReconciliationError("venue evidence source is not registered")
        try:
            evidence = VenueTerminalEvidenceV1.model_validate(
                verifier.verify_terminal_evidence(raw_venue_evidence, context=self.context, binding=binding)
            )
            if evidence.source_id != source_id:
                raise ProductionReconciliationError(
                    "registered verifier returned evidence under a different source identity"
                )
            trade = await self.trades.get(binding.trade_id)
            await self._verify_trade(trade, binding, evidence)
            effects = await self._owned_effects(binding.trade_id)
            await self._verify_effects(effects, binding, trade)
            effects_digest = _canonical_sha256([dict(effect) for effect in effects])
            facts = await self.trades.list_execution_events(binding.trade_id)
            facts_digest = _canonical_sha256([event.model_dump(mode="json") for event in facts])
            await self._verify_facts(facts, binding, trade, evidence)
            now = self._now()
            self._verify_venue_evidence(evidence, binding, now)
            payload = {
                "database_uuid": str(self.database_uuid),
                "context_sha256": self.context_sha256,
                "account_sha256": self.account_sha256,
                "trade_id": binding.trade_id,
                "decision_id": binding.decision_id,
                "effect_id": binding.effect_id,
                "lifecycle_entry_effect_id": binding.lifecycle_entry_effect_id,
                "signing_request_id": binding.signing_request_id,
                "client_order_id": binding.client_order_id,
                "exchange_parent_order_id": binding.exchange_parent_order_id,
                "trade_journal_head_sha256": trade.journal_head_sha256,
                "execution_facts_sha256": facts_digest,
                "owned_effects_sha256": effects_digest,
                "entry_filled_quantity": _decimal_text(evidence.entry_filled_quantity),
                "closed_quantity": _decimal_text(evidence.closed_quantity),
                "entry_notional_usd": _decimal_text(evidence.entry_notional_usd),
                "exit_notional_usd": _decimal_text(evidence.exit_notional_usd),
                "entry_fees_usd": _decimal_text(evidence.entry_fees_usd),
                "exit_fees_usd": _decimal_text(evidence.exit_fees_usd),
                "venue_source_id": evidence.source_id,
                "venue_evidence_sha256": evidence.source_evidence_sha256,
                "venue_complete": evidence.complete,
                "venue_terminal": evidence.terminal,
                "collection_started_at": evidence.collection_started_at.isoformat(),
                "collection_finished_at": evidence.collection_finished_at.isoformat(),
                "observed_at": evidence.observed_at.isoformat(),
                "residual_position_quantity": "0",
                "residual_order_count": 0,
                "residual_protection_count": 0,
            }
            payload_sha = _canonical_sha256(payload)
            receipt_id = uuid4()
            async with self.pool.acquire() as connection:
                async with connection.transaction():
                    await self._inspect(connection)
                    await connection.execute(
                        "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                        _account_reservation_lock(self.context),
                    )
                    reservation = await connection.fetchrow(
                        "SELECT r.effect_id,r.signing_request_id,r.decision_id,r.context_sha256,"
                        "r.account_sha256,d.payload AS risk_payload,d.payload_sha256 "
                        "FROM kairos_production_state_v1.risk_reservations r "
                        "JOIN kairos_production_state_v1.risk_decisions d "
                        "ON d.context_sha256=r.context_sha256 AND d.signing_request_id=r.signing_request_id "
                        "WHERE r.account_sha256=$1 AND r.effect_id=$2",
                        self.account_sha256,
                        binding.effect_id,
                    )
                    self._verify_reservation(reservation, binding)
                    existing = await connection.fetchrow(
                        "SELECT receipt_id,payload_sha256 "
                        "FROM kairos_production_reconciliation_v1.terminal_receipts "
                        "WHERE account_sha256=$1 AND effect_id=$2",
                        self.account_sha256,
                        binding.effect_id,
                    )
                    if existing is not None:
                        if existing["payload_sha256"] != payload_sha:
                            raise ProductionReconciliationError("terminal receipt identity was rebound")
                        return {
                            "receipt_id": str(existing["receipt_id"]),
                            "created": False,
                            "payload_sha256": payload_sha,
                        }
                    await connection.execute(
                        "INSERT INTO kairos_production_reconciliation_v1.terminal_receipts "
                        "(receipt_id,database_uuid,context_sha256,account_sha256,trade_id,decision_id,effect_id,"
                        "signing_request_id,client_order_id,exchange_parent_order_id,trade_journal_head_sha256,"
                        "lifecycle_entry_effect_id,execution_facts_sha256,owned_effects_sha256,"
                        "entry_filled_quantity,closed_quantity,entry_notional_usd,"
                        "exit_notional_usd,entry_fees_usd,exit_fees_usd,"
                        "venue_source_id,venue_evidence_sha256,venue_complete,venue_terminal,"
                        "collection_started_at,collection_finished_at,observed_at,"
                        "residual_position_quantity,residual_order_count,residual_protection_count,"
                        "payload,payload_sha256) "
                        "VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15::numeric,$16::numeric,"
                        "$17::numeric,$18::numeric,$19::numeric,$20::numeric,$21,$22,true,true,"
                        "$23,$24,$25,0,0,0,$26::jsonb,$27)",
                        receipt_id,
                        self.database_uuid,
                        self.context_sha256,
                        self.account_sha256,
                        binding.trade_id,
                        binding.decision_id,
                        binding.effect_id,
                        binding.signing_request_id,
                        binding.client_order_id,
                        binding.exchange_parent_order_id,
                        trade.journal_head_sha256,
                        binding.lifecycle_entry_effect_id,
                        facts_digest,
                        effects_digest,
                        _decimal_text(evidence.entry_filled_quantity),
                        _decimal_text(evidence.closed_quantity),
                        _decimal_text(evidence.entry_notional_usd),
                        _decimal_text(evidence.exit_notional_usd),
                        _decimal_text(evidence.entry_fees_usd),
                        _decimal_text(evidence.exit_fees_usd),
                        evidence.source_id,
                        evidence.source_evidence_sha256,
                        evidence.collection_started_at,
                        evidence.collection_finished_at,
                        evidence.observed_at,
                        json.dumps(payload, sort_keys=True, separators=(",", ":")),
                        payload_sha,
                    )
            return {"receipt_id": str(receipt_id), "created": True, "payload_sha256": payload_sha}
        except ProductionReconciliationError:
            raise
        except Exception as exc:
            raise ProductionReconciliationError(
                f"terminal reconciliation refused ({type(exc).__name__})"
            ) from None

    async def _inspect(self, connection: asyncpg.Connection) -> None:
        identity = await connection.fetchrow("SELECT current_database() AS db,current_user AS role")
        if (
            identity is None
            or identity["db"] != self.expected_database
            or identity["role"] != self.expected_role
        ):
            raise ProductionReconciliationError("reconciliation database/role mismatch")
        state = await connection.fetchrow(
            "SELECT * FROM kairos_production_state_v1.identity WHERE singleton=true"
        )
        if (
            state is None
            or state["database_uuid"] != self.database_uuid
            or state["account_sha256"] != self.account_sha256
        ):
            raise ProductionReconciliationError("production state identity differs from reconciliation scope")
        if state["schema_version"] != 2:
            raise ProductionReconciliationError("unsupported production state schema")
        if (
            state["runtime_role"] == self.expected_role
            or state["owner_role"] == self.expected_role
            or any(
                state[key] == self.expected_role
                for key in ("operator_writer_role", "risk_writer_role", "exposure_writer_role")
            )
        ):
            raise ProductionReconciliationError(
                "reconciler role must be isolated from protected production roles"
            )
        for protected in (
            state["owner_role"],
            state["runtime_role"],
            state["operator_writer_role"],
            state["risk_writer_role"],
            state["exposure_writer_role"],
        ):
            await _check_role_isolated(connection, self.expected_role, (protected,))
        reconcile_identity = await connection.fetchrow(
            "SELECT * FROM kairos_production_reconciliation_v1.identity WHERE singleton=true"
        )
        if reconcile_identity is None or any(
            (
                reconcile_identity["database_uuid"] != self.database_uuid,
                reconcile_identity["policy_namespace"] != self.policy_namespace,
                reconcile_identity["account_sha256"] != self.account_sha256,
                reconcile_identity["owner_role"] != state["owner_role"],
                reconcile_identity["reconciler_role"] != self.expected_role,
            )
        ):
            raise ProductionReconciliationError("reconciliation schema identity mismatch")
        if state["policy_namespace"] != self.policy_namespace:
            raise ProductionReconciliationError(
                "production state policy namespace differs from reconciliation identity"
            )
        for privilege in ("UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"):
            if await connection.fetchval(
                "SELECT has_table_privilege($1,$2,$3)",
                self.expected_role,
                f"{SCHEMA}.terminal_receipts",
                privilege,
            ):
                raise ProductionReconciliationError(
                    "reconciler role has mutation privileges beyond append-only insert"
                )

    async def _verify_trade(self, trade, binding, evidence) -> None:
        if trade is None or trade.state.value != "FLAT":
            raise ProductionReconciliationError("durable trade is absent or not FLAT")
        if not await self.trades.verify_chain(binding.trade_id):
            raise ProductionReconciliationError("durable trade lifecycle chain is invalid")
        if (
            trade.trade_id != binding.trade_id
            or trade.risk_decision_id != binding.decision_id
            or trade.trading_mode != "LIVE"
            or trade.environment != self._lifecycle_environment
            or trade.profile != "PROD"
            or trade.exchange.casefold() != "evedex"
            or trade.account_id != self.context.remote_account_id
            or trade.entry_client_order_id != binding.client_order_id
            or trade.entry_exchange_order_id != binding.exchange_parent_order_id
        ):
            raise ProductionReconciliationError(
                "durable trade identity differs from exact reservation lineage"
            )
        if Decimal(str(trade.filled_quantity)) <= 0:
            raise ProductionReconciliationError("trade has no actual durable entry fill")
        if evidence.entry_filled_quantity != Decimal(str(trade.filled_quantity)):
            raise ProductionReconciliationError("venue entry quantity differs from durable trade fill")

    async def _owned_effects(self, trade_id: str):
        pool = getattr(self.effects, "pool", None)
        if pool is None:
            raise ProductionReconciliationError("execution journal has no durable query source")
        rows = await pool.fetch(
            "SELECT effect_key,status,trade_id,account_id,environment,exchange,symbol,client_order_id,"
            "exchange_effect_id,journal_head_sha256 FROM execution_effects "
            "WHERE trade_id=$1 ORDER BY effect_key",
            trade_id,
        )
        return tuple(rows)

    async def _verify_effects(self, effects, binding, trade) -> None:
        if not effects:
            raise ProductionReconciliationError("trade has no owned durable execution effects")
        found_entry = False
        for effect in effects:
            if (
                effect["account_id"] != self.context.remote_account_id
                or effect["trade_id"] != trade.trade_id
                or effect["environment"] != self._lifecycle_environment
                or str(effect["exchange"]).casefold() != "evedex"
                or effect["status"] not in {"RECONCILED", "CONFIRMED"}
            ):
                raise ProductionReconciliationError(
                    "owned execution effect is unknown, unresolved, or out of scope"
                )
            if not await self.effects.verify_chain(effect["effect_key"]):
                raise ProductionReconciliationError("owned execution effect journal chain is invalid")
            if effect["effect_key"] == binding.lifecycle_entry_effect_id:
                if (
                    effect["client_order_id"] != binding.client_order_id
                    or effect["exchange_effect_id"] != binding.exchange_parent_order_id
                ):
                    raise ProductionReconciliationError(
                        "entry effect is not bound to exact venue order identifiers"
                    )
                found_entry = True
        if not found_entry:
            raise ProductionReconciliationError("entry reservation effect is absent from owned trade journal")

    @staticmethod
    async def _verify_facts(facts, binding, trade, evidence) -> None:
        if not facts:
            raise ProductionReconciliationError("durable execution facts are absent")
        if (
            len(facts) != trade.state_version + 1
            or [event.event_seq for event in facts] != list(range(1, len(facts) + 1))
            or facts[-1].lifecycle_state.value != "FLAT"
            or facts[-1].position_quantity != 0
        ):
            raise ProductionReconciliationError("durable execution fact sequence is not complete and FLAT")
        if any(
            event.trade_id != binding.trade_id
            or event.risk_decision_id != binding.decision_id
            or event.account_id != trade.account_id
            or event.trading_mode.value != "LIVE"
            or event.evedex_profile.value != "PROD"
            for event in facts
        ):
            raise ProductionReconciliationError("durable execution facts conflict with trade identity")
        if not any(
            event.event_type.value in {"EXIT_FILLED", "EMERGENCY_CLOSE"} and event.filled_quantity > 0
            for event in facts
        ):
            raise ProductionReconciliationError("durable execution facts lack an actual exit fill")
        if not any(
            event.event_type.value in {"ENTRY_FILLED", "ENTRY_PARTIAL_FILL"}
            and event.order_role is not None
            and event.order_role.value == "ENTRY"
            and event.filled_quantity > 0
            for event in facts
        ):
            raise ProductionReconciliationError("durable execution facts lack an actual entry fill")
        if evidence.closed_quantity != evidence.entry_filled_quantity:
            raise ProductionReconciliationError("closed quantity does not exactly equal actual entry fills")

    def _verify_venue_evidence(self, evidence, binding, now) -> None:
        exact = (
            evidence.source_id in self.source_verifiers,
            evidence.context_sha256 == self.context_sha256,
            evidence.account_id == self.context.remote_account_id,
            evidence.trade_id == binding.trade_id,
            evidence.decision_id == binding.decision_id,
            evidence.effect_id == binding.effect_id,
            evidence.lifecycle_entry_effect_id == binding.lifecycle_entry_effect_id,
            evidence.signing_request_id == binding.signing_request_id,
            evidence.client_order_id == binding.client_order_id,
            evidence.exchange_parent_order_id == binding.exchange_parent_order_id,
        )
        if not all(exact):
            raise ProductionReconciliationError(
                "venue evidence identity does not match exact trade/reservation"
            )
        if not evidence.complete or not evidence.terminal or evidence.unowned_exposure_count != 0:
            raise ProductionReconciliationError(
                "venue evidence is incomplete, nonterminal, or has unowned exposure"
            )
        if any(
            value != 0
            for value in (
                evidence.residual_position_quantity,
                Decimal(evidence.residual_order_count),
                Decimal(evidence.residual_protection_count),
            )
        ):
            raise ProductionReconciliationError(
                "venue evidence reports nonzero residual exposure/order/protection"
            )
        if evidence.entry_filled_quantity <= 0 or evidence.closed_quantity != evidence.entry_filled_quantity:
            raise ProductionReconciliationError(
                "venue evidence does not prove a fully filled and closed trade"
            )
        if evidence.entry_notional_usd <= 0 or evidence.exit_notional_usd <= 0:
            raise ProductionReconciliationError("venue evidence lacks exact positive entry/exit notionals")
        started, finished, observed = (
            VenueTerminalEvidenceV1._utc(v)
            for v in (evidence.collection_started_at, evidence.collection_finished_at, evidence.observed_at)
        )
        if finished < started or observed < finished or now < observed or now - observed > MAX_EVIDENCE_AGE:
            raise ProductionReconciliationError("venue evidence collection is stale or has invalid bounds")

    def _verify_reservation(self, row, binding) -> None:
        if row is None:
            raise ProductionReconciliationError("exact durable entry reservation is absent")
        payload = row["risk_payload"]
        if isinstance(payload, str):
            payload = json.loads(payload)
        if (
            row["effect_id"] != binding.effect_id
            or row["decision_id"] != binding.decision_id
            or row["signing_request_id"] != binding.signing_request_id
            or row["context_sha256"] != self.context_sha256
            or row["account_sha256"] != self.account_sha256
            or payload.get("client_order_id") != binding.client_order_id
            or payload.get("effect_id") != binding.effect_id
            or payload.get("decision_id") != binding.decision_id
            or payload.get("signing_request_id") != binding.signing_request_id
        ):
            raise ProductionReconciliationError(
                "reservation does not match immutable risk decision/order binding"
            )
        if (
            hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            != row["payload_sha256"]
        ):
            raise ProductionReconciliationError("persisted risk decision digest is invalid")

    def _now(self):
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() != timedelta(0):
            raise ProductionReconciliationError("reconciliation clock must be explicit UTC")
        return now

    @property
    def _lifecycle_environment(self) -> str:
        return f"PROD:{self.context_sha256}:LIVE"


async def provision_production_reconciliation_schema(
    connection: asyncpg.Connection,
    *,
    expected_database: str,
    database_uuid: UUID,
    policy_namespace: str,
    context: ProductionContextV1,
    owner_role: str,
    reconciler_role: str,
) -> None:
    """Owner-only create-only provisioning; never modifies schema-v2 tables."""
    owner_role, reconciler_role = _role(owner_role), _role(reconciler_role)
    context = ProductionContextV1.model_validate(context)
    if database_uuid.int == 0:
        raise ProductionReconciliationError("nonzero database UUID is required")
    actual = await connection.fetchrow("SELECT current_database() AS db,current_user AS role")
    if actual is None or actual["db"] != expected_database or actual["role"] != owner_role:
        raise ProductionReconciliationError("reconciliation schema owner/database mismatch")
    state = await connection.fetchrow(
        "SELECT * FROM kairos_production_state_v1.identity WHERE singleton=true"
    )
    if (
        state is None
        or state["database_uuid"] != database_uuid
        or state["account_sha256"] != _account_scope_sha256(context)
        or state["owner_role"] != owner_role
    ):
        raise ProductionReconciliationError(
            "existing production state identity differs from reconciliation scope"
        )
    protected = (
        state["owner_role"],
        state["runtime_role"],
        state["operator_writer_role"],
        state["risk_writer_role"],
        state["exposure_writer_role"],
    )
    if reconciler_role in protected:
        raise ProductionReconciliationError("reconciler role must be separately provisioned and isolated")
    await _check_role_isolated(connection, reconciler_role, protected)
    if await connection.fetchval("SELECT to_regnamespace($1)", SCHEMA) is not None:
        raise ProductionReconciliationError("reconciliation schema already exists; do not re-provision")
    async with connection.transaction():
        await connection.execute(DDL)
        await connection.execute(
            "INSERT INTO kairos_production_reconciliation_v1.identity VALUES(true,$1,$2,$3,$4,$5,$6)",
            database_uuid,
            _identity(policy_namespace),
            _account_scope_sha256(context),
            SCHEMA_VERSION,
            owner_role,
            reconciler_role,
        )
        await connection.execute(f'GRANT USAGE ON SCHEMA {SCHEMA} TO "{reconciler_role}"')
        await connection.execute(f'GRANT SELECT,INSERT ON {SCHEMA}.terminal_receipts TO "{reconciler_role}"')
        await connection.execute(f'GRANT SELECT ON {SCHEMA}.identity TO "{reconciler_role}"')
        await connection.execute(
            f'GRANT SELECT ON kairos_production_state_v1.identity TO "{reconciler_role}"'
        )
        await connection.execute(f'GRANT USAGE ON SCHEMA kairos_production_state_v1 TO "{reconciler_role}"')
        await connection.execute(
            f'GRANT SELECT ON kairos_production_state_v1.risk_reservations TO "{reconciler_role}"'
        )
        await connection.execute(
            f'GRANT SELECT ON kairos_production_state_v1.risk_decisions TO "{reconciler_role}"'
        )


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def _decimal_text(value: Decimal) -> str:
    if not isinstance(value, Decimal) or not value.is_finite():
        raise ProductionReconciliationError("economic evidence must use finite exact decimals")
    return format(value, "f")
