"""Explicit v3 capital accounting over immutable reconciliation-v2 receipts.

No runtime factory selects this module. Old state-v2 and receipt-v1 records are
not migrated. Loss charge is cumulative, without profit offsets or an inferred
UTC daily reset: max(0,-gross) + fees + max(0,funding debit). A separate qualified
daily ledger is needed before this deliberately conservative floor can reset.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any
from uuid import UUID

from .production_readiness import ProductionContextV1, canonical_digest
from .production_reconciliation import (
    ACCOUNTING_SCHEMA as RECEIPT_SCHEMA,
)
from .production_reconciliation import (
    MAX_EVIDENCE_AGE,
    _canonical_sha256,
)
from .production_state import (
    ProductionStateError,
    _account_reservation_lock,
    _account_scope_sha256,
    _check_role_isolated,
    _database_name,
    _digest,
    _identity,
    _role,
)

SCHEMA = "kairos_production_accounting_v1"
SCHEMA_VERSION = 1

DDL = """
CREATE SCHEMA kairos_production_accounting_v1;
REVOKE ALL ON SCHEMA kairos_production_accounting_v1 FROM PUBLIC;
CREATE TABLE kairos_production_accounting_v1.identity (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 database_uuid uuid NOT NULL, policy_namespace text NOT NULL,
 account_sha256 text NOT NULL CHECK(account_sha256 ~ '^[a-f0-9]{64}$'),
 schema_version integer NOT NULL CHECK(schema_version=1),
 state_schema_version integer NOT NULL CHECK(state_schema_version=3),
 receipt_schema_version integer NOT NULL CHECK(receipt_schema_version=2),
 owner_role name NOT NULL, runtime_role name NOT NULL, accounting_role name NOT NULL
);
CREATE TABLE kairos_production_accounting_v1.accepted_releases (
 receipt_id uuid PRIMARY KEY REFERENCES kairos_production_reconciliation_v2.terminal_receipts(receipt_id),
 database_uuid uuid NOT NULL,
 context_sha256 text NOT NULL CHECK(context_sha256 ~ '^[a-f0-9]{64}$'),
 account_sha256 text NOT NULL CHECK(account_sha256 ~ '^[a-f0-9]{64}$'),
 effect_id text NOT NULL CHECK(effect_id ~ '^[a-f0-9]{64}$'),
 trade_id text NOT NULL CHECK(length(trade_id) BETWEEN 1 AND 160),
 owner_arm_sha256 text NOT NULL CHECK(owner_arm_sha256 ~ '^[a-f0-9]{64}$'),
 reservation_request_sha256 text NOT NULL CHECK(reservation_request_sha256 ~ '^[a-f0-9]{64}$'),
 receipt_payload_sha256 text NOT NULL CHECK(receipt_payload_sha256 ~ '^[a-f0-9]{64}$'),
 gross_pnl_usd numeric NOT NULL CHECK(abs(gross_pnl_usd) < 'Infinity'::numeric),
 fees_usd numeric NOT NULL CHECK(fees_usd >= 0 AND fees_usd < 'Infinity'::numeric),
 funding_cost_usd numeric NOT NULL CHECK(abs(funding_cost_usd) < 'Infinity'::numeric),
 net_pnl_usd numeric NOT NULL CHECK(abs(net_pnl_usd) < 'Infinity'::numeric),
 loss_charge_usd numeric NOT NULL CHECK(loss_charge_usd >= 0 AND loss_charge_usd < 'Infinity'::numeric),
 settled_at timestamptz NOT NULL,
 accepted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(account_sha256,effect_id), UNIQUE(account_sha256,trade_id),
 FOREIGN KEY(account_sha256,effect_id)
  REFERENCES kairos_production_state_v1.risk_reservations(account_sha256,effect_id),
 CHECK(net_pnl_usd=gross_pnl_usd-fees_usd-funding_cost_usd),
 CHECK(loss_charge_usd=greatest(0,-gross_pnl_usd)+fees_usd+greatest(0,funding_cost_usd))
);
CREATE FUNCTION kairos_production_accounting_v1.reject_mutation() RETURNS trigger
 LANGUAGE plpgsql SET search_path=pg_catalog AS $$
 BEGIN RAISE EXCEPTION 'immutable production accounting record'; END $$;
CREATE TRIGGER identity_immutable BEFORE UPDATE OR DELETE
 ON kairos_production_accounting_v1.identity FOR EACH ROW
 EXECUTE FUNCTION kairos_production_accounting_v1.reject_mutation();
CREATE TRIGGER accounting_immutable BEFORE UPDATE OR DELETE
 ON kairos_production_accounting_v1.accepted_releases FOR EACH ROW
 EXECUTE FUNCTION kairos_production_accounting_v1.reject_mutation();
CREATE FUNCTION kairos_production_accounting_v1.enforce_release() RETURNS trigger
 LANGUAGE plpgsql SET search_path=pg_catalog AS $$
 DECLARE t record; p record; r record; i record; d record; gross numeric;
 BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended('risk-reservation:'||NEW.account_sha256,0));
  SELECT * INTO i FROM kairos_production_accounting_v1.identity WHERE singleton=true;
  SELECT * INTO t FROM kairos_production_reconciliation_v2.terminal_receipts WHERE receipt_id=NEW.receipt_id;
  SELECT * INTO r FROM kairos_production_state_v1.risk_reservations
   WHERE account_sha256=NEW.account_sha256 AND effect_id=NEW.effect_id;
  IF t IS NULL OR r IS NULL OR i IS NULL THEN RAISE EXCEPTION 'exact accounting lineage absent'; END IF;
  SELECT * INTO p FROM jsonb_populate_record(
   NULL::kairos_production_reconciliation_v2.terminal_receipts,t.payload);
  IF (to_jsonb(p)-ARRAY['receipt_id','inserted_at','payload','payload_sha256'])
   IS DISTINCT FROM (to_jsonb(t)-ARRAY['receipt_id','inserted_at','payload','payload_sha256']) THEN
   RAISE EXCEPTION 'terminal receipt payload/column conflict';
  END IF;
  SELECT * INTO d FROM kairos_production_state_v1.risk_decisions
   WHERE context_sha256=r.context_sha256 AND signing_request_id=r.signing_request_id;
  IF d IS NULL OR i.database_uuid<>NEW.database_uuid OR i.account_sha256<>NEW.account_sha256
   OR t.database_uuid<>NEW.database_uuid OR t.context_sha256<>NEW.context_sha256
   OR r.context_sha256<>NEW.context_sha256 OR t.account_sha256<>NEW.account_sha256
   OR t.effect_id<>NEW.effect_id OR t.trade_id<>NEW.trade_id
   OR t.payload_sha256<>NEW.receipt_payload_sha256
   OR t.owner_arm_sha256<>NEW.owner_arm_sha256 OR r.owner_arm_sha256<>NEW.owner_arm_sha256
   OR t.reservation_request_sha256<>NEW.reservation_request_sha256
   OR r.request_sha256<>NEW.reservation_request_sha256
   OR t.signing_request_id<>r.signing_request_id OR t.decision_id<>r.decision_id
   OR t.entry_side IS DISTINCT FROM d.payload->>'side'
   OR t.client_order_id IS DISTINCT FROM d.payload->>'client_order_id'
   OR d.payload_sha256<>r.evidence_sha256
   OR NOT t.venue_complete OR NOT t.venue_terminal OR NOT t.funding_complete
   OR t.unowned_exposure_count<>0 OR t.residual_position_quantity<>0
   OR t.residual_order_count<>0 OR t.residual_protection_count<>0
   OR t.entry_filled_quantity<=0 OR t.entry_filled_quantity<>t.closed_quantity
   OR t.observed_at<t.collection_finished_at OR t.collection_finished_at<t.collection_started_at
   OR t.settled_at>t.collection_finished_at OR t.settled_at<r.observed_at
   OR t.observed_at>t.inserted_at OR t.inserted_at>clock_timestamp()
   OR t.inserted_at-t.observed_at>interval '2 minutes'
   OR NEW.settled_at<>t.settled_at OR NEW.funding_cost_usd<>t.funding_cost_usd
   OR NEW.fees_usd<>t.entry_fees_usd+t.exit_fees_usd
  THEN RAISE EXCEPTION 'terminal accounting identity/economics not accepted'; END IF;
  gross := CASE WHEN t.entry_side='BUY' THEN t.exit_notional_usd-t.entry_notional_usd
   ELSE t.entry_notional_usd-t.exit_notional_usd END;
  IF NEW.gross_pnl_usd<>gross THEN RAISE EXCEPTION 'accounting gross economics mismatch'; END IF;
  RETURN NEW;
 END $$;
CREATE TRIGGER accounting_guard BEFORE INSERT
 ON kairos_production_accounting_v1.accepted_releases FOR EACH ROW
 EXECUTE FUNCTION kairos_production_accounting_v1.enforce_release();
"""


class ProductionAccountingError(ProductionStateError):
    """Accounting must not free capital on incomplete or conflicting proof."""


def terminal_economics(payload: dict[str, Any]) -> dict[str, Decimal]:
    """Exact economics, with adverse components retained without offsets."""
    if payload.get("entry_side") not in ("BUY", "SELL") or payload.get("funding_complete") is not True:
        raise ProductionAccountingError("complete side/funding evidence is required")
    values = {}
    for key in (
        "entry_notional_usd",
        "exit_notional_usd",
        "entry_fees_usd",
        "exit_fees_usd",
        "funding_cost_usd",
    ):
        value = payload.get(key)
        if type(value) not in (str, Decimal):
            raise ProductionAccountingError("economics must be explicit exact decimals")
        try:
            number = Decimal(str(value))
        except Exception:
            raise ProductionAccountingError("economics decimal is invalid") from None
        if not number.is_finite() or (key != "funding_cost_usd" and number < 0):
            raise ProductionAccountingError("economics must be finite and correctly signed")
        values[key] = number
    if values["entry_notional_usd"] <= 0 or values["exit_notional_usd"] <= 0:
        raise ProductionAccountingError("actual gross entry and exit fills are required")
    gross = values["exit_notional_usd"] - values["entry_notional_usd"]
    if payload["entry_side"] == "SELL":
        gross = -gross
    fees = values["entry_fees_usd"] + values["exit_fees_usd"]
    funding = values["funding_cost_usd"]
    return {
        "gross_pnl_usd": gross,
        "fees_usd": fees,
        "funding_cost_usd": funding,
        "net_pnl_usd": gross - fees - funding,
        "loss_charge_usd": max(Decimal(0), -gross) + fees + max(Decimal(0), funding),
    }


def verify_terminal_receipt(row: Any, *, now: datetime) -> dict[str, Any]:
    """Hash and every persisted projection must agree before a release is read."""
    if row is None:
        raise ProductionAccountingError("exact immutable terminal receipt is absent")
    payload = row["payload"]
    if isinstance(payload, str):
        payload = json.loads(payload)
    if not isinstance(payload, dict) or _canonical_sha256(payload) != row["payload_sha256"]:
        raise ProductionAccountingError("terminal receipt payload integrity mismatch")
    # A future producer cannot omit a projected fact and rely on a DB default.
    ignored = {"receipt_id", "payload", "payload_sha256", "inserted_at"}
    for key in set(row.keys()) - ignored:
        if key not in payload:
            raise ProductionAccountingError("terminal receipt payload omits an authoritative column")
        value = row[key]
        encoded = payload[key]
        if isinstance(value, Decimal):
            same = type(encoded) is str and Decimal(encoded) == value
        elif isinstance(value, datetime):
            same = type(encoded) is str and datetime.fromisoformat(encoded) == value
        elif isinstance(value, UUID):
            same = str(value) == encoded
        else:
            same = type(value) is type(encoded) and value == encoded
        if not same:
            raise ProductionAccountingError("terminal receipt payload/column conflict")
    for key in ("venue_complete", "venue_terminal", "funding_complete"):
        if payload.get(key) is not True:
            raise ProductionAccountingError("terminal receipt is incomplete or nonterminal")
    for key in (
        "residual_position_quantity",
        "residual_order_count",
        "residual_protection_count",
        "unowned_exposure_count",
    ):
        if key not in payload or Decimal(str(payload[key])) != 0:
            raise ProductionAccountingError("terminal receipt retains residual or unowned exposure")
    entry, closed = Decimal(payload["entry_filled_quantity"]), Decimal(payload["closed_quantity"])
    if not entry.is_finite() or entry <= 0 or entry != closed:
        raise ProductionAccountingError("terminal receipt lacks actual fully closed fills")
    started, finished, observed, settled = (
        datetime.fromisoformat(payload[key])
        for key in ("collection_started_at", "collection_finished_at", "observed_at", "settled_at")
    )
    inserted = row["inserted_at"]
    if any(
        value.tzinfo is None or value.utcoffset() != timedelta(0)
        for value in (started, finished, observed, settled, inserted, now)
    ):
        raise ProductionAccountingError("accounting timestamps must be explicit UTC")
    # Freshness was established when the independent immutable receipt entered
    # the database, not when a separate accounting worker happened to recover.
    if (
        not settled <= finished <= observed <= inserted <= now
        or started > finished
        or inserted - observed > MAX_EVIDENCE_AGE
    ):
        raise ProductionAccountingError("terminal receipt is stale or temporally incomplete")
    terminal_economics(payload)
    return payload


async def _inspect(connection, *, database_uuid, policy_namespace, context, role, expected_database):
    actual = await connection.fetchrow("SELECT current_database() AS db,current_user AS role")
    identity = await connection.fetchrow(
        "SELECT * FROM kairos_production_accounting_v1.identity WHERE singleton=true"
    )
    state = await connection.fetchrow(
        "SELECT * FROM kairos_production_state_v1.identity WHERE singleton=true"
    )
    receipt = await connection.fetchrow(
        "SELECT * FROM kairos_production_reconciliation_v2.identity WHERE singleton=true"
    )
    if actual is None or actual["db"] != expected_database or actual["role"] != role:
        raise ProductionAccountingError("accounting database/role mismatch")
    expected = {
        "database_uuid": database_uuid,
        "policy_namespace": policy_namespace,
        "account_sha256": _account_scope_sha256(context),
        "schema_version": 1,
        "state_schema_version": 3,
        "receipt_schema_version": 2,
    }
    if identity is None or any(identity[key] != value for key, value in expected.items()):
        raise ProductionAccountingError("accounting identity/version mismatch")
    for record, version in ((state, 3), (receipt, 2)):
        if record is None or any(
            record[key] != expected[key] for key in ("database_uuid", "policy_namespace", "account_sha256")
        ):
            raise ProductionAccountingError("accounting source database/context identity mismatch")
        if record["schema_version"] != version or record["owner_role"] != identity["owner_role"]:
            raise ProductionAccountingError("accounting source schema/owner mismatch")
    if state["runtime_role"] != identity["runtime_role"]:
        raise ProductionAccountingError("accounting runtime identity mismatch")
    protected = tuple(
        state[key]
        for key in (
            "owner_role",
            "runtime_role",
            "operator_writer_role",
            "risk_writer_role",
            "exposure_writer_role",
        )
    ) + (receipt["reconciler_role"], identity["accounting_role"])
    if len(set(protected)) != len(protected) or role not in (
        identity["runtime_role"],
        identity["accounting_role"],
    ):
        raise ProductionAccountingError("accounting roles are not isolated")
    await _check_role_isolated(connection, role, protected)
    for schema in (SCHEMA, RECEIPT_SCHEMA, "kairos_production_state_v1"):
        owner = await connection.fetchval(
            "SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname=$1", schema
        )
        if owner != identity["owner_role"] or await connection.fetchval(
            "SELECT has_schema_privilege($1,$2,'CREATE')", role, schema
        ):
            raise ProductionAccountingError("accounting schema owner/privilege mismatch")
    for table in (
        f"{SCHEMA}.identity",
        f"{SCHEMA}.accepted_releases",
        f"{RECEIPT_SCHEMA}.identity",
        f"{RECEIPT_SCHEMA}.terminal_receipts",
        "kairos_production_state_v1.identity",
        "kairos_production_state_v1.risk_reservations",
        "kairos_production_state_v1.risk_decisions",
        "kairos_production_state_v1.owner_arms",
        "kairos_production_state_v1.operator_observations",
        "kairos_production_state_v1.exposure_observations",
    ):
        table_owner = await connection.fetchval(
            "SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid=to_regclass($1)", table
        )
        select_expected = role == identity["runtime_role"] or table not in (
            "kairos_production_state_v1.owner_arms",
            "kairos_production_state_v1.operator_observations",
            "kairos_production_state_v1.exposure_observations",
        )
        if table_owner != identity["owner_role"] or select_expected != await connection.fetchval(
            "SELECT has_table_privilege($1,$2,'SELECT')", role, table
        ):
            raise ProductionAccountingError("accounting table owner/read privilege mismatch")
        for privilege in ("UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER", "INSERT"):
            allowed = (
                privilege == "INSERT"
                and role == identity["accounting_role"]
                and table == f"{SCHEMA}.accepted_releases"
            )
            # The v3 runtime retains its original reserve-only INSERT; this
            # grants no accounting or reconciler write authority.
            allowed = allowed or (
                privilege == "INSERT"
                and role == identity["runtime_role"]
                and table == "kairos_production_state_v1.risk_reservations"
            )
            actual_privilege = await connection.fetchval(
                "SELECT has_table_privilege($1,$2,$3)", role, table, privilege
            )
            if actual_privilege != allowed:
                raise ProductionAccountingError("accounting role has excessive or missing privileges")
    return identity


async def inspect_accounting_runtime(connection, *, state_source) -> None:
    await _inspect(
        connection,
        database_uuid=state_source.database_uuid,
        policy_namespace=state_source.policy_namespace,
        context=state_source.context,
        role=state_source.runtime_role,
        expected_database=state_source.expected_database,
    )


class PostgresProductionAccounting:
    """Independent append-only acceptor; cannot change Risk, receipts or arms."""

    def __init__(self, pool, *, expected_database, database_uuid, policy_namespace, context, accounting_role):
        self.pool = pool
        self.expected_database = _database_name(expected_database)
        if not isinstance(database_uuid, UUID) or database_uuid.int == 0:
            raise ProductionAccountingError("exact nonzero accounting database UUID required")
        self.database_uuid = database_uuid
        self.policy_namespace = _identity(policy_namespace)
        self.context = ProductionContextV1.model_validate(context)
        self.accounting_role = _role(accounting_role)

    async def accept_terminal_receipt(
        self, *, receipt_id: UUID, receipt_payload_sha256: str
    ) -> dict[str, Any]:
        if not isinstance(receipt_id, UUID):
            raise ProductionAccountingError("exact receipt UUID required")
        _digest(receipt_payload_sha256)
        try:
            async with asyncio.timeout(10), self.pool.acquire() as connection:
                async with connection.transaction():
                    await connection.execute("SET LOCAL statement_timeout='5s'")
                    await _inspect(
                        connection,
                        database_uuid=self.database_uuid,
                        policy_namespace=self.policy_namespace,
                        context=self.context,
                        role=self.accounting_role,
                        expected_database=self.expected_database,
                    )
                    await connection.execute(
                        "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                        _account_reservation_lock(self.context),
                    )
                    existing = await connection.fetchrow(
                        "SELECT * FROM kairos_production_accounting_v1.accepted_releases WHERE receipt_id=$1",
                        receipt_id,
                    )
                    if existing is not None:
                        if existing["receipt_payload_sha256"] != receipt_payload_sha256 or existing[
                            "context_sha256"
                        ] != canonical_digest(self.context):
                            raise ProductionAccountingError("accounting receipt identity rebound")
                        return {
                            "created": False,
                            "receipt_id": str(receipt_id),
                            "loss_charge_usd": existing["loss_charge_usd"],
                        }
                    row = await connection.fetchrow(
                        "SELECT * FROM kairos_production_reconciliation_v2.terminal_receipts "
                        "WHERE receipt_id=$1",
                        receipt_id,
                    )
                    now = await connection.fetchval("SELECT clock_timestamp()")
                    payload = verify_terminal_receipt(row, now=now.astimezone(UTC))
                    if (
                        row["payload_sha256"] != receipt_payload_sha256
                        or row["database_uuid"] != self.database_uuid
                        or row["context_sha256"] != canonical_digest(self.context)
                        or row["account_sha256"] != _account_scope_sha256(self.context)
                    ):
                        raise ProductionAccountingError("terminal receipt exact scope/digest mismatch")
                    economics = terminal_economics(payload)
                    fields = {
                        "receipt_id": receipt_id,
                        "database_uuid": self.database_uuid,
                        **{
                            key: row[key]
                            for key in (
                                "context_sha256",
                                "account_sha256",
                                "effect_id",
                                "trade_id",
                                "owner_arm_sha256",
                                "reservation_request_sha256",
                                "settled_at",
                            )
                        },
                        "receipt_payload_sha256": receipt_payload_sha256,
                        **economics,
                    }
                    await connection.execute(
                        "INSERT INTO kairos_production_accounting_v1.accepted_releases "
                        "(receipt_id,database_uuid,context_sha256,account_sha256,effect_id,trade_id,"
                        "owner_arm_sha256,reservation_request_sha256,settled_at,receipt_payload_sha256,"
                        "gross_pnl_usd,fees_usd,funding_cost_usd,net_pnl_usd,loss_charge_usd) "
                        "VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
                        *fields.values(),
                    )
                    return {"created": True, "receipt_id": str(receipt_id), **economics}
        except ProductionAccountingError:
            raise
        except Exception:
            raise ProductionAccountingError(
                "terminal accounting outcome unresolved; inspect exact receipt before retry"
            ) from None


async def provision_production_accounting_schema(
    connection,
    *,
    expected_database,
    database_uuid,
    policy_namespace,
    context,
    owner_role,
    accounting_role,
) -> None:
    """Fresh-only owner provisioning; no existing state/receipt/history updates."""
    expected_database = _database_name(expected_database)
    owner_role, accounting_role = _role(owner_role), _role(accounting_role)
    context = ProductionContextV1.model_validate(context)
    actual = await connection.fetchrow("SELECT current_database() AS db,current_user AS role")
    if actual is None or actual["db"] != expected_database or actual["role"] != owner_role:
        raise ProductionAccountingError("accounting schema owner/database mismatch")
    state = await connection.fetchrow(
        "SELECT * FROM kairos_production_state_v1.identity WHERE singleton=true"
    )
    receipt = await connection.fetchrow(
        "SELECT * FROM kairos_production_reconciliation_v2.identity WHERE singleton=true"
    )
    for record, version in ((state, 3), (receipt, 2)):
        if record is None or any(
            (
                record["database_uuid"] != database_uuid,
                record["policy_namespace"] != policy_namespace,
                record["account_sha256"] != _account_scope_sha256(context),
                record["schema_version"] != version,
                record["owner_role"] != owner_role,
            )
        ):
            raise ProductionAccountingError(
                "accounting requires exact fresh state-v3 and receipt-v2 identities"
            )
    protected = tuple(
        state[key]
        for key in (
            "owner_role",
            "runtime_role",
            "operator_writer_role",
            "risk_writer_role",
            "exposure_writer_role",
        )
    ) + (receipt["reconciler_role"],)
    if accounting_role in protected:
        raise ProductionAccountingError("accounting requires a separate isolated append-only role")
    await _check_role_isolated(connection, accounting_role, protected)
    if await connection.fetchval("SELECT to_regnamespace($1)", SCHEMA) is not None:
        raise ProductionAccountingError("accounting schema already exists; do not re-provision")
    async with connection.transaction():
        await connection.execute(DDL)
        await connection.execute(
            "INSERT INTO kairos_production_accounting_v1.identity VALUES(true,$1,$2,$3,1,3,2,$4,$5,$6)",
            database_uuid,
            policy_namespace,
            _account_scope_sha256(context),
            owner_role,
            state["runtime_role"],
            accounting_role,
        )
        for role in (accounting_role, state["runtime_role"]):
            await connection.execute(f'GRANT USAGE ON SCHEMA {SCHEMA},{RECEIPT_SCHEMA} TO "{role}"')
            await connection.execute(f'GRANT SELECT ON ALL TABLES IN SCHEMA {SCHEMA} TO "{role}"')
            await connection.execute(
                f'GRANT SELECT ON {RECEIPT_SCHEMA}.identity,{RECEIPT_SCHEMA}.terminal_receipts TO "{role}"'
            )
        await connection.execute(f'GRANT INSERT ON {SCHEMA}.accepted_releases TO "{accounting_role}"')
        await connection.execute(f'GRANT USAGE ON SCHEMA kairos_production_state_v1 TO "{accounting_role}"')
        await connection.execute(
            "GRANT SELECT ON kairos_production_state_v1.identity,"
            "kairos_production_state_v1.risk_reservations,"
            f'kairos_production_state_v1.risk_decisions TO "{accounting_role}"'
        )
