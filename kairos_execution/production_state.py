"""Async production signing evidence source, durable reservations and appenders.

This module is a persistence boundary, not a LIVE enablement switch. Provisioning
is explicit and owner-only. Runtime reads require the exact isolated evidence
database and claims identity; upstream writers use separate PostgreSQL roles
for operator/owner-arm, risk and exposure records. Entry signing now commits an
exact-decimal account-scoped risk/notional reservation before any signing claim
or custody callback. Reservations are immutable and never released by expiry
or local outcomes. Default state-v2 keeps all reservations counted. Explicit
fresh-only state-v3 excludes only independently accepted accounting records
over complete reconciliation-v2 evidence, retaining adverse loss and historical
cap/equity floors. One isolated state database is required per venue
account so policy/system contexts share the same account reservation ledger.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import traceback
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any
from uuid import UUID, uuid4

import asyncpg  # type: ignore[import-untyped]  # Upstream ships no typing marker/stubs.
from pydantic import Field, field_validator

from .managed_signer import CustodyBindingV1, ManagedSigningRequestV1, _typed_message
from .production_claims import (
    SCHEMA_VERSION as CLAIMS_SCHEMA_VERSION,
)
from .production_claims import (
    PostgresProductionClaims,
    ProductionClaimError,
    _database_name,
)
from .production_readiness import (
    ProductionContextV1,
    SignedManualArmRequestV1,
    StrictRecord,
    canonical_digest,
)
from .signing_authorization import (
    AcceptedManualNonceV1,
    ExposureSnapshotV1,
    LiveOperatorStateV1,
    ProductionSigningEvidenceV1,
    RiskGeometryV1,
)

SCHEMA = "kairos_production_state_v1"
SCHEMA_VERSION = 2
ACCOUNTING_STATE_SCHEMA_VERSION = 3
_ROLE_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,62}\Z")
_ID_PATTERN = re.compile(r"[A-Za-z0-9_.:-]{1,160}\Z")
_DIGEST_PATTERN = re.compile(r"[a-f0-9]{64}\Z")
_SQLSTATE_PATTERN = re.compile(r"[0-9A-Z]{5}\Z")
_SQLSTATE_CODES = {
    "P0001": "trigger_rejection",
    "23502": "not_null_constraint",
    "23503": "foreign_key_constraint",
    "23505": "unique_constraint",
    "23514": "check_constraint",
    "42501": "privilege_denied",
}


class AcceptedEntryReservationV1(StrictRecord):
    """Read-only proof that one signed ENTRY effect reserved risk for an arm."""

    context_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    account_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    effect_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    signing_request_id: str = Field(min_length=1, max_length=160)
    decision_id: str = Field(min_length=1, max_length=160)
    client_order_id: str = Field(min_length=1, max_length=160)
    owner_arm_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    risk_evidence: RiskGeometryV1
    observed_at: datetime
    reserved_at: datetime
    risk_usd: Decimal = Field(gt=0)
    notional_usd: Decimal = Field(gt=0)
    account_equity_usd: Decimal = Field(gt=0)
    daily_realized_loss_usd: Decimal = Field(ge=0)
    aggregate_open_risk_usd: Decimal = Field(ge=0)
    aggregate_open_notional_usd: Decimal = Field(ge=0)
    dollar_cap: Decimal = Field(gt=0)
    daily_stop_loss_usd: Decimal = Field(gt=0)
    evidence_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    request_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")

    @field_validator("observed_at", "reserved_at")
    @classmethod
    def utc_timestamps(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("reservation timestamps must be explicit UTC")
        return value

    @field_validator(
        "risk_usd",
        "notional_usd",
        "account_equity_usd",
        "daily_realized_loss_usd",
        "aggregate_open_risk_usd",
        "aggregate_open_notional_usd",
        "dollar_cap",
        "daily_stop_loss_usd",
    )
    @classmethod
    def finite_reservation_amounts(cls, value: Decimal) -> Decimal:
        if not value.is_finite():
            raise ValueError("reservation amounts must be finite")
        return value


_PYTHON_ERROR_CODES = {
    "AttributeError": "python_attribute_error",
    "TypeError": "python_type_error",
    "ValueError": "python_value_error",
    "TimeoutError": "python_timeout",
}
_PYTHON_DIAGNOSTIC_MODULES = frozenset(
    {"production_state.py", "production_readiness.py", "signing_authorization.py"}
)
_SQL_GUARD_REASONS = {
    "operator observation must precede database clock": "operator_clock",
    "operator history must start DISARMED": "operator_initial_state",
    "operator observation time must increase": "operator_time_order",
    "operator command changed without a new revision": "operator_revision_content",
    "operator rearm requires a fresh signed owner arm": "operator_arm_transition",
    "operator rearm cannot reuse a prior owner nonce": "operator_nonce_reuse",
    "operator ARM lacks its exact signed owner request": "operator_owner_arm_link",
    "operator command revision/lineage is not contiguous": "operator_revision_lineage",
    "exposure observation must precede database clock": "exposure_clock",
    "exposure observation time must increase": "exposure_time_order",
}

DDL = """
CREATE SCHEMA kairos_production_state_v1;
REVOKE ALL ON SCHEMA kairos_production_state_v1 FROM PUBLIC;
CREATE TABLE kairos_production_state_v1.identity (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 database_uuid uuid NOT NULL, policy_namespace text NOT NULL,
 account_sha256 text NOT NULL CHECK(account_sha256 ~ '^[a-f0-9]{64}$'),
 schema_version integer NOT NULL CHECK(schema_version=2),
 owner_role name NOT NULL, runtime_role name NOT NULL,
 operator_writer_role name NOT NULL, risk_writer_role name NOT NULL,
 exposure_writer_role name NOT NULL
);
CREATE TABLE kairos_production_state_v1.owner_arms (
 context_sha256 text NOT NULL CHECK(context_sha256 ~ '^[a-f0-9]{64}$'),
 request_sha256 text NOT NULL CHECK(request_sha256 ~ '^[a-f0-9]{64}$'),
 owner_identity text NOT NULL CHECK(length(owner_identity) BETWEEN 1 AND 160),
 nonce text NOT NULL CHECK(length(nonce) BETWEEN 1 AND 160),
 observed_at timestamptz NOT NULL,
 payload jsonb NOT NULL,
 payload_sha256 text NOT NULL CHECK(payload_sha256 ~ '^[a-f0-9]{64}$'),
 inserted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(context_sha256,request_sha256),
 UNIQUE(context_sha256,owner_identity,nonce),
 CHECK(payload->'request'->>'owner_identity'=owner_identity),
 CHECK(payload->'request'->>'nonce'=nonce),
 CHECK((payload->'request'->>'created_at')::timestamptz=observed_at)
);
CREATE TABLE kairos_production_state_v1.operator_observations (
 context_sha256 text NOT NULL CHECK(context_sha256 ~ '^[a-f0-9]{64}$'),
 observation_id uuid NOT NULL,
 version bigint NOT NULL CHECK(version > 0),
 observed_at timestamptz NOT NULL,
 payload jsonb NOT NULL,
 payload_sha256 text NOT NULL CHECK(payload_sha256 ~ '^[a-f0-9]{64}$'),
 inserted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(context_sha256,observation_id),
 CHECK((payload->>'version')::bigint=version),
 CHECK((payload->>'observed_at')::timestamptz=observed_at)
);
CREATE INDEX operator_observations_latest
 ON kairos_production_state_v1.operator_observations(context_sha256,observed_at DESC,inserted_at DESC);
CREATE TABLE kairos_production_state_v1.risk_decisions (
 context_sha256 text NOT NULL CHECK(context_sha256 ~ '^[a-f0-9]{64}$'),
 signing_request_id text NOT NULL CHECK(length(signing_request_id) BETWEEN 1 AND 160),
 decision_id text NOT NULL CHECK(length(decision_id) BETWEEN 1 AND 160),
 observed_at timestamptz NOT NULL,
 valid_until timestamptz NOT NULL,
 payload jsonb NOT NULL,
 payload_sha256 text NOT NULL CHECK(payload_sha256 ~ '^[a-f0-9]{64}$'),
 inserted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(context_sha256,signing_request_id),
 CHECK(valid_until > observed_at AND valid_until <= observed_at + interval '30 seconds'),
 CHECK(payload->>'signing_request_id'=signing_request_id),
 CHECK(payload->>'decision_id'=decision_id),
 CHECK((payload->>'observed_at')::timestamptz=observed_at),
 CHECK((payload->>'valid_until')::timestamptz=valid_until)
);
-- Entry reservations are irrevocable in this schema version. There is no
-- release path until a separately reviewed venue reconciliation can bind an
-- authoritative terminal outcome to this exact effect. Unknown outcomes
-- therefore remain in every subsequent account-cap calculation.
CREATE TABLE kairos_production_state_v1.risk_reservations (
 context_sha256 text NOT NULL CHECK(context_sha256 ~ '^[a-f0-9]{64}$'),
 account_sha256 text NOT NULL CHECK(account_sha256 ~ '^[a-f0-9]{64}$'),
 effect_id text NOT NULL CHECK(effect_id ~ '^[a-f0-9]{64}$'),
 signing_request_id text NOT NULL CHECK(length(signing_request_id) BETWEEN 1 AND 160),
 decision_id text NOT NULL CHECK(length(decision_id) BETWEEN 1 AND 160),
 owner_arm_sha256 text NOT NULL CHECK(owner_arm_sha256 ~ '^[a-f0-9]{64}$'),
 observed_at timestamptz NOT NULL,
 risk_usd numeric NOT NULL CHECK(risk_usd > 0 AND risk_usd < 'Infinity'::numeric),
 notional_usd numeric NOT NULL CHECK(notional_usd > 0 AND notional_usd < 'Infinity'::numeric),
 account_equity_usd numeric NOT NULL CHECK(
  account_equity_usd > 0 AND account_equity_usd < 'Infinity'::numeric),
 daily_realized_loss_usd numeric NOT NULL CHECK(
  daily_realized_loss_usd >= 0 AND daily_realized_loss_usd < 'Infinity'::numeric),
 aggregate_open_risk_usd numeric NOT NULL CHECK(
  aggregate_open_risk_usd >= 0 AND aggregate_open_risk_usd < 'Infinity'::numeric),
 aggregate_open_notional_usd numeric NOT NULL CHECK(
  aggregate_open_notional_usd >= 0 AND aggregate_open_notional_usd < 'Infinity'::numeric),
 dollar_cap numeric NOT NULL CHECK(dollar_cap > 0 AND dollar_cap < 'Infinity'::numeric),
 daily_stop_loss_usd numeric NOT NULL CHECK(
  daily_stop_loss_usd > 0 AND daily_stop_loss_usd < 'Infinity'::numeric),
 evidence_sha256 text NOT NULL CHECK(evidence_sha256 ~ '^[a-f0-9]{64}$'),
 request_sha256 text NOT NULL CHECK(request_sha256 ~ '^[a-f0-9]{64}$'),
 reserved_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(account_sha256,effect_id),
 UNIQUE(account_sha256,signing_request_id),
 FOREIGN KEY(context_sha256,signing_request_id)
  REFERENCES kairos_production_state_v1.risk_decisions(context_sha256,signing_request_id)
);
CREATE INDEX risk_reservations_account_totals
 ON kairos_production_state_v1.risk_reservations(account_sha256,context_sha256);
CREATE TABLE kairos_production_state_v1.exposure_observations (
 context_sha256 text NOT NULL CHECK(context_sha256 ~ '^[a-f0-9]{64}$'),
 observation_id uuid NOT NULL,
 instrument text NOT NULL CHECK(length(instrument) BETWEEN 1 AND 64),
 observed_at timestamptz NOT NULL,
 valid_until timestamptz NOT NULL,
 payload jsonb NOT NULL,
 payload_sha256 text NOT NULL CHECK(payload_sha256 ~ '^[a-f0-9]{64}$'),
 inserted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(context_sha256,observation_id),
 CHECK(valid_until > observed_at AND valid_until <= observed_at + interval '5 seconds'),
 CHECK(payload->>'instrument'=instrument),
 CHECK((payload->>'observed_at')::timestamptz=observed_at),
 CHECK((payload->>'valid_until')::timestamptz=valid_until)
);
CREATE INDEX exposure_observations_latest
 ON kairos_production_state_v1.exposure_observations(
  context_sha256,instrument,observed_at DESC,inserted_at DESC);
CREATE FUNCTION kairos_production_state_v1.reject_mutation() RETURNS trigger
 LANGUAGE plpgsql SET search_path=pg_catalog AS $$
 BEGIN RAISE EXCEPTION 'immutable production state record'; END $$;
CREATE TRIGGER identity_immutable BEFORE UPDATE OR DELETE ON kairos_production_state_v1.identity
 FOR EACH ROW EXECUTE FUNCTION kairos_production_state_v1.reject_mutation();
CREATE TRIGGER owner_arms_immutable BEFORE UPDATE OR DELETE ON kairos_production_state_v1.owner_arms
 FOR EACH ROW EXECUTE FUNCTION kairos_production_state_v1.reject_mutation();
CREATE TRIGGER operator_observations_immutable BEFORE UPDATE OR DELETE
 ON kairos_production_state_v1.operator_observations
 FOR EACH ROW EXECUTE FUNCTION kairos_production_state_v1.reject_mutation();
CREATE TRIGGER risk_decisions_immutable BEFORE UPDATE OR DELETE ON kairos_production_state_v1.risk_decisions
 FOR EACH ROW EXECUTE FUNCTION kairos_production_state_v1.reject_mutation();
CREATE TRIGGER risk_reservations_immutable BEFORE UPDATE OR DELETE
 ON kairos_production_state_v1.risk_reservations
 FOR EACH ROW EXECUTE FUNCTION kairos_production_state_v1.reject_mutation();
CREATE FUNCTION kairos_production_state_v1.enforce_risk_reservation() RETURNS trigger
 LANGUAGE plpgsql SET search_path=pg_catalog AS $$
 DECLARE account_scope text; risk_row record; arm_payload jsonb; arm_cap numeric; arm_daily numeric;
  prior record; base_risk numeric; base_notional numeric; daily_loss numeric;
  account_equity numeric; dollar_limit numeric; daily_limit numeric; expected_notional numeric;
  now_at timestamptz;
 BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended('risk-reservation:'||NEW.account_sha256,0));
  SELECT identity.account_sha256 INTO account_scope
   FROM kairos_production_state_v1.identity identity WHERE singleton=true;
  IF account_scope IS NULL OR account_scope<>NEW.account_sha256 THEN
   RAISE EXCEPTION 'reservation account scope mismatch';
  END IF;
  now_at := clock_timestamp();
  SELECT decision_id,observed_at,valid_until,payload_sha256,payload INTO risk_row
   FROM kairos_production_state_v1.risk_decisions
   WHERE context_sha256=NEW.context_sha256 AND signing_request_id=NEW.signing_request_id;
  IF risk_row IS NULL OR risk_row.decision_id<>NEW.decision_id
   OR risk_row.observed_at<>NEW.observed_at OR risk_row.payload_sha256<>NEW.evidence_sha256
   OR risk_row.payload->>'effect_id'<>NEW.effect_id
   OR (risk_row.payload->>'worst_case_loss_usd')::numeric<>NEW.risk_usd
   OR (risk_row.payload->>'account_equity_usd')::numeric<>NEW.account_equity_usd
   OR (risk_row.payload->>'daily_realized_loss_usd')::numeric<>NEW.daily_realized_loss_usd
   OR (risk_row.payload->>'aggregate_open_risk_usd')::numeric<>NEW.aggregate_open_risk_usd
   OR (risk_row.payload->>'aggregate_open_notional_usd')::numeric<>NEW.aggregate_open_notional_usd
   OR (risk_row.payload->>'leverage')::integer<>1
   OR risk_row.payload->>'approved' IS DISTINCT FROM 'true' THEN
   RAISE EXCEPTION 'reservation differs from exact risk decision';
  END IF;
  IF risk_row.payload->>'cash_quantity' IS NOT NULL THEN
   expected_notional := (risk_row.payload->>'cash_quantity')::numeric/100000000;
  ELSE
   IF risk_row.payload->>'price' IS NULL THEN
    RAISE EXCEPTION 'risk decision lacks exact entry price';
   END IF;
   expected_notional := (risk_row.payload->>'quantity')::numeric
    *(risk_row.payload->>'price')::numeric/10000000000000000;
  END IF;
  IF expected_notional<>NEW.notional_usd OR risk_row.valid_until<=now_at
   OR risk_row.observed_at>=now_at
   OR now_at-risk_row.observed_at>interval '5 seconds' THEN
   RAISE EXCEPTION 'reservation notional or evidence lease is invalid';
  END IF;
  SELECT payload INTO arm_payload FROM kairos_production_state_v1.owner_arms
   WHERE context_sha256=NEW.context_sha256 AND request_sha256=NEW.owner_arm_sha256;
  IF arm_payload IS NULL THEN RAISE EXCEPTION 'reservation owner arm is absent'; END IF;
  arm_cap := (arm_payload->'request'->>'dollar_cap')::numeric;
  arm_daily := (arm_payload->'request'->>'daily_stop_loss_usd')::numeric;
  IF arm_cap<>NEW.dollar_cap OR arm_daily<>NEW.daily_stop_loss_usd
   OR (arm_payload->'request'->>'expires_at')::timestamptz<=now_at THEN
   RAISE EXCEPTION 'reservation owner limits changed or expired';
  END IF;
  SELECT coalesce(sum(risk_usd),0) AS risk_usd,
   coalesce(sum(notional_usd),0) AS notional_usd,
   max(aggregate_open_risk_usd) AS base_risk,
   max(aggregate_open_notional_usd) AS base_notional,
   max(daily_realized_loss_usd) AS daily_realized,
   min(account_equity_usd) AS account_equity,
   min(dollar_cap) AS dollar_cap,
   min(daily_stop_loss_usd) AS daily_stop
   INTO prior FROM kairos_production_state_v1.risk_reservations
   WHERE account_sha256=NEW.account_sha256;
  base_risk := greatest(NEW.aggregate_open_risk_usd,coalesce(prior.base_risk,0));
  base_notional := greatest(NEW.aggregate_open_notional_usd,coalesce(prior.base_notional,0));
  daily_loss := greatest(NEW.daily_realized_loss_usd,coalesce(prior.daily_realized,0));
  account_equity := least(NEW.account_equity_usd,coalesce(prior.account_equity,NEW.account_equity_usd));
  dollar_limit := least(NEW.dollar_cap,coalesce(prior.dollar_cap,NEW.dollar_cap));
  daily_limit := least(NEW.daily_stop_loss_usd,coalesce(prior.daily_stop,NEW.daily_stop_loss_usd));
  IF NEW.risk_usd>dollar_limit OR NEW.risk_usd>account_equity*0.0025
   OR base_risk+prior.risk_usd+NEW.risk_usd>account_equity*0.01
   OR daily_loss+prior.risk_usd+NEW.risk_usd>daily_limit
   OR base_notional+prior.notional_usd+NEW.notional_usd>dollar_limit THEN
   RAISE EXCEPTION 'account risk reservation exceeds cap';
  END IF;
  RETURN NEW;
 END $$;
CREATE TRIGGER risk_reservation_guard BEFORE INSERT
 ON kairos_production_state_v1.risk_reservations
 FOR EACH ROW EXECUTE FUNCTION kairos_production_state_v1.enforce_risk_reservation();
CREATE TRIGGER exposure_observations_immutable BEFORE UPDATE OR DELETE
 ON kairos_production_state_v1.exposure_observations
 FOR EACH ROW EXECUTE FUNCTION kairos_production_state_v1.reject_mutation();
CREATE FUNCTION kairos_production_state_v1.enforce_operator_append() RETURNS trigger
 LANGUAGE plpgsql SET search_path=pg_catalog AS $$
 DECLARE prior_version bigint; prior_payload jsonb; prior_observed_at timestamptz;
  prior_exists boolean; prior_state text;
 BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended(NEW.context_sha256,0));
  SELECT version,payload,observed_at INTO prior_version,prior_payload,prior_observed_at
   FROM kairos_production_state_v1.operator_observations
   WHERE context_sha256=NEW.context_sha256
   ORDER BY observed_at DESC,inserted_at DESC LIMIT 1;
  prior_exists := FOUND;
  IF NEW.observed_at >= clock_timestamp() THEN
   RAISE EXCEPTION 'operator observation must precede database clock';
  END IF;
  IF NOT prior_exists THEN
   IF NEW.payload->>'state' <> 'DISARMED' THEN
    RAISE EXCEPTION 'operator history must start DISARMED';
   END IF;
  ELSIF NEW.observed_at <= prior_observed_at THEN
   RAISE EXCEPTION 'operator observation time must increase';
  ELSIF NEW.version=prior_version THEN
   IF (NEW.payload-'observed_at') IS DISTINCT FROM (prior_payload-'observed_at') THEN
    RAISE EXCEPTION 'operator command changed without a new revision';
   END IF;
  ELSE
   prior_state := prior_payload->>'state';
   IF NEW.payload->>'state'='ARMED' THEN
    IF prior_state='ARMED'
     OR NEW.payload->>'arm_nonce' IS NULL
     OR NEW.payload->>'arm_request_sha256' IS NULL
     OR NEW.payload->>'expires_at' IS NULL
     OR (NEW.payload->>'expires_at')::timestamptz <= NEW.observed_at THEN
     RAISE EXCEPTION 'operator rearm requires a fresh signed owner arm';
    END IF;
    IF EXISTS (
     SELECT 1 FROM kairos_production_state_v1.operator_observations prior
     WHERE prior.context_sha256=NEW.context_sha256
      AND prior.payload->>'state'='ARMED'
      AND prior.payload->>'arm_nonce'=NEW.payload->>'arm_nonce'
      AND prior.payload->>'arm_request_sha256'=NEW.payload->>'arm_request_sha256'
    ) THEN
     RAISE EXCEPTION 'operator rearm cannot reuse a prior owner nonce';
    END IF;
    IF NOT EXISTS (
     SELECT 1 FROM kairos_production_state_v1.owner_arms arm
     WHERE arm.context_sha256=NEW.context_sha256
      AND arm.request_sha256=NEW.payload->>'arm_request_sha256'
      AND arm.nonce=NEW.payload->>'arm_nonce'
    ) THEN
     RAISE EXCEPTION 'operator ARM lacks its exact signed owner request';
    END IF;
   END IF;
   IF NEW.version<>prior_version+1
   OR NEW.payload->>'previous_command_sha256' IS DISTINCT FROM prior_payload->>'command_sha256'
    OR (NEW.payload->>'changed_at')::timestamptz < (prior_payload->>'changed_at')::timestamptz THEN
    RAISE EXCEPTION 'operator command revision/lineage is not contiguous';
   END IF;
  END IF;
  RETURN NEW;
 END $$;
CREATE TRIGGER operator_append_guard BEFORE INSERT ON kairos_production_state_v1.operator_observations
 FOR EACH ROW EXECUTE FUNCTION kairos_production_state_v1.enforce_operator_append();
CREATE FUNCTION kairos_production_state_v1.enforce_exposure_append() RETURNS trigger
 LANGUAGE plpgsql SET search_path=pg_catalog AS $$
 DECLARE prior_observed_at timestamptz; prior_exists boolean;
 BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended(NEW.context_sha256||':'||NEW.instrument,0));
  SELECT observed_at INTO prior_observed_at
   FROM kairos_production_state_v1.exposure_observations
   WHERE context_sha256=NEW.context_sha256 AND instrument=NEW.instrument
   ORDER BY observed_at DESC,inserted_at DESC LIMIT 1;
  prior_exists := FOUND;
  IF NEW.observed_at >= clock_timestamp() THEN
   RAISE EXCEPTION 'exposure observation must precede database clock';
  END IF;
  IF prior_exists AND NEW.observed_at <= prior_observed_at THEN
   RAISE EXCEPTION 'exposure observation time must increase';
  END IF;
  RETURN NEW;
 END $$;
CREATE TRIGGER exposure_append_guard BEFORE INSERT ON kairos_production_state_v1.exposure_observations
 FOR EACH ROW EXECUTE FUNCTION kairos_production_state_v1.enforce_exposure_append();
REVOKE ALL ON ALL TABLES IN SCHEMA kairos_production_state_v1 FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA kairos_production_state_v1 FROM PUBLIC;
"""


def _reservation_totals_query(schema_version: int) -> str:
    """No historical row/cap/baseline is removed, including across policy arms."""
    accounting = schema_version == ACCOUNTING_STATE_SCHEMA_VERSION
    risk = "CASE WHEN a.effect_id IS NULL THEN r.risk_usd ELSE 0 END" if accounting else "r.risk_usd"
    notional = (
        "CASE WHEN a.effect_id IS NULL THEN r.notional_usd ELSE 0 END" if accounting else "r.notional_usd"
    )
    return (
        f"SELECT coalesce(sum({risk}),0) AS risk_usd, "
        f"coalesce(sum({notional}),0) AS notional_usd, "
        "max(r.aggregate_open_risk_usd) AS base_risk, "
        "max(r.aggregate_open_notional_usd) AS base_notional, "
        "max(r.daily_realized_loss_usd) AS daily_realized, "
        "min(r.account_equity_usd) AS account_equity, min(r.dollar_cap) AS dollar_cap, "
        "min(r.daily_stop_loss_usd) AS daily_stop"
        + (", coalesce(sum(a.loss_charge_usd),0) AS realized_charge " if accounting else " ")
        + "FROM kairos_production_state_v1.risk_reservations r "
        + (
            "LEFT JOIN kairos_production_accounting_v1.accepted_releases a "
            "ON a.account_sha256=r.account_sha256 AND a.effect_id=r.effect_id "
            if accounting
            else ""
        )
        + "WHERE r.account_sha256=$1"
    )


# Fresh explicit provisioning only; no ALTER, migration or reinterpretation of
# retained v2 state. The accounting schema must be independently provisioned
# before the v3 runtime can reserve anything.
_V2_TRIGGER_TOTALS_START = DDL.index("  SELECT coalesce(sum(risk_usd),0) AS risk_usd,")
_V2_TRIGGER_TOTALS_END = DDL.index("  base_risk :=", _V2_TRIGGER_TOTALS_START)
_V3_TRIGGER_TOTALS = (
    _reservation_totals_query(3)
    .replace(
        "FROM kairos_production_state_v1.risk_reservations r",
        "INTO prior FROM kairos_production_state_v1.risk_reservations r",
    )
    .replace("$1", "NEW.account_sha256")
)
DDL_V3 = (
    (DDL[:_V2_TRIGGER_TOTALS_START] + "  " + _V3_TRIGGER_TOTALS + ";\n" + DDL[_V2_TRIGGER_TOTALS_END:])
    .replace("CHECK(schema_version=2)", "CHECK(schema_version=3)")
    .replace(
        "daily_loss := greatest(NEW.daily_realized_loss_usd,coalesce(prior.daily_realized,0));",
        "daily_loss := greatest(NEW.daily_realized_loss_usd,coalesce(prior.daily_realized,0))"
        "+coalesce(prior.realized_charge,0);",
    )
)


_TABLES = (
    "identity",
    "owner_arms",
    "operator_observations",
    "risk_decisions",
    "risk_reservations",
    "exposure_observations",
)
_WRITER_TABLES = {
    "operator_writer_role": frozenset({"owner_arms", "operator_observations"}),
    "risk_writer_role": frozenset({"risk_decisions"}),
    "exposure_writer_role": frozenset({"exposure_observations"}),
}
_WRITER_SELECT_TABLES = {
    "operator_writer_role": frozenset({"identity", "owner_arms", "operator_observations"}),
    "risk_writer_role": frozenset({"identity"}),
    "exposure_writer_role": frozenset({"identity", "exposure_observations"}),
}


class ProductionStateError(PermissionError):
    """Sanitized source identity, state or persistence error; never includes a DSN."""


def _sql_diagnostic(sqlstate: object, message: object) -> str:
    """Return a fixed diagnostic token; never reflect PostgreSQL text or values."""
    if type(sqlstate) is not str or _SQLSTATE_PATTERN.fullmatch(sqlstate) is None:
        return "database_error"
    reason = _SQL_GUARD_REASONS.get(message) if type(message) is str else None
    return f"{sqlstate}/{reason or _SQLSTATE_CODES.get(sqlstate, 'database_error')}"


def _python_diagnostic(exc: Exception) -> str:
    """Return a fixed error class and allowlisted source basename/line only."""
    code = _PYTHON_ERROR_CODES.get(type(exc).__name__, "unexpected_error")
    frame = next(
        (
            item
            for item in reversed(traceback.extract_tb(exc.__traceback__))
            if item.filename.rsplit("/", 1)[-1].rsplit("\\", 1)[-1] in _PYTHON_DIAGNOSTIC_MODULES
        ),
        None,
    )
    if frame is None:
        return code
    filename = frame.filename.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    return f"{code}/{filename}:{frame.lineno}"


def _role(value: str) -> str:
    if type(value) is not str or _ROLE_PATTERN.fullmatch(value) is None:
        raise ProductionStateError("reviewed PostgreSQL role name is required")
    return value


def _identity(value: str) -> str:
    if type(value) is not str or _ID_PATTERN.fullmatch(value) is None:
        raise ProductionStateError("invalid production state identity")
    return value


def _digest(value: str) -> str:
    if type(value) is not str or _DIGEST_PATTERN.fullmatch(value) is None:
        raise ProductionStateError("invalid production state digest")
    return value


def _account_scope_sha256(context: ProductionContextV1) -> str:
    """Identify an account across instruments and policy/system revisions."""
    payload = {
        "environment": context.environment,
        "exchange": context.exchange,
        "remote_account_id": context.remote_account_id,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _account_reservation_lock(context: ProductionContextV1) -> str:
    return "risk-reservation:" + _account_scope_sha256(context)


def _decimal_text(value: Decimal) -> str:
    if not isinstance(value, Decimal) or not value.is_finite():
        raise ProductionStateError("risk reservation amount must be an exact finite decimal")
    return format(value, "f")


def _canonical_json_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return hashlib.sha256(encoded).hexdigest()


def _entry_notional_usd(message: dict[str, Any]) -> Decimal:
    if "cashQuantity" in message:
        amount = message["cashQuantity"]
        if type(amount) is not int or amount <= 0:
            raise ProductionStateError("entry cash notional is not an exact positive integer")
        return Decimal(amount) / Decimal(10**8)
    quantity = message.get("quantity")
    price = message.get("limitPrice", message.get("price"))
    if type(quantity) is not int or quantity <= 0 or type(price) is not int or price <= 0:
        raise ProductionStateError("entry quantity/price notional is not exact")
    notional = Decimal(quantity) * Decimal(price) / Decimal(10**16)
    if notional <= 0 or not notional.is_finite():
        raise ProductionStateError("entry notional is outside the exact positive range")
    return notional


def _payload(model: Any) -> tuple[dict[str, Any], str]:
    data = model.model_dump(mode="json")
    encoded = json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return data, hashlib.sha256(encoded).hexdigest()


def _parse_json_model(payload: Any, model_type: Any, label: str) -> Any:
    if isinstance(payload, str):
        encoded = payload
    elif isinstance(payload, dict):
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
    else:
        raise ProductionStateError(f"stored {label} payload is not JSON")
    try:
        return model_type.model_validate_json(encoded)
    except Exception:
        raise ProductionStateError(f"stored {label} payload is invalid") from None


def _validate_snapshot_clock(
    *, started_at: datetime, resolved_at: datetime, checked_at: datetime, max_age: timedelta
) -> None:
    """Compare DB time to a fresh post-I/O local clock, not request start time."""
    values = (started_at, resolved_at, checked_at)
    if any(value.tzinfo is None or value.utcoffset() != timedelta(0) for value in values):
        raise ProductionStateError("production snapshot clocks must be explicit UTC timestamps")
    if checked_at < started_at:
        raise ProductionStateError("production authorization clock moved backwards")
    if resolved_at > checked_at or checked_at - resolved_at > max_age:
        raise ProductionStateError("production signing state snapshot is stale or future-dated")


async def _check_role_isolated(
    connection: asyncpg.Connection, role_name: str, protected: Sequence[str]
) -> None:
    row = await connection.fetchrow(
        "SELECT rolsuper,rolcreaterole,rolcreatedb,rolreplication,rolbypassrls,rolinherit "
        "FROM pg_roles WHERE rolname=$1",
        role_name,
    )
    if row is None or any(row.values()):
        raise ProductionStateError("production state role has unsafe PostgreSQL attributes")
    for target in protected:
        if role_name != target and await connection.fetchval(
            "SELECT pg_has_role($1,$2,'MEMBER')", role_name, target
        ):
            raise ProductionStateError("production state roles must not inherit one another")


async def provision_production_state_schema(
    connection: asyncpg.Connection,
    *,
    expected_database: str,
    database_uuid: UUID,
    policy_namespace: str,
    context: ProductionContextV1,
    owner_role: str,
    runtime_role: str,
    operator_writer_role: str,
    risk_writer_role: str,
    exposure_writer_role: str,
    state_schema_version: int = SCHEMA_VERSION,
) -> None:
    """Explicit owner-only schema provisioning; never called by a runtime path.

    Login roles must already exist and be mutually isolated. The caller must
    provision a fresh, exact-prefix database; this function creates no database
    and refuses an existing schema.
    """
    expected_database = _database_name(expected_database)
    if state_schema_version not in (SCHEMA_VERSION, ACCOUNTING_STATE_SCHEMA_VERSION):
        raise ProductionStateError("unsupported explicit production state schema version")
    roles = {
        "owner_role": _role(owner_role),
        "runtime_role": _role(runtime_role),
        "operator_writer_role": _role(operator_writer_role),
        "risk_writer_role": _role(risk_writer_role),
        "exposure_writer_role": _role(exposure_writer_role),
    }
    if (
        len(set(roles.values())) != len(roles)
        or not isinstance(database_uuid, UUID)
        or database_uuid.int == 0
    ):
        raise ProductionStateError("separate state ownership, reader and writer identities are required")
    if _identity(policy_namespace) != policy_namespace:
        raise ProductionStateError("invalid production state policy namespace")
    context = ProductionContextV1.model_validate(context)
    actual = await connection.fetchrow("SELECT current_database() AS db,current_user AS role")
    if actual["db"] != expected_database or actual["role"] != owner_role:
        raise ProductionStateError("production state schema owner/database mismatch")
    protected = tuple(roles.values())
    for role_name in protected:
        await _check_role_isolated(connection, role_name, protected)
    if await connection.fetchval("SELECT to_regnamespace($1)", SCHEMA) is not None:
        raise ProductionStateError("production state schema already exists; do not re-provision")

    async with connection.transaction():
        await connection.execute(DDL if state_schema_version == SCHEMA_VERSION else DDL_V3)
        await connection.execute(
            "INSERT INTO kairos_production_state_v1.identity VALUES(true,$1,$2,$3,$4,$5,$6,$7,$8,$9)",
            database_uuid,
            policy_namespace,
            _account_scope_sha256(context),
            state_schema_version,
            owner_role,
            runtime_role,
            operator_writer_role,
            risk_writer_role,
            exposure_writer_role,
        )
        await connection.execute(f'GRANT USAGE ON SCHEMA {SCHEMA} TO "{runtime_role}"')
        await connection.execute(f'GRANT SELECT ON ALL TABLES IN SCHEMA {SCHEMA} TO "{runtime_role}"')
        for writer_field, table_set in _WRITER_TABLES.items():
            writer = roles[writer_field]
            await connection.execute(f'GRANT USAGE ON SCHEMA {SCHEMA} TO "{writer}"')
            select_tables = _WRITER_SELECT_TABLES[writer_field]
            select_names = ",".join(f"{SCHEMA}.{table}" for table in sorted(select_tables))
            await connection.execute(f'GRANT SELECT ON {select_names} TO "{writer}"')
            table_names = ",".join(f"{SCHEMA}.{table}" for table in sorted(table_set))
            await connection.execute(f'GRANT INSERT ON {table_names} TO "{writer}"')
        await connection.execute(f'GRANT INSERT ON {SCHEMA}.risk_reservations TO "{roles["runtime_role"]}"')


class _StateDB:
    def __init__(
        self,
        pool: asyncpg.Pool,
        *,
        expected_database: str,
        database_uuid: UUID,
        policy_namespace: str,
        context: ProductionContextV1,
        role_field: str,
        expected_role: str,
        state_schema_version: int = SCHEMA_VERSION,
    ) -> None:
        self.pool = pool
        self.expected_database = _database_name(expected_database)
        if not isinstance(database_uuid, UUID) or database_uuid.int == 0:
            raise ProductionStateError("an exact nonzero isolated database UUID is required")
        self.database_uuid = database_uuid
        self.policy_namespace = _identity(policy_namespace)
        self.context = ProductionContextV1.model_validate(context)
        self.context_sha256 = canonical_digest(self.context)
        self.role_field = role_field
        self.expected_role = _role(expected_role)
        if state_schema_version not in (SCHEMA_VERSION, ACCOUNTING_STATE_SCHEMA_VERSION):
            raise ProductionStateError("unsupported explicit production state schema version")
        self.state_schema_version = state_schema_version

    async def inspect(self, connection: asyncpg.Connection) -> asyncpg.Record:
        actual = await connection.fetchrow("SELECT current_database() AS db,current_user AS role")
        if actual is None or actual["db"] != self.expected_database or actual["role"] != self.expected_role:
            raise ProductionStateError("production state database/role mismatch")
        identity = await connection.fetchrow(
            "SELECT * FROM kairos_production_state_v1.identity WHERE singleton=true"
        )
        expected_columns = {
            "database_uuid": self.database_uuid,
            "policy_namespace": self.policy_namespace,
            "account_sha256": _account_scope_sha256(self.context),
            "schema_version": self.state_schema_version,
            self.role_field: self.expected_role,
        }
        if identity is None or any(identity[key] != value for key, value in expected_columns.items()):
            raise ProductionStateError("production state UUID/context/schema/role mismatch")
        owner = identity["owner_role"]
        protected = tuple(identity[key] for key in ("owner_role", "runtime_role", *_WRITER_TABLES))
        if len(set(protected)) != len(protected):
            raise ProductionStateError("production state roles are not isolated")
        await _check_role_isolated(connection, owner, protected)
        await _check_role_isolated(connection, self.expected_role, protected)
        schema_owner = await connection.fetchval(
            "SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname=$1", SCHEMA
        )
        if schema_owner != owner:
            raise ProductionStateError("production state schema ownership mismatch")

        allowed_tables = (
            frozenset({"risk_reservations"})
            if self.role_field == "runtime_role"
            else _WRITER_TABLES.get(self.role_field, frozenset())
        )
        for table in _TABLES:
            name = f"{SCHEMA}.{table}"
            table_owner = await connection.fetchval(
                "SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid=to_regclass($1)", name
            )
            if table_owner != owner:
                raise ProductionStateError("production state table ownership mismatch")
            has_select = await connection.fetchval(
                "SELECT has_table_privilege($1,$2,'SELECT')", self.expected_role, name
            )
            expected_select = self.role_field == "runtime_role" or table in _WRITER_SELECT_TABLES.get(
                self.role_field, frozenset()
            )
            if has_select != expected_select:
                raise ProductionStateError("production state SELECT privilege mismatch")
            if await connection.fetchval(
                "SELECT has_table_privilege($1,$2,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')",
                self.expected_role,
                name,
            ):
                raise ProductionStateError("production state role can alter immutable evidence")
            insert = await connection.fetchval(
                "SELECT has_table_privilege($1,$2,'INSERT')", self.expected_role, name
            )
            expected_insert = table in allowed_tables
            if insert != expected_insert:
                raise ProductionStateError("production state role has unexpected insert privilege")
        if await connection.fetchval(
            "SELECT has_schema_privilege($1,$2,'CREATE')", self.expected_role, SCHEMA
        ):
            raise ProductionStateError("production state role can modify its schema")
        return identity

    async def _write(self, callback):
        try:
            async with asyncio.timeout(10):
                async with self.pool.acquire() as connection:
                    await self.inspect(connection)
                    async with connection.transaction():
                        await connection.execute("SET LOCAL statement_timeout='5s'")
                        return await callback(connection)
        except ProductionStateError:
            raise
        except asyncpg.PostgresError as exc:
            diagnostic = _sql_diagnostic(exc.sqlstate, exc.message)
            raise ProductionStateError(f"production state append rejected [{diagnostic}]") from None
        except Exception as exc:
            safe_code = _python_diagnostic(exc)
            raise ProductionStateError(
                f"production state append outcome unavailable [{safe_code}]; do not retry blindly"
            ) from None


class PostgresOperatorStateWriter(_StateDB):
    """INSERT-only operator/owner-arm writer; must use its dedicated login role."""

    def __init__(self, pool: asyncpg.Pool, **kwargs: Any) -> None:
        super().__init__(pool, role_field="operator_writer_role", **kwargs)

    async def append_owner_arm_async(self, signed_arm: SignedManualArmRequestV1) -> None:
        signed_arm = SignedManualArmRequestV1.model_validate(signed_arm)
        if signed_arm.request.context != self.context:
            raise ProductionStateError("owner arm context differs from source scope")
        data, payload_sha = _payload(signed_arm)
        request_sha = canonical_digest(signed_arm.request)

        async def append(connection: asyncpg.Connection) -> None:
            # Owner-arm changes and reservations serialize for the same
            # account. Operator transitions acquire this lock as well.
            await connection.fetchval(
                "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                _account_reservation_lock(self.context),
            )
            await connection.execute(
                "INSERT INTO kairos_production_state_v1.owner_arms "
                "(context_sha256,request_sha256,owner_identity,nonce,observed_at,payload,payload_sha256) "
                "VALUES($1,$2,$3,$4,$5,$6::jsonb,$7)",
                self.context_sha256,
                request_sha,
                signed_arm.request.owner_identity,
                signed_arm.request.nonce,
                signed_arm.request.created_at,
                json.dumps(data, separators=(",", ":"), allow_nan=False),
                payload_sha,
            )

        await self._write(append)

    async def append_operator_observation_async(self, state: LiveOperatorStateV1) -> UUID:
        state = LiveOperatorStateV1.model_validate(state)
        if state.context != self.context:
            raise ProductionStateError("operator state context differs from source scope")
        data, payload_sha = _payload(state)
        observation_id = uuid4()

        async def append(connection: asyncpg.Connection) -> None:
            await connection.fetchval(
                "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                _account_reservation_lock(self.context),
            )
            await connection.fetchval(
                "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                f"operator:{self.context_sha256}",
            )
            latest = await connection.fetchrow(
                "SELECT version,observed_at,payload FROM kairos_production_state_v1.operator_observations "
                "WHERE context_sha256=$1 ORDER BY observed_at DESC,inserted_at DESC LIMIT 1",
                self.context_sha256,
            )
            db_now = (await connection.fetchval("SELECT clock_timestamp()")).astimezone(UTC)
            if state.observed_at >= db_now:
                raise ProductionStateError("operator observation is not before the database clock")
            if latest is None:
                if state.state != "DISARMED":
                    raise ProductionStateError("operator history must start with an explicit DISARMED state")
            else:
                prior = _parse_json_model(latest["payload"], LiveOperatorStateV1, "operator observation")
                if state.observed_at <= prior.observed_at:
                    raise ProductionStateError("operator observation time must increase monotonically")
                if state.version == prior.version:
                    current_data = state.model_dump(mode="json")
                    previous_data = prior.model_dump(mode="json")
                    current_data.pop("observed_at")
                    previous_data.pop("observed_at")
                    if current_data != previous_data:
                        raise ProductionStateError("unchanged operator revision changed command state")
                elif (
                    state.version != prior.version + 1
                    or state.previous_command_sha256 != prior.command_sha256
                    or state.changed_at < prior.changed_at
                ):
                    raise ProductionStateError("operator command revision/lineage is not contiguous")
            await connection.execute(
                "INSERT INTO kairos_production_state_v1.operator_observations "
                "(context_sha256,observation_id,version,observed_at,payload,payload_sha256) "
                "VALUES($1,$2,$3,$4,$5::jsonb,$6)",
                self.context_sha256,
                observation_id,
                state.version,
                state.observed_at,
                json.dumps(data, separators=(",", ":"), allow_nan=False),
                payload_sha,
            )

        await self._write(append)
        return observation_id


class PostgresRiskStateWriter(_StateDB):
    """INSERT-only exact-request risk writer; cannot write operator/exposure evidence."""

    def __init__(self, pool: asyncpg.Pool, **kwargs: Any) -> None:
        super().__init__(pool, role_field="risk_writer_role", **kwargs)

    async def append_risk_decision_async(self, risk: RiskGeometryV1) -> None:
        risk = RiskGeometryV1.model_validate(risk)
        if risk.context != self.context:
            raise ProductionStateError("risk context differs from source scope")
        data, payload_sha = _payload(risk)

        async def append(connection: asyncpg.Connection) -> None:
            await connection.fetchval(
                "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                _account_reservation_lock(self.context),
            )
            await connection.execute(
                "INSERT INTO kairos_production_state_v1.risk_decisions "
                "(context_sha256,signing_request_id,decision_id,observed_at,valid_until,payload,"
                "payload_sha256) "
                "VALUES($1,$2,$3,$4,$5,$6::jsonb,$7)",
                self.context_sha256,
                risk.signing_request_id,
                risk.decision_id,
                risk.observed_at,
                risk.valid_until,
                json.dumps(data, separators=(",", ":"), allow_nan=False),
                payload_sha,
            )

        await self._write(append)


class PostgresExposureStateWriter(_StateDB):
    """INSERT-only current-position snapshot writer; cannot alter risk/operator state."""

    def __init__(self, pool: asyncpg.Pool, **kwargs: Any) -> None:
        super().__init__(pool, role_field="exposure_writer_role", **kwargs)

    async def append_exposure_async(self, exposure: ExposureSnapshotV1) -> UUID:
        exposure = ExposureSnapshotV1.model_validate(exposure)
        if exposure.context != self.context:
            raise ProductionStateError("exposure context differs from source scope")
        data, payload_sha = _payload(exposure)
        observation_id = uuid4()

        async def append(connection: asyncpg.Connection) -> None:
            await connection.fetchval(
                "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                f"exposure:{self.context_sha256}:{exposure.instrument}",
            )
            latest = await connection.fetchrow(
                "SELECT observed_at FROM kairos_production_state_v1.exposure_observations "
                "WHERE context_sha256=$1 AND instrument=$2 "
                "ORDER BY observed_at DESC,inserted_at DESC LIMIT 1",
                self.context_sha256,
                exposure.instrument,
            )
            db_now = (await connection.fetchval("SELECT clock_timestamp()")).astimezone(UTC)
            if exposure.observed_at >= db_now:
                raise ProductionStateError("exposure observation is not before the database clock")
            if latest is not None and exposure.observed_at <= latest["observed_at"]:
                raise ProductionStateError("exposure observation time must increase monotonically")
            await connection.execute(
                "INSERT INTO kairos_production_state_v1.exposure_observations "
                "(context_sha256,observation_id,instrument,observed_at,valid_until,payload,payload_sha256) "
                "VALUES($1,$2,$3,$4,$5,$6::jsonb,$7)",
                self.context_sha256,
                observation_id,
                exposure.instrument,
                exposure.observed_at,
                exposure.valid_until,
                json.dumps(data, separators=(",", ":"), allow_nan=False),
                payload_sha,
            )

        await self._write(append)
        return observation_id


class AsyncPostgresProductionSigningStateSource(_StateDB):
    """Resolve exact owner, nonce, operator, risk and exposure records asynchronously.

    All joins happen in one `REPEATABLE READ, READ ONLY` snapshot. The same
    connection runs the claims identity/least-privilege inspection before the
    accepted owner nonce is read, so a separately configured or primary claims
    store cannot be substituted.
    """

    def __init__(
        self,
        pool: asyncpg.Pool,
        *,
        expected_database: str,
        database_uuid: UUID,
        policy_namespace: str,
        runtime_role: str,
        context: ProductionContextV1,
        max_snapshot_age: timedelta = timedelta(seconds=5),
        clock_probe: Callable[[], datetime] = lambda: datetime.now(UTC),
        state_schema_version: int = SCHEMA_VERSION,
    ) -> None:
        if not timedelta(0) < max_snapshot_age <= timedelta(seconds=5):
            raise ValueError("production state freshness may not exceed five seconds")
        super().__init__(
            pool,
            expected_database=expected_database,
            database_uuid=database_uuid,
            policy_namespace=policy_namespace,
            context=context,
            role_field="runtime_role",
            expected_role=runtime_role,
            state_schema_version=state_schema_version,
        )
        self.runtime_role = _role(runtime_role)
        self.max_snapshot_age = max_snapshot_age
        self._clock_probe = clock_probe

    async def resolve_owner_lineage_async(
        self, manual_request_sha256: str
    ) -> tuple[SignedManualArmRequestV1, AcceptedManualNonceV1]:
        """Resolve one accepted signed owner arm from the isolated read snapshot.

        This is deliberately independent of signing requests: cancellation is
        authenticated by the original accepted owner lineage, not by forging a
        new managed-signing operation. The arm may be historical; its caller
        verifies it at the durable nonce-claim time using the same pinned owner
        key and preconditions as order authorization.
        """
        try:
            request_digest = _digest(manual_request_sha256)
            started_at = self._clock_probe()
            if started_at.tzinfo is None or started_at.utcoffset() != timedelta(0):
                raise ProductionStateError("an explicit UTC owner-lineage time is required")
            async with asyncio.timeout(10):
                async with self.pool.acquire() as connection:
                    async with connection.transaction(isolation="repeatable_read", readonly=True):
                        await connection.execute("SET LOCAL statement_timeout='5s'")
                        identity = await self.inspect(connection)
                        claims = PostgresProductionClaims(
                            self.pool,
                            expected_database=self.expected_database,
                            database_uuid=self.database_uuid,
                            policy_namespace=self.policy_namespace,
                            runtime_role=self.runtime_role,
                            context=self.context,
                        )
                        await claims.inspect(connection)
                        claim_identity = await connection.fetchrow(
                            "SELECT schema_version FROM kairos_production_evidence_v1.identity "
                            "WHERE singleton=true"
                        )
                        if (
                            claim_identity is None
                            or claim_identity["schema_version"] != CLAIMS_SCHEMA_VERSION
                        ):
                            raise ProductionStateError("production claims schema version mismatch")
                        await self._inspect_writer_contract(connection, identity)
                        arm_row = await connection.fetchrow(
                            "SELECT * FROM kairos_production_state_v1.owner_arms "
                            "WHERE context_sha256=$1 AND request_sha256=$2",
                            self.context_sha256,
                            request_digest,
                        )
                        owner_arm = self._verified_payload(arm_row, SignedManualArmRequestV1, "owner arm")
                        arm = owner_arm.request
                        if arm.context != self.context or canonical_digest(arm) != request_digest:
                            raise ProductionStateError("stored owner arm context/request binding mismatch")
                        if (
                            arm_row["owner_identity"] != arm.owner_identity
                            or arm_row["nonce"] != arm.nonce
                            or arm_row["observed_at"] != arm.created_at
                        ):
                            raise ProductionStateError("stored owner arm identity mismatch")
                        nonce_row = await connection.fetchrow(
                            "SELECT * FROM kairos_production_evidence_v1.claims "
                            "WHERE claim_kind='MANUAL_NONCE' AND namespace=$1 AND identity=$2",
                            arm.owner_identity,
                            arm.nonce,
                        )
                        if nonce_row is None:
                            raise ProductionStateError("accepted owner nonce claim is absent")
                        owner_claim = AcceptedManualNonceV1(
                            owner_identity=nonce_row["namespace"],
                            nonce=nonce_row["identity"],
                            request_sha256=nonce_row["request_sha256"],
                            context_sha256=nonce_row["context_sha256"],
                            database_uuid=self.database_uuid,
                            claimed_at=nonce_row["claimed_at"].astimezone(UTC),
                        )
                        if (
                            owner_claim.owner_identity != arm.owner_identity
                            or owner_claim.nonce != arm.nonce
                            or owner_claim.request_sha256 != request_digest
                            or owner_claim.context_sha256 != self.context_sha256
                            or owner_claim.claimed_at < arm.created_at
                        ):
                            raise ProductionStateError("accepted owner nonce does not bind the exact arm")
                        resolved_at = (await connection.fetchval("SELECT clock_timestamp()")).astimezone(UTC)
            checked_at = self._clock_probe()
            _validate_snapshot_clock(
                started_at=started_at,
                resolved_at=resolved_at,
                checked_at=checked_at,
                max_age=self.max_snapshot_age,
            )
            return owner_arm, owner_claim
        except ProductionStateError:
            raise
        except Exception:
            raise ProductionStateError("authoritative production owner lineage is unavailable") from None

    async def resolve_entry_reservation_async(
        self,
        signing_effect_id: str,
        manual_request_sha256: str,
        signing_request_id: str,
        decision_id: str,
    ) -> AcceptedEntryReservationV1:
        """Resolve an immutable ENTRY risk reservation and its exact risk row.

        This read-only lookup exists for historical lifecycle cancellation: it
        proves that the original signing effect was durably reserved against
        this owner arm, without relying on an expired short-lived risk lease.
        The reservation, risk row, claims identity, and writer contract are
        checked inside one isolated REPEATABLE READ snapshot.
        """
        try:
            effect_digest = _digest(signing_effect_id)
            owner_digest = _digest(manual_request_sha256)
            request_id = _identity(signing_request_id)
            expected_decision = _identity(decision_id)
            started_at = self._clock_probe()
            if started_at.tzinfo is None or started_at.utcoffset() != timedelta(0):
                raise ProductionStateError("an explicit UTC entry-reservation time is required")
            async with asyncio.timeout(10):
                async with self.pool.acquire() as connection:
                    async with connection.transaction(isolation="repeatable_read", readonly=True):
                        await connection.execute("SET LOCAL statement_timeout='5s'")
                        identity = await self.inspect(connection)
                        claims = PostgresProductionClaims(
                            self.pool,
                            expected_database=self.expected_database,
                            database_uuid=self.database_uuid,
                            policy_namespace=self.policy_namespace,
                            runtime_role=self.runtime_role,
                            context=self.context,
                        )
                        await claims.inspect(connection)
                        claim_identity = await connection.fetchrow(
                            "SELECT schema_version FROM kairos_production_evidence_v1.identity "
                            "WHERE singleton=true"
                        )
                        if (
                            claim_identity is None
                            or claim_identity["schema_version"] != CLAIMS_SCHEMA_VERSION
                        ):
                            raise ProductionStateError("production claims schema version mismatch")
                        await self._inspect_writer_contract(connection, identity)
                        risk_row = await connection.fetchrow(
                            "SELECT * FROM kairos_production_state_v1.risk_decisions "
                            "WHERE context_sha256=$1 AND signing_request_id=$2",
                            self.context_sha256,
                            request_id,
                        )
                        risk = self._verified_payload(risk_row, RiskGeometryV1, "entry risk decision")
                        _, evidence_sha256 = _payload(risk)
                        if (
                            risk.context != self.context
                            or risk.signing_request_id != request_id
                            or risk.decision_id != expected_decision
                            or risk.effect_id != effect_digest
                            or risk.operation != "New limit order"
                            or risk.client_order_id is None
                            or risk.observed_at != risk_row["observed_at"]
                            or risk.valid_until != risk_row["valid_until"]
                        ):
                            raise ProductionStateError("entry risk row differs from exact signing effect")
                        reservation_row = await connection.fetchrow(
                            "SELECT * FROM kairos_production_state_v1.risk_reservations "
                            "WHERE context_sha256=$1 AND account_sha256=$2 AND effect_id=$3",
                            self.context_sha256,
                            _account_scope_sha256(self.context),
                            effect_digest,
                        )
                        if reservation_row is None:
                            raise ProductionStateError("exact entry risk reservation is absent")
                        if (
                            reservation_row["context_sha256"] != self.context_sha256
                            or reservation_row["account_sha256"] != _account_scope_sha256(self.context)
                            or reservation_row["effect_id"] != effect_digest
                            or reservation_row["signing_request_id"] != request_id
                            or reservation_row["decision_id"] != expected_decision
                            or reservation_row["owner_arm_sha256"] != owner_digest
                            or reservation_row["observed_at"] != risk.observed_at
                            or reservation_row["evidence_sha256"] != evidence_sha256
                            or Decimal(reservation_row["risk_usd"]) != risk.worst_case_loss_usd
                            or risk.price is None
                            or Decimal(reservation_row["notional_usd"])
                            != Decimal(risk.quantity) * Decimal(risk.price) / Decimal(10**16)
                            or Decimal(reservation_row["account_equity_usd"]) != risk.account_equity_usd
                            or Decimal(reservation_row["daily_realized_loss_usd"])
                            != risk.daily_realized_loss_usd
                            or Decimal(reservation_row["aggregate_open_risk_usd"])
                            != risk.aggregate_open_risk_usd
                            or Decimal(reservation_row["aggregate_open_notional_usd"])
                            != risk.aggregate_open_notional_usd
                        ):
                            raise ProductionStateError(
                                "entry risk reservation does not bind exact arm and risk row"
                            )
                        fact = AcceptedEntryReservationV1(
                            context_sha256=reservation_row["context_sha256"],
                            account_sha256=reservation_row["account_sha256"],
                            effect_id=reservation_row["effect_id"],
                            signing_request_id=reservation_row["signing_request_id"],
                            decision_id=reservation_row["decision_id"],
                            client_order_id=risk.client_order_id,
                            owner_arm_sha256=reservation_row["owner_arm_sha256"],
                            risk_evidence=risk,
                            observed_at=reservation_row["observed_at"].astimezone(UTC),
                            reserved_at=reservation_row["reserved_at"].astimezone(UTC),
                            risk_usd=Decimal(reservation_row["risk_usd"]),
                            notional_usd=Decimal(reservation_row["notional_usd"]),
                            account_equity_usd=Decimal(reservation_row["account_equity_usd"]),
                            daily_realized_loss_usd=Decimal(reservation_row["daily_realized_loss_usd"]),
                            aggregate_open_risk_usd=Decimal(reservation_row["aggregate_open_risk_usd"]),
                            aggregate_open_notional_usd=Decimal(
                                reservation_row["aggregate_open_notional_usd"]
                            ),
                            dollar_cap=Decimal(reservation_row["dollar_cap"]),
                            daily_stop_loss_usd=Decimal(reservation_row["daily_stop_loss_usd"]),
                            evidence_sha256=reservation_row["evidence_sha256"],
                            request_sha256=reservation_row["request_sha256"],
                        )
                        resolved_at = (await connection.fetchval("SELECT clock_timestamp()")).astimezone(UTC)
            checked_at = self._clock_probe()
            _validate_snapshot_clock(
                started_at=started_at,
                resolved_at=resolved_at,
                checked_at=checked_at,
                max_age=self.max_snapshot_age,
            )
            return fact
        except ProductionStateError:
            raise
        except Exception:
            raise ProductionStateError("authoritative entry risk reservation is unavailable") from None

    async def resolve_signing_evidence_async(
        self, *, request: ManagedSigningRequestV1, binding: CustodyBindingV1, now: datetime
    ) -> ProductionSigningEvidenceV1:
        """Read durable source evidence without blocking the caller's event loop."""
        try:
            request = ManagedSigningRequestV1.model_validate(request)
            binding = CustodyBindingV1.model_validate(binding)
            if now.tzinfo is None or now.utcoffset() != timedelta(0):
                raise ProductionStateError("an explicit UTC authorization time is required")
            if request.context != self.context or binding.context != self.context:
                raise ProductionStateError("signing request/custody context differs from source scope")
            message = _typed_message(request, binding)[1]
            exit_operation = request.operation in {"Position close order", "New take-profit/stop-loss"}
            async with asyncio.timeout(10):
                async with self.pool.acquire() as connection:
                    async with connection.transaction(isolation="repeatable_read", readonly=True):
                        await connection.execute("SET LOCAL statement_timeout='5s'")
                        identity = await self.inspect(connection)
                        claims = PostgresProductionClaims(
                            self.pool,
                            expected_database=self.expected_database,
                            database_uuid=self.database_uuid,
                            policy_namespace=self.policy_namespace,
                            runtime_role=self.runtime_role,
                            context=self.context,
                        )
                        await claims.inspect(connection)
                        claim_identity = await connection.fetchrow(
                            "SELECT schema_version FROM kairos_production_evidence_v1.identity "
                            "WHERE singleton=true"
                        )
                        if (
                            claim_identity is None
                            or claim_identity["schema_version"] != CLAIMS_SCHEMA_VERSION
                        ):
                            raise ProductionStateError("production claims schema version mismatch")
                        await self._inspect_writer_contract(connection, identity)
                        evidence = await self._read_snapshot(
                            connection,
                            request=request,
                            message=message,
                            exit_operation=exit_operation,
                            now=now,
                        )
            checked_at = self._clock_probe()
            _validate_snapshot_clock(
                started_at=now,
                resolved_at=evidence.resolved_at,
                checked_at=checked_at,
                max_age=self.max_snapshot_age,
            )
            return evidence
        except (ProductionStateError, ProductionClaimError):
            raise
        except Exception:
            raise ProductionStateError("authoritative production signing state is unavailable") from None

    async def reserve_entry_async(
        self,
        *,
        request: ManagedSigningRequestV1,
        binding: CustodyBindingV1,
        evidence: ProductionSigningEvidenceV1,
    ) -> None:
        """Commit one account-scoped entry reservation before signing.

        Reservations remain immutable. Default v2 keeps every reservation
        counted; explicit fresh v3 joins accepted terminal accounting records.
        A signed/unknown order always keeps consuming capacity without that
        exact independent proof. Neither version resets a daily limit.
        """
        try:
            request = ManagedSigningRequestV1.model_validate(request)
            binding = CustodyBindingV1.model_validate(binding)
            evidence = ProductionSigningEvidenceV1.model_validate(evidence)
            if request.operation in {"Position close order", "New take-profit/stop-loss"}:
                return
            if request.context != self.context or binding.context != self.context:
                raise ProductionStateError("risk reservation context differs from source scope")
            risk = evidence.risk
            arm = evidence.owner_arm.request
            if (
                evidence.operator is None
                or risk.context != self.context
                or risk.signing_request_id != request.request_id
                or request.manual_request_sha256 != canonical_digest(arm)
                or arm.context != self.context
            ):
                raise ProductionStateError("risk reservation lacks the exact verified entry lineage")
            message = _typed_message(request, binding)[1]
            notional = _entry_notional_usd(message)
            risk_amount = risk.worst_case_loss_usd
            if not risk_amount.is_finite() or risk_amount <= 0:
                raise ProductionStateError("risk reservation loss must be finite and positive")
            context_digest = self.context_sha256
            account_digest = _account_scope_sha256(self.context)
            _, evidence_digest = _payload(risk)
            request_digest = _canonical_json_digest(
                {
                    "request": request.model_dump(mode="json"),
                    "binding": binding.model_dump(mode="json"),
                    "risk_evidence_sha256": evidence_digest,
                    "owner_arm_sha256": canonical_digest(arm),
                    "effect_id": risk.effect_id,
                }
            )
            claims = PostgresProductionClaims(
                self.pool,
                expected_database=self.expected_database,
                database_uuid=self.database_uuid,
                policy_namespace=self.policy_namespace,
                runtime_role=self.runtime_role,
                context=self.context,
            )

            async def reserve(connection: asyncpg.Connection) -> None:
                await claims.inspect(connection)
                # The same account key serializes risk-decision insertion,
                # operator command changes and competing entry reservations.
                await connection.fetchval(
                    "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                    _account_reservation_lock(self.context),
                )
                await connection.fetchval(
                    "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                    f"operator:{context_digest}",
                )
                db_now = (await connection.fetchval("SELECT clock_timestamp()")).astimezone(UTC)
                if (
                    risk.observed_at > db_now
                    or db_now - risk.observed_at > self.max_snapshot_age
                    or risk.valid_until <= db_now
                    or risk.valid_until - risk.observed_at > timedelta(seconds=30)
                    or not arm.created_at <= db_now < arm.expires_at
                ):
                    raise ProductionStateError("risk or owner limit evidence expired before reservation")

                risk_row = await connection.fetchrow(
                    "SELECT decision_id,observed_at,payload_sha256 FROM "
                    "kairos_production_state_v1.risk_decisions "
                    "WHERE context_sha256=$1 AND signing_request_id=$2",
                    context_digest,
                    request.request_id,
                )
                if (
                    risk_row is None
                    or risk_row["decision_id"] != risk.decision_id
                    or risk_row["observed_at"] != risk.observed_at
                    or risk_row["payload_sha256"] != evidence_digest
                ):
                    raise ProductionStateError("risk reservation is not bound to its persisted decision")

                arm_digest = canonical_digest(arm)
                arm_row = await connection.fetchrow(
                    "SELECT payload_sha256 FROM kairos_production_state_v1.owner_arms "
                    "WHERE context_sha256=$1 AND request_sha256=$2 AND owner_identity=$3 AND nonce=$4",
                    context_digest,
                    arm_digest,
                    arm.owner_identity,
                    arm.nonce,
                )
                _, arm_payload_digest = _payload(evidence.owner_arm)
                nonce_row = await connection.fetchrow(
                    "SELECT request_sha256,context_sha256 FROM kairos_production_evidence_v1.claims "
                    "WHERE claim_kind='MANUAL_NONCE' AND namespace=$1 AND identity=$2",
                    arm.owner_identity,
                    arm.nonce,
                )
                if (
                    arm_row is None
                    or arm_row["payload_sha256"] != arm_payload_digest
                    or nonce_row is None
                    or nonce_row["request_sha256"] != arm_digest
                    or nonce_row["context_sha256"] != context_digest
                ):
                    raise ProductionStateError("risk reservation lacks the accepted exact owner arm")

                operator_row = await connection.fetchrow(
                    "SELECT payload,payload_sha256 FROM kairos_production_state_v1.operator_observations "
                    "WHERE context_sha256=$1 ORDER BY observed_at DESC,inserted_at DESC LIMIT 1",
                    context_digest,
                )
                if operator_row is None:
                    raise ProductionStateError("risk reservation lacks current operator state")
                operator = _parse_json_model(
                    operator_row["payload"], LiveOperatorStateV1, "operator observation"
                )
                _, operator_digest = _payload(operator)
                if (
                    operator_digest != operator_row["payload_sha256"]
                    or operator != evidence.operator
                    or operator.state != "ARMED"
                    or operator.arm_nonce != arm.nonce
                    or operator.arm_request_sha256 != arm_digest
                    or operator.expires_at is None
                    or operator.expires_at <= db_now
                ):
                    raise ProductionStateError("current operator command changed before reservation")

                existing = await connection.fetchrow(
                    "SELECT * FROM kairos_production_state_v1.risk_reservations "
                    "WHERE account_sha256=$1 AND effect_id=$2",
                    account_digest,
                    risk.effect_id,
                )
                if existing is not None:
                    if (
                        existing["context_sha256"] != context_digest
                        or existing["owner_arm_sha256"] != arm_digest
                        or existing["account_sha256"] != account_digest
                        or existing["signing_request_id"] != request.request_id
                        or existing["decision_id"] != risk.decision_id
                        or existing["risk_usd"] != risk_amount
                        or existing["notional_usd"] != notional
                        or existing["account_equity_usd"] != risk.account_equity_usd
                        or existing["daily_realized_loss_usd"] != risk.daily_realized_loss_usd
                        or existing["aggregate_open_risk_usd"] != risk.aggregate_open_risk_usd
                        or existing["aggregate_open_notional_usd"] != risk.aggregate_open_notional_usd
                        or existing["dollar_cap"] != arm.dollar_cap
                        or existing["daily_stop_loss_usd"] != arm.daily_stop_loss_usd
                        or existing["evidence_sha256"] != evidence_digest
                        or existing["request_sha256"] != request_digest
                    ):
                        raise ProductionStateError("risk reservation effect identity was rebound")
                    return
                prior_request = await connection.fetchval(
                    "SELECT 1 FROM kairos_production_state_v1.risk_reservations "
                    "WHERE account_sha256=$1 AND signing_request_id=$2",
                    account_digest,
                    request.request_id,
                )
                if prior_request is not None:
                    raise ProductionStateError("signing request already reserves a different effect")

                if self.state_schema_version == ACCOUNTING_STATE_SCHEMA_VERSION:
                    from .production_accounting import inspect_accounting_runtime

                    await inspect_accounting_runtime(connection, state_source=self)
                totals = await connection.fetchrow(
                    _reservation_totals_query(self.state_schema_version),
                    account_digest,
                )
                reserved_risk = Decimal(totals["risk_usd"])
                reserved_notional = Decimal(totals["notional_usd"])
                base_risk = max(
                    risk.aggregate_open_risk_usd,
                    Decimal(totals["base_risk"] or 0),
                )
                base_notional = max(
                    risk.aggregate_open_notional_usd,
                    Decimal(totals["base_notional"] or 0),
                )
                daily_realized = max(
                    risk.daily_realized_loss_usd,
                    Decimal(totals["daily_realized"] or 0),
                )
                if self.state_schema_version == ACCOUNTING_STATE_SCHEMA_VERSION:
                    # Deliberately no daily/window reset or profit offset. The
                    # historical snapshot floor can overlap this charge; that
                    # over-count is conservative until a qualified daily ledger.
                    daily_realized += Decimal(totals["realized_charge"])
                account_equity = min(
                    risk.account_equity_usd,
                    Decimal(totals["account_equity"] or risk.account_equity_usd),
                )
                dollar_limit = min(
                    arm.dollar_cap,
                    Decimal(totals["dollar_cap"] or arm.dollar_cap),
                )
                daily_limit = min(
                    arm.daily_stop_loss_usd,
                    Decimal(totals["daily_stop"] or arm.daily_stop_loss_usd),
                )
                next_risk = base_risk + reserved_risk + risk_amount
                next_notional = base_notional + reserved_notional + notional
                next_daily_loss = daily_realized + reserved_risk + risk_amount
                if (
                    risk.leverage != 1
                    or risk_amount > dollar_limit
                    or risk_amount > account_equity * Decimal("0.0025")
                    or next_risk > account_equity * Decimal("0.01")
                    or next_daily_loss > daily_limit
                    or next_notional > dollar_limit
                ):
                    raise ProductionStateError(
                        "account risk reservation exceeds the current exact-decimal cap"
                    )
                await connection.execute(
                    "INSERT INTO kairos_production_state_v1.risk_reservations "
                    "(context_sha256,account_sha256,effect_id,signing_request_id,decision_id,"
                    "owner_arm_sha256,observed_at,risk_usd,notional_usd,account_equity_usd,"
                    "daily_realized_loss_usd,aggregate_open_risk_usd,aggregate_open_notional_usd,"
                    "dollar_cap,daily_stop_loss_usd,evidence_sha256,request_sha256) "
                    "VALUES($1,$2,$3,$4,$5,$6,$7,$8::numeric,$9::numeric,$10::numeric,$11::numeric,"
                    "$12::numeric,$13::numeric,$14::numeric,$15::numeric,$16,$17)",
                    context_digest,
                    account_digest,
                    risk.effect_id,
                    request.request_id,
                    risk.decision_id,
                    arm_digest,
                    risk.observed_at,
                    _decimal_text(risk_amount),
                    _decimal_text(notional),
                    _decimal_text(risk.account_equity_usd),
                    _decimal_text(risk.daily_realized_loss_usd),
                    _decimal_text(risk.aggregate_open_risk_usd),
                    _decimal_text(risk.aggregate_open_notional_usd),
                    _decimal_text(arm.dollar_cap),
                    _decimal_text(arm.daily_stop_loss_usd),
                    evidence_digest,
                    request_digest,
                )

            await self._write(reserve)
        except ProductionStateError:
            raise
        except Exception:
            raise ProductionStateError(
                "account risk reservation outcome unresolved; do not retry blindly"
            ) from None

    async def _inspect_writer_contract(
        self, connection: asyncpg.Connection, identity: asyncpg.Record
    ) -> None:
        protected = tuple(identity[key] for key in ("owner_role", "runtime_role", *_WRITER_TABLES))
        for role_field, writer_role in ((key, identity[key]) for key in _WRITER_TABLES):
            await _check_role_isolated(connection, writer_role, protected)
            allowed = _WRITER_TABLES[role_field]
            for table in _TABLES:
                name = f"{SCHEMA}.{table}"
                has_insert = await connection.fetchval(
                    "SELECT has_table_privilege($1,$2,'INSERT')", writer_role, name
                )
                if not has_insert:
                    if table in allowed:
                        raise ProductionStateError("production state writer privilege is absent")
                elif table not in allowed:
                    raise ProductionStateError("production state writer crosses its least-privilege boundary")
                for privilege in ("UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"):
                    if await connection.fetchval(
                        "SELECT has_table_privilege($1,$2,$3)", writer_role, name, privilege
                    ):
                        raise ProductionStateError("production state writer has excessive table privileges")
                has_select = await connection.fetchval(
                    "SELECT has_table_privilege($1,$2,'SELECT')", writer_role, name
                )
                expected_select = table in _WRITER_SELECT_TABLES.get(role_field, frozenset())
                if has_select != expected_select:
                    raise ProductionStateError("production state writer SELECT privilege mismatch")
            if await connection.fetchval("SELECT has_schema_privilege($1,$2,'CREATE')", writer_role, SCHEMA):
                raise ProductionStateError("production state writer can modify its schema")

    async def _read_snapshot(
        self,
        connection: asyncpg.Connection,
        *,
        request: ManagedSigningRequestV1,
        message: dict[str, Any],
        exit_operation: bool,
        now: datetime,
    ) -> ProductionSigningEvidenceV1:
        request_digest = _digest(request.manual_request_sha256)
        arm_row = await connection.fetchrow(
            "SELECT * FROM kairos_production_state_v1.owner_arms "
            "WHERE context_sha256=$1 AND request_sha256=$2",
            self.context_sha256,
            request_digest,
        )
        arm_data = self._verified_payload(arm_row, SignedManualArmRequestV1, "owner arm")
        owner_arm = arm_data
        if owner_arm.request.context != self.context or canonical_digest(owner_arm.request) != request_digest:
            raise ProductionStateError("stored owner arm context/request binding mismatch")
        if (
            arm_row["owner_identity"] != owner_arm.request.owner_identity
            or arm_row["nonce"] != owner_arm.request.nonce
            or arm_row["observed_at"] != owner_arm.request.created_at
        ):
            raise ProductionStateError("stored owner arm identity mismatch")

        nonce_row = await connection.fetchrow(
            "SELECT * FROM kairos_production_evidence_v1.claims "
            "WHERE claim_kind='MANUAL_NONCE' AND namespace=$1 AND identity=$2",
            owner_arm.request.owner_identity,
            owner_arm.request.nonce,
        )
        if nonce_row is None:
            raise ProductionStateError("accepted owner nonce claim is absent")
        owner_claim = AcceptedManualNonceV1(
            owner_identity=nonce_row["namespace"],
            nonce=nonce_row["identity"],
            request_sha256=nonce_row["request_sha256"],
            context_sha256=nonce_row["context_sha256"],
            database_uuid=self.database_uuid,
            claimed_at=nonce_row["claimed_at"].astimezone(UTC),
        )
        if nonce_row["context_sha256"] != canonical_digest(self.context):
            raise ProductionStateError("accepted owner nonce belongs to another context")

        operator_row = await connection.fetchrow(
            "SELECT * FROM kairos_production_state_v1.operator_observations WHERE context_sha256=$1 "
            "ORDER BY observed_at DESC,inserted_at DESC LIMIT 2",
            self.context_sha256,
        )
        operator: LiveOperatorStateV1 | None = None
        if operator_row is not None:
            if (
                await connection.fetchval(
                    "SELECT count(*) FROM kairos_production_state_v1.operator_observations "
                    "WHERE context_sha256=$1 AND observed_at=$2",
                    self.context_sha256,
                    operator_row["observed_at"],
                )
                != 1
            ):
                raise ProductionStateError("latest operator observation is ambiguous")
            operator_data = self._verified_payload(operator_row, LiveOperatorStateV1, "operator observation")
            operator = operator_data
            if (
                operator.context != self.context
                or operator.version != operator_row["version"]
                or operator.observed_at != operator_row["observed_at"]
            ):
                raise ProductionStateError("operator observation scope/version mismatch")

        risk_row = await connection.fetchrow(
            "SELECT * FROM kairos_production_state_v1.risk_decisions "
            "WHERE context_sha256=$1 AND signing_request_id=$2",
            self.context_sha256,
            request.request_id,
        )
        risk_data = self._verified_payload(risk_row, RiskGeometryV1, "risk decision")
        risk = risk_data
        if (
            risk.context != self.context
            or risk.signing_request_id != request.request_id
            or risk.observed_at != risk_row["observed_at"]
            or risk.valid_until != risk_row["valid_until"]
        ):
            raise ProductionStateError("risk decision scope/request mismatch")
        if risk.decision_id != risk_row["decision_id"]:
            raise ProductionStateError("risk decision identity mismatch")

        exposure: ExposureSnapshotV1 | None = None
        if exit_operation:
            instrument = message.get("instrument")
            if type(instrument) is not str:
                raise ProductionStateError("exit order instrument is invalid")
            exposure_row = await connection.fetchrow(
                "SELECT * FROM kairos_production_state_v1.exposure_observations "
                "WHERE context_sha256=$1 AND instrument=$2 "
                "ORDER BY observed_at DESC,inserted_at DESC LIMIT 1",
                self.context_sha256,
                instrument,
            )
            if exposure_row is not None:
                if (
                    await connection.fetchval(
                        "SELECT count(*) FROM kairos_production_state_v1.exposure_observations "
                        "WHERE context_sha256=$1 AND instrument=$2 AND observed_at=$3",
                        self.context_sha256,
                        instrument,
                        exposure_row["observed_at"],
                    )
                    != 1
                ):
                    raise ProductionStateError("latest exposure observation is ambiguous")
                exposure_data = self._verified_payload(
                    exposure_row, ExposureSnapshotV1, "exposure observation"
                )
                exposure = exposure_data
                if (
                    exposure.context != self.context
                    or exposure.instrument != instrument
                    or exposure.observed_at != exposure_row["observed_at"]
                    or exposure.valid_until != exposure_row["valid_until"]
                ):
                    raise ProductionStateError("exposure observation scope/instrument mismatch")

        times = [owner_claim.claimed_at, risk.observed_at]
        if operator is not None:
            times.append(operator.observed_at)
        if exposure is not None:
            times.append(exposure.observed_at)
        # resolved_at reflects a server clock read inside the same consistent
        # transaction; each component retains its own observed_at as well.
        resolved_at = (await connection.fetchval("SELECT clock_timestamp()")).astimezone(UTC)
        if resolved_at < max(times):
            raise ProductionStateError("source record is future-dated")
        return ProductionSigningEvidenceV1(
            owner_arm=owner_arm,
            owner_nonce_claim=owner_claim,
            operator=operator,
            risk=risk,
            exposure=exposure,
            resolved_at=resolved_at,
        )

    @staticmethod
    def _verified_payload(row: asyncpg.Record | None, model_type: Any, label: str) -> Any:
        if row is None:
            raise ProductionStateError(f"authoritative {label} is absent")
        model = _parse_json_model(row["payload"], model_type, label)
        _, digest = _payload(model)
        if not _DIGEST_PATTERN.fullmatch(row["payload_sha256"]) or digest != row["payload_sha256"]:
            raise ProductionStateError(f"authoritative {label} payload integrity mismatch")
        return model
