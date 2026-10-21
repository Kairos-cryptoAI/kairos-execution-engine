"""Async read-only production signing evidence source and role-scoped appenders.

This module is a persistence boundary, not a LIVE enablement switch. Provisioning
is explicit and owner-only. Runtime reads require the exact isolated evidence
database and claims identity; upstream writers use separate PostgreSQL roles
for operator/owner-arm, risk and exposure records.
Risk decisions remain unqualified until an independent risk service atomically
reserves account-scoped pending risk/notional; this store does not compute or
invent those totals.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import asyncpg  # type: ignore[import-untyped]  # Upstream ships no typing marker/stubs.

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
_ROLE_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,62}\Z")
_ID_PATTERN = re.compile(r"[A-Za-z0-9_.:-]{1,160}\Z")
_DIGEST_PATTERN = re.compile(r"[a-f0-9]{64}\Z")

DDL = """
CREATE SCHEMA kairos_production_state_v1;
REVOKE ALL ON SCHEMA kairos_production_state_v1 FROM PUBLIC;
CREATE TABLE kairos_production_state_v1.identity (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 database_uuid uuid NOT NULL, policy_namespace text NOT NULL,
 context_sha256 text NOT NULL CHECK(context_sha256 ~ '^[a-f0-9]{64}$'),
 schema_version integer NOT NULL CHECK(schema_version=1),
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
      AND arm.owner_identity=NEW.payload#>>'{request,owner_identity}'
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

_TABLES = ("identity", "owner_arms", "operator_observations", "risk_decisions", "exposure_observations")
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


def _payload(model: Any) -> tuple[dict[str, Any], str]:
    data = model.model_dump(mode="json")
    encoded = json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return data, hashlib.sha256(encoded).hexdigest()


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
) -> None:
    """Explicit owner-only schema provisioning; never called by a runtime path.

    Login roles must already exist and be mutually isolated. The caller must
    provision a fresh, exact-prefix database; this function creates no database
    and refuses an existing schema.
    """
    expected_database = _database_name(expected_database)
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
        await connection.execute(DDL)
        await connection.execute(
            f"INSERT INTO {SCHEMA}.identity VALUES(true,$1,$2,$3,1,$4,$5,$6,$7,$8)",
            database_uuid,
            policy_namespace,
            canonical_digest(context),
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

    async def inspect(self, connection: asyncpg.Connection) -> asyncpg.Record:
        actual = await connection.fetchrow("SELECT current_database() AS db,current_user AS role")
        if actual is None or actual["db"] != self.expected_database or actual["role"] != self.expected_role:
            raise ProductionStateError("production state database/role mismatch")
        identity = await connection.fetchrow(f"SELECT * FROM {SCHEMA}.identity WHERE singleton=true")
        expected_columns = {
            "database_uuid": self.database_uuid,
            "policy_namespace": self.policy_namespace,
            "context_sha256": self.context_sha256,
            "schema_version": 1,
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

        allowed_tables = _WRITER_TABLES.get(self.role_field, frozenset())
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
        except Exception:
            raise ProductionStateError(
                "production state append outcome unavailable; do not retry blindly"
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
            await connection.execute(
                f"INSERT INTO {SCHEMA}.owner_arms "
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
                f"operator:{self.context_sha256}",
            )
            latest = await connection.fetchrow(
                f"SELECT version,observed_at,payload FROM {SCHEMA}.operator_observations "
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
                prior_payload = latest["payload"]
                if isinstance(prior_payload, str):
                    prior_payload = json.loads(prior_payload)
                prior = LiveOperatorStateV1.model_validate(prior_payload)
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
                f"INSERT INTO {SCHEMA}.operator_observations "
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
            await connection.execute(
                f"INSERT INTO {SCHEMA}.risk_decisions "
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
                f"SELECT observed_at FROM {SCHEMA}.exposure_observations "
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
                f"INSERT INTO {SCHEMA}.exposure_observations "
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
        )
        self.runtime_role = _role(runtime_role)
        self.max_snapshot_age = max_snapshot_age

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
            if evidence.resolved_at > now or now - evidence.resolved_at > self.max_snapshot_age:
                raise ProductionStateError("production signing state snapshot is stale or future-dated")
            return evidence
        except (ProductionStateError, ProductionClaimError):
            raise
        except Exception:
            raise ProductionStateError("authoritative production signing state is unavailable") from None

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
            f"SELECT * FROM {SCHEMA}.owner_arms WHERE context_sha256=$1 AND request_sha256=$2",
            self.context_sha256,
            request_digest,
        )
        arm_data = self._verified_payload(arm_row, SignedManualArmRequestV1, "owner arm")
        owner_arm = SignedManualArmRequestV1.model_validate(arm_data)
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
            f"SELECT * FROM {SCHEMA}.operator_observations WHERE context_sha256=$1 "
            "ORDER BY observed_at DESC,inserted_at DESC LIMIT 2",
            self.context_sha256,
        )
        operator: LiveOperatorStateV1 | None = None
        if operator_row is not None:
            if (
                await connection.fetchval(
                    f"SELECT count(*) FROM {SCHEMA}.operator_observations "
                    "WHERE context_sha256=$1 AND observed_at=$2",
                    self.context_sha256,
                    operator_row["observed_at"],
                )
                != 1
            ):
                raise ProductionStateError("latest operator observation is ambiguous")
            operator_data = self._verified_payload(operator_row, LiveOperatorStateV1, "operator observation")
            operator = LiveOperatorStateV1.model_validate(operator_data)
            if operator.context != self.context or operator.version != operator_row["version"]:
                raise ProductionStateError("operator observation scope/version mismatch")

        risk_row = await connection.fetchrow(
            f"SELECT * FROM {SCHEMA}.risk_decisions WHERE context_sha256=$1 AND signing_request_id=$2",
            self.context_sha256,
            request.request_id,
        )
        risk_data = self._verified_payload(risk_row, RiskGeometryV1, "risk decision")
        risk = RiskGeometryV1.model_validate(risk_data)
        if risk.context != self.context or risk.signing_request_id != request.request_id:
            raise ProductionStateError("risk decision scope/request mismatch")
        if risk.decision_id != risk_row["decision_id"]:
            raise ProductionStateError("risk decision identity mismatch")

        exposure: ExposureSnapshotV1 | None = None
        if exit_operation:
            instrument = message.get("instrument")
            if type(instrument) is not str:
                raise ProductionStateError("exit order instrument is invalid")
            exposure_row = await connection.fetchrow(
                f"SELECT * FROM {SCHEMA}.exposure_observations WHERE context_sha256=$1 AND instrument=$2 "
                "ORDER BY observed_at DESC,inserted_at DESC LIMIT 1",
                self.context_sha256,
                instrument,
            )
            if exposure_row is not None:
                if (
                    await connection.fetchval(
                        f"SELECT count(*) FROM {SCHEMA}.exposure_observations "
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
                exposure = ExposureSnapshotV1.model_validate(exposure_data)
                if exposure.context != self.context or exposure.instrument != instrument:
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
    def _verified_payload(row: asyncpg.Record | None, model_type: Any, label: str) -> dict[str, Any]:
        if row is None:
            raise ProductionStateError(f"authoritative {label} is absent")
        payload = row["payload"]
        if isinstance(payload, str):
            payload = json.loads(payload)
        if not isinstance(payload, dict):
            raise ProductionStateError(f"authoritative {label} payload is invalid")
        model = model_type.model_validate(payload)
        _, digest = _payload(model)
        if not _DIGEST_PATTERN.fullmatch(row["payload_sha256"]) or digest != row["payload_sha256"]:
            raise ProductionStateError(f"authoritative {label} payload integrity mismatch")
        return model.model_dump(mode="json")
