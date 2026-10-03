"""Opt-in isolated PostgreSQL claims; never primary migrations or auto-provisioning.

Claim COMMIT precedes any external signing callback. Unknown results cannot be
reclaimed, released, expired or deleted by the runtime role. No credentials are
loaded here, and connect/inspect performs no DDL.
"""

from __future__ import annotations

import asyncio
import re
from contextlib import asynccontextmanager
from typing import Literal
from uuid import UUID

import asyncpg  # type: ignore[import-untyped]  # Upstream ships no typing marker/stubs.

from .production_readiness import ProductionContextV1, canonical_digest

SCHEMA = "kairos_production_evidence_v1"
DDL = """
CREATE SCHEMA kairos_production_evidence_v1;
REVOKE ALL ON SCHEMA kairos_production_evidence_v1 FROM PUBLIC;
CREATE TABLE kairos_production_evidence_v1.identity (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 database_uuid uuid NOT NULL, policy_namespace text NOT NULL,
 schema_version integer NOT NULL CHECK(schema_version=1),
 owner_role name NOT NULL, runtime_role name NOT NULL
);
CREATE TABLE kairos_production_evidence_v1.claims (
 claim_kind text NOT NULL CHECK(claim_kind IN ('MANUAL_NONCE','TYPED_SIGNING')),
 namespace text NOT NULL CHECK(length(namespace) BETWEEN 1 AND 160),
 identity text NOT NULL CHECK(length(identity) BETWEEN 1 AND 160),
 request_sha256 text NOT NULL CHECK(request_sha256 ~ '^[a-f0-9]{64}$'),
 context_sha256 text NOT NULL CHECK(context_sha256 ~ '^[a-f0-9]{64}$'),
 claimed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(claim_kind,namespace,identity),
 UNIQUE(claim_kind,namespace,identity,request_sha256)
);
CREATE TABLE kairos_production_evidence_v1.terminals (
 claim_kind text NOT NULL CHECK(claim_kind='TYPED_SIGNING'),
 namespace text NOT NULL, identity text NOT NULL,
 request_sha256 text NOT NULL CHECK(request_sha256 ~ '^[a-f0-9]{64}$'),
 terminal_status text NOT NULL CHECK(terminal_status IN ('COMPLETED','UNRESOLVED')),
 result_sha256 text CHECK(result_sha256 ~ '^[a-f0-9]{64}$'),
 observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(claim_kind,namespace,identity),
 FOREIGN KEY(claim_kind,namespace,identity,request_sha256)
  REFERENCES kairos_production_evidence_v1.claims(claim_kind,namespace,identity,request_sha256),
 CHECK((terminal_status='COMPLETED' AND result_sha256 IS NOT NULL)
    OR (terminal_status='UNRESOLVED' AND result_sha256 IS NULL))
);
CREATE FUNCTION kairos_production_evidence_v1.reject_mutation() RETURNS trigger
 LANGUAGE plpgsql SET search_path=pg_catalog AS $$
 BEGIN RAISE EXCEPTION 'immutable production evidence record'; END $$;
CREATE TRIGGER identity_immutable BEFORE UPDATE OR DELETE ON kairos_production_evidence_v1.identity
 FOR EACH ROW EXECUTE FUNCTION kairos_production_evidence_v1.reject_mutation();
CREATE TRIGGER claims_immutable BEFORE UPDATE OR DELETE ON kairos_production_evidence_v1.claims
 FOR EACH ROW EXECUTE FUNCTION kairos_production_evidence_v1.reject_mutation();
CREATE TRIGGER terminals_immutable BEFORE UPDATE OR DELETE ON kairos_production_evidence_v1.terminals
 FOR EACH ROW EXECUTE FUNCTION kairos_production_evidence_v1.reject_mutation();
REVOKE ALL ON ALL TABLES IN SCHEMA kairos_production_evidence_v1 FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA kairos_production_evidence_v1 FROM PUBLIC;
"""


class ProductionClaimError(PermissionError):
    """Sanitized identity, ownership or claim conflict; never include a DSN."""


def _identity(value: str) -> str:
    if type(value) is not str or re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", value) is None:
        raise ProductionClaimError("invalid production evidence identity")
    return value


def _digest(value: str) -> str:
    if type(value) is not str or re.fullmatch(r"[a-f0-9]{64}", value) is None:
        raise ProductionClaimError("invalid production evidence digest")
    return value


def _database_name(value: str) -> str:
    # Explicit positive namespace excludes kairos, postgres, historical runtime
    # clones, and every simulator/primary migration profile.
    if type(value) is not str or re.fullmatch(r"kairos_production_evidence_[a-z0-9_]{12,80}", value) is None:
        raise ProductionClaimError("an exact isolated production-evidence database is required")
    return value


async def provision_isolated_schema(
    connection: asyncpg.Connection,
    *,
    expected_database: str,
    database_uuid: UUID,
    policy_namespace: str,
    owner_role: str,
    runtime_role: str,
) -> None:
    """Explicit owner-only provisioning on a new isolated DB; no CREATE DATABASE.

    Caller must already provision separate login roles. This function is never
    invoked by runtime connect, settings, service, signer or any default factory.
    Existing schema is an error, not a migration/retry opportunity.
    """
    expected_database = _database_name(expected_database)
    owner_role, runtime_role = _identity(owner_role), _identity(runtime_role)
    policy_namespace = _identity(policy_namespace)
    if owner_role == runtime_role or not isinstance(database_uuid, UUID):
        raise ProductionClaimError("separate reviewed owner/runtime identities are required")
    actual = await connection.fetchrow("SELECT current_database() AS db,current_user AS role")
    if actual["db"] != expected_database or actual["role"] != owner_role:
        raise ProductionClaimError("isolated schema owner/database mismatch")
    runtime = await connection.fetchrow(
        "SELECT rolsuper,rolcreaterole,rolcreatedb,rolreplication,rolbypassrls "
        "FROM pg_roles WHERE rolname=$1",
        runtime_role,
    )
    if (
        runtime is None
        or any(runtime.values())
        or await connection.fetchval("SELECT pg_has_role($1,$2,'MEMBER')", runtime_role, owner_role)
    ):
        raise ProductionClaimError("runtime role has unsafe owner or administrative privileges")
    if await connection.fetchval("SELECT to_regnamespace($1)", SCHEMA) is not None:
        raise ProductionClaimError("production evidence schema already exists; do not re-provision")
    # Identifiers pass a stricter SQL name rule before interpolation. Values are
    # parameters. No transaction is held over a network/custody operation.
    if any(re.fullmatch(r"[a-z][a-z0-9_]{0,62}", role) is None for role in (owner_role, runtime_role)):
        raise ProductionClaimError("reviewed PostgreSQL role names are required")
    async with connection.transaction():
        await connection.execute(DDL)
        await connection.execute(
            "INSERT INTO kairos_production_evidence_v1.identity VALUES(true,$1,$2,1,$3,$4)",
            database_uuid,
            policy_namespace,
            owner_role,
            runtime_role,
        )
        await connection.execute(f'GRANT USAGE ON SCHEMA {SCHEMA} TO "{runtime_role}"')
        await connection.execute(f'GRANT SELECT ON ALL TABLES IN SCHEMA {SCHEMA} TO "{runtime_role}"')
        await connection.execute(f'GRANT INSERT ON {SCHEMA}.claims,{SCHEMA}.terminals TO "{runtime_role}"')


class PostgresProductionClaims:
    """Insert-only runtime adapter bound to one independently provisioned DB UUID."""

    def __init__(
        self,
        pool: asyncpg.Pool,
        *,
        expected_database: str,
        database_uuid: UUID,
        policy_namespace: str,
        runtime_role: str,
        context: ProductionContextV1,
    ):
        self.pool = pool
        self.expected_database = _database_name(expected_database)
        if not isinstance(database_uuid, UUID):
            raise ProductionClaimError("an explicit isolated database UUID is required")
        self.database_uuid = database_uuid
        self.policy_namespace = _identity(policy_namespace)
        self.runtime_role = _identity(runtime_role)
        self.context_sha256 = canonical_digest(ProductionContextV1.model_validate(context))

    async def inspect(self, connection: asyncpg.Connection) -> None:
        actual = await connection.fetchrow("SELECT current_database() AS db,current_user AS role")
        if actual["db"] != self.expected_database or actual["role"] != self.runtime_role:
            raise ProductionClaimError("production evidence database/runtime role mismatch")
        identity = await connection.fetchrow(
            "SELECT * FROM kairos_production_evidence_v1.identity WHERE singleton=true"
        )
        if identity is None or (
            identity["database_uuid"] != self.database_uuid
            or identity["schema_version"] != 1
            or identity["policy_namespace"] != self.policy_namespace
            or identity["runtime_role"] != self.runtime_role
            or identity["owner_role"] == self.runtime_role
        ):
            raise ProductionClaimError("production evidence UUID/namespace/schema mismatch")
        schema_owner = await connection.fetchval(
            "SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname=$1", SCHEMA
        )
        if schema_owner != identity["owner_role"]:
            raise ProductionClaimError("production evidence schema ownership mismatch")
        role = await connection.fetchrow(
            "SELECT rolsuper,rolcreaterole,rolcreatedb,rolreplication,rolbypassrls "
            "FROM pg_roles WHERE rolname=current_user"
        )
        if (
            role is None
            or any(role.values())
            or await connection.fetchval(
                "SELECT pg_has_role(current_user,$1,'MEMBER')", identity["owner_role"]
            )
        ):
            raise ProductionClaimError("production claim runtime has unsafe privileges")
        for table in ("identity", "claims", "terminals"):
            name = f"{SCHEMA}.{table}"
            table_owner = await connection.fetchval(
                "SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid=to_regclass($1)", name
            )
            if table_owner != identity["owner_role"]:
                raise ProductionClaimError("production evidence table ownership mismatch")
            if not await connection.fetchval("SELECT has_table_privilege(current_user,$1,'SELECT')", name):
                raise ProductionClaimError("production claim read privilege is absent")
            if await connection.fetchval(
                "SELECT has_table_privilege(current_user,$1,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')",
                name,
            ):
                raise ProductionClaimError("production claim runtime can alter immutable evidence")
            insert = await connection.fetchval("SELECT has_table_privilege(current_user,$1,'INSERT')", name)
            if insert != (table != "identity"):
                raise ProductionClaimError("production claim runtime insert privilege mismatch")
        if await connection.fetchval("SELECT has_schema_privilege(current_user,$1,'CREATE')", SCHEMA):
            raise ProductionClaimError("production claim runtime can modify its schema")

    @asynccontextmanager
    async def _connection(self):
        # Covers pool queue, identity inspection and short transaction/COMMIT.
        # Timeout after a server commit is UNKNOWN, never permission to retry.
        async with asyncio.timeout(10):
            async with self.pool.acquire() as connection:
                await self.inspect(connection)
                yield connection

    async def claim(
        self,
        kind: Literal["MANUAL_NONCE", "TYPED_SIGNING"],
        namespace: str,
        identity: str,
        request_sha256: str,
    ) -> bool:
        namespace, identity = _identity(namespace), _identity(identity)
        request_sha256 = _digest(request_sha256)
        if kind not in {"MANUAL_NONCE", "TYPED_SIGNING"}:
            raise ProductionClaimError("unsupported claim kind")
        try:
            async with self._connection() as connection:
                async with connection.transaction():
                    await connection.execute("SET LOCAL statement_timeout='5s'")
                    row = await connection.fetchrow(
                        "INSERT INTO kairos_production_evidence_v1.claims VALUES($1,$2,$3,$4,$5,DEFAULT) "
                        "ON CONFLICT DO NOTHING RETURNING request_sha256",
                        kind,
                        namespace,
                        identity,
                        request_sha256,
                        self.context_sha256,
                    )
                    if row is None:
                        prior = await connection.fetchrow(
                            "SELECT request_sha256,context_sha256 FROM kairos_production_evidence_v1.claims "
                            "WHERE claim_kind=$1 AND namespace=$2 AND identity=$3",
                            kind,
                            namespace,
                            identity,
                        )
                        if (
                            prior is None
                            or prior["request_sha256"] != request_sha256
                            or (prior["context_sha256"] != self.context_sha256)
                        ):
                            raise ProductionClaimError("one-use claim identity was rebound")
                # Return only after COMMIT acknowledgment. Lost acknowledgment
                # raises; caller must not invoke an external signing callback.
                return row is not None
        except ProductionClaimError:
            raise
        except Exception:
            raise ProductionClaimError("production claim outcome unresolved; do not retry") from None

    async def consume_once_async(self, *, owner_identity: str, nonce: str, request_sha256: str) -> bool:
        return await self.claim("MANUAL_NONCE", owner_identity, nonce, request_sha256)

    async def claim_once_async(self, *, custody_reference: str, request_id: str, request_sha256: str) -> bool:
        return await self.claim("TYPED_SIGNING", custody_reference, request_id, request_sha256)

    async def finish_signing_async(
        self,
        *,
        custody_reference: str,
        request_id: str,
        request_sha256: str,
        terminal_status: Literal["COMPLETED", "UNRESOLVED"],
        result_sha256: str | None,
    ) -> None:
        custody_reference, request_id = _identity(custody_reference), _identity(request_id)
        request_sha256 = _digest(request_sha256)
        if (
            (terminal_status == "COMPLETED" and result_sha256 is None)
            or (terminal_status == "UNRESOLVED" and result_sha256 is not None)
            or terminal_status not in {"COMPLETED", "UNRESOLVED"}
        ):
            raise ProductionClaimError("invalid signing terminal evidence")
        if result_sha256 is not None:
            result_sha256 = _digest(result_sha256)
        try:
            async with self._connection() as connection:
                async with connection.transaction():
                    await connection.execute("SET LOCAL statement_timeout='5s'")
                    prior = await connection.fetchrow(
                        "SELECT * FROM kairos_production_evidence_v1.claims WHERE claim_kind='TYPED_SIGNING' "
                        "AND namespace=$1 AND identity=$2",
                        custody_reference,
                        request_id,
                    )
                    if (
                        prior is None
                        or prior["request_sha256"] != request_sha256
                        or (prior["context_sha256"] != self.context_sha256)
                    ):
                        raise ProductionClaimError("signing terminal does not resolve its exact claim")
                    await connection.execute(
                        "INSERT INTO kairos_production_evidence_v1.terminals "
                        "VALUES('TYPED_SIGNING',$1,$2,$3,$4,$5,DEFAULT) "
                        "ON CONFLICT DO NOTHING",
                        custody_reference,
                        request_id,
                        request_sha256,
                        terminal_status,
                        result_sha256,
                    )
                    terminal = await connection.fetchrow(
                        "SELECT * FROM kairos_production_evidence_v1.terminals "
                        "WHERE claim_kind='TYPED_SIGNING' "
                        "AND namespace=$1 AND identity=$2",
                        custody_reference,
                        request_id,
                    )
                    if (
                        terminal["terminal_status"] != terminal_status
                        or terminal["result_sha256"] != result_sha256
                    ):
                        raise ProductionClaimError("immutable signing terminal conflict")
        except ProductionClaimError:
            raise
        except Exception:
            raise ProductionClaimError("signing terminal outcome unresolved; do not retry") from None

    async def load_claim(self, *, kind: str, namespace: str, identity: str) -> dict | None:
        namespace, identity = _identity(namespace), _identity(identity)
        if kind not in {"MANUAL_NONCE", "TYPED_SIGNING"}:
            raise ProductionClaimError("unsupported claim kind")
        try:
            async with self._connection() as connection:
                row = await connection.fetchrow(
                    "SELECT c.*,t.terminal_status,t.result_sha256 "
                    "FROM kairos_production_evidence_v1.claims c "
                    "LEFT JOIN kairos_production_evidence_v1.terminals t "
                    "USING(claim_kind,namespace,identity) "
                    "WHERE claim_kind=$1 AND namespace=$2 AND identity=$3",
                    kind,
                    namespace,
                    identity,
                )
                if row is not None and row["context_sha256"] != self.context_sha256:
                    raise ProductionClaimError("production claim observation scope mismatch")
                return dict(row) if row is not None else None
        except ProductionClaimError:
            raise
        except Exception:
            raise ProductionClaimError("production claim observation unavailable") from None
