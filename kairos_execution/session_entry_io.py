"""Experimental account-wide write-ahead journal for one entry's I/O.

No provisioning, reconciler, venue authority, or qualified account source is
introduced. Once a record exists, every different entry stays blocked. Only
the exact proven-complete signing result may advance to one wire attempt.
There is intentionally no automatic release, including after a venue ACK.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from uuid import UUID

from .production_claims import PostgresProductionClaims, _digest, _identity
from .production_state import (
    AsyncPostgresProductionSigningStateSource,
    _account_reservation_lock,
    _account_scope_sha256,
)

DDL = """
CREATE SCHEMA kairos_session_entry_io_v1;
REVOKE ALL ON SCHEMA kairos_session_entry_io_v1 FROM PUBLIC;
CREATE TABLE kairos_session_entry_io_v1.events (
 account_sha256 text NOT NULL CHECK(account_sha256 ~ '^[a-f0-9]{64}$'),
 session_id uuid NOT NULL,
 sequence bigint NOT NULL,
 phase text NOT NULL CHECK(phase IN ('SIGN_STARTED','SIGNED','WIRE_STARTED')),
 custody_reference text NOT NULL,
 request_id text NOT NULL,
 request_sha256 text NOT NULL CHECK(request_sha256 ~ '^[a-f0-9]{64}$'),
 signature_sha256 text CHECK(signature_sha256 ~ '^[a-f0-9]{64}$'),
 effect_id text,
 wire_sha256 text CHECK(wire_sha256 ~ '^[a-f0-9]{64}$'),
 inserted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(account_sha256,sequence)
);
CREATE FUNCTION kairos_session_entry_io_v1.immutable() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'entry I/O journal is immutable'; END $$;
CREATE TRIGGER immutable_events BEFORE UPDATE OR DELETE OR TRUNCATE
 ON kairos_session_entry_io_v1.events FOR EACH STATEMENT
 EXECUTE FUNCTION kairos_session_entry_io_v1.immutable();
CREATE FUNCTION kairos_session_entry_io_v1.check_append() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE prior kairos_session_entry_io_v1.events%ROWTYPE;
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('risk-reservation:' || NEW.account_sha256,0));
 SELECT * INTO prior FROM kairos_session_entry_io_v1.events
 WHERE account_sha256=NEW.account_sha256 ORDER BY sequence DESC LIMIT 1;
 IF NOT FOUND THEN
  IF NEW.sequence<>1 OR NEW.phase<>'SIGN_STARTED' OR NEW.signature_sha256 IS NOT NULL
   OR NEW.effect_id IS NOT NULL OR NEW.wire_sha256 IS NOT NULL
  THEN RAISE EXCEPTION 'invalid first entry I/O record'; END IF;
 ELSE
  IF NEW.sequence<>prior.sequence+1 OR NEW.session_id<>prior.session_id
   OR NEW.request_id<>prior.request_id OR NEW.request_sha256<>prior.request_sha256
   OR NEW.custody_reference<>prior.custody_reference
  THEN RAISE EXCEPTION 'entry I/O lineage conflict'; END IF;
  IF NOT ((prior.phase='SIGN_STARTED' AND NEW.phase='SIGNED'
           AND NEW.signature_sha256 IS NOT NULL AND NEW.effect_id IS NULL AND NEW.wire_sha256 IS NULL)
      OR (prior.phase='SIGNED' AND NEW.phase='WIRE_STARTED'
           AND NEW.signature_sha256 IS NOT NULL AND NEW.signature_sha256=prior.signature_sha256
           AND NEW.effect_id IS NOT NULL
           AND NEW.wire_sha256 IS NOT NULL))
  THEN RAISE EXCEPTION 'entry I/O already unresolved or phase mismatch'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER check_events BEFORE INSERT ON kairos_session_entry_io_v1.events
 FOR EACH ROW EXECUTE FUNCTION kairos_session_entry_io_v1.check_append();
"""


class SessionEntryIoError(PermissionError):
    """A committed prior entry or unverified operation prevents I/O."""


class PostgresEntryIoJournal:
    def __init__(self, source, claims, *, session_id: UUID, max_age: timedelta) -> None:
        if type(source) is not AsyncPostgresProductionSigningStateSource:
            raise TypeError("exact production state source required")
        if type(claims) is not PostgresProductionClaims:
            raise TypeError("exact production claims required")
        if (
            source.pool is not claims.pool
            or source.database_uuid != claims.database_uuid
            or source.context_sha256 != claims.context_sha256
            or source.expected_database != claims.expected_database
            or source.policy_namespace != claims.policy_namespace
            or source.runtime_role != claims.runtime_role
        ):
            raise ValueError("entry I/O journal source and claims scope differs")
        if not isinstance(session_id, UUID) or session_id.int == 0:
            raise ValueError("explicit nonzero session UUID required")
        if not timedelta(0) < max_age <= timedelta(seconds=5):
            raise ValueError("session observation age must be at most five seconds")
        self.source, self.claims, self.session_id, self.max_age = source, claims, session_id, max_age

    async def _validate_locked(self, connection):
        await self.claims.inspect(connection)
        await connection.fetchval(
            "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
            _account_reservation_lock(self.source.context),
        )
        now = await connection.fetchval("SELECT clock_timestamp()")
        row = await connection.fetchrow(
            "SELECT state,session_id,observed_at FROM kairos_session_loss_v1.events "
            "WHERE account_sha256=$1 ORDER BY sequence DESC LIMIT 1",
            _account_scope_sha256(self.source.context),
        )
        if (
            not isinstance(now, datetime)
            or now.tzinfo is None
            or row is None
            or row["state"] != "ACTIVE"
            or row["session_id"] != self.session_id
            or not isinstance(row["observed_at"], datetime)
            or row["observed_at"].tzinfo is None
            or row["observed_at"] > now
            or now - row["observed_at"] > self.max_age
        ):
            raise SessionEntryIoError("session STOP or fresh evidence unavailable")

    async def _signing_complete(
        self, connection, *, custody_reference, request_id, request_sha, signature_sha
    ):
        row = await connection.fetchrow(
            "SELECT c.context_sha256,t.terminal_status,t.result_sha256 "
            "FROM kairos_production_evidence_v1.claims c "
            "JOIN kairos_production_evidence_v1.terminals t "
            "ON (c.claim_kind,c.namespace,c.identity,c.request_sha256)="
            "(t.claim_kind,t.namespace,t.identity,t.request_sha256) "
            "WHERE c.claim_kind='TYPED_SIGNING' AND c.namespace=$1 AND c.identity=$2 AND c.request_sha256=$3",
            custody_reference,
            request_id,
            request_sha,
        )
        if (
            row is None
            or row["context_sha256"] != self.source.context_sha256
            or row["terminal_status"] != "COMPLETED"
            or row["result_sha256"] != signature_sha
        ):
            raise SessionEntryIoError("completed signing claim is absent or differs")

    async def begin_sign(self, *, custody_reference: str, request_id: str, request_sha: str) -> None:
        custody_reference, request_id, request_sha = (
            _identity(custody_reference),
            _identity(request_id),
            _digest(request_sha),
        )

        async def append(connection):
            await self._validate_locked(connection)
            account = _account_scope_sha256(self.source.context)
            if await connection.fetchval(
                "SELECT EXISTS(SELECT 1 FROM kairos_session_entry_io_v1.events WHERE account_sha256=$1)",
                account,
            ):
                raise SessionEntryIoError("prior account entry I/O awaits reconciliation")
            claim = await connection.fetchrow(
                "SELECT c.context_sha256,t.terminal_status FROM kairos_production_evidence_v1.claims c "
                "LEFT JOIN kairos_production_evidence_v1.terminals t "
                "ON (c.claim_kind,c.namespace,c.identity,c.request_sha256)="
                "(t.claim_kind,t.namespace,t.identity,t.request_sha256) "
                "WHERE c.claim_kind='TYPED_SIGNING' AND c.namespace=$1 AND c.identity=$2 "
                "AND c.request_sha256=$3",
                custody_reference,
                request_id,
                request_sha,
            )
            if (
                claim is None
                or claim["context_sha256"] != self.source.context_sha256
                or claim["terminal_status"] is not None
            ):
                raise SessionEntryIoError("exact pending signing claim is absent")
            await connection.execute(
                "INSERT INTO kairos_session_entry_io_v1.events "
                "(account_sha256,session_id,sequence,phase,custody_reference,request_id,request_sha256) "
                "VALUES($1,$2,1,'SIGN_STARTED',$3,$4,$5)",
                account,
                self.session_id,
                custody_reference,
                request_id,
                request_sha,
            )

        await self.source._write(append)

    async def complete_sign(
        self, *, custody_reference: str, request_id: str, request_sha: str, signature_sha: str
    ) -> None:
        custody_reference, request_id = _identity(custody_reference), _identity(request_id)
        request_sha, signature_sha = _digest(request_sha), _digest(signature_sha)

        async def append(connection):
            await self._validate_locked(connection)
            await self._signing_complete(
                connection,
                custody_reference=custody_reference,
                request_id=request_id,
                request_sha=request_sha,
                signature_sha=signature_sha,
            )
            await connection.execute(
                "INSERT INTO kairos_session_entry_io_v1.events "
                "(account_sha256,session_id,sequence,phase,custody_reference,request_id,"
                "request_sha256,signature_sha256) "
                "VALUES($1,$2,2,'SIGNED',$3,$4,$5,$6)",
                _account_scope_sha256(self.source.context),
                self.session_id,
                custody_reference,
                request_id,
                request_sha,
                signature_sha,
            )

        await self.source._write(append)

    async def begin_wire(
        self,
        *,
        custody_reference: str,
        request_id: str,
        request_sha: str,
        signature_sha: str,
        effect_id: str,
        wire_sha: str,
    ) -> None:
        custody_reference, request_id, effect_id = (
            _identity(custody_reference),
            _identity(request_id),
            _identity(effect_id),
        )
        request_sha, signature_sha, wire_sha = _digest(request_sha), _digest(signature_sha), _digest(wire_sha)

        async def append(connection):
            await self._validate_locked(connection)
            await self._signing_complete(
                connection,
                custody_reference=custody_reference,
                request_id=request_id,
                request_sha=request_sha,
                signature_sha=signature_sha,
            )
            wire_claim = await connection.fetchrow(
                "SELECT c.context_sha256,t.terminal_status FROM kairos_production_evidence_v1.claims c "
                "LEFT JOIN kairos_production_evidence_v1.wire_terminals t "
                "ON (c.claim_kind,c.namespace,c.identity,c.request_sha256)="
                "(t.claim_kind,t.namespace,t.identity,t.request_sha256) "
                "WHERE c.claim_kind='WIRE_DISPATCH' AND c.namespace=$1 AND c.identity=$2 "
                "AND c.request_sha256=$3",
                "wire:" + self.source.context_sha256,
                effect_id,
                wire_sha,
            )
            if (
                wire_claim is None
                or wire_claim["context_sha256"] != self.source.context_sha256
                or wire_claim["terminal_status"] is not None
            ):
                raise SessionEntryIoError("exact pending wire claim is absent")
            await connection.execute(
                "INSERT INTO kairos_session_entry_io_v1.events "
                "(account_sha256,session_id,sequence,phase,custody_reference,request_id,request_sha256,"
                "signature_sha256,effect_id,wire_sha256) VALUES($1,$2,3,'WIRE_STARTED',$3,$4,$5,$6,$7,$8)",
                _account_scope_sha256(self.source.context),
                self.session_id,
                custody_reference,
                request_id,
                request_sha,
                signature_sha,
                effect_id,
                wire_sha,
            )

        await self.source._write(append)
