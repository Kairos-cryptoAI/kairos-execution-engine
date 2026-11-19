"""Experimental durable session-loss decision; no qualified LIVE source exists.

This module is not an authority to trade. Provisioning is deliberately manual;
it must never be pointed at an existing production database without separately
reviewing ownership, grants, anti-rollback, and cross-worker fencing.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from decimal import Decimal
from typing import Literal, Protocol
from uuid import UUID

import asyncpg  # type: ignore[import-untyped]  # Upstream ships no typing marker/stubs.
from pydantic import Field, field_validator

from .production_readiness import StrictRecord

SCHEMA = "kairos_session_loss_v1"
DDL = """
CREATE SCHEMA kairos_session_loss_v1;
CREATE TABLE kairos_session_loss_v1.events (
 account_sha256 text NOT NULL CHECK (account_sha256 ~ '^[a-f0-9]{64}$'),
 session_id uuid NOT NULL,
 sequence bigint NOT NULL CHECK (sequence >= 1),
 state text NOT NULL CHECK (state IN ('ACTIVE','STOP')),
 baseline_equity_usd numeric NOT NULL CHECK (baseline_equity_usd > 0),
 baseline_net_deposits_usd numeric NOT NULL,
 net_deposits_usd numeric NOT NULL,
 equity_usd numeric NOT NULL,
 remaining_incremental_risk_usd numeric NOT NULL CHECK (remaining_incremental_risk_usd >= 0),
 evidence_sha256 text NOT NULL CHECK (evidence_sha256 ~ '^[a-f0-9]{64}$'),
 observed_at timestamptz NOT NULL CHECK (isfinite(observed_at)),
 CONSTRAINT session_money_finite CHECK (
  baseline_equity_usd > '-Infinity'::numeric AND baseline_equity_usd < 'Infinity'::numeric
  AND baseline_net_deposits_usd > '-Infinity'::numeric AND baseline_net_deposits_usd < 'Infinity'::numeric
  AND net_deposits_usd > '-Infinity'::numeric AND net_deposits_usd < 'Infinity'::numeric
  AND equity_usd > '-Infinity'::numeric AND equity_usd < 'Infinity'::numeric
  AND remaining_incremental_risk_usd > '-Infinity'::numeric
  AND remaining_incremental_risk_usd < 'Infinity'::numeric
 ),
 PRIMARY KEY(account_sha256, sequence)
);
CREATE FUNCTION kairos_session_loss_v1.deny_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'session history is immutable'; END $$;
CREATE TRIGGER immutable_events BEFORE UPDATE OR DELETE OR TRUNCATE
 ON kairos_session_loss_v1.events FOR EACH STATEMENT
 EXECUTE FUNCTION kairos_session_loss_v1.deny_mutation();
CREATE FUNCTION kairos_session_loss_v1.check_append() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE prior kairos_session_loss_v1.events%ROWTYPE;
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('risk-reservation:' || NEW.account_sha256,0));
 SELECT * INTO prior FROM kairos_session_loss_v1.events
  WHERE account_sha256=NEW.account_sha256 ORDER BY sequence DESC LIMIT 1;
 IF NOT FOUND THEN
  IF NEW.sequence <> 1 THEN RAISE EXCEPTION 'missing baseline'; END IF;
 ELSE
  IF NEW.sequence <> prior.sequence+1 OR NEW.session_id <> prior.session_id
   OR NEW.baseline_equity_usd <> prior.baseline_equity_usd
   OR NEW.baseline_net_deposits_usd <> prior.baseline_net_deposits_usd
   OR NEW.observed_at <= prior.observed_at
   OR (prior.state='STOP' AND NEW.state<>'STOP')
  THEN RAISE EXCEPTION 'session history continuity failure'; END IF;
 END IF;
 IF NEW.state='ACTIVE' AND NEW.baseline_equity_usd + NEW.net_deposits_usd
   - NEW.baseline_net_deposits_usd - NEW.equity_usd >= 5
 THEN RAISE EXCEPTION 'breached session cannot be active'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER check_events BEFORE INSERT ON kairos_session_loss_v1.events
 FOR EACH ROW EXECUTE FUNCTION kairos_session_loss_v1.check_append();
"""


class SessionLossError(PermissionError):
    """Unknown or conflicting evidence never admits a new entry."""


class VerifiedSessionObservationV1(StrictRecord):
    """Output contract for a future qualified source, not self-authenticating."""

    account_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    session_id: UUID
    sequence: int = Field(ge=1)
    baseline_equity_usd: Decimal = Field(gt=0)
    baseline_net_deposits_usd: Decimal
    net_deposits_usd: Decimal
    equity_usd: Decimal
    remaining_incremental_risk_usd: Decimal = Field(ge=0)
    evidence_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    observed_at: datetime

    @field_validator(
        "baseline_equity_usd",
        "baseline_net_deposits_usd",
        "net_deposits_usd",
        "equity_usd",
        "remaining_incremental_risk_usd",
    )
    @classmethod
    def finite(cls, value: Decimal) -> Decimal:
        if not value.is_finite():
            raise ValueError("session money must be finite")
        return value

    @field_validator("session_id")
    @classmethod
    def nonzero_session(cls, value: UUID) -> UUID:
        if value.int == 0:
            raise ValueError("session identity must be nonzero")
        return value

    @field_validator("observed_at")
    @classmethod
    def utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("observation must use UTC")
        return value


class PinnedEvedexSessionVerifier:
    """No qualified balance/flow/fee/funding ledger is available today."""

    def verify(self, raw: object, *, account_sha256: str) -> VerifiedSessionObservationV1:
        raise SessionLossError("qualified EVEDEX session-loss source unavailable")

    async def resolve(
        self, connection: asyncpg.Connection, *, account_sha256: str, context_sha256: str, now: datetime
    ) -> VerifiedSessionObservationV1:
        raise SessionLossError("qualified EVEDEX session-loss source unavailable")


class QualifiedSessionObservationSource(Protocol):
    """Future qualified source; resolve under the existing locked transaction.

    The returned observation must prove source lineage and bind every current
    position, remaining cost and reservation to this exact account and DB view.
    This protocol and a compliant type signature do not qualify any source.
    """

    def verify(self, raw: object, *, account_sha256: str) -> VerifiedSessionObservationV1: ...

    async def resolve(
        self, connection: asyncpg.Connection, *, account_sha256: str, context_sha256: str, now: datetime
    ) -> VerifiedSessionObservationV1: ...


def projected_session_loss_usd(observation: VerifiedSessionObservationV1, candidate_risk: Decimal) -> Decimal:
    """Observed equity loss plus *incremental* remaining and new-candidate risk.

    Future source qualification must prove that remaining risk includes every
    existing position and pending reservation exactly once, from current mark
    to protection including unreflected costs. No cost defaults exist here.
    """
    if not candidate_risk.is_finite() or candidate_risk <= 0:
        raise SessionLossError("candidate risk must be finite and positive")
    observed_loss = max(
        Decimal(0),
        observation.baseline_equity_usd
        + observation.net_deposits_usd
        - observation.baseline_net_deposits_usd
        - observation.equity_usd,
    )
    return observed_loss + observation.remaining_incremental_risk_usd + candidate_risk


async def append_session_decision(
    connection: asyncpg.Connection,
    observation: VerifiedSessionObservationV1,
    *,
    account_sha256: str,
    now: datetime,
) -> Literal["ACTIVE", "STOP"]:
    """Append under the caller's account advisory transaction lock.

    Caller MUST commit returned STOP before raising its external denial. This
    checks a completed mark-to-market loss only; open-risk limits remain in
    the existing reservation code and are not added to equity again.
    """
    observation = VerifiedSessionObservationV1.model_validate(observation)
    if (
        observation.account_sha256 != account_sha256
        or now.tzinfo is None
        or now.utcoffset() != timedelta(0)
        or observation.observed_at > now
        or now - observation.observed_at > timedelta(seconds=5)
    ):
        raise SessionLossError("session observation scope or freshness invalid")
    last = await connection.fetchrow(
        "SELECT * FROM kairos_session_loss_v1.events WHERE account_sha256=$1 ORDER BY sequence DESC LIMIT 1",
        account_sha256,
    )
    if last is not None:
        if (
            last["session_id"] != observation.session_id
            or last["baseline_equity_usd"] != observation.baseline_equity_usd
            or last["baseline_net_deposits_usd"] != observation.baseline_net_deposits_usd
        ):
            raise SessionLossError("session baseline or identity differs")
        if observation.sequence == last["sequence"]:
            if (
                last["evidence_sha256"] != observation.evidence_sha256
                or last["observed_at"] != observation.observed_at
                or last["net_deposits_usd"] != observation.net_deposits_usd
                or last["equity_usd"] != observation.equity_usd
                or last["remaining_incremental_risk_usd"] != observation.remaining_incremental_risk_usd
            ):
                raise SessionLossError("conflicting session observation replay")
            return last["state"]
        if observation.sequence != last["sequence"] + 1 or observation.observed_at <= last["observed_at"]:
            raise SessionLossError("session observation sequence or time is not continuous")
    elif observation.sequence != 1:
        raise SessionLossError("session baseline is missing")
    loss = (
        observation.baseline_equity_usd
        + observation.net_deposits_usd
        - observation.baseline_net_deposits_usd
        - observation.equity_usd
    )
    stopped = (last is not None and last["state"] == "STOP") or loss >= Decimal("5")
    state: Literal["ACTIVE", "STOP"] = "STOP" if stopped else "ACTIVE"
    await connection.execute(
        "INSERT INTO kairos_session_loss_v1.events "
        "(account_sha256,session_id,sequence,state,baseline_equity_usd,baseline_net_deposits_usd,"
        "net_deposits_usd,equity_usd,remaining_incremental_risk_usd,evidence_sha256,observed_at) "
        "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
        account_sha256,
        observation.session_id,
        observation.sequence,
        state,
        observation.baseline_equity_usd,
        observation.baseline_net_deposits_usd,
        observation.net_deposits_usd,
        observation.equity_usd,
        observation.remaining_incremental_risk_usd,
        observation.evidence_sha256,
        observation.observed_at,
    )
    return state
