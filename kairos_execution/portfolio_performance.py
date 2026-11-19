"""Read and persist the pilot's account-wide performance, including external cash transfers."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

from .one_canary_account import CanaryAccountError, EvedexCanaryAccountSource
from .portfolio_journal import PortfolioJournal


async def observe_pilot(
    journal: PortfolioJournal,
    source: EvedexCanaryAccountSource,
    *,
    expected_remote_account_id: str,
    entry_deadline_utc: datetime,
) -> dict[str, Any]:
    """Take a flat baseline once. Bracket later snapshots with venue cash-flow reads."""
    prior = journal.pilot_status()
    since = datetime.fromisoformat(prior["started_at"]) if prior else None
    flows = await source.external_flows_since(since) if since else None
    current = await source.observe()
    if current.account_id != expected_remote_account_id or not current.reads:
        raise CanaryAccountError("portfolio observation lacks expected account evidence")
    current.require_recent(datetime.now(UTC), max_age_seconds=30)
    evidence = [r.body_sha256 for r in current.reads]
    if current.pending_withdrawals:
        raise CanaryAccountError("account withdrawal pending")
    if not prior:
        current.require_flat()
    elif flows and since:
        after = await source.external_flows_since(since)
        if (
            flows.since != since
            or after.since != since
            or not flows.reported_pages_exhausted
            or not after.reported_pages_exhausted
            or not flows.until <= current.started_at <= current.finished_at <= after.until
            or not flows.reads
            or not after.reads
            or (flows.deposits_usdt, flows.withdrawals_usdt) != (after.deposits_usdt, after.withdrawals_usdt)
        ):
            raise CanaryAccountError("account transfers changed across the observation")
        evidence.extend(r.body_sha256 for r in (*flows.reads, *after.reads))
        current.require_recent(datetime.now(UTC), max_age_seconds=30)
    return journal.record_observation(
        observed_at=current.finished_at,
        funding=current.funding_usdt,
        conservative_equity=current.equity_lower_bound_usdt,
        external_flow=flows.net_deposits_usdt if flows else Decimal(0),
        positions=current.nonzero_positions,
        entry_deadline_utc=entry_deadline_utc,
        read_digests=evidence,
        baseline_at=prior["started_at"] if prior else None,
    )


def read_pilot_status(path: Path) -> dict[str, Any] | None:
    """Observe the writer's committed state without creating a new journal or claiming ownership."""
    if not path.is_file():
        return None
    db = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
    try:
        db.row_factory = sqlite3.Row
        row = db.execute("SELECT * FROM pilot WHERE singleton=1").fetchone()
        if row is None:
            return None
        result = dict(row)
        result["attributed_closures"] = db.execute(
            """SELECT count(*) FROM trades WHERE state='CLOSED' AND exit_origin='system'
               AND pnl_basis='execution_fills' AND net_pnl IS NOT NULL"""
        ).fetchone()[0]
        result["total_closures"] = db.execute("SELECT count(*) FROM trades WHERE state='CLOSED'").fetchone()[
            0
        ]
        result["unresolved_effects"] = db.execute(
            "SELECT count(*) FROM effects WHERE status IN ('UNKNOWN','PREPARED')"
        ).fetchone()[0]
        return result
    finally:
        db.close()
