"""Closed trades of the production path, read from its own database: the single journal.

Every row joins the durable trade, its original Risk decision, the exit transition of
its journal and the accepted terminal accounting. ``r_multiple`` is the accounted net
result over the decision's worst-case loss (1 R), the unit the learning ledger and the
Risk Manager use. A TIMEOUT exit with ``early_exit`` set is the composer's early close
(its reason), not an expired holding time. Only trades with accepted accounting are
reported; nothing here is estimated.

    python -m kairos_execution.production_report --manifest manifest.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from decimal import Decimal
from pathlib import Path
from typing import Any

import asyncpg  # type: ignore[import-untyped]  # Upstream ships no typing marker/stubs.

from .production_provisioning import ProvisionedDatabaseV1

REPORT_VERSION = "kairos.execution-closed-trade.v1"
_EXIT_REASONS = {
    "EXITING_TARGET": "TARGET",
    "EXITING_STOP": "STOP",
    "EXITING_TIMEOUT": "TIMEOUT",
    "EXITING_EMERGENCY": "EMERGENCY",
}

_TRADES = """
SELECT t.trade_id, t.strategy_id, t.strategy_revision, t.symbol, t.venue_symbol, t.side, t.quantity,
       t.filled_quantity, t.first_fill_at, t.risk_decision_payload
FROM execution_trades t WHERE t.state = 'FLAT' ORDER BY t.first_fill_at, t.trade_id
"""
_EXITS = """
SELECT DISTINCT ON (trade_id) trade_id, to_state, event_payload->'event'->>'early_exit' AS early_exit
FROM execution_trade_events
WHERE to_state LIKE 'EXITING_%' ORDER BY trade_id, sequence
"""
_ACCOUNTING = """
SELECT trade_id, gross_pnl_usd, fees_usd, funding_cost_usd, net_pnl_usd, settled_at
FROM kairos_production_accounting_v1.accepted_releases
"""


def _text(value: Decimal) -> str:
    text = format(value, "f")
    return text.rstrip("0").rstrip(".") if "." in text else text


async def closed_trades(manifest: ProvisionedDatabaseV1) -> list[dict[str, Any]]:
    runtime = await asyncpg.connect(manifest.dsn("runtime"))
    try:
        trades = await runtime.fetch(_TRADES)
        exit_rows = await runtime.fetch(_EXITS)
        exits = {row["trade_id"]: row["to_state"] for row in exit_rows}
        early = {row["trade_id"]: row["early_exit"] for row in exit_rows if row["early_exit"]}
    finally:
        await runtime.close()
    accounting = await asyncpg.connect(manifest.dsn("accounting"))
    try:
        releases = {row["trade_id"]: row for row in await accounting.fetch(_ACCOUNTING)}
    finally:
        await accounting.close()
    rows = []
    for trade in trades:
        release = releases.get(trade["trade_id"])
        if release is None:
            continue  # FLAT but not yet accounted: not a closed trade of the journal.
        decision = trade["risk_decision_payload"]
        decision = json.loads(decision) if isinstance(decision, str) else decision
        one_r = Decimal(str(decision["worst_case_loss_usd"]))
        net = Decimal(release["net_pnl_usd"])
        intent = decision["intent"]
        rows.append(
            {
                "version": REPORT_VERSION,
                "trade_id": trade["trade_id"],
                "strategy_id": trade["strategy_id"],
                "strategy_revision": trade["strategy_revision"],
                "symbol": trade["symbol"],
                "venue_symbol": trade["venue_symbol"],
                "side": trade["side"],
                "quantity": trade["filled_quantity"],
                "decided_at_ms": decision["decided_at_ms"],
                "intent_decision_ts_ms": intent["decision_ts_ms"],
                "entered_at": trade["first_fill_at"].isoformat() if trade["first_fill_at"] else None,
                "settled_at": release["settled_at"].isoformat(),
                "exit_reason": _EXIT_REASONS.get(exits.get(trade["trade_id"], ""), "UNKNOWN"),
                # Why a position left before its holding time (regime change, material event).
                "early_exit": early.get(trade["trade_id"]),
                "worst_case_loss_usd": _text(one_r),
                "gross_pnl_usd": _text(Decimal(release["gross_pnl_usd"])),
                "fees_usd": _text(Decimal(release["fees_usd"])),
                "funding_cost_usd": _text(Decimal(release["funding_cost_usd"])),
                "net_pnl_usd": _text(net),
                "r_multiple": _text((net / one_r).quantize(Decimal("0.0001"))) if one_r > 0 else None,
            }
        )
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m kairos_execution.production_report", description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        rows = asyncio.run(closed_trades(ProvisionedDatabaseV1.load(args.manifest)))
    except (OSError, ValueError, asyncpg.PostgresError) as exc:
        print(f"report refused: {type(exc).__name__}: {str(exc)[:300]}", file=sys.stderr)
        return 1
    for row in rows:
        print(json.dumps(row, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
