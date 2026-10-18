"""Fail-closed runtime and account health for the bounded read-only recorder.

The supplied pool must already be bound to the isolated recorder database. This
module performs only independent SELECT statements; venue access is delegated to
an explicit caller and never occurs while a database transaction is open.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from kairos_persistence.canary_session import SYMBOLS, CanaryScope, digest

from .readonly_recorder import RecorderHealth


@dataclass(frozen=True, slots=True)
class AccountEvidence:
    """Result of actual authenticated read-only account GETs and reconciliation."""

    snapshot: Any
    remote_account_id: str
    observed_at_ms: int
    orphan_tpsl_count: int


AccountReader = Callable[[CanaryScope], Awaitable[AccountEvidence]]
_AUTH_PATHS = (
    "/api/user/me",
    "/api/market/available-balance",
    "/api/position",
    "/api/order/opened",
    "/api/tpsl",
)

# Match metrics_exporter.py's event_audit source and 24-hour produced_at horizon,
# but require the complete exact five-symbol denominator and a recent closed bar.
_BAR_HEALTH_QUERY = """
WITH db_clock AS (
    SELECT clock_timestamp() AS ts
), bounds AS (
    SELECT ts,
           date_trunc('minute', ts) - interval '24 hours' AS first_open,
           date_trunc('minute', ts) - interval '1 minute' AS last_open
      FROM db_clock
), expected(symbol) AS (
    SELECT unnest($1::text[])
), bars AS (
    SELECT payload->>'symbol' AS symbol,
           (payload->>'open_time_ms')::bigint AS open_time_ms,
           produced_at
      FROM event_audit, bounds
     WHERE topic = 'kairos.market.closed_bar.v1'
       AND produced_at >= bounds.ts - interval '24 hours'
       AND produced_at <= bounds.ts
       AND (payload->>'open_time_ms')::bigint >=
           (extract(epoch FROM bounds.first_open) * 1000)::bigint
       AND (payload->>'open_time_ms')::bigint <=
           (extract(epoch FROM bounds.last_open) * 1000)::bigint
       AND payload->>'symbol' = ANY($1::text[])
), distinct_bars AS (
    SELECT symbol, open_time_ms, max(produced_at) AS produced_at
      FROM bars GROUP BY symbol, open_time_ms
), sequenced AS (
    SELECT symbol, open_time_ms,
           lag(open_time_ms) OVER (PARTITION BY symbol ORDER BY open_time_ms) AS previous_ms
      FROM distinct_bars
), coverage AS (
    SELECT e.symbol,
           count(d.open_time_ms)::bigint AS bar_count,
           count(DISTINCT d.open_time_ms)::bigint AS distinct_count,
           max(d.produced_at) AS latest_produced_at,
           count(s.open_time_ms) FILTER (
               WHERE s.previous_ms IS NOT NULL AND s.open_time_ms <> s.previous_ms + 60000
           )::bigint AS gaps
      FROM expected e
      LEFT JOIN distinct_bars d ON d.symbol=e.symbol
      LEFT JOIN sequenced s ON s.symbol=e.symbol AND s.open_time_ms=d.open_time_ms
     GROUP BY e.symbol
)
SELECT (extract(epoch FROM bounds.ts) * 1000)::bigint AS db_now_ms,
       count(*) FILTER (WHERE coverage.bar_count=1440 AND coverage.distinct_count=1440
          AND coverage.gaps=0 AND coverage.latest_produced_at >= bounds.ts - interval '120 seconds'
          AND coverage.latest_produced_at <= bounds.ts)::bigint AS healthy_symbols,
       COALESCE(sum(coverage.gaps),0)::bigint AS gaps,
       count(*)::bigint AS expected_symbols
  FROM coverage CROSS JOIN bounds
 GROUP BY bounds.ts
"""

_MUTATION_QUERY = """
SELECT
  (SELECT count(*)::bigint FROM execution_effects) AS effects,
  (SELECT count(*)::bigint FROM execution_trades) AS trades,
  (SELECT count(*)::bigint FROM paper_canary_dispatch_claims) AS dispatch_claims,
  (SELECT count(*)::bigint FROM execution_effects WHERE status='PREPARED') AS pending_effects,
  (SELECT count(*)::bigint FROM execution_trades
    WHERE state NOT IN ('FLAT','CANCELLED')) AS pending_trades
"""

_RUN_QUERY = """
SELECT r.scope,r.scope_sha256,r.state,r.database_instance_id,
       i.instance_id AS current_instance_id
  FROM paper_readonly_runs r
  CROSS JOIN paper_canary_database_identity i
 WHERE r.run_id=$1 AND i.singleton=TRUE
"""


def _strict_count(value: Any, field: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"runtime health {field} is missing or malformed")
    return value


async def read_readonly_health(
    pool: Any,
    run_id: str,
    scope: CanaryScope,
    account_reader: AccountReader,
) -> RecorderHealth:
    """Read DB/runtime health, then independently reconcile the exact DEV account.

    Lifetime-zero execution counters are deliberately conservative: the isolated
    recorder DB must contain no effects/trades/dispatch claims, avoiding unsafe
    attribution of legacy rows to a run. Missing tables or query failures refuse.
    """
    if not isinstance(run_id, str) or not run_id.strip():
        raise ValueError("read-only run identity is missing")
    try:
        run = await pool.fetchrow(_RUN_QUERY, run_id)
        bars = await pool.fetchrow(_BAR_HEALTH_QUERY, list(SYMBOLS))
        mutations = await pool.fetchrow(_MUTATION_QUERY)
    except Exception:
        raise ValueError("read-only runtime health query failed; details redacted") from None
    if run is None or bars is None or mutations is None:
        raise ValueError("read-only runtime health is unavailable")
    if run["state"] != "RECORDING" or run["database_instance_id"] != run["current_instance_id"]:
        raise ValueError("read-only run is sealed or bound to another database instance")
    recorded_scope = run["scope"]
    expected_scope = scope.model_dump(mode="json")
    if isinstance(recorded_scope, str):
        try:
            recorded_scope = json.loads(recorded_scope)
        except (TypeError, ValueError) as exc:
            raise ValueError("read-only run scope is malformed") from exc
    if recorded_scope != expected_scope:
        raise ValueError("read-only run scope does not match the independent canary scope")
    if run["scope_sha256"] != digest(expected_scope):
        raise ValueError("read-only run scope digest is invalid")

    expected_symbols = _strict_count(bars["expected_symbols"], "symbol denominator")
    healthy_symbols = _strict_count(bars["healthy_symbols"], "closed-bar coverage")
    gaps = _strict_count(bars["gaps"], "closed-bar gaps")
    db_now_ms = _strict_count(bars["db_now_ms"], "database clock")
    if expected_symbols != len(SYMBOLS):
        raise ValueError("read-only closed-bar symbol denominator is incomplete")
    if healthy_symbols != len(SYMBOLS):
        raise ValueError("read-only closed-bar coverage is missing, stale, or discontinuous")

    counts = tuple(
        _strict_count(mutations[name], name)
        for name in ("effects", "trades", "dispatch_claims", "pending_effects", "pending_trades")
    )
    if any(counts):
        raise ValueError("isolated read-only database contains execution or dispatch records")

    # Deliberately outside SQL transaction: account_reader is the sole network
    # boundary and must use authenticated GETs only, without signing/mutations.
    try:
        account = await account_reader(scope)
    except Exception:
        raise ValueError("read-only account reconciliation failed; details redacted") from None
    snapshot = account.snapshot
    observed_at_ms = _strict_count(account.observed_at_ms, "account timestamp")
    if abs(db_now_ms - observed_at_ms) > 2_000:
        raise ValueError("read-only account evidence is stale or clock-skewed")
    if account.remote_account_id != scope.remote_account_id:
        raise ValueError("read-only remote account does not match the exact canary scope")
    if getattr(snapshot, "account_id", None) != scope.account_id:
        raise ValueError("read-only account identity does not match the exact canary scope")
    if getattr(snapshot, "reconciled", None) is not True:
        raise ValueError("authoritative account reconciliation is not confirmed")
    captured_at = getattr(snapshot, "captured_at", None)
    if not isinstance(captured_at, datetime) or captured_at.tzinfo is None:
        raise ValueError("read-only account snapshot timestamp is missing")
    snapshot_ms = int(captured_at.astimezone(UTC).timestamp() * 1000)
    if abs(observed_at_ms - snapshot_ms) > 2_000:
        raise ValueError("read-only account snapshot is stale or clock-skewed")
    positions = getattr(snapshot, "positions", None)
    orders = getattr(snapshot, "open_order_ids", None)
    if not isinstance(positions, list) or not isinstance(orders, list):
        raise ValueError("read-only account exposure evidence is incomplete")
    if positions or orders or type(account.orphan_tpsl_count) is not int or account.orphan_tpsl_count != 0:
        raise ValueError("read-only account is not flat or has orphan protective orders")

    return RecorderHealth(
        observed_at_ms=observed_at_ms,
        account_id=scope.account_id,
        remote_account_id=scope.remote_account_id,
        config_sha256=scope.config_sha256,
        account_reconciled=True,
        unresolved_bar_gaps=gaps,
        reconciliation_drift=False,
        entry_mutations=0,
    )


class _NeverSign:
    address = "0x0000000000000000000000000000000000000000"

    def sign_typed_data(self, *_args: Any, **_kwargs: Any) -> str:
        raise RuntimeError("read-only health must never sign")


class PostgresReadonlyHealthReader:
    """Recorder callback backed by SELECT-only PostgreSQL and authenticated GETs.

    ``getter`` is supplied by the CLI, which owns credentials and pins the
    HTTPS destination/GET allowlist. It must return qualification.HttpObservation.
    No credential is read or retained by this module.
    """

    def __init__(
        self,
        pool: Any,
        *,
        getter: Callable[[str, Any], Awaitable[Any]],
        clock: Callable[[], datetime] | None = None,
        operation_timeout_s: float = 10.0,
    ) -> None:
        if not isinstance(operation_timeout_s, (int, float)) or not 0 < operation_timeout_s <= 30:
            raise ValueError("health operation timeout must be positive and at most 30 seconds")
        self._pool = pool
        self._getter = getter
        self._clock = clock or (lambda: datetime.now(UTC))
        self._timeout = float(operation_timeout_s)

    async def __call__(self, run_id: str, scope: CanaryScope) -> RecorderHealth:
        started = time.monotonic()
        payloads: dict[str, Any] = {}

        async def account_reader(expected_scope: CanaryScope) -> AccountEvidence:
            from .adapters.evedex import EvedexAdapter

            poll_started = self._clock()
            if poll_started.tzinfo is None:
                raise ValueError("account clock must be timezone-aware")
            poll_started = poll_started.astimezone(UTC)
            observations = await asyncio.gather(*(self._getter(path, {}) for path in _AUTH_PATHS))
            for path, observation in zip(_AUTH_PATHS, observations, strict=True):
                if getattr(observation, "status", None) != 200:
                    raise ValueError("authenticated EVEDEX GET did not return HTTP 200")
                payloads[path] = observation.payload
            user = payloads["/api/user/me"]
            if not isinstance(user, dict) or user.get("exchangeId") != expected_scope.remote_account_id:
                raise ValueError("authenticated EVEDEX account identity mismatch")

            async def recorded_get(path: str) -> Any:
                return payloads[path]

            adapter = EvedexAdapter(
                exchange_base_url=expected_scope.exchange_url,
                signer=_NeverSign(),
                chain_id=expected_scope.chain_id,
                jwt=None,
                dry_run=False,
                symbol_map={symbol: f"{symbol.removesuffix('USDT')}USD:DEV" for symbol in SYMBOLS},
                clock=self._clock,
            )
            adapter._get = recorded_get  # type: ignore[method-assign]
            snapshot = await adapter.fetch_account_snapshot(
                account_id=expected_scope.account_id,
                peak_equity_usd=0,
            )
            tpsl = payloads["/api/tpsl"]
            if isinstance(tpsl, dict) and isinstance(tpsl.get("list"), list):
                tpsl = tpsl["list"]
            if not isinstance(tpsl, list) or not all(isinstance(item, dict) for item in tpsl):
                raise ValueError("authenticated EVEDEX TP/SL response is malformed")
            raw_positions = payloads["/api/position"]
            raw_orders = payloads["/api/order/opened"]
            if isinstance(raw_positions, dict) and isinstance(raw_positions.get("list"), list):
                raw_positions = raw_positions["list"]
            if isinstance(raw_orders, dict) and isinstance(raw_orders.get("list"), list):
                raw_orders = raw_orders["list"]
            if not isinstance(raw_positions, list) or not isinstance(raw_orders, list):
                raise ValueError("authenticated EVEDEX exposure response is malformed")
            poll_ended = self._clock()
            if poll_ended.tzinfo is None:
                raise ValueError("account clock must be timezone-aware")
            poll_ended = poll_ended.astimezone(UTC)
            poll_age_ms = (poll_ended - poll_started).total_seconds() * 1000
            if not 0 <= poll_age_ms < 2_000:
                raise ValueError("authenticated EVEDEX account poll is stale or clock-skewed")
            if getattr(snapshot, "exchange", None) != "evedex":
                raise ValueError("account snapshot is not from EVEDEX")
            now_ms = int(poll_started.timestamp() * 1000)
            return AccountEvidence(
                snapshot=snapshot,
                remote_account_id=str(user["exchangeId"]),
                observed_at_ms=now_ms,
                # Flat baseline: every raw position/order/TP-SL record is unsafe,
                # including unknown or inactive TP/SL states.
                orphan_tpsl_count=len(tpsl) + len(raw_positions) + len(raw_orders),
            )

        try:
            health = await asyncio.wait_for(
                read_readonly_health(self._pool, run_id, scope, account_reader), timeout=self._timeout
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            # Avoid surfacing driver, payload, remote account, or credential details.
            raise ValueError("read-only health check failed; details redacted") from None
        elapsed = time.monotonic() - started
        if elapsed >= 2.0:
            raise ValueError("read-only health cycle exceeded the two-second evidence window")
        return health
