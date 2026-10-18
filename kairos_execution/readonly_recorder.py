"""Live-source, read-only evidence recorder for the bounded EVEDEX DEV canary.

This module records observations only. It has no order, signing, or credential-file
access. Callers provide the already-bound PostgreSQL repository and an explicit
account/runtime health reader; missing health is a refusal, never a zero.
"""

from __future__ import annotations

import asyncio
import json
import math
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import aiohttp
from kairos_persistence.canary_session import (
    SYMBOLS,
    CanaryScope,
    CanarySessionRepository,
    ReadonlyObservation,
    SymbolObservation,
)


@dataclass(frozen=True, slots=True)
class RecorderHealth:
    """Required contemporaneous, independently scoped account/runtime evidence."""

    observed_at_ms: int
    account_id: str
    remote_account_id: str
    config_sha256: str
    account_reconciled: bool
    unresolved_bar_gaps: int
    reconciliation_drift: bool
    entry_mutations: int

    def validate(self, scope: CanaryScope, *, now_ms: int) -> None:
        if type(self.observed_at_ms) is not int or self.observed_at_ms <= 0:
            raise ValueError("account/runtime health timestamp is missing")
        if abs(now_ms - self.observed_at_ms) > 2_000:
            raise ValueError("account/runtime health is stale or clock-skewed")
        if (
            self.account_id != scope.account_id
            or self.remote_account_id != scope.remote_account_id
            or self.config_sha256 != scope.config_sha256
        ):
            raise ValueError("account/runtime health does not match the exact canary scope")
        if self.account_reconciled is not True:
            raise ValueError("authoritative account reconciliation is not confirmed")
        if type(self.unresolved_bar_gaps) is not int or self.unresolved_bar_gaps < 0:
            raise ValueError("unresolved bar-gap count is unknown or malformed")
        if type(self.reconciliation_drift) is not bool:
            raise ValueError("reconciliation drift state is unknown or malformed")
        if type(self.entry_mutations) is not int or self.entry_mutations < 0:
            raise ValueError("entry-mutation count is unknown or malformed")


HealthReader = Callable[[str, CanaryScope], Awaitable[RecorderHealth]]
Sleep = Callable[[float], Awaitable[None]]
Monotonic = Callable[[], float]


@dataclass(frozen=True, slots=True)
class MeasurementBatch:
    captured_at_ms: int
    symbols: tuple[SymbolObservation, ...]


MeasurementReader = Callable[[], Awaitable[MeasurementBatch]]


async def record_readonly_window(
    repository: CanarySessionRepository,
    scope: CanaryScope,
    *,
    measure: MeasurementReader,
    read_health: HealthReader,
    sample_period_ms: int = 15_000,
    duration_s: float = 86_400.0,
    operation_timeout_s: float = 10.0,
    sleep: Sleep = asyncio.sleep,
    monotonic: Monotonic = time.monotonic,
) -> tuple[str, str]:
    """Persist full-denominator samples on the DB clock, then derive a receipt.

    ``measure`` must return one row per fixed symbol, marking failed/missing
    measurements unavailable. An exception marks the complete denominator
    unavailable for this poll. Health-source failures instead abort the run,
    because unknown counters cannot safely be serialized as zero.
    """
    if type(sample_period_ms) is not int or not 5_000 <= sample_period_ms <= 60_000:
        raise ValueError("read-only cadence must be 5..60 seconds")
    if not math.isfinite(duration_s) or duration_s < 86_400:
        raise ValueError("a live recorder window must run for at least 24 actual hours")
    if not math.isfinite(operation_timeout_s) or not 0 < operation_timeout_s <= 30:
        raise ValueError("recorder operation timeout must be positive and at most 30 seconds")

    run_id = await asyncio.wait_for(
        repository.begin_readonly(scope, sample_period_ms=sample_period_ms),
        timeout=operation_timeout_s,
    )
    monotonic_start = monotonic()
    target_end = monotonic_start + duration_s
    cadence_s = sample_period_ms / 1_000
    next_tick = 0
    while True:
        due = monotonic_start + next_tick * cadence_s
        if due > monotonic():
            await sleep(due - monotonic())
        # Take venue and health measurements outside all persistence transactions.
        try:
            batch = await asyncio.wait_for(measure(), timeout=operation_timeout_s)
            symbols = batch.symbols
            if len(symbols) != len(SYMBOLS) or {item.symbol for item in symbols} != set(SYMBOLS):
                raise ValueError("measurement reader did not return the exact five-symbol denominator")
            if type(batch.captured_at_ms) is not int or batch.captured_at_ms <= 0:
                raise ValueError("measurement batch lacks a real source capture timestamp")
        except asyncio.CancelledError:
            raise
        except Exception:
            batch = MeasurementBatch(
                captured_at_ms=int(datetime.now(UTC).timestamp() * 1_000),
                symbols=tuple(SymbolObservation(symbol=symbol, available=False) for symbol in SYMBOLS),
            )
            symbols = tuple(SymbolObservation(symbol=symbol, available=False) for symbol in SYMBOLS)

        health = await asyncio.wait_for(read_health(run_id, scope), timeout=operation_timeout_s)
        observed_at_ms = int(datetime.now(UTC).timestamp() * 1_000)
        health.validate(scope, now_ms=observed_at_ms)
        elapsed_ms = observed_at_ms - batch.captured_at_ms
        if elapsed_ms < 0:
            raise ValueError("measurement batch timestamp is in the future")
        symbols = _age_symbols(symbols, elapsed_ms)
        observation = ReadonlyObservation(
            observed_at_ms=observed_at_ms,
            symbols=tuple(symbols),
            unresolved_bar_gaps=health.unresolved_bar_gaps,
            reconciliation_drift=health.reconciliation_drift,
            entry_mutations=health.entry_mutations,
        )
        await asyncio.wait_for(
            repository.append_observation(run_id, observation), timeout=operation_timeout_s
        )
        appended_at = monotonic()
        if appended_at >= target_end:
            break
        # Keep an absolute cadence grid; on an overrun skip missed ticks instead
        # of shifting every later sample or issuing catch-up bursts.
        next_tick = math.floor((appended_at - monotonic_start) / cadence_s) + 1

    receipt_id = await asyncio.wait_for(
        repository.certify_readonly(run_id, expected_scope=scope), timeout=operation_timeout_s
    )
    return run_id, receipt_id


def _age_symbols(symbols: tuple[SymbolObservation, ...], elapsed_ms: int) -> tuple[SymbolObservation, ...]:
    aged: list[SymbolObservation] = []
    for item in symbols:
        age = item.book_age_ms + elapsed_ms if item.book_age_ms is not None else None
        stale = age is None or age > 5_000
        aged.append(
            item.model_copy(
                update={
                    "available": item.available and not stale,
                    "book_age_ms": age,
                }
            )
        )
    return tuple(aged)


async def measure_public_venue_sample(
    *,
    symbol_map: dict[str, str],
    notional_usd: float = 1_000.0,
    timeout_s: float = 8.0,
) -> MeasurementBatch:
    """Measure one paired public EVEDEX DEV/Binance sample via Quant primitives."""
    expected_map = {symbol: f"{symbol.removesuffix('USDT')}USD:DEV" for symbol in SYMBOLS}
    if symbol_map != expected_map:
        raise ValueError("recorder requires the exact five EVEDEX DEV instrument identities")
    if not math.isfinite(notional_usd) or notional_usd <= 0 or notional_usd > 1_000:
        raise ValueError("recorder notional must be positive and no greater than $1,000")
    try:
        from kairos_quant.venue_comparison import (  # type: ignore[import-untyped]
            compare_venues,
            parse_binance_book,
            parse_evedex_book,
        )
    except ImportError as exc:  # pragma: no cover - packaging failure
        raise RuntimeError("install the optional recorder extra to use Quant market measurements") from exc

    timeout = aiohttp.ClientTimeout(total=timeout_s)
    async with aiohttp.ClientSession(
        timeout=timeout,
        connector=aiohttp.TCPConnector(limit=10),
        trust_env=False,
    ) as session:

        async def fetch_json(url: str) -> tuple[Any, float]:
            return await _get_public_json(session, url)

        async def fetch_pair(logical: str, venue: str):
            evedex_result, reference_result = await asyncio.gather(
                fetch_json(f"https://trading-api.evedex.tech/api/market/{venue}/deep"),
                fetch_json(f"https://fapi.binance.com/fapi/v1/depth?symbol={logical}&limit=100"),
            )
            evedex_payload, evedex_latency = evedex_result
            reference_payload, reference_latency = reference_result
            return (
                parse_evedex_book(venue, evedex_payload, latency_ms=evedex_latency),
                parse_binance_book(logical, reference_payload, latency_ms=reference_latency),
            )

        report = await compare_venues(
            fetch_pair=fetch_pair,
            symbol_map=symbol_map,
            samples=1,
            interval_s=0,
            notional_usd=notional_usd,
        )
    return _batch_from_venue_report(report)


def _batch_from_venue_report(report: Any) -> MeasurementBatch:
    samples = report.samples
    by_symbol = {sample.logical_symbol: sample for sample in samples}
    captures = [datetime.fromisoformat(sample.captured_at).astimezone(UTC) for sample in samples]
    captured_at_ms = (
        int(min(captures).timestamp() * 1_000) if captures else int(datetime.now(UTC).timestamp() * 1_000)
    )
    result: list[SymbolObservation] = []
    for symbol in SYMBOLS:
        sample = by_symbol.get(symbol)
        if sample is None:
            result.append(SymbolObservation(symbol=symbol, available=False))
            continue
        venue_age_ms = max(
            captured_at_ms - sample.evedex_timestamp_ms,
            captured_at_ms - sample.binance_timestamp_ms,
        )
        future_skew_ms = max(
            sample.evedex_timestamp_ms - captured_at_ms,
            sample.binance_timestamp_ms - captured_at_ms,
        )
        age_ms = max(0, venue_age_ms)
        slippage = (sample.evedex_buy_slippage_bps, sample.evedex_sell_slippage_bps)
        available = (
            age_ms <= 5_000
            and future_skew_ms <= 2_000
            and sample.timestamp_skew_ms <= 2_000
            and all(value is not None and math.isfinite(value) for value in slippage)
            and math.isfinite(sample.basis_bps)
            and math.isfinite(sample.evedex_spread_bps)
        )
        if not available:
            result.append(SymbolObservation(symbol=symbol, available=False))
            continue
        result.append(
            SymbolObservation(
                symbol=symbol,
                available=True,
                basis_bps=sample.basis_bps,
                spread_bps=sample.evedex_spread_bps,
                slippage_bps=max(value for value in slippage if value is not None),
                book_age_ms=age_ms,
                timestamp_skew_ms=sample.timestamp_skew_ms,
                book_nonempty=True,
            )
        )
    return MeasurementBatch(captured_at_ms=captured_at_ms, symbols=tuple(result))


async def _get_public_json(session: Any, url: str) -> tuple[Any, float]:
    """GET one already-pinned public quote URL with redirect and body bounds."""
    allowed_urls = {
        f"https://trading-api.evedex.tech/api/market/{venue}/deep"
        for venue in ("BTCUSD:DEV", "ETHUSD:DEV", "SOLUSD:DEV", "BNBUSD:DEV", "XRPUSD:DEV")
    } | {f"https://fapi.binance.com/fapi/v1/depth?symbol={symbol}&limit=100" for symbol in SYMBOLS}
    if url not in allowed_urls:
        raise ValueError("public quote URL is outside the fixed EVEDEX DEV/reference allowlist")
    started = time.perf_counter()
    async with session.get(url, allow_redirects=False) as response:
        if response.status != 200:
            raise ValueError("public quote GET did not return HTTP 200")
        response.raise_for_status()
        value = await read_bounded_json(response, max_bytes=1_048_576)
        return value, (time.perf_counter() - started) * 1_000


async def read_bounded_json(response: Any, *, max_bytes: int = 1_048_576) -> Any:
    """Decode one bounded streamed JSON response without accepting truncation."""
    if type(max_bytes) is not int or not 1 <= max_bytes <= 1_048_576:
        raise ValueError("JSON body limit must be between 1 byte and 1 MiB")
    chunks: list[bytes] = []
    size = 0
    async for chunk in response.content.iter_chunked(64 * 1024):
        size += len(chunk)
        if size > max_bytes:
            raise ValueError("response exceeded the recorder body bound")
        chunks.append(chunk)
    return json.loads(b"".join(chunks))
