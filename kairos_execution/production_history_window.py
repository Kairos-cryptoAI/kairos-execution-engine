"""Bounded native EVEDEX history pages, never an account or LIVE authority.

The returned window records the observed pages and their wire captures. Even
when reported counts are exhausted, offset pagination has no qualified
snapshot watermark, retention, ordering or late-correction guarantee. In
particular, identical funding rows must not be deduplicated: the venue schema
does not supply a stable unique event ID for those rows.
"""
from __future__ import annotations

import asyncio
import copy
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from .production_reads import ProductionEvedexReads, ProductionReadUnavailable
from .production_transport import _history_interval

MAX_WINDOW_BODY_BYTES = 8_000_000


@dataclass(frozen=True, slots=True)
class ObservedHistoryWindow:
    account_id: str = field(repr=False)
    after: str
    before: str
    started_at: datetime
    finished_at: datetime
    # These contain sensitive account history and raw response bodies. Callers
    # must apply private storage/retention controls; do not log the object.
    funding_pages: tuple[dict[str, Any], ...] = field(repr=False)
    fill_pages: tuple[dict[str, Any], ...] = field(repr=False)
    funding_captures: tuple[dict[str, Any], ...] = field(repr=False)
    fill_captures: tuple[dict[str, Any], ...] = field(repr=False)
    identity_before_capture: dict[str, Any] = field(repr=False)
    identity_after_capture: dict[str, Any] = field(repr=False)
    # UNKNOWN deliberately cannot be passed off as positive evidence.
    account_revision_authoritative: Literal[False] = False
    history_complete: None = None
    fees_final: None = None
    trading_authority: Literal[False] = False


async def collect_history_window(
    reads: ProductionEvedexReads,
    *,
    after: str,
    before: str,
    page_size: int = 100,
    max_pages_per_source: int = 20,
    timeout_seconds: float = 30.0,
) -> ObservedHistoryWindow:
    """Read both histories and bracket them with account identity checks.

    Counts are checked consistently across pages; opaque cursors, ambiguous
    rows, overlong captures, duplicated fill IDs, and count drift refuse the
    complete capture. This is a read-only observation with no retries.
    """
    if type(reads) is not ProductionEvedexReads or not reads._preflight_complete:
        raise ProductionReadUnavailable("preflighted exact PROD reader required")
    _history_interval(after, before)
    window_start = datetime.fromisoformat(after.replace("Z", "+00:00"))
    window_end = datetime.fromisoformat(before.replace("Z", "+00:00"))
    if type(page_size) is not int or not 1 <= page_size <= 100:
        raise ValueError("page size must be an integer from 1 to 100")
    if type(max_pages_per_source) is not int or not 1 <= max_pages_per_source <= 100:
        raise ValueError("page count must be an integer from 1 to 100")
    if type(timeout_seconds) not in (int, float) or not 0 < timeout_seconds <= 30:
        raise ValueError("timeout must be positive and at most 30 seconds")

    retained_bytes = 0

    def retain_capture(source: str) -> dict[str, Any]:
        nonlocal retained_bytes
        capture = reads.last_captures[source]
        size = capture.get("body_bytes")
        if type(size) is not int or size < 0:
            raise ProductionReadUnavailable("native capture byte count is unavailable")
        retained_bytes += size
        if retained_bytes > MAX_WINDOW_BODY_BYTES:
            raise ProductionReadUnavailable("bounded history capture exceeds cumulative byte limit")
        return copy.deepcopy(capture)

    async def identity() -> dict[str, Any]:
        value = await reads._read("account_identity")
        if not isinstance(value, dict) or str(value.get("exchangeId", "")) != reads.expected_account_id:
            raise ProductionReadUnavailable("history account identity changed or is unavailable")
        return retain_capture("account_identity")

    async def pages(source: Literal["funding_transfers", "fill_history"]):
        result: list[dict[str, Any]] = []
        captures: list[dict[str, Any]] = []
        expected: int | None = None
        total = 0
        fill_ids: set[str] = set()
        for index in range(max_pages_per_source):
            offset = index * page_size
            if source == "funding_transfers":
                page = await reads.fetch_funding_transfers(
                    after=after, before=before, limit=page_size, offset=offset
                )
            else:
                page = await reads.fetch_fill_history(
                    after=after, before=before, limit=page_size, offset=offset
                )
            captures.append(retain_capture(source))
            count = reads._integer(page.get("count"), "history page count", maximum=10_000)
            rows = reads._history_page(page, limit=page_size)
            if expected is None:
                expected = count
            if count != expected:
                raise ProductionReadUnavailable("native history count changed during pagination")
            if page.get("next") is not None:
                raise ProductionReadUnavailable(
                    "native history opaque cursor is not qualified for offset pagination"
                )
            for row in rows:
                try:
                    timestamp = datetime.fromisoformat(row["createdAt"].replace("Z", "+00:00"))
                    if timestamp.tzinfo is None or not window_start <= timestamp <= window_end:
                        raise ValueError
                except (AttributeError, KeyError, TypeError, ValueError):
                    raise ProductionReadUnavailable(
                        "native history row lies outside the queried window"
                    ) from None
            if source == "fill_history":
                for row in rows:
                    if row["id"] in fill_ids:
                        raise ProductionReadUnavailable("native fill ID repeated across pages")
                    fill_ids.add(row["id"])
            total += len(rows)
            result.append(copy.deepcopy(page))
            if total > count:
                raise ProductionReadUnavailable("native history exceeds reported count")
            if total == count:
                return tuple(result), tuple(captures)
            if len(rows) != page_size:
                raise ProductionReadUnavailable("native history returned a truncated nonterminal page")
        raise ProductionReadUnavailable("native history exceeds page budget")

    started = datetime.now(UTC)
    try:
        async with asyncio.timeout(timeout_seconds):
            identity_before = await identity()
            funding_pages, funding_captures = await pages("funding_transfers")
            fill_pages, fill_captures = await pages("fill_history")
            identity_after = await identity()
    except TimeoutError:
        raise ProductionReadUnavailable("bounded history capture timed out; discarded") from None
    finished = datetime.now(UTC)
    if finished < started:
        raise ProductionReadUnavailable("history capture clock moved backwards")
    return ObservedHistoryWindow(
        account_id=reads.expected_account_id, after=after, before=before,
        started_at=started, finished_at=finished,
        funding_pages=funding_pages, fill_pages=fill_pages,
        funding_captures=funding_captures, fill_captures=fill_captures,
        identity_before_capture=identity_before, identity_after_capture=identity_after,
    )
