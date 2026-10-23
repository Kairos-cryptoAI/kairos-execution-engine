"""Bounded raw pinned-SDK history reads; never terminal or exposure authority.

Retained JSON is canonical *parsed SDK JSON*, not original HTTP bytes. In
particular JavaScript Number decoding may already have rounded JSON numbers.
Decimal strings are retained unchanged; no totals, USD conversions, missing
fees, funding payments, atomic snapshots or venue sequence are invented here.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Final, Literal, Protocol

from pydantic import Field, model_validator

from .production_readiness import Digest, ProductionContextV1, StrictRecord

SOURCE_ID: Final = "evedex-pinned-sdk-1.2.11-rest-history-v1"
MAX_HISTORY_ROWS = 10_000
MAX_HISTORY_PAGES = 100
MAX_HISTORY_BYTES = 4_000_000
PAGE_SIZE = 100


class ProductionHistoryError(PermissionError):
    """A raw account history capture was malformed or incomplete."""


class HistoryReadTransport(Protocol):
    async def fetch_account_identity(self) -> Any: ...
    async def fetch_order_history_page(
        self,
        *,
        version: int,
        limit: int,
        offset: int,
        next_cursor: str | None = None,
    ) -> Any: ...
    async def fetch_tpsl_page(self, *, limit: int, offset: int) -> Any: ...
    async def fetch_funding(self) -> Any: ...


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


class ProductionHistoryComponentV1(StrictRecord):
    path: str
    query_json: str
    payload_json: str
    payload_sha256: Digest
    started_at: datetime
    finished_at: datetime

    @model_validator(mode="after")
    def validate_content(self) -> ProductionHistoryComponentV1:
        if hashlib.sha256(self.payload_json.encode()).hexdigest() != self.payload_sha256:
            raise ValueError("history component digest differs from its retained parsed JSON")
        if self.finished_at < self.started_at:
            raise ValueError("history component clock bounds are reversed")
        for value in (self.started_at, self.finished_at):
            _utc(value)
        return self


class ProductionHistoryCaptureV1(StrictRecord):
    """Account identity checked, bounded pagination exhausted, NOT coverage proof."""

    source_id: Literal["evedex-pinned-sdk-1.2.11-rest-history-v1"] = SOURCE_ID
    context: ProductionContextV1
    account_id: str
    collection_started_at: datetime
    collection_finished_at: datetime
    components: tuple[ProductionHistoryComponentV1, ...]
    order_count: int = Field(ge=0, le=MAX_HISTORY_ROWS)
    protection_count: int = Field(ge=0, le=MAX_HISTORY_ROWS)
    pagination_exhausted: Literal[True] = True
    authoritative_reconciliation: Literal[False] = False
    atomic_exposure: Literal[False] = False
    funding_payment_coverage: Literal[False] = False

    @model_validator(mode="after")
    def validate_bounds(self) -> ProductionHistoryCaptureV1:
        _utc(self.collection_started_at)
        _utc(self.collection_finished_at)
        if self.account_id != self.context.remote_account_id:
            raise ValueError("history capture account differs from its exact context")
        previous = self.collection_started_at
        for component in self.components:
            if not previous <= component.started_at <= component.finished_at <= self.collection_finished_at:
                raise ValueError("history components are outside ordered capture bounds")
            previous = component.finished_at
        if not self.components or self.collection_finished_at < self.collection_started_at:
            raise ValueError("history capture is empty or reversed")
        return self


class ProductionHistoryCollector:
    """Read one account's actual raw REST SDK methods with no retry or signer.

    Order ``next`` is followed when supplied; otherwise the documented offset
    pagination is used. Repeated cursors/IDs and count drift discard the entire
    result. Exhaustion proves only what these responses reported, not that an
    order could not move between pages. No server time-range cursor is offered
    by the pinned OrderListQuery or TpSlListQuery, so none is fabricated.
    """

    def __init__(
        self,
        *,
        context: ProductionContextV1,
        transport: HistoryReadTransport,
        clock: Callable[[], datetime] | None = None,
        max_seconds: float = 30.0,
    ) -> None:
        if not 0 < max_seconds <= 30:
            raise ValueError("history capture must be bounded to at most thirty seconds")
        self.context = ProductionContextV1.model_validate(context)
        self.transport = transport
        self.clock = clock or (lambda: datetime.now(UTC))
        self.max_seconds = max_seconds

    async def capture_once(self) -> ProductionHistoryCaptureV1:
        components: list[ProductionHistoryComponentV1] = []
        total_bytes = 0
        previous = started = _utc(self.clock())

        async def read(path: str, params: dict[str, int | str] | None = None) -> Any:
            nonlocal total_bytes, previous
            before = _utc(self.clock())
            if before < previous:
                raise ProductionHistoryError("history clock moved backwards")
            if path == "/api/user/me":
                value = await self.transport.fetch_account_identity()
            elif path == "/api/user/funding":
                value = await self.transport.fetch_funding()
            elif path == "/api/order" and params is not None:
                value = await self.transport.fetch_order_history_page(
                    version=int(params["version"]),
                    limit=int(params["limit"]),
                    offset=int(params["offset"]),
                    next_cursor=str(params["next"]) if "next" in params else None,
                )
            elif path == "/api/tpsl" and params is not None:
                value = await self.transport.fetch_tpsl_page(
                    limit=int(params["limit"]), offset=int(params["offset"])
                )
            else:
                raise ProductionHistoryError("unsupported pinned history read")
            after = _utc(self.clock())
            if after < before:
                raise ProductionHistoryError("history clock moved backwards")
            payload = _canonical(value)
            total_bytes += len(payload.encode())
            if total_bytes > MAX_HISTORY_BYTES:
                raise ProductionHistoryError("history capture exceeds its cumulative size bound")
            components.append(
                ProductionHistoryComponentV1(
                    path=path,
                    query_json=_canonical(params),
                    payload_json=payload,
                    payload_sha256=hashlib.sha256(payload.encode()).hexdigest(),
                    started_at=before,
                    finished_at=after,
                )
            )
            previous = after
            return value

        def account(value: Any) -> None:
            identity = value.get("exchangeId") if isinstance(value, dict) else None
            if (
                isinstance(identity, bool)
                or not isinstance(identity, (str, int))
                or str(identity) != self.context.remote_account_id
            ):
                raise ProductionHistoryError("history account differs from exact authenticated exchangeId")

        async def pages(path: str, *, orders: bool) -> int:
            seen: set[str] = set()
            cursors: set[str] = set()
            expected: int | None = None
            next_cursor: str | None = None
            for _ in range(MAX_HISTORY_PAGES):
                query: dict[str, int | str] = {"limit": PAGE_SIZE, "offset": len(seen)}
                if orders:
                    query["version"] = 2
                    if next_cursor is not None:
                        query["next"] = next_cursor
                page = await read(path, query)
                if not isinstance(page, dict):
                    raise ProductionHistoryError("history page is not an object")
                rows, count = page.get("list"), page.get("count")
                if (
                    type(count) is not int
                    or not 0 <= count <= MAX_HISTORY_ROWS
                    or not isinstance(rows, list)
                    or len(rows) > PAGE_SIZE
                ):
                    raise ProductionHistoryError("history pagination is malformed or exceeds its bound")
                if expected is not None and count != expected:
                    raise ProductionHistoryError("history count changed during pagination")
                expected = count
                for row in rows:
                    if not isinstance(row, dict):
                        raise ProductionHistoryError("history row is not an object")
                    identity = row.get("id")
                    if not isinstance(identity, str) or not 1 <= len(identity) <= 160 or identity in seen:
                        raise ProductionHistoryError("history row ID is absent, duplicate or unbounded")
                    if orders and (
                        isinstance(row.get("user"), bool)
                        or str(row.get("user")) != self.context.remote_account_id
                    ):
                        raise ProductionHistoryError(
                            "history row belongs to a different authenticated account"
                        )
                    if "user" in row and str(row["user"]) != self.context.remote_account_id:
                        raise ProductionHistoryError("history row account contradicts the capture")
                    seen.add(identity)
                cursor = page.get("next")
                if cursor is not None and (not isinstance(cursor, str) or len(cursor) > 2048):
                    raise ProductionHistoryError("history next cursor is malformed")
                if cursor:
                    if not orders or cursor in cursors:
                        raise ProductionHistoryError("history next cursor is unsupported or repeated")
                    cursors.add(cursor)
                if len(seen) == expected:
                    if cursor:
                        raise ProductionHistoryError("history next cursor contradicts exhausted count")
                    return len(seen)
                if not rows or len(seen) > expected:
                    raise ProductionHistoryError("history pagination ended before its reported count")
                next_cursor = cursor or None
            raise ProductionHistoryError("history pagination exceeded its page bound")

        try:
            async with asyncio.timeout(self.max_seconds):
                account(await read("/api/user/me"))
                order_count = await pages("/api/order", orders=True)
                protection_count = await pages("/api/tpsl", orders=False)
                funding = await read("/api/user/funding")
                if not isinstance(funding, list) or len(funding) > MAX_HISTORY_ROWS:
                    raise ProductionHistoryError("funding balance response is not a bounded array")
                account(await read("/api/user/me"))
                finished = _utc(self.clock())
                if finished < previous or (finished - started).total_seconds() > self.max_seconds:
                    raise ProductionHistoryError("history capture exceeded its clock bounds")
        except asyncio.CancelledError:
            raise
        except ProductionHistoryError:
            raise
        except TimeoutError:
            raise ProductionHistoryError("history capture timed out; partial result discarded") from None
        except Exception:
            raise ProductionHistoryError("history read failed or returned malformed parsed JSON") from None
        return ProductionHistoryCaptureV1(
            context=self.context,
            account_id=self.context.remote_account_id,
            collection_started_at=started,
            collection_finished_at=finished,
            components=tuple(components),
            order_count=order_count,
            protection_count=protection_count,
        )


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
        raise ProductionHistoryError("history timestamps must be explicit UTC")
    return value
