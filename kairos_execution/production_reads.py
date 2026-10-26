"""Native PROD REST projections, not account/recovery or LIVE authority.

The legacy ``fetch_paper_state`` name is only the lifecycle DTO interface. This
reader uses the existing API-key PROD process, never a DEV wallet or signer.
Every component retains its original HTTP capture. Sequential REST responses
are explicitly not an atomic account revision or a recoverable event stream.
"""

from __future__ import annotations

import re
from datetime import datetime
from decimal import Decimal
from typing import Any

from .production_transport import (
    FUNDING_TRANSFER_TYPES,
    ProductionEvedexSdkClient,
    ProductionTransportError,
    _raw_capture_request,
    parse_raw_response_capture,
)


class ProductionReadUnavailable(ProductionTransportError):
    """The pinned native source cannot establish the requested read fact."""


class ProductionEvedexReads:
    """Read-only DTO binding to one exact production SDK client/account."""

    name = "evedex"
    protective_stop_lookup_authoritative = False

    def __init__(self, client: ProductionEvedexSdkClient, *, symbol_map: dict[str, str]):
        if not isinstance(client, ProductionEvedexSdkClient):
            raise TypeError("the exact PROD SDK client is required")
        if not symbol_map or any(
            not isinstance(key, str)
            or not key
            or not isinstance(value, str)
            or re.fullmatch(r"[A-Z0-9]{1,32}", value) is None
            for key, value in symbol_map.items()
        ):
            raise ValueError("explicit PROD symbol mapping is required")
        normalized = {key.upper(): value for key, value in symbol_map.items()}
        if len(normalized) != len(symbol_map) or len(set(normalized.values())) != len(normalized):
            raise ValueError("PROD symbol mapping must be one-to-one")
        self.client = client
        self.expected_account_id = client.expected_account_id
        self.symbol_map = normalized
        self._preflight_complete = False
        self.last_captures: dict[str, dict[str, Any]] = {}

    async def _read(self, source: str, **kwargs: Any) -> Any:
        if not self._preflight_complete:
            raise ProductionReadUnavailable("explicit PROD reader preflight is required")
        payload, query = _raw_capture_request(
            source,
            version=kwargs.get("version"),
            limit=kwargs.get("limit"),
            offset=kwargs.get("offset"),
            next_cursor=kwargs.get("next_cursor"),
            instrument=kwargs.get("instrument"),
            max_level=kwargs.get("max_level"),
            order_id=kwargs.get("order_id"),
            after=kwargs.get("after"),
            before=kwargs.get("before"),
            transfer_type=kwargs.get("transfer_type"),
        )
        capture = await self.client.fetch_raw_capture(payload)
        value = parse_raw_response_capture(
            capture,
            source=source,
            expected_query=query,
            instrument=kwargs.get("instrument"),
            order_id=kwargs.get("order_id"),
        )
        if not 200 <= capture["status"] < 300:
            raise ProductionReadUnavailable("PROD native read returned a non-success HTTP status")
        self.last_captures[source] = dict(capture)
        return value

    async def preflight(self) -> dict[str, Any]:
        await self.client.preflight()
        self._preflight_complete = True
        try:
            identity = self._object(await self._read("account_identity"))
            account_capture = dict(self.last_captures["account_identity"])
            if str(identity.get("exchangeId", "")) != self.expected_account_id:
                raise ProductionReadUnavailable("native PROD account identity differs from bound account")
            instruments = self._list(await self._read("instruments"))
            instrument_capture = dict(self.last_captures["instruments"])
            for instrument in self.symbol_map.values():
                if sum(item.get("name") == instrument for item in instruments) != 1:
                    raise ProductionReadUnavailable("native PROD instrument metadata is absent or duplicated")
            health = await self.client.read_health()
        except BaseException:
            self._preflight_complete = False
            raise
        return {
            **health,
            "read_authenticated": True,
            "live_ready": False,
            "account_revision_authoritative": False,
            "recoverable_events_available": False,
            "protection_parent_lineage_available": False,
            "account_capture": account_capture,
            "instrument_capture": instrument_capture,
        }

    async def _pages(self, source: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        records: list[dict[str, Any]] = []
        captures = []
        identities: set[str] = set()
        expected_count = None
        next_cursor = None
        seen_cursors: set[str] = set()
        for offset in range(0, 10_001, 100):
            kwargs: dict[str, Any] = {"limit": 100, "offset": offset}
            if source == "order_page":
                kwargs["version"] = 2
                if next_cursor is not None:
                    kwargs["next_cursor"] = next_cursor
            page = self._object(await self._read(source, **kwargs))
            captures.append(dict(self.last_captures[source]))
            count = self._integer(page.get("count"), "native page count", maximum=10_000)
            if expected_count is None:
                expected_count = count
            if count != expected_count:
                raise ProductionReadUnavailable("native PROD history changed during bounded pagination")
            rows = self._list(page.get("list"))
            if len(rows) > 100:
                raise ProductionReadUnavailable("native PROD page exceeds requested size")
            for item in rows:
                identity = item.get("id")
                if not isinstance(identity, str) or not identity or identity in identities:
                    raise ProductionReadUnavailable("native PROD history identities are absent or repeated")
                identities.add(identity)
                records.append(item)
            cursor = page.get("next")
            if cursor is not None and (not isinstance(cursor, str) or not cursor or cursor in seen_cursors):
                raise ProductionReadUnavailable("native PROD pagination cursor is invalid or repeated")
            if len(records) == count:
                if cursor is not None:
                    raise ProductionReadUnavailable("native PROD pagination contradicts its terminal count")
                return records, captures
            if len(records) > count or not rows:
                raise ProductionReadUnavailable("native PROD history is incomplete or exceeds its count")
            if cursor is not None:
                if source != "order_page":
                    raise ProductionReadUnavailable("native TP/SL cursor is unsupported by pinned SDK query")
                seen_cursors.add(cursor)
            next_cursor = cursor
        raise ProductionReadUnavailable("native PROD history exceeded the bounded read contract")

    async def fetch_paper_state(self) -> dict[str, Any]:
        captures = {}
        account = self._object(await self._read("account_identity"))
        captures["account_identity"] = dict(self.last_captures["account_identity"])
        if str(account.get("exchangeId", "")) != self.expected_account_id:
            raise ProductionReadUnavailable("native account identity changed")
        native_balance = self._object(await self._read("available_balance"))
        captures["available_balance"] = dict(self.last_captures["available_balance"])
        balance = self._balance_projection(native_balance)
        positions = self._list(self._object(await self._read("positions")).get("list"))
        captures["positions"] = dict(self.last_captures["positions"])
        orders = self._list(await self._read("open_orders"))
        captures["open_orders"] = dict(self.last_captures["open_orders"])
        instruments = self._list(await self._read("instruments"))
        captures["instruments"] = dict(self.last_captures["instruments"])
        tpsl, tpsl_captures = await self._pages("tpsl_page")
        history, history_captures = await self._pages("order_page")
        return {
            "account": account,
            "balance": balance,
            "positions": positions,
            "orders": orders,
            "tpsl": tpsl,
            "order_history": history,
            "instruments": instruments,
            "native_read_captures": {
                **captures,
                "tpsl_pages": tpsl_captures,
                "order_pages": history_captures,
            },
            "account_revision_authoritative": False,
            "recoverable_events_available": False,
        }

    def _balance_projection(self, native: dict[str, Any]) -> dict[str, Any]:
        """Mirror SDK ApiKeyAccount.fetchAvailableBalance without numeric loss.

        Native ``position``/``openOrder`` are arrays. The similarly named
        deprecated plural maps are not their substitutes. Raw response bytes
        retain all native fields, including the original ``updatedAt``.
        """
        funding = self._object(native.get("funding"))
        currency = funding.get("currency")
        if not isinstance(currency, str) or not currency.strip():
            raise ProductionReadUnavailable("native funding currency is absent or malformed")
        funding_balance = self._decimal(funding.get("balance"), "native funding balance")
        available = self._decimal(native.get("availableBalance"), "native available balance")
        positions = self._balance_summaries(native.get("position"), fields=("volume", "initialMargin"))
        orders = self._balance_summaries(
            native.get("openOrder"), fields=("unFilledVolume", "unFilledInitialMargin")
        )
        return {
            "funding": {"currency": currency, "balance": str(funding_balance)},
            "positions": positions,
            "openOrders": orders,
            "availableBalance": str(available),
        }

    def _balance_summaries(self, value: Any, *, fields: tuple[str, str]) -> list[dict[str, Any]]:
        rows = self._list(value)
        for row in rows:
            if (
                not isinstance(row.get("instrument"), str)
                or re.fullmatch(r"[A-Z0-9]{1,32}", row["instrument"]) is None
                or row.get("side") not in {"BUY", "SELL"}
            ):
                raise ProductionReadUnavailable("native balance summary instrument/side is malformed")
            for field in fields:
                if self._decimal(row.get(field), f"native balance summary {field}") < 0:
                    raise ProductionReadUnavailable("native balance summary contains a negative amount")
        return rows

    async def fetch_depth(self, *, symbol: str, max_level: int = 100) -> dict[str, Any]:
        instrument = self._venue_symbol(symbol)
        depth = self._object(await self._read("depth", instrument=instrument, max_level=max_level))
        # Only lossless integral timestamp conversion; never replace the venue clock.
        timestamp = self._integer(depth.get("t"), "native depth timestamp", maximum=2**53 - 1)
        for field in ("asks", "bids"):
            for row in self._list(depth.get(field)):
                if (
                    self._decimal(row.get("price"), "native depth price") <= 0
                    or self._decimal(row.get("quantity"), "native depth quantity") <= 0
                ):
                    raise ProductionReadUnavailable("native depth contains nonpositive levels")
        return {**depth, "t": timestamp, "native_read_capture": dict(self.last_captures["depth"])}

    async def drain_events(self, *, limit: int = 1000) -> list[dict[str, Any]]:
        raise ProductionReadUnavailable(
            "pinned PROD API-key REST binding has no ordered recoverable fill/fee/funding event source"
        )

    async def fetch_order_fills(self, *, order_id: str) -> list[dict[str, Any]]:
        """Read one known V2 order's native fills, not a final-settlement marker.

        Source route: official Exchange OpenAPI ``/api/order/{orderId}/fill``.
        The path binds ownership to the caller's explicit journal order ID; no
        order or parent fields are added to the native returned rows.
        """
        rows = self._list(await self._read("order_fills", order_id=order_id))
        if len(rows) > 10_000:
            raise ProductionReadUnavailable("native per-order fill count exceeded its bound")
        seen: set[str] = set()
        for row in rows:
            self._fill_row(row, seen=seen)
            for fee in self._list(row.get("fee")):
                if not isinstance(fee.get("coin"), str) or not fee["coin"]:
                    raise ProductionReadUnavailable("native fill fee currency is absent")
                self._decimal(fee.get("quantity"), "native fill fee")
        return rows

    async def fetch_funding_transfers(
        self,
        *,
        after: str,
        before: str,
        transfer_type: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> dict[str, Any]:
        """One bounded native funding page; rows have no stable provider ID.

        Duplicate-looking rows remain distinct. Never deduplicate them by a
        locally generated hash, infer trade linkage, or declare finality. The
        explicit millisecond-Z interval is locally bounded to at most one day.
        """
        page = self._object(
            await self._read(
                "funding_transfers",
                after=after,
                before=before,
                transfer_type=transfer_type,
                limit=limit,
                offset=offset,
            )
        )
        for row in self._history_page(page, limit=limit):
            if row.get("type") not in FUNDING_TRANSFER_TYPES or (
                transfer_type is not None and row.get("type") != transfer_type
            ):
                raise ProductionReadUnavailable("native funding transfer type differs from documented query")
            if not isinstance(row.get("coin"), str) or not row["coin"]:
                raise ProductionReadUnavailable("native funding transfer currency is absent")
            self._decimal(row.get("quantity"), "native funding transfer quantity")
            self._original_timestamp(row.get("createdAt"))
        return page

    async def fetch_fill_history(
        self,
        *,
        after: str,
        before: str,
        symbol: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> dict[str, Any]:
        """One explicit-window native /api/fill page, not an account revision.

        Pagination is explicit by offset (the published request has no `next`
        parameter). Returning a page does not claim all pages were consumed.
        No history endpoint is automatically queried by lifecycle polling.
        """
        instrument = None if symbol is None else self._venue_symbol(symbol)
        page = self._object(
            await self._read(
                "fill_history",
                after=after,
                before=before,
                instrument=instrument,
                limit=limit,
                offset=offset,
            )
        )
        seen: set[str] = set()
        for row in self._history_page(page, limit=limit):
            self._fill_row(row, seen=seen)
            if (
                not isinstance(row.get("order"), str)
                or not row["order"]
                or not isinstance(row.get("instrument"), str)
                or not row["instrument"]
                or (instrument is not None and row["instrument"] != instrument)
                or row.get("fillRole") not in {"MAKER", "TAKER", "NONE"}
                or not isinstance(row.get("matchId"), str)
                or not row["matchId"]
            ):
                raise ProductionReadUnavailable(
                    "native fill history linkage fields are absent or inconsistent"
                )
        return page

    def _fill_row(self, row: dict[str, Any], *, seen: set[str]) -> None:
        identity = row.get("id")
        if not isinstance(identity, str) or not identity or identity in seen:
            raise ProductionReadUnavailable("native fill identity is absent or duplicated")
        seen.add(identity)
        if (
            self._decimal(row.get("fillQuantity"), "native fill quantity") <= 0
            or self._decimal(row.get("fillPrice"), "native fill price") <= 0
        ):
            raise ProductionReadUnavailable("native fill geometry is nonpositive")
        self._original_timestamp(row.get("createdAt"))

    def _history_page(self, page: dict[str, Any], *, limit: int) -> list[dict[str, Any]]:
        count = self._integer(page.get("count"), "native history count", maximum=10_000)
        rows = self._list(page.get("list"))
        if len(rows) > limit or len(rows) > count or (count > 0 and not rows):
            raise ProductionReadUnavailable("native bounded history page is incomplete or exceeds its count")
        cursor = page.get("next")
        if cursor is not None and (not isinstance(cursor, str) or not cursor or len(cursor) > 500):
            raise ProductionReadUnavailable("native bounded history cursor is malformed")
        if len(rows) == count and cursor is not None:
            raise ProductionReadUnavailable("native history terminal count contradicts its cursor")
        return rows

    @staticmethod
    def _original_timestamp(value: Any) -> None:
        try:
            if (
                not isinstance(value, str)
                or datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is None
            ):
                raise ValueError
        except (ValueError, TypeError):
            raise ProductionReadUnavailable("native history timestamp is absent or malformed") from None

    async def find_tpsl_record(
        self,
        *,
        symbol: str,
        tpsl_id: str | None = None,
        tpsl_type: str | None = None,
        price: Any = None,
        parent_order_id: str | None = None,
    ) -> dict[str, Any] | None:
        instrument = self._venue_symbol(symbol)
        if parent_order_id is not None:
            raise ProductionReadUnavailable(
                "native TP/SL DTO has no parent-entry lineage; triggerOrder is not parent"
            )
        rows, _ = await self._pages("tpsl_page")
        matches = []
        for item in rows:
            if item.get("instrument") != instrument or (tpsl_id is not None and item.get("id") != tpsl_id):
                continue
            if tpsl_type is not None and item.get("type") != tpsl_type.casefold().replace("_", "-"):
                continue
            if price is not None:
                try:
                    actual, expected = Decimal(str(item["price"])), Decimal(str(price))
                    if not actual.is_finite() or not expected.is_finite() or actual != expected:
                        continue
                except (KeyError, ValueError, ArithmeticError):
                    raise ProductionReadUnavailable("native TP/SL price is malformed") from None
            matches.append(item)
        if len(matches) > 1:
            raise ProductionReadUnavailable("native PROD protection lookup is ambiguous")
        return matches[0] if matches else None

    def _venue_symbol(self, symbol: str) -> str:
        if not isinstance(symbol, str) or symbol.upper() not in self.symbol_map:
            raise ProductionReadUnavailable("symbol is outside explicit PROD mapping")
        return self.symbol_map[symbol.upper()]

    @staticmethod
    def _decimal(value: Any, label: str) -> Decimal:
        if isinstance(value, bool) or not isinstance(value, (int, Decimal, str)):
            raise ProductionReadUnavailable(f"{label} is absent or not an exact decimal")
        try:
            number = Decimal(value)
        except (ValueError, ArithmeticError):
            raise ProductionReadUnavailable(f"{label} is not an exact decimal") from None
        if not number.is_finite():
            raise ProductionReadUnavailable(f"{label} is not finite")
        return number

    @staticmethod
    def _integer(value: Any, label: str, *, maximum: int | None = None) -> int:
        if isinstance(value, bool) or not isinstance(value, (int, Decimal)):
            raise ProductionReadUnavailable(f"{label} is not an exact integer")
        if isinstance(value, Decimal) and (not value.is_finite() or value != value.to_integral_value()):
            raise ProductionReadUnavailable(f"{label} is not an exact integer")
        if value < 0 or (maximum is not None and value > maximum):
            raise ProductionReadUnavailable(f"{label} exceeds its bounds")
        return int(value)

    @staticmethod
    def _object(value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise ProductionReadUnavailable("native PROD object is absent or malformed")
        return value

    @staticmethod
    def _list(value: Any) -> list[dict[str, Any]]:
        if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
            raise ProductionReadUnavailable("native PROD list is absent or malformed; absence is not empty")
        return value

    async def close(self) -> None:
        await self.client.close()
