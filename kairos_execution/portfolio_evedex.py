"""EVEDEX REST access: public market data, API-key reads and signed order writes.

Signing mirrors the official SDK (@evedex/exchange-crypto 1.1.0, exchange-bot-sdk
1.2.11): the EIP-712 message carries integers scaled by 1e8, the REST body carries
plain decimal strings, ``chainId`` is sent as a string and the TP/SL ``order`` link is
not part of the signed message. Parity with the SDK is covered by tests.

Writes are never retried here. A 4xx answer means the venue refused the request
(``Rejected``); a timeout, network error or 5xx means the outcome is unknown
(``Unknown``) and the caller must reconcile before doing anything else.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import ROUND_DOWN, ROUND_HALF_UP, ROUND_UP, Decimal
from typing import Any

import aiohttp

from .crypto import EIP712_SCHEMAS

MARKET_DATA = "https://market-data-api.evedex.com"
EXCHANGE = "https://exchange-api.evedex.com"
TRADING = "https://trading-api.evedex.com"
USER_AGENT = "kairos-execution-engine/portfolio-v1"

MATCHER = Decimal(10) ** 8
ORDER_ID_EPOCH = datetime(2025, 7, 24, tzinfo=UTC)
GROUP_MS = {"1m": 60_000, "5m": 300_000, "15m": 900_000, "1h": 3_600_000}  # venue candle groups
ACTIVE_TPSL = {"waitOrder", "active", "process"}
TPSL_PAGE = 100

DOMAIN = {
    "name": "EVEDEX",
    "version": "2",
    "salt": "0x5792f7333c35db190e30acc144f049fd15b24f552c0010b8b3e06f9105c37c5a",
}
DOMAIN_TYPE = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
    {"name": "salt", "type": "bytes32"},
]
TYPES = {
    "New limit order": EIP712_SCHEMAS["New limit order"]["New limit order"],
    "New market order": [
        {"name": "id", "type": "string"},
        {"name": "instrument", "type": "string"},
        {"name": "side", "type": "string"},
        {"name": "timeInForce", "type": "string"},
        {"name": "leverage", "type": "uint8"},
        {"name": "cashQuantity", "type": "uint96"},
        {"name": "chainId", "type": "uint256"},
    ],
    "Position close order": [
        {"name": "id", "type": "string"},
        {"name": "instrument", "type": "string"},
        {"name": "leverage", "type": "uint8"},
        {"name": "quantity", "type": "uint96"},
        {"name": "chainId", "type": "uint256"},
    ],
    "New take-profit/stop-loss": [
        {"name": "instrument", "type": "string"},
        {"name": "type", "type": "string"},
        {"name": "side", "type": "string"},
        {"name": "quantity", "type": "uint96"},
        {"name": "price", "type": "uint80"},
    ],
}


def dec(value: Any) -> Decimal:
    """Exact decimal from a JSON number or string; rejects NaN and infinities."""
    if isinstance(value, bool) or value is None:
        raise ValueError("numeric value is missing")
    result = value if isinstance(value, Decimal) else Decimal(str(value))
    if not result.is_finite():
        raise ValueError("numeric value is not finite")
    return result


def plain(value: Decimal) -> str:
    """Decimal string as the SDK sends it: 8 places, half up, no trailing zeros."""
    rounded = value.quantize(Decimal("0.00000001"), rounding=ROUND_HALF_UP)
    text = format(rounded.normalize(), "f")
    return "0" if text in ("-0", "0") else text


def eth_number(value: Decimal) -> int:
    """Integer scaled by 1e8, as signed by the SDK's ``toEthNumber``."""
    return int((dec(plain(value)) * MATCHER).quantize(Decimal(1), rounding=ROUND_HALF_UP))


def new_order_id(now: datetime | None = None) -> str:
    """Order ID v2: days since 2025-07-24, zero padded to 5, then 26 hex characters."""
    moment = now or datetime.now(UTC)
    return f"{(moment - ORDER_ID_EPOCH).days:05d}:{uuid.uuid4().hex[:26]}"


def floor_step(value: Decimal, step: Decimal) -> Decimal:
    return (value / step).to_integral_value(rounding=ROUND_DOWN) * step


def ceil_step(value: Decimal, step: Decimal) -> Decimal:
    return (value / step).to_integral_value(rounding=ROUND_UP) * step


class EvedexError(RuntimeError):
    def __init__(self, message: str, *, status: int | None = None, body: str = "") -> None:
        super().__init__(message)
        self.status = status
        self.body = body


class Rejected(EvedexError):
    """The venue answered with a 4xx: the request was refused and had no effect."""

    @property
    def label(self) -> str:
        """The venue's machine-readable error label, for example ``invalid_signature_error``."""
        try:
            value = json.loads(self.body).get("label", "")
        except (ValueError, AttributeError):
            return ""
        return value if isinstance(value, str) else ""


class Unknown(EvedexError):
    """Timeout, network failure or 5xx: the request may or may not have had an effect."""


@dataclass(frozen=True, slots=True)
class Instrument:
    name: str
    min_quantity: Decimal
    quantity_step: Decimal
    price_step: Decimal
    min_volume: Decimal
    tradable: bool
    max_leverage: int = 1  # the venue's own maximum for this instrument


@dataclass(frozen=True, slots=True)
class Book:
    time_ms: int
    bid: Decimal
    ask: Decimal
    bid_qty: Decimal = Decimal(0)  # size resting at the best bid; zero when unknown
    ask_qty: Decimal = Decimal(0)


@dataclass(frozen=True, slots=True)
class Candle:
    t: int
    o: float
    h: float
    l: float  # noqa: E741 - conventional OHLC name
    c: float
    v: float


@dataclass(frozen=True, slots=True)
class Position:
    instrument: str
    side: str  # BUY (long) or SELL (short)
    quantity: Decimal
    avg_price: Decimal
    has_stop: bool = False  # an active stop-loss is attached on the venue
    stop_id: str | None = None  # the venue's identity of that stop-loss
    venue_id: str | None = None
    user: str | None = None
    protections: tuple[dict[str, Any], ...] = ()


class OrderSigner:
    """Signs order payloads with the wallet key. Holds no withdraw schema at all."""

    def __init__(self, private_key: str, chain_id: int) -> None:
        from eth_account import Account

        self._account = Account.from_key(private_key)
        self.address: str = self._account.address
        self.chain_id = int(chain_id)

    def _sign(self, primary: str, message: dict[str, Any]) -> str:
        from eth_account.messages import encode_typed_data

        full = {
            "types": {"EIP712Domain": DOMAIN_TYPE, primary: TYPES[primary]},
            "primaryType": primary,
            "domain": {**DOMAIN, "chainId": self.chain_id},
            "message": message,
        }
        signature = self._account.sign_message(encode_typed_data(full_message=full)).signature.hex()
        return signature if signature.startswith("0x") else "0x" + signature

    def market_order(
        self,
        *,
        order_id: str,
        instrument: str,
        side: str,
        cash: Decimal,
        protection: list[dict[str, str]] | None = None,
        leverage: int = 1,
    ) -> dict[str, Any]:
        """Market IOC by cash (the position's notional, whatever the leverage).

        ``protection`` rides in the body; the venue does not sign it.
        """
        if side not in ("BUY", "SELL") or cash <= 0:
            raise ValueError("market order needs BUY/SELL and positive cash")
        if not 1 <= int(leverage) <= 255:
            raise ValueError("leverage is a whole number within 1..255")
        base = {
            "id": order_id,
            "instrument": instrument,
            "side": side,
            "timeInForce": "IOC",
            "leverage": int(leverage),
        }
        signature = self._sign(
            "New market order", {**base, "cashQuantity": eth_number(cash), "chainId": self.chain_id}
        )
        body = {**base, "cashQuantity": plain(cash), "chainId": str(self.chain_id), "signature": signature}
        if protection:
            body["tpsl"] = protection
        return body

    def bounded_entry(
        self,
        *,
        order_id: str,
        instrument: str,
        side: str,
        quantity: Decimal,
        price: Decimal,
        leverage: int,
        protection: list[dict[str, str]],
    ) -> dict[str, Any]:
        """Native limit GTC. Both base quantity and limit price enter the signature."""
        if side not in {"BUY", "SELL"} or not 1 <= leverage <= 30:
            raise ValueError("invalid portfolio limit order")
        if any(value <= 0 or Decimal(plain(value)) != value for value in (price, quantity)):
            raise ValueError("limit order geometry exceeds EVEDEX precision")
        base = {"id": order_id, "instrument": instrument, "side": side, "leverage": leverage}
        signature = self._sign(
            "New limit order",
            {
                **base,
                "quantity": eth_number(quantity),
                "limitPrice": eth_number(price),
                "chainId": self.chain_id,
            },
        )
        return {
            **base,
            "quantity": plain(quantity),
            "limitPrice": plain(price),
            "chainId": str(self.chain_id),
            "tpsl": protection,
            "signature": signature,
        }

    def close_order(
        self, *, order_id: str, instrument: str, quantity: Decimal, leverage: int = 1
    ) -> dict[str, Any]:
        if quantity <= 0:
            raise ValueError("close quantity must be positive")
        if not 1 <= int(leverage) <= 255:
            raise ValueError("leverage is a whole number within 1..255")
        base = {"id": order_id, "instrument": instrument, "leverage": int(leverage)}
        signature = self._sign(
            "Position close order", {**base, "quantity": eth_number(quantity), "chainId": self.chain_id}
        )
        return {**base, "quantity": plain(quantity), "chainId": str(self.chain_id), "signature": signature}

    def tpsl(
        self, *, instrument: str, kind: str, side: str, quantity: Decimal, price: Decimal
    ) -> dict[str, Any]:
        if kind not in ("stop-loss", "take-profit") or side not in ("BUY", "SELL"):
            raise ValueError("TP/SL kind or side is invalid")
        if quantity < 0 or price <= 0:
            raise ValueError("TP/SL quantity must not be negative (zero means the full position)")
        base = {"instrument": instrument, "type": kind, "side": side}
        signature = self._sign(
            "New take-profit/stop-loss",
            {**base, "quantity": eth_number(quantity), "price": eth_number(price)},
        )
        return {
            **base,
            "quantity": plain(quantity),
            "price": plain(price),
            "order": None,
            "signature": signature,
        }


def _rows(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict) and isinstance(value.get("list"), list):
        value = value["list"]
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise EvedexError("venue returned an unexpected list shape")
    return value


def _complete_rows(value: Any) -> list[dict[str, Any]]:
    rows = _rows(value)
    if isinstance(value, dict) and "count" in value and value["count"] != len(rows):
        raise EvedexError("venue returned an incomplete account projection")
    return rows


class Evedex:
    """Small async client. ``api_key`` is needed only for private calls."""

    def __init__(self, session: aiohttp.ClientSession, api_key: str | None = None) -> None:
        self._session = session
        self._api_key = api_key

    async def _request(
        self,
        method: str,
        url: str,
        *,
        private: bool = False,
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
    ) -> Any:
        headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
        if private:
            if not self._api_key:
                raise EvedexError("an EVEDEX API key is required for this call")
            headers["x-api-key"] = self._api_key
        attempts = 3 if method == "GET" else 1
        last: Exception | None = None
        for attempt in range(attempts):
            try:
                async with self._session.request(
                    method,
                    url,
                    params=params,
                    json=body,
                    headers=headers,
                    allow_redirects=False,
                    timeout=aiohttp.ClientTimeout(total=12),
                ) as response:
                    text = await response.text()
                    status = response.status
            except (TimeoutError, aiohttp.ClientError) as exc:
                last = Unknown(f"{method} {url.split('?')[0]} failed: {type(exc).__name__}")
                if attempt + 1 < attempts:
                    await asyncio.sleep(0.5 * (attempt + 1))
                continue
            if 200 <= status < 300:
                if not text.strip():
                    return None
                try:
                    return json.loads(text, parse_float=Decimal)
                except json.JSONDecodeError as exc:
                    raise Unknown("venue returned a non-JSON success body", status=status) from exc
            snippet = text[:400]
            if status == 429 and attempt + 1 < attempts:
                await asyncio.sleep(1.5 * (attempt + 1))  # rate limited read: wait and ask again
                continue
            if 400 <= status < 500 and status not in {408, 409, 425, 429}:
                raise Rejected(
                    f"{method} {url.split('?')[0]} refused: HTTP {status}", status=status, body=snippet
                )
            last = Unknown(f"{method} {url.split('?')[0]} failed: HTTP {status}", status=status, body=snippet)
            if attempt + 1 < attempts:
                await asyncio.sleep(0.5 * (attempt + 1))
        if last is None:
            raise Unknown(f"{method} {url.split('?')[0]} failed without an answer")
        raise last

    # ---- public market data -------------------------------------------------

    async def instruments(self) -> dict[str, Instrument]:
        rows = _rows(
            await self._request("GET", f"{TRADING}/api/market/instrument", params={"fields": "metrics"})
        )
        result = {}
        for row in rows:
            try:
                result[str(row["name"])] = Instrument(
                    name=str(row["name"]),
                    min_quantity=dec(row["minQuantity"]),
                    quantity_step=dec(row["quantityIncrement"]),
                    price_step=dec(row["priceIncrement"]),
                    min_volume=dec(row["minVolume"]),
                    tradable=row.get("trading") == "all" and row.get("marketState") == "OPEN",
                    max_leverage=max(1, int(row.get("maxLeverage") or 1)),
                )
            except (KeyError, ValueError):
                continue
        return result

    async def metrics(self) -> dict[str, dict[str, Any]]:
        """Public per-instrument context: funding, open interest, 24h volume and range."""
        rows = _rows(
            await self._request("GET", f"{TRADING}/api/market/instrument", params={"fields": "metrics"})
        )
        result: dict[str, dict[str, Any]] = {}
        for row in rows:
            try:
                last = float(row["lastPrice"])
                high, low = float(row["high"]), float(row["low"])
                result[str(row["name"])] = {
                    "funding_rate_pct": round(float(row["fundingRate"]) * 100, 5),
                    "funding_interval_hours": row.get("fundingRateInterval"),
                    "open_interest_usd": round(float(row["openInterest"]) * last),
                    "volume_24h_usd": round(float(row["volumeBase"])),
                    "mark_vs_last_bps": round((float(row["markPrice"]) / last - 1) * 1e4, 2),
                    "position_in_24h_range": round((last - low) / (high - low), 3) if high > low else None,
                }
            except (KeyError, TypeError, ValueError, ZeroDivisionError):
                continue
        return result

    async def server_time_ms(self) -> int:
        value = await self._request("GET", f"{TRADING}/api/ping")
        try:
            return int(value["time"])
        except (KeyError, TypeError, ValueError) as exc:
            raise EvedexError("ping answer is malformed") from exc

    async def taker_fee(self) -> Decimal:
        market = await self._request("GET", f"{EXCHANGE}/api/market")
        if not isinstance(market, dict) or market.get("state") != "active":
            raise EvedexError("market state is not active")
        return dec(market["fees"]["taker"])

    async def book(self, instrument: str) -> Book:
        raw = await self._request(
            "GET", f"{EXCHANGE}/api/market/{instrument}/deep", params={"marketLevel": 1}
        )
        try:
            bid, ask = dec(raw["bids"][0]["price"]), dec(raw["asks"][0]["price"])
            moment = int(raw["t"])
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise EvedexError(f"order book for {instrument} is empty or malformed") from exc
        if bid <= 0 or ask <= bid:
            raise EvedexError(f"order book for {instrument} is crossed or empty")
        try:
            bid_qty, ask_qty = dec(raw["bids"][0]["quantity"]), dec(raw["asks"][0]["quantity"])
        except (KeyError, TypeError, ValueError):
            bid_qty = ask_qty = Decimal(0)
        return Book(moment, bid, ask, bid_qty, ask_qty)

    async def candles(self, instrument: str, group: str, start_ms: int, end_ms: int) -> list[Candle]:
        """Bars of one timeframe, oldest first. ``Candle.v`` is the quote volume."""
        rows = await self.candle_rows(instrument, group, start_ms, end_ms)
        return [Candle(int(r[0]), r[1], r[2], r[3], r[4], r[6]) for r in rows]

    async def candle_rows(self, instrument: str, group: str, start_ms: int, end_ms: int) -> list[list[float]]:
        """Bars as ``[open_time_ms, open, high, low, close, base_volume, quote_volume]``, oldest first.

        The venue returns at most about a thousand rows per request, so the range is paged.
        The bar that is still forming may be included; callers drop it by time.
        """

        def iso(ms: int) -> str:
            return datetime.fromtimestamp(ms / 1000, UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        rows: dict[int, list[float]] = {}
        page_ms = 1000 * GROUP_MS[group]
        cursor = end_ms
        while cursor > start_ms:
            page_start = max(start_ms, cursor - page_ms)
            raw = await self._request(
                "GET",
                f"{MARKET_DATA}/api/history/{instrument}/list",
                params={"after": iso(page_start), "before": iso(cursor), "group": group},
            )
            if not isinstance(raw, list):
                raise EvedexError("candle history is malformed")
            for r in raw:
                # Venue row order is: time, open, close, high, low, quote volume, base volume.
                rows[int(r[0])] = [
                    int(r[0]),
                    float(r[1]),
                    float(r[3]),
                    float(r[4]),
                    float(r[2]),
                    float(r[6]),
                    float(r[5]),
                ]
            cursor = page_start
        return [rows[t] for t in sorted(rows)]

    # ---- private reads ------------------------------------------------------

    async def me(self) -> dict[str, Any]:
        value = await self._request("GET", f"{TRADING}/api/user/me", private=True)
        if not isinstance(value, dict) or "exchangeId" not in value:
            raise EvedexError("account identity is malformed")
        return value

    async def balance(self) -> tuple[Decimal, Decimal]:
        """Return (funding balance, available balance) in USDT."""
        value = await self._request("GET", f"{TRADING}/api/market/available-balance", private=True)
        try:
            if str(value["currency"]).lower() != "usdt":
                raise EvedexError("only USDT collateral is supported")
            return dec(value["funding"]["balance"]), dec(value["availableBalance"])
        except (KeyError, TypeError, ValueError) as exc:
            raise EvedexError("balance is malformed") from exc

    async def positions(self) -> list[Position]:
        rows = _complete_rows(
            await self._request("GET", f"{TRADING}/api/position", private=True, params={"withTpSL": "yes"})
        )
        result = []
        for row in rows:
            quantity = dec(row["quantity"])
            if quantity != 0:
                if (
                    not isinstance(row.get("instrument"), str)
                    or not row["instrument"]
                    or not isinstance(row.get("id"), str)
                    or not row["id"]
                    or row.get("user") is None
                    or not str(row["user"])
                    or row.get("side") not in {"BUY", "SELL"}
                    or dec(row.get("avgPrice")) <= 0
                ):
                    raise EvedexError("venue returned an incomplete open position")
                tpsl_rows = row.get("tpslList")
                attached = tpsl_rows if isinstance(tpsl_rows, list) else []
                stops = [
                    item
                    for item in attached
                    if isinstance(item, dict)
                    and item.get("type") == "stop-loss"
                    and item.get("status") in ACTIVE_TPSL
                ]
                has_stop = bool(stops)
                stop_id = str(stops[0].get("id")) if stops and stops[0].get("id") else None
                result.append(
                    Position(
                        str(row["instrument"]),
                        str(row["side"]),
                        abs(quantity),
                        dec(row.get("avgPrice", 0)),
                        has_stop,
                        stop_id,
                        row.get("id"),
                        str(row["user"]) if row.get("user") is not None else None,
                        tuple(attached) if all(isinstance(child, dict) for child in attached) else (),
                    )
                )
        return result

    async def open_orders(self) -> list[dict[str, Any]]:
        return _complete_rows(await self._request("GET", f"{TRADING}/api/order/opened", private=True))

    async def position_version_closed(self, instrument: str, version: int) -> bool:
        """Check the actual filtered history rows. EVEDEX's count can include other versions."""
        page = await self._request(
            "GET",
            f"{TRADING}/api/position/history",
            private=True,
            params={"instrument": instrument, "version": version, "limit": 2, "offset": 0},
        )
        if not isinstance(page, dict) or not isinstance(page.get("list"), list) or page.get("next"):
            raise EvedexError("position history lacks its filtered list")
        rows = _rows(page)
        if rows and (
            len(rows) != 1
            or rows[0].get("instrument") != instrument
            or rows[0].get("version") != version
            or not rows[0].get("closeAt")
        ):
            raise EvedexError("position history returned an ambiguous generation")
        return bool(rows)

    async def position_version_orders(self, instrument: str, version: int) -> list[dict[str, Any]]:
        """A generation with more than one complete page needs manual reconciliation."""
        page = await self._request(
            "GET",
            f"{TRADING}/api/order",
            private=True,
            params={"instrument": instrument, "version": version, "limit": 100, "offset": 0},
        )
        if not isinstance(page, dict) or type(page.get("count")) is not int:
            raise EvedexError("position generation order list lacks a count")
        return _complete_rows(page)

    async def order(self, order_id: str) -> dict[str, Any] | None:
        try:
            value = await self._request("GET", f"{TRADING}/api/order/{order_id}", private=True)
        except Rejected as exc:
            if exc.status == 404:
                return None
            raise
        return value if isinstance(value, dict) else None

    async def order_with_protections(self, instrument: str, order_id: str) -> dict[str, Any] | None:
        """Read the exact parent across position versions. A position version is not an API version."""
        params: dict[str, Any] = {
            "instrument": instrument,
            "withTpSL": "yes",
            "limit": 100,
            "offset": 0,
        }
        seen = set()
        for _ in range(100):
            page = await self._request("GET", f"{TRADING}/api/order", private=True, params=params)
            rows = _rows(page)
            if not isinstance(page, dict) or not isinstance(page.get("count"), int) or page["count"] < 0:
                raise EvedexError("order history lacks a complete count")
            for row in rows:
                key = row.get("id")
                if not key or key in seen or row.get("instrument") != instrument:
                    raise EvedexError("order history has a repeated or mismatched record")
                seen.add(key)
                if key == order_id:
                    return row
            if len(seen) == page["count"]:
                return None
            if not rows or len(seen) > page["count"]:
                raise EvedexError("incomplete order history")
            params["offset"] = len(seen)
            if page.get("next"):
                params["next"] = page["next"]
        raise EvedexError("order history exceeded its pagination bound")

    async def active_tpsl(self, instrument: str | None = None) -> list[dict[str, Any]]:
        """TP/SL records that can still fire. Filtered on the venue and again locally."""
        result: dict[str, dict[str, Any]] = {}
        for status in sorted(ACTIVE_TPSL):
            params: dict[str, Any] = {"status": status, "limit": TPSL_PAGE, "offset": 0}
            if instrument is not None:
                params["instrument"] = instrument
            seen: set[str] = set()
            for page in range(100):
                params["offset"] = page * TPSL_PAGE
                rows = _rows(await self._request("GET", f"{TRADING}/api/tpsl", private=True, params=params))
                for row in rows:
                    key = row.get("id")
                    if not isinstance(key, str) or not key or key in seen:
                        raise EvedexError("incomplete or conflicting TP/SL page")
                    seen.add(key)
                    if row.get("status") in ACTIVE_TPSL and (
                        instrument is None or row.get("instrument") == instrument
                    ):
                        result[key] = row
                if len(rows) < TPSL_PAGE:
                    break
            else:
                raise EvedexError("TP/SL pagination bound exceeded")
        return list(result.values())

    # ---- signed writes ------------------------------------------------------

    async def post_limit_order(self, body: dict[str, Any]) -> dict[str, Any]:
        return await self._request("POST", f"{TRADING}/api/v2/order/limit", private=True, body=body)

    async def cancel_order(self, order_id: str) -> None:
        await self._request("DELETE", f"{TRADING}/api/order/{order_id}", private=True)

    async def post_market_order(self, body: dict[str, Any]) -> dict[str, Any]:
        return await self._request("POST", f"{TRADING}/api/v2/order/market", private=True, body=body)

    async def post_close(self, body: dict[str, Any]) -> dict[str, Any]:
        return await self._request(
            "POST", f"{TRADING}/api/v2/position/{body['instrument']}/close", private=True, body=body
        )

    async def post_tpsl(self, body: dict[str, Any]) -> dict[str, Any]:
        return await self._request(
            "POST", f"{TRADING}/api/tpsl/{body['instrument']}", private=True, body=body
        )

    async def set_leverage(self, instrument: str, leverage: int) -> None:
        """Change the account's leverage setting for one instrument (an API-key call, not signed)."""
        await self._request(
            "PUT", f"{TRADING}/api/position/{instrument}", private=True, body={"leverage": int(leverage)}
        )

    async def cancel_tpsl(self, instrument: str, tpsl_id: str) -> None:
        await self._request("DELETE", f"{TRADING}/api/tpsl/{instrument}/{tpsl_id}", private=True)
