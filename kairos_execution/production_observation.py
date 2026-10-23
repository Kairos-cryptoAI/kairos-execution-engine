"""Read-only, account-bound EVEDEX PROD observations.

This module deliberately has no signer, EIP-712 chain, trading operation,
readiness promotion, or authority to create signing exposure records. The
result is a bounded capture of independently fetched REST components, not an
atomic venue snapshot or authoritative reconciliation receipt.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import Field, model_validator

from .adapters.evedex import EvedexAdapter
from .production_readiness import Digest, ProductionContextV1, StrictRecord

PROD_EXCHANGE_ORIGIN = "https://trading-api.evedex.com"
MAX_CAPTURE_SECONDS = 5.0
MAX_COMPONENT_BYTES = 2_000_000
MAX_COMPONENT_ROWS = 10_000
READ_PATHS = frozenset(
    {"/api/user/me", "/api/market/available-balance", "/api/position", "/api/order/opened", "/api/tpsl"}
)
ComponentName = Literal[
    "account_before", "available_balance", "positions", "open_orders", "tpsl", "account_after"
]


class ProductionObservationError(PermissionError):
    """Sanitized refusal to capture a bounded production account observation."""


GetJson = Callable[[str], Awaitable[Any]]
Clock = Callable[[], datetime]


def _credential_headers(jwt: str | None, api_key: str | None) -> dict[str, str]:
    if (jwt is None) == (api_key is None):
        raise ValueError("authenticated production reads require exactly one JWT or API key")
    credential = jwt if jwt is not None else api_key
    if (
        not isinstance(credential, str)
        or not 1 <= len(credential) <= 8192
        or any(not 33 <= ord(character) <= 126 for character in credential)
    ):
        raise ValueError("authenticated production reads require a nonempty bounded credential")
    return {"Authorization": f"Bearer {credential}"} if jwt is not None else {"x-api-key": credential}


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate response field")
        result[key] = value
    return result


@dataclass(frozen=True, slots=True)
class _Read:
    name: ComponentName
    started_at: datetime
    finished_at: datetime
    raw_json: str
    raw_sha256: str
    normalized_json: str
    normalized_sha256: str


class ProductionObservationComponentV1(StrictRecord):
    """Canonical parsed endpoint JSON, not original HTTP bytes or server time."""

    name: ComponentName
    started_at: datetime
    finished_at: datetime
    raw_payload_json: str = Field(max_length=MAX_COMPONENT_BYTES)
    raw_sha256: Digest
    normalized_payload_json: str = Field(max_length=MAX_COMPONENT_BYTES)
    normalized_sha256: Digest

    @model_validator(mode="after")
    def verify_content(self) -> ProductionObservationComponentV1:
        for value in (self.started_at, self.finished_at):
            if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
                raise ValueError("component timestamps must be explicit UTC")
        if self.finished_at < self.started_at:
            raise ValueError("component retrieval bounds are reversed")
        for payload, digest in (
            (self.raw_payload_json, self.raw_sha256),
            (self.normalized_payload_json, self.normalized_sha256),
        ):
            if hashlib.sha256(payload.encode("utf-8")).hexdigest() != digest:
                raise ValueError("component content digest mismatch")
        return self


class ProductionAccountObservationV1(StrictRecord):
    """Bounded read-only account capture; explicitly not current-state authority."""

    version: Literal["kairos.production-account-observation.v1"] = "kairos.production-account-observation.v1"
    context: ProductionContextV1
    exchange_account_id: str
    captured_started_at: datetime
    captured_finished_at: datetime
    components: tuple[ProductionObservationComponentV1, ...]
    authoritative_reconciliation: Literal[False] = False
    readiness: Literal[False] = False

    @model_validator(mode="after")
    def verify_scope_and_bounds(self) -> ProductionAccountObservationV1:
        if self.exchange_account_id != self.context.remote_account_id:
            raise ValueError("observation account differs from its production context")
        for value in (self.captured_started_at, self.captured_finished_at):
            if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
                raise ValueError("capture timestamps must be explicit UTC")
        if self.captured_finished_at < self.captured_started_at:
            raise ValueError("capture bounds are reversed")
        if (self.captured_finished_at - self.captured_started_at).total_seconds() > MAX_CAPTURE_SECONDS:
            raise ValueError("capture exceeds the five-second observation bound")
        expected = (
            "account_before",
            "available_balance",
            "positions",
            "open_orders",
            "tpsl",
            "account_after",
        )
        if tuple(item.name for item in self.components) != expected:
            raise ValueError("observation components are incomplete or out of order")
        previous = self.captured_started_at
        for component in self.components:
            if not previous <= component.started_at <= component.finished_at <= self.captured_finished_at:
                raise ValueError("component bounds differ from the ordered capture interval")
            previous = component.finished_at
        return self


class ProductionAccountObserver:
    """Capture PROD account state with GET-only transport and no signing-chain input.

    ``get_json`` is a read-only transport seam (for example, the private GET
    helper below or a deterministic fixture in tests). The production origin
    is exact and non-configurable by URL path/query/fragment. Reads are
    sequential so each retained component has honest local start/end bounds;
    the venue provides no shared cursor here, so the result is not atomic.
    """

    def __init__(
        self,
        *,
        context: ProductionContextV1,
        get_json: GetJson,
        jwt: str | None = None,
        api_key: str | None = None,
        exchange_base_url: str = PROD_EXCHANGE_ORIGIN,
        clock: Clock | None = None,
        max_capture_seconds: float = MAX_CAPTURE_SECONDS,
    ) -> None:
        context = ProductionContextV1.model_validate(context)
        if exchange_base_url.rstrip("/") != PROD_EXCHANGE_ORIGIN or exchange_base_url not in {
            PROD_EXCHANGE_ORIGIN,
            PROD_EXCHANGE_ORIGIN + "/",
        }:
            raise ValueError("read-only production observation requires the exact official PROD HTTPS origin")
        _credential_headers(jwt, api_key)
        if not callable(get_json):
            raise ValueError("a GET-only JSON transport is required")
        if not math.isfinite(max_capture_seconds) or not 0 < max_capture_seconds <= MAX_CAPTURE_SECONDS:
            raise ValueError("capture bound must be positive and no greater than five seconds")
        self.context = context
        self.get_json = get_json
        self._clock = clock or (lambda: datetime.now(UTC))
        self._clock_high_water: datetime | None = None
        self.max_capture_seconds = max_capture_seconds

    async def capture_once(self) -> ProductionAccountObservationV1:
        """Capture and cross-check account components without signing or mutation."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.max_capture_seconds
        start = self._now()
        reads: list[_Read] = []
        try:
            async with asyncio.timeout_at(deadline):
                before = await self._read("account_before", "/api/user/me", self._normalize_account)
                self._require_account(before[2]["exchange_account_id"])

                balance = await self._read(
                    "available_balance", "/api/market/available-balance", self._normalize_balance
                )
                positions = await self._read("positions", "/api/position", self._normalize_positions)
                orders = await self._read("open_orders", "/api/order/opened", self._normalize_open_orders)
                tpsl = await self._read("tpsl", "/api/tpsl", self._normalize_tpsl)

                after = await self._read("account_after", "/api/user/me", self._normalize_account)
                if before[2]["exchange_account_id"] != after[2]["exchange_account_id"]:
                    raise ProductionObservationError("authenticated exchange account changed during capture")
                self._require_account(after[2]["exchange_account_id"])

                # Reuse the established EVEDEX normalizers/cross-checks rather
                # than creating a second account-summary interpretation.
                balance_payload = json.loads(balance[0].raw_json)
                position_payload = json.loads(positions[0].raw_json)
                order_payload = json.loads(orders[0].raw_json)
                EvedexAdapter._cross_check_positions(balance_payload["position"], position_payload)
                EvedexAdapter._cross_check_orders(balance_payload["openOrder"], order_payload)
                reads = [before[0], balance[0], positions[0], orders[0], tpsl[0], after[0]]
                end = self._now()
                if (end - start).total_seconds() > self.max_capture_seconds or loop.time() > deadline:
                    raise ProductionObservationError("production observation exceeded its bounded capture")
        except asyncio.CancelledError:
            raise
        except TimeoutError:
            raise ProductionObservationError(
                "production account observation timed out; capture discarded"
            ) from None
        except ProductionObservationError:
            raise
        except Exception as exc:
            raise ProductionObservationError(
                f"production account observation was incomplete or malformed ({type(exc).__name__})"
            ) from None

        components = tuple(
            ProductionObservationComponentV1(
                name=item.name,
                started_at=item.started_at,
                finished_at=item.finished_at,
                raw_payload_json=item.raw_json,
                raw_sha256=item.raw_sha256,
                normalized_payload_json=item.normalized_json,
                normalized_sha256=item.normalized_sha256,
            )
            for item in reads
        )
        return ProductionAccountObservationV1(
            context=self.context,
            exchange_account_id=self.context.remote_account_id,
            captured_started_at=start,
            captured_finished_at=end,
            components=components,
        )

    async def _read(
        self, name: ComponentName, path: str, normalizer: Callable[[Any], Any]
    ) -> tuple[_Read, str, Any]:
        started = self._now()
        try:
            value = await self.get_json(path)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise ProductionObservationError(f"{name} read failed; capture discarded") from None
        finished = self._now()
        if finished < started:
            raise ProductionObservationError("local capture clock moved backwards")
        self._require_embedded_account(value)
        raw_json = self._canonical(value)
        if len(raw_json.encode("utf-8")) > MAX_COMPONENT_BYTES:
            raise ProductionObservationError(f"{name} response exceeds the bounded observation size")
        try:
            normalized = normalizer(value)
        except Exception:
            raise ProductionObservationError(f"{name} response is malformed; capture discarded") from None
        normalized_json = self._canonical(normalized)
        return (
            _Read(
                name=name,
                started_at=started,
                finished_at=finished,
                raw_json=raw_json,
                raw_sha256=self._sha(raw_json),
                normalized_json=normalized_json,
                normalized_sha256=self._sha(normalized_json),
            ),
            path,
            normalized,
        )

    def _require_account(self, account_id: str) -> None:
        if account_id != self.context.remote_account_id:
            raise ProductionObservationError("authenticated EVEDEX account does not match production context")

    def _require_embedded_account(self, payload: Any) -> None:
        """Refuse contradictory row ownership when the endpoint supplies it.

        An absent row owner is not invented or turned into authoritative
        reconciliation; reads remain bound only to the checked credential's account.
        """
        if isinstance(payload, list):
            rows = payload
        elif isinstance(payload, dict) and isinstance(payload.get("list"), list):
            rows = payload["list"]
        else:
            rows = [payload]
        for row in rows:
            if isinstance(row, dict) and "user" in row:
                try:
                    account_id = self._account_id(row["user"])
                except ValueError:
                    raise ProductionObservationError("endpoint row account identity is malformed") from None
                self._require_account(account_id)

    @staticmethod
    def _normalize_account(value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise ValueError("account response must be an object")
        account_id = ProductionAccountObserver._account_id(value.get("exchangeId"))
        margin_call = EvedexAdapter._required_bool(value.get("marginCall"), "marginCall")
        if margin_call:
            raise ValueError("account is in margin call")
        return {"exchange_account_id": account_id, "margin_call": False}

    @staticmethod
    def _account_id(value: Any) -> str:
        if isinstance(value, bool) or not isinstance(value, (int, str)):
            raise ValueError("authenticated account exchangeId is absent")
        account_id = str(value)
        if not account_id.isdigit() or int(account_id) <= 0:
            raise ValueError("authenticated account exchangeId is malformed")
        return account_id

    @staticmethod
    def _normalize_balance(value: Any) -> dict[str, Any]:
        if not isinstance(value, dict) or not isinstance(value.get("funding"), dict):
            raise ValueError("available-balance response is malformed")
        funding = ProductionAccountObserver._number(value["funding"].get("balance"), "funding.balance")
        available = ProductionAccountObserver._number(value.get("availableBalance"), "availableBalance")
        negative_unpnl = ProductionAccountObserver._number(value.get("negativeUnPnL"), "negativeUnPnL")
        if funding <= 0 or available < 0 or negative_unpnl < 0:
            raise ValueError("available-balance amounts are outside their valid range")
        positions = value.get("position")
        orders = value.get("openOrder")
        if not isinstance(positions, list) or not isinstance(orders, list):
            raise ValueError("available-balance summaries are missing")
        return {
            "funding_balance": funding,
            "available_balance": available,
            "negative_unrealized_pnl": negative_unpnl,
            "position_totals": ProductionAccountObserver._totals(positions, "volume"),
            "open_order_totals": ProductionAccountObserver._totals(orders, "unFilledVolume"),
        }

    @staticmethod
    def _totals(items: list[dict[str, Any]], quantity_key: str) -> list[dict[str, Any]]:
        if len(items) > MAX_COMPONENT_ROWS:
            raise ValueError("account summary exceeds row bound")
        for item in items:
            ProductionAccountObserver._number(item.get(quantity_key), quantity_key)
        totals = EvedexAdapter._position_totals(items, quantity_key=quantity_key)
        return [
            {"instrument": instrument, "side": side, "quantity": quantity}
            for (instrument, side), quantity in sorted(totals.items())
        ]

    @staticmethod
    def _normalize_positions(value: Any) -> list[dict[str, Any]]:
        items = EvedexAdapter._as_list(value)
        if len(items) > MAX_COMPONENT_ROWS:
            raise ValueError("position response exceeds row bound")
        result = []
        for item in items:
            if not isinstance(item, dict):
                raise ValueError("position row is not an object")
            instrument = EvedexAdapter._normalized_symbol(item.get("instrument"), "position instrument")
            side = str(item.get("side", "")).upper()
            if side not in {"BUY", "SELL"}:
                raise ValueError("position side is malformed")
            quantity = ProductionAccountObserver._number(item.get("quantity"), f"{instrument}.quantity")
            if quantity < 0:
                raise ValueError("position quantity is negative")
            normalized: dict[str, Any] = {"instrument": instrument, "side": side, "quantity": quantity}
            numeric_fields = (
                "avgPrice",
                "markPrice",
                "currentPrice",
                "leverage",
                "liquidationPrice",
                "unrealizedPnL",
                "unrealizedPnl",
            )
            for field in numeric_fields:
                if item.get(field) is not None:
                    if isinstance(item[field], bool):
                        raise ValueError("boolean position amount is not numeric")
                    try:
                        parsed = float(item[field])
                    except (TypeError, ValueError):
                        raise ValueError(f"{instrument}.{field} is not numeric") from None
                    signed_pnl = field in {"unrealizedPnL", "unrealizedPnl"}
                    if not math.isfinite(parsed) or (not signed_pnl and parsed < 0):
                        raise ValueError("position numeric field is outside its valid range")
                    normalized[field] = parsed
            result.append(normalized)
        # Existing EVEDEX normalization validates quantities, instruments, sides,
        # duplicate aggregation semantics and finite arithmetic.
        EvedexAdapter._position_totals(items, quantity_key="quantity")
        return result

    @staticmethod
    def _normalize_open_orders(value: Any) -> list[dict[str, Any]]:
        items = EvedexAdapter._as_list(value)
        if len(items) > MAX_COMPONENT_ROWS:
            raise ValueError("open-order response exceeds row bound")
        result = []
        ids: set[str] = set()
        for item in items:
            if not isinstance(item, dict):
                raise ValueError("open order is not an object")
            order_id = item.get("id")
            instrument = EvedexAdapter._normalized_symbol(item.get("instrument"), "open-order instrument")
            side = str(item.get("side", "")).upper()
            if (
                not isinstance(order_id, str)
                or not order_id
                or order_id in ids
                or side not in {"BUY", "SELL"}
            ):
                raise ValueError("open-order identity is malformed or duplicated")
            ids.add(order_id)
            remaining = ProductionAccountObserver._number(item.get("unFilledQuantity"), "unFilledQuantity")
            if remaining <= 0:
                raise ValueError("opened order has no positive remaining quantity")
            result.append(
                {
                    "id": order_id,
                    "instrument": instrument,
                    "side": side,
                    "remaining_quantity": remaining,
                }
            )
        EvedexAdapter._position_totals(items, quantity_key="unFilledQuantity")
        return result

    @staticmethod
    def _normalize_tpsl(value: Any) -> list[dict[str, Any]]:
        items = EvedexAdapter._as_list(value)
        if len(items) > MAX_COMPONENT_ROWS:
            raise ValueError("TP/SL response exceeds row bound")
        result = []
        for item in items:
            if not isinstance(item, dict):
                raise ValueError("TP/SL record is not an object")
            record_id = item.get("id")
            instrument = EvedexAdapter._normalized_symbol(item.get("instrument"), "TP/SL instrument")
            side = str(item.get("side", "")).upper()
            kind = str(item.get("type", "")).casefold().replace("_", "-")
            status = str(item.get("status", "")).casefold()
            if not isinstance(record_id, (str, int)) or isinstance(record_id, bool) or not str(record_id):
                raise ValueError("TP/SL identity is malformed")
            if side not in {"BUY", "SELL"} or kind not in {"stop-loss", "take-profit"} or not status:
                raise ValueError("TP/SL lifecycle fields are malformed")
            quantity = ProductionAccountObserver._number(item.get("quantity"), "TP/SL quantity")
            price = ProductionAccountObserver._number(item.get("price"), "TP/SL price")
            if quantity < 0 or price <= 0:
                raise ValueError("TP/SL geometry is outside its valid range")
            parent = item.get("order")
            if parent is not None and not isinstance(parent, str):
                raise ValueError("TP/SL parent order identity is malformed")
            result.append(
                {
                    "id": str(record_id),
                    "instrument": instrument,
                    "side": side,
                    "type": kind,
                    "status": status,
                    "quantity": quantity,
                    "price": price,
                    "parent_order_id": parent,
                }
            )
        return result

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
            raise ProductionObservationError("observation clock must return explicit UTC")
        if self._clock_high_water is not None and value < self._clock_high_water:
            raise ProductionObservationError("local capture clock moved backwards")
        self._clock_high_water = value
        return value

    @staticmethod
    def _number(value: Any, field: str) -> float:
        if isinstance(value, bool):
            raise ValueError("boolean account amount is not numeric")
        return EvedexAdapter._required_float(value, field)

    @staticmethod
    def _canonical(value: Any) -> str:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)

    @staticmethod
    def _sha(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()


class AiohttpProdGetJson:
    """Minimal GET-only HTTP transport for the exact official PROD origin."""

    def __init__(
        self,
        *,
        jwt: str | None = None,
        api_key: str | None = None,
        exchange_base_url: str = PROD_EXCHANGE_ORIGIN,
    ) -> None:
        if exchange_base_url.rstrip("/") != PROD_EXCHANGE_ORIGIN or exchange_base_url not in {
            PROD_EXCHANGE_ORIGIN,
            PROD_EXCHANGE_ORIGIN + "/",
        }:
            raise ValueError("GET transport requires the exact official PROD HTTPS origin")
        self._headers = _credential_headers(jwt, api_key)
        self._base = PROD_EXCHANGE_ORIGIN

    async def __call__(self, path: str) -> Any:
        if path not in READ_PATHS:
            raise ProductionObservationError("unsupported read-only API path")
        try:
            import aiohttp
        except Exception:
            raise ProductionObservationError(
                "aiohttp is unavailable for authenticated account reads"
            ) from None
        timeout = aiohttp.ClientTimeout(total=3.0, connect=1.0)
        async with aiohttp.ClientSession(headers=self._headers, timeout=timeout) as session:
            async with session.get(f"{self._base}{path}", allow_redirects=False) as response:
                if not 200 <= response.status < 300:
                    raise ProductionObservationError("authenticated PROD account GET failed")
                # Bound bytes before JSON decoding; an oversized response must
                # not be fully buffered merely to discover the size afterwards.
                payload = bytearray()
                async for chunk in response.content.iter_chunked(65_536):
                    if len(payload) + len(chunk) > MAX_COMPONENT_BYTES:
                        raise ProductionObservationError("PROD account GET exceeds the response size bound")
                    payload.extend(chunk)
                try:
                    parsed = json.loads(payload, object_pairs_hook=_unique_json_object)
                    # Python's decoder accepts non-standard NaN/Infinity unless
                    # explicitly refused; keep the captured JSON finite.
                    json.dumps(parsed, allow_nan=False)
                    return parsed
                except (ValueError, UnicodeError, RecursionError):
                    raise ProductionObservationError("PROD account GET returned malformed JSON") from None
