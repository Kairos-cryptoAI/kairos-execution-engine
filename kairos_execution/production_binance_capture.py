"""Read-only original-body capture for the fixed Binance USD-M depth source.

This adapter captures public ``/fapi/v1/depth`` responses before JSON parsing,
normalizes them with the existing Quant book parser, and persists the exact
capture wrapper through the native create-only evidence sink. Construction is
side-effect free; the sole network operation is one fixed bounded GET.

The result is source evidence, not a signed producer receipt or LIVE authority.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Final, Literal, cast

import aiohttp
from kairos_core.contracts import canonical_json_bytes
from pydantic import Field
from yarl import URL

from .production_native_capture_store import (
    NativeCaptureSessionSink,
    NativeCaptureStoredObservation,
)
from .production_readiness import StrictRecord

BinanceReferenceSymbol = Literal["BTCUSDT", "ETHUSDT", "SOLUSDT", "BNBUSDT", "XRPUSDT"]
BinanceSourceTimestampField = Literal["T", "E"]
BINANCE_DEPTH_URL: Final[Literal["https://fapi.binance.com/fapi/v1/depth"]] = (
    "https://fapi.binance.com/fapi/v1/depth"
)
BINANCE_REFERENCE_SYMBOLS: Final[frozenset[BinanceReferenceSymbol]] = frozenset(
    {"BTCUSDT", "ETHUSDT", "SOLUSDT", "BNBUSDT", "XRPUSDT"}
)
BINANCE_DEPTH_LIMIT: Final[Literal[100]] = 100
MAX_BINANCE_DEPTH_BODY_BYTES: Final = 1_000_000
_REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=5, connect=2, sock_read=3)
_CAPTURE_DOMAIN = b"kairos.binance-depth-capture.v1\x00"


class BinanceCaptureUnavailable(PermissionError):
    """The bounded public Binance source did not produce a retainable response."""


class BinanceDepthCaptureV1(StrictRecord):
    """Original Binance response entity plus its distinct local source clocks."""

    schema_version: Literal["kairos.binance-depth-capture.v1"] = "kairos.binance-depth-capture.v1"
    source: Literal["BINANCE_REFERENCE"] = "BINANCE_REFERENCE"
    method: Literal["GET"] = "GET"
    url: Literal["https://fapi.binance.com/fapi/v1/depth"] = BINANCE_DEPTH_URL
    symbol: BinanceReferenceSymbol
    limit: Literal[100] = BINANCE_DEPTH_LIMIT
    requested_url: str = Field(min_length=1, max_length=256)
    request_query_json: str = Field(min_length=1, max_length=128)
    status: Literal[200] = 200
    requested_at_ms: int = Field(ge=0, lt=2**63, strict=True)
    received_at_ms: int = Field(ge=0, lt=2**63, strict=True)
    source_timestamp_ms: int = Field(gt=0, lt=2**63, strict=True)
    source_timestamp_field: BinanceSourceTimestampField
    body_bytes: int = Field(ge=1, le=MAX_BINANCE_DEPTH_BODY_BYTES, strict=True)
    body_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    body_base64: str = Field(
        min_length=4,
        max_length=4 * ((MAX_BINANCE_DEPTH_BODY_BYTES + 2) // 3),
    )


@dataclass(frozen=True, slots=True)
class BinanceDepthCaptureResult:
    """A normalized book tied to its exact raw source and local fsync witness."""

    capture_id: str
    capture: BinanceDepthCaptureV1
    book: Any
    stored: NativeCaptureStoredObservation


class BinanceDepthCaptureAdapter:
    """One-request public depth adapter using a caller-owned aiohttp session.

    The injected session must have ``trust_env=False``, no default auth, and no
    Authorization or Binance API-key header. Requests also explicitly disable
    redirects, auth, and proxies and request identity encoding. No credentials
    are accepted by this API.
    """

    def __init__(
        self,
        session: Any,
        sink: NativeCaptureSessionSink,
        *,
        clock_ms: Callable[[], int],
        monotonic: Callable[[], float] = time.perf_counter,
    ) -> None:
        if not callable(getattr(session, "get", None)) or getattr(session, "closed", False):
            raise TypeError("an open caller-owned aiohttp-compatible session is required")
        if getattr(session, "_trust_env", None) is not False:
            raise ValueError("Binance capture requires a session with trust_env=False")
        if getattr(session, "_default_auth", None) is not None:
            raise ValueError("Binance capture forbids session default authentication")
        if (
            getattr(session, "_default_proxy", None) is not None
            or getattr(session, "_default_proxy_auth", None) is not None
        ):
            raise ValueError("Binance capture forbids session default proxy routing")
        headers = getattr(session, "_default_headers", {})
        if any(
            str(key).lower() in {"authorization", "proxy-authorization", "x-mbx-apikey"}
            for key in (headers.keys() if hasattr(headers, "keys") else ())
        ):
            raise ValueError("Binance public capture forbids authentication and API-key headers")
        if not isinstance(sink, NativeCaptureSessionSink):
            raise TypeError("the exact native create-only capture sink is required")
        if not callable(clock_ms):
            raise TypeError("an explicit source request/receive clock is required")
        if not callable(monotonic):
            raise TypeError("a monotonic request-duration clock is required")
        self._session = session
        self._sink = sink
        self._clock_ms = clock_ms
        self._monotonic = monotonic
        self._last_clock_ms: int | None = None

    def _time(self) -> int:
        value = self._clock_ms()
        if (
            type(value) is not int
            or not 0 <= value < 2**63
            or (self._last_clock_ms is not None and value < self._last_clock_ms)
        ):
            raise BinanceCaptureUnavailable("Binance capture clock is invalid or moved backwards")
        self._last_clock_ms = value
        return value

    async def capture_depth(self, symbol: str) -> BinanceDepthCaptureResult:
        """GET, retain, then normalize one approved Binance USD-M book snapshot."""
        if not isinstance(symbol, str) or symbol not in BINANCE_REFERENCE_SYMBOLS:
            raise BinanceCaptureUnavailable("symbol is outside the fixed Binance reference universe")
        normalized_symbol = cast(BinanceReferenceSymbol, symbol)

        requested_at_ms = self._time()
        started = self._monotonic()
        if not math.isfinite(started):
            raise BinanceCaptureUnavailable("Binance request-duration clock is invalid")
        expected_query = {"symbol": normalized_symbol, "limit": str(BINANCE_DEPTH_LIMIT)}
        expected_url = str(URL(BINANCE_DEPTH_URL).with_query(expected_query))
        try:
            async with self._session.get(
                BINANCE_DEPTH_URL,
                params=(("symbol", normalized_symbol), ("limit", str(BINANCE_DEPTH_LIMIT))),
                allow_redirects=False,
                auth=None,
                proxy=None,
                headers={"Accept-Encoding": "identity"},
                auto_decompress=False,
                timeout=_REQUEST_TIMEOUT,
            ) as response:
                if (
                    response.status != 200
                    or getattr(response, "history", ())
                    or str(getattr(response, "url", "")) != expected_url
                ):
                    raise BinanceCaptureUnavailable("Binance depth response status/route/redirect is invalid")
                encoding = str(getattr(response, "headers", {}).get("Content-Encoding", "identity")).lower()
                if encoding not in {"", "identity"}:
                    raise BinanceCaptureUnavailable(
                        "compressed Binance response is not accepted as raw entity bytes"
                    )
                content_length = getattr(response, "content_length", None)
                if content_length is not None and (
                    type(content_length) is not int
                    or content_length < 0
                    or content_length > MAX_BINANCE_DEPTH_BODY_BYTES
                ):
                    raise BinanceCaptureUnavailable("Binance depth response exceeds its byte bound")
                body = await self._read_body(response)
                received_at_ms = self._time()
                finished = self._monotonic()
                if not math.isfinite(finished) or finished < started or finished - started > 5.0:
                    raise BinanceCaptureUnavailable("Binance request-duration clock moved backwards")
        except BinanceCaptureUnavailable:
            raise
        except Exception as exc:
            raise BinanceCaptureUnavailable("Binance depth GET did not complete") from exc

        if not requested_at_ms <= received_at_ms:
            raise BinanceCaptureUnavailable("Binance request/receive clocks are inconsistent")
        try:

            def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
                value: dict[str, Any] = {}
                for key, item in pairs:
                    if key in value:
                        raise ValueError("duplicate JSON object key")
                    value[key] = item
                return value

            def reject_constant(value: str) -> None:
                raise ValueError(value)

            payload = json.loads(
                body.decode("utf-8", errors="strict"),
                object_pairs_hook=unique_object,
                parse_constant=reject_constant,
            )
            if not isinstance(payload, dict):
                raise ValueError
            source_field: BinanceSourceTimestampField = "T" if "T" in payload else "E"
            source_timestamp_ms = payload.get(source_field)
            if type(source_timestamp_ms) is not int or source_timestamp_ms <= 0:
                raise ValueError
            from kairos_quant.venue_comparison import parse_binance_book  # type: ignore[import-untyped]

            book = parse_binance_book(
                normalized_symbol,
                payload,
                latency_ms=(finished - started) * 1_000,
            )
        except Exception as exc:
            raise BinanceCaptureUnavailable(
                "Binance depth body is malformed or cannot be normalized"
            ) from exc
        if book.timestamp_ms != source_timestamp_ms or source_timestamp_ms > received_at_ms:
            raise BinanceCaptureUnavailable("Binance source timestamp is invalid or postdates receipt")

        capture = BinanceDepthCaptureV1(
            symbol=normalized_symbol,
            requested_url=expected_url,
            request_query_json=json.dumps(expected_query, sort_keys=True, separators=(",", ":")),
            requested_at_ms=requested_at_ms,
            received_at_ms=received_at_ms,
            source_timestamp_ms=source_timestamp_ms,
            source_timestamp_field=source_field,
            body_bytes=len(body),
            body_sha256=hashlib.sha256(body).hexdigest(),
            body_base64=base64.b64encode(body).decode("ascii"),
        )
        record = canonical_json_bytes(capture)
        capture_id = hashlib.sha256(_CAPTURE_DOMAIN + record).hexdigest()[:32]
        try:
            self._sink.create_only(capture_id, record)
            stored = self._sink.reader.read(capture_id)
        except Exception as exc:
            raise BinanceCaptureUnavailable("Binance source bytes were not durably acknowledged") from exc
        if stored.record != record or stored.witness.observation_id != capture_id:
            raise BinanceCaptureUnavailable("native Binance capture witness does not bind the source wrapper")
        return BinanceDepthCaptureResult(capture_id, capture, book, stored)

    @staticmethod
    async def _read_body(response: Any) -> bytes:
        content = getattr(response, "content", None)
        iterator = getattr(content, "iter_chunked", None)
        if not callable(iterator):
            raise BinanceCaptureUnavailable("Binance response does not expose bounded streamed bytes")
        chunks: list[bytes] = []
        size = 0
        async for chunk in iterator(64 * 1024):
            if not isinstance(chunk, bytes):
                raise BinanceCaptureUnavailable("Binance response yielded a non-byte body chunk")
            size += len(chunk)
            if size > MAX_BINANCE_DEPTH_BODY_BYTES:
                raise BinanceCaptureUnavailable("Binance depth response exceeds its byte bound")
            chunks.append(chunk)
        body = b"".join(chunks)
        if not body or len(body) > MAX_BINANCE_DEPTH_BODY_BYTES:
            raise BinanceCaptureUnavailable("Binance depth response body is empty or oversized")
        if getattr(response, "content_length", None) is not None and len(body) != response.content_length:
            raise BinanceCaptureUnavailable("Binance response body length differs from Content-Length")
        return body


__all__ = [
    "BINANCE_DEPTH_URL",
    "BINANCE_REFERENCE_SYMBOLS",
    "BINANCE_DEPTH_LIMIT",
    "MAX_BINANCE_DEPTH_BODY_BYTES",
    "BinanceCaptureUnavailable",
    "BinanceDepthCaptureV1",
    "BinanceDepthCaptureResult",
    "BinanceDepthCaptureAdapter",
]
