"""Offline tests for the fixed read-only Binance depth capture boundary."""

import base64
import hashlib
import json
import os
import sys
import types
from dataclasses import dataclass
from pathlib import Path

import pytest

import kairos_execution.production_native_capture_store as native_store
from kairos_execution.production_binance_capture import (
    BINANCE_DEPTH_URL,
    BinanceCaptureUnavailable,
    BinanceDepthCaptureAdapter,
)
from kairos_execution.production_native_capture_store import NativeCaptureSessionSink

BODY = b'{"lastUpdateId":42,"E":1010,"T":1011,"bids":[["100.10","2.000"]],"asks":[["100.20","3.000"]]}'
SYMBOL = "BTCUSDT"
URL = f"{BINANCE_DEPTH_URL}?symbol={SYMBOL}&limit=100"


@dataclass(frozen=True)
class FakeBook:
    source: str
    symbol: str
    timestamp_ms: int
    bids: tuple
    asks: tuple
    latency_ms: float


class FakeContent:
    def __init__(self, chunks):
        self.chunks = chunks

    async def iter_chunked(self, _size):
        for chunk in self.chunks:
            yield chunk


class FakeResponse:
    def __init__(self, body=BODY, *, status=200, url=URL, history=(), content_length=None, headers=None):
        self.status = status
        self.url = url
        self.history = history
        self.content_length = len(body) if content_length is None else content_length
        self.headers = headers or {}
        self.content = FakeContent((body[:15], body[15:]))

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None


class FakeSession:
    _trust_env = False
    _default_auth = None
    _default_headers = {}
    closed = False

    def __init__(self, response=None):
        self.response = response or FakeResponse()
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.response


def install_fake_quant_normalizer(monkeypatch, calls):
    package = types.ModuleType("kairos_quant")
    package.__path__ = []
    module = types.ModuleType("kairos_quant.venue_comparison")

    def parse_binance_book(symbol, payload, *, latency_ms):
        calls.append((symbol, payload, latency_ms))
        timestamp = payload.get("T") or payload.get("E")
        return FakeBook(
            "binance",
            symbol,
            timestamp,
            tuple(payload["bids"]),
            tuple(payload["asks"]),
            latency_ms,
        )

    module.parse_binance_book = parse_binance_book
    monkeypatch.setitem(sys.modules, "kairos_quant", package)
    monkeypatch.setitem(sys.modules, "kairos_quant.venue_comparison", module)


def make_sink(monkeypatch, directory, *, clock_ms):
    """Use production owner-only storage when available; otherwise an fsync double."""

    try:
        native_store._storage_class()
    except ModuleNotFoundError as exc:
        if exc.name not in {"kairos_llm", "kairos_llm.call_evidence"}:
            raise
    else:
        return NativeCaptureSessionSink(directory, clock_ms=clock_ms)

    class FsyncingDirectoryStore:
        def __init__(self, path):
            self.directory = Path(path).absolute()
            self.directory.mkdir(parents=False, exist_ok=False)

        @staticmethod
        def _is_reparse(info):
            import stat

            return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)

        @classmethod
        def _reject_reparse_ancestors(cls, path):
            for ancestor in (Path(path), *Path(path).parents):
                if cls._is_reparse(ancestor.lstat()):
                    raise ValueError("test storage rejects reparse paths")

        @staticmethod
        def _identity(path):
            info = Path(path).lstat()
            return info.st_dev, info.st_ino

        def create_only(self, identity, slot, record):
            path = self.directory / f"{identity}.{slot}.json"
            with path.open("xb") as handle:
                handle.write(record)
                handle.flush()
                os.fsync(handle.fileno())

    monkeypatch.setattr(native_store, "_storage_class", lambda: FsyncingDirectoryStore)
    return NativeCaptureSessionSink(directory, clock_ms=clock_ms)


def test_capture_is_lazy_fixed_read_only_and_persists_original_bytes_first(tmp_path, monkeypatch):
    normalized = []
    install_fake_quant_normalizer(monkeypatch, normalized)
    session = FakeSession()
    source_clock = iter((1000, 1020))
    monotonic_clock = iter((2.0, 2.015))
    sink_clock = iter((2000, 2001))
    sink = make_sink(monkeypatch, tmp_path / "native-session", clock_ms=lambda: next(sink_clock))

    adapter = BinanceDepthCaptureAdapter(
        session,
        sink,
        clock_ms=lambda: next(source_clock),
        monotonic=lambda: next(monotonic_clock),
    )
    assert session.calls == []  # Constructor performs no network or source read.

    import asyncio

    result = asyncio.run(adapter.capture_depth(SYMBOL))

    assert len(session.calls) == 1
    url, request = session.calls[0]
    assert url == BINANCE_DEPTH_URL
    assert request == {
        "params": (("symbol", SYMBOL), ("limit", "100")),
        "allow_redirects": False,
        "auth": None,
        "proxy": None,
        "headers": {"Accept-Encoding": "identity"},
        "auto_decompress": False,
        "timeout": request["timeout"],
    }
    assert request["timeout"].total == 5
    assert request["timeout"].connect == 2
    assert request["timeout"].sock_read == 3
    assert normalized[0][0] == SYMBOL and normalized[0][2] == pytest.approx(15.0)
    assert result.book.timestamp_ms == 1011
    assert result.capture.source_timestamp_field == "T"
    assert result.capture.source_timestamp_ms == 1011
    assert result.capture.requested_at_ms == 1000
    assert result.capture.received_at_ms == 1020
    assert result.capture.requested_url == URL
    assert result.capture.request_query_json == '{"limit":"100","symbol":"BTCUSDT"}'
    assert base64.b64decode(result.capture.body_base64) == BODY
    assert result.capture.body_bytes == len(BODY)
    assert result.capture.body_sha256 == hashlib.sha256(BODY).hexdigest()
    from kairos_core.contracts import canonical_json_bytes

    assert result.stored.record == canonical_json_bytes(result.capture)
    retained = sink.reader.read(result.capture_id)
    assert retained.record == result.stored.record
    record = json.loads(retained.record)
    assert record["body_base64"] == base64.b64encode(BODY).decode("ascii")
    assert retained.witness.record_sha256 == hashlib.sha256(retained.record).hexdigest()
    assert retained.witness.acknowledged_at_ms == 2001


@pytest.mark.parametrize(
    "response",
    [
        FakeResponse(status=503),
        FakeResponse(url="https://evil.example/fapi/v1/depth?symbol=BTCUSDT&limit=100"),
        FakeResponse(history=(object(),)),
        FakeResponse(headers={"Content-Encoding": "gzip"}),
        FakeResponse(content_length=1_000_001),
        FakeResponse(content_length=len(BODY) + 1),
    ],
)
def test_bad_http_response_is_not_persisted(tmp_path, monkeypatch, response):
    normalized = []
    install_fake_quant_normalizer(monkeypatch, normalized)
    sink = make_sink(monkeypatch, tmp_path / "native-session", clock_ms=lambda: 2000)
    adapter = BinanceDepthCaptureAdapter(FakeSession(response), sink, clock_ms=lambda: 1000)

    import asyncio

    with pytest.raises(BinanceCaptureUnavailable):
        asyncio.run(adapter.capture_depth(SYMBOL))
    assert sink.reader.observation_ids() == ()
    assert normalized == []


@pytest.mark.parametrize("symbol", ["BTCUSD", "btcUSDT", "DOGEUSDT", ""])
def test_unapproved_symbol_refuses_before_http(tmp_path, monkeypatch, symbol):
    normalized = []
    install_fake_quant_normalizer(monkeypatch, normalized)
    session = FakeSession()
    sink = make_sink(monkeypatch, tmp_path / "native-session", clock_ms=lambda: 2000)
    adapter = BinanceDepthCaptureAdapter(session, sink, clock_ms=lambda: 1000)

    import asyncio

    with pytest.raises(BinanceCaptureUnavailable):
        asyncio.run(adapter.capture_depth(symbol))
    assert session.calls == []
    assert sink.reader.observation_ids() == ()


@pytest.mark.parametrize(
    "session",
    [
        type("EnvSession", (FakeSession,), {"_trust_env": True})(),
        type("AuthSession", (FakeSession,), {"_default_auth": object()})(),
        type("KeySession", (FakeSession,), {"_default_headers": {"X-MBX-APIKEY": "never-read"}})(),
        type("ProxySession", (FakeSession,), {"_default_proxy": "https://proxy.example"})(),
    ],
)
def test_authenticated_or_environment_routed_session_is_rejected(tmp_path, monkeypatch, session):
    sink = make_sink(monkeypatch, tmp_path / "native-session", clock_ms=lambda: 2000)
    with pytest.raises(ValueError):
        BinanceDepthCaptureAdapter(session, sink, clock_ms=lambda: 1000)


def test_sink_failure_never_returns_a_normalized_market_book(tmp_path, monkeypatch):
    normalized = []
    install_fake_quant_normalizer(monkeypatch, normalized)
    sink = make_sink(monkeypatch, tmp_path / "native-session", clock_ms=lambda: 2000)

    def fail_write(_identity, _record):
        raise OSError("simulated local capture failure")

    monkeypatch.setattr(sink, "create_only", fail_write)
    source_clock = iter((1000, 1020))
    adapter = BinanceDepthCaptureAdapter(FakeSession(), sink, clock_ms=lambda: next(source_clock))

    import asyncio

    with pytest.raises(BinanceCaptureUnavailable, match="not durably acknowledged"):
        asyncio.run(adapter.capture_depth(SYMBOL))
    assert sink.reader.observation_ids() == ()
    # Normalization is allowed, but no result escapes before persistence succeeds.
    assert normalized


def test_source_timestamp_is_not_retimed_from_receive_clock(tmp_path, monkeypatch):
    normalized = []
    install_fake_quant_normalizer(monkeypatch, normalized)
    sink = make_sink(monkeypatch, tmp_path / "native-session", clock_ms=lambda: 2000)
    adapter = BinanceDepthCaptureAdapter(FakeSession(), sink, clock_ms=lambda: 1010)

    import asyncio

    with pytest.raises(BinanceCaptureUnavailable, match="source timestamp is invalid"):
        asyncio.run(adapter.capture_depth(SYMBOL))
    assert sink.reader.observation_ids() == ()
