from __future__ import annotations

import asyncio
import json
import sys
from dataclasses import replace
from datetime import UTC, datetime
from types import ModuleType, SimpleNamespace

import pytest
from kairos_persistence.canary_session import SYMBOLS, CanaryScope, SymbolObservation

from kairos_execution.readonly_recorder import (
    MeasurementBatch,
    RecorderHealth,
    _age_symbols,
    _batch_from_venue_report,
    _get_public_json,
    measure_public_venue_sample,
    record_readonly_window,
)


def scope() -> CanaryScope:
    return CanaryScope(
        environment="paper-dev",
        account_id="kairos-paper-dev-test",
        remote_account_id="evedex-dev-test",
        config_sha256="a" * 64,
        recorder_code_sha256="b" * 64,
    )


def healthy(scope_value: CanaryScope) -> RecorderHealth:
    return RecorderHealth(
        observed_at_ms=int(datetime.now(UTC).timestamp() * 1_000),
        account_id=scope_value.account_id,
        remote_account_id=scope_value.remote_account_id,
        config_sha256=scope_value.config_sha256,
        account_reconciled=True,
        unresolved_bar_gaps=0,
        reconciliation_drift=False,
        entry_mutations=0,
    )


async def test_public_measurement_rejects_non_dev_symbol_identity_before_network() -> None:
    with pytest.raises(ValueError, match="exact five EVEDEX DEV"):
        await measure_public_venue_sample(
            symbol_map={"BTCUSDT": "BTCUSD"},
            notional_usd=1_000,
        )


class _FakeResponse:
    def __init__(self, body: bytes, status: int = 200) -> None:
        self.status = status
        self.content = self
        self.body = body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def iter_chunked(self, chunk_size: int):
        for start in range(0, len(self.body), chunk_size):
            yield self.body[start : start + chunk_size]

    def raise_for_status(self) -> None:
        if self.status >= 400:
            raise ValueError("HTTP error")


class _FakeSession:
    def __init__(self, *, body: bytes = b"{}", status: int = 200) -> None:
        self.body = body
        self.status = status
        self.calls: list[tuple[str, dict[str, object]]] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    def get(self, url: str, **kwargs):
        self.calls.append((url, kwargs))
        return _FakeResponse(self.body, self.status)


async def test_public_json_wrapper_rejects_redirect_malformed_and_oversize_bodies() -> None:
    url = "https://trading-api.evedex.tech/api/market/BTCUSD:DEV/deep"
    session = _FakeSession(status=302)
    with pytest.raises(ValueError, match="HTTP 200"):
        await _get_public_json(session, url)
    assert session.calls == [(url, {"allow_redirects": False})]

    with pytest.raises(json.JSONDecodeError):
        await _get_public_json(_FakeSession(body=b"not-json"), url)
    with pytest.raises(ValueError, match="exceeded the recorder body bound"):
        await _get_public_json(_FakeSession(body=b"x" * 1_048_577), url)
    with pytest.raises(ValueError, match="allowlist"):
        await _get_public_json(_FakeSession(), "https://example.invalid/book")

    chunked = await _get_public_json(_FakeSession(body=b'{"pad":"' + b"x" * 70_000 + b'"}'), url)
    assert len(chunked[0]["pad"]) == 70_000


async def test_measurement_uses_pinned_mocked_gets_and_marks_missing_book_unavailable(monkeypatch) -> None:
    package = ModuleType("kairos_quant")
    package.__path__ = []
    quant = ModuleType("kairos_quant.venue_comparison")
    session = _FakeSession()
    monkeypatch.setattr("kairos_execution.readonly_recorder.aiohttp.ClientSession", lambda **_kwargs: session)

    def parse_book(source: str, symbol: str, payload: object):
        return SimpleNamespace(source=source, symbol=symbol)

    quant.parse_evedex_book = lambda symbol, payload, **kwargs: parse_book("evedex", symbol, payload)
    quant.parse_binance_book = lambda symbol, payload, **kwargs: parse_book("binance", symbol, payload)

    async def compare_venues(*, fetch_pair, symbol_map, **_kwargs):
        samples = []
        for logical, venue in symbol_map.items():
            try:
                evedex, reference = await fetch_pair(logical, venue)
            except Exception:
                continue
            assert evedex.source == "evedex" and reference.source == "binance"
            now_ms = int(datetime.now(UTC).timestamp() * 1_000)
            samples.append(
                SimpleNamespace(
                    logical_symbol=logical,
                    captured_at=datetime.now(UTC).isoformat(),
                    evedex_timestamp_ms=now_ms,
                    binance_timestamp_ms=now_ms,
                    timestamp_skew_ms=0,
                    basis_bps=1.0,
                    evedex_spread_bps=1.0,
                    evedex_buy_slippage_bps=1.0,
                    evedex_sell_slippage_bps=1.0,
                )
            )
        return SimpleNamespace(samples=samples)

    quant.compare_venues = compare_venues
    monkeypatch.setitem(sys.modules, "kairos_quant", package)
    monkeypatch.setitem(sys.modules, "kairos_quant.venue_comparison", quant)
    symbol_map = {symbol: f"{symbol.removesuffix('USDT')}USD:DEV" for symbol in SYMBOLS}
    batch = await measure_public_venue_sample(symbol_map=symbol_map)

    assert len(session.calls) == 10
    assert all(call[1] == {"allow_redirects": False} for call in session.calls)
    assert {url.split("/")[2] for url, _ in session.calls} == {
        "trading-api.evedex.tech",
        "fapi.binance.com",
    }
    assert all(item.available for item in batch.symbols)

    async def compare_with_empty(*, fetch_pair, symbol_map, **_kwargs):
        samples = []
        for logical, venue in symbol_map.items():
            if logical == "BTCUSDT":
                continue
            evedex, reference = await fetch_pair(logical, venue)
            now_ms = int(datetime.now(UTC).timestamp() * 1_000)
            samples.append(
                SimpleNamespace(
                    logical_symbol=logical,
                    captured_at=datetime.now(UTC).isoformat(),
                    evedex_timestamp_ms=now_ms,
                    binance_timestamp_ms=now_ms,
                    timestamp_skew_ms=0,
                    basis_bps=1.0,
                    evedex_spread_bps=1.0,
                    evedex_buy_slippage_bps=1.0,
                    evedex_sell_slippage_bps=1.0,
                )
            )
        return SimpleNamespace(samples=samples)

    quant.compare_venues = compare_with_empty
    empty = await measure_public_venue_sample(symbol_map=symbol_map)
    assert len(empty.symbols) == 5
    assert not empty.symbols[0].available


def test_stale_and_future_venue_timestamps_are_unavailable() -> None:
    now = datetime.now(UTC)
    base = {
        "captured_at": now.isoformat(),
        "timestamp_skew_ms": 0,
        "basis_bps": 1.0,
        "evedex_spread_bps": 1.0,
        "evedex_buy_slippage_bps": 1.0,
        "evedex_sell_slippage_bps": 1.0,
    }
    now_ms = int(now.timestamp() * 1_000)
    stale = SimpleNamespace(
        logical_symbol=SYMBOLS[0],
        evedex_timestamp_ms=now_ms - 5_001,
        binance_timestamp_ms=now_ms - 5_001,
        **base,
    )
    future = SimpleNamespace(
        logical_symbol=SYMBOLS[1],
        evedex_timestamp_ms=now_ms + 2_001,
        binance_timestamp_ms=now_ms + 2_001,
        **base,
    )
    batch = _batch_from_venue_report(SimpleNamespace(samples=[stale, future]))
    assert not batch.symbols[0].available
    assert not batch.symbols[1].available
    assert all(not item.available for item in batch.symbols[2:])


def test_book_that_goes_stale_during_account_health_poll_is_unavailable() -> None:
    symbols = tuple(
        SymbolObservation(
            symbol=symbol,
            available=True,
            basis_bps=0.5,
            spread_bps=1.0,
            slippage_bps=1.0,
            book_age_ms=5_000 if symbol == "BTCUSDT" else 1_000,
            timestamp_skew_ms=0,
            book_nonempty=True,
        )
        for symbol in SYMBOLS
    )
    aged = _age_symbols(symbols, 1)
    assert not aged[0].available
    assert aged[0].book_age_ms == 5_001
    assert all(item.available for item in aged[1:])


class FakeRepository:
    def __init__(self) -> None:
        self.observations = []
        self.certified = False

    async def begin_readonly(self, scope_value, *, sample_period_ms):
        assert scope_value == scope()
        assert sample_period_ms == 60_000
        return "run-id"

    async def append_observation(self, run_id, observation):
        assert run_id == "run-id"
        self.observations.append(observation)
        return len(self.observations)

    async def certify_readonly(self, run_id, *, expected_scope):
        assert run_id == "run-id"
        assert expected_scope == scope()
        self.certified = True
        return "receipt-id"


async def test_measurement_failure_is_persisted_as_full_unavailable_denominator() -> None:
    repository = FakeRepository()
    scope_value = scope()
    tick = [0.0]

    async def fail_measurement():
        raise OSError("offline")

    async def read_health(run_id, requested_scope):
        assert run_id == "run-id"
        assert requested_scope == scope_value
        return healthy(scope_value)

    async def fast_sleep(seconds: float) -> None:
        tick[0] += seconds

    run_id, receipt_id = await record_readonly_window(
        repository,
        scope_value,
        measure=fail_measurement,
        read_health=read_health,
        sample_period_ms=60_000,
        duration_s=86_400,
        sleep=fast_sleep,
        monotonic=lambda: tick[0],
    )

    assert (run_id, receipt_id) == ("run-id", "receipt-id")
    assert repository.certified
    assert len(repository.observations) == 1_441
    assert all(len(item.symbols) == 5 for item in repository.observations)
    assert all(not symbol.available for item in repository.observations for symbol in item.symbols)


async def test_overrun_skips_to_absolute_grid_without_shifting_or_bursting() -> None:
    repository = FakeRepository()
    scope_value = scope()
    tick = [0.0]
    poll_starts: list[float] = []
    unavailable = tuple(SymbolObservation(symbol=symbol, available=False) for symbol in SYMBOLS)
    call_count = 0

    async def measure():
        nonlocal call_count
        poll_starts.append(tick[0])
        call_count += 1
        if call_count == 1:
            tick[0] += 65
        return MeasurementBatch(
            captured_at_ms=int(datetime.now(UTC).timestamp() * 1_000), symbols=unavailable
        )

    async def read_health(run_id, requested_scope):
        return healthy(requested_scope)

    async def fast_sleep(seconds: float) -> None:
        tick[0] += seconds

    await record_readonly_window(
        repository,
        scope_value,
        measure=measure,
        read_health=read_health,
        sample_period_ms=60_000,
        duration_s=86_400,
        sleep=fast_sleep,
        monotonic=lambda: tick[0],
    )
    assert poll_starts[:3] == [0.0, 120.0, 180.0]


async def test_normal_poll_latency_does_not_accumulate_as_a_cadence_gap() -> None:
    repository = FakeRepository()
    scope_value = scope()
    tick = [0.0]
    poll_starts: list[float] = []
    unavailable = tuple(SymbolObservation(symbol=symbol, available=False) for symbol in SYMBOLS)

    async def measure():
        poll_starts.append(tick[0])
        tick[0] += 3
        return MeasurementBatch(
            captured_at_ms=int(datetime.now(UTC).timestamp() * 1_000), symbols=unavailable
        )

    async def read_health(run_id, requested_scope):
        return healthy(requested_scope)

    async def fast_sleep(seconds: float) -> None:
        tick[0] += seconds

    await record_readonly_window(
        repository,
        scope_value,
        measure=measure,
        read_health=read_health,
        sample_period_ms=60_000,
        duration_s=86_400,
        sleep=fast_sleep,
        monotonic=lambda: tick[0],
    )
    assert poll_starts[:3] == [0.0, 60.0, 120.0]


async def test_unknown_or_unreconciled_health_refuses_without_fabricated_observation() -> None:
    repository = FakeRepository()
    scope_value = scope()
    tick = [0.0]
    complete = tuple(SymbolObservation(symbol=symbol, available=False) for symbol in SYMBOLS)

    async def measure():
        return MeasurementBatch(captured_at_ms=int(datetime.now(UTC).timestamp() * 1_000), symbols=complete)

    async def unknown_health(run_id, requested_scope):
        value = healthy(requested_scope)
        return replace(value, unresolved_bar_gaps=None)

    with pytest.raises(ValueError, match="gap count is unknown"):
        await record_readonly_window(
            repository,
            scope_value,
            measure=measure,
            read_health=unknown_health,
            sample_period_ms=60_000,
            duration_s=86_400,
            sleep=lambda seconds: asyncio.sleep(0),
            monotonic=lambda: tick[0],
        )
    assert repository.observations == []
    assert not repository.certified


async def test_cancellation_does_not_certify_or_swallow_cancellation() -> None:
    repository = FakeRepository()
    scope_value = scope()
    complete = tuple(SymbolObservation(symbol=symbol, available=False) for symbol in SYMBOLS)
    count = 0

    async def measure():
        return MeasurementBatch(captured_at_ms=int(datetime.now(UTC).timestamp() * 1_000), symbols=complete)

    async def read_health(run_id, requested_scope):
        return healthy(requested_scope)

    async def cancel_after_one(seconds: float) -> None:
        nonlocal count
        count += 1
        raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await record_readonly_window(
            repository,
            scope_value,
            measure=measure,
            read_health=read_health,
            sample_period_ms=60_000,
            duration_s=86_400,
            sleep=cancel_after_one,
        )
    assert count == 1
    assert len(repository.observations) == 1
    assert not repository.certified
