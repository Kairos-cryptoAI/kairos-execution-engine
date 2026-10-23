"""Synthetic-only tests for the read-only EVEDEX PROD account observation seam."""

import asyncio
import hashlib
import inspect
import json
from datetime import UTC, datetime, timedelta

import pytest

from kairos_execution.production_observation import (
    MAX_COMPONENT_BYTES,
    PROD_EXCHANGE_ORIGIN,
    AiohttpProdGetJson,
    ProductionAccountObservationV1,
    ProductionAccountObserver,
    ProductionObservationError,
)
from kairos_execution.production_readiness import ProductionContextV1

_SYNTHETIC = "synthetic fixture; not captured venue evidence"
_T0 = datetime(2026, 10, 23, 12, tzinfo=UTC)


def _context(account: str = "42") -> ProductionContextV1:
    return ProductionContextV1(
        remote_account_id=account,
        adaptive_system_id="synthetic-system",
        frozen_policy_sha256="a" * 64,
        source_set_sha256="b" * 64,
    )


def _responses(account_before: int | str = 42, account_after: int | str = 42) -> dict[str, object]:
    return {
        "/api/user/me": [
            {"exchangeId": account_before, "marginCall": False, "fixture_note": _SYNTHETIC},
            {"exchangeId": account_after, "marginCall": False, "fixture_note": _SYNTHETIC},
        ],
        "/api/market/available-balance": {
            "funding": {"balance": "10000"},
            "availableBalance": "8000",
            "negativeUnPnL": "50",
            "position": [{"instrument": "BTCUSD", "side": "BUY", "volume": "0.2"}],
            "openOrder": [{"instrument": "BTCUSD", "side": "SELL", "unFilledVolume": "0.1"}],
            "fixture_note": _SYNTHETIC,
        },
        "/api/position": [
            {
                "instrument": "BTCUSD",
                "side": "BUY",
                "quantity": "0.2",
                "avgPrice": "65000",
                "markPrice": "64750",
                "leverage": 1,
                "unrealizedPnL": "-50",
                "fixture_note": _SYNTHETIC,
            }
        ],
        "/api/order/opened": [
            {
                "id": "synthetic-order-1",
                "instrument": "BTCUSD",
                "side": "SELL",
                "unFilledQuantity": "0.1",
                "fixture_note": _SYNTHETIC,
            }
        ],
        "/api/tpsl": {
            "list": [
                {
                    "id": "synthetic-stop-1",
                    "instrument": "BTCUSD",
                    "type": "stop-loss",
                    "side": "BUY",
                    "quantity": "0",
                    "price": "64000",
                    "status": "active",
                    "order": "synthetic-parent-1",
                    "fixture_note": _SYNTHETIC,
                }
            ]
        },
    }


class _Clock:
    def __init__(self) -> None:
        self.value = _T0

    def __call__(self) -> datetime:
        result = self.value
        self.value += timedelta(milliseconds=2)
        return result


def _observer(*, responses=None, context=None, get_json=None, **kwargs) -> ProductionAccountObserver:
    fixtures = responses or _responses()
    account_calls = 0
    calls: list[str] = []

    async def read(path: str):
        nonlocal account_calls
        calls.append(path)
        value = fixtures[path]
        if path == "/api/user/me":
            index = account_calls
            account_calls += 1
            return value[index]  # type: ignore[index]
        return value

    observer = ProductionAccountObserver(
        context=context or _context(),
        jwt="synthetic-jwt",
        get_json=get_json or read,
        clock=_Clock(),
        **kwargs,
    )
    observer._test_calls = calls
    return observer


@pytest.mark.asyncio
async def test_capture_is_immutable_bounded_account_bound_and_explicitly_non_authoritative():
    observer = _observer()
    observation = await observer.capture_once()

    assert isinstance(observation, ProductionAccountObservationV1)
    assert observation.exchange_account_id == "42"
    assert observation.context == _context("42")
    assert observation.authoritative_reconciliation is False
    assert observation.readiness is False
    assert observation.captured_started_at <= observation.captured_finished_at
    assert tuple(component.name for component in observation.components) == (
        "account_before",
        "available_balance",
        "positions",
        "open_orders",
        "tpsl",
        "account_after",
    )
    assert observer._test_calls == [
        "/api/user/me",
        "/api/market/available-balance",
        "/api/position",
        "/api/order/opened",
        "/api/tpsl",
        "/api/user/me",
    ]
    assert all(path.startswith("/api/") for path in observer._test_calls)
    assert len({component.raw_sha256 for component in observation.components}) == 5
    assert observation.components[0].raw_sha256 == observation.components[-1].raw_sha256
    component = observation.components[2]
    assert hashlib.sha256(component.raw_payload_json.encode()).hexdigest() == component.raw_sha256
    assert hashlib.sha256(component.normalized_payload_json.encode()).hexdigest() == (
        component.normalized_sha256
    )
    assert _SYNTHETIC in component.raw_payload_json
    assert json.loads(component.normalized_payload_json)[0]["quantity"] == 0.2
    with pytest.raises(ValueError):
        observation.exchange_account_id = "43"  # type: ignore[misc]


@pytest.mark.asyncio
async def test_context_alias_is_not_accepted_as_authenticated_exchange_id():
    observer = _observer(context=_context("primary"))
    with pytest.raises(ProductionObservationError, match="does not match"):
        await observer.capture_once()
    assert observer._test_calls == ["/api/user/me"]


@pytest.mark.asyncio
async def test_changed_account_identity_during_capture_discards_observation():
    observer = _observer(responses=_responses(42, 43))
    with pytest.raises(ProductionObservationError, match="changed during capture"):
        await observer.capture_once()
    assert observer._test_calls[-1] == "/api/user/me"


@pytest.mark.asyncio
async def test_embedded_order_owner_cannot_contradict_authenticated_account():
    responses = _responses()
    responses["/api/order/opened"][0]["user"] = 43
    with pytest.raises(ProductionObservationError, match="does not match"):
        await _observer(responses=responses).capture_once()


@pytest.mark.parametrize(
    "url",
    [
        "http://trading-api.evedex.com",
        "https://trading-api.evedex.tech",
        "https://trading-api.evedex.com/other",
        "https://trading-api.evedex.com?redirect=1",
        "https://user@trading-api.evedex.com",
    ],
)
def test_observer_and_transport_reject_noncanonical_or_nonprod_origins(url):
    with pytest.raises(ValueError, match="official PROD"):
        _observer(exchange_base_url=url)
    with pytest.raises(ValueError, match="official PROD"):
        AiohttpProdGetJson(jwt="synthetic-jwt", exchange_base_url=url)


def test_read_seam_has_no_signer_or_chain_parameter_and_transport_only_exposes_get():
    parameters = inspect.signature(ProductionAccountObserver).parameters
    assert "signer" not in parameters
    assert "chain_id" not in parameters
    transport = AiohttpProdGetJson(jwt="synthetic-jwt")
    assert callable(transport)
    assert PROD_EXCHANGE_ORIGIN == "https://trading-api.evedex.com"


@pytest.mark.asyncio
async def test_missing_jwt_and_margin_call_fail_closed():
    with pytest.raises(ValueError, match="require a JWT"):
        ProductionAccountObserver(context=_context(), jwt=" ", get_json=lambda _: None)

    responses = _responses()
    responses["/api/user/me"] = [{"exchangeId": 42, "marginCall": True}]
    observer = _observer(responses=responses)
    with pytest.raises(ProductionObservationError, match="malformed"):
        await observer.capture_once()
    assert observer._test_calls == ["/api/user/me"]


@pytest.mark.asyncio
async def test_bad_account_identity_in_later_component_fails_closed():
    responses = _responses()
    responses["/api/market/available-balance"] = {
        "funding": {"balance": "NaN"},
        "availableBalance": "8000",
        "negativeUnPnL": "0",
        "position": [],
        "openOrder": [],
    }
    observer = _observer(responses=responses)
    with pytest.raises(ProductionObservationError, match="malformed"):
        await observer.capture_once()


@pytest.mark.asyncio
async def test_nonfinite_json_and_position_summary_mismatch_fail_closed():
    responses = _responses()
    responses["/api/market/available-balance"] = {
        **responses["/api/market/available-balance"],  # type: ignore[arg-type]
        "negativeUnPnL": float("nan"),
    }
    observer = _observer(responses=responses)
    with pytest.raises(ProductionObservationError, match="malformed"):
        await observer.capture_once()

    responses = _responses()
    responses["/api/position"] = []
    observer = _observer(responses=responses)
    with pytest.raises(ProductionObservationError, match="malformed"):
        await observer.capture_once()


@pytest.mark.asyncio
async def test_malformed_tpsl_is_not_hidden_in_raw_capture():
    responses = _responses()
    responses["/api/tpsl"] = {
        "list": [
            {
                "id": "synthetic-stop",
                "instrument": "BTCUSD",
                "type": "stop-loss",
                "side": "BUY",
                "quantity": "NaN",
                "price": "64000",
                "status": "active",
            }
        ]
    }
    observer = _observer(responses=responses)
    with pytest.raises(ProductionObservationError, match="malformed"):
        await observer.capture_once()


@pytest.mark.asyncio
async def test_timeout_discards_partial_capture():
    started = asyncio.Event()

    async def slow_get(path: str):
        started.set()
        await asyncio.Event().wait()

    observer = _observer(get_json=slow_get, max_capture_seconds=0.02)
    with pytest.raises(ProductionObservationError, match="timed out"):
        await observer.capture_once()
    assert started.is_set()


@pytest.mark.asyncio
async def test_clock_regression_between_components_and_wall_time_jump_are_rejected():
    observer = _observer()
    ticks = iter([_T0, _T0, _T0 + timedelta(milliseconds=10), _T0 + timedelta(milliseconds=5)])
    observer._clock = lambda: next(ticks)
    with pytest.raises(ProductionObservationError, match="clock moved backwards"):
        await observer.capture_once()

    observer = _observer()
    tick = _T0

    def clock():
        nonlocal tick
        tick += timedelta(seconds=1)
        return tick

    observer._clock = clock
    with pytest.raises(ProductionObservationError, match="bounded capture"):
        await observer.capture_once()


@pytest.mark.asyncio
async def test_boolean_amount_is_not_accepted_as_one_dollar():
    responses = _responses()
    responses["/api/market/available-balance"]["funding"]["balance"] = True
    with pytest.raises(ProductionObservationError, match="malformed"):
        await _observer(responses=responses).capture_once()


class _Context:
    def __init__(self, value):
        self.value = value

    async def __aenter__(self):
        return self.value

    async def __aexit__(self, *args):
        return False


def _mock_http(monkeypatch, chunks, *, status=200):
    import aiohttp

    calls = []

    class Content:
        async def iter_chunked(self, size):
            for chunk in chunks:
                yield chunk

    class Response:
        content = Content()

        def __init__(self):
            self.status = status

    class Session:
        def get(self, url, **kwargs):
            calls.append((url, kwargs))
            return _Context(Response())

    monkeypatch.setattr(aiohttp, "ClientSession", lambda **kwargs: _Context(Session()))
    return calls


@pytest.mark.asyncio
async def test_real_transport_seam_is_get_only_nonredirecting_and_path_allowlisted(monkeypatch):
    calls = _mock_http(monkeypatch, [b'{"exchangeId":42}'])
    transport = AiohttpProdGetJson(jwt="synthetic-jwt")
    assert await transport("/api/user/me") == {"exchangeId": 42}
    assert calls == [(PROD_EXCHANGE_ORIGIN + "/api/user/me", {"allow_redirects": False})]
    for path in ("/api/logout", "/api/user/me/../../logout", "/api/user/me?x=1"):
        with pytest.raises(ProductionObservationError, match="unsupported"):
            await transport(path)
    assert len(calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "chunks,status",
    [
        ([b'{"exchangeId":42,"exchangeId":43}'], 200),
        ([b'{"amount":NaN}'], 200),
        ([b"not-json"], 200),
        ([b"x" * MAX_COMPONENT_BYTES, b"x"], 200),
        ([b"{}"], 302),
    ],
)
async def test_transport_refuses_ambiguous_nonfinite_oversized_or_redirected_response(
    monkeypatch, chunks, status
):
    _mock_http(monkeypatch, chunks, status=status)
    with pytest.raises(ProductionObservationError):
        await AiohttpProdGetJson(jwt="synthetic-jwt")("/api/user/me")
