from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest

from kairos_execution.adapters import evedex
from kairos_execution.adapters.evedex import EvedexAdapter

NOW = datetime(2026, 10, 21, 12, tzinfo=UTC)
ORDER_ID = "00384:ABCDEF0123456789ABCDEF0123"


def _adapter() -> EvedexAdapter:
    return EvedexAdapter(
        exchange_base_url="https://example.invalid",
        signer=object(),  # Read-only calls never invoke the signer.
        chain_id=1,
        jwt="synthetic-jwt",
        dry_run=False,
        clock=lambda: NOW,
    )


def _order(order_id: str = ORDER_ID, *, user: str = "23") -> dict:
    return {
        "id": order_id,
        "user": user,
        "instrument": "BTCUSDT",
        "side": "BUY",
        "type": "LIMIT",
        "quantity": "0.25",
        "unFilledQuantity": "0.1",
        "filledAvgPrice": "64000.0",
        "status": "PARTIALLY_FILLED",
        "createdAt": "2026-10-20T10:00:00.000Z",
        "updatedAt": "2026-10-20T10:01:00.000Z",
    }


@pytest.mark.asyncio
async def test_order_history_uses_documented_bounded_pagination_and_account_binding():
    adapter = _adapter()
    pages = {
        0: {"list": [_order(f"00384:{index:026X}") for index in range(100)], "count": 101},
        100: {"list": [_order("00384:ABCDEF0123456789ABCDEF0123")], "count": 101},
    }

    async def get_page(path, *, params=None):
        assert path == "/api/order"
        assert params["version"] == 2
        assert params["limit"] == 100
        return pages[params["offset"]]

    adapter._get = AsyncMock(return_value={"exchangeId": 23})
    adapter._get_with_params = AsyncMock(side_effect=get_page)
    result = await adapter.fetch_order_history()

    assert result.exchange_account_id == "23"
    assert result.reported_count == 101
    assert result.page_count == 2
    assert len(result.orders) == 101
    assert result.orders[0].status.value == "PARTIALLY_FILLED"
    assert result.authoritative_reconciliation is False
    assert [call.args[0] for call in adapter._get_with_params.await_args_list] == [
        "/api/order",
        "/api/order",
    ]
    assert [call.kwargs["params"]["offset"] for call in adapter._get_with_params.await_args_list] == [0, 100]


@pytest.mark.asyncio
async def test_order_history_rejects_duplicate_pages_from_nonadvancing_server():
    adapter = _adapter()

    async def get_page(path, *, params=None):
        return {"list": [_order()], "count": 2}

    adapter._get = AsyncMock(return_value={"exchangeId": 23})
    adapter._get_with_params = AsyncMock(side_effect=get_page)
    with pytest.raises(ValueError, match="duplicate IDs"):
        await adapter.fetch_order_history()


@pytest.mark.asyncio
async def test_order_history_rejects_partial_page_and_count_drift():
    adapter = _adapter()
    responses = iter(
        [
            {"list": [_order()], "count": 2},
            {"list": [], "count": 2},
        ]
    )

    async def get_page(path, *, params=None):
        return next(responses)

    adapter._get = AsyncMock(return_value={"exchangeId": 23})
    adapter._get_with_params = AsyncMock(side_effect=get_page)
    with pytest.raises(ValueError, match="empty"):
        await adapter.fetch_order_history()

    adapter = _adapter()
    responses = iter(
        [
            {"list": [_order()], "count": 2},
            {"list": [_order("00384:ABCDEF0123456789ABCDEF0124")], "count": 3},
        ]
    )

    async def drift(path, *, params=None):
        return next(responses)

    adapter._get = AsyncMock(return_value={"exchangeId": 23})
    adapter._get_with_params = AsyncMock(side_effect=drift)
    with pytest.raises(ValueError, match="count changed"):
        await adapter.fetch_order_history()


@pytest.mark.asyncio
async def test_order_history_refuses_unbounded_count_and_wrong_account_rows():
    adapter = _adapter()

    async def over_limit(path, *, params=None):
        return {"list": [], "count": 10_001}

    adapter._get = AsyncMock(return_value={"exchangeId": 23})
    adapter._get_with_params = AsyncMock(side_effect=over_limit)
    with pytest.raises(ValueError, match="record bound"):
        await adapter.fetch_order_history()

    adapter = _adapter()

    async def wrong_account(path, *, params=None):
        return {"list": [_order(user="24")], "count": 1}

    adapter._get = AsyncMock(return_value={"exchangeId": 23})
    adapter._get_with_params = AsyncMock(side_effect=wrong_account)
    with pytest.raises(ValueError, match="authenticated account"):
        await adapter.fetch_order_history()


@pytest.mark.asyncio
async def test_order_history_preserves_documented_terminal_statuses_and_rejects_bad_quantities():
    adapter = _adapter()
    adapter._get = AsyncMock(return_value={"exchangeId": 23})
    adapter._get_with_params = AsyncMock(return_value={"list": [_order()], "count": 1})
    first = await adapter.fetch_order_history()
    assert first.orders[0].status.value == "PARTIALLY_FILLED"

    for status in ("REPLACED", "EXPIRED"):
        adapter = _adapter()
        terminal_order = {
            **_order(),
            "status": status,
            "unFilledQuantity": "0.25",
            "filledAvgPrice": "0",
        }
        adapter._get = AsyncMock(return_value={"exchangeId": 23})
        adapter._get_with_params = AsyncMock(return_value={"list": [terminal_order], "count": 1})
        result = await adapter.fetch_order_history()
        assert result.orders[0].status.value == status

    adapter = _adapter()
    malformed_order = {**_order(), "unFilledQuantity": "0.3"}
    adapter._get = AsyncMock(return_value={"exchangeId": 23})
    adapter._get_with_params = AsyncMock(return_value={"list": [malformed_order], "count": 1})
    with pytest.raises(ValueError, match="inconsistent requested"):
        await adapter.fetch_order_history()

    adapter = _adapter()
    missing_average = {**_order(), "filledAvgPrice": "0"}
    adapter._get = AsyncMock(return_value={"exchangeId": 23})
    adapter._get_with_params = AsyncMock(return_value={"list": [missing_average], "count": 1})
    with pytest.raises(ValueError, match="no positive average"):
        await adapter.fetch_order_history()


@pytest.mark.asyncio
async def test_order_history_rejects_stale_nonadvancing_clock():
    adapter = _adapter()
    times = iter([NOW, datetime(2026, 10, 21, 11, 59, tzinfo=UTC)])
    adapter._clock = lambda: next(times)
    adapter._get = AsyncMock(return_value={"exchangeId": 23})
    adapter._get_with_params = AsyncMock(return_value={"list": [_order()], "count": 1})
    with pytest.raises(ValueError, match="clock moved backwards"):
        await adapter.fetch_order_history()


@pytest.mark.asyncio
async def test_order_history_and_fills_require_fast_bounded_completion(monkeypatch):
    monkeypatch.setattr(evedex, "ORDER_HISTORY_MAX_SECONDS", 0.01)
    adapter = _adapter()

    async def hang(path, *, params=None):
        await __import__("asyncio").sleep(1)

    adapter._get = AsyncMock(side_effect=hang)
    with pytest.raises(ValueError, match="timed out"):
        await adapter.fetch_order_history()
    with pytest.raises(ValueError, match="timed out"):
        await adapter.fetch_order_fills(ORDER_ID)


@pytest.mark.asyncio
async def test_order_history_api_error_is_propagated_without_partial_read():
    adapter = _adapter()
    adapter._get = AsyncMock(return_value={"exchangeId": 23})
    adapter._get_with_params = AsyncMock(side_effect=RuntimeError("synthetic HTTP 503"))
    with pytest.raises(RuntimeError, match="synthetic HTTP 503"):
        await adapter.fetch_order_history()


@pytest.mark.asyncio
async def test_get_uses_existing_authenticated_http_session_and_documented_query(monkeypatch):
    adapter = _adapter()
    seen: dict[str, object] = {}

    class FakeResponse:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        def raise_for_status(self):
            seen["status_checked"] = True

        async def json(self):
            return {"list": [], "count": 0}

    class FakeSession:
        def __init__(self, *, headers):
            seen["headers"] = headers

        def get(self, url, *, params=None):
            seen["url"] = url
            seen["params"] = params
            seen["method"] = "GET"
            return FakeResponse()

    monkeypatch.setattr(evedex.aiohttp, "ClientSession", FakeSession)
    adapter._bucket.acquire = AsyncMock()
    payload = await adapter._get_with_params(
        "/api/order",
        params={"version": 2, "limit": 100, "offset": 0},
    )

    assert seen == {
        "headers": {"Authorization": "Bearer synthetic-jwt"},
        "url": "https://example.invalid/api/order",
        "params": {"version": 2, "limit": 100, "offset": 0},
        "method": "GET",
        "status_checked": True,
    }
    assert payload == {"list": [], "count": 0}


@pytest.mark.asyncio
async def test_order_fills_use_exact_account_bound_get_and_validate_rows():
    adapter = _adapter()
    fill = {
        "executionId": "exec-1",
        "instrument": "BTCUSDT",
        "side": "BUY",
        "fillQuantity": "0.15",
        "fillPrice": "64000.5",
        "createdAt": "2026-10-20T10:00:01.000Z",
        "makerTakerFlag": "TAKER",
        "orderId": ORDER_ID,
    }

    async def get(path, *, params=None):
        if path == "/api/user/me":
            return {"exchangeId": 23}
        if path == "/api/order/00384%3AABCDEF0123456789ABCDEF0123":
            return _order()
        assert path == "/api/order/00384%3AABCDEF0123456789ABCDEF0123/fill"
        return [fill]

    adapter._get = AsyncMock(side_effect=get)
    result = await adapter.fetch_order_fills(ORDER_ID)
    assert result.exchange_account_id == "23"
    assert result.fills[0].quantity == 0.15
    assert result.fills[0].maker_taker_flag == "TAKER"
    assert result.authoritative_reconciliation is False

    adapter._get = AsyncMock(side_effect=[{"exchangeId": 23}, _order(), [fill, fill]])
    with pytest.raises(ValueError, match="duplicate execution"):
        await adapter.fetch_order_fills(ORDER_ID)

    adapter._get = AsyncMock(
        side_effect=[
            {"exchangeId": 23},
            _order(),
            [{**fill, "orderId": "00384:ABCDEF0123456789ABCDEF0124"}],
        ]
    )
    with pytest.raises(ValueError, match="different order"):
        await adapter.fetch_order_fills(ORDER_ID)


@pytest.mark.asyncio
async def test_order_reads_fail_closed_without_jwt_or_for_dry_run():
    adapter = _adapter()
    adapter.jwt = None
    with pytest.raises(RuntimeError, match="JWT"):
        await adapter.fetch_order_history()
    with pytest.raises(RuntimeError, match="JWT"):
        await adapter.fetch_order_fills(ORDER_ID)

    adapter = _adapter()
    adapter.dry_run = True
    with pytest.raises(RuntimeError, match="dry-run"):
        await adapter.fetch_order_history()
    with pytest.raises(RuntimeError, match="dry-run"):
        await adapter.fetch_order_fills(ORDER_ID)

    adapter = _adapter()
    adapter._get = AsyncMock()
    with pytest.raises(ValueError, match="unsafe characters"):
        await adapter.fetch_order_fills("../../account")
    adapter._get.assert_not_awaited()
