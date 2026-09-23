from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from kairos_core.contracts import OrderIntent
from kairos_core.enums import OrderSide, OrderType, ReasonCode

from kairos_execution.adapters.ccxt_adapter import CCXTAdapter
from kairos_execution.adapters.evedex import EvedexAdapter
from kairos_execution.live_authorization import (
    LiveMutationAuthorization,
    LiveMutationAuthorizationError,
)


class RecordingSigner:
    address = "0x0000000000000000000000000000000000000000"

    def __init__(self) -> None:
        self.messages: list[dict] = []

    def sign_typed_data(self, domain, types, message) -> str:
        self.messages.append(message)
        return "0x" + "00" * 65


def _intent() -> OrderIntent:
    return OrderIntent(
        source="risk",
        message_id="live-gate-test-order",
        produced_at=datetime.now(UTC),
        symbol="BTCUSDT",
        side=OrderSide.BUY,
        order_type=OrderType.LIMIT,
        quantity=0.1,
        price=65_000,
        reason_code=ReasonCode.ENTER_LONG_TREND,
    )


def _evedex_adapter(signer: RecordingSigner | None = None) -> EvedexAdapter:
    return EvedexAdapter(
        exchange_base_url="https://example.invalid",
        signer=signer or RecordingSigner(),
        chain_id=161803,
        dry_run=False,
    )


def test_live_authorization_cannot_be_constructed_without_release_issuer():
    with pytest.raises(TypeError, match="issued by the release gate"):
        LiveMutationAuthorization()


@pytest.mark.asyncio
async def test_direct_evedex_place_order_fails_before_signing_or_network():
    signer = RecordingSigner()
    adapter = _evedex_adapter(signer)
    adapter._session_get = AsyncMock(side_effect=AssertionError("network must not be reached"))

    with pytest.raises(LiveMutationAuthorizationError, match="LIVE release authorization"):
        await adapter.place_order(_intent())

    assert signer.messages == []
    adapter._session_get.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "args"),
    [
        ("_post", ("/api/v2/order/market", {"id": "test"})),
        ("_put", ("/api/position/BTCUSD", {"leverage": 2})),
    ],
)
async def test_evedex_http_mutation_sinks_fail_closed(method, args):
    adapter = _evedex_adapter()
    adapter._session_get = AsyncMock(side_effect=AssertionError("network must not be reached"))

    with pytest.raises(LiveMutationAuthorizationError):
        await getattr(adapter, method)(*args)

    adapter._session_get.assert_not_awaited()


@pytest.mark.asyncio
async def test_direct_evedex_cancel_fails_before_order_lookup_or_delete():
    adapter = _evedex_adapter()
    adapter.is_order_active_by_client_id = AsyncMock(return_value=True)
    adapter._session_get = AsyncMock(side_effect=AssertionError("network must not be reached"))

    with pytest.raises(LiveMutationAuthorizationError):
        await adapter.cancel_order_by_client_id(
            "BTCUSDT",
            "00384:ABCDEF0123456789ABCDEF0123",
        )

    adapter.is_order_active_by_client_id.assert_not_awaited()
    adapter._session_get.assert_not_awaited()


@pytest.mark.asyncio
async def test_direct_ccxt_mutations_fail_before_client_calls():
    client = SimpleNamespace(
        create_order=AsyncMock(),
        cancel_order=AsyncMock(),
        set_leverage=AsyncMock(),
        fetch_open_orders=AsyncMock(),
        fetch_positions=AsyncMock(),
    )
    adapter = CCXTAdapter(dry_run=True)
    adapter.dry_run = False
    adapter._client = client

    operations = (
        adapter.place_order(_intent()),
        adapter.cancel_order_by_client_id("BTC/USDT:USDT", "client-order-1"),
        adapter.close_position(
            "BTC/USDT:USDT",
            quantity=0.1,
            side=OrderSide.SELL,
            client_order_id="client-close-1",
        ),
        adapter.set_leverage("BTC/USDT:USDT", 2),
        adapter.set_protective_stop("BTC/USDT:USDT", 64_000, OrderSide.BUY, "entry-1"),
    )
    for operation in operations:
        with pytest.raises(LiveMutationAuthorizationError):
            await operation

    for method in (client.create_order, client.cancel_order, client.set_leverage):
        method.assert_not_awaited()
    client.fetch_open_orders.assert_not_awaited()
    client.fetch_positions.assert_not_awaited()
