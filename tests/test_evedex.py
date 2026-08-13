import re
from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest
from kairos_core.contracts import OrderIntent
from kairos_core.enums import OrderSide, OrderStatus, OrderType, ReasonCode

from kairos_execution.adapters.evedex import EvedexAdapter

NOW = datetime(2026, 8, 12, 12, tzinfo=UTC)


class RecordingSigner:
    address = "0x0000000000000000000000000000000000000000"

    def __init__(self) -> None:
        self.messages: list[dict] = []

    def sign_typed_data(self, domain, types, message) -> str:
        self.messages.append(message)
        return "0x" + "00" * 65


def _intent(*, client_order_id: str | None = None) -> OrderIntent:
    return OrderIntent(
        source="risk",
        message_id="validated-order-1",
        produced_at=NOW,
        client_order_id=client_order_id,
        symbol="BTCUSDT",
        side=OrderSide.BUY,
        order_type=OrderType.LIMIT,
        quantity=0.1,
        price=65_000,
        reason_code=ReasonCode.ENTER_LONG_TREND,
    )


@pytest.mark.asyncio
async def test_generated_order_id_matches_evedex_format_and_is_deterministic():
    signer = RecordingSigner()
    adapter = EvedexAdapter(
        exchange_base_url="https://example.invalid",
        signer=signer,
        chain_id=1,
        dry_run=True,
        clock=lambda: NOW,
    )

    first = await adapter.place_order(_intent())
    second = await adapter.place_order(_intent())

    assert first.client_order_id == second.client_order_id
    assert re.fullmatch(r"[0-9]{5}:[0-9A-Fa-f]{26}", first.client_order_id)
    assert signer.messages[0]["id"] == first.client_order_id
    assert signer.messages[1]["id"] == second.client_order_id


@pytest.mark.asyncio
async def test_valid_evedex_order_id_is_preserved():
    client_id = "00384:0123456789ABCDEF0123456789"
    adapter = EvedexAdapter(
        exchange_base_url="https://example.invalid",
        signer=RecordingSigner(),
        chain_id=1,
        dry_run=True,
        clock=lambda: NOW,
    )

    report = await adapter.place_order(_intent(client_order_id=client_id))

    assert report.client_order_id == client_id


@pytest.mark.asyncio
async def test_legacy_order_id_is_mapped_deterministically():
    adapter = EvedexAdapter(
        exchange_base_url="https://example.invalid",
        signer=RecordingSigner(),
        chain_id=1,
        dry_run=True,
        clock=lambda: NOW,
    )
    intent = _intent(client_order_id="legacy-order-id")

    first = await adapter.place_order(intent)
    second = await adapter.place_order(intent)

    assert first.client_order_id == second.client_order_id
    assert first.client_order_id != intent.client_order_id
    assert re.fullmatch(r"[0-9]{5}:[0-9A-Fa-f]{26}", first.client_order_id)


@pytest.mark.asyncio
async def test_stale_order_id_is_rejected_before_signing_or_posting():
    signer = RecordingSigner()
    adapter = EvedexAdapter(
        exchange_base_url="https://example.invalid",
        signer=signer,
        chain_id=1,
        dry_run=True,
        clock=lambda: NOW,
    )

    report = await adapter.place_order(_intent(client_order_id="00382:0123456789ABCDEF0123456789"))

    assert report.status.value == "REJECTED"
    assert "stale" in report.message
    assert signer.messages == []


@pytest.mark.asyncio
async def test_close_requires_deterministic_fresh_order_id():
    signer = RecordingSigner()
    adapter = EvedexAdapter(
        exchange_base_url="https://example.invalid",
        signer=signer,
        chain_id=1,
        dry_run=True,
        clock=lambda: NOW,
    )

    with pytest.raises(ValueError, match="deterministic"):
        await adapter.close_position("BTCUSDT")

    close_id = "00384:ABCDEF0123456789ABCDEF0123"
    report = await adapter.close_position("BTCUSDT", quantity=0.25, client_order_id=close_id)
    assert report.client_order_id == close_id
    assert report.requested_qty == 0.25
    assert signer.messages[-1]["quantity"] == 25_000_000


@pytest.mark.asyncio
async def test_market_order_without_reference_price_is_rejected_before_signing():
    signer = RecordingSigner()
    adapter = EvedexAdapter(
        exchange_base_url="https://example.invalid",
        signer=signer,
        chain_id=1,
        dry_run=True,
        clock=lambda: NOW,
    )
    intent = _intent().model_copy(update={"order_type": OrderType.MARKET, "price": None})

    report = await adapter.place_order(intent)

    assert report.status is OrderStatus.REJECTED
    assert "reference price" in report.message
    assert signer.messages == []


@pytest.mark.asyncio
async def test_full_account_snapshot_is_cross_checked_and_normalized():
    adapter = EvedexAdapter(
        exchange_base_url="https://example.invalid",
        signer=RecordingSigner(),
        chain_id=1,
        jwt="jwt",
        dry_run=False,
        clock=lambda: NOW,
    )
    responses = {
        "/api/user/me": {"exchangeId": "exchange-42", "marginCall": False},
        "/api/market/available-balance": {
            "funding": {"currency": "USDT", "balance": "10000"},
            "availableBalance": "8000",
            "negativeUnPnL": "50",
            "position": [
                {
                    "instrument": "BTCUSDT",
                    "side": "BUY",
                    "volume": "0.2",
                    "initialMargin": "1000",
                }
            ],
            "openOrder": [
                {
                    "instrument": "BTCUSDT",
                    "side": "SELL",
                    "unFilledVolume": "0.1",
                }
            ],
        },
        "/api/position": [
            {
                "instrument": "BTCUSDT",
                "side": "BUY",
                "quantity": "0.2",
                "avgPrice": "65000",
                "markPrice": "64750",
                "leverage": 2,
                "liquidationPrice": "32000",
                "unrealizedPnL": "-50",
            }
        ],
        "/api/order/opened": [
            {
                "id": "order-1",
                "instrument": "BTCUSDT",
                "side": "SELL",
                "unFilledQuantity": "0.1",
            }
        ],
        "/api/tpsl": {
            "list": [
                {
                    "id": "stop-1",
                    "instrument": "BTCUSDT",
                    "type": "stop-loss",
                    "status": "active",
                }
            ]
        },
    }
    adapter._get = AsyncMock(side_effect=lambda path: responses[path])

    snapshot = await adapter.fetch_account_snapshot(account_id="primary", peak_equity_usd=10_100)

    assert snapshot.reconciled is True
    assert snapshot.equity_usd == 9_950
    assert snapshot.available_balance_usd == 8_000
    assert snapshot.margin_used_usd == 1_000
    assert snapshot.peak_equity_usd == 10_100
    assert snapshot.open_order_ids == ["order-1"]
    assert snapshot.positions[0].signed_quantity == 0.2
    assert snapshot.positions[0].mark_price == 64_750
    assert snapshot.positions[0].protective_stop_order_id == "stop-1"


@pytest.mark.asyncio
async def test_account_snapshot_rejects_cross_endpoint_position_mismatch():
    adapter = EvedexAdapter(
        exchange_base_url="https://example.invalid",
        signer=RecordingSigner(),
        chain_id=1,
        jwt="jwt",
        dry_run=False,
        clock=lambda: NOW,
    )
    responses = {
        "/api/user/me": {"exchangeId": "exchange-42", "marginCall": False},
        "/api/market/available-balance": {
            "funding": {"balance": "10000"},
            "availableBalance": "9000",
            "negativeUnPnL": 0,
            "position": [{"instrument": "BTCUSDT", "side": "BUY", "volume": "0.2"}],
            "openOrder": [],
        },
        "/api/position": [
            {
                "instrument": "BTCUSDT",
                "side": "BUY",
                "quantity": "0.3",
                "avgPrice": "65000",
            }
        ],
        "/api/order/opened": [],
        "/api/tpsl": {"list": []},
    }
    adapter._get = AsyncMock(side_effect=lambda path: responses[path])

    with pytest.raises(ValueError, match="position detail"):
        await adapter.fetch_account_snapshot(account_id="primary", peak_equity_usd=10_000)
