import re
from datetime import UTC, datetime

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
    adapter = EvedexAdapter(
        exchange_base_url="https://example.invalid",
        signer=RecordingSigner(),
        chain_id=1,
        dry_run=True,
        clock=lambda: NOW,
    )

    with pytest.raises(ValueError, match="deterministic"):
        await adapter.close_position("BTCUSDT")

    close_id = "00384:ABCDEF0123456789ABCDEF0123"
    report = await adapter.close_position("BTCUSDT", client_order_id=close_id)
    assert report.client_order_id == close_id


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
