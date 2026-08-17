import re
from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest
from kairos_core.contracts import OrderIntent
from kairos_core.enums import OrderSide, OrderStatus, OrderType, ReasonCode

from kairos_execution.adapters.evedex import EvedexAdapter

NOW = datetime(2026, 8, 12, 12, tzinfo=UTC)
PARENT_ORDER_ID = "00384:ABCDEF0123456789ABCDEF0123"


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
async def test_symbol_map_translates_orders_and_preserves_logical_report_symbol():
    signer = RecordingSigner()
    adapter = EvedexAdapter(
        exchange_base_url="https://example.invalid",
        signer=signer,
        chain_id=1,
        dry_run=True,
        symbol_map={"BTCUSDT": "BTCUSD"},
        clock=lambda: NOW,
    )

    report = await adapter.place_order(_intent())

    assert signer.messages[-1]["instrument"] == "BTCUSD"
    assert report.symbol == "BTCUSDT"


def test_symbol_map_must_be_one_to_one():
    with pytest.raises(ValueError, match="one-to-one"):
        EvedexAdapter(
            exchange_base_url="https://example.invalid",
            signer=RecordingSigner(),
            chain_id=1,
            dry_run=True,
            symbol_map={"BTCUSDT": "BTCUSD", "WBTCUSDT": "BTCUSD"},
        )


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
async def test_place_order_rejects_response_id_that_differs_from_submitted_id():
    adapter = EvedexAdapter(
        exchange_base_url="https://example.invalid",
        signer=RecordingSigner(),
        chain_id=1,
        dry_run=True,
        clock=lambda: NOW,
    )
    adapter._post = AsyncMock(return_value={"id": "attacker-controlled", "status": "NEW"})

    with pytest.raises(ValueError, match="does not match the submitted order ID"):
        await adapter.place_order(_intent(client_order_id=PARENT_ORDER_ID))


@pytest.mark.asyncio
async def test_close_rejects_response_id_that_differs_from_submitted_id():
    adapter = EvedexAdapter(
        exchange_base_url="https://example.invalid",
        signer=RecordingSigner(),
        chain_id=1,
        dry_run=True,
        clock=lambda: NOW,
    )
    adapter._post = AsyncMock(return_value={"id": "attacker-controlled", "status": "FILLED"})

    with pytest.raises(ValueError, match="does not match the submitted close ID"):
        await adapter.close_position(
            "BTCUSDT",
            quantity=0.1,
            side=OrderSide.SELL,
            client_order_id=PARENT_ORDER_ID,
        )


@pytest.mark.asyncio
async def test_unknown_evedex_order_status_is_not_coerced_to_new():
    adapter = EvedexAdapter(
        exchange_base_url="https://example.invalid",
        signer=RecordingSigner(),
        chain_id=1,
        dry_run=True,
        clock=lambda: NOW,
    )
    adapter._post = AsyncMock(return_value={"id": PARENT_ORDER_ID, "status": "mystery"})

    with pytest.raises(ValueError, match="unknown order status"):
        await adapter.place_order(_intent(client_order_id=PARENT_ORDER_ID))


@pytest.mark.asyncio
async def test_protective_stop_uses_server_assigned_id_without_inventing_payload_id():
    signer = RecordingSigner()
    adapter = EvedexAdapter(
        exchange_base_url="https://example.invalid",
        signer=signer,
        chain_id=1,
        dry_run=True,
        clock=lambda: NOW,
    )
    adapter._post = AsyncMock(return_value={"id": "server-stop-42", "status": "waitOrder"})

    ack = await adapter.set_protective_stop(
        "BTCUSDT",
        64_000.0,
        OrderSide.BUY,
        PARENT_ORDER_ID,
    )

    assert ack.exchange_order_id == "server-stop-42"
    path, payload = adapter._post.await_args.args
    assert path == "/api/tpsl/BTCUSDT"
    assert "id" not in payload
    assert payload["order"] == PARENT_ORDER_ID
    assert payload["side"] == "BUY"
    assert signer.messages[-1].keys() == {
        "instrument",
        "type",
        "side",
        "quantity",
        "price",
        "order",
    }
    assert signer.messages[-1]["order"] == PARENT_ORDER_ID


@pytest.mark.asyncio
async def test_protective_stop_without_server_id_fails_closed():
    adapter = EvedexAdapter(
        exchange_base_url="https://example.invalid",
        signer=RecordingSigner(),
        chain_id=1,
        dry_run=True,
        clock=lambda: NOW,
    )
    adapter._post = AsyncMock(return_value={"status": "waitOrder"})

    with pytest.raises(ValueError, match="server-assigned ID"):
        await adapter.set_protective_stop(
            "BTCUSDT",
            64_000.0,
            OrderSide.BUY,
            PARENT_ORDER_ID,
        )


@pytest.mark.parametrize("create_status", ["waitOrder", "active"])
@pytest.mark.asyncio
async def test_live_protective_stop_requires_live_create_and_get_reconciliation(create_status):
    adapter = EvedexAdapter(
        exchange_base_url="https://example.invalid",
        signer=RecordingSigner(),
        chain_id=1,
        dry_run=False,
        clock=lambda: NOW,
    )
    adapter._post = AsyncMock(return_value={"id": "server-stop-42", "status": create_status})
    adapter._get = AsyncMock(
        return_value={
            "list": [
                {
                    "id": "server-stop-42",
                    "instrument": "BTCUSDT",
                    "type": "stop-loss",
                    "side": "BUY",
                    "quantity": "0",
                    "price": "64000",
                    "status": "active",
                    "order": PARENT_ORDER_ID,
                }
            ]
        }
    )

    ack = await adapter.set_protective_stop(
        "BTCUSDT",
        64_000.0,
        OrderSide.BUY,
        PARENT_ORDER_ID,
    )

    assert ack.exchange_order_id == "server-stop-42"
    adapter._get.assert_awaited_once_with("/api/tpsl")


@pytest.mark.parametrize("status", ["NEW", "process", "done", None])
@pytest.mark.asyncio
async def test_protective_stop_rejects_undocumented_create_status(status):
    adapter = EvedexAdapter(
        exchange_base_url="https://example.invalid",
        signer=RecordingSigner(),
        chain_id=1,
        dry_run=True,
        clock=lambda: NOW,
    )
    adapter._post = AsyncMock(return_value={"id": "server-stop-42", "status": status})

    with pytest.raises(ValueError, match="waitOrder nor active"):
        await adapter.set_protective_stop(
            "BTCUSDT",
            64_000.0,
            OrderSide.BUY,
            PARENT_ORDER_ID,
        )


@pytest.mark.parametrize("record_status", ["process", "triggered", "done", "cancelled"])
@pytest.mark.asyncio
async def test_live_protective_stop_requires_a_still_live_record(record_status):
    adapter = EvedexAdapter(
        exchange_base_url="https://example.invalid",
        signer=RecordingSigner(),
        chain_id=1,
        dry_run=False,
        clock=lambda: NOW,
    )
    adapter._post = AsyncMock(return_value={"id": "server-stop-42", "status": "waitOrder"})
    adapter._get = AsyncMock(
        return_value={
            "list": [
                {
                    "id": "server-stop-42",
                    "instrument": "BTCUSDT",
                    "type": "stop-loss",
                    "side": "BUY",
                    "quantity": "0",
                    "price": "64000",
                    "status": record_status,
                    "order": PARENT_ORDER_ID,
                }
            ]
        }
    )

    with pytest.raises(ValueError, match="protective lifecycle"):
        await adapter.set_protective_stop(
            "BTCUSDT",
            64_000.0,
            OrderSide.BUY,
            PARENT_ORDER_ID,
        )


@pytest.mark.asyncio
async def test_live_protective_stop_rejects_mismatched_echoed_parent():
    adapter = EvedexAdapter(
        exchange_base_url="https://example.invalid",
        signer=RecordingSigner(),
        chain_id=1,
        dry_run=False,
        clock=lambda: NOW,
    )
    adapter._post = AsyncMock(return_value={"id": "server-stop-42", "status": "waitOrder"})
    adapter._get = AsyncMock(
        return_value={
            "list": [
                {
                    "id": "server-stop-42",
                    "instrument": "BTCUSDT",
                    "type": "stop-loss",
                    "side": "BUY",
                    "quantity": "0",
                    "price": "64000",
                    "status": "active",
                    "order": "00384:00000000000000000000000000",
                }
            ]
        }
    )

    with pytest.raises(ValueError, match="wrong parent order"):
        await adapter.set_protective_stop(
            "BTCUSDT",
            64_000.0,
            OrderSide.BUY,
            PARENT_ORDER_ID,
        )


@pytest.mark.parametrize(
    ("record_update", "error"),
    [
        ({"quantity": "0.01"}, "not for the full position"),
        ({"price": "63999"}, "wrong price"),
    ],
)
@pytest.mark.asyncio
async def test_live_protective_stop_requires_reconciled_full_quantity_and_price(
    record_update,
    error,
):
    adapter = EvedexAdapter(
        exchange_base_url="https://example.invalid",
        signer=RecordingSigner(),
        chain_id=1,
        dry_run=False,
        clock=lambda: NOW,
    )
    adapter._post = AsyncMock(return_value={"id": "server-stop-42", "status": "waitOrder"})
    record = {
        "id": "server-stop-42",
        "instrument": "BTCUSDT",
        "type": "stop-loss",
        "side": "BUY",
        "quantity": "0",
        "price": "64000",
        "status": "active",
        "order": PARENT_ORDER_ID,
        **record_update,
    }
    adapter._get = AsyncMock(return_value={"list": [record]})

    with pytest.raises(ValueError, match=error):
        await adapter.set_protective_stop(
            "BTCUSDT",
            64_000.0,
            OrderSide.BUY,
            PARENT_ORDER_ID,
        )


@pytest.mark.asyncio
async def test_live_protective_stop_requires_returned_id_in_get_snapshot():
    adapter = EvedexAdapter(
        exchange_base_url="https://example.invalid",
        signer=RecordingSigner(),
        chain_id=1,
        dry_run=False,
        clock=lambda: NOW,
    )
    adapter._post = AsyncMock(return_value={"id": "server-stop-42", "status": "waitOrder"})
    adapter._get = AsyncMock(return_value={"list": []})

    with pytest.raises(ValueError, match="not uniquely reconciled"):
        await adapter.set_protective_stop(
            "BTCUSDT",
            64_000.0,
            OrderSide.BUY,
            PARENT_ORDER_ID,
        )


@pytest.mark.asyncio
async def test_find_protective_stop_requires_one_exact_live_parent_linked_record():
    adapter = EvedexAdapter(
        exchange_base_url="https://example.invalid",
        signer=RecordingSigner(),
        chain_id=1,
        dry_run=False,
        clock=lambda: NOW,
    )
    record = {
        "id": "server-stop-42",
        "instrument": "BTCUSDT",
        "type": "stop-loss",
        "side": "BUY",
        "quantity": "0",
        "price": "64000",
        "status": "active",
        "order": PARENT_ORDER_ID,
    }
    adapter._get = AsyncMock(return_value={"list": [record]})

    ack = await adapter.find_protective_stop("BTCUSDT", 64_000.0, OrderSide.BUY, PARENT_ORDER_ID)
    assert ack is not None
    assert ack.exchange_order_id == "server-stop-42"

    adapter._get = AsyncMock(return_value={"list": [record, {**record, "id": "duplicate"}]})
    with pytest.raises(ValueError, match="duplicate live protective stops"):
        await adapter.find_protective_stop("BTCUSDT", 64_000.0, OrderSide.BUY, PARENT_ORDER_ID)


@pytest.mark.asyncio
async def test_find_protective_stop_rejects_ambiguous_unlinked_live_geometry():
    adapter = EvedexAdapter(
        exchange_base_url="https://example.invalid",
        signer=RecordingSigner(),
        chain_id=1,
        dry_run=False,
        clock=lambda: NOW,
    )
    adapter._get = AsyncMock(
        return_value={
            "list": [
                {
                    "id": "unlinked-stop",
                    "instrument": "BTCUSDT",
                    "type": "stop-loss",
                    "side": "BUY",
                    "quantity": "0",
                    "price": "64000",
                    "status": "active",
                }
            ]
        }
    )

    with pytest.raises(ValueError, match="lacks its parent-order link"):
        await adapter.find_protective_stop("BTCUSDT", 64_000.0, OrderSide.BUY, PARENT_ORDER_ID)


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
                    "side": "BUY",
                    "quantity": "0",
                    "status": "active",
                },
                {
                    "id": "stop-process",
                    "instrument": "BTCUSDT",
                    "type": "stop-loss",
                    "side": "BUY",
                    "quantity": "0",
                    "status": "process",
                },
                {
                    "id": "stop-wrong-side",
                    "instrument": "BTCUSDT",
                    "type": "stop-loss",
                    "side": "SELL",
                    "quantity": "0",
                    "status": "active",
                },
                {
                    "id": "stop-partial",
                    "instrument": "BTCUSDT",
                    "type": "stop-loss",
                    "side": "BUY",
                    "quantity": "0.1",
                    "status": "active",
                },
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


@pytest.mark.parametrize("margin_call", [True, 1, "true", "1", " TRUE "])
@pytest.mark.asyncio
async def test_account_snapshot_rejects_normalized_margin_call_flags(margin_call):
    adapter = EvedexAdapter(
        exchange_base_url="https://example.invalid",
        signer=RecordingSigner(),
        chain_id=1,
        jwt="jwt",
        dry_run=False,
        clock=lambda: NOW,
    )
    responses = {
        "/api/user/me": {"exchangeId": "exchange-42", "marginCall": margin_call},
        "/api/market/available-balance": {
            "funding": {"balance": "10000"},
            "availableBalance": "10000",
            "negativeUnPnL": 0,
            "position": [],
            "openOrder": [],
        },
        "/api/position": [],
        "/api/order/opened": [],
        "/api/tpsl": {"list": []},
    }
    adapter._get = AsyncMock(side_effect=lambda path: responses[path])

    with pytest.raises(ValueError, match="account is in margin call"):
        await adapter.fetch_account_snapshot(account_id="primary", peak_equity_usd=10_000)


@pytest.mark.parametrize("value", [False, 0, "false", "0", " FALSE "])
def test_evedex_false_flags_are_not_coerced_to_true(value):
    assert EvedexAdapter._required_bool(value, "flag") is False


@pytest.mark.parametrize("value", [None, "", 2, -1, "garbage", {}, []])
def test_evedex_malformed_required_flags_fail_closed(value):
    with pytest.raises(ValueError, match="not a valid boolean"):
        EvedexAdapter._required_bool(value, "flag")


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


@pytest.mark.asyncio
async def test_account_snapshot_rejects_non_numeric_position_quantity():
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
                "quantity": "not-a-number",
                "avgPrice": "65000",
            }
        ],
        "/api/order/opened": [],
        "/api/tpsl": {"list": []},
    }
    adapter._get = AsyncMock(side_effect=lambda path: responses[path])

    with pytest.raises(ValueError, match="quantity is not numeric"):
        await adapter.fetch_account_snapshot(account_id="primary", peak_equity_usd=10_000)


@pytest.mark.asyncio
async def test_account_snapshot_maps_venue_instrument_back_to_logical_symbol():
    adapter = EvedexAdapter(
        exchange_base_url="https://example.invalid",
        signer=RecordingSigner(),
        chain_id=1,
        jwt="jwt",
        dry_run=False,
        symbol_map={"BTCUSDT": "BTCUSD"},
        clock=lambda: NOW,
    )
    responses = {
        "/api/user/me": {"exchangeId": "exchange-42", "marginCall": False},
        "/api/market/available-balance": {
            "funding": {"balance": "10000"},
            "availableBalance": "9000",
            "negativeUnPnL": 0,
            "position": [{"instrument": "BTCUSD", "side": "BUY", "volume": "0.2"}],
            "openOrder": [],
        },
        "/api/position": [
            {
                "instrument": "BTCUSD",
                "side": "BUY",
                "quantity": "0.2",
                "avgPrice": "65000",
            }
        ],
        "/api/order/opened": [],
        "/api/tpsl": {"list": []},
    }
    adapter._get = AsyncMock(side_effect=lambda path: responses[path])

    snapshot = await adapter.fetch_account_snapshot(account_id="primary", peak_equity_usd=10_000)

    assert snapshot.positions[0].symbol == "BTCUSDT"


@pytest.mark.asyncio
async def test_account_snapshot_rejects_unmapped_venue_position():
    adapter = EvedexAdapter(
        exchange_base_url="https://example.invalid",
        signer=RecordingSigner(),
        chain_id=1,
        jwt="jwt",
        dry_run=False,
        symbol_map={"BTCUSDT": "BTCUSD"},
        clock=lambda: NOW,
    )
    responses = {
        "/api/user/me": {"exchangeId": "exchange-42", "marginCall": False},
        "/api/market/available-balance": {
            "funding": {"balance": "10000"},
            "availableBalance": "9000",
            "negativeUnPnL": 0,
            "position": [{"instrument": "DOGEUSD", "side": "BUY", "volume": "1"}],
            "openOrder": [],
        },
        "/api/position": [
            {
                "instrument": "DOGEUSD",
                "side": "BUY",
                "quantity": "1",
                "avgPrice": "0.2",
            }
        ],
        "/api/order/opened": [],
        "/api/tpsl": {"list": []},
    }
    adapter._get = AsyncMock(side_effect=lambda path: responses[path])

    with pytest.raises(ValueError, match="not present in the configured symbol map"):
        await adapter.fetch_account_snapshot(account_id="primary", peak_equity_usd=10_000)
