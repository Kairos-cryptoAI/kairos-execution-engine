"""Offline exact EIP-712 integer to REST wire normalization tests."""

import pytest

from kairos_execution.production_dispatch import ProductionDispatchError, production_wire_body

SIGNATURE = "0x" + "11" * 65


@pytest.mark.parametrize(
    ("operation", "message", "expected"),
    [
        (
            "New limit order",
            {
                "id": "00384:ABCDEF0123456789ABCDEF0123",
                "instrument": "BTCUSD",
                "side": "BUY",
                "leverage": 1,
                "quantity": 123_456_789,
                "limitPrice": 12_345_000_000,
                "chainId": 161803,
            },
            {"quantity": "1.23456789", "limitPrice": "123.45", "timeInForce": "IOC"},
        ),
        (
            "New market order",
            {
                "id": "00384:ABCDEF0123456789ABCDEF0124",
                "instrument": "BTCUSD",
                "side": "BUY",
                "timeInForce": "IOC",
                "leverage": 1,
                "cashQuantity": 250_000_000,
                "chainId": 161803,
            },
            {"cashQuantity": "2.5"},
        ),
        (
            "New stop-limit order",
            {
                "id": "00384:ABCDEF0123456789ABCDEF0125",
                "instrument": "BTCUSD",
                "side": "SELL",
                "leverage": 1,
                "quantity": 100_000_000,
                "limitPrice": 9_999_000_000,
                "stopPrice": 10_001_250_000,
                "chainId": 161803,
            },
            {"quantity": "1", "limitPrice": "99.99", "stopPrice": "100.0125"},
        ),
        (
            "Position close order",
            {
                "id": "00384:ABCDEF0123456789ABCDEF0126",
                "instrument": "BTCUSD",
                "leverage": 1,
                "quantity": 0,
                "chainId": 161803,
            },
            {"quantity": "0"},
        ),
        (
            "New take-profit/stop-loss",
            {
                "instrument": "BTCUSD",
                "type": "stop-loss",
                "side": "SELL",
                "quantity": 0,
                "price": 9_875_000_000,
                "order": "00384:ABCDEF0123456789ABCDEF0123",
            },
            {"quantity": "0", "price": "98.75"},
        ),
    ],
)
def test_supported_wire_operations_use_canonical_sdk_decimal_strings(operation, message, expected):
    body = production_wire_body(operation, message, SIGNATURE)

    assert {key: body[key] for key in expected} == expected
    assert body["signature"] == SIGNATURE
    assert body.get("leverage", 1) == 1
    if "chainId" in message:
        assert body["chainId"] == 161803
    assert not any(type(value) is float for value in body.values())
    if operation == "New limit order":
        assert body["timeInForce"] == "IOC"
        assert "postOnly" not in body


@pytest.mark.parametrize("value", [True, 1.0, "100000000", -1])
def test_wire_geometry_rejects_non_exact_unsigned_eip_integer(value):
    message = {
        "id": "00384:ABCDEF0123456789ABCDEF0123",
        "instrument": "BTCUSD",
        "side": "BUY",
        "leverage": 1,
        "quantity": value,
        "limitPrice": 10_000_000_000,
        "chainId": 161803,
    }
    with pytest.raises(ProductionDispatchError, match="exact unsigned EIP integers"):
        production_wire_body("New limit order", message, SIGNATURE)


def test_wire_body_does_not_invent_usd_cash_value_or_optional_post_only():
    message = {
        "id": "00384:ABCDEF0123456789ABCDEF0123",
        "instrument": "BTCUSD",
        "side": "BUY",
        "leverage": 1,
        "quantity": 100_000_000,
        "limitPrice": 10_000_000_000,
        "chainId": 161803,
    }
    body = production_wire_body("New limit order", message, SIGNATURE)

    assert body["quantity"] == "1"
    assert body["limitPrice"] == "100"
    assert "cashQuantity" not in body
    assert "postOnly" not in body
