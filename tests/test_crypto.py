from decimal import Decimal
from kairos_execution.crypto import to_eth_number, EIP712_SCHEMAS, build_domain


def test_normalization_half_up_8dp():
    assert to_eth_number(1) == 100_000_000
    assert to_eth_number("0.00000001") == 1
    assert to_eth_number(65000.123456789) == 6500012345679  # HALF_UP at 8dp


def test_withdrawal_rounds_down():
    assert to_eth_number("0.000000019", round_down=True) == 1
    assert to_eth_number("0.000000019") == 2  # half-up


def test_domain_has_evedex_identity():
    d = build_domain(1)
    assert d["name"] == "EVEDEX" and d["version"] == "2" and d["chainId"] == "1"
    assert "salt" in d


def test_limit_schema_field_order():
    fields = [f["name"] for f in EIP712_SCHEMAS["New limit order"]["New limit order"]]
    assert fields == ["id", "instrument", "side", "leverage", "quantity", "limitPrice", "chainId"]
