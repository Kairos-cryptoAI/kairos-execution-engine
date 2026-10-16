import pytest

from kairos_execution.crypto import (
    EIP712_SCHEMAS,
    EthAccountSigner,
    _domain_types,
    build_domain,
    to_eth_number,
)


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


def test_evedex_limit_signature_matches_offline_known_vector_and_is_mutation_sensitive():
    eth_account = pytest.importorskip("eth_account")
    from eth_account.messages import encode_typed_data
    from eth_utils import keccak

    # Public test-only key; no owner credential, provider, SDK session or network.
    # Digest/signature also match the locked @evedex/exchange-crypto 1.1.0 JS
    # schema with ethers, independently of our Python domain/schema builders.
    signer = EthAccountSigner("0x" + "01" * 32)
    domain = build_domain(16182)
    types = EIP712_SCHEMAS["New limit order"]
    message = {
        "id": "00384:ABCDEF0123456789ABCDEF0123",
        "instrument": "BTCUSD:DEV",
        "side": "BUY",
        "leverage": 1,
        "quantity": 100_000_000,
        "limitPrice": 6_500_012_345_679,
        "chainId": 16182,
    }
    signature = signer.sign_typed_data(domain, types, message)

    def signable(payload):
        return encode_typed_data(
            full_message={
                "types": {**types, "EIP712Domain": _domain_types(domain)},
                "primaryType": "New limit order",
                "domain": domain,
                "message": payload,
            }
        )

    assert signer.address == "0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1"
    assert signature == (
        "ec2f4f093a36d748a8ac6b1cc7dceb73bfe17e07a7e9117bcbba3c45566538d2"
        "08c85d4cfd5874f5c3d8207edb9f86103b5303eb453f77a6266779c331d209d31c"
    )
    encoded = signable(message)
    assert keccak(b"\x19" + encoded.version + encoded.header + encoded.body).hex() == (
        "aaeede141482b3a18980ca5dec38b284e3f5aafdf39d2e3273db3e61e0ef3654"
    )
    assert eth_account.Account.recover_message(signable(message), signature=signature) == signer.address
    for mutation in (
        {"quantity": message["quantity"] + 1},
        {"instrument": "ETHUSD:DEV"},
        {"chainId": 161803},
    ):
        altered = {**message, **mutation}
        assert eth_account.Account.recover_message(signable(altered), signature=signature) != signer.address
