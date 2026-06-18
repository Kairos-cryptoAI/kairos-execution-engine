"""EVEDEX EIP-712 typed-data signing.

Mirrors the canonical schema from ``evedex-official/exchange-crypto`` (src/utils/crypto.ts).
All float fields are normalised to integers with ``round(value * 10**8)`` (HALF_UP),
matching ``toEthNumber`` / ``MATCHER_PRECISION = 8`` — except withdrawals which round DOWN.
"""
from __future__ import annotations

from decimal import Decimal, ROUND_DOWN, ROUND_HALF_UP
from typing import Any, Dict, Protocol

MATCHER_PRECISION = 8

# Domain and type schemas, copied field-for-field from the EVEDEX reference.
DOMAIN = {
    "name": "EVEDEX",
    "version": "2",
    "salt": "0x5792f7333c35db190e30acc144f049fd15b24f552c0010b8b3e06f9105c37c5a",
}

EIP712_SCHEMAS: Dict[str, Dict[str, list]] = {
    "Withdraw": {"Withdraw": [
        {"name": "recipient", "type": "address"},
        {"name": "amount", "type": "uint256"},
    ]},
    "New limit order": {"New limit order": [
        {"name": "id", "type": "string"},
        {"name": "instrument", "type": "string"},
        {"name": "side", "type": "string"},
        {"name": "leverage", "type": "uint8"},
        {"name": "quantity", "type": "uint96"},
        {"name": "limitPrice", "type": "uint80"},
        {"name": "chainId", "type": "uint256"},
    ]},
    "New market order": {"New market order": [
        {"name": "id", "type": "string"},
        {"name": "instrument", "type": "string"},
        {"name": "side", "type": "string"},
        {"name": "timeInForce", "type": "string"},
        {"name": "leverage", "type": "uint8"},
        {"name": "cashQuantity", "type": "uint96"},
        {"name": "chainId", "type": "uint256"},
    ]},
    "New stop-limit order": {"New stop-limit order": [
        {"name": "id", "type": "string"},
        {"name": "instrument", "type": "string"},
        {"name": "side", "type": "string"},
        {"name": "leverage", "type": "uint8"},
        {"name": "quantity", "type": "uint96"},
        {"name": "limitPrice", "type": "uint80"},
        {"name": "stopPrice", "type": "uint80"},
        {"name": "chainId", "type": "uint256"},
    ]},
    "Position close order": {"Position close order": [
        {"name": "id", "type": "string"},
        {"name": "instrument", "type": "string"},
        {"name": "leverage", "type": "uint8"},
        {"name": "quantity", "type": "uint96"},
        {"name": "chainId", "type": "uint256"},
    ]},
    "New take-profit/stop-loss": {"New take-profit/stop-loss": [
        {"name": "instrument", "type": "string"},
        {"name": "type", "type": "string"},
        {"name": "side", "type": "string"},
        {"name": "quantity", "type": "uint96"},
        {"name": "price", "type": "uint80"},
    ]},
}


def to_eth_number(value: float | str | Decimal, *, round_down: bool = False) -> int:
    """``round(value * 10**8)`` — HALF_UP everywhere except withdrawals (DOWN)."""
    scaled = Decimal(str(value)) * (Decimal(10) ** MATCHER_PRECISION)
    rounding = ROUND_DOWN if round_down else ROUND_HALF_UP
    return int(scaled.quantize(Decimal(1), rounding=rounding))


def build_domain(chain_id: int | str) -> Dict[str, Any]:
    return {**DOMAIN, "chainId": str(chain_id)}


class Signer(Protocol):
    """Anything that can produce an EIP-712 signature for a wallet."""

    address: str

    def sign_typed_data(self, domain: Dict[str, Any], types: Dict[str, list], message: Dict[str, Any]) -> str:
        ...


class EthAccountSigner:
    """Production signer backed by ``eth_account`` (optional dependency)."""

    def __init__(self, private_key: str) -> None:
        from eth_account import Account  # lazy import; only needed for live trading

        self._account = Account.from_key(private_key)
        self.address = self._account.address

    def sign_typed_data(self, domain, types, message) -> str:
        from eth_account.messages import encode_typed_data

        primary = next(iter(types))
        full = {
            "types": {**types, "EIP712Domain": _domain_types(domain)},
            "primaryType": primary,
            "domain": domain,
            "message": message,
        }
        signable = encode_typed_data(full_message=full)
        return self._account.sign_message(signable).signature.hex()


def _domain_types(domain: Dict[str, Any]) -> list:
    fields = [("name", "string"), ("version", "string"), ("chainId", "uint256"),
              ("verifyingContract", "address"), ("salt", "bytes32")]
    return [{"name": n, "type": t} for n, t in fields if n in domain]
