"""Construct only the official EVEDEX SIWE authentication message.

This helper makes no network calls and grants no trading authority. The nonce
must come from EVEDEX and is consumed by its authentication service.
"""

import re
from datetime import UTC, datetime, timedelta


def evedex_siwe_message(*, address: str, chain_id: int, nonce: str, issued_at: str) -> str:
    try:
        from eth_utils import is_checksum_address
    except ImportError:
        raise ValueError("SIWE crypto dependencies are unavailable") from None
    if (
        not isinstance(address, str)
        or re.fullmatch(r"0x[0-9a-fA-F]{40}", address) is None
        or not is_checksum_address(address)
    ):
        raise ValueError("invalid SIWE wallet")
    if type(chain_id) is not int or not 0 < chain_id < 2**256:
        raise ValueError("invalid SIWE chain")
    if not isinstance(nonce, str) or re.fullmatch(r"[A-Za-z0-9]{8,128}", nonce) is None:
        raise ValueError("invalid SIWE nonce")
    if (
        not isinstance(issued_at, str)
        or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z", issued_at)
        is None
    ):
        raise ValueError("invalid SIWE timestamp")
    try:
        issued = datetime.strptime(issued_at, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError:
        raise ValueError("invalid SIWE timestamp") from None
    if abs(datetime.now(UTC) - issued) > timedelta(seconds=30):
        raise ValueError("expired or future SIWE timestamp")
    return (
        "https://evedex.com wants you to sign in with your Ethereum account:\n"
        f"{address}\n\nSign in to evedex.com\n\nURI: https://evedex.com\nVersion: 1\n"
        f"Chain ID: {chain_id}\nNonce: {nonce}\nIssued At: {issued_at}"
    )
