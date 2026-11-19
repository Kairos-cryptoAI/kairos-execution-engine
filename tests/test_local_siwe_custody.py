"""Synthetic isolated-keystore SIWE checks; no authentication or network."""

from datetime import UTC, datetime, timedelta

import pytest

from kairos_execution.local_custody import LocalCustodyError
from kairos_execution.siwe_auth import evedex_siwe_message
from tests.test_local_custody import CHAIN, REFERENCE, _backend

Account = pytest.importorskip("eth_account").Account
encode_defunct = pytest.importorskip("eth_account.messages").encode_defunct


def stamp(delta=0):
    return (
        (datetime.now(UTC) + timedelta(seconds=delta))
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def test_isolated_keystore_signs_only_fixed_evedex_siwe(tmp_path):
    backend, wallet = _backend(tmp_path)
    issued_at = stamp()
    message, signature = backend._sign_evedex_siwe_unclaimed(
        custody_reference=REFERENCE, nonce="TestNonce12345678", issued_at=issued_at
    )
    assert message == (
        f"https://evedex.com wants you to sign in with your Ethereum account:\n{wallet}\n\n"
        "Sign in to evedex.com\n\nURI: https://evedex.com\nVersion: 1\n"
        f"Chain ID: {CHAIN}\nNonce: TestNonce12345678\nIssued At: {issued_at}"
    )
    assert Account.recover_message(encode_defunct(text=message), signature=signature) == wallet


@pytest.mark.parametrize("nonce", ["short", "abc defgh", "goodnonce\nURI: https://evil.example", "x" * 129])
def test_rejects_invalid_nonce_before_child(tmp_path, nonce, monkeypatch):
    backend, _ = _backend(tmp_path)
    monkeypatch.setattr(backend, "_invoke_request", lambda *_: pytest.fail("child must not start"))
    with pytest.raises(LocalCustodyError):
        backend._sign_evedex_siwe_unclaimed(custody_reference=REFERENCE, nonce=nonce, issued_at=stamp())


@pytest.mark.parametrize("delta", [-31, 31])
def test_rejects_stale_or_future_messages(delta):
    with pytest.raises(ValueError):
        evedex_siwe_message(address="0x" + "1" * 40, chain_id=1, nonce="TestNonce123", issued_at=stamp(delta))


def test_rejects_wrong_custody_reference(tmp_path, monkeypatch):
    backend, _ = _backend(tmp_path)
    monkeypatch.setattr(backend, "_invoke_request", lambda *_: pytest.fail("child must not start"))
    with pytest.raises(LocalCustodyError):
        backend._sign_evedex_siwe_unclaimed(
            custody_reference="another", nonce="TestNonce123", issued_at=stamp()
        )


def test_rejects_non_checksum_wallet():
    wallet = Account.from_key((1).to_bytes(32, "big")).address
    assert wallet != wallet.lower()
    with pytest.raises(ValueError, match="wallet"):
        evedex_siwe_message(address=wallet.lower(), chain_id=1, nonce="TestNonce123", issued_at=stamp())


def test_recovery_exception_does_not_leak_context(tmp_path, monkeypatch):
    backend, _ = _backend(tmp_path)
    monkeypatch.setattr(backend, "_invoke_request", lambda _: "0x" + "0" * 130)

    def broken(*args, **kwargs):
        raise RuntimeError("synthetic-secret-proof")

    monkeypatch.setattr(Account, "recover_message", broken)
    with pytest.raises(LocalCustodyError) as error:
        backend._sign_evedex_siwe_unclaimed(
            custody_reference=REFERENCE, nonce="TestNonce123", issued_at=stamp()
        )
    assert error.value.__context__ is None
    assert "synthetic-secret-proof" not in str(error.value)
