"""Offline tests for the isolated local encrypted-keystore backend."""

import io
import json
import os
import subprocess
import threading
import time
from pathlib import Path

import pytest

from kairos_execution.crypto import EIP712_SCHEMAS, build_domain
from kairos_execution.local_custody import (
    MAX_RESPONSE_BYTES,
    CoincurveTypedDataVerifier,
    LocalCustodyError,
    LocalEncryptedKeystoreBackend,
)

pytest.importorskip("eth_account")
pytest.importorskip("coincurve")
from eth_account import Account

INSTRUMENTS = ("BTCUSD:DEV", "ETHUSD:DEV", "SOLUSD:DEV", "BNBUSD:DEV", "XRPUSD:DEV")
KEY = (1).to_bytes(32, "big")
PASSWORD = "synthetic-test-unlock"
CHAIN = 16182
REFERENCE = "local-test-keystore"
MESSAGE = {
    "id": "00384:ABCDEF0123456789ABCDEF0123",
    "instrument": "BTCUSD:DEV",
    "side": "BUY",
    "leverage": 1,
    "quantity": 100,
    "limitPrice": 1000,
    "chainId": CHAIN,
}


def _make_private(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    if os.name == "nt":
        identity = subprocess.run(
            ["whoami"], check=True, capture_output=True, text=True, timeout=5
        ).stdout.strip()
        subprocess.run(
            [
                "icacls",
                str(path),
                "/inheritance:r",
                "/grant:r",
                f"{identity}:(F)",
                "SYSTEM:(R)",
            ],
            check=True,
            capture_output=True,
            timeout=5,
        )
    else:
        path.chmod(0o600)


def _backend(tmp_path: Path, *, timeout_s: float = 8.0):
    account = Account.from_key(KEY)
    encrypted = Account.encrypt(KEY, PASSWORD, kdf="pbkdf2")
    key_path, unlock_path = tmp_path / "wallet.json", tmp_path / "unlock.txt"
    _make_private(key_path, json.dumps(encrypted).encode())
    _make_private(unlock_path, (PASSWORD + "\n").encode())
    backend = LocalEncryptedKeystoreBackend(
        python_executable=Path(os.path.abspath(os.sys.executable)),
        keystore_file=key_path,
        unlock_file=unlock_path,
        custody_reference=REFERENCE,
        wallet_address=account.address,
        chain_id=CHAIN,
        approved_instruments=INSTRUMENTS,
        timeout_s=timeout_s,
    )
    return backend, account.address


def test_local_child_signs_one_fixed_typed_message_and_verifier_recovers_address(tmp_path):
    backend, wallet = _backend(tmp_path)
    signature = backend.sign_typed_data(
        custody_reference=REFERENCE,
        domain=build_domain(CHAIN),
        types=EIP712_SCHEMAS["New limit order"],
        message=MESSAGE,
    )
    verifier = CoincurveTypedDataVerifier()
    assert (
        verifier.verify(
            wallet_address=wallet,
            domain=build_domain(CHAIN),
            types=EIP712_SCHEMAS["New limit order"],
            message=MESSAGE,
            signature=signature,
        )
        is True
    )
    assert (
        verifier.verify(
            wallet_address=wallet,
            domain=build_domain(CHAIN),
            types=EIP712_SCHEMAS["New limit order"],
            message={**MESSAGE, "quantity": MESSAGE["quantity"] + 1},
            signature=signature,
        )
        is False
    )


@pytest.mark.skipif(not os.sys.platform.startswith("linux"), reason="Linux venv launcher regression")
def test_linux_venv_launcher_path_is_preserved_for_the_signing_child(tmp_path):
    launcher = Path(os.sys.executable)
    if not launcher.is_symlink():
        pytest.skip("current Linux interpreter is not launched through a venv symlink")
    backend, wallet = _backend(tmp_path)
    assert backend.python_executable == Path(os.path.abspath(os.sys.executable))
    signature = backend.sign_typed_data(
        custody_reference=REFERENCE,
        domain=build_domain(CHAIN),
        types=EIP712_SCHEMAS["New limit order"],
        message=MESSAGE,
    )
    assert CoincurveTypedDataVerifier().verify(
        wallet_address=wallet,
        domain=build_domain(CHAIN),
        types=EIP712_SCHEMAS["New limit order"],
        message=MESSAGE,
        signature=signature,
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"custody_reference": "other"},
        {"domain": build_domain(1)},
        {"types": {"Withdraw": []}},
        {"message": {**MESSAGE, "chainId": 1}},
        {"message": {**MESSAGE, "instrument": "OTHER"}},
    ],
)
def test_invalid_contract_fails_before_child_dispatch(tmp_path, monkeypatch, changes):
    backend, _ = _backend(tmp_path)

    def forbidden(*args, **kwargs):
        raise AssertionError("invalid contract reached child process")

    monkeypatch.setattr("kairos_execution.local_custody.subprocess.Popen", forbidden)
    fields = {
        "custody_reference": REFERENCE,
        "domain": build_domain(CHAIN),
        "types": EIP712_SCHEMAS["New limit order"],
        "message": MESSAGE,
    }
    fields.update(changes)
    with pytest.raises(LocalCustodyError):
        backend.sign_typed_data(**fields)


def test_bad_unlock_material_is_sanitized_and_does_not_return_signature(tmp_path):
    backend, _ = _backend(tmp_path)
    backend.unlock_file.write_text("wrong password\n", encoding="utf-8")
    if os.name != "nt":
        backend.unlock_file.chmod(0o600)
    with pytest.raises(LocalCustodyError):
        backend.sign_typed_data(
            custody_reference=REFERENCE,
            domain=build_domain(CHAIN),
            types=EIP712_SCHEMAS["New limit order"],
            message=MESSAGE,
        )


def test_subprocess_stdout_is_bounded_while_reading(tmp_path, monkeypatch):
    backend, _ = _backend(tmp_path)

    class OversizedChild:
        def __init__(self, *args, **kwargs):
            self.stdin = io.BytesIO()
            self.stdout = io.BytesIO(b"x" * (MAX_RESPONSE_BYTES + 100))
            self.killed = False

        def poll(self):
            return None

        def kill(self):
            self.killed = True

        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr("kairos_execution.local_custody.subprocess.Popen", OversizedChild)
    with pytest.raises(LocalCustodyError, match="subprocess failed"):
        backend.sign_typed_data(
            custody_reference=REFERENCE,
            domain=build_domain(CHAIN),
            types=EIP712_SCHEMAS["New limit order"],
            message=MESSAGE,
        )


def test_blocked_stdin_writer_cannot_escape_subprocess_deadline(tmp_path, monkeypatch):
    backend, _ = _backend(tmp_path, timeout_s=0.1)
    killed = threading.Event()

    class BlockingStdin:
        def write(self, _data):
            killed.wait()
            raise BrokenPipeError

        def close(self):
            return None

    class ChildBlockedBeforeReading:
        def __init__(self, *args, **kwargs):
            self.stdin = BlockingStdin()
            self.stdout = io.BytesIO(b"")

        def poll(self):
            return -9 if killed.is_set() else None

        def kill(self):
            killed.set()

        def wait(self, timeout=None):
            if killed.wait(timeout):
                return -9
            raise subprocess.TimeoutExpired("synthetic-child", timeout)

    monkeypatch.setattr("kairos_execution.local_custody.subprocess.Popen", ChildBlockedBeforeReading)
    started = time.monotonic()
    with pytest.raises(LocalCustodyError, match="timed out"):
        backend.sign_typed_data(
            custody_reference=REFERENCE,
            domain=build_domain(CHAIN),
            types=EIP712_SCHEMAS["New limit order"],
            message=MESSAGE,
        )
    assert time.monotonic() - started < 1.0
    assert killed.is_set()


def test_backend_requires_private_file_and_same_interpreter(tmp_path):
    backend, _ = _backend(tmp_path)
    assert backend.python_executable == Path(os.path.abspath(os.sys.executable))
    if os.name != "nt":
        backend.keystore_file.chmod(0o644)
        with pytest.raises(LocalCustodyError, match="permissions"):
            LocalEncryptedKeystoreBackend(
                python_executable=Path(os.path.abspath(os.sys.executable)),
                keystore_file=backend.keystore_file,
                unlock_file=backend.unlock_file,
                custody_reference=REFERENCE,
                wallet_address=Account.from_key(KEY).address,
                chain_id=CHAIN,
                approved_instruments=INSTRUMENTS,
            )
        backend.keystore_file.chmod(0o600)
