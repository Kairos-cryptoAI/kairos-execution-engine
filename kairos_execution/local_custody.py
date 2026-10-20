"""One-shot local encrypted-keystore custody backend.

The main process handles only protected-file paths and typed data. A fresh,
isolated Python child decrypts and signs one request, then exits. This module
does not provide an exchange client, generic digest signing, or key import.
"""

from __future__ import annotations

import json
import os
import re

# Fixed argv launches only the pinned isolated signing worker.
import subprocess  # nosec B404
import sys
import threading
import time
from pathlib import Path
from typing import Any

from .crypto import EIP712_SCHEMAS, build_domain

MAX_REQUEST_BYTES = 32 * 1024
MAX_RESPONSE_BYTES = 4096
MAX_WORKER_TIMEOUT_S = 10.0
_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_OPERATIONS = frozenset(
    {
        "New limit order",
        "New market order",
        "New stop-limit order",
        "Position close order",
        "New take-profit/stop-loss",
    }
)


class LocalCustodyError(PermissionError):
    """Sanitized local custody validation, process, or signature failure."""


def _regular_protected_file(path: Path) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise LocalCustodyError("custody file path must be absolute")
    try:
        resolved = path.resolve(strict=True)
        info = path.lstat()
        for component in (path, *path.parents):
            component_info = component.lstat()
            if component.is_symlink() or getattr(component_info, "st_file_attributes", 0) & 0x400:
                raise LocalCustodyError("custody path contains a link or reparse point")
    except OSError:
        raise LocalCustodyError("custody file is unavailable") from None
    if path.is_symlink() or not resolved.is_file():
        raise LocalCustodyError("custody path must name a regular non-link file")
    if getattr(info, "st_file_attributes", 0) & getattr(
        __import__("stat"), "FILE_ATTRIBUTE_REPARSE_POINT", 0x400
    ):
        raise LocalCustodyError("custody path must not be a reparse point")
    if os.name != "nt" and info.st_mode & 0o077:
        raise LocalCustodyError("custody file permissions must be private")
    if os.name == "nt":
        _assert_private_windows_acl(resolved)
    return resolved


def _assert_private_windows_acl(path: Path) -> None:
    """Require the current user as owner and only user/SYSTEM DACL entries."""
    import ctypes
    from ctypes import wintypes

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    ptr = ctypes.c_void_p
    advapi.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ptr),
        ctypes.POINTER(ptr),
        ctypes.POINTER(ptr),
        ctypes.POINTER(ptr),
        ctypes.POINTER(ptr),
    ]
    advapi.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi.GetSecurityDescriptorDacl.argtypes = [
        ptr,
        ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(ptr),
        ctypes.POINTER(wintypes.BOOL),
    ]
    advapi.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    advapi.EqualSid.argtypes = [ptr, ptr]
    advapi.EqualSid.restype = wintypes.BOOL
    advapi.CreateWellKnownSid.argtypes = [wintypes.DWORD, ptr, ptr, ctypes.POINTER(wintypes.DWORD)]
    advapi.CreateWellKnownSid.restype = wintypes.BOOL
    advapi.GetAce.argtypes = [ptr, wintypes.DWORD, ctypes.POINTER(ptr)]
    advapi.GetAce.restype = wintypes.BOOL
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.OpenProcessToken.restype = wintypes.BOOL
    advapi.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ptr,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi.GetTokenInformation.restype = wintypes.BOOL
    kernel.GetCurrentProcess.argtypes = []
    kernel.GetCurrentProcess.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ptr]
    kernel.LocalFree.restype = ptr
    SE_FILE_OBJECT = 1
    OWNER_SECURITY_INFORMATION = 1
    DACL_SECURITY_INFORMATION = 4
    TOKEN_QUERY = 0x0008
    TOKEN_USER = 1
    ACCESS_ALLOWED_ACE_TYPE = 0
    INHERITED_ACE = 0x10
    WinLocalSystemSid = 22

    owner = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    result = advapi.GetNamedSecurityInfoW(
        str(path),
        SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        ctypes.byref(owner),
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(descriptor),
    )
    if result != 0:
        raise LocalCustodyError("custody file ACL could not be verified")
    token = wintypes.HANDLE()
    buffer = ctypes.create_string_buffer(1024)
    needed = wintypes.DWORD()
    local_system = ctypes.create_string_buffer(68)
    sid_size = wintypes.DWORD(len(local_system))
    try:
        if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)):
            raise LocalCustodyError("custody file owner could not be verified")
        if not advapi.GetTokenInformation(token, TOKEN_USER, buffer, len(buffer), ctypes.byref(needed)):
            raise LocalCustodyError("custody file owner could not be verified")
        user_sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
        if not advapi.EqualSid(owner, user_sid):
            raise LocalCustodyError("custody file must be owned by the current user")
        if not advapi.CreateWellKnownSid(WinLocalSystemSid, None, local_system, ctypes.byref(sid_size)):
            raise LocalCustodyError("custody ACL policy could not be verified")
        present = wintypes.BOOL()
        defaulted = wintypes.BOOL()
        if (
            not advapi.GetSecurityDescriptorDacl(
                descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)
            )
            or not present.value
            or not dacl.value
        ):
            raise LocalCustodyError("custody file must have a private DACL")
        acl_header = ctypes.string_at(dacl.value, 8)
        ace_count = int.from_bytes(acl_header[4:6], "little")
        if ace_count == 0 or ace_count > 32:
            raise LocalCustodyError("custody file DACL is empty or malformed")
        for index in range(ace_count):
            ace = ctypes.c_void_p()
            if not advapi.GetAce(dacl, index, ctypes.byref(ace)):
                raise LocalCustodyError("custody file DACL could not be verified")
            ace_address = ace.value
            if ace_address is None:
                raise LocalCustodyError("custody file DACL could not be verified")
            header = ctypes.string_at(ace_address, 4)
            if header[0] != ACCESS_ALLOWED_ACE_TYPE or header[1] & INHERITED_ACE:
                raise LocalCustodyError("custody file DACL contains an unapproved ACE")
            sid = ctypes.c_void_p(ace_address + 8)
            if not advapi.EqualSid(sid, user_sid) and not advapi.EqualSid(
                sid, ctypes.addressof(local_system)
            ):
                raise LocalCustodyError("custody file DACL grants access beyond user/SYSTEM")
        kernel.LocalFree(descriptor)
        descriptor = ctypes.c_void_p()
    finally:
        if token:
            kernel.CloseHandle(token)
        if descriptor:
            kernel.LocalFree(descriptor)


def _validate_contract(
    *,
    custody_reference: str,
    expected_custody_reference: str,
    wallet_address: str,
    chain_id: int,
    approved_instruments: tuple[str, ...],
    domain: dict[str, Any],
    types: dict[str, list],
    message: dict[str, Any],
) -> str:
    if not isinstance(expected_custody_reference, str) or not expected_custody_reference:
        raise LocalCustodyError("custody reference is invalid")
    if custody_reference != expected_custody_reference:
        raise LocalCustodyError("request is outside this custody reference")
    if re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", expected_custody_reference) is None:
        raise LocalCustodyError("custody reference is invalid")
    if _ADDRESS.fullmatch(wallet_address) is None or type(chain_id) is not int or not 0 < chain_id < 2**256:
        raise LocalCustodyError("custody wallet or chain is invalid")
    if (
        not isinstance(approved_instruments, tuple)
        or len(approved_instruments) != 5
        or len(set(approved_instruments)) != 5
        or not all(isinstance(item, str) and item for item in approved_instruments)
    ):
        raise LocalCustodyError("custody instrument universe is invalid")
    if not isinstance(types, dict) or len(types) != 1:
        raise LocalCustodyError("typed schema is not allowlisted")
    operation = next(iter(types), None)
    if operation not in _OPERATIONS or types != EIP712_SCHEMAS[operation]:
        raise LocalCustodyError("typed schema is not allowlisted")
    if domain != build_domain(chain_id):
        raise LocalCustodyError("typed domain differs from custody binding")
    fields = EIP712_SCHEMAS[operation][operation]
    if type(message) is not dict or set(message) != {field["name"] for field in fields}:
        raise LocalCustodyError("typed message does not match its fixed schema")
    for field in fields:
        value = message[field["name"]]
        if field["type"].startswith("uint"):
            bits = int(field["type"][4:])
            if type(value) is not int or not 0 <= value < 2**bits:
                raise LocalCustodyError("typed integer violates the fixed schema")
        elif type(value) is not str or not 0 < len(value) <= 160 or any(ord(c) < 32 for c in value):
            raise LocalCustodyError("typed string violates the fixed schema")
    if message.get("instrument") not in approved_instruments:
        raise LocalCustodyError("instrument is outside the custody universe")
    if "chainId" in message and message["chainId"] != chain_id:
        raise LocalCustodyError("typed chain differs from custody binding")
    if "side" in message and message["side"] not in {"BUY", "SELL"}:
        raise LocalCustodyError("typed side is invalid")
    if "leverage" in message and message["leverage"] != 1:
        raise LocalCustodyError("typed leverage is not allowlisted")
    if "timeInForce" in message and message["timeInForce"] != "IOC":
        raise LocalCustodyError("typed time-in-force is not allowlisted")
    if "id" in message and re.fullmatch(r"[0-9]{5}:[A-Fa-f0-9]{26}", message["id"]) is None:
        raise LocalCustodyError("typed order ID is invalid")
    if "order" in message and re.fullmatch(r"[0-9]{5}:[A-Fa-f0-9]{26}", message["order"]) is None:
        raise LocalCustodyError("typed parent order ID is invalid")
    if "type" in message and message["type"] not in {"stop-loss", "take-profit"}:
        raise LocalCustodyError("typed protection is not allowlisted")
    for name in ("cashQuantity", "limitPrice", "stopPrice", "price"):
        if name in message and message[name] <= 0:
            raise LocalCustodyError("typed price/cash quantity must be positive")
    if "quantity" in message and message["quantity"] == 0 and operation != "New take-profit/stop-loss":
        raise LocalCustodyError("typed quantity must be positive")
    return operation


class LocalEncryptedKeystoreBackend:
    """Sign one reviewed EIP-712 request in an isolated, short-lived child."""

    def __init__(
        self,
        *,
        python_executable: Path,
        keystore_file: Path,
        unlock_file: Path,
        custody_reference: str,
        wallet_address: str,
        chain_id: int,
        approved_instruments: tuple[str, ...],
        timeout_s: float = 8.0,
    ) -> None:
        if type(timeout_s) not in {int, float} or not 0 < timeout_s <= MAX_WORKER_TIMEOUT_S:
            raise ValueError("local custody subprocess timeout must be within (0, 10] seconds")
        if not isinstance(python_executable, Path) or not python_executable.is_absolute():
            raise ValueError("Python executable must be an absolute path")
        # Preserve the interpreter launcher path exactly: resolving a venv's
        # python symlink loses pyvenv.cfg and can bypass its installed packages.
        configured = Path(os.path.abspath(os.fspath(python_executable)))
        current_launcher = Path(os.path.abspath(sys.executable))
        try:
            target = configured.resolve(strict=True)
            current = Path(sys.executable).resolve(strict=True)
        except OSError as exc:
            raise ValueError("Python executable could not be resolved") from exc
        if configured != current_launcher or target != current or not target.is_file():
            raise ValueError("worker must use the exact current Python interpreter launcher")
        self.python_executable = configured
        self.keystore_file = _regular_protected_file(keystore_file)
        self.unlock_file = _regular_protected_file(unlock_file)
        if self.keystore_file == self.unlock_file:
            raise ValueError("keystore and unlock files must be separate")
        self.custody_reference = custody_reference
        self.wallet_address = wallet_address
        self.chain_id = chain_id
        self.approved_instruments = approved_instruments
        self.timeout_s = float(timeout_s)
        worker_path = Path(__file__).with_name("_local_custody_worker.py")
        if worker_path.is_symlink():
            raise ValueError("dedicated custody worker must not be a symbolic link")
        self.worker = worker_path.resolve(strict=True)
        if not self.worker.is_file():
            raise ValueError("dedicated custody worker is unavailable")

    def sign_typed_data(self, *, custody_reference: str, domain: dict, types: dict, message: dict) -> str:
        operation = _validate_contract(
            custody_reference=custody_reference,
            expected_custody_reference=self.custody_reference,
            wallet_address=self.wallet_address,
            chain_id=self.chain_id,
            approved_instruments=self.approved_instruments,
            domain=domain,
            types=types,
            message=message,
        )
        request = {
            "version": "kairos.local-keystore-sign.v1",
            "custody_reference": custody_reference,
            "wallet_address": self.wallet_address,
            "chain_id": self.chain_id,
            "approved_instruments": list(self.approved_instruments),
            "domain": domain,
            "types": types,
            "message": message,
            "operation": operation,
            "keystore_file": str(self.keystore_file),
            "unlock_file": str(self.unlock_file),
        }
        encoded = json.dumps(request, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        if len(encoded) > MAX_REQUEST_BYTES:
            raise LocalCustodyError("typed request exceeds the local custody protocol limit")
        expected_binding = json.dumps(
            {
                "custody_reference": self.custody_reference,
                "wallet_address": self.wallet_address,
                "chain_id": self.chain_id,
                "approved_instruments": list(self.approved_instruments),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        env = (
            {"SYSTEMROOT": os.environ["SYSTEMROOT"]} if os.name == "nt" and "SYSTEMROOT" in os.environ else {}
        )
        deadline = time.monotonic() + self.timeout_s
        try:
            # Executable/worker are pinned absolute paths; shell execution is disabled.
            process = subprocess.Popen(
                [str(self.python_executable), "-I", "-B", str(self.worker), expected_binding],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                cwd=str(self.worker.parent),
                env=env,
            )  # nosec B603
        except OSError:
            raise LocalCustodyError("local signing subprocess could not start") from None
        if process.stdout is None or process.stdin is None:
            process.kill()
            process.wait()
            raise LocalCustodyError("local signing subprocess streams are unavailable")
        child_stdout = process.stdout
        child_stdin = process.stdin

        output = bytearray()
        overflow = threading.Event()
        reader_failed = threading.Event()
        writer_failed = threading.Event()

        def read_bounded_output() -> None:
            try:
                while len(output) <= MAX_RESPONSE_BYTES:
                    chunk = child_stdout.read(min(1024, MAX_RESPONSE_BYTES + 1 - len(output)))
                    if not chunk:
                        return
                    output.extend(chunk)
                overflow.set()
                if process.poll() is None:
                    process.kill()
            except OSError:
                reader_failed.set()

        def write_bounded_request() -> None:
            try:
                child_stdin.write(encoded)
                child_stdin.close()
            except OSError:
                writer_failed.set()

        reader = threading.Thread(target=read_bounded_output, daemon=True)
        writer = threading.Thread(target=write_bounded_request, daemon=True)
        reader.start()
        writer.start()
        try:
            return_code = process.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            process.kill()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
            writer.join(timeout=0.25)
            reader.join(timeout=0.25)
            raise LocalCustodyError(
                "local signing subprocess timed out; signing claim remains consumed"
            ) from None
        except OSError:
            if process.poll() is None:
                process.kill()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
            writer.join(timeout=0.25)
            reader.join(timeout=0.25)
            raise LocalCustodyError(
                "local signing subprocess failed; signing claim remains consumed"
            ) from None
        writer.join(timeout=0.25)
        reader.join(timeout=0.25)
        if writer.is_alive() or reader.is_alive() or reader_failed.is_set():
            if process.poll() is None:
                process.kill()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
            raise LocalCustodyError("local signing subprocess streams did not close cleanly")
        if overflow.is_set() or writer_failed.is_set() or return_code != 0:
            raise LocalCustodyError("local signing subprocess failed; signing claim remains consumed")
        try:
            response = json.loads(bytes(output))
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise LocalCustodyError("local signing subprocess returned malformed output") from None
        if (
            type(response) is not dict
            or set(response) != {"version", "wallet_address", "signature"}
            or response.get("version") != "kairos.local-keystore-sign-result.v1"
            or not isinstance(response.get("wallet_address"), str)
            or response["wallet_address"].casefold() != self.wallet_address.casefold()
            or not isinstance(response.get("signature"), str)
            or re.fullmatch(r"0x[0-9a-fA-F]{130}", response["signature"]) is None
        ):
            raise LocalCustodyError("local signing subprocess response failed validation")
        return response["signature"]


class CoincurveTypedDataVerifier:
    """Independently recover the signer using libsecp256k1/coincurve."""

    def verify(
        self, *, wallet_address: str, domain: dict, types: dict, message: dict, signature: str
    ) -> bool:
        if (
            _ADDRESS.fullmatch(wallet_address) is None
            or re.fullmatch(r"0x[0-9a-fA-F]{130}", signature) is None
        ):
            return False
        try:
            from coincurve import PublicKey
            from eth_account.messages import encode_typed_data
            from eth_utils import keccak

            primary = next(iter(types))
            chain_id = domain.get("chainId")
            if type(chain_id) is int:
                normalized_chain_id = chain_id
            elif type(chain_id) is str:
                normalized_chain_id = int(chain_id)
            else:
                return False
            if (
                primary not in _OPERATIONS
                or types != EIP712_SCHEMAS[primary]
                or domain != build_domain(normalized_chain_id)
            ):
                return False
            fields = EIP712_SCHEMAS[primary][primary]
            if type(message) is not dict or set(message) != {field["name"] for field in fields}:
                return False
            for field in fields:
                value = message[field["name"]]
                if field["type"].startswith("uint"):
                    bits = int(field["type"][4:])
                    if type(value) is not int or not 0 <= value < 2**bits:
                        return False
                elif type(value) is not str or not 0 < len(value) <= 160:
                    return False
            full = {
                "types": {**types, "EIP712Domain": _domain_fields(domain)},
                "primaryType": primary,
                "domain": domain,
                "message": message,
            }
            signable = encode_typed_data(full_message=full)
            digest = keccak(b"\x19" + signable.version + signable.header + signable.body)
            raw = bytes.fromhex(signature[2:])
            recovery_id = raw[64] - 27 if raw[64] >= 27 else raw[64]
            if recovery_id not in (0, 1):
                return False
            public_key = PublicKey.from_signature_and_message(
                raw[:64] + bytes([recovery_id]), digest, hasher=None
            )
            recovered = "0x" + keccak(public_key.format(compressed=False)[1:])[-20:].hex()
            return recovered.casefold() == wallet_address.casefold()
        except Exception:
            return False


def _domain_fields(domain: dict[str, Any]) -> list[dict[str, str]]:
    order = (
        ("name", "string"),
        ("version", "string"),
        ("chainId", "uint256"),
        ("verifyingContract", "address"),
        ("salt", "bytes32"),
    )
    return [{"name": name, "type": kind} for name, kind in order if name in domain]
