"""Private one-request child for local EIP-712 signing; invoked with -I -B."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

# -I excludes CWD and PYTHONPATH; this explicit root is derived solely from
# this pinned worker's own location, not from request data or environment.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from eth_account import Account

from kairos_execution.local_custody import _assert_private_windows_acl  # noqa: E402

MAX_LINE = 32 * 1024
MAX_SECRET_FILE = 64 * 1024
_OPS = {
    "New limit order": [
        ("id", "string"),
        ("instrument", "string"),
        ("side", "string"),
        ("leverage", "uint8"),
        ("quantity", "uint96"),
        ("limitPrice", "uint80"),
        ("chainId", "uint256"),
    ],
    "New market order": [
        ("id", "string"),
        ("instrument", "string"),
        ("side", "string"),
        ("timeInForce", "string"),
        ("leverage", "uint8"),
        ("cashQuantity", "uint96"),
        ("chainId", "uint256"),
    ],
    "New stop-limit order": [
        ("id", "string"),
        ("instrument", "string"),
        ("side", "string"),
        ("leverage", "uint8"),
        ("quantity", "uint96"),
        ("limitPrice", "uint80"),
        ("stopPrice", "uint80"),
        ("chainId", "uint256"),
    ],
    "Position close order": [
        ("id", "string"),
        ("instrument", "string"),
        ("leverage", "uint8"),
        ("quantity", "uint96"),
        ("chainId", "uint256"),
    ],
    "New take-profit/stop-loss": [
        ("instrument", "string"),
        ("type", "string"),
        ("side", "string"),
        ("quantity", "uint96"),
        ("price", "uint80"),
        ("order", "string"),
    ],
}
_PRODUCTION_OPS = {
    **_OPS,
    "New take-profit/stop-loss": [
        ("instrument", "string"),
        ("type", "string"),
        ("side", "string"),
        ("quantity", "uint96"),
        ("price", "uint80"),
    ],
}
_PRODUCTION_PROFILE = "kairos.evedex-managed-sdk.v1"
_LEGACY_PROFILE = "kairos.evedex-legacy-signing.v1"
_DOMAIN = {
    "name": "EVEDEX",
    "version": "2",
    "salt": "0x5792f7333c35db190e30acc144f049fd15b24f552c0010b8b3e06f9105c37c5a",
}


def _reject_duplicates(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _path(value: Any) -> Path:
    if type(value) is not str:
        raise ValueError("invalid path")
    path = Path(value)
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("invalid path")
    resolved = path.resolve(strict=True)
    info = path.lstat()
    for component in (path, *path.parents):
        component_info = component.lstat()
        if component.is_symlink() or getattr(component_info, "st_file_attributes", 0) & 0x400:
            raise ValueError("link or reparse point")
    if not resolved.is_file() or getattr(info, "st_file_attributes", 0) & 0x400:
        raise ValueError("invalid file")
    if sys.platform == "win32":
        _assert_private_windows_acl(resolved)
    elif info.st_mode & 0o077:
        raise ValueError("non-private file")
    return resolved


def _read_private(path: Path, limit: int) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("oversized file")
    return data


def _validate_keystore(document: dict) -> None:
    if type(document) is not dict or document.get("version") != 3:
        raise ValueError("unsupported keystore")
    crypto = document.get("crypto", document.get("Crypto"))
    if type(crypto) is not dict or crypto.get("cipher") != "aes-128-ctr":
        raise ValueError("unsupported cipher")
    params = crypto.get("cipherparams")
    if type(params) is not dict or re.fullmatch(r"[0-9a-fA-F]{32}", str(params.get("iv", ""))) is None:
        raise ValueError("invalid cipher parameters")
    if re.fullmatch(r"[0-9a-fA-F]{64}", str(crypto.get("ciphertext", ""))) is None:
        raise ValueError("invalid ciphertext")
    if re.fullmatch(r"[0-9a-fA-F]{64}", str(crypto.get("mac", ""))) is None:
        raise ValueError("invalid MAC")
    kdf = crypto.get("kdf")
    kdfparams = crypto.get("kdfparams")
    if type(kdfparams) is not dict or kdfparams.get("dklen") != 32:
        raise ValueError("invalid KDF parameters")
    if re.fullmatch(r"[0-9a-fA-F]{32}", str(kdfparams.get("salt", ""))) is None:
        raise ValueError("invalid KDF salt")
    if kdf == "scrypt":
        n, r, p = kdfparams.get("n"), kdfparams.get("r"), kdfparams.get("p")
        if type(n) is not int or n not in {2**14, 2**15, 2**16, 2**17, 2**18} or r != 8 or p != 1:
            raise ValueError("scrypt parameters exceed the bounded policy")
    elif kdf == "pbkdf2":
        c = kdfparams.get("c")
        if type(c) is not int or not 100_000 <= c <= 1_000_000 or kdfparams.get("prf") != "hmac-sha256":
            raise ValueError("PBKDF2 parameters exceed the bounded policy")
    else:
        raise ValueError("unsupported KDF")


def _run(request: dict, expected_binding: dict) -> dict:
    if type(request) is not dict or request.get("version") != "kairos.local-keystore-sign.v1":
        raise ValueError("invalid request")
    operation = request.get("operation")
    if type(operation) is not str:
        raise ValueError("operation not allowlisted")
    schema_profile = request.get("schema_profile")
    if schema_profile == _PRODUCTION_PROFILE:
        profile_ops = _PRODUCTION_OPS
    elif schema_profile == _LEGACY_PROFILE:
        profile_ops = _OPS
    else:
        raise ValueError("schema profile not allowlisted")
    fields = profile_ops.get(operation)
    if fields is None:
        raise ValueError("operation not allowlisted")
    ref = request.get("custody_reference")
    wallet = request.get("wallet_address")
    chain_id = request.get("chain_id")
    instruments = request.get("approved_instruments")
    if (
        type(ref) is not str
        or not ref
        or ref != expected_binding.get("custody_reference")
        or type(wallet) is not str
        or re.fullmatch(r"0x[0-9a-fA-F]{40}", wallet) is None
        or wallet.casefold() != str(expected_binding.get("wallet_address", "")).casefold()
    ):
        raise ValueError("invalid custody binding")
    if (
        type(chain_id) is not int
        or chain_id <= 0
        or chain_id != expected_binding.get("chain_id")
        or type(instruments) is not list
        or len(instruments) != 5
        or len(set(instruments)) != 5
        or instruments != expected_binding.get("approved_instruments")
        or not all(type(item) is str and 0 < len(item) <= 80 for item in instruments)
    ):
        raise ValueError("invalid custody binding")
    expected_domain = {**_DOMAIN, "chainId": str(chain_id)}
    expected_types = {operation: [{"name": name, "type": kind} for name, kind in fields]}
    if request.get("domain") != expected_domain or request.get("types") != expected_types:
        raise ValueError("domain/schema mismatch")
    message = request.get("message")
    metadata_fields = (
        {"order"}
        if schema_profile == _PRODUCTION_PROFILE and operation == "New take-profit/stop-loss"
        else set()
    )
    if type(message) is not dict or set(message) != {name for name, _ in fields} | metadata_fields:
        raise ValueError("message/schema mismatch")
    for name, kind in fields:
        value = message[name]
        if kind.startswith("uint"):
            bits = int(kind[4:])
            if type(value) is not int or not 0 <= value < 2**bits:
                raise ValueError("invalid typed integer")
        elif type(value) is not str or not 0 < len(value) <= 160 or any(ord(c) < 32 for c in value):
            raise ValueError("invalid typed string")
    if message.get("instrument") not in instruments:
        raise ValueError("instrument outside custody universe")
    if "chainId" in message and message["chainId"] != chain_id:
        raise ValueError("chain mismatch")
    if "side" in message and message["side"] not in {"BUY", "SELL"}:
        raise ValueError("invalid side")
    if "leverage" in message and message["leverage"] != 1:
        raise ValueError("invalid leverage")
    if "timeInForce" in message and message["timeInForce"] != "IOC":
        raise ValueError("invalid time in force")
    if "id" in message and re.fullmatch(r"[0-9]{5}:[A-Fa-f0-9]{26}", message["id"]) is None:
        raise ValueError("invalid order ID")
    if "order" in message and re.fullmatch(r"[0-9]{5}:[A-Fa-f0-9]{26}", message["order"]) is None:
        raise ValueError("invalid parent ID")
    if "type" in message and message["type"] not in {"stop-loss", "take-profit"}:
        raise ValueError("invalid protective type")
    for name in ("cashQuantity", "limitPrice", "stopPrice", "price"):
        if name in message and message[name] <= 0:
            raise ValueError("non-positive price")
    if "quantity" in message and message["quantity"] == 0 and operation != "New take-profit/stop-loss":
        raise ValueError("non-positive quantity")

    # Crucially, keystore and unlock files are opened only after all binding,
    # domain, schema, and message checks have succeeded.
    key_path = _path(request.get("keystore_file"))
    unlock_path = _path(request.get("unlock_file"))
    if key_path == unlock_path:
        raise ValueError("key and unlock files must be separate")
    key_document = json.loads(_read_private(key_path, MAX_SECRET_FILE), object_pairs_hook=_reject_duplicates)
    _validate_keystore(key_document)
    password_bytes = _read_private(unlock_path, 4096)
    password = password_bytes.decode("utf-8")
    if password.endswith("\r\n"):
        password = password[:-2]
    elif password.endswith("\n"):
        password = password[:-1]
    if not password or "\x00" in password:
        raise ValueError("invalid unlock material")
    private_key = bytearray(Account.decrypt(key_document, password))
    try:
        account = Account.from_key(bytes(private_key))
        if account.address.casefold() != wallet.casefold():
            raise ValueError("decrypted wallet mismatch")
        signed_message = {name: message[name] for name, _ in fields}
        signable = Account.sign_typed_data(
            account.key,
            domain_data=expected_domain,
            message_types=expected_types,
            message_data=signed_message,
        )
        signature = signable.signature.hex()
        if not signature.startswith("0x"):
            signature = "0x" + signature
        return {
            "version": "kairos.local-keystore-sign-result.v1",
            "wallet_address": account.address,
            "signature": signature,
        }
    finally:
        private_key[:] = b"\x00" * len(private_key)


def main() -> int:
    try:
        raw = sys.stdin.buffer.read(MAX_LINE + 1)
        if len(raw) > MAX_LINE:
            return 2
        if len(sys.argv) != 2:
            return 2
        expected_binding = json.loads(sys.argv[1], object_pairs_hook=_reject_duplicates)
        if type(expected_binding) is not dict or set(expected_binding) != {
            "custody_reference",
            "wallet_address",
            "chain_id",
            "approved_instruments",
        }:
            return 2
        request = json.loads(raw, object_pairs_hook=_reject_duplicates)
        response = _run(request, expected_binding)
        output = json.dumps(response, sort_keys=True, separators=(",", ":")).encode()
        if len(output) > 4096:
            return 3
        sys.stdout.buffer.write(output)
        return 0
    except Exception:
        # Never reveal decrypted material, file paths, or library diagnostics.
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
