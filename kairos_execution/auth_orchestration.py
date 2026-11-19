"""Explicit provisioning and one-shot EVEDEX authentication observation.

This module never submits orders. Its functions are deployment actions, not
startup hooks: provisioning copies existing credentials into protected files,
and the session call creates an authenticated session only when invoked.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from .auth_audit import AuthAuditJournal
from .evedex_private_ws import EvedexPrivateWsStream
from .local_custody import LocalEncryptedKeystoreBackend, _regular_protected_file
from .production_claims import PostgresProductionClaims
from .production_readiness import ProductionContextV1
from .production_reads import ProductionEvedexReads
from .production_ws_observer import WsRestObservation, capture_ws_rest_observation
from .protected_files import ProtectedFileError, create_private_directory, write_new_private_file
from .siwe_session import (
    VerifiedWalletSession,
    WalletSessionRegionForbidden,
    WalletSessionTwofaRequired,
    create_evedex_wallet_session,
)


class AuthPreparationError(PermissionError):
    """A protected file or explicit authentication step is unavailable."""


@dataclass(frozen=True, slots=True)
class ProtectedAuthMaterial:
    directory: Path = field(repr=False)
    keystore_file: Path = field(repr=False)
    unlock_file: Path = field(repr=False)
    api_key_file: Path = field(repr=False)
    wallet_address: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class AuthenticatedAccountObservation:
    session: VerifiedWalletSession = field(repr=False)
    observation: WsRestObservation = field(repr=False)
    trading_authority: Literal[False] = field(default=False, init=False)


def _assert_path_without_links(path: Path) -> None:
    for candidate in (path, *path.parents):
        if not candidate.exists():
            continue
        info = candidate.lstat()
        if candidate.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
            raise AuthPreparationError("authentication material path contains a link")


def _private_acl(path: Path, *, directory: bool) -> None:
    if os.name != "nt":
        path.chmod(0o700 if directory else 0o600)
        return
    identity = subprocess.run(
        ["whoami"], check=True, capture_output=True, text=True, timeout=5
    ).stdout.strip()
    if not identity or "\n" in identity or "\r" in identity:
        raise AuthPreparationError("current Windows identity unavailable")
    # These commands target only the just-created empty directory/files. A
    # secret is written only after owner and DACL validation has completed.
    user_grant = f"{identity}:(OI)(CI)(F)" if directory else f"{identity}:(F)"
    system_grant = "SYSTEM:(OI)(CI)(R)" if directory else "SYSTEM:(R)"
    for arguments in (
        ["/setowner", identity],
        ["/inheritance:r", "/grant:r", user_grant, system_grant],
        ["/remove:g", "*S-1-5-32-544"],
    ):
        subprocess.run(["icacls", str(path), *arguments], check=True, capture_output=True, timeout=5)


def _write_new_private_file(path: Path, content: bytes) -> None:
    succeeded = False
    try:
        write_new_private_file(path, content)
        succeeded = True
    except ProtectedFileError:
        pass
    if not succeeded:
        raise AuthPreparationError("new authentication material could not be created privately")


def provision_existing_auth_material(
    *, destination: Path, wallet_private_key: str, api_key: str, expected_wallet_address: str,
) -> ProtectedAuthMaterial:
    """Copy an existing key into new encrypted, private local custody files.

    No key, wallet, account or exchange API credential is generated. The local
    unlock secret is random and never returned. The destination must not exist;
    failure can leave a partial directory which must be reviewed, never reused.
    Existing user files are never altered or deleted.
    """
    material = None
    try:
        from eth_account import Account
        from eth_utils import is_checksum_address

        if not isinstance(destination, Path) or not destination.is_absolute():
            raise ValueError("absolute destination required")
        if destination.exists() or not destination.parent.is_dir():
            raise ValueError("new destination under an existing parent required")
        _assert_path_without_links(destination)
        if not isinstance(api_key, str) or not 1 <= len(api_key) <= 8192:
            raise ValueError("bounded existing API key required")
        if any(ord(character) < 33 or ord(character) > 126 for character in api_key):
            raise ValueError("API key contains invalid characters")
        if not is_checksum_address(expected_wallet_address):
            raise ValueError("explicit checksum wallet required")
        wallet = Account.from_key(wallet_private_key)
        if wallet.address != expected_wallet_address:
            raise ValueError("existing wallet does not match expected account")
        unlock = secrets.token_urlsafe(48)
        encrypted = Account.encrypt(wallet_private_key, unlock, kdf="pbkdf2", iterations=262144)
        create_private_directory(destination)
        keystore, unlock_file, api_file = (
            destination / "wallet.json", destination / "unlock.txt", destination / "api-key.txt"
        )
        _write_new_private_file(keystore, json.dumps(encrypted, separators=(",", ":")).encode())
        _write_new_private_file(unlock_file, (unlock + "\n").encode())
        _write_new_private_file(api_file, (api_key + "\n").encode())
        material = ProtectedAuthMaterial(destination, keystore, unlock_file, api_file, wallet.address)
    except Exception:
        pass
    if material is None:
        raise AuthPreparationError(
            "protected authentication material unavailable; inspect destination"
        ) from None
    return material


def build_auth_custody(
    material: ProtectedAuthMaterial, *, chain_id: int, custody_reference: str,
) -> LocalEncryptedKeystoreBackend:
    """Build the existing isolated worker with an explicitly selected auth chain."""
    if type(material) is not ProtectedAuthMaterial or type(chain_id) is not int or chain_id <= 0:
        raise AuthPreparationError("explicit authentication material and chain required")
    return LocalEncryptedKeystoreBackend(
        python_executable=Path(os.path.abspath(sys.executable)),
        keystore_file=material.keystore_file, unlock_file=material.unlock_file,
        custody_reference=custody_reference, wallet_address=material.wallet_address,
        chain_id=chain_id, approved_instruments=("BTCUSD",),
    )


async def authenticate_and_capture_once(
    *, backend: LocalEncryptedKeystoreBackend, claims: PostgresProductionClaims,
    reads: ProductionEvedexReads, expected_context: ProductionContextV1,
    expected_wallet_address: str, allow_session_creation: bool,
    observation_timeout_seconds: float = 30.0,
    audit: AuthAuditJournal | None = None,
) -> AuthenticatedAccountObservation:
    """Create exactly one wallet session and perform one read-only WS capture.

    Existing nonce/session claims prevent blind retries within their bound DB.
    A failed or ambiguous login/capture returns no token. A capture failure
    does not mean the auth session was absent, revoked or cancelled.
    """
    if (
        allow_session_creation is not True
        or type(observation_timeout_seconds) not in (int, float)
        or not 0 < observation_timeout_seconds <= 30
    ):
        raise AuthPreparationError("explicit authentication action and bounded observation required")
    result = None
    twofa_required = False
    region_forbidden = False
    try:
        session = await create_evedex_wallet_session(
            backend=backend, claims=claims, reads=reads, expected_context=expected_context,
            expected_wallet_address=expected_wallet_address,
            allow_session_creation=allow_session_creation,
            audit=audit,
        )
        if audit is not None:
            await audit.record("WS_CAPTURE_STARTED")
        stream = EvedexPrivateWsStream(reads=reads, access_token=session.access_token)
        observation = await capture_ws_rest_observation(
            reads, stream, timeout_seconds=observation_timeout_seconds,
        )
        if audit is not None:
            await audit.record("WS_CAPTURED")
        result = AuthenticatedAccountObservation(session, observation)
    except WalletSessionTwofaRequired:
        twofa_required = True
    except WalletSessionRegionForbidden:
        region_forbidden = True
    except Exception:
        pass
    if twofa_required:
        raise WalletSessionTwofaRequired() from None
    if region_forbidden:
        raise WalletSessionRegionForbidden() from None
    if result is None:
        raise AuthPreparationError("authentication observation refused or unresolved; do not retry") from None
    return result


def auth_material_summary(material: ProtectedAuthMaterial) -> dict:
    """Public diagnostics only; no credential, wallet or account is returned."""
    return {
        "version": "kairos.protected-auth-material.v1",
        "wallet_binding_sha256": hashlib.sha256(material.wallet_address.lower().encode()).hexdigest(),
        "files_private": all(_regular_protected_file(path) for path in (
            material.keystore_file, material.unlock_file, material.api_key_file
        )),
        "trading_authority": False,
    }
