"""Explicit EVEDEX SIWE session creation; never trading or LIVE authority.

The session function sends a sign-up POST which may create an auth session or
account and requires separately authorized explicit invocation. It compares
the original API-key account wallet and returned Bearer account identity;
failure or an ambiguous POST must never be retried blindly.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

import aiohttp

from .auth_audit import AuthAuditJournal, public_auth_error_code
from .local_custody import LocalCustodyError, LocalEncryptedKeystoreBackend
from .production_claims import PostgresProductionClaims
from .production_readiness import ProductionContextV1, canonical_digest
from .production_reads import ProductionEvedexReads
from .siwe_auth import evedex_siwe_message

NONCE_URL = "https://auth-api.evedex.com/auth/nonce"
AUTH_URL = "https://auth-api.evedex.com/auth/user/sign-up"
ACCOUNT_URL = "https://trading-api.evedex.com/api/user/me"


@dataclass(frozen=True, slots=True)
class VerifiedWalletSession:
    """Ephemeral credentials: never log or persist this object."""

    access_token: str = field(repr=False)
    refresh_token: str | None = field(repr=False)
    account_id: str = field(repr=False)


class WalletSessionTwofaRequired(LocalCustodyError):
    """The auth server explicitly returned the documented 2FA-required label."""

    code = "TWOFA_REQUIRED"

    def __init__(self):
        super().__init__("EVEDEX authentication requires the account's two-factor code")


class WalletSessionRegionForbidden(LocalCustodyError):
    """The auth server explicitly refused the current region with HTTP 451."""

    code = "FORBIDDEN_REGION"

    def __init__(self):
        super().__init__("EVEDEX refused authentication for the current region")


@dataclass(frozen=True, slots=True)
class _ConfirmedTwofaRefusal:
    pass


@dataclass(frozen=True, slots=True)
class _ConfirmedRegionalRefusal:
    pass


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


async def _fetch_evedex_nonce() -> str:
    """Exact official TLS endpoint; no redirects, credentials, proxy or retries."""
    try:
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(
            timeout=timeout, trust_env=False, cookie_jar=aiohttp.DummyCookieJar()
        ) as session:
            async with session.get(NONCE_URL, allow_redirects=False) as response:
                if response.status != 200 or response.content_type != "application/json":
                    raise ValueError("nonce response rejected")
                body = bytearray()
                async for chunk in response.content.iter_chunked(1024):
                    body.extend(chunk)
                    if len(body) > 4096:
                        raise ValueError("nonce response exceeded bound")
        data = json.loads(body, object_pairs_hook=_unique_object)
        if type(data) is not dict or set(data) != {"nonce"} or type(data["nonce"]) is not str:
            raise ValueError("nonce response malformed")
        return data["nonce"]
    except Exception:
        pass
    # Raised outside the external exception handler: no secret-bearing
    # exception is retained in the exception context.
    raise LocalCustodyError("EVEDEX nonce is unavailable") from None


async def prepare_evedex_siwe_once(
    *,
    backend: LocalEncryptedKeystoreBackend,
    claims: PostgresProductionClaims,
    expected_context: ProductionContextV1,
    expected_wallet_address: str,
    audit: AuthAuditJournal | None = None,
) -> tuple[str, str]:
    """Commit a scoped one-use nonce, then prepare a fixed SIWE signature.

    This is an explicit action and does not post the signature or create a
    session. Unknown claim or signing outcomes are never retried. Issuance of a
    session later requires separate account-identity and authorization checks.
    """
    if (
        type(backend) is not LocalEncryptedKeystoreBackend
        or type(claims) is not PostgresProductionClaims
        or type(expected_context) is not ProductionContextV1
        or claims.context_sha256 != canonical_digest(expected_context)
        or backend.wallet_address != expected_wallet_address
        or (audit is not None and (type(audit) is not AuthAuditJournal or audit.claims is not claims))
    ):
        raise LocalCustodyError("SIWE account or custody scope mismatch")
    nonce = await _fetch_evedex_nonce()
    issued_at = datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    try:
        message = evedex_siwe_message(
            address=backend.wallet_address, chain_id=backend.chain_id, nonce=nonce, issued_at=issued_at
        )
    except ValueError:
        raise LocalCustodyError("EVEDEX nonce failed validation") from None
    wallet_digest = hashlib.sha256(backend.wallet_address.lower().encode()).hexdigest()
    nonce_digest = hashlib.sha256(nonce.encode()).hexdigest()
    request_digest = hashlib.sha256(message.encode()).hexdigest()
    try:
        claimed = await claims.claim(
            "MANUAL_NONCE", "siwe:" + wallet_digest, "siwe:" + nonce_digest, request_digest
        )
    except Exception:
        claimed = None
    if claimed is None:
        raise LocalCustodyError("SIWE nonce claim outcome unknown; do not retry") from None
    if claimed is not True:
        raise LocalCustodyError("SIWE nonce was already used")
    if audit is not None:
        await audit.record("NONCE_CLAIMED")
    # A cancellation or deadline cannot stop a running thread. Its nonce was
    # already committed, and the result must never be retried blindly.
    try:
        if audit is not None:
            await audit.record("SIGN_STARTED")
        result = await asyncio.to_thread(
            backend._sign_evedex_siwe_unclaimed,
            custody_reference=backend.custody_reference,
            nonce=nonce,
            issued_at=issued_at,
        )
    except Exception:
        result = None
    if result is None:
        raise LocalCustodyError("SIWE signing outcome unknown; do not retry") from None
    if result[0] != message:
        raise LocalCustodyError("SIWE message differs from its nonce claim")
    if audit is not None:
        await audit.record("SIGNATURE_RECOVERED")
    return result


async def _bounded_json(response, *, expected_status=200) -> dict:
    if response.status != expected_status or response.content_type != "application/json":
        raise ValueError("remote response rejected")
    body = bytearray()
    async for chunk in response.content.iter_chunked(1024):
        body.extend(chunk)
        if len(body) > 64 * 1024:
            raise ValueError("remote response exceeds bound")
    result = json.loads(body, object_pairs_hook=_unique_object)
    if type(result) is not dict:
        raise ValueError("remote response malformed")
    return result


async def _create_evedex_wallet_session_impl(
    *,
    backend: LocalEncryptedKeystoreBackend,
    claims: PostgresProductionClaims,
    reads: ProductionEvedexReads,
    expected_context: ProductionContextV1,
    expected_wallet_address: str,
    allow_session_creation: bool,
    audit: AuthAuditJournal | None = None,
) -> VerifiedWalletSession | _ConfirmedTwofaRefusal | _ConfirmedRegionalRefusal:
    """Create one wallet auth session, returning it only for the exact account.

    This sends the official sign-up POST and may create a session or an account.
    Only call after explicit authorization for that action. It never submits a
    trade, and no caller may infer trading authority or continuous history.
    """
    if (
        allow_session_creation is not True
        or type(reads) is not ProductionEvedexReads
        or type(backend) is not LocalEncryptedKeystoreBackend
        or type(claims) is not PostgresProductionClaims
        or not reads._preflight_complete
        or type(expected_context) is not ProductionContextV1
        or reads.expected_account_id != expected_context.remote_account_id
        or claims.context_sha256 != canonical_digest(expected_context)
        or backend.wallet_address != expected_wallet_address
    ):
        raise LocalCustodyError("wallet session scope or explicit authorization unavailable")
    try:
        initial = await reads._read("account_identity")
        if (
            type(initial) is not dict
            or str(initial.get("exchangeId", "")) != expected_context.remote_account_id
            or not isinstance(initial.get("wallet"), str)
            or initial["wallet"].casefold() != expected_wallet_address.casefold()
        ):
            raise ValueError("preflight account mismatch")
        # Within this claims database and context one attempt is permanent,
        # including a lost response. Other databases/workers are not fenced.
        attempt_hash = hashlib.sha256(
            (claims.context_sha256 + "\n" + expected_wallet_address).encode()
        ).hexdigest()
        attempt = await claims.claim(
            "MANUAL_NONCE", "siwe-session:" + claims.context_sha256, "one-attempt", attempt_hash
        )
        if attempt is not True:
            raise ValueError("SIWE session attempt already consumed")
        if audit is not None:
            if type(audit) is not AuthAuditJournal or audit.claims is not claims:
                raise ValueError("audit and authentication claims scope differ")
            await audit.record("SESSION_ATTEMPT_CLAIMED")
        message, signature = await prepare_evedex_siwe_once(
            backend=backend,
            claims=claims,
            expected_context=expected_context,
            expected_wallet_address=expected_wallet_address,
            audit=audit,
        )
        nonce_match = re.search(r"\nNonce: ([A-Za-z0-9]{8,128})\nIssued At:", message)
        issued_match = re.search(r"\nIssued At: ([0-9T:.\-]+Z)$", message)
        if nonce_match is None or issued_match is None:
            raise ValueError("bound SIWE nonce unavailable")
        if message != evedex_siwe_message(
            address=backend.wallet_address,
            chain_id=backend.chain_id,
            nonce=nonce_match.group(1),
            issued_at=issued_match.group(1),
        ):
            raise ValueError("SIWE message changed or expired")
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=10), trust_env=False, cookie_jar=aiohttp.DummyCookieJar()
        ) as session:
            payload = {
                "wallet": expected_wallet_address,
                "message": message,
                "nonce": nonce_match.group(1),
                "signature": signature,
            }
            if audit is not None:
                await audit.record("AUTH_POST_STARTED")
            async with session.post(AUTH_URL, json=payload, allow_redirects=False) as response:
                if audit is not None:
                    await audit.record("AUTH_HTTP", http_status=response.status)
                if response.status >= 400:
                    refusal = await _bounded_json(response, expected_status=response.status)
                    if audit is not None:
                        await audit.record(
                            "AUTH_ERROR_CODE", http_status=response.status,
                            code=public_auth_error_code(refusal.get("label"))
                        )
                    if response.status == 400 and refusal.get("label") == "twofa_code_required_error":
                        return _ConfirmedTwofaRefusal()
                    if response.status == 451 and refusal.get("label") == "forbidden_region_error":
                        return _ConfirmedRegionalRefusal()
                    raise ValueError("authentication rejected")
                if not 200 <= response.status < 300:
                    raise ValueError("authentication rejected")
                auth = await _bounded_json(response, expected_status=response.status)
            token = auth.get("token")
            user = auth.get("user")
            if (
                type(token) is not dict
                or type(user) is not dict
                or str(user.get("wallet", "")).casefold() != expected_wallet_address.casefold()
                or not isinstance(token.get("accessToken"), str)
                or not token["accessToken"]
                or ("refreshToken" in token and (
                    not isinstance(token["refreshToken"], str) or not token["refreshToken"]
                    or any(c in token["refreshToken"] for c in "\r\n")
                    or len(token["refreshToken"]) > 8192
                ))
                or any(c in token["accessToken"] for c in "\r\n")
                or len(token["accessToken"]) > 8192
            ):
                raise ValueError("wallet authentication response mismatch")
            if audit is not None:
                await audit.record("AUTH_SCHEMA_VALID")
                await audit.record("BEARER_GET_STARTED")
            async with session.get(
                ACCOUNT_URL,
                headers={"Authorization": "Bearer " + token["accessToken"]},
                allow_redirects=False,
            ) as response:
                if audit is not None:
                    await audit.record("BEARER_HTTP", http_status=response.status)
                account = await _bounded_json(response)
            if str(account.get("exchangeId", "")) != expected_context.remote_account_id:
                raise ValueError("wallet session belongs to a different account")
            if audit is not None:
                await audit.record("BEARER_IDENTITY_VALID")
            return VerifiedWalletSession(
                token["accessToken"], token.get("refreshToken"), expected_context.remote_account_id
            )
    except asyncio.CancelledError:
        raise
    except Exception:
        pass
    raise LocalCustodyError("wallet session refused or outcome unknown; do not retry blindly") from None


async def create_evedex_wallet_session(
    *,
    backend: LocalEncryptedKeystoreBackend,
    claims: PostgresProductionClaims,
    reads: ProductionEvedexReads,
    expected_context: ProductionContextV1,
    expected_wallet_address: str,
    allow_session_creation: bool,
    audit: AuthAuditJournal | None = None,
) -> VerifiedWalletSession:
    """Explicitly create a wallet session; never submit orders or grant LIVE."""
    result = None
    try:
        result = await _create_evedex_wallet_session_impl(
            backend=backend,
            claims=claims,
            reads=reads,
            expected_context=expected_context,
            expected_wallet_address=expected_wallet_address,
            allow_session_creation=allow_session_creation,
            audit=audit,
        )
    except asyncio.CancelledError:
        raise
    except Exception:
        pass
    if type(result) is _ConfirmedTwofaRefusal:
        raise WalletSessionTwofaRequired() from None
    if type(result) is _ConfirmedRegionalRefusal:
        raise WalletSessionRegionForbidden() from None
    if type(result) is VerifiedWalletSession:
        return result
    if audit is not None:
        try:
            await audit.record("AUTH_UNKNOWN")
        except Exception:
            pass
    # Do not retain the inner traceback, which can contain temporary tokens.
    raise LocalCustodyError("wallet session refused or outcome unknown; do not retry blindly") from None
