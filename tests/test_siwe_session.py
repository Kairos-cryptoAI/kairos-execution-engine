"""No live credentials, authentication, or network in these tests."""

from uuid import UUID

import pytest

from kairos_execution import siwe_session
from kairos_execution.local_custody import LocalCustodyError
from kairos_execution.production_claims import PostgresProductionClaims
from kairos_execution.production_readiness import ProductionContextV1
from kairos_execution.production_reads import ProductionEvedexReads
from tests.test_local_custody import _backend


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload,valid",
    [(b'{"nonce":"TestNonce123"}', True), (b'{"nonce":"TestNonce123","nonce":"other"}', False)],
)
async def test_nonce_endpoint_reads_fragmented_body_and_rejects_duplicates(monkeypatch, payload, valid):
    class Content:
        async def iter_chunked(self, size):
            assert size == 1024
            yield payload[:4]
            yield payload[4:]

    class Response:
        status, content_type, content = 200, "application/json", Content()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

    class Session:
        def __init__(self, **kwargs):
            assert kwargs["trust_env"] is False

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        def get(self, url, **kwargs):
            assert url == "https://auth-api.evedex.com/auth/nonce"
            assert kwargs == {"allow_redirects": False}
            return Response()

    monkeypatch.setattr(siwe_session.aiohttp, "ClientSession", Session)
    if valid:
        assert await siwe_session._fetch_evedex_nonce() == "TestNonce123"
    else:
        with pytest.raises(LocalCustodyError) as error:
            await siwe_session._fetch_evedex_nonce()
        assert error.value.__context__ is None


@pytest.mark.asyncio
async def test_nonce_claim_is_committed_before_siwe_and_reuse_refused(tmp_path, monkeypatch):
    backend, wallet = _backend(tmp_path)
    context = ProductionContextV1(
        remote_account_id="synthetic-account",
        adaptive_system_id="test",
        frozen_policy_sha256="a" * 64,
        source_set_sha256="b" * 64,
    )
    claims = PostgresProductionClaims(
        object(),
        expected_database="kairos_production_evidence_siwe_test_1234",
        database_uuid=UUID(int=1),
        policy_namespace="test",
        runtime_role="runtime",
        context=context,
    )
    seen = set()
    audit_stages = []

    async def nonce():
        return "TestNonce12345678"

    async def claim(kind, namespace, identity, digest):
        if namespace.startswith("auth-stage:"):
            audit_stages.append(identity)
            return True
        assert kind == "MANUAL_NONCE" and namespace.startswith("siwe:")
        assert identity.startswith("siwe:") and len(digest) == 64
        if identity in seen:
            return False
        seen.add(identity)
        return True

    monkeypatch.setattr(siwe_session, "_fetch_evedex_nonce", nonce)
    monkeypatch.setattr(claims, "claim", claim)
    args = dict(
        backend=backend,
        claims=claims,
        expected_context=context,
        expected_wallet_address=wallet,
        audit=siwe_session.AuthAuditJournal(claims),
    )
    message, signature = await siwe_session.prepare_evedex_siwe_once(**args)
    assert "Nonce: TestNonce12345678" in message and signature.startswith("0x")
    assert audit_stages == ["NONCE_CLAIMED", "SIGN_STARTED", "SIGNATURE_RECOVERED"]
    with pytest.raises(LocalCustodyError, match="already used"):
        await siwe_session.prepare_evedex_siwe_once(**args)


@pytest.mark.asyncio
async def test_claim_failure_never_invokes_signer(tmp_path, monkeypatch):
    backend, wallet = _backend(tmp_path)
    context = ProductionContextV1(
        remote_account_id="synthetic-account",
        adaptive_system_id="test",
        frozen_policy_sha256="a" * 64,
        source_set_sha256="b" * 64,
    )
    claims = PostgresProductionClaims(
        object(),
        expected_database="kairos_production_evidence_siwe_test_1234",
        database_uuid=UUID(int=1),
        policy_namespace="test",
        runtime_role="runtime",
        context=context,
    )

    async def nonce():
        return "TestNonce12345678"

    async def claim(*args):
        raise RuntimeError("synthetic private diagnostics")

    monkeypatch.setattr(siwe_session, "_fetch_evedex_nonce", nonce)
    monkeypatch.setattr(claims, "claim", claim)
    monkeypatch.setattr(backend, "_sign_evedex_siwe_unclaimed", lambda **kwargs: pytest.fail("must not sign"))
    with pytest.raises(LocalCustodyError, match="outcome unknown"):
        await siwe_session.prepare_evedex_siwe_once(
            backend=backend, claims=claims, expected_context=context, expected_wallet_address=wallet
        )


@pytest.mark.asyncio
async def test_session_attempt_is_not_retried_after_lost_post(tmp_path, monkeypatch):
    backend, wallet = _backend(tmp_path)
    context = ProductionContextV1(
        remote_account_id="synthetic-account",
        adaptive_system_id="test",
        frozen_policy_sha256="a" * 64,
        source_set_sha256="b" * 64,
    )
    claims = PostgresProductionClaims(
        object(),
        expected_database="kairos_production_evidence_siwe_test_1234",
        database_uuid=UUID(int=1),
        policy_namespace="test",
        runtime_role="runtime",
        context=context,
    )
    reads = object.__new__(ProductionEvedexReads)
    reads._preflight_complete = True
    reads.expected_account_id = context.remote_account_id
    attempts = set()
    posts = []

    async def read_identity(source):
        assert source == "account_identity"
        return {"exchangeId": context.remote_account_id, "wallet": wallet}

    async def claim(kind, namespace, identity, digest):
        if identity in attempts:
            return False
        attempts.add(identity)
        return True

    async def prepare(**kwargs):
        from datetime import UTC, datetime

        issued = datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        return siwe_session.evedex_siwe_message(
            address=wallet, chain_id=backend.chain_id, nonce="TestNonce12345678", issued_at=issued
        ), "0xsignature"

    class Session:
        def __init__(self, **kwargs):
            assert kwargs["trust_env"] is False

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        def post(self, url, **kwargs):
            assert url == siwe_session.AUTH_URL and kwargs["allow_redirects"] is False
            posts.append(url)
            raise TimeoutError("synthetic-private-server-error")

    monkeypatch.setattr(reads, "_read", read_identity)
    monkeypatch.setattr(claims, "claim", claim)
    monkeypatch.setattr(siwe_session, "prepare_evedex_siwe_once", prepare)
    monkeypatch.setattr(siwe_session.aiohttp, "ClientSession", Session)
    args = dict(
        backend=backend,
        claims=claims,
        reads=reads,
        expected_context=context,
        expected_wallet_address=wallet,
        allow_session_creation=True,
    )
    for _ in range(2):
        with pytest.raises(LocalCustodyError, match="outcome unknown") as error:
            await siwe_session.create_evedex_wallet_session(**args)
        assert "synthetic-private-server-error" not in str(error.value)
        assert error.value.__context__ is None
    assert len(posts) == 1


@pytest.mark.asyncio
async def test_session_rejects_wallet_mismatch_before_any_signing(tmp_path, monkeypatch):
    backend, wallet = _backend(tmp_path)
    context = ProductionContextV1(
        remote_account_id="synthetic-account",
        adaptive_system_id="test",
        frozen_policy_sha256="a" * 64,
        source_set_sha256="b" * 64,
    )
    claims = PostgresProductionClaims(
        object(),
        expected_database="kairos_production_evidence_siwe_test_1234",
        database_uuid=UUID(int=1),
        policy_namespace="test",
        runtime_role="runtime",
        context=context,
    )
    reads = object.__new__(ProductionEvedexReads)
    reads._preflight_complete = True
    reads.expected_account_id = context.remote_account_id

    async def wrong_wallet(_source):
        return {"exchangeId": context.remote_account_id, "wallet": "0x" + "0" * 40}

    monkeypatch.setattr(reads, "_read", wrong_wallet)
    with pytest.raises(LocalCustodyError):
        await siwe_session.create_evedex_wallet_session(
            backend=backend,
            claims=claims,
            reads=reads,
            expected_context=context,
            expected_wallet_address=wallet,
            allow_session_creation=True,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "session_account,should_succeed", [("synthetic-account", True), ("different", False)]
)
@pytest.mark.parametrize("with_refresh", [True, False])
@pytest.mark.parametrize("auth_requires_twofa", [True, False])
@pytest.mark.parametrize("auth_success_status", [200, 201, 204, 302, 451])
async def test_wallet_session_checks_server_account_before_return(
    tmp_path,
    monkeypatch,
    session_account,
    should_succeed,
    with_refresh,
    auth_requires_twofa,
    auth_success_status,
):
    import json
    from datetime import UTC, datetime

    backend, wallet = _backend(tmp_path)
    context = ProductionContextV1(
        remote_account_id="synthetic-account",
        adaptive_system_id="test",
        frozen_policy_sha256="a" * 64,
        source_set_sha256="b" * 64,
    )
    claims = PostgresProductionClaims(
        object(),
        expected_database="kairos_production_evidence_siwe_test_1234",
        database_uuid=UUID(int=1),
        policy_namespace="test",
        runtime_role="runtime",
        context=context,
    )
    reads = object.__new__(ProductionEvedexReads)
    reads._preflight_complete = True
    reads.expected_account_id = context.remote_account_id

    async def read_identity(_source):
        return {"exchangeId": context.remote_account_id, "wallet": wallet}

    async def claim(*args):
        return True

    async def prepare(**kwargs):
        issued = datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        return siwe_session.evedex_siwe_message(
            address=wallet, chain_id=backend.chain_id, nonce="TestNonce12345678", issued_at=issued
        ), "0xsignature"

    class Content:
        def __init__(self, value):
            self.raw = json.dumps(value).encode()

        async def iter_chunked(self, _size):
            yield self.raw[:7]
            yield self.raw[7:]

    class Response:
        status, content_type = 200, "application/json"

        def __init__(self, value, status=200):
            self.status = status
            self.content = Content(value)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

    class Session:
        def __init__(self, **kwargs):
            assert kwargs["trust_env"] is False

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        def post(self, url, **kwargs):
            assert url == siwe_session.AUTH_URL and kwargs["allow_redirects"] is False
            if auth_requires_twofa:
                return Response({"label": "twofa_code_required_error", "message": "synthetic-private"}, 400)
            if auth_success_status == 204:
                return Response(None, 204)
            if auth_success_status == 451:
                return Response({"label": "forbidden_region_error", "message": "synthetic-private"}, 451)
            return Response(
                {
                    "user": {"wallet": wallet},
                    "token": {
                        "accessToken": "synthetic-access",
                        **({"refreshToken": "synthetic-refresh"} if with_refresh else {}),
                    },
                },
                auth_success_status,
            )

        def get(self, url, **kwargs):
            assert not auth_requires_twofa
            assert auth_success_status in (200, 201)
            assert url == siwe_session.ACCOUNT_URL and kwargs["allow_redirects"] is False
            assert kwargs["headers"]["Authorization"] == "Bearer synthetic-access"
            return Response({"exchangeId": session_account})

    monkeypatch.setattr(reads, "_read", read_identity)
    monkeypatch.setattr(claims, "claim", claim)
    monkeypatch.setattr(siwe_session, "prepare_evedex_siwe_once", prepare)
    monkeypatch.setattr(siwe_session.aiohttp, "ClientSession", Session)
    args = dict(
        backend=backend,
        claims=claims,
        reads=reads,
        expected_context=context,
        expected_wallet_address=wallet,
        allow_session_creation=True,
    )
    if auth_requires_twofa:
        with pytest.raises(siwe_session.WalletSessionTwofaRequired) as error:
            await siwe_session.create_evedex_wallet_session(**args)
        assert error.value.code == "TWOFA_REQUIRED" and error.value.__context__ is None
        assert "synthetic-private" not in str(error.value)
    elif auth_success_status == 451:
        with pytest.raises(siwe_session.WalletSessionRegionForbidden) as error:
            await siwe_session.create_evedex_wallet_session(**args)
        assert error.value.code == "FORBIDDEN_REGION" and error.value.__context__ is None
        assert "synthetic-private" not in str(error.value)
    elif auth_success_status not in (200, 201):
        with pytest.raises(LocalCustodyError):
            await siwe_session.create_evedex_wallet_session(**args)
    elif should_succeed:
        result = await siwe_session.create_evedex_wallet_session(**args)
        assert result.access_token == "synthetic-access"
        assert result.refresh_token == ("synthetic-refresh" if with_refresh else None)
        assert "synthetic-access" not in repr(result) and "synthetic-refresh" not in repr(result)
    else:
        with pytest.raises(LocalCustodyError):
            await siwe_session.create_evedex_wallet_session(**args)
