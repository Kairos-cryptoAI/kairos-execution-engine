"""Synthetic credential copies and mocked auth/WS; no real account calls."""

import asyncio
import json

import pytest

pytest.importorskip("eth_account")
from eth_account import Account

from kairos_execution.auth_orchestration import (
    AuthPreparationError,
    auth_material_summary,
    authenticate_and_capture_once,
    build_auth_custody,
    provision_existing_auth_material,
)
from kairos_execution.local_custody import _regular_protected_file
from kairos_execution.siwe_session import VerifiedWalletSession, WalletSessionRegionForbidden

KEY = "0x" + "21" * 32
API_KEY = "synthetic-api-key-not-real"


def provision(tmp_path):
    return provision_existing_auth_material(
        destination=tmp_path / "protected",
        wallet_private_key=KEY,
        api_key=API_KEY,
        expected_wallet_address=Account.from_key(KEY).address,
    )


def test_private_existing_material_is_encrypted_and_owner_checked(tmp_path):
    material = provision(tmp_path)
    for path in (material.keystore_file, material.unlock_file, material.api_key_file):
        assert _regular_protected_file(path) == path.resolve()
    encrypted = json.loads(material.keystore_file.read_text())
    unlock = material.unlock_file.read_text().strip()
    assert bytes(Account.decrypt(encrypted, unlock)) == bytes.fromhex(KEY[2:])
    assert material.api_key_file.read_text().strip() == API_KEY
    assert KEY[2:] not in material.keystore_file.read_text()
    assert KEY not in repr(material) and API_KEY not in repr(material)
    summary = auth_material_summary(material)
    assert summary["files_private"] is True and summary["trading_authority"] is False
    assert material.wallet_address not in json.dumps(summary)
    backend = build_auth_custody(material, chain_id=161803, custody_reference="auth:synthetic")
    assert backend.chain_id == 161803


def test_existing_destination_and_wallet_mismatch_refused_without_changes(tmp_path):
    material = provision(tmp_path)
    before = material.keystore_file.read_bytes()
    with pytest.raises(AuthPreparationError):
        provision_existing_auth_material(
            destination=material.directory,
            wallet_private_key=KEY,
            api_key=API_KEY,
            expected_wallet_address=material.wallet_address,
        )
    assert material.keystore_file.read_bytes() == before
    with pytest.raises(AuthPreparationError):
        provision_existing_auth_material(
            destination=tmp_path / "wrong",
            wallet_private_key=KEY,
            api_key=API_KEY,
            expected_wallet_address=Account.from_key("0x" + "22" * 32).address,
        )
    assert not (tmp_path / "wrong").exists()


@pytest.mark.parametrize("api", ["", "x\nsecret", "x\rsecret", " ", "x" * 8193])
def test_invalid_api_key_refused_before_directory_creation(tmp_path, api):
    with pytest.raises(AuthPreparationError):
        provision_existing_auth_material(
            destination=tmp_path / "protected",
            wallet_private_key=KEY,
            api_key=api,
            expected_wallet_address=Account.from_key(KEY).address,
        )
    assert not (tmp_path / "protected").exists()


def test_symlink_parent_refused(tmp_path):
    target = tmp_path / "actual"
    target.mkdir()
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("this host does not permit synthetic directory symlink creation")
    with pytest.raises(AuthPreparationError):
        provision_existing_auth_material(
            destination=alias / "protected",
            wallet_private_key=KEY,
            api_key=API_KEY,
            expected_wallet_address=Account.from_key(KEY).address,
        )
    assert not (target / "protected").exists()


@pytest.mark.asyncio
async def test_one_login_then_same_token_stream_capture(monkeypatch):
    import kairos_execution.auth_orchestration as module

    calls = []
    session = VerifiedWalletSession("synthetic-access", "synthetic-refresh", "synthetic-account")
    reads = object()
    observed = object()

    async def login(**kwargs):
        calls.append(("login", kwargs))
        return session

    class Stream:
        def __init__(self, **kwargs):
            assert kwargs == {"reads": reads, "access_token": session.access_token}
            calls.append(("stream", None))

    async def capture(actual_reads, stream, **kwargs):
        assert actual_reads is reads and isinstance(stream, Stream)
        calls.append(("capture", kwargs))
        return observed

    monkeypatch.setattr(module, "create_evedex_wallet_session", login)
    monkeypatch.setattr(module, "EvedexPrivateWsStream", Stream)
    monkeypatch.setattr(module, "capture_ws_rest_observation", capture)
    result = await authenticate_and_capture_once(
        backend=object(),
        claims=object(),
        reads=reads,
        expected_context=object(),
        expected_wallet_address="synthetic-wallet",
        allow_session_creation=True,
    )
    assert [name for name, _ in calls] == ["login", "stream", "capture"]
    assert result.session is session and result.observation is observed
    assert session.access_token not in repr(result)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["login", "stream", "capture"])
async def test_external_failure_sanitized_no_retry_or_secret_context(monkeypatch, failure):
    import kairos_execution.auth_orchestration as module

    calls = []

    async def login(**kwargs):
        calls.append("login")
        if failure == "login":
            raise RuntimeError("synthetic-private-marker")
        return VerifiedWalletSession("synthetic-private-marker", "synthetic-refresh", "account")

    class Stream:
        def __init__(self, **kwargs):
            calls.append("stream")
            if failure == "stream":
                raise RuntimeError("synthetic-private-marker")

    async def capture(*args, **kwargs):
        calls.append("capture")
        raise RuntimeError("synthetic-private-marker")

    monkeypatch.setattr(module, "create_evedex_wallet_session", login)
    monkeypatch.setattr(module, "EvedexPrivateWsStream", Stream)
    monkeypatch.setattr(module, "capture_ws_rest_observation", capture)
    with pytest.raises(AuthPreparationError) as error:
        await authenticate_and_capture_once(
            backend=object(),
            claims=object(),
            reads=object(),
            expected_context=object(),
            expected_wallet_address="wallet",
            allow_session_creation=True,
        )
    assert "synthetic-private-marker" not in str(error.value)
    assert error.value.__context__ is None
    assert calls.count("login") == 1


@pytest.mark.asyncio
async def test_cancellation_preserved(monkeypatch):
    import kairos_execution.auth_orchestration as module

    async def login(**kwargs):
        raise asyncio.CancelledError

    monkeypatch.setattr(module, "create_evedex_wallet_session", login)
    with pytest.raises(asyncio.CancelledError):
        await authenticate_and_capture_once(
            backend=object(),
            claims=object(),
            reads=object(),
            expected_context=object(),
            expected_wallet_address="wallet",
            allow_session_creation=True,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("timeout", [0, -1, 31, float("inf"), float("nan"), True, "30"])
async def test_bad_observation_budget_refused_before_login(monkeypatch, timeout):
    import kairos_execution.auth_orchestration as module

    async def login(**kwargs):
        pytest.fail("no auth operation is allowed for invalid observation parameters")

    monkeypatch.setattr(module, "create_evedex_wallet_session", login)
    with pytest.raises(AuthPreparationError):
        await authenticate_and_capture_once(
            backend=object(),
            claims=object(),
            reads=object(),
            expected_context=object(),
            expected_wallet_address="wallet",
            allow_session_creation=True,
            observation_timeout_seconds=timeout,
        )


def test_bad_existing_secret_not_retained_in_exception_context(tmp_path):
    with pytest.raises(AuthPreparationError) as error:
        provision_existing_auth_material(
            destination=tmp_path / "protected",
            wallet_private_key="synthetic-secret-marker",
            api_key=API_KEY,
            expected_wallet_address=Account.from_key(KEY).address,
        )
    assert "synthetic-secret-marker" not in str(error.value)
    assert error.value.__context__ is None


def test_cli_reports_confirmed_region_refusal_without_private_details(monkeypatch, capsys):
    import sys

    from kairos_execution import auth_observation_cli as module

    async def login(args):
        raise WalletSessionRegionForbidden()

    monkeypatch.setattr(module, "login_capture", login)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "auth_observation_cli",
            "login-followup-capture",
            "--runtime-dir",
            "synthetic-private-path",
            "--plan-sha256",
            "a" * 64,
            "--acknowledge-prior-unknown",
        ],
    )
    with pytest.raises(SystemExit) as error:
        module.main()
    captured = capsys.readouterr()
    assert error.value.code == 4 and not captured.err
    assert json.loads(captured.out) == {
        "event": "AUTH_REGION_FORBIDDEN",
        "action": "login-followup-capture",
        "code": "FORBIDDEN_REGION",
        "trading_authority": False,
    }


@pytest.mark.asyncio
async def test_confirmed_region_refusal_stops_before_ws(monkeypatch):
    import kairos_execution.auth_orchestration as module

    async def login(**kwargs):
        raise WalletSessionRegionForbidden()

    class Stream:
        def __init__(self, **kwargs):
            pytest.fail("confirmed regional rejection cannot open a WS connection")

    monkeypatch.setattr(module, "create_evedex_wallet_session", login)
    monkeypatch.setattr(module, "EvedexPrivateWsStream", Stream)
    with pytest.raises(WalletSessionRegionForbidden) as error:
        await authenticate_and_capture_once(
            backend=object(),
            claims=object(),
            reads=object(),
            expected_context=object(),
            expected_wallet_address="synthetic-wallet",
            allow_session_creation=True,
        )
    assert error.value.code == "FORBIDDEN_REGION" and error.value.__context__ is None
