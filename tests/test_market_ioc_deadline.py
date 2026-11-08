"""Offline one-use dispatcher-to-SDK deadline checks, including lock delay."""

import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from kairos_execution.production_dispatch import _WIRE_SEAL, _canonical_bytes, _sha256, _WireToken
from kairos_execution.production_transport import ProductionEvedexSdkClient, ProductionTransportError


def test_ipc_capability_is_bound_to_the_original_body_deadline_and_consumed_once():
    path = "/api/v2/order/market"
    digest = _sha256(_canonical_bytes({"id": "fixture"}))
    now = datetime.now(UTC)
    deadline = now + timedelta(seconds=1)
    expiry_ms = (deadline - datetime(1970, 1, 1, tzinfo=UTC)) // timedelta(milliseconds=1)
    token = _WireToken(seal=_WIRE_SEAL, method="POST", path=path, body_sha256=digest, expires_at=deadline)
    with pytest.raises(PermissionError):
        token.consume_ipc(method="POST", path=path, body_sha256=digest, deadline_ms=expiry_ms, now=now)
    token.consume(method="POST", path=path, body_sha256=digest, now=now)
    with pytest.raises(PermissionError):
        token.consume_ipc(method="POST", path=path, body_sha256=digest, deadline_ms=expiry_ms + 1, now=now)
    with pytest.raises(PermissionError):
        token.consume_ipc(method="POST", path=path, body_sha256="f" * 64, deadline_ms=expiry_ms, now=now)
    token.consume_ipc(method="POST", path=path, body_sha256=digest, deadline_ms=expiry_ms, now=now)
    with pytest.raises(PermissionError):
        token.consume_ipc(method="POST", path=path, body_sha256=digest, deadline_ms=expiry_ms, now=now)


@pytest.mark.asyncio
async def test_client_rejects_direct_market_without_dispatch_capability(tmp_path):
    client = ProductionEvedexSdkClient(
        node_executable=tmp_path / "node.exe", api_key_file=tmp_path / "key", expected_account_id="fixture"
    )
    body = {
        "id": "market-1",
        "instrument": "BTCUSD",
        "side": "BUY",
        "timeInForce": "IOC",
        "leverage": 1,
        "cashQuantity": "5",
        "chainId": 42161,
        "signature": "0x" + "12" * 65,
    }
    with pytest.raises(ProductionTransportError, match="wire authorization"):
        await client.send_signed_post(
            method="POST",
            path="/api/v2/order/market",
            body=body,
            expires_at=datetime.now(UTC) + timedelta(seconds=1),
        )


@pytest.mark.asyncio
async def test_expired_after_waiting_for_client_lock_never_writes_ipc(tmp_path):
    client = ProductionEvedexSdkClient(
        node_executable=tmp_path / "node.exe", api_key_file=tmp_path / "key", expected_account_id="fixture"
    )
    written = []
    client._preflight_complete = True
    client._process = SimpleNamespace(
        returncode=None,
        stdin=SimpleNamespace(write=lambda data: written.append(data)),
        stdout=SimpleNamespace(),
    )
    path = "/api/v2/order/market"
    body = {"id": "fixture"}
    deadline = datetime.now(UTC) + timedelta(milliseconds=100)
    token = _WireToken(
        seal=_WIRE_SEAL,
        method="POST",
        path=path,
        body_sha256=_sha256(_canonical_bytes(body)),
        expires_at=deadline,
    )
    token.consume(
        method="POST", path=path, body_sha256=_sha256(_canonical_bytes(body)), now=datetime.now(UTC)
    )
    payload = {
        "method": "POST",
        "path": path,
        "body": body,
        "deadline_ms": (deadline - datetime(1970, 1, 1, tzinfo=UTC)) // timedelta(milliseconds=1),
    }
    await client._lock.acquire()
    queued = asyncio.create_task(client._call("send_signed_post", payload, mutation=True, wire_token=token))
    await asyncio.sleep(0.15)
    client._lock.release()
    with pytest.raises(PermissionError, match="IPC authorization"):
        await queued
    assert not written
