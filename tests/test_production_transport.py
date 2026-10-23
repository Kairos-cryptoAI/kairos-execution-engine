"""Offline PROD transport contract tests; never construct a network client."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from kairos_execution.managed_signer import CustodyBindingV1, reviewed_schema_sha256
from kairos_execution.production_readiness import ProductionContextV1
from kairos_execution.production_transport import (
    MAX_IPC_RESPONSE_BYTES,
    ProductionEvedexSdkClient,
    ProductionEvedexTransport,
    ProductionTransportError,
)
from tests.test_production_runtime import runtime_fixture
from tests.test_signing_authorization import fixture as signing_fixture

CONTEXT = ProductionContextV1(
    remote_account_id="acct-prod-1",
    adaptive_system_id="adaptive-v1",
    frozen_policy_sha256="a" * 64,
    source_set_sha256="b" * 64,
)
BINDING = CustodyBindingV1(
    context=CONTEXT,
    custody_reference="prod-custody-1",
    wallet_address="0x" + "12" * 20,
    chain_id=42161,
    schema_sha256=reviewed_schema_sha256(42161),
    approved_instruments=("BTCUSD", "ETHUSD", "SOLUSD", "BNBUSD", "XRPUSD"),
    custody_receipt_sha256="c" * 64,
)


class FakeClient:
    def __init__(self, *, expected_account_id="acct-prod-1", identity=None):
        self.expected_account_id = expected_account_id
        self.identity = identity or {"exchangeId": expected_account_id, "opaque": "raw"}
        self.calls = []

    async def preflight(self):
        self.calls.append(("preflight",))
        return self.identity

    async def send_signed_post(self, **kwargs):
        self.calls.append(("signed", kwargs))
        return {"id": kwargs["body"].get("id", "tpsl"), "status": "NEW"}

    async def cancel_order(self, **kwargs):
        self.calls.append(("cancel_order", kwargs))
        return {"id": kwargs["order_id"], "status": "CANCELED"}

    async def cancel_tpsl(self, **kwargs):
        self.calls.append(("cancel_tpsl", kwargs))
        return {"id": kwargs["protection_id"], "status": "CANCELED"}

    async def fetch_account_identity(self):
        self.calls.append(("identity",))
        return self.identity

    async def fetch_order_history_page(self, **kwargs):
        self.calls.append(("orders", kwargs))
        return {"count": 1, "list": [{"price": "1.2300"}]}

    async def fetch_tpsl_page(self, **kwargs):
        self.calls.append(("tpsl", kwargs))
        return {"count": 0, "list": []}

    async def fetch_funding(self):
        self.calls.append(("funding",))
        return {"list": [{"balance": "2.5000"}]}


def _signed_tpsl():
    return {
        "instrument": "BTCUSD",
        "type": "stop-loss",
        "side": "BUY",
        "quantity": "0.125",
        "price": "60123.45006789",
        "order": "entry-order-1",
        "signature": "0x" + "12" * 65,
    }


@pytest.mark.asyncio
async def test_preflight_binds_exact_exchange_id_and_enables_typed_sdk_surface_only():
    client = FakeClient()
    transport = ProductionEvedexTransport(context=CONTEXT, custody_binding=BINDING, client=client)
    identity = await transport.preflight()
    assert identity["exchangeId"] == CONTEXT.remote_account_id
    assert await transport.fetch_account_identity() == identity
    order_page = await transport.fetch_order_history_page(
        version=2, limit=100, offset=0, next_cursor="cursor-1"
    )
    assert order_page["list"][0]["price"] == "1.2300"
    assert await transport.fetch_tpsl_page(limit=100, offset=0) == {"count": 0, "list": []}
    assert await transport.fetch_funding() == {"list": [{"balance": "2.5000"}]}
    assert client.calls == [
        ("preflight",),
        ("identity",),
        ("orders", {"version": 2, "limit": 100, "offset": 0, "next_cursor": "cursor-1"}),
        ("tpsl", {"limit": 100, "offset": 0}),
        ("funding",),
    ]


@pytest.mark.asyncio
async def test_mutation_requires_preflight_and_signed_body_is_immutable_exact_decimal_payload():
    client = FakeClient()
    transport = ProductionEvedexTransport(context=CONTEXT, custody_binding=BINDING, client=client)
    original = _signed_tpsl()
    with pytest.raises(ProductionTransportError, match="explicit.*preflight"):
        await transport.send_signed_post(method="POST", path="/api/tpsl/BTCUSD", body=original)
    await transport.preflight()
    result = await transport.send_signed_post(method="POST", path="/api/tpsl/BTCUSD", body=original)
    assert result["status"] == "NEW"
    sent = client.calls[-1][1]["body"]
    assert sent == original
    assert sent is not original
    assert sent["price"] == "60123.45006789"
    assert "chainId" not in sent  # pinned TP/SL EIP schema has no message chainId field


@pytest.mark.asyncio
async def test_transport_refuses_account_context_mismatch_and_chain_mismatch():
    with pytest.raises(ValueError, match="exactly match"):
        ProductionEvedexTransport(
            context=CONTEXT,
            custody_binding=BINDING,
            client=FakeClient(expected_account_id="other"),
        )
    wrong_identity = ProductionEvedexTransport(
        context=CONTEXT,
        custody_binding=BINDING,
        client=FakeClient(identity={"exchangeId": "other"}),
    )
    with pytest.raises(ProductionTransportError, match="differs from the bound"):
        await wrong_identity.preflight()
    old_chain_binding = CustodyBindingV1(
        **{
            **BINDING.model_dump(),
            "chain_id": 161803,
            "schema_sha256": reviewed_schema_sha256(161803),
        }
    )
    with pytest.raises(ValueError, match="SDK-pinned.*42161"):
        ProductionEvedexTransport(context=CONTEXT, custody_binding=old_chain_binding, client=FakeClient())
    transport = ProductionEvedexTransport(context=CONTEXT, custody_binding=BINDING, client=FakeClient())
    await transport.preflight()
    body = {
        "id": "entry-1",
        "instrument": "BTCUSD",
        "side": "BUY",
        "leverage": 1,
        "quantity": "1",
        "limitPrice": "2",
        "chainId": 161803,
        "timeInForce": "IOC",
        "signature": "0x" + "12" * 65,
    }
    with pytest.raises(ProductionTransportError, match="chain.*42161"):
        await transport.send_signed_post(method="POST", path="/api/v2/order/limit", body=body)
    wrong_runtime_binding = CustodyBindingV1(**{**BINDING.model_dump(), "custody_receipt_sha256": "d" * 64})
    with pytest.raises(ProductionTransportError, match="runtime signing binding differs"):
        transport.require_runtime_binding(wrong_runtime_binding)


@pytest.mark.asyncio
async def test_sdk_process_is_latched_after_unknown_transport_outcome():
    client = ProductionEvedexSdkClient(
        node_executable=Path(__file__).resolve().parent / "not-installed/node.exe",
        api_key_file=Path(__file__).resolve().parent / "not-installed/prod-api-key.txt",
        expected_account_id=CONTEXT.remote_account_id,
    )

    class Process:
        returncode = None

        async def wait(self):
            self.returncode = -9

        def kill(self):
            pass

    process = Process()
    client._process = process
    await client._abort(process)
    with pytest.raises(ProductionTransportError, match="latched"):
        await client.start()


def test_deployment_constructor_binds_profile_without_starting_process_or_reading_keys():
    transport = ProductionEvedexTransport.from_deployment(
        context=CONTEXT,
        custody_binding=BINDING,
        node_executable=Path(__file__).resolve().parent / "not-installed/node.exe",
        api_key_file=Path(__file__).resolve().parent / "not-installed/prod-api-key.txt",
    )
    assert isinstance(transport.client, ProductionEvedexSdkClient)
    assert transport.client.expected_account_id == CONTEXT.remote_account_id
    assert transport.client._process is None


def test_runtime_refuses_transport_when_actual_signer_binding_uses_legacy_chain():
    _, request, legacy_binding, _, _ = signing_fixture()
    transport_binding = legacy_binding.model_copy(
        update={"chain_id": 42161, "schema_sha256": reviewed_schema_sha256(42161)}
    )
    transport = ProductionEvedexTransport(
        context=request.context,
        custody_binding=transport_binding,
        client=FakeClient(expected_account_id=request.context.remote_account_id),
    )
    with pytest.raises(ProductionTransportError, match="runtime signing binding differs"):
        runtime_fixture(sender=transport.send_signed_post)


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf"), 31])
def test_unbounded_timeout_refuses_before_process_or_secret_access(timeout):
    with pytest.raises(ValueError, match="finite"):
        ProductionEvedexSdkClient(
            node_executable=Path(__file__).resolve().parent / "not-installed/node.exe",
            api_key_file=Path(__file__).resolve().parent / "not-installed/prod-api-key.txt",
            expected_account_id=CONTEXT.remote_account_id,
            timeout_s=timeout,
        )


@pytest.mark.asyncio
async def test_version_probe_cancellation_reaps_only_owned_probe_without_reading_api_key(
    tmp_path, monkeypatch
):
    node = tmp_path / "node.exe"
    node.write_bytes(b"test-fixture-not-executed")
    client = ProductionEvedexSdkClient(
        node_executable=node,
        api_key_file=tmp_path / "missing-api-key",
        expected_account_id=CONTEXT.remote_account_id,
    )
    probe = SimpleNamespace(returncode=None, kill=lambda: None, wait=AsyncMock(return_value=0))
    entered = asyncio.Event()

    async def communicate():
        entered.set()
        await asyncio.Event().wait()

    probe.communicate = communicate
    monkeypatch.setattr(asyncio, "create_subprocess_exec", AsyncMock(return_value=probe))
    task = asyncio.create_task(client.start())
    await asyncio.wait_for(entered.wait(), timeout=2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    probe.wait.assert_awaited_once()
    assert client._process is None
    assert not client.api_key_file.exists()


@pytest.mark.asyncio
async def test_broken_ipc_write_latches_mutation_without_resend():
    client = ProductionEvedexSdkClient(
        node_executable=Path(__file__).resolve().parent / "not-installed/node.exe",
        api_key_file=Path(__file__).resolve().parent / "not-installed/prod-api-key.txt",
        expected_account_id=CONTEXT.remote_account_id,
    )

    class BrokenInput:
        def write(self, _):
            raise BrokenPipeError("synthetic error not exposed")

    process = SimpleNamespace(
        returncode=None,
        stdin=BrokenInput(),
        stdout=object(),
        kill=lambda: None,
        wait=AsyncMock(return_value=0),
    )
    client._process = process
    client._preflight_complete = True
    with pytest.raises(ProductionTransportError, match="outcome may be unresolved"):
        await client._call("send_signed_post", {}, mutation=True)
    assert client._process is None and client._failed
    with pytest.raises(ProductionTransportError, match="latched"):
        await client._call("send_signed_post", {}, mutation=True)


@pytest.mark.asyncio
async def test_python_ipc_reader_accepts_bounded_multimegabyte_result():
    client = ProductionEvedexSdkClient(
        node_executable=Path(__file__).resolve().parent / "not-installed/node.exe",
        api_key_file=Path(__file__).resolve().parent / "not-installed/prod-api-key.txt",
        expected_account_id=CONTEXT.remote_account_id,
    )
    stdout = asyncio.StreamReader(limit=MAX_IPC_RESPONSE_BYTES + 1)

    class Input:
        def write(self, request_line):
            request = json.loads(request_line)
            response = {
                "id": request["id"],
                "ok": True,
                "result": {"payload": "x" * (2 * 1024 * 1024)},
            }
            stdout.feed_data(json.dumps(response).encode("utf-8") + b"\n")
            stdout.feed_eof()

        async def drain(self):
            return None

    process = SimpleNamespace(returncode=None, stdin=Input(), stdout=stdout)
    client._process = process
    client._preflight_complete = True
    result = await client._call("fetch_funding", {}, mutation=False)
    assert len(result["payload"]) == 2 * 1024 * 1024


@pytest.mark.asyncio
async def test_oversized_sidecar_mutation_response_latches_unknown_outcome():
    client = ProductionEvedexSdkClient(
        node_executable=Path(__file__).resolve().parent / "not-installed/node.exe",
        api_key_file=Path(__file__).resolve().parent / "not-installed/prod-api-key.txt",
        expected_account_id=CONTEXT.remote_account_id,
    )
    stdout = asyncio.StreamReader(limit=MAX_IPC_RESPONSE_BYTES + 1)

    class Input:
        def write(self, request_line):
            request = json.loads(request_line)
            refusal = {
                "code": "RESPONSE_TOO_LARGE",
                "message": (
                    "EVEDEX SDK response exceeded the IPC limit; "
                    "mutation outcome may be unresolved. Reconcile before retry."
                ),
            }
            stdout.feed_data(
                json.dumps({"id": request["id"], "ok": False, "error": refusal}).encode("utf-8") + b"\n"
            )
            stdout.feed_eof()

        async def drain(self):
            return None

    class Process:
        returncode = None

        async def wait(self):
            self.returncode = -9

        def kill(self):
            self.returncode = -9

    process = Process()
    process.stdin = Input()
    process.stdout = stdout
    client._process = process
    client._preflight_complete = True
    with pytest.raises(ProductionTransportError, match="mutation failed"):
        await client._call("send_signed_post", {}, mutation=True)
    assert client._failed and client._process is None
