"""Offline PROD transport contract tests; never construct a network client."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from decimal import Decimal
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
    parse_raw_response_capture,
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

    async def fetch_raw_capture(self, payload):
        self.calls.append(("raw_capture", payload))
        source = payload["source"]
        path = {
            "account_identity": "/api/user/me",
            "funding": "/api/user/funding",
            "order_page": "/api/order",
            "tpsl_page": "/api/tpsl",
        }[source]
        query = {
            ("next" if key == "next_cursor" else key): str(value)
            for key, value in payload.items()
            if key != "source"
        }
        if source == "order_page":
            query["withTpSL"] = ""
        raw = b'{"quantity":1.2300,"large":123456789012345678901234567890}'
        return {
            "source": source,
            "path": path,
            "query_json": json.dumps(query, sort_keys=True, separators=(",", ":")),
            "status": 200,
            "requested_at": "2026-10-25T10:00:00.000Z",
            "received_at": "2026-10-25T10:00:00.010Z",
            "body_bytes": len(raw),
            "body_sha256": hashlib.sha256(raw).hexdigest(),
            "body_base64": base64.b64encode(raw).decode("ascii"),
        }


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
async def test_raw_capture_is_fixed_read_only_and_lossless_without_authority_promotion():
    client = FakeClient()
    transport = ProductionEvedexTransport(context=CONTEXT, custody_binding=BINDING, client=client)
    await transport.preflight()
    capture = await transport.fetch_raw_capture(
        "order_page", version=2, limit=50, offset=100, next_cursor="cursor-1"
    )
    parsed = parse_raw_response_capture(
        capture,
        source="order_page",
        expected_query={"version": 2, "limit": 50, "offset": 100, "next": "cursor-1", "withTpSL": ""},
    )
    assert parsed["quantity"] == Decimal("1.2300")
    assert parsed["large"] == Decimal("123456789012345678901234567890")
    assert client.calls[-1] == (
        "raw_capture",
        {
            "source": "order_page",
            "version": 2,
            "limit": 50,
            "offset": 100,
            "next_cursor": "cursor-1",
        },
    )
    with pytest.raises(ProductionTransportError, match="fixed account/history allowlist"):
        await transport.fetch_raw_capture("arbitrary", limit=10, offset=0)
    with pytest.raises(ProductionTransportError, match="fixed read contract"):
        await transport.fetch_raw_capture("order_page", version=2, limit=True, offset=0)
    assert len(client.calls) == 2  # preflight and the sole bounded capture

    failed_client = FakeClient()
    original_capture = failed_client.fetch_raw_capture

    async def failed_http_capture(payload):
        capture = await original_capture(payload)
        capture["status"] = 503
        return capture

    failed_client.fetch_raw_capture = failed_http_capture
    failed_transport = ProductionEvedexTransport(
        context=CONTEXT, custody_binding=BINDING, client=failed_client
    )
    await failed_transport.preflight()
    with pytest.raises(ProductionTransportError, match="status is not successful"):
        await failed_transport.fetch_raw_capture("funding")


def test_raw_capture_rejects_tampering_oversize_and_non_json_bodies():
    raw = b'{"n":1.2000}'
    capture = {
        "source": "funding",
        "path": "/api/user/funding",
        "query_json": "{}",
        "status": 200,
        "requested_at": "2026-10-25T10:00:00.000Z",
        "received_at": "2026-10-25T10:00:00.001Z",
        "body_bytes": len(raw),
        "body_sha256": hashlib.sha256(raw).hexdigest(),
        "body_base64": base64.b64encode(raw).decode("ascii"),
    }
    assert parse_raw_response_capture(capture, source="funding", expected_query={})["n"] == Decimal("1.2000")
    tampered = {**capture, "body_base64": base64.b64encode(b'{"n":2}').decode("ascii")}
    with pytest.raises(ProductionTransportError, match="digest or length"):
        parse_raw_response_capture(tampered, source="funding", expected_query={})
    duplicate_query = {**capture, "query_json": '{"unexpected":"1","unexpected":"2"}'}
    with pytest.raises(ProductionTransportError, match="query is malformed"):
        parse_raw_response_capture(duplicate_query, source="funding", expected_query={})
    with pytest.raises(ProductionTransportError, match="fixed read contract"):
        parse_raw_response_capture(
            capture,
            source="order_page",
            expected_query={"version": 2, "limit": 1, "offset": 0, "extra": "unexpected"},
        )
    oversized = {**capture, "body_bytes": 2 * 1024 * 1024 + 1}
    with pytest.raises(ProductionTransportError, match="byte bound"):
        parse_raw_response_capture(oversized, source="funding", expected_query={})
    malformed = {
        **capture,
        "body_base64": base64.b64encode(b"not-json").decode("ascii"),
        "body_bytes": 8,
        "body_sha256": hashlib.sha256(b"not-json").hexdigest(),
    }
    with pytest.raises(ProductionTransportError, match="JSON body"):
        parse_raw_response_capture(malformed, source="funding", expected_query={})


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
async def test_transport_rejects_unsupported_limit_ioc_but_keeps_market_ioc():
    client = FakeClient()
    transport = ProductionEvedexTransport(context=CONTEXT, custody_binding=BINDING, client=client)
    await transport.preflight()
    market = {
        "id": "market-1",
        "instrument": "BTCUSD",
        "side": "BUY",
        "timeInForce": "IOC",
        "leverage": 1,
        "cashQuantity": "5",
        "chainId": 42161,
        "signature": "0x" + "12" * 65,
    }
    await transport.send_signed_post(method="POST", path="/api/v2/order/market", body=market)
    assert client.calls[-1][0] == "signed"
    calls_before_limit = len(client.calls)
    limit = {
        "id": "limit-1",
        "instrument": "BTCUSD",
        "side": "BUY",
        "leverage": 1,
        "quantity": "0.25",
        "limitPrice": "60000",
        "chainId": 42161,
        "timeInForce": "IOC",
        "signature": "0x" + "12" * 65,
    }
    with pytest.raises(ProductionTransportError, match="limit orders are GTC.*IOC limit.*unsupported"):
        await transport.send_signed_post(method="POST", path="/api/v2/order/limit", body=limit)
    assert len(client.calls) == calls_before_limit


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
    node.chmod(0o700)
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
