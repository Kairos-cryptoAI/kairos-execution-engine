"""Offline wire-body tests for the real PROD reader; never start a sidecar."""

import base64
import hashlib
import json
from decimal import Decimal
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from kairos_execution.production_reads import ProductionEvedexReads, ProductionReadUnavailable
from kairos_execution.production_transport import ProductionEvedexSdkClient, ProductionTransportError

ORDER_ID = "00001:" + "a" * 26
AFTER = "2026-10-27T00:00:00.000Z"
BEFORE = "2026-10-27T01:00:00.000Z"


def fixture(*, bodies=None):
    client = ProductionEvedexSdkClient(
        node_executable=Path("D:/offline/node.exe"),
        api_key_file=Path("D:/offline/not-read.key"),
        expected_account_id="acct-prod-1",
    )
    defaults = {
        "account_identity": b'{"exchangeId":"acct-prod-1","marginCall":false}',
        "available_balance": (
            b'{"funding":{"currency":"USDT","balance":123456789012345678.123400},'
            b'"availableBalance":1.23400,"position":[],"openOrder":[], '
            b'"updatedAt":"2026-10-27T01:00:00Z"}'
        ),
        "positions": b'{"list":[]}',
        "open_orders": b"[]",
        "instruments": (
            b'[{"name":"BTCUSD","quantityIncrement":0.000000000000000001,"updatedAt":"2020-01-01T00:00:00Z"}]'
        ),
        "order_page": b'{"count":0,"list":[]}',
        "tpsl_page": b'{"count":0,"list":[]}',
        "depth": b'{"t":1793062800123,"asks":[{"price":1.234567890123456789,"quantity":2.5000}],"bids":[]}',
        "order_fills": (
            b'[{"id":"fill-1","fillQuantity":0.000000000000000001,"fillPrice":123456789.123456789,'
            b'"fee":[{"coin":"usdt","quantity":0.000000000000000003}],"createdAt":"2026-10-27T00:00:03.123Z"}]'
        ),
        "funding_transfers": (
            b'{"count":1,"list":[{"type":"fundingRate","coin":"usdt","quantity":-0.000000000000000001,'
            b'"createdAt":"2026-10-27T00:00:03.123Z"}]}'
        ),
        "fill_history": (
            b'{"count":1,"list":[{"id":"fill-1","order":"native-order","instrument":"BTCUSD",'
            b'"fillQuantity":1.2300,"fillPrice":123456789.123456789,"fillRole":"MAKER",'
            b'"matchId":"native-match","createdAt":"2026-10-27T00:00:03.123Z"}]}'
        ),
    }
    defaults.update(bodies or {})
    calls = []

    async def capture(payload):
        calls.append(dict(payload))
        source = payload["source"]
        paths = {
            "account_identity": "/api/user/me",
            "available_balance": "/api/market/available-balance",
            "positions": "/api/position",
            "open_orders": "/api/order/opened",
            "instruments": "/api/market/instrument",
            "order_page": "/api/order",
            "tpsl_page": "/api/tpsl",
            "depth": f"/api/market/{payload.get('instrument')}/deep",
            "order_fills": f"/api/order/{payload.get('order_id')}/fill",
            "funding_transfers": "/api/user/funding-transfer",
            "fill_history": "/api/fill",
        }
        query = {key: str(value) for key, value in payload.items() if key != "source"}
        if source == "instruments":
            query = {"fields": "metrics"}
        if source == "depth":
            query = {"maxLevel": str(payload["max_level"])}
        if source == "order_fills":
            query = {"version": "2"}
        if "transfer_type" in query:
            query["type"] = query.pop("transfer_type")
        if source == "order_page":
            query["withTpSL"] = ""
            if "next_cursor" in query:
                query["next"] = query.pop("next_cursor")
        body = defaults[source]
        return {
            "source": source,
            "path": paths[source],
            "query_json": json.dumps(query),
            "status": 200,
            "requested_at": "2026-10-27T01:00:00.000Z",
            "received_at": "2026-10-27T01:00:00.010Z",
            "body_bytes": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "body_base64": base64.b64encode(body).decode(),
        }

    client.preflight = AsyncMock(return_value={"exchangeId": "acct-prod-1"})
    client.fetch_raw_capture = AsyncMock(side_effect=capture)
    client.read_health = AsyncMock(
        return_value={
            "ok": True,
            "profile": "PROD",
            "chain_id": 42161,
            "sdk_version": "1.2.11",
            "account_id": "acct-prod-1",
            "exchange_url": "https://trading-api.evedex.com",
            "auth_url": "https://auth-api.evedex.com",
            "auth_age_ms": 10,
            "auth_expires_in_ms": None,
            "local_mutation_rate_limit_observable": True,
            "local_mutation_rate_limit_capacity": 30,
            "local_mutation_rate_limit_reserve": 30,
            "local_mutation_rate_limit_window_ms": 60_000,
            "local_mutation_compensation_reserve": 4,
            "local_mutation_entry_min_reserve": 7,
            "venue_rate_limit_observable": False,
            "venue_rate_limit_reserve": None,
        }
    )
    return ProductionEvedexReads(client, symbol_map={"BTCUSDT": "BTCUSD"}), calls


@pytest.mark.asyncio
async def test_preflight_exposes_native_captures_and_explicit_capability_gaps():
    reads, _ = fixture()
    with pytest.raises(ProductionReadUnavailable, match="preflight"):
        await reads.fetch_paper_state()
    health = await reads.preflight()
    assert health["profile"] == "PROD" and health["chain_id"] == 42161
    assert health["instrument_capture"]["received_at"] == "2026-10-27T01:00:00.010Z"
    assert health["live_ready"] is False
    assert health["account_revision_authoritative"] is False
    assert health["recoverable_events_available"] is False
    assert health["local_mutation_rate_limit_observable"] is True
    assert health["local_mutation_rate_limit_reserve"] == 30
    assert health["auth_age_ms"] == 10 and health["auth_expires_in_ms"] is None
    assert health["exchange_url"] == "https://trading-api.evedex.com"
    with pytest.raises(ProductionReadUnavailable, match="recoverable"):
        await reads.drain_events()


@pytest.mark.asyncio
async def test_state_keeps_original_decimals_clocks_and_original_body_without_invented_fills():
    reads, calls = fixture()
    await reads.preflight()
    state = await reads.fetch_paper_state()
    assert state["balance"]["funding"]["balance"] == "123456789012345678.123400"
    assert state["balance"]["funding"]["currency"] == "USDT"
    assert Decimal(state["balance"]["availableBalance"]).as_tuple().exponent == -5
    assert state["balance"]["positions"] == [] and state["balance"]["openOrders"] == []
    assert state["instruments"][0]["updatedAt"] == "2020-01-01T00:00:00Z"
    assert state["positions"] == [] and state["orders"] == []
    assert "fills" not in state
    assert len(state["native_read_captures"]["order_pages"]) == 1
    assert calls[-1] == {"source": "order_page", "version": 2, "limit": 100, "offset": 0}
    assert state["account_revision_authoritative"] is False


@pytest.mark.asyncio
async def test_depth_keeps_exact_native_timestamp_and_no_decimal_roundtrip():
    reads, calls = fixture()
    await reads.preflight()
    depth = await reads.fetch_depth(symbol="BTCUSDT", max_level=20)
    assert type(depth["t"]) is int and depth["t"] == 1793062800123
    assert depth["asks"][0]["price"] == Decimal("1.234567890123456789")
    assert calls[-1] == {"source": "depth", "instrument": "BTCUSD", "max_level": 20}
    with pytest.raises(ProductionTransportError):
        await reads.fetch_depth(symbol="BTCUSDT", max_level=True)
    with pytest.raises(ProductionReadUnavailable):
        await reads.fetch_depth(symbol="ETHUSDT")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "source,body",
    [
        ("positions", b"{}"),
        ("open_orders", b"{}"),
        ("available_balance", b'{"funding":{},"availableBalance":0}'),
        ("available_balance", b'{"funding":{"balance":null},"availableBalance":0}'),
        ("order_page", b'{"count":1,"list":[]}'),
        ("tpsl_page", b'{"count":0,"list":[{"id":"extra"}]}'),
        ("tpsl_page", b'{"count":0,"list":[],"next":"cannot-be-terminal"}'),
    ],
)
async def test_missing_or_incomplete_native_state_is_never_fabricated_empty(source, body):
    reads, _ = fixture(bodies={source: body})
    await reads.preflight()
    with pytest.raises(ProductionReadUnavailable):
        await reads.fetch_paper_state()


@pytest.mark.asyncio
async def test_protection_parent_lineage_is_not_inferred_from_trigger_order():
    reads, _ = fixture(
        bodies={
            "tpsl_page": (
                b'{"count":1,"list":[{"id":"stop","instrument":"BTCUSD","type":"stop-loss",'
                b'"price":"1.2500","triggerOrder":"entry"}]}'
            )
        }
    )
    await reads.preflight()
    assert (await reads.find_tpsl_record(symbol="BTCUSDT", tpsl_id="stop", price=Decimal("1.25")))[
        "id"
    ] == "stop"
    assert (
        await reads.find_tpsl_record(symbol="BTCUSDT", tpsl_id="stop", price=Decimal("1.2500000001")) is None
    )
    with pytest.raises(ProductionReadUnavailable, match="parent-entry"):
        await reads.find_tpsl_record(symbol="BTCUSDT", parent_order_id="entry")


@pytest.mark.asyncio
async def test_mismatch_preflight_disables_reads():
    reads, _ = fixture(bodies={"account_identity": b'{"exchangeId":"other"}'})
    with pytest.raises(ProductionReadUnavailable, match="identity"):
        await reads.preflight()
    with pytest.raises(ProductionReadUnavailable, match="preflight"):
        await reads.fetch_paper_state()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body",
    [
        b'{"t":1.5,"asks":[],"bids":[]}',
        b'{"t":1e100000,"asks":[],"bids":[]}',
        b'{"t":1000,"asks":[{"price":1}],"bids":[]}',
        b'{"t":1000,"asks":[{"price":0,"quantity":1}],"bids":[]}',
        b'{"t":1000,"asks":null,"bids":[]}',
    ],
)
async def test_native_depth_missing_fields_and_invalid_clocks_fail_closed(body):
    reads, _ = fixture(bodies={"depth": body})
    await reads.preflight()
    with pytest.raises(ProductionReadUnavailable):
        await reads.fetch_depth(symbol="BTCUSDT")


@pytest.mark.asyncio
async def test_prod_client_rejects_read_route_substitution_before_ipc():
    reads, _ = fixture()
    client = reads.client
    client._call = AsyncMock()
    with pytest.raises(ProductionTransportError):
        await ProductionEvedexSdkClient.fetch_raw_capture(
            client,
            {
                "source": "depth",
                "instrument": "BTCUSD",
                "max_level": 10,
                "path": "https://dev.evedex.com",
            },
        )
    with pytest.raises(ProductionTransportError):
        await ProductionEvedexSdkClient.fetch_raw_capture(
            client,
            {
                "source": "instruments",
                "fields": "other",
            },
        )
    client._call.assert_not_called()


@pytest.mark.asyncio
async def test_documented_order_fills_preserve_native_fields_raw_body_and_no_finality():
    from kairos_execution.production_transport import PROD_HISTORY_OPENAPI_SOURCE

    assert PROD_HISTORY_OPENAPI_SOURCE == "https://exchange-api.evedex.com/api/openapi.json"
    reads, calls = fixture()
    await reads.preflight()
    rows = await reads.fetch_order_fills(order_id=ORDER_ID)
    assert rows[0]["fillQuantity"] == Decimal("0.000000000000000001")
    assert rows[0]["fillPrice"] == Decimal("123456789.123456789")
    assert rows[0]["fee"][0]["quantity"] == Decimal("0.000000000000000003")
    assert rows[0]["createdAt"] == "2026-10-27T00:00:03.123Z"
    assert "orderId" not in rows[0] and "settled" not in rows[0]
    assert calls[-1] == {"source": "order_fills", "order_id": ORDER_ID}
    assert reads.last_captures["order_fills"]["path"] == f"/api/order/{ORDER_ID}/fill"


@pytest.mark.asyncio
async def test_history_pages_keep_native_rows_and_do_not_add_provider_ids_or_query_automatically():
    reads, calls = fixture()
    await reads.preflight()
    assert not any(call["source"] in {"fill_history", "funding_transfers"} for call in calls)
    page = await reads.fetch_funding_transfers(after=AFTER, before=BEFORE, transfer_type="fundingRate")
    assert page["list"][0]["quantity"] == Decimal("-0.000000000000000001")
    assert set(page["list"][0]) == {"type", "coin", "quantity", "createdAt"}
    assert calls[-1] == {
        "source": "funding_transfers",
        "after": AFTER,
        "before": BEFORE,
        "transfer_type": "fundingRate",
        "limit": 100,
        "offset": 0,
    }
    fill_page = await reads.fetch_fill_history(after=AFTER, before=BEFORE, symbol="BTCUSDT", limit=10)
    assert fill_page["list"][0]["order"] == "native-order"
    assert fill_page["list"][0]["fillQuantity"].as_tuple().exponent == -4
    assert calls[-1]["instrument"] == "BTCUSD"
    assert reads.last_captures["fill_history"]["requested_at"] == "2026-10-27T01:00:00.000Z"
    with pytest.raises(ProductionReadUnavailable, match="recoverable"):
        await reads.drain_events()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kwargs",
    [
        {"after": "2026-10-27T00:00:00+00:00"},
        {"before": AFTER},
        {"before": "2026-10-29T01:00:00.000Z"},
        {"after": "2026-02-30T00:00:00.000Z"},
        {"limit": True},
        {"limit": 101},
        {"offset": -1},
        {"transfer_type": "madeUp"},
    ],
)
async def test_funding_query_rejects_unbounded_invalid_or_guessed_params_before_ipc(kwargs):
    reads, calls = fixture()
    await reads.preflight()
    before_count = len(calls)
    with pytest.raises(ProductionTransportError):
        await reads.fetch_funding_transfers(**{"after": AFTER, "before": BEFORE, **kwargs})
    assert len(calls) == before_count


@pytest.mark.asyncio
async def test_native_fill_duplicates_rejected_but_identical_no_id_funding_rows_preserved():
    fill = b'{"id":"same","fillQuantity":1,"fillPrice":1,"fee":[],"createdAt":"2026-10-27T00:00:00Z"}'
    funding = b'{"type":"fundingRate","coin":"usdt","quantity":-1,"createdAt":"2026-10-27T00:00:00Z"}'
    reads, _ = fixture(
        bodies={
            "order_fills": b"[" + fill + b"," + fill + b"]",
            "funding_transfers": b'{"count":2,"list":[' + funding + b"," + funding + b"]}",
        }
    )
    await reads.preflight()
    with pytest.raises(ProductionReadUnavailable, match="duplicated"):
        await reads.fetch_order_fills(order_id=ORDER_ID)
    rows = (await reads.fetch_funding_transfers(after=AFTER, before=BEFORE))["list"]
    assert len(rows) == 2 and rows[0] == rows[1] and "id" not in rows[0]


@pytest.mark.asyncio
async def test_prod_client_health_checks_enforced_budget_and_original_authentication_capture():
    reads, _ = fixture()
    client = reads.client
    health = await client.read_health()
    health["preflight_capture"] = await client.fetch_raw_capture({"source": "account_identity"})
    client._call = AsyncMock(return_value=health)
    actual = await ProductionEvedexSdkClient.read_health(client)
    assert actual["local_mutation_rate_limit_reserve"] == 30
    assert actual["auth_expires_in_ms"] is None and actual["venue_rate_limit_reserve"] is None
    client._call.assert_awaited_once_with("read_health", {}, mutation=False)
    for change in (
        {"local_mutation_rate_limit_reserve": 31},
        {"local_mutation_rate_limit_reserve": -1},
        {"local_mutation_rate_limit_reserve": True},
        {"local_mutation_rate_limit_capacity": 31},
        {"local_mutation_entry_min_reserve": 4},
        {"auth_age_ms": -1},
        {"auth_age_ms": 0.5},
        {"profile": "DEV"},
        {"exchange_url": "https://trading-api.evedex.tech"},
        {"local_mutation_rate_limit_observable": 1},
        {"venue_rate_limit_observable": True},
        {"auth_expires_in_ms": 60_000},
        {"preflight_capture": None},
        {"preflight_capture": {**health["preflight_capture"], "status": 401}},
        {"preflight_capture": {**health["preflight_capture"], "body_sha256": "0" * 64}},
    ):
        client._call = AsyncMock(return_value={**health, **change})
        with pytest.raises(ProductionTransportError):
            await ProductionEvedexSdkClient.read_health(client)
    missing_expiry = {key: value for key, value in health.items() if key != "auth_expires_in_ms"}
    client._call = AsyncMock(return_value=missing_expiry)
    with pytest.raises(ProductionTransportError):
        await ProductionEvedexSdkClient.read_health(client)


@pytest.mark.asyncio
async def test_prod_client_read_health_requires_explicit_preflight_before_process_or_credentials():
    reads, _ = fixture()
    client = reads.client
    with pytest.raises(ProductionTransportError, match="preflight"):
        await ProductionEvedexSdkClient.read_health(client)
    assert client._process is None


@pytest.mark.asyncio
async def test_reader_does_not_admit_failed_budget_health_as_successful_preflight():
    reads, _ = fixture()
    reads.client.read_health = AsyncMock(side_effect=ProductionTransportError("native budget unavailable"))
    with pytest.raises(ProductionTransportError, match="budget unavailable"):
        await reads.preflight()
    with pytest.raises(ProductionReadUnavailable, match="preflight"):
        await reads.fetch_paper_state()


@pytest.mark.asyncio
async def test_balance_projects_native_summary_arrays_to_existing_sdk_dto_without_decimal_loss():
    body = (
        b'{"funding":{"currency":"usdt","balance":123456789012345678.123400},'
        b'"availableBalance":0.000000000000000001,'
        b'"position":[{"instrument":"BTCUSD","side":"BUY","volume":"1.2300",'
        b'"initialMargin":0.000000000000000003}],'
        b'"openOrder":[{"instrument":"ETHUSD","side":"SELL","unFilledVolume":"4.5000",'
        b'"unFilledInitialMargin":"0.000000000000000005"}],'
        b'"positions":{"deprecated-map":999},"openOrders":{"deprecated-map":999},'
        b'"updatedAt":"2020-01-01T00:00:00.123Z"}'
    )
    reads, _ = fixture(bodies={"available_balance": body})
    await reads.preflight()
    state = await reads.fetch_paper_state()
    balance = state["balance"]
    assert set(balance) == {"funding", "positions", "openOrders", "availableBalance"}
    assert balance["funding"] == {"currency": "usdt", "balance": "123456789012345678.123400"}
    assert Decimal(balance["availableBalance"]) == Decimal("0.000000000000000001")
    assert balance["positions"][0] == {
        "instrument": "BTCUSD",
        "side": "BUY",
        "volume": "1.2300",
        "initialMargin": Decimal("0.000000000000000003"),
    }
    assert balance["openOrders"][0] == {
        "instrument": "ETHUSD",
        "side": "SELL",
        "unFilledVolume": "4.5000",
        "unFilledInitialMargin": "0.000000000000000005",
    }
    capture = state["native_read_captures"]["available_balance"]
    assert base64.b64decode(capture["body_base64"]) == body
    assert b'"updatedAt":"2020-01-01T00:00:00.123Z"' in body
    assert state["account_revision_authoritative"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field,value",
    [
        ("position", None),
        ("openOrder", None),
        ("position", {}),
        ("openOrder", {}),
        ("funding", {"balance": "1"}),
        ("funding", {"currency": None, "balance": "1"}),
        ("funding", {"currency": "", "balance": "1"}),
    ],
)
async def test_balance_absent_summary_arrays_or_currency_are_not_replaced_by_deprecated_maps(field, value):
    native = {
        "funding": {"currency": "USDT", "balance": "1"},
        "availableBalance": "1",
        "positions": {},
        "openOrders": {},
        "position": [],
        "openOrder": [],
    }
    native[field] = value
    reads, _ = fixture(bodies={"available_balance": json.dumps(native).encode()})
    await reads.preflight()
    with pytest.raises(ProductionReadUnavailable):
        await reads.fetch_paper_state()
    del native[field]
    reads, _ = fixture(bodies={"available_balance": json.dumps(native).encode()})
    await reads.preflight()
    with pytest.raises(ProductionReadUnavailable):
        await reads.fetch_paper_state()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "collection,field,value",
    [
        ("position", "instrument", None),
        ("position", "side", None),
        ("position", "volume", None),
        ("position", "initialMargin", None),
        ("position", "volume", "-1"),
        ("position", "initialMargin", "NaN"),
        ("openOrder", "instrument", ""),
        ("openOrder", "side", "UNKNOWN"),
        ("openOrder", "unFilledVolume", None),
        ("openOrder", "unFilledInitialMargin", None),
        ("openOrder", "unFilledVolume", "Infinity"),
        ("openOrder", "unFilledInitialMargin", "-1"),
    ],
)
async def test_native_balance_summaries_require_all_fsm_geometry_fields(collection, field, value):
    native = {
        "funding": {"currency": "USDT", "balance": "1"},
        "availableBalance": "1",
        "position": [{"instrument": "BTCUSD", "side": "BUY", "volume": "1", "initialMargin": "0"}],
        "openOrder": [
            {"instrument": "BTCUSD", "side": "BUY", "unFilledVolume": "1", "unFilledInitialMargin": "0"}
        ],
    }
    native[collection][0][field] = value
    reads, _ = fixture(bodies={"available_balance": json.dumps(native).encode()})
    await reads.preflight()
    with pytest.raises(ProductionReadUnavailable):
        await reads.fetch_paper_state()
