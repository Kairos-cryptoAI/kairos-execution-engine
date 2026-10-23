"""Synthetic wire fixtures, never real account or authority acceptance evidence."""

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from kairos_execution.production_exposure import (
    GAPS,
    PinnedEvedexTerminalEvidenceVerifier,
    assess_pinned_history_authority,
    require_exposure_write_authority,
)
from kairos_execution.production_history import (
    MAX_HISTORY_BYTES,
    SOURCE_ID,
    ProductionHistoryCaptureV1,
    ProductionHistoryCollector,
    ProductionHistoryError,
)
from kairos_execution.production_readiness import ProductionContextV1
from kairos_execution.production_reconciliation import (
    ProductionReconciliationError,
    ReservationTradeBindingV1,
)

NOW = datetime(2026, 10, 23, 12, tzinfo=UTC)


def context():
    return ProductionContextV1(
        remote_account_id="42",
        adaptive_system_id="synthetic-history-fixture",
        frozen_policy_sha256="a" * 64,
        source_set_sha256="b" * 64,
    )


def order(order_id="entry-1", **kwargs):
    return {
        "id": order_id,
        "user": "42",
        "instrument": "BTCUSD",
        "side": "BUY",
        "quantity": "0.123456789123456789",
        "unFilledQuantity": "0",
        "fee": [{"coin": "USDT", "quantity": "0.000000000123456789"}],
        "realizedPnL": "-2.000000000001",
        **kwargs,
    }


def transport():
    return type(
        "SyntheticTypedTransport",
        (),
        {
            "fetch_account_identity": AsyncMock(return_value={"exchangeId": 42}),
            "fetch_order_history_page": AsyncMock(return_value={"list": [order()], "count": 1}),
            "fetch_tpsl_page": AsyncMock(
                return_value={"list": [{"id": "stop-1", "triggerOrder": "exit-1"}], "count": 1}
            ),
            "fetch_funding": AsyncMock(
                return_value=[{"coin": "USDT", "quantity": 100, "updatedAt": NOW.isoformat()}]
            ),
        },
    )()


async def capture(client=None, **kwargs):
    return await ProductionHistoryCollector(
        context=context(),
        transport=client or transport(),
        clock=lambda: NOW,
        **kwargs,
    ).capture_once()


@pytest.mark.asyncio
async def test_typed_actual_paths_raw_decimal_strings_and_unknowns_are_preserved():
    client = transport()
    result = await capture(client)
    assert result.source_id == SOURCE_ID
    assert result.order_count == result.protection_count == 1
    assert result.pagination_exhausted is True
    assert (
        result.authoritative_reconciliation
        is result.atomic_exposure
        is result.funding_payment_coverage
        is False
    )
    assert [component.path for component in result.components] == [
        "/api/user/me",
        "/api/order",
        "/api/tpsl",
        "/api/user/funding",
        "/api/user/me",
    ]
    retained = json.loads(result.components[1].payload_json)["list"][0]
    assert retained == order()
    assert retained["quantity"] == "0.123456789123456789"
    assert retained["fee"][0]["quantity"] == "0.000000000123456789"
    assert "funding_cost_usd" not in result.model_dump()
    assert "order" not in json.loads(result.components[2].payload_json)["list"][0]
    client.fetch_order_history_page.assert_awaited_once_with(version=2, limit=100, offset=0, next_cursor=None)
    client.fetch_tpsl_page.assert_awaited_once_with(limit=100, offset=0)
    assert client.fetch_account_identity.await_count == 2


@pytest.mark.asyncio
async def test_real_transport_wrapper_composes_after_explicit_preflight_without_process_start():
    from kairos_execution.managed_signer import CustodyBindingV1, reviewed_schema_sha256
    from kairos_execution.production_transport import ProductionEvedexTransport

    client = transport()
    client.expected_account_id = "42"
    client.preflight = AsyncMock(return_value={"exchangeId": 42})
    binding = CustodyBindingV1(
        context=context(),
        custody_reference="synthetic-custody",
        wallet_address="0x" + "12" * 20,
        chain_id=42161,
        schema_sha256=reviewed_schema_sha256(42161),
        approved_instruments=("BTCUSD", "ETHUSD", "SOLUSD", "BNBUSD", "XRPUSD"),
        custody_receipt_sha256="c" * 64,
    )
    sdk_transport = ProductionEvedexTransport(context=context(), custody_binding=binding, client=client)
    await sdk_transport.preflight()
    result = await capture(sdk_transport)
    assert result.order_count == 1
    assert assess_pinned_history_authority(result).exposure_authority is False
    client.preflight.assert_awaited_once()


@pytest.mark.asyncio
async def test_order_next_cursor_is_followed_and_retained_without_invented_time_cursor():
    client = transport()
    client.fetch_order_history_page.side_effect = [
        {"list": [order()], "count": 2, "next": "opaque-token"},
        {"list": [order("entry-2")], "count": 2},
    ]
    result = await capture(client)
    assert result.order_count == 2
    assert json.loads(result.components[2].query_json) == {
        "version": 2,
        "limit": 100,
        "offset": 1,
        "next": "opaque-token",
    }
    assert client.fetch_order_history_page.await_args_list[1].kwargs == {
        "version": 2,
        "limit": 100,
        "offset": 1,
        "next_cursor": "opaque-token",
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "pages,match",
    [
        ([{"list": [order()], "count": 2}, {"list": [order()], "count": 2}], "duplicate"),
        ([{"list": [order()], "count": 2}, {"list": [], "count": 2}], "ended"),
        ([{"list": [order()], "count": 2}, {"list": [order("other")], "count": 3}], "changed"),
        ([{"list": [], "count": 10001}], "bound"),
        ([{"list": [], "count": True}], "malformed"),
        ([{"list": [order(user="43")], "count": 1}], "different"),
        ([{"list": [order()], "count": 1, "next": "still-more"}], "contradicts"),
        (
            [
                {"list": [order()], "count": 3, "next": "repeat"},
                {"list": [order("other")], "count": 3, "next": "repeat"},
            ],
            "repeated",
        ),
    ],
)
async def test_pagination_incompleteness_drift_repeats_and_account_conflicts_are_discarded(pages, match):
    client = transport()
    client.fetch_order_history_page.side_effect = pages
    with pytest.raises(ProductionHistoryError, match=match):
        await capture(client)
    client.fetch_funding.assert_not_awaited()


@pytest.mark.asyncio
async def test_account_alias_is_not_exchange_identity_and_changed_identity_is_discarded():
    client = transport()
    client.fetch_account_identity.return_value = {"id": "42", "exchangeId": 43}
    with pytest.raises(ProductionHistoryError, match="exchangeId"):
        await capture(client)
    client.fetch_order_history_page.assert_not_awaited()
    client = transport()
    client.fetch_account_identity.side_effect = [{"exchangeId": 42}, {"exchangeId": 43}]
    with pytest.raises(ProductionHistoryError, match="exchangeId"):
        await capture(client)


@pytest.mark.asyncio
async def test_protection_pages_are_exhausted_and_trigger_order_is_not_parent():
    client = transport()
    client.fetch_tpsl_page.side_effect = [
        {"list": [{"id": "stop-1", "triggerOrder": "exit-1"}], "count": 2},
        {"list": [{"id": "stop-2", "triggerOrder": None}], "count": 2},
    ]
    result = await capture(client)
    assert result.protection_count == 2
    assert client.fetch_tpsl_page.await_args_list[1].kwargs == {"limit": 100, "offset": 1}


@pytest.mark.asyncio
async def test_empty_funding_balance_list_does_not_mean_complete_zero_funding_cost():
    client = transport()
    client.fetch_funding.return_value = []
    result = await capture(client)
    assert result.funding_payment_coverage is False
    assert (
        "no_account_funding_payment_ledger_or_settlement_coverage"
        in assess_pinned_history_authority(result).reasons
    )


@pytest.mark.asyncio
async def test_missing_fees_remain_missing_and_page_budget_is_hard(monkeypatch):
    import kairos_execution.production_history as history

    client = transport()
    missing_fee = order()
    del missing_fee["fee"]
    client.fetch_order_history_page.return_value = {"list": [missing_fee], "count": 1}
    result = await capture(client)
    assert "fee" not in json.loads(result.components[1].payload_json)["list"][0]
    monkeypatch.setattr(history, "MAX_HISTORY_PAGES", 2)
    client = transport()
    client.fetch_order_history_page.side_effect = [
        {"list": [order("one")], "count": 3},
        {"list": [order("two")], "count": 3},
    ]
    with pytest.raises(ProductionHistoryError, match="page bound"):
        await capture(client)
    assert client.fetch_order_history_page.await_count == 2


@pytest.mark.asyncio
async def test_bounds_no_retries_sanitized_errors_and_no_partial_result():
    client = transport()
    client.fetch_order_history_page.side_effect = RuntimeError("secret bearer never in errors")
    with pytest.raises(ProductionHistoryError, match="read failed") as error:
        await capture(client)
    assert "secret" not in str(error.value)
    assert client.fetch_order_history_page.await_count == 1
    client = transport()
    client.fetch_order_history_page.return_value = {"list": [order(note="x" * MAX_HISTORY_BYTES)], "count": 1}
    with pytest.raises(ProductionHistoryError, match="size bound"):
        await capture(client)
    client = transport()

    async def never():
        await asyncio.Event().wait()

    client.fetch_account_identity.side_effect = never
    with pytest.raises(ProductionHistoryError, match="timed out"):
        await capture(client, max_seconds=0.01)
    assert client.fetch_account_identity.await_count == 1


@pytest.mark.asyncio
async def test_refusal_is_registered_verifier_compatible_and_cannot_be_promoted_by_payload():
    result = await capture()
    assessment = assess_pinned_history_authority(result)
    assert assessment.reasons == GAPS
    assert (
        assessment.terminal_authority
        is assessment.exposure_authority
        is assessment.accounting_authority
        is False
    )
    binding = ReservationTradeBindingV1(
        trade_id="1" * 64,
        decision_id="synthetic-decision",
        effect_id="2" * 64,
        lifecycle_entry_effect_id="3" * 64,
        signing_request_id="synthetic-request",
        client_order_id="entry-1",
        exchange_parent_order_id="entry-1",
    )
    verifier = PinnedEvedexTerminalEvidenceVerifier()
    registered = {verifier.source_id: verifier}
    with pytest.raises(ProductionReconciliationError, match="cannot establish terminal/accounting"):
        registered[SOURCE_ID].verify_terminal_evidence(result, context=context(), binding=binding)
    with pytest.raises(ProductionReconciliationError, match="exposure write"):
        require_exposure_write_authority(result)
    forged = result.model_dump()
    forged["complete"] = True
    forged["funding_cost_usd"] = "0"
    with pytest.raises(ProductionReconciliationError, match="malformed"):
        verifier.verify_terminal_evidence(forged, context=context(), binding=binding)
    with pytest.raises(ValueError):
        ProductionHistoryCaptureV1.model_validate({**result.model_dump(), "atomic_exposure": True})


@pytest.mark.asyncio
async def test_retained_digest_and_monotone_clock_are_checked():
    result = await capture()
    component = result.components[1].model_dump()
    component["payload_json"] = "{}"
    with pytest.raises(ValueError, match="digest"):
        type(result.components[1]).model_validate(component)
    ticks = iter([NOW, NOW - timedelta(seconds=1)])
    with pytest.raises(ProductionHistoryError, match="clock moved backwards"):
        await ProductionHistoryCollector(
            context=context(), transport=transport(), clock=lambda: next(ticks)
        ).capture_once()


def test_installed_pinned_sdk_contract_documents_authority_gaps_not_synthetic_evidence():
    """Static local primary-code parity, explicitly not live account validation."""
    root = Path(__file__).parents[1] / "kairos_execution/evedex_sidecar/node_modules/@evedex"
    if not root.is_dir():
        pytest.skip("reviewed installed SDK is unavailable; synthetic tests do not prove parity")
    api = root / "exchange-api"
    assert json.loads((api / "package.json").read_text())["version"] == "1.0.70"
    assert json.loads((root / "exchange-bot-sdk/package.json").read_text())["version"] == "1.2.11"
    types = (api / "dist/mjs/utils/types.d.ts").read_text()
    rest = (api / "dist/mjs/exchangeRestGateway.d.ts").read_text()
    ws = (api / "dist/mjs/exchangeWsGateway.js").read_text()
    funding = types.split("export interface Funding {", 1)[1].split("}", 1)[0]
    tpsl = types.split("export interface TpSl {", 1)[1].split("}", 1)[0]
    query = rest.split("export interface OrderListQuery", 1)[1].split("}", 1)[0]
    assert "coin: string" in funding and "quantity: number" in funding
    assert "triggerOrder:" in tpsl and "    order:" not in tpsl
    assert "next?: string" in query and "before" not in query and "after" not in query
    assert "getFunding(): Promise<FundingList>" in rest
    assert "getOrderFills" not in rest
    assert "this.listenChannel(`orderFills-${query.userExchangeId}`, false," in ws
