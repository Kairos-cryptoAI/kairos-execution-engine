"""Operational observations only; no exchange credential or authority."""

import copy
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest

from kairos_execution.one_canary_account import (
    CanaryAccountError,
    EvedexCanaryAccountSource,
    observed_session_loss_usdt,
)


@pytest.fixture
def source(monkeypatch):
    source = EvedexCanaryAccountSource(api_key="synthetic-key", expected_account_id="7")
    data = {
        "/api/user/me": {"exchangeId": 7, "createdAt": "2026-05-25T12:00:00Z", "marginCall": False},
        "/api/market/available-balance": {
            "currency": "usdt",
            "funding": {"currency": "usdt", "balance": "109.42"},
            "availableBalance": "109.42",
            "negativeUnPnL": 0,
            "position": [],
            "openOrder": [],
        },
        "/api/user/funding": [{"coin": "usdt", "quantity": "109.42"}],
        "/api/position": {"list": [{"quantity": "0"}]},
        "/api/order/opened": [],
        "/api/tpsl": {
            "count": 2,
            "list": [
                {"id": "a", "quantity": "1", "triggeredQuantity": "0", "status": "cancelled"},
                {"id": "b", "quantity": "1", "triggeredQuantity": "1", "status": "done"},
            ],
        },
        "/api/transfer": {"count": 0, "list": []},
        "/api/user/funding-transfer": {"count": 0, "list": []},
    }

    async def get(session, path, reads, **params):
        return copy.deepcopy(data[path])

    monkeypatch.setattr(source, "_get", get)
    return source, data


@pytest.mark.asyncio
async def test_terminal_tpsl_is_history_not_live_obligation(source):
    src, _ = source
    observation = await src.observe()
    observation.require_flat()
    observation.require_recent(datetime.now(UTC))
    assert observation.funding_usdt == Decimal("109.42")
    assert observation.equity_lower_bound_usdt == Decimal("109.42")
    assert observation.nonterminal_tpsl == 0
    assert dict(observation.tpsl_status_counts) == {"cancelled": 1, "done": 1}


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["quantity", "triggeredQuantity", "status"])
async def test_missing_tpsl_data_not_empty_or_terminal(source, field):
    src, data = source
    data["/api/tpsl"]["list"][0].pop(field)
    with pytest.raises(CanaryAccountError):
        await src.observe()


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["active", "waitOrder", "process", "triggered"])
async def test_nonterminal_tpsl_blocks_flat_admission(source, status):
    src, data = source
    data["/api/tpsl"]["list"][0]["status"] = status
    observation = await src.observe()
    with pytest.raises(CanaryAccountError):
        observation.require_flat()


@pytest.mark.asyncio
async def test_missing_position_quantity_is_unknown(source):
    src, data = source
    data["/api/position"]["list"] = [{}]
    with pytest.raises(CanaryAccountError):
        await src.observe()


@pytest.mark.asyncio
@pytest.mark.parametrize("quantity", ["-1", "1"])
async def test_either_position_direction_blocks_admission(source, quantity):
    src, data = source
    data["/api/position"]["list"][0]["quantity"] = quantity
    observation = await src.observe()
    with pytest.raises(CanaryAccountError):
        observation.require_flat()


@pytest.mark.asyncio
async def test_pending_withdrawal_blocks(source):
    src, data = source
    data["/api/transfer"] = {"count": 1, "list": [{"id": "withdraw"}]}
    with pytest.raises(CanaryAccountError):
        (await src.observe()).require_flat()


@pytest.mark.asyncio
async def test_balance_disagreement_blocks(source):
    src, data = source
    data["/api/user/funding"][0]["quantity"] = "110"
    with pytest.raises(CanaryAccountError):
        await src.observe()


@pytest.mark.asyncio
async def test_nonfinite_balance_and_unvalued_currency_rejected(source):
    src, data = source
    data["/api/user/funding"].append({"coin": "btc", "quantity": "1"})
    with pytest.raises(CanaryAccountError):
        await src.observe()
    data["/api/user/funding"].pop()
    data["/api/market/available-balance"]["negativeUnPnL"] = "NaN"
    with pytest.raises(CanaryAccountError):
        await src.observe()


@pytest.mark.asyncio
async def test_snapshot_cannot_be_replayed_as_fresh(source):
    observation = await source[0].observe()
    with pytest.raises(CanaryAccountError):
        observation.require_recent(observation.started_at - timedelta(seconds=1))
    with pytest.raises(CanaryAccountError):
        observation.require_recent(observation.finished_at + timedelta(seconds=31))


@pytest.mark.asyncio
async def test_deposit_adjustment_does_not_mask_loss(source):
    src, data = source
    start = datetime.now(UTC) - timedelta(seconds=2)
    data["/api/user/funding-transfer"] = {
        "count": 2,
        "list": [
            {"type": "deposit", "quantity": "25", "coin": "usdt", "createdAt": start.isoformat()},
            {"type": "orderFillFee", "quantity": "-0.25", "coin": "usdt", "createdAt": start.isoformat()},
        ],
    }
    flows = await src.external_flows_since(start)
    assert flows.net_deposits_usdt == Decimal("25")
    current = await src.observe()
    assert observed_session_loss_usdt(
        baseline_equity_usdt=Decimal("100"), current=current, net_deposits_usdt=flows.net_deposits_usdt
    ) == Decimal("15.58")


@pytest.mark.asyncio
async def test_unclassified_flow_not_assumed_zero(source):
    src, data = source
    start = datetime.now(UTC) - timedelta(seconds=2)
    data["/api/user/funding-transfer"] = {
        "count": 1,
        "list": [
            {"type": "unknown", "quantity": "3", "coin": "usdt", "createdAt": start.isoformat()},
        ],
    }
    with pytest.raises(CanaryAccountError):
        await src.external_flows_since(start)


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["count", "duplicate", "truncated", "cursor"])
async def test_pagination_ambiguity_rejected(source, change, monkeypatch):
    src, _ = source
    calls = 0

    async def get(session, path, reads, **params):
        nonlocal calls
        calls += 1
        rows = [{"id": str(n)} for n in range(100)]
        if calls == 1:
            if change == "truncated":
                rows.pop()
            return {"count": 101, "list": rows, **({"next": "opaque"} if change == "cursor" else {})}
        return {
            "count": 102 if change == "count" else 101,
            "list": [{"id": "0" if change == "duplicate" else "100"}],
        }

    monkeypatch.setattr(src, "_get", get)
    with pytest.raises(CanaryAccountError):
        await src._pages(None, "/api/tpsl", [])
