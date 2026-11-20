from unittest.mock import AsyncMock

import pytest

from kairos_execution.portfolio_broker import NeedsOperator, SettlementPending
from tests.test_native_target_plan import open_targets
from tests.test_portfolio_broker import position_projection as position_projection
from tests.test_portfolio_broker import runner_trade
from tests.test_portfolio_broker import system as system


def lagging_exchange(s, monkeypatch):
    indexed = AsyncMock(return_value=False)
    monkeypatch.setattr(s.v, "position_version_closed", indexed)
    old_cancel, old_close = s.v.cancel_tpsl, s.v.post_close
    terminal = {}

    async def cancel(symbol, key):
        terminal[key] = {**s.v.tpsl[key], "status": "cancelled", "triggeredQuantity": "0"}
        await old_cancel(symbol, key)

    async def close(body):
        row = await old_close(body)
        row["group"] = "manually"
        for key in list(s.v.tpsl):
            await cancel(body["instrument"], key)
        return row

    async def history(symbol, ids):
        return {key: terminal.get(key) or s.v.tpsl[key] for key in ids}

    monkeypatch.setattr(s.v, "target_history", history, raising=False)
    monkeypatch.setattr(s.v, "cancel_tpsl", cancel)
    monkeypatch.setattr(s.v, "post_close", close)
    return indexed, terminal


@pytest.mark.parametrize("side", ["basic", "LONG", "SHORT"])
async def test_owned_flat_close_waits_across_admission_management_and_restart(
    system, position_projection, monkeypatch, side
):
    s = system
    trade = runner_trade(s, await s.enter()) if side == "basic" else await open_targets(s, side, monkeypatch)
    indexed, _ = lagging_exchange(s, monkeypatch)
    symbol, trade_id = trade["symbol"], trade["risk_trade_id"]

    with pytest.raises(SettlementPending) as pending:
        await s.b.close(trade, await s.v.book(symbol), "TIMEOUT")
    assert pending.value.symbol == symbol
    s.b._position_entries.clear()
    for check in (
        lambda: s.b.prepare_admission({symbol}),
        lambda: s.b.reconcile_start([trade], None),
        lambda: s.b.reconcile_start([], None),
        lambda: s.b.reconcile_settlement(symbol),
        lambda: s.b.settle(trade),
    ):
        with pytest.raises(SettlementPending):
            await check()
    assert s.j.active_trade(symbol)["state"] == "OPEN"
    assert not s.v.held and not s.v.tpsl
    indexed.return_value = True
    await s.b.reconcile_settlement(symbol)
    await s.b.reconcile_start([trade], None)
    assert (await s.b.settle(trade))["exit_origin"] == "system"
    assert not s.j.active_trades()
    assert sum(e["kind"] == "CLOSE" for e in s.j.effects(trade_id)) == 1


@pytest.mark.parametrize("fault", ["foreign_fill", "wrong_quantity", "missing_close", "resting", "sibling"])
async def test_unexplained_flatness_cannot_be_reported_as_index_lag(
    system, position_projection, monkeypatch, fault
):
    s = system
    trade = await open_targets(s, "SHORT", monkeypatch)
    _, terminal = lagging_exchange(s, monkeypatch)
    with pytest.raises(SettlementPending):
        await s.b.close(trade, await s.v.book("BTCUSD"), "TIMEOUT")
    close_id = next(e["venue_id"] for e in s.j.effects("owned") if e["kind"] == "CLOSE")
    if fault == "foreign_fill":
        position_projection["fault"] = "foreign_fill"
    elif fault == "wrong_quantity":
        s.v.records[close_id]["quantity"] = ".09"
    elif fault == "missing_close":
        exact_order = s.v.order

        async def missing(order_id):
            return None if order_id == close_id else await exact_order(order_id)

        monkeypatch.setattr(s.v, "order", missing)
    elif fault == "resting":
        s.v.records["foreign"] = {"instrument": "BTCUSD", "status": "NEW"}
    else:
        next(iter(terminal.values()))["status"] = "active"
    with pytest.raises(NeedsOperator):
        await s.b.reconcile_settlement("BTCUSD")
    assert s.j.active_trade("BTCUSD")["state"] == "OPEN"
    assert sum(e["kind"] == "CLOSE" for e in s.j.effects("owned")) == 1
