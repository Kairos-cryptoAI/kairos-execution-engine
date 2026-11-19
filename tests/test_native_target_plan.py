import asyncio
from dataclasses import replace
from decimal import Decimal as D

import pytest

from kairos_execution.portfolio_broker import NeedsOperator
from kairos_execution.portfolio_evedex import Instrument
from kairos_execution.portfolio_targets import (
    TargetEvidenceError,
    partial_target_spec,
    sized_targets,
    target_fills,
)
from tests.test_portfolio_broker import position_projection as position_projection
from tests.test_portfolio_broker import system as system

TARGETS = [{"at_r": 0.3, "fraction": 0.25}, {"at_r": 0.6, "fraction": 0.25}]
TICK = Instrument("BTCUSD", D(".001"), D(".001"), D(".01"), D("1"), True, 30)


async def open_targets(s, side, monkeypatch):
    await s.b.reconcile_start([], None)
    buy = side == "LONG"
    stop, take = (D(95), D(105)) if buy else (D(105), D(95))
    s.j.reserve_entry(
        trade_id="owned",
        decision_id="decision",
        symbol="BTCUSD",
        side=side,
        quantity=D(".1"),
        leverage=1,
        stop=stop,
        take=take,
        worst_case_loss=D(".1"),
        notional=D(10),
        equity=D(100),
    )
    body = {
        "id": "entry",
        "instrument": "BTCUSD",
        "side": "BUY" if buy else "SELL",
        "quantity": ".1",
        "limitPrice": "100",
        "tpsl": [
            {"type": kind, "side": "SELL" if buy else "BUY", "quantity": "0", "price": str(px)}
            for kind, px in (("stop-loss", stop), ("take-profit", take))
        ],
    }
    eid = s.j.prepare_effect(
        trade_id="owned",
        kind="ENTRY",
        operation_key="enter",
        request={"id": "entry", "price": "100", "partial_targets": partial_target_spec(TARGETS, TICK)},
    )
    await s.v.post_limit_order(body)
    s.j.finish_effect(eid, "ACCEPTED", "entry")
    monkeypatch.setattr(s.v, "post_partial_target", s.v.post_tpsl, raising=False)
    monkeypatch.setattr(s.v, "native_ladder_qualified_for", lambda sym: sym == "BTCUSD", raising=False)
    result = await s.b._confirm_entry(s.j.trade("owned"), "entry", D(100))
    assert result["native_partial_targets"]
    return {
        "id": "entry",
        "symbol": "BTCUSD",
        "risk_trade_id": "owned",
        "risk_decision_id": "decision",
        "side": side,
        "quantity": ".1",
        "stop": str(stop),
    }


async def test_authenticated_risk_observations_read_concurrently_after_identity(system, monkeypatch):
    s = system
    requests = set()
    all_started = asyncio.Event()

    async def identity():
        requests.add("identity")

    def reader(name, result):
        async def read():
            assert "identity" in requests
            requests.add(name)
            if len(requests) == 4:
                all_started.set()
            await asyncio.wait_for(all_started.wait(), timeout=1)
            return result

        return read

    monkeypatch.setattr(s.b, "_identity", identity)
    monkeypatch.setattr(s.v, "balance", reader("balance", (D(100), D(98))))
    monkeypatch.setattr(s.v, "positions", reader("positions", []))
    monkeypatch.setattr(s.v, "open_orders", reader("orders", []))
    assert await s.b.account_reads() == (D(100), D(98), [], [])


async def test_waiting_acknowledged_stop_is_removed_without_touching_the_current_cover(
    system, position_projection, monkeypatch
):
    s = system
    fill = await s.enter()
    item = s.j.trade(fill["trade_id"])
    original = set(s.v.tpsl)
    row = {
        "id": "waiting",
        "instrument": "BTCUSD",
        "type": "stop-loss",
        "status": "waitOrder",
        "quantity": "0",
        "side": "SELL",
        "price": "97",
        "order": item["entry_order_id"],
    }
    # Previous builds bound already-filled entries on the wire and could leave a dormant trigger.
    eid = s.j.prepare_effect(
        trade_id=item["trade_id"],
        kind="STOP",
        operation_key="97",
        request={"order": item["entry_order_id"], "side": "SELL", "price": "97"},
    )
    s.j.finish_effect(eid, "ACCEPTED", "waiting")
    s.v.tpsl["waiting"] = row
    s.b._position_entries.clear()
    trade = {
        "id": item["entry_order_id"],
        "symbol": "BTCUSD",
        "side": "LONG",
        "risk_trade_id": item["trade_id"],
        "risk_decision_id": item["decision_id"],
        "quantity": item["quantity"],
        "stop": item["stop"],
    }
    await s.b.reconcile_start([trade], None)
    assert set(s.v.tpsl) == original and D(trade["stop"]) == D(item["stop"])
    assert s.b._tightest_stop(item) == D(item["stop"])
    assert [e["request"]["id"] for e in s.j.effects(item["trade_id"]) if e["kind"] == "CANCEL_STOP"] == [
        "waiting"
    ]


@pytest.mark.parametrize("side", ["LONG", "SHORT"])
async def test_resting_ladder_restores_each_fill_once_and_keeps_full_stop(
    system, position_projection, side, monkeypatch
):
    s = system
    trade = await open_targets(s, side, monkeypatch)
    effective = [r for r in s.v.tpsl.values() if D(r["quantity"]) > 0]
    assert all("order" in r and r["order"] is None for r in effective)
    owned = [e["request"] for e in s.j.effects("owned") if e["kind"] == "PARTIAL_TAKE"]
    assert all(r["order"] == "entry" and r["wire_scope"] == "position" and r["version"] == 4 for r in owned)
    assert [(D(r["price"]), D(r["quantity"])) for r in effective] == (
        [(D("101.5"), D(".025")), (D(103), D(".025"))]
        if side == "LONG"
        else [(D("98.5"), D(".025")), (D(97), D(".025"))]
    )
    terminal = {}

    async def history(_symbol, ids):
        return {key: terminal.get(key) or s.v.tpsl[key] for key in ids}

    monkeypatch.setattr(s.v, "target_history", history, raising=False)
    for level in effective:
        trigger = level["id"]
        s.v.tpsl.pop(trigger)
        terminal[trigger] = {
            **level,
            "status": "done",
            "triggerOrder": "entry" if side == "LONG" else None,
            "triggeredQuantity": level["quantity"],
        }
        # Live EVEDEX has returned triggerOrder=null while GET /api/order/{trigger.id} identifies the child.
        s.v.records[trigger] = {
            "id": trigger,
            "instrument": "BTCUSD",
            "type": "MARKET",
            "status": "FILLED",
            "side": level["side"],
            "quantity": level["quantity"],
            "unFilledQuantity": "0",
            "group": "take-profit",
            "hasOpenedPosition": False,
            "filledAvgPrice": level["price"],
        }
        s.v.held["BTCUSD"] = replace(
            s.v.held["BTCUSD"], quantity=s.v.held["BTCUSD"].quantity - D(level["quantity"])
        )
        s.b._position_entries.clear()  # reconstruct the generation and original plan on restart
        await s.b.reconcile_start([trade], None)
        assert await s.b.position_open(trade)
        assert await s.b.position_open(trade)
        assert D(trade["quantity"]) == s.v.held["BTCUSD"].quantity
        assert any(r["type"] == "stop-loss" and D(r["quantity"]) == 0 for r in s.v.tpsl.values())
    assert len(s.j.native_target_fills("owned")) == 2
    assert D(trade["quantity"]) == D(".05")
    with pytest.raises(NeedsOperator, match="sole owner"):
        await s.b.partial_close(trade, await s.v.book("BTCUSD"), D(".01"))


@pytest.mark.parametrize(
    "side,kind,linked,restart",
    [
        ("LONG", "take-profit", True, False),
        ("SHORT", "stop-loss", True, False),
        ("SHORT", "stop-loss", False, False),
        ("SHORT", "stop-loss", True, True),
    ],
)
async def test_bracket_closes_before_first_position_read(
    system, position_projection, monkeypatch, side, kind, linked, restart
):
    s = system
    await s.b.reconcile_start([], None)
    buy = side == "LONG"
    entry_side, exit_side = ("BUY", "SELL") if buy else ("SELL", "BUY")
    stop, take = (D(95), D(105)) if buy else (D(105), D(95))
    s.j.reserve_entry(
        trade_id="fast",
        decision_id="decision",
        symbol="BTCUSD",
        side=side,
        quantity=D(".1"),
        leverage=1,
        stop=stop,
        take=take,
        worst_case_loss=D(".1"),
        notional=D(10),
        equity=D(100),
    )
    eid = s.j.prepare_effect(
        trade_id="fast",
        kind="ENTRY",
        operation_key="enter",
        request={"id": "entry", "price": "100", "partial_targets": partial_target_spec(TARGETS, TICK)},
    )
    s.j.finish_effect(eid, "ACCEPTED", "entry")
    s.v.records["entry"] = dict(
        id="entry",
        instrument="BTCUSD",
        side=entry_side,
        status="FILLED",
        type="LIMIT",
        limitPrice="100",
        quantity=".1",
        unFilledQuantity="0",
        filledAvgPrice="100",
    )
    s.v.records["exit"] = dict(
        id="exit",
        instrument="BTCUSD",
        side=exit_side,
        status="FILLED",
        type="MARKET",
        group=kind,
        hasOpenedPosition=False,
        quantity=".1",
        unFilledQuantity="0",
        filledAvgPrice="105.01",
    )

    async def terminal(symbol, key):
        assert symbol == "BTCUSD" and key == "exit"
        return {
            "id": key,
            "instrument": symbol,
            "side": exit_side,
            "status": "done",
            "price": "105",
            "quantity": "0",
            "triggeredQuantity": ".1",
            "type": kind,
            "triggerOrder": "entry" if linked else "other-entry",
        }

    monkeypatch.setattr(s.v, "protection_for_fill", terminal, raising=False)
    if restart:
        s.j.opened("fast", entry_order_id="entry", quantity=D(".1"), price=D(100))
        await s.b.reconcile_start([], None)
        assert s.j.trade("fast")["exit_origin"] == "system" and not s.j.active_trades()
    elif linked:
        fill = await s.b._confirm_entry(s.j.trade("fast"), "entry", D(100))
        assert fill["closed_at_entry"] == ("TAKE" if buy else "STOP")
        assert fill["exit_price"] == D("105.01") and not s.j.active_trades()
        assert s.j.trade("fast")["exit_origin"] == "system" and s.j.native_target_plan("fast") is None
    else:
        with pytest.raises(NeedsOperator):
            await s.b._confirm_entry(s.j.trade("fast"), "entry", D(100))
        assert s.j.trade("fast")["state"] == "RESERVED"
    assert not s.v.sent and not s.v.tpsl and not s.v.held


def test_small_fill_never_overallocates_native_targets():
    spec = partial_target_spec(TARGETS, TICK)
    assert sized_targets(spec, "LONG", D(100), D(95), D(105), D(".001")) == []
    assert sum(D(r["quantity"]) for r in sized_targets(spec, "SHORT", D(100), D(105), D(95), D(".1"))) == D(
        ".05"
    )


async def test_unqualified_native_target_plan_is_refused_before_any_effect(system):
    from types import SimpleNamespace

    s = system
    candidate = SimpleNamespace(id=s.risk.intent.intent_id, instrument="BTCUSD", side="LONG")
    assert (
        await s.b.enter(
            candidate,
            D(".1"),
            await s.v.book("BTCUSD"),
            TICK,
            D(95),
            D(105),
            7,
            decision=s.risk,
            partial_targets=TARGETS,
        )
        is None
    )
    assert not s.j.active_trades() and not s.v.leverages and not s.v.sent


@pytest.mark.parametrize("side", ["LONG", "SHORT"])
async def test_full_exit_cancels_all_native_partials_before_close(
    system, position_projection, side, monkeypatch
):
    s = system
    trade = await open_targets(s, side, monkeypatch)
    terminal = {}

    async def cancel(symbol, key):
        terminal[key] = {**s.v.tpsl.pop(key), "status": "cancelled", "triggeredQuantity": "0"}

    async def history(symbol, ids):
        return {key: terminal.get(key) or s.v.tpsl[key] for key in ids}

    close = s.v.post_close

    async def exit_position(body):
        assert not any(D(r["quantity"]) for r in s.v.tpsl.values())
        assert any(r["type"] == "stop-loss" for r in s.v.tpsl.values())
        result = await close(body)
        result["hasOpenedPosition"] = False
        for key in list(s.v.tpsl):
            await cancel("BTCUSD", key)
        return result

    monkeypatch.setattr(s.v, "cancel_tpsl", cancel)
    monkeypatch.setattr(s.v, "post_close", exit_position)
    monkeypatch.setattr(s.v, "target_history", history, raising=False)
    await s.b.close(trade, await s.v.book("BTCUSD"), "OPERATOR_CLOSE")
    assert (await s.b.settle(trade))["exit_origin"] == "operator"
    assert not s.v.held and not s.v.tpsl and not s.j.unresolved_effects()


def test_nullable_child_requires_a_unique_generation_fill_and_unique_bound_sibling():
    item = {"entry_order_id": "entry", "side": "SHORT", "symbol": "BTCUSD", "price": "100"}
    plan = {"initial_quantity": "1", "version": 4}
    effect = {
        "kind": "PARTIAL_TAKE",
        "status": "ACCEPTED",
        "venue_id": "trigger",
        "request": {"side": "BUY", "quantity": ".25", "price": "99"},
    }
    trigger = {
        "id": "trigger",
        "instrument": "BTCUSD",
        "type": "take-profit",
        "side": "BUY",
        "quantity": ".25",
        "price": "99",
        "status": "done",
        "triggerOrder": None,
        "triggeredQuantity": ".25",
        "updatedAt": "2026-11-19T10:00:00.000Z",
    }
    entry = {
        "id": "entry",
        "instrument": "BTCUSD",
        "user": "test-account",
        "side": "SELL",
        "quantity": "1",
        "unFilledQuantity": "0",
        "filledAvgPrice": "100",
    }
    close = {
        **entry,
        "id": "different-child",
        "side": "BUY",
        "quantity": ".25",
        "filledAvgPrice": "99",
        "group": "take-profit",
        "hasOpenedPosition": False,
        "status": "FILLED",
        "positionVersions": [4],
        "updatedAt": "2026-11-19T10:00:00.509Z",
    }

    def match(children, child=close):
        return target_fills(item, plan, [effect], children, [entry, child], "test-account", D(".75"), set())

    assert match({"trigger": trigger}) == {"trigger": ("different-child", "0.25", "99")}
    with pytest.raises(TargetEvidenceError):
        match({"trigger": trigger, "also": {**trigger, "id": "also"}})
    with pytest.raises(TargetEvidenceError):
        match({"trigger": trigger}, {**close, "positionVersions": [5]})
    with pytest.raises(TargetEvidenceError):
        match({"trigger": trigger}, {**close, "hasOpenedPosition": True})
