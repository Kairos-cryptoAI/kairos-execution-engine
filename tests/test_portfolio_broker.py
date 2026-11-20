"""Portfolio integration with synthetic EVEDEX and authentic Core Risk contracts; no network."""

import hashlib
import json
import sqlite3
from contextlib import closing
from datetime import UTC, datetime, timedelta
from decimal import Decimal as D
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from kairos_core.contracts import RiskTradeDecisionV1

from kairos_execution import portfolio_broker as portfolio
from kairos_execution.native_protection import EVEDEX_NATIVE_PROTECTION_UNAVAILABLE
from kairos_execution.portfolio_evedex import (
    TRADING,
    Book,
    Evedex,
    EvedexError,
    Instrument,
    Position,
    Rejected,
    Unknown,
)
from kairos_execution.portfolio_journal import PortfolioJournal
from kairos_execution.prod_universe import PROD_INSTRUMENTS, PROD_SYMBOL_MAP
from tests.test_production_lifecycle_binding import _decision

Account = pytest.importorskip("eth_account").Account


class Venue:
    # Model a venue with independently qualified reducing brackets and replacement stops.
    native_protection_unavailable: str | None = None

    def __init__(self, clock):
        self.clock = clock
        self.records = {}
        self.held = {}
        self.tpsl = {}
        self.sent = []
        self.leverages = []
        self.response = "FILLED"
        self.cash = D(100)
        self.drop_ack = False
        self.omit_parent = False

    def native_stop_move_qualified_for(self, instrument):
        return self.native_protection_unavailable is None

    async def server_time_ms(self):
        return self.clock()

    async def me(self):
        return {"exchangeId": "test-account"}

    async def balance(self):
        return self.cash, self.cash

    async def positions(self):
        return list(self.held.values())

    async def open_orders(self):
        return [r for r in self.records.values() if r["status"] in {"NEW", "PARTIALLY_FILLED"}]

    async def book(self, symbol):
        return Book(self.clock(), D("100.49"), D("100.51"))

    async def active_tpsl(self, symbol=None):
        return [r for r in self.tpsl.values() if symbol is None or r["instrument"] == symbol]

    async def set_leverage(self, symbol, leverage):
        self.leverages.append((symbol, leverage))

    async def post_limit_order(self, body):
        self.sent.append(body)
        sym = body["instrument"]
        qty = D(body["quantity"])
        filled = {"NEW": D(0), "PARTIALLY_FILLED": qty / 2, "FILLED": qty}[self.response]
        record = {
            **body,
            "type": "LIMIT",
            "status": self.response,
            "unFilledQuantity": str(qty - filled),
            "filledAvgPrice": body["limitPrice"],
        }
        self.records[body["id"]] = record
        if filled:
            self.held[sym] = Position(sym, body["side"], filled, D(body["limitPrice"]))
            for r in body["tpsl"]:
                key = body["id"] + "-" + r["type"]
                self.tpsl[key] = {**r, "id": key, "order": body["id"], "instrument": sym, "status": "active"}
        if self.omit_parent:
            for row in self.tpsl.values():
                row.pop("order", None)
        if self.drop_ack:
            raise Unknown("synthetic lost response")
        return record

    async def cancel_order(self, order_id):
        self.records[order_id]["status"] = "CANCELED"

    async def order_with_protections(self, symbol, order_id):
        record = self.records.get(order_id)
        if record:
            return {
                **record,
                "user": "test-account",
                "tpslList": [r for key, r in self.tpsl.items() if key.startswith(order_id)],
            }
        return None

    async def order(self, order_id):
        return self.records.get(order_id)

    async def cancel_tpsl(self, symbol, key):
        assert self.tpsl[key]["instrument"] == symbol
        del self.tpsl[key]

    async def post_tpsl(self, body):
        key = f"stop-{len(self.tpsl)}"
        self.tpsl[key] = {**body, "status": "active", "id": key}
        return self.tpsl[key]

    async def post_close(self, body):
        symbol = body["instrument"]
        position = self.held.pop(symbol)
        quantity = D(body["quantity"])
        if position.quantity > quantity:
            self.held[symbol] = Position(
                symbol, position.side, position.quantity - quantity, position.avg_price
            )
        row = {
            **body,
            "side": "SELL" if position.side == "BUY" else "BUY",
            "status": "FILLED",
            "type": "MARKET",
            "unFilledQuantity": "0",
            "filledAvgPrice": "101.23",
        }
        self.records[body["id"]] = row
        return row


@pytest.fixture
def system(tmp_path, monkeypatch):
    wallet = Account.create()
    digest = hashlib.sha256(wallet.address.lower().encode()).hexdigest()
    account = "evedex-prod-" + digest[:20]
    deadline = datetime.now(UTC) + timedelta(hours=5)
    profile = SimpleNamespace(
        account_id=account,
        remote_account_id="test-account",
        signer_wallet_sha256=digest,
        journal_path=tmp_path / "journal",
        runner_runtime_dir=tmp_path,
        chain_id=42161,
        symbols=sorted(PROD_INSTRUMENTS - {"SOLUSD"}),
        max_positions=10,
        entry_deadline_utc=deadline,
        max_trade_loss_usd="0.25",
        max_notional_usd=25,
    )
    journal = PortfolioJournal(profile.journal_path, account_id=account, symbols=profile.symbols)
    src = _decision()
    data = src.model_dump(mode="python")
    for field in (
        "quantity",
        "estimated_fees_usd",
        "estimated_slippage_usd",
        "notional_usd",
        "worst_case_loss_usd",
    ):
        data[field] *= 0.25
    data.update(decision_id=None, trade_id=None, account_id=account, leverage=7)
    risk = RiskTradeDecisionV1.model_validate(data)
    # Freeze the economic clock; the journal continues using its actual UTC clock for freshness.
    now = risk.decided_at_ms
    deadline = max(deadline, datetime.fromtimestamp(now / 1000, UTC) + timedelta(days=1))
    profile.entry_deadline_utc = deadline
    monkeypatch.setattr(portfolio, "_now", lambda: now)
    monkeypatch.setattr(portfolio, "verify_profile", lambda p: p)  # signature verification has its own suite
    venue = Venue(lambda: now)

    async def observe(journal, source, *, expected_remote_account_id, entry_deadline_utc):
        prior = journal.pilot_status()
        return journal.record_observation(
            observed_at=datetime.now(UTC),
            funding=D(100),
            conservative_equity=D(100),
            external_flow=D(0),
            positions=len(venue.held),
            open_orders=len(await venue.open_orders()),
            active_protections=len(await venue.active_tpsl()),
            entry_deadline_utc=entry_deadline_utc,
            read_digests=["a" * 64],
            baseline_at=prior["started_at"] if prior else None,
        )

    monkeypatch.setattr(portfolio, "observe_pilot", observe)
    store = SimpleNamespace(directory=tmp_path, state={}, flag=lambda _: False, journal=Mock())
    broker = portfolio.PortfolioBroker(
        venue,
        store,
        {},
        wallet.key.hex(),
        settle_seconds=0,
        journal=journal,
        profile=profile,
        account_source_reader=object(),
    )
    candidate = SimpleNamespace(id=risk.intent.intent_id, instrument="BTCUSD", side="LONG")
    instrument = Instrument("BTCUSD", D("0.001"), D("0.001"), D("0.01"), D("1"), True, 30)

    async def enter(*, quantity=None, leverage=7):
        return await broker.enter(
            candidate,
            quantity if quantity is not None else D(str(risk.quantity)),
            await venue.book("BTCUSD"),
            instrument,
            D("95"),
            D("105"),
            leverage,
            decision=risk,
        )

    yield SimpleNamespace(b=broker, v=venue, j=journal, enter=enter, risk=risk, store=store, profile=profile)
    broker.release()


def runner_trade(s, fill):
    return {
        "id": fill["order_id"],
        "risk_trade_id": s.risk.trade_id,
        "risk_decision_id": s.risk.decision_id,
        "symbol": "BTCUSD",
        "side": "LONG",
        "quantity": str(fill["quantity"]),
        "stop": "95",
    }


async def test_unqualified_bracket_blocks_before_reserving_or_dispatching(system):
    s = system
    s.v.native_protection_unavailable = EVEDEX_NATIVE_PROTECTION_UNAVAILABLE
    assert await s.enter() is None
    assert s.v.leverages == s.v.sent == s.j.active_trades() == []
    s.store.journal.assert_called_with("entry_skipped", reason=EVEDEX_NATIVE_PROTECTION_UNAVAILABLE)


async def test_unqualified_bracket_keeps_owned_close_available_without_rearming(system):
    s = system
    trade = runner_trade(s, await s.enter())
    s.v.native_protection_unavailable = EVEDEX_NATIVE_PROTECTION_UNAVAILABLE
    # Both parent-linked, full-size native triggers can be active even on a venue
    # that later executes them in the same direction as the opening order.
    assert len(s.v.tpsl) == 2
    assert EVEDEX_NATIVE_PROTECTION_UNAVAILABLE in await s.b.foreign_exposure({"BTCUSD"})
    assert not await s.b.ensure_stop(trade)
    s.v.tpsl.clear()
    assert await s.b.position_open(trade)
    assert not await s.b.ensure_stop(trade)
    assert not await s.b.move_stop(trade, D("96"))
    assert s.v.tpsl == {}
    original = s.v.held["BTCUSD"]
    quantity = original.quantity
    s.v.held["BTCUSD"] = Position("BTCUSD", "BUY", 2 * quantity, D("100.3"))
    with pytest.raises(portfolio.NeedsOperator, match="differs from the owned entry"):
        await s.b.position_open(trade)
    assert D(s.j.trade(s.risk.trade_id)["quantity"]) == quantity
    s.v.held["BTCUSD"] = original
    await s.b.close(trade, await s.v.book("BTCUSD"), "OPERATOR_CLOSE")
    assert s.v.held == {}


@pytest.mark.parametrize("side", ["BUY", "SELL"])
async def test_production_wire_cannot_open_or_send_full_size_native_trigger(side):
    api = Evedex(Mock())
    api._request = AsyncMock(return_value={"id": "accepted"})
    for kind in ("take-profit", "stop-loss"):
        trigger = {"instrument": "OPUSD", "side": side, "type": kind, "quantity": "0"}
        for send, body in (
            (api.post_limit_order, {"side": side, "tpsl": [trigger]}),
            (api.post_market_order, {"side": side}),
            (api.post_tpsl, trigger),
        ):
            with pytest.raises(EvedexError, match="not qualified"):
                await send(body)
    api._request.assert_not_awaited()
    body = {"instrument": "OPUSD", "quantity": "1"}
    assert await api.post_close(body) == {"id": "accepted"}
    api._request.assert_awaited_once_with(
        "POST", f"{TRADING}/api/v2/position/OPUSD/close", private=True, body=body
    )
    await api.cancel_tpsl("OPUSD", "existing")
    api._request.assert_awaited_with("DELETE", f"{TRADING}/api/tpsl/OPUSD/existing", private=True)


@pytest.mark.parametrize("lost_ack", [False, True])
async def test_partial_gtc_entry_cancel_protect_management_manual_settlement(system, lost_ack):
    s = system
    await s.b.reconcile_start([], None)
    assert await s.b.prepare_admission(set()) == D(100)
    s.v.response, s.v.drop_ack = "PARTIALLY_FILLED", lost_ack
    fill = await s.enter()
    assert fill["protected"] and fill["quantity"] == D("0.0125")
    assert s.v.leverages == [("BTCUSD", 7)]
    assert len(s.v.sent) == 1 and s.v.sent[0]["limitPrice"] == "100.51"
    assert s.v.sent[0]["quantity"] == "0.025" and "cashQuantity" not in s.v.sent[0]
    assert "timeInForce" not in s.v.sent[0]
    assert not s.j.unresolved_effects() and not await s.v.open_orders()
    trade = runner_trade(s, fill)
    assert await s.b.move_stop(trade, D(97))
    assert await s.b.partial_close(trade, await s.v.book("BTCUSD"), D("0.0025")) == D("101.23")
    assert s.j.active_trade("BTCUSD")["quantity"] == "0.0100"
    s.v.held.clear()  # An unobserved external/manual exit.
    assert await s.b.settle(trade) == {"exit_origin": "unknown", "net_pnl": None, "pnl_basis": "unknown"}
    assert not s.j.active_trades() and not s.v.tpsl


async def test_owned_operator_close_records_origin_and_is_idempotent(system):
    s = system
    trade = runner_trade(s, await s.enter())
    await s.b.close(trade, await s.v.book("BTCUSD"), "OPERATOR_CLOSE")
    assert (await s.b.settle(trade))["exit_origin"] == "operator"
    assert (await s.b.settle(trade))["exit_origin"] == "operator"
    assert len([e for e in s.j.effects(s.risk.trade_id) if e["kind"] == "CLOSE"]) == 1


@pytest.mark.parametrize("full", [True, False])
@pytest.mark.parametrize("status", ["CANCELED", "EXPIRED"])
async def test_exact_terminal_unfilled_exit_allows_a_fresh_attempt(system, monkeypatch, full, status):
    s = system
    trade = runner_trade(s, await s.enter())
    book = await s.v.book("BTCUSD")
    send = s.v.post_close

    async def cancel_without_fills(body):
        record = {**body, "status": status, "unFilledQuantity": body["quantity"], "side": "SELL"}
        s.v.records[body["id"]] = record
        return record

    monkeypatch.setattr(s.v, "post_close", cancel_without_fills)
    if full:
        with pytest.raises(portfolio.CloseUnfilled):
            await s.b.close(trade, book, "TIMEOUT")
    else:
        assert await s.b.partial_close(trade, book, D(".005")) is None
    size = D(trade["quantity"])
    assert s.v.held["BTCUSD"].quantity == D(s.j.active_trade("BTCUSD")["quantity"]) == size
    await s.b.reconcile_start([trade], None)
    monkeypatch.setattr(s.v, "post_close", send)
    if full:
        await s.b.close(trade, book, "TIMEOUT")
        assert not s.v.held
    else:
        assert await s.b.partial_close(trade, book, D(".005"))
        assert s.v.held["BTCUSD"].quantity == size - D(".005")
    exits = [e for e in s.j.effects(s.risk.trade_id) if e["kind"] in {"PARTIAL_CLOSE", "CLOSE"}]
    assert [e["status"] for e in exits] == ["REJECTED", "ACCEPTED"]
    assert exits[0]["request"]["id"] != exits[1]["request"]["id"]


async def test_partial_close_resynchronizes_stale_runner_quantity_before_another_target(system):
    s = system
    trade = runner_trade(s, await s.enter())
    before = trade["quantity"]
    book = await s.v.book("BTCUSD")
    assert await s.b.partial_close(trade, book, D(".005"))
    trade["quantity"] = before  # crash after the journal confirmed this fill
    assert await s.b.partial_close(trade, book, D(".005")) is None
    assert D(trade["quantity"]) == s.v.held["BTCUSD"].quantity
    assert [e["kind"] for e in s.j.effects(s.risk.trade_id)].count("PARTIAL_CLOSE") == 1


async def test_refused_size_leverage_foreign_position_or_protection_never_sends(system):
    s = system
    for kwargs in ({"quantity": D(1)}, {"leverage": 31}):
        with pytest.raises(portfolio.NeedsOperator):
            await s.enter(**kwargs)
    s.v.held["ETHUSD"] = Position("ETHUSD", "BUY", D(1), D(42))
    with pytest.raises(portfolio.NeedsOperator, match="unowned"):
        await s.enter()
    s.v.held.clear()
    trade = runner_trade(s, await s.enter())
    foreign = {
        "id": "foreign",
        "type": "stop-loss",
        "side": "BUY",
        "order": "other-trade",
        "instrument": "BTCUSD",
        "price": "96",
        "quantity": "0",
        "status": "active",
    }
    s.v.tpsl["foreign"] = foreign
    s.v.held.clear()
    with pytest.raises(portfolio.NeedsOperator, match="foreign"):
        await s.b.settle(trade)
    assert s.v.tpsl["foreign"] == foreign and len(s.v.sent) == 1


async def test_terminal_zero_fill_and_missing_order_preserve_idempotency(system):
    s = system
    s.v.response = "NEW"
    assert await s.enter() is None
    assert s.j.trade(s.risk.trade_id)["state"] == "REFUSED"
    assert not await s.v.open_orders()


async def test_lost_ack_and_no_exact_order_prevents_second_dispatch(system, monkeypatch):
    s = system
    s.v.drop_ack = True

    async def missing(_):
        return None

    monkeypatch.setattr(s.v, "order", missing)
    with pytest.raises(portfolio.NeedsOperator, match="reconciliation"):
        await s.enter()
    with pytest.raises(portfolio.NeedsOperator):
        await s.enter()
    assert len(s.v.sent) == 1 and s.j.unresolved_effects()


def decision_for_symbol(risk, symbol):
    data = risk.model_dump(mode="python")
    signal = next(s for s, v in PROD_SYMBOL_MAP.items() if v == symbol)
    intent = {**data["intent"], "symbol": signal, "intent_id": None}
    route = {**data["review"]["route"], "intent": intent, "route_id": None, "intent_sha256": None}
    review = {**data["review"], "intent": intent, "intent_sha256": None, "route": route, "review_id": None}
    venue = {**data["venue_quality"], "measurement_id": None, "symbol": symbol}
    data.update(
        intent=intent,
        review=review,
        venue_quality=venue,
        venue_symbol=symbol,
        decision_id=None,
        trade_id=None,
    )
    return RiskTradeDecisionV1.model_validate(data)


async def test_two_instruments_close_one_keeps_the_other_protected(system):
    s = system
    btc = runner_trade(s, await s.enter())
    other = decision_for_symbol(s.risk, "ETHUSD")
    candidate = SimpleNamespace(id=other.intent.intent_id, instrument="ETHUSD", side="LONG")
    instrument = Instrument("ETHUSD", D("0.001"), D("0.001"), D("0.01"), D("1"), True, 30)
    fill = await s.b.enter(
        candidate,
        D(str(other.quantity)),
        await s.v.book("ETHUSD"),
        instrument,
        D(95),
        D(105),
        7,
        decision=other,
    )
    assert len(s.j.active_trades()) == 2 and not await s.b.foreign_exposure({"BTCUSD", "ETHUSD"})
    await s.b.close(btc, await s.v.book("BTCUSD"), "TIMEOUT")
    assert (await s.b.settle(btc))["exit_origin"] == "system"
    assert list(s.v.held) == ["ETHUSD"] and not await s.b.foreign_exposure({"ETHUSD"})
    assert {r["order"] for r in s.v.tpsl.values()} == {fill["order_id"]}


async def test_lost_close_ack_resolves_by_exact_order_without_resubmit(system, monkeypatch):
    s = system
    trade = runner_trade(s, await s.enter())
    post = s.v.post_close

    async def lost(body):
        await post(body)
        raise Unknown("lost close ack")

    monkeypatch.setattr(s.v, "post_close", lost)
    await s.b.close(trade, await s.v.book("BTCUSD"), "TIMEOUT")
    assert not s.j.unresolved_effects()
    assert (await s.b.settle(trade))["exit_origin"] == "system"
    assert len([e for e in s.j.effects(s.risk.trade_id) if e["kind"] == "CLOSE"]) == 1


async def test_expired_risk_or_operator_stop_skips_without_latching(system, monkeypatch):
    s = system
    s.store.state["halted"] = "operator"
    assert await s.enter() is None and not s.v.leverages
    s.store.state.clear()
    monkeypatch.setattr(portfolio, "_now", lambda: s.risk.venue_quality.expires_at_ms + 1)
    assert await s.enter() is None and not s.v.sent and not s.j.active_trades()


async def test_crash_after_durable_open_before_runner_save_closes_proven_orphan_once(system):
    s = system
    fill = await s.enter()
    assert len(s.v.tpsl) == 2 and s.j.active_trade("BTCUSD")["entry_order_id"] == fill["order_id"]
    await s.b.reconcile_start([], None)
    await s.b.reconcile_start([], None)
    assert not s.j.active_trades() and not s.v.held and not s.v.tpsl
    settled = s.j.trade(s.risk.trade_id)
    assert settled["exit_origin"] == "unknown" and settled["pnl_basis"] == "unknown"
    assert [e["kind"] for e in s.j.effects(s.risk.trade_id)].count("CLOSE") == 1


@pytest.mark.parametrize("leftover", [None, "resting", "protection", "unknown", "read_failure"])
async def test_full_emergency_exit_settles_before_runner_records_entry(system, monkeypatch, leftover):
    s = system
    post_close = s.v.post_close

    async def unverified(item, *, position=None):
        assert position is not None and position.instrument == item["symbol"]
        return False

    async def unavailable(symbol):
        raise portfolio.EvedexError("protection read timed out")

    async def close(body):
        row = await post_close(body)
        s.v.tpsl.clear()  # EVEDEX cancels attached protection when the position closes.
        if leftover == "resting":
            s.v.records["foreign"] = {"instrument": "BTCUSD", "status": "NEW"}
        elif leftover == "protection":
            s.v.tpsl["foreign"] = {"id": "foreign", "instrument": "BTCUSD", "status": "active"}
        elif leftover == "read_failure":
            monkeypatch.setattr(s.v, "active_tpsl", unavailable)
        elif leftover == "unknown":
            effect = s.j.prepare_effect(
                trade_id=s.risk.trade_id, kind="STOP", operation_key="stop", request={}
            )
            s.j.finish_effect(effect, "UNKNOWN")
        return row

    monkeypatch.setattr(s.b, "_ensure_entry_protection", unverified)
    monkeypatch.setattr(s.v, "post_close", close)
    with pytest.raises(portfolio.NeedsOperator, match="protection could not be verified"):
        await s.enter()
    settled = s.j.trade(s.risk.trade_id)
    if leftover is None:
        assert settled["state"] == "CLOSED" and settled["exit_origin"] == "system"
        assert settled["net_pnl"] is None and settled["pnl_basis"] == "unknown"
        await s.b.reconcile_start([], None)
    else:
        assert settled["state"] == "OPEN" and settled["exit_origin"] is None
    assert [e["kind"] for e in s.j.effects(s.risk.trade_id)].count("CLOSE") == 1


async def test_missing_runner_and_mismatched_venue_never_closes_other_exposure(system):
    s = system
    await s.enter()
    s.v.held["BTCUSD"] = Position("BTCUSD", "BUY", D(2), D("100.51"))
    with pytest.raises(portfolio.NeedsOperator):
        await s.b.reconcile_start([], None)
    assert not [e for e in s.j.effects(s.risk.trade_id) if e["kind"] == "CLOSE"]


async def test_sdk_child_rows_without_order_are_bound_through_exact_order_list(system):
    s = system
    s.v.omit_parent = True
    trade = runner_trade(s, await s.enter())
    assert not any("order" in r for r in s.v.tpsl.values())
    assert len(s.j.attached(s.risk.trade_id)) == 2 and await s.b.position_open(trade)
    await s.b.close(trade, await s.v.book("BTCUSD"), "TIMEOUT")
    await s.b.settle(trade)
    assert not s.v.tpsl


@pytest.mark.parametrize("projection_lags", [False, True])
async def test_parent_is_found_across_position_versions_and_links_exact_ids(
    system, monkeypatch, projection_lags
):
    s = system
    s.v.omit_parent = True
    sdk_projection = s.v.order_with_protections
    reader = Evedex(Mock())
    history_reads = []

    async def history(method, url, *, private, params):
        assert method == "GET" and url == f"{TRADING}/api/order" and private
        assert params["withTpSL"] == "yes" and params["instrument"] == "BTCUSD"
        history_reads.append(dict(params))
        order_id = s.v.sent[0]["id"]
        parent = await sdk_projection("BTCUSD", order_id)
        parent["positionVersions"] = [3]
        if projection_lags and len(history_reads) == 1:
            parent["tpslList"] = []
        rows = [parent] if params.get("version") in {None, 3} else []
        return {"count": len(rows), "list": rows}

    monkeypatch.setattr(reader, "_request", history)
    monkeypatch.setattr(s.v, "order_with_protections", reader.order_with_protections)
    assert (await s.enter())["protected"]
    assert len(history_reads) == 1 + projection_lags
    assert [e["kind"] for e in s.j.effects(s.risk.trade_id)] == ["LEVERAGE", "ENTRY"]
    assert {p["venue_id"] for p in s.j.attached(s.risk.trade_id)} == set(s.v.tpsl)


@pytest.mark.parametrize(
    ("mode", "reads", "reason"),
    [
        ("different_ids", 2, "link active protection IDs"),
        ("incomplete", 1, "link active protection IDs"),
        ("waitOrder", 1, "link active protection IDs"),
        ("wrong_account", 1, "authenticated account"),
    ],
)
async def test_unverified_children_close_only_the_owned_fill(system, monkeypatch, mode, reads, reason):
    s = system
    s.v.omit_parent = True
    submit = s.v.post_limit_order
    sdk_projection = s.v.order_with_protections
    history_reads = []

    async def accept(body):
        result = await submit(body)
        if mode == "incomplete":
            s.v.tpsl.popitem()
        elif mode == "waitOrder":
            next(iter(s.v.tpsl.values()))["status"] = "waitOrder"
        return result

    async def history(symbol, order_id):
        history_reads.append(order_id)
        parent = await sdk_projection(symbol, order_id)
        if mode == "wrong_account":
            parent["user"] = "other-account"
        else:
            parent["tpslList"] = [{**r, "id": "foreign-" + r["id"]} for r in parent["tpslList"]]
        return parent

    monkeypatch.setattr(s.v, "post_limit_order", accept)
    monkeypatch.setattr(s.v, "order_with_protections", history)
    with pytest.raises(portfolio.NeedsOperator, match=reason):
        await s.enter()
    assert len(history_reads) == reads and len(s.v.sent) == 1
    assert not s.j.attached(s.risk.trade_id) and not s.v.held
    assert [e["kind"] for e in s.j.effects(s.risk.trade_id)] == ["LEVERAGE", "ENTRY", "CLOSE"]


async def test_start_reinstalls_both_missing_protections_and_poll_keeps_tight_stop(system):
    s = system
    trade = runner_trade(s, await s.enter())
    s.v.tpsl.clear()
    await s.b.reconcile_start([trade], None)
    assert {r["type"] for r in s.v.tpsl.values()} == {"stop-loss", "take-profit"}
    await s.b.move_stop(trade, D(97))
    trade["stop"] = "95"  # process crashed before its runner JSON captured the tighter venue stop
    assert await s.b.position_open(trade) and D(trade["stop"]) == 97
    s.v.tpsl.clear()  # an already-issued protective order cannot be replayed on missing evidence
    assert not await s.b.position_open(trade)
    assert not s.v.held
    assert (await s.b.settle(trade))["exit_origin"] == "unknown"


@pytest.mark.parametrize(
    "identity",
    [
        {},
        {"id": "position"},
        {"user": "test-account"},
        {"id": " ", "user": "test-account"},
        {"id": "position", "user": {}},
        {"id": "position", "user": True},
    ],
)
async def test_native_position_reads_require_position_and_account_identity(system, monkeypatch, identity):
    s = system
    reader = Evedex(Mock())

    async def get(method, url, *, private, params):
        assert method == "GET" and url == f"{TRADING}/api/position" and private
        return {
            "list": [
                {
                    **identity,
                    "instrument": "BTCUSD",
                    "quantity": "0.025",
                    "side": "BUY",
                    "avgPrice": "100.51",
                    "tpslList": [],
                }
            ]
        }

    monkeypatch.setattr(reader, "_request", get)
    monkeypatch.setattr(s.v, "positions", reader.positions)
    with pytest.raises(portfolio.EvedexError, match="incomplete open position"):
        await s.enter()
    assert not s.v.sent and not s.v.leverages and not s.j.active_trades()


@pytest.fixture
def position_projection(system, monkeypatch):
    """Pinned SDK projections: parent empty, full-position children have no parent/order."""
    s = system
    s.v.omit_parent = True
    sdk_parent = s.v.order_with_protections
    api = Evedex(Mock())
    config = {"fault": "", "reads": []}

    async def history(symbol, order_id):
        record = await sdk_parent(symbol, order_id)
        return {**record, "tpslList": []}

    async def order_detail(order_id):
        versions = (
            [5]
            if config["fault"] == "wrong_close_version" and s.v.records[order_id]["type"] == "MARKET"
            else [4]
        )
        return {**s.v.records[order_id], "user": "test-account", "positionVersions": versions}

    async def get(method, url, *, private, params):
        assert method == "GET" and private
        fault = config["fault"]
        if url == f"{TRADING}/api/position":
            assert params == {"withTpSL": "yes"}
            positions = []
            for pos in s.v.held.values():
                children = [dict(r) for r in s.v.tpsl.values() if r["instrument"] == pos.instrument]
                if fault == "missing":
                    children.clear()
                if fault == "swapped":
                    children[0]["id"] = "different"
                if fault == "mismatch":
                    children[0]["price"] = "17"
                positions.append(
                    dict(
                        id="replacement" if fault == "replacement" else "position",
                        user="foreign" if fault == "account" else "test-account",
                        instrument=pos.instrument,
                        side=pos.side,
                        quantity=str(pos.quantity),
                        avgPrice=str(pos.avg_price),
                        tpslList=children,
                    )
                )
            return {"list": positions}
        config["reads"].append(url)
        assert params["version"] == 4 and params["instrument"] == "BTCUSD"
        if url == f"{TRADING}/api/position/history":
            rows = (
                [{"instrument": "BTCUSD", "version": 4, "closeAt": "2026-11-19T10:10:00Z"}]
                if fault == "closed" or not s.v.held
                else []
            )
            # The real filtered history returns count=1 even for nonexistent versions.
            return {"count": 1, "list": rows}
        assert url == f"{TRADING}/api/order"
        rows = [{**r, "user": "test-account"} for r in s.v.records.values()]
        if fault == "foreign_fill":
            rows.append({**rows[0], "id": "other"})
        return {"count": len(rows), "list": rows}

    monkeypatch.setattr(api, "_request", get)
    monkeypatch.setattr(s.v, "order", order_detail)
    monkeypatch.setattr(s.v, "positions", api.positions)
    monkeypatch.setattr(s.v, "position_version_orders", api.position_version_orders, raising=False)
    monkeypatch.setattr(s.v, "position_version_closed", api.position_version_closed, raising=False)
    monkeypatch.setattr(s.v, "order_with_protections", history)
    return config


@pytest.mark.parametrize("entry_status", ["FILLED", "PARTIALLY_FILLED"])
async def test_position_cover_is_read_only_on_entry_restart_tightening_and_close(
    system, position_projection, entry_status
):
    s = system
    s.v.response = entry_status
    trade = runner_trade(s, await s.enter())
    if entry_status == "PARTIALLY_FILLED":
        assert [e["kind"] for e in s.j.effects(s.risk.trade_id)].count("CANCEL_ENTRY") == 1
    assert not s.j.attached(s.risk.trade_id)
    original = set(s.v.tpsl)
    s.b._position_entries.clear()  # process restart must independently reconstruct cover
    await s.b.reconcile_start([trade], None)
    assert await s.b.prepare_admission({"BTCUSD"}) == D(100)
    assert await s.b.position_open(trade) and await s.b.move_stop(trade, D(97))
    assert original < set(s.v.tpsl) and not s.j.attached(s.risk.trade_id)
    assert await s.b.position_open(trade)
    await s.b.close(trade, await s.v.book("BTCUSD"), "TIMEOUT")
    with pytest.raises(portfolio.NeedsOperator):
        await s.b.settle(trade)  # an external protection lingering after flatness cannot be cancelled
    assert original.issubset(s.v.tpsl)
    s.v.tpsl.clear()  # real venue cancels the full-position pair when its generation closes
    await s.b.settle(trade)
    assert not any(e["kind"] in {"CANCEL_STOP", "CANCEL_TAKE"} for e in s.j.effects(s.risk.trade_id))


async def test_position_coverage_rechecks_generation_before_reducing_same_price_exposure(
    system, position_projection
):
    s = system
    trade = runner_trade(s, await s.enter())
    assert await s.b.partial_close(trade, await s.v.book("BTCUSD"), D("0.005"))
    reads_before = len(position_projection["reads"])
    assert await s.b.position_open(trade)
    assert len(position_projection["reads"]) - reads_before == 2
    # An externally closed generation cannot authorize a reduction of an identical new position.
    position_projection["fault"] = "closed"
    with pytest.raises(portfolio.PositionIdentityError, match="already closed"):
        await s.b.close(trade, await s.v.book("BTCUSD"), "TIMEOUT")
    assert s.v.held and not any(e["kind"] == "CLOSE" for e in s.j.effects(s.risk.trade_id))


@pytest.mark.parametrize("side", ["LONG", "SHORT"])
async def test_two_scale_outs_then_close_only_reduce_the_owned_generation(system, position_projection, side):
    s = system
    await s.b.reconcile_start([], None)
    entry_id, trade_id = "owned-entry", "existing-trade"
    buy = side == "LONG"
    stop, take = (D(95), D(105)) if buy else (D(105), D(95))
    s.j.reserve_entry(
        trade_id=trade_id,
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
        "id": entry_id,
        "instrument": "BTCUSD",
        "side": "BUY" if buy else "SELL",
        "quantity": ".1",
        "limitPrice": "100",
        "tpsl": [
            {"type": k, "side": "SELL" if buy else "BUY", "quantity": "0", "price": str(p)}
            for k, p in (("stop-loss", stop), ("take-profit", take))
        ],
    }
    effect = s.j.prepare_effect(
        trade_id=trade_id, kind="ENTRY", operation_key="enter", request={"id": entry_id, "price": "100"}
    )
    await s.v.post_limit_order(body)
    s.j.finish_effect(effect, "ACCEPTED", entry_id)
    s.j.opened(trade_id, entry_order_id=entry_id, quantity=D(".1"), price=D(100))
    trade = {
        "risk_trade_id": trade_id,
        "risk_decision_id": "decision",
        "id": entry_id,
        "symbol": "BTCUSD",
        "side": side,
        "quantity": ".1",
        "stop": str(stop),
    }
    book = await s.v.book("BTCUSD")
    assert await s.b.move_stop(trade, D(99) if buy else D(101))
    with pytest.raises(ValueError, match="less risk"):
        await s.b.move_stop(trade, stop)
    for qty, remaining in ((D(".025"), D(".075")), (D(".035"), D(".04"))):
        assert await s.b.partial_close(trade, book, qty)
        assert s.v.held["BTCUSD"].quantity == D(s.j.trade(trade_id)["quantity"]) == remaining
    await s.b.close(trade, book, "TIMEOUT")
    assert not s.v.held
    exits = [e for e in s.j.effects(trade_id) if e["kind"] in {"PARTIAL_CLOSE", "CLOSE"}]
    assert [e["kind"] for e in exits] == ["PARTIAL_CLOSE", "PARTIAL_CLOSE", "CLOSE"]
    assert all(e["request"]["position_version"] == 4 for e in exits)
    assert all(s.v.records[e["venue_id"]]["side"] == ("SELL" if buy else "BUY") for e in exits)


@pytest.mark.parametrize("fault", ["wrong_close_version", "replacement"])
async def test_partial_close_rejects_fill_or_remainder_from_another_generation(
    system, position_projection, monkeypatch, fault
):
    s = system
    trade = runner_trade(s, await s.enter())
    original_quantity = D(trade["quantity"])
    send = s.v.post_close

    async def swap_after_dispatch(body):
        receipt = await send(body)
        position_projection["fault"] = fault
        return receipt

    monkeypatch.setattr(s.v, "post_close", swap_after_dispatch)
    with pytest.raises(portfolio.NeedsOperator, match="cannot be confirmed"):
        await s.b.partial_close(trade, await s.v.book("BTCUSD"), D(".005"))
    assert D(s.j.trade(s.risk.trade_id)["quantity"]) == original_quantity
    s.b._position_entries.clear()
    with pytest.raises(portfolio.NeedsOperator, match="cannot be confirmed"):
        await s.b.reconcile_start([trade], None)
    assert [e["kind"] for e in s.j.effects(s.risk.trade_id)].count("PARTIAL_CLOSE") == 1


@pytest.mark.parametrize(
    ("fault", "reason"),
    [
        ("missing", "position lists no protection IDs"),
        ("swapped", "protection IDs differ"),
        ("mismatch", "does not match the initial"),
        ("account", "authenticated open position does not match"),
        ("closed", "generation is already closed"),
        ("foreign_fill", "fills outside the owned entry"),
    ],
)
async def test_position_projection_ambiguity_closes_fill_without_adopting_or_deleting(
    system, position_projection, fault, reason
):
    s = system
    position_projection["fault"] = fault
    with pytest.raises(portfolio.NeedsOperator, match=reason):
        await s.enter()
    assert len(s.v.tpsl) == 2 and not s.j.attached(s.risk.trade_id)
    kinds = [e["kind"] for e in s.j.effects(s.risk.trade_id)]
    if fault in {"closed", "foreign_fill", "account"}:
        assert s.v.held and kinds == ["LEVERAGE", "ENTRY"]
    else:
        assert not s.v.held and kinds == ["LEVERAGE", "ENTRY", "CLOSE"]


async def test_venue_clock_leading_host_allows_fresh_approval_and_expiration_does_not_halt(
    system, monkeypatch
):
    s = system
    # Both venue quote and the signed Risk timestamp come from the exchange clock.
    monkeypatch.setattr(portfolio, "_now", lambda: s.risk.decided_at_ms - 850)
    assert (await s.enter())["protected"]
    assert not s.store.state.get("halted")


async def test_large_clock_lead_skips_without_sending(system, monkeypatch):
    s = system
    monkeypatch.setattr(portfolio, "_now", lambda: s.risk.decided_at_ms - 3000)
    assert await s.enter() is None and not s.v.leverages and not s.j.active_trades()


async def test_admission_requires_current_tightened_stop_and_correct_target(system):
    s = system
    trade = runner_trade(s, await s.enter())
    before = dict(s.v.tpsl)
    await s.b.move_stop(trade, D(97))
    tight = dict(s.v.tpsl)
    s.v.tpsl = before  # only the old, looser stop remains
    assert await s.b.foreign_exposure({"BTCUSD"})
    s.v.tpsl = {key: row for key, row in tight.items() if row["type"] != "take-profit"}
    with pytest.raises(portfolio.NeedsOperator, match="confirmed stop and take"):
        await s.b.prepare_admission({"BTCUSD"})
    assert len(s.v.sent) == 1


def refused_effect(journal):
    with closing(sqlite3.connect(journal.path.as_uri() + "?mode=ro", uri=True)) as db:
        rows = db.execute("SELECT payload FROM events WHERE event='EFFECT_RESULT'").fetchall()
    return next(row for (value,) in rows if (row := json.loads(value))["status"] == "REJECTED")


@pytest.mark.parametrize("cause", ["local_deadline", "local_operator_stop"])
async def test_refusal_after_durable_preparation_records_local_cause_without_http(system, monkeypatch, cause):
    s = system
    prepare = s.j.prepare_effect

    def before_dispatch(**kwargs):
        effect_id = prepare(**kwargs)
        if kwargs["kind"] == "ENTRY":
            if cause == "local_deadline":
                monkeypatch.setattr(portfolio, "_now", lambda: s.risk.venue_quality.expires_at_ms + 1)
            else:
                s.store.state["halted"] = True
        return effect_id

    monkeypatch.setattr(s.j, "prepare_effect", before_dispatch)
    assert await s.enter() is None and not s.v.sent
    result = refused_effect(s.j)
    assert result["reason"] == cause and "http_status" not in result
    entry = next(e for e in s.j.effects(s.risk.trade_id) if e["kind"] == "ENTRY")
    assert entry["request"]["venue_checked_at_ms"] < entry["request"]["expires_at_ms"]


@pytest.mark.parametrize(
    ("label", "reason"),
    [
        ("invalid_signature_error", "venue_invalid_signature"),
        ("unreviewed_sensitive_response_value", "venue_other"),
    ],
)
async def test_http_refusal_records_safe_reason_without_venue_response(system, monkeypatch, label, reason):
    s = system

    async def reject(body):
        s.v.sent.append(body)
        raise Rejected("refused", status=422, body=json.dumps({"label": label, "detail": "private-response"}))

    monkeypatch.setattr(s.v, "post_limit_order", reject)
    assert await s.enter() is None and len(s.v.sent) == 1
    row = refused_effect(s.j)
    assert row["reason"] == reason and row["http_status"] == 422
    assert "private-response" not in str(row) and label not in row.values()


@pytest.mark.parametrize("reuses_id", [True, False])
async def test_stop_move_preserves_the_new_live_order_after_exchange_replacement(system, reuses_id):
    s = system
    trade = runner_trade(s, await s.enter())
    old_key = next(key for key, row in s.v.tpsl.items() if row["type"] == "stop-loss")
    original = s.v.post_tpsl

    async def replace(body):
        assert "order" in body and body["order"] is None
        s.v.tpsl.pop(old_key)
        if not reuses_id:
            return await original(body)
        row = {**body, "status": "active", "id": old_key}
        s.v.tpsl[old_key] = row
        return row

    s.v.post_tpsl = replace
    assert await s.b.move_stop(trade, D("97"))
    active = list(s.v.tpsl.values())
    assert {r["type"] for r in active} == {"stop-loss", "take-profit"}
    assert D(next(r["price"] for r in active if r["type"] == "stop-loss")) == D("97")


async def test_qualified_initial_bracket_retained_when_stop_move_unproven(system):
    s = system
    s.v.native_stop_move_qualified_for = lambda symbol: False
    trade = runner_trade(s, await s.enter())
    original = dict(s.v.tpsl)
    assert await s.b.ensure_stop(trade)
    assert not await s.b.move_stop(trade, D("97"))
    assert not await s.b.ensure_stop({**trade, "stop": "97"})
    assert s.v.tpsl == original and trade["stop"] == "95"
