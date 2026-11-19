"""Portfolio integration with synthetic EVEDEX and authentic Core Risk contracts; no network."""

import hashlib
import json
import sqlite3
from contextlib import closing
from datetime import UTC, datetime, timedelta
from decimal import Decimal as D
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from kairos_core.contracts import RiskTradeDecisionV1

from kairos_execution import portfolio_broker as portfolio
from kairos_execution.portfolio_evedex import TRADING, Book, Evedex, Instrument, Position, Rejected, Unknown
from kairos_execution.portfolio_journal import PortfolioJournal
from kairos_execution.prod_universe import PROD_INSTRUMENTS, PROD_SYMBOL_MAP
from tests.test_production_lifecycle_binding import _decision

Account = pytest.importorskip("eth_account").Account


class Venue:
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
            "side": "SELL",
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
