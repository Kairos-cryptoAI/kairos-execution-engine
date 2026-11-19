from datetime import UTC, datetime, timedelta
from decimal import Decimal as D
from pathlib import Path

import pytest

from kairos_execution.portfolio_journal import (
    PortfolioAdmissionRefused,
    PortfolioJournal,
    PortfolioJournalError,
)
from kairos_execution.portfolio_performance import read_pilot_status

FUTURE = datetime(2099, 1, 1, tzinfo=UTC)
SYMBOLS = tuple(f"S{i}USD" for i in range(23))


def owner(path: Path, **kwargs) -> PortfolioJournal:
    return PortfolioJournal(path, account_id="account-one", symbols=SYMBOLS, **kwargs)


def observation(j, funding="109", equity=None, flow="0", deadline=FUTURE, when=None):
    prev = j.pilot_status()
    return j.record_observation(
        observed_at=when or datetime.now(UTC),
        funding=D(funding),
        conservative_equity=D(equity or funding),
        external_flow=D(flow),
        positions=0,
        entry_deadline_utc=deadline,
        read_digests=["a" * 64],
        baseline_at=prev["started_at"] if prev else None,
    )


def reserve(j, i=0, **kwargs):
    j.reserve_entry(
        **(
            dict(
                trade_id=f"t{i}",
                decision_id=f"d{i}",
                symbol=SYMBOLS[i],
                side="LONG",
                quantity=D(2),
                leverage=2,
                stop=D(9),
                take=D(11),
                worst_case_loss=D(".10"),
                notional=D(20),
                equity=D(109),
            )
            | kwargs
        )
    )


def open_trade(j, i=0, **kwargs):
    reserve(j, i, **kwargs)
    eid = j.prepare_effect(trade_id=f"t{i}", kind="ENTRY", operation_key="enter", request={"id": f"q{i}"})
    j.finish_effect(eid, "ACCEPTED", f"q{i}")
    j.opened(f"t{i}", entry_order_id=f"q{i}", quantity=D(2), price=D(10))


def test_lock_crash_and_exact_reconciliation(tmp_path):
    path = tmp_path / "pilot.db"
    with owner(path) as j:
        with pytest.raises(PortfolioJournalError):
            owner(path)
        observation(j)
        reserve(j)
        eid = j.prepare_effect(trade_id="t0", kind="ENTRY", operation_key="enter", request={"id": "q1"})
        with pytest.raises(PortfolioJournalError):
            j.finish_effect(eid, "ACCEPTED", "different")
        j.finish_effect(eid, "UNKNOWN", "q1")
    with owner(path) as j:
        assert len(j.unresolved_effects()) == 1
        with pytest.raises(PortfolioJournalError):
            reserve(j, 1)
        with pytest.raises(PortfolioJournalError):
            j.release_refused("t0")
        with pytest.raises(PortfolioJournalError):
            j.reconcile_effect(eid, venue_id="q2")
        j.reconcile_effect(eid, venue_id="q1")
        with pytest.raises(PortfolioJournalError):
            j.opened("t0", entry_order_id="q1", quantity=D(3), price=D(10))
        j.no_fill("t0", entry_order_id="q1")
        j.no_fill("t0", entry_order_id="q1")
        assert not j.active_trades()
    path.unlink()
    with pytest.raises(PortfolioJournalError, match="missing"):
        owner(path)


def test_account_identity_and_limit_cannot_change_on_restart(tmp_path):
    path = tmp_path / "pilot.db"
    owner(path).close()
    with pytest.raises(PortfolioJournalError):
        PortfolioJournal(path, account_id="other", symbols=SYMBOLS)
    with pytest.raises(PortfolioJournalError):
        owner(path, max_positions=9)


def test_portfolio_caps_and_ten_independent_positions(tmp_path):
    with owner(tmp_path / "pilot.db") as j:
        with pytest.raises(PortfolioJournalError):
            reserve(j)
        observation(j)
        for invalid in [dict(leverage=31), dict(worst_case_loss=D(".26")), dict(notional=D("25.01"))]:
            with pytest.raises(PortfolioJournalError):
                reserve(j, **invalid)
        for i in range(10):
            open_trade(j, i)
        assert len(j.active_trades()) == 10
        with pytest.raises(PortfolioJournalError):
            reserve(j, 10, worst_case_loss=D(".01"))
        j.closed("t0", exit_origin="operator")
        with pytest.raises(PortfolioJournalError):
            reserve(j, 10, worst_case_loss=D(".11"))
        open_trade(j, 10)
        assert read_pilot_status(j.path)["attributed_closures"] == 0


def test_partial_close_delta_once_and_daily_limit(tmp_path):
    with owner(tmp_path / "pilot.db") as j:
        observation(j)
        open_trade(j)
        op = j.prepare_effect(
            trade_id="t0", kind="PARTIAL_CLOSE", operation_key="half", request={"id": "reduce1"}
        )
        j.finish_effect(op, "UNKNOWN", "reduce1")
        with pytest.raises(PortfolioJournalError):
            j.reconcile_effect(op, venue_id="foreign-order")
        j.reconcile_effect(op, venue_id="reduce1")
        j.reduced("t0", close_order_id="reduce1", quantity=D(".8"))
        j.reduced("t0", close_order_id="reduce1", quantity=D(".8"))
        assert D(j.trade("t0")["quantity"]) == D("1.2")
        with pytest.raises(PortfolioJournalError):
            j.reduced("t0", close_order_id="reduce1", quantity=D(".4"))
        j.closed("t0", exit_origin="unknown")
        for i in range(1, 12):
            open_trade(j, i)
            j.closed(f"t{i}", exit_origin="system", pnl_basis="execution_fills", net_pnl=D("0.05"))
        with pytest.raises(PortfolioAdmissionRefused, match="daily"):
            reserve(j, 12)
        assert read_pilot_status(j.path)["attributed_closures"] == 11


def test_transfers_drawdown_and_sticky_restart(tmp_path):
    path = tmp_path / "pilot.db"
    assert read_pilot_status(path) is None
    with owner(path) as j:
        observation(j)
        status = observation(j, funding="119", flow="10", equity="118")
        assert D(status["account_result"]) == 0
        assert D(status["adverse_loss"]) == 1
        observation(j, funding="114.10", flow="10")
        with pytest.raises(PortfolioJournalError, match="loss"):
            reserve(j, worst_case_loss=D(".2"), equity=D("114.10"))
        assert observation(j, funding="114", flow="10")["stopped"]
    with owner(path) as j:
        assert observation(j, funding="120", flow="10")["stopped"]
        with pytest.raises(PortfolioJournalError):
            reserve(j)
        with pytest.raises(PortfolioJournalError):
            observation(j, deadline=datetime.now(UTC))


def test_stale_read_and_signed_entry_window(tmp_path):
    with owner(tmp_path / "pilot.db") as j:
        deadline = datetime.now(UTC) - timedelta(hours=1)
        observation(j, when=datetime.now(UTC) - timedelta(hours=25), deadline=deadline)
        with pytest.raises(PortfolioAdmissionRefused, match="fresh"):
            reserve(j)
        observation(j, deadline=deadline)
        with pytest.raises(PortfolioAdmissionRefused, match="window"):
            reserve(j)
