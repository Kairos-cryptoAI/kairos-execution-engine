from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal as D
from unittest.mock import AsyncMock

import pytest

from kairos_execution.one_canary_account import (
    CanaryAccountError,
    CanaryAccountObservation,
    CanaryExternalFlows,
    RestReadDigest,
)
from kairos_execution.portfolio_journal import PortfolioJournal
from kairos_execution.portfolio_performance import observe_pilot


def observation():
    now = datetime.now(UTC)
    digest = RestReadDigest("/api/user/me", now, now, "b" * 64)
    return CanaryAccountObservation(
        "expected", now - timedelta(days=10), now, now, D("109"), D("109"), D(0), 0, 0, 0, 0, (), (digest,)
    )


async def test_pilot_requires_verified_flat_account(tmp_path):
    source = AsyncMock()
    with PortfolioJournal(tmp_path / "pilot.db", account_id="local", symbols=["TSTUSD"]) as journal:
        deadline = datetime.now(UTC) + timedelta(days=2)
        args = dict(expected_remote_account_id="expected", entry_deadline_utc=deadline)
        for invalid in (
            dict(account_id="other"),
            dict(pending_withdrawals=1),
            dict(nonzero_positions=1),
            dict(available_usdt=D("99")),
            dict(reads=()),
        ):
            source.observe.return_value = replace(observation(), **invalid)
            with pytest.raises(CanaryAccountError):
                await observe_pilot(journal, source, **args)
            assert not journal.pilot_status()
        source.observe.return_value = observation()
        assert (await observe_pilot(journal, source, **args))["baseline"] == "109"
        source.external_flows_since.assert_not_awaited()
        since = datetime.fromisoformat(journal.pilot_status()["started_at"])
        current = replace(
            observation(),
            funding_usdt=D("129.50"),
            available_usdt=D("120"),
            nonzero_positions=1,
            adverse_unrealized_usdt=D("-1"),
        )
        source.observe.return_value = current
        before = CanaryExternalFlows(since, current.started_at, D("20"), D(0), (), current.reads)
        after = replace(before, until=current.finished_at + timedelta(microseconds=1))
        source.external_flows_since.side_effect = [before, replace(after, deposits_usdt=D("30"))]
        with pytest.raises(CanaryAccountError, match="transfers changed"):
            await observe_pilot(journal, source, **args)
        source.external_flows_since.side_effect = [before, after]
        status = await observe_pilot(journal, source, **args)
        assert D(status["account_result"]) == D(".50")
        assert D(status["adverse_loss"]) == D(".50")
        assert status["open_positions"] == 1
