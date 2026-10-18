from __future__ import annotations

from datetime import UTC, datetime

import pytest
from kairos_persistence.canary_session import SYMBOLS, CanaryScope, digest

from kairos_execution.readonly_health import AccountEvidence, read_readonly_health

NOW_MS = 1_800_000_000_000


def scope() -> CanaryScope:
    return CanaryScope(
        environment="paper-dev",
        account_id="kairos-paper-dev-health-test",
        remote_account_id="dev-account-7",
        config_sha256="a" * 64,
        recorder_code_sha256="b" * 64,
    )


class Snapshot:
    exchange = "evedex"
    account_id = "kairos-paper-dev-health-test"
    reconciled = True
    positions: list[object] = []
    open_order_ids: list[str] = []
    captured_at = datetime.fromtimestamp(NOW_MS / 1000, UTC)


class Pool:
    def __init__(self, *, healthy_symbols: int = 5, scope_override=None, mutations=None):
        self.queries: list[str] = []
        self.healthy_symbols = healthy_symbols
        self.scope_override = scope_override
        self.mutations = mutations or {
            "effects": 0,
            "trades": 0,
            "dispatch_claims": 0,
            "pending_effects": 0,
            "pending_trades": 0,
        }

    async def fetchrow(self, query, *args):
        self.queries.append(query)
        if "paper_readonly_runs" in query:
            return {
                "scope": self.scope_override or scope().model_dump(mode="json"),
                "scope_sha256": digest(scope().model_dump(mode="json")),
                "state": "RECORDING",
                "database_instance_id": "same-instance",
                "current_instance_id": "same-instance",
            }
        if "closed_bar.v1" in query:
            return {
                "db_now_ms": NOW_MS,
                "expected_symbols": len(SYMBOLS),
                "healthy_symbols": self.healthy_symbols,
                "gaps": 0,
            }
        if "execution_effects" in query:
            return self.mutations
        raise AssertionError("unexpected SQL")


def evidence(*, remote="dev-account-7", observed_at=NOW_MS, tpsl=0):
    return AccountEvidence(Snapshot(), remote, observed_at, tpsl)


@pytest.mark.asyncio
async def test_readonly_health_requires_exact_scope_and_flat_live_reconciled_account():
    pool = Pool()
    called = False

    async def account_reader(given_scope):
        nonlocal called
        called = True
        assert given_scope == scope()
        # Three SELECTs have completed before account/network access begins.
        assert len(pool.queries) == 3
        return evidence()

    health = await read_readonly_health(pool, "run-1", scope(), account_reader)
    assert called
    assert health.account_reconciled is True
    assert health.entry_mutations == 0
    assert health.unresolved_bar_gaps == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "pool, account, message",
    [
        (Pool(healthy_symbols=4), evidence(), "coverage"),
        (
            Pool(
                mutations={
                    "effects": 1,
                    "trades": 0,
                    "dispatch_claims": 0,
                    "pending_effects": 0,
                    "pending_trades": 0,
                }
            ),
            evidence(),
            "records",
        ),
        (Pool(), evidence(remote="other-account"), "remote account"),
        (Pool(), evidence(observed_at=NOW_MS + 2_001), "stale"),
        (Pool(), evidence(tpsl=1), "orphan"),
    ],
)
async def test_readonly_health_fails_closed(pool, account, message):
    async def account_reader(_scope):
        return account

    with pytest.raises(ValueError, match=message):
        await read_readonly_health(pool, "run-1", scope(), account_reader)


@pytest.mark.asyncio
async def test_readonly_health_rejects_run_scope_mismatch_before_account_access():
    pool = Pool(scope_override={"environment": "paper"})

    async def account_reader(_scope):
        pytest.fail("account GET must not run for a mismatched run scope")

    with pytest.raises(ValueError, match="run scope"):
        await read_readonly_health(pool, "run-1", scope(), account_reader)
