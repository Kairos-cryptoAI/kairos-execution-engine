"""Real SQL/chain mechanics on disposable synthetic data, never venue qualification."""

from __future__ import annotations

from uuid import uuid4

import pytest
from kairos_persistence import Database
from kairos_persistence.canary_session import (
    SYMBOLS,
    CanaryAdmissionError,
    CanaryScope,
    CanarySessionRepository,
    ReadonlyObservation,
    SymbolObservation,
    millis,
)

from kairos_execution.readonly_health import _BAR_HEALTH_QUERY
from tests.disposable_database import connect_disposable_database, disposable_settings

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]


async def test_actual_sql_full_denominator_chain_and_no_short_window_certification():
    database = Database(disposable_settings())
    await connect_disposable_database(database)
    source = "synthetic-readonly-recorder-" + uuid4().hex
    run_id = None
    try:
        # Causal timestamps around two extra boundary minutes make the fixed
        # 1440-minute SQL roster stable across a real minute rollover in CI.
        await database.pool.execute(
            """INSERT INTO event_audit
               (produced_at,message_id,topic,source,schema_version,payload)
               SELECT opened + interval '1 minute', $2 || symbol || opened::text,
                 'kairos.market.closed_bar.v1', $2, '1',
                 jsonb_build_object('symbol',symbol,'open_time_ms',
                   (extract(epoch FROM opened)*1000)::bigint)
               FROM unnest($1::text[]) AS symbol CROSS JOIN generate_series(
                 date_trunc('minute',clock_timestamp()) - interval '24 hours 1 minute',
                 date_trunc('minute',clock_timestamp()), interval '1 minute') AS opened""",
            list(SYMBOLS),
            source,
        )
        facts = await database.pool.fetchrow(_BAR_HEALTH_QUERY, list(SYMBOLS))
        assert facts["healthy_symbols"] == facts["expected_symbols"] == 5
        assert facts["gaps"] == 0
        # Delete only this fixture's XRP rows, never another test's history.
        await database.pool.execute(
            "DELETE FROM event_audit WHERE source=$1 AND payload->>'symbol'='XRPUSDT'", source
        )
        facts = await database.pool.fetchrow(_BAR_HEALTH_QUERY, list(SYMBOLS))
        assert facts["healthy_symbols"] == 4
        assert facts["expected_symbols"] == 5

        scope = CanaryScope(
            environment="paper-dev",
            account_id="kairos-paper-dev-recorder-fixture",
            remote_account_id="synthetic-" + uuid4().hex,
            config_sha256="c" * 64,
            recorder_code_sha256="d" * 64,
        )
        repository = CanarySessionRepository(database.pool)
        run_id = await repository.begin_readonly(scope, sample_period_ms=15_000)
        now = millis(await database.pool.fetchval("SELECT clock_timestamp()"))
        sample = ReadonlyObservation(
            observed_at_ms=now,
            symbols=tuple(SymbolObservation(symbol=s, available=False) for s in SYMBOLS),
            unresolved_bar_gaps=0,
            reconciliation_drift=False,
            entry_mutations=0,
        )
        assert await repository.append_observation(run_id, sample) == 1
        assert await repository.append_observation(run_id, sample) == 1  # exact immutable replay
        row = await database.pool.fetchrow("SELECT * FROM paper_readonly_runs WHERE run_id=$1", run_id)
        assert row["sample_count"] == 1
        assert row["head_sha256"] != "0" * 64
        with pytest.raises(CanaryAdmissionError, match="24-hour"):
            await repository.certify_readonly(run_id, expected_scope=scope)
        assert (
            await database.pool.fetchval(
                "SELECT count(*) FROM paper_readonly_receipts WHERE run_id=$1", run_id
            )
            == 0
        )
    finally:
        if run_id:
            await database.pool.execute("DELETE FROM paper_readonly_samples WHERE run_id=$1", run_id)
            await database.pool.execute("DELETE FROM paper_readonly_runs WHERE run_id=$1", run_id)
        await database.pool.execute("DELETE FROM event_audit WHERE source=$1", source)
        await database.close()
