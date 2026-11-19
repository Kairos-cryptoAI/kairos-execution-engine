"""One automatically armed trade end to end: provisioned database, real graph, venue double.

Opt-in: ``KAIROS_REST_STAND=1`` and the local administrator DSN file. The database is
disposable and dropped afterwards; the venue is ``tests.rest_stand.FakeEvedex`` behind
the real ``ProductionEvedexSdkClient``; the evidence is synthetic and labelled so.
"""

from __future__ import annotations

import asyncio
import tempfile
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from uuid import UUID

import asyncpg  # type: ignore[import-untyped]
import pytest
from kairos_core.contracts import StrategicAllocation, VenueQualityV1
from kairos_core.enums import EvedexProfile, MarketRegime, StrategicTrigger
from kairos_risk.live import LiveRiskLimitsV1

from kairos_execution.local_custody import CoincurveTypedDataVerifier
from kairos_execution.managed_signer import CustodyBindingV1, reviewed_schema_sha256
from kairos_execution.production_lifecycle import ProductionLifecycleConfigV1, ProductionVenueHealthV1
from kairos_execution.production_observation import PROD_EXCHANGE_ORIGIN
from kairos_execution.production_owner import OWNER_KEY_FILE
from kairos_execution.production_provisioning import provision_production_database
from kairos_execution.production_session import (
    AutoArmSigner,
    RolePools,
    TradeCandidate,
    build_rest_session,
    run_one_trade,
)
from kairos_execution.production_transport import ProductionEvedexSdkClient, ProductionEvedexTransport
from kairos_execution.profiles import profile_params
from kairos_execution.signed_evidence import DirectoryEvidenceResolver
from kairos_execution.technical_canary_readiness import TechnicalCanaryPreconditionsVerifier
from kairos_execution.utc_clock import precise_utc_now
from tests import paper_fixtures
from tests.rest_stand import FakeEvedex, StandCustody, issue_stand_evidence, stand_admin_dsn

pytestmark = pytest.mark.integration


async def _drop(admin_dsn: str, database: str, roles) -> None:
    admin = await asyncpg.connect(admin_dsn)
    try:
        await admin.execute(f'DROP DATABASE IF EXISTS "{database}" WITH (FORCE)')
        for role in roles:
            await admin.execute(f'DROP ROLE IF EXISTS "{role}"')
    finally:
        await admin.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("exit_kind", ["take-profit", "stop-loss", "early-exit"])
async def test_one_armed_trade_enters_protects_exits_and_is_accounted(monkeypatch, exit_kind):
    admin_dsn = stand_admin_dsn()
    stand_custody = StandCustody()
    root = Path(tempfile.mkdtemp(prefix="rest-stand-"))
    now = precise_utc_now()
    template_intent = paper_fixtures.approved_decision().review.intent
    strategy_id = template_intent.strategy_id
    context, references, registry, pin, owner_key = issue_stand_evidence(
        root,
        remote_account_id="synthetic-stand-account",
        adaptive_system_id=strategy_id,
        source_set_sha256="b" * 64,
        custody_reference="synthetic:stand-custody",
        wallet_address=stand_custody.wallet_address,
        chain_id=42161,
        owner_identity="owner",
        dollar_cap=Decimal("200"),
        daily_stop_loss_usd=Decimal("5"),
        now=now.replace(microsecond=0) - timedelta(seconds=5),
    )
    custody = CustodyBindingV1(
        context=context,
        custody_reference="synthetic:stand-custody",
        wallet_address=stand_custody.wallet_address,
        chain_id=42161,
        schema_sha256=reviewed_schema_sha256(42161),
        approved_instruments=("BTCUSD",),
        custody_receipt_sha256="c" * 64,
    )
    settings = ProductionLifecycleConfigV1(
        context=context,
        custody_binding=custody,
        strategy_revision=template_intent.strategy_revision,
        expected_health=ProductionVenueHealthV1(
            chain_id=42161,
            exchange_url=PROD_EXCHANGE_ORIGIN,
            auth_url=profile_params(EvedexProfile.PROD).auth_url,
            sdk_version="1.2.11",
        ),
        service_name="kairos-production-execution",
        symbol_map={template_intent.symbol: "BTCUSD"},
        entry_order_type="LIMIT_GTC",
    )
    manifest = await provision_production_database(
        admin_dsn, context=context, secrets_dir=root / "secrets", policy_namespace="synthetic:rest-stand"
    )
    pools: dict[str, asyncpg.Pool] = {}
    try:
        for name in ("runtime", "operator", "risk", "exposure", "reconciler", "accounting"):
            pools[name] = await asyncpg.create_pool(manifest.dsn(name), min_size=1, max_size=4)
        venue = FakeEvedex(context.remote_account_id, bid="100.49", ask="100.51")
        client = ProductionEvedexSdkClient(
            node_executable=Path(__file__).resolve().parent / "fixtures" / "node.exe",
            api_key_file=Path(__file__).resolve().parent / "fixtures" / "must-not-be-read.key",
            expected_account_id=context.remote_account_id,
        )
        client._call = venue.call  # type: ignore[method-assign]
        transport = ProductionEvedexTransport(context=context, custody_binding=custody, client=client)
        session = build_rest_session(
            pools=RolePools(
                runtime=pools["runtime"],
                operator=pools["operator"],
                risk=pools["risk"],
                exposure=pools["exposure"],
                reconciliation=pools["reconciler"],
                accounting=pools["accounting"],
                roles=manifest.roles,
                database=manifest.database,
                database_uuid=UUID(manifest.database_uuid),
                policy_namespace=manifest.policy_namespace,
            ),
            settings=settings,
            references=references,
            canary_verifier=TechnicalCanaryPreconditionsVerifier(
                registry, DirectoryEvidenceResolver(root / "evidence"), pinned_registry_sha256=pin
            ),
            owner_key=owner_key,
            custody_backend=stand_custody,
            custody_signature_verifier=CoincurveTypedDataVerifier(),
            wire_signature_verifier=CoincurveTypedDataVerifier(),
            transport=transport,
            limits=LiveRiskLimitsV1(
                per_trade_risk_fraction=0.0025,
                aggregate_open_risk_fraction=0.01,
                max_leverage=1.0,
                per_trade_dollar_cap_usd=500.0,
                aggregate_dollar_cap_usd=3_000.0,
                daily_loss_cap_usd=1_000.0,
                max_account_equity_usd=20_000.0,
                max_position_notional_usd=2_000.0,
                min_notional_usd=5.0,
            ),
            exit_fee_rate=Decimal("0.0005"),
            adverse_slippage_rate=Decimal("0.001"),
            clock=precise_utc_now,
        )
        # Build a fresh candidate after provisioning. Wait for the next closed
        # bar when the current entry window would expire during host startup.
        elapsed_ms = int(precise_utc_now().timestamp() * 1_000) % 60_000
        if elapsed_ms >= 45_000:
            await asyncio.sleep((60_500 - elapsed_ms) / 1_000)
        elif elapsed_ms < 500:
            await asyncio.sleep((500 - elapsed_ms) / 1_000)
        current_minute_ms = int(precise_utc_now().timestamp() * 1_000) // 60_000 * 60_000
        base_ms = current_minute_ms - 60_000
        monkeypatch.setattr(paper_fixtures, "T0", base_ms)
        paper = paper_fixtures.approved_decision()
        review = paper.review
        allocation = StrategicAllocation(
            source="synthetic-stand-macro",
            regime=MarketRegime.BULL,
            stable_reserve_pct=0.2,
            strategy_weights={strategy_id: 0.8},
            max_gross_leverage=1.0,
            triggered_by=StrategicTrigger.SCHEDULE,
            produced_at=datetime.fromtimestamp(base_ms / 1000, tz=UTC),
        )

        async def venue_provider(_review):
            observed = int(precise_utc_now().timestamp() * 1000)
            data = paper.venue_quality.model_dump(mode="python")
            data.update(
                profile=EvedexProfile.PROD,
                symbol="BTCUSD",
                observed_at_ms=observed,
                expires_at_ms=observed + 4_900,
                reference_timestamp_ms=observed - 300,
                book_timestamp_ms=observed - 200,
                measurement_id=None,
                entry_allowed=True,
            )
            return VenueQualityV1.model_validate(data)

        async def market():
            while not (venue.positions and sum(r["status"] == "active" for r in venue.tpsl) == 2):
                await asyncio.sleep(0.2)
            await asyncio.sleep(1.0)
            if exit_kind == "early-exit":
                protected.set()
            else:
                venue.trigger(exit_kind)

        protected = asyncio.Event()

        def early_exit():
            return "regime BEAR opposes LONG" if protected.is_set() else None

        # Diagnostics: the production path deliberately hides causes behind
        # sanitized errors; on failure the test prints the original tracebacks.
        import traceback

        from kairos_execution import production_session as session_module
        from kairos_execution.paper_engine import PaperExecutionEngine
        from kairos_execution.production_path import ProductionLiveLifecycleCoordinator

        failures: list[str] = []
        built_hosts: list = []

        def traced(label, original):
            async def wrapper(*args, **kwargs):
                try:
                    return await original(*args, **kwargs)
                except BaseException:
                    text = label + " " + traceback.format_exc()
                    if text not in failures:
                        failures.append(text)
                    raise

            return wrapper

        monkeypatch.setattr(
            ProductionLiveLifecycleCoordinator,
            "admit_and_handle_entry",
            traced("COORDINATOR", ProductionLiveLifecycleCoordinator.admit_and_handle_entry),
        )
        monkeypatch.setattr(
            PaperExecutionEngine,
            "_reconcile_once_unlocked",
            traced("RECONCILE", PaperExecutionEngine._reconcile_once_unlocked),
        )
        original_build = session_module.build_production_host

        def traced_build(resources, *, entry_provider, **kwargs):
            host = original_build(resources, entry_provider=traced("ENTRY", entry_provider), **kwargs)
            built_hosts.append(host)
            return host

        monkeypatch.setattr(session_module, "build_production_host", traced_build)
        market_task = asyncio.create_task(market())
        try:
            result = await asyncio.wait_for(
                run_one_trade(
                    session,
                    TradeCandidate(review, allocation),
                    AutoArmSigner(root / "owner" / OWNER_KEY_FILE, owner_key),
                    venue_provider,
                    early_exit=early_exit if exit_kind == "early-exit" else None,
                ),
                timeout=90,
            )
        except BaseException:
            for failure in failures:
                print(failure)
            print("TPSL", venue.tpsl)
            print("POSITIONS", venue.positions)
            print("CALLS", venue.calls[-40:])
            rows = await pools["runtime"].fetch(
                "SELECT state, reconciliation_detail, filled_quantity FROM execution_trades"
            )
            print("TRADES", [dict(row) for row in rows])
            events = await pools["runtime"].fetch(
                "SELECT effect_key, effect_type, status, error FROM execution_effects ORDER BY prepared_at"
            )
            print("EFFECTS", [dict(row) for row in events])
            for host in built_hosts:
                print("HOST", host.status)
                print("BLOCKERS", host.assembly.engine.recovery_blockers)
            recovery = await pools["runtime"].fetch("SELECT * FROM execution_recovery_state")
            print("RECOVERY", [dict(row) for row in recovery])
            raise
        finally:
            market_task.cancel()
        print("venue calls:", venue.calls)
        for failure in failures:
            print(failure)
        assert result.outcome == "CLOSED_AND_ACCOUNTED", result
        assert venue.positions == [] and venue.history[0]["status"] == "FILLED"
        accounted = await pools["accounting"].fetchval(
            "SELECT count(*) FROM kairos_production_accounting_v1.accepted_releases"
        )
        assert accounted == 1
        from kairos_execution.production_report import closed_trades

        (closed,) = await closed_trades(manifest)
        expected = {"take-profit": "TARGET", "stop-loss": "STOP", "early-exit": "TIMEOUT"}[exit_kind]
        assert closed["exit_reason"] == expected
        r_multiple = Decimal(closed["r_multiple"])
        if exit_kind == "take-profit":
            assert r_multiple > 0
        elif exit_kind == "stop-loss":
            assert r_multiple < 0
        else:
            # A market close at the bid right after entry: a small loss of the spread and fees.
            assert Decimal("-1") < r_multiple < 0
            assert closed["early_exit"] == "regime BEAR opposes LONG"
            assert any(call.endswith("/close") for call in venue.calls)
        assert Decimal(closed["net_pnl_usd"]) == Decimal(closed["gross_pnl_usd"]) - Decimal(
            closed["fees_usd"]
        ) - Decimal(closed["funding_cost_usd"])
    finally:
        for pool in pools.values():
            await pool.close()
        await _drop(admin_dsn, manifest.database, manifest.roles.values())
