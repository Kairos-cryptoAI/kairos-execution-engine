"""End-to-end synthetic-only LIVE Risk → protected PROD lifecycle proof.

The PostgreSQL journals, authority source, writers, claims, runtime, and
publishers are real. Account, quote, exit-economics, venue, and terminal
evidence verifiers are explicit local synthetic fixtures; this is not an
EVEDEX connectivity or acceptance claim.
"""

from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

import asyncpg
import pytest
from kairos_core.contracts import StrategicAllocation, VenueQualityV1, canonical_sha256
from kairos_core.enums import EvedexProfile, MarketRegime, StrategicTrigger, SystemMode
from kairos_persistence import (
    Database,
    ExecutionJournalRepository,
    MigrationProfile,
    PersistenceSettings,
    TradeLifecycleRepository,
    TradeState,
)
from kairos_risk.live import LiveRiskEvaluator, LiveRiskLimitsV1, LiveRiskScopeV1

from kairos_execution.factory import build_production_service
from kairos_execution.managed_signer import ManagedSignerBoundary
from kairos_execution.production_accounting import (
    PostgresProductionAccounting,
    provision_production_accounting_schema,
)
from kairos_execution.production_cancellation import ProductionCancellationVerifier
from kairos_execution.production_claims import PostgresProductionClaims, provision_isolated_schema
from kairos_execution.production_dispatch import ProductionEffectDispatcher
from kairos_execution.production_exit_risk import (
    ProductionLiveExitRiskPublisher,
    VerifiedLiveExitEvidenceV1,
)
from kairos_execution.production_lifecycle import (
    ProductionLifecycleConfigV1,
    ProductionVenueHealthV1,
)
from kairos_execution.production_lifecycle_adapter import ManagedProductionLifecycleAdapter
from kairos_execution.production_lifecycle_store import PostgresLifecycleBindingStore
from kairos_execution.production_path import (
    ProductionLiveLifecycleCoordinator,
    ProductionPreparedExitRiskStager,
)
from kairos_execution.production_readiness import canonical_digest
from kairos_execution.production_reconciliation import (
    ProductionReservationReconciler,
    VenueTerminalEvidenceV2,
    provision_production_reconciliation_schema,
)
from kairos_execution.production_risk import ProductionLiveRiskPublisher
from kairos_execution.production_runtime import ProductionExecutionRuntime
from kairos_execution.production_service import ProductionEntryEnvelope
from kairos_execution.production_state import (
    AsyncPostgresProductionSigningStateSource,
    PostgresExposureStateWriter,
    PostgresOperatorStateWriter,
    PostgresRiskStateWriter,
    ProductionStateError,
    provision_production_state_schema,
)
from kairos_execution.profiles import profile_params
from kairos_execution.signing_authorization import ProductionSigningAuthorizationVerifier
from tests import paper_fixtures
from tests import test_production_risk as risk_fixtures
from tests.test_integration_production_lifecycle import (
    _no_sleep,
    _ProductionReads,
    _SyntheticCancellationTransport,
    _SyntheticCancellationVenueSource,
)
from tests.test_integration_production_lifecycle import (
    _SyntheticVenue as _BaseSyntheticVenue,
)
from tests.test_managed_signer import setup_signer
from tests.test_production_dispatch import SyntheticSignatureVerifier
from tests.test_signing_authorization import fixture as signing_fixture


class _ExitVerifier:
    """Synthetic per-effect evidence source; never qualified for a venue."""

    source_id = "synthetic-prod-exit-source"

    def verify_exit(self, raw_evidence, *, expected_context, trade, decision, effect, role, now):
        assert raw_evidence == "synthetic-exit-proof"
        from kairos_execution.production_readiness import canonical_digest as digest
        from kairos_execution.signing_authorization import ExposureSnapshotV1

        exposure = ExposureSnapshotV1(
            context=expected_context,
            instrument=trade.venue_symbol,
            position_side=trade.side,
            remaining_quantity=max(1, int(Decimal(str(trade.filled_quantity)) * Decimal(10**8))),
            parent_order_id=trade.entry_client_order_id,
            observed_at=now - timedelta(milliseconds=50),
            valid_until=now + timedelta(seconds=2),
        )
        return VerifiedLiveExitEvidenceV1(
            source_id=self.source_id,
            evidence_sha256="a" * 64,
            context_sha256=digest(expected_context),
            trade_id=trade.trade_id,
            original_decision_id=decision.decision_id,
            original_decision_sha256=digest(decision),
            effect_id=effect.effect_key,
            effect_request_sha256=effect.request_sha256,
            role=role,
            exposure=exposure,
            account_equity_usd=Decimal("10000"),
            daily_realized_loss_usd=Decimal("0"),
            aggregate_open_risk_usd=Decimal("25"),
            aggregate_open_notional_usd=Decimal("400"),
            position_entry_price_usd=Decimal(str(decision.worst_entry_price)),
            reference_price_usd=Decimal("100.5"),
            executable_exit_price_usd=Decimal("100.49"),
            exit_fee_rate=Decimal("0.0005"),
            adverse_slippage_rate=Decimal("0.001"),
            observed_at=now - timedelta(milliseconds=50),
            valid_until=now + timedelta(seconds=2),
        )


class _SyntheticExitProvider:
    source_id = _ExitVerifier.source_id

    async def capture_prepared_exit(self, *, context, effect_id, now):
        assert context.remote_account_id and effect_id and now.tzinfo is UTC
        return "synthetic-exit-proof"


class _FreshSyntheticAccountVerifier(risk_fixtures.SyntheticAccountVerifier):
    """Test-only verifier that timestamps its synthetic snapshot at evaluation."""

    def verify(self, raw_evidence, *, source_id, expected_scope):
        verified = super().verify(raw_evidence, source_id=source_id, expected_scope=expected_scope)
        as_of_ms = int(datetime.now(UTC).timestamp() * 1000) - 100
        account_data = verified.account.model_dump(mode="python")
        account_data.update(captured_at_ms=as_of_ms, snapshot_id=None)
        account = type(verified.account).model_validate(account_data)
        return risk_fixtures.VerifiedLiveAccountV1.model_validate(
            verified.model_copy(update={"as_of_ms": as_of_ms, "account": account}).model_dump(mode="json")
        )


class _WallClock:
    """Monotone synthetic test clock that still tracks database wall time."""

    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return max(self.value, datetime.now(UTC))


async def _check_writer_contract(source, pool, identity) -> None:
    async with pool.acquire() as connection:
        await source._inspect_writer_contract(connection, identity)


class _SyntheticVenue(_BaseSyntheticVenue):
    def close(self, body: dict[str, object]) -> dict[str, object]:
        self.calls.append("CLOSE")
        assert body.get("instrument") == "BTCUSD"
        self.state["positions"] = []
        self.state["balance"]["positions"] = []
        self.state["orders"] = []
        self.state["balance"]["openOrders"] = []
        self.state["tpsl"] = [{**item, "status": "cancelled"} for item in self.state["tpsl"]]
        return {
            "id": body["id"],
            "instrument": "BTCUSD",
            "status": "FILLED",
            "quantity": float(body["quantity"]),
            "unFilledQuantity": 0,
            "filledAvgPrice": 100.5,
        }


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.parametrize("use_service_driver", [False, True], ids=["coordinator", "service-driver"])
async def test_native_synthetic_live_path_stages_entry_exits_closes_and_releases_once(
    monkeypatch, use_service_driver
):
    admin_dsn = os.getenv("KAIROS_PRODUCTION_ACCOUNTING_FIXTURE_ADMIN_DSN")
    if not admin_dsn:
        pytest.skip("explicit fresh disposable PostgreSQL fixture admin DSN required")
    parsed = urlsplit(admin_dsn)
    if parsed.hostname not in {"127.0.0.1", "localhost"} or not parsed.path.startswith(
        "/kairos_execution_test_"
    ):
        pytest.fail(
            "production-path test requires the explicitly owned local synthetic fixture", pytrace=False
        )

    signing_authority, _, custody, owner_evidence, _ = signing_fixture(
        remote_account_id="kairos-prod-path-synthetic-account",
        adaptive_system_id="technical-canary",
    )
    context = custody.context
    database_uuid = uuid4()
    policy_namespace = "synthetic:production-path-wiring"
    suffix = uuid4().hex[:12]
    database = f"kairos_production_evidence_{suffix}"
    roles = {
        name: f"path_{name}_{suffix}"
        for name in ("owner", "runtime", "operator", "risk", "exposure", "reconciler", "accounting")
    }
    print(f"created synthetic production-path fixture database={database}", flush=True)
    admin = await asyncpg.connect(admin_dsn)
    owner = None
    connections = []
    pools = {}
    persistence = None
    service_driver = None
    try:
        for role in roles.values():
            await admin.execute(f"CREATE ROLE \"{role}\" LOGIN NOINHERIT PASSWORD 'synthetic_fixture_only'")
        await admin.execute(f'CREATE DATABASE "{database}" OWNER "{roles["owner"]}"')
        for name, role in roles.items():
            role_dsn = urlunsplit(
                (
                    parsed.scheme,
                    f"{role}:synthetic_fixture_only@{parsed.hostname}:{parsed.port}",
                    f"/{database}",
                    "",
                    "",
                )
            )
            if name == "owner":
                owner = await asyncpg.connect(role_dsn)
                connections.append(owner)
            else:
                pools[name] = await asyncpg.create_pool(role_dsn, min_size=1, max_size=3)

        # Use the actual runtime Persistence migrations for journals and event tables.
        owner_dsn = urlunsplit(
            (
                parsed.scheme,
                f"{roles['owner']}:synthetic_fixture_only@{parsed.hostname}:{parsed.port}",
                f"/{database}",
                "",
                "",
            )
        )
        persistence = Database(
            PersistenceSettings(database_url=owner_dsn), migration_profile=MigrationProfile.RUNTIME
        )
        await persistence.connect()
        await persistence.migrate()
        await persistence.close()
        persistence = None

        await owner.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
        common = dict(
            expected_database=database,
            database_uuid=database_uuid,
            policy_namespace=policy_namespace,
            context=context,
        )
        await provision_isolated_schema(
            owner,
            expected_database=database,
            database_uuid=database_uuid,
            policy_namespace=policy_namespace,
            owner_role=roles["owner"],
            runtime_role=roles["runtime"],
        )
        await provision_production_state_schema(
            owner,
            **common,
            owner_role=roles["owner"],
            runtime_role=roles["runtime"],
            operator_writer_role=roles["operator"],
            risk_writer_role=roles["risk"],
            exposure_writer_role=roles["exposure"],
            state_schema_version=3,
        )
        await provision_production_reconciliation_schema(
            owner, **common, owner_role=roles["owner"], reconciler_role=roles["reconciler"], schema_version=2
        )
        await provision_production_accounting_schema(
            owner, **common, owner_role=roles["owner"], accounting_role=roles["accounting"]
        )
        assert await owner.fetchval("SELECT to_regclass('public.event_audit')") == "event_audit"
        await owner.execute(f'GRANT SELECT,INSERT ON public.event_audit TO "{roles["runtime"]}"')
        await owner.execute(
            f"GRANT SELECT,INSERT,UPDATE ON "
            "public.execution_effects,public.execution_trades,public.execution_recovery_state,"
            "public.account_equity_state,public.execution_runtime_health,public.message_outbox "
            f'TO "{roles["runtime"]}"'
        )
        await owner.execute(
            f"GRANT SELECT,INSERT ON "
            "public.execution_effect_events,public.execution_trade_events,public.public_execution_events "
            f'TO "{roles["runtime"]}"'
        )
        await owner.execute(
            f"GRANT SELECT,INSERT ON "
            "public.execution_mutation_budget_scopes,public.execution_mutation_reservations "
            f'TO "{roles["runtime"]}"'
        )
        await owner.execute(
            "GRANT USAGE,SELECT ON SEQUENCE "
            "public.execution_trade_events_sequence_seq,public.execution_effect_events_sequence_seq,"
            "public.message_outbox_id_seq "
            f'TO "{roles["runtime"]}"'
        )

        runtime_pool = pools["runtime"]
        claims = PostgresProductionClaims(runtime_pool, **common, runtime_role=roles["runtime"])
        await claims.consume_once_async(
            owner_identity=owner_evidence.owner_arm.request.owner_identity,
            nonce=owner_evidence.owner_arm.request.nonce,
            request_sha256=canonical_digest(owner_evidence.owner_arm.request),
        )
        state_common = dict(**common, state_schema_version=3)
        operator = PostgresOperatorStateWriter(
            pools["operator"], **state_common, expected_role=roles["operator"]
        )
        risk_writer = PostgresRiskStateWriter(pools["risk"], **state_common, expected_role=roles["risk"])
        exposure_writer = PostgresExposureStateWriter(
            pools["exposure"], **state_common, expected_role=roles["exposure"]
        )
        bindings = PostgresLifecycleBindingStore(
            runtime_pool, context=context, expected_database=database, expected_role=roles["runtime"]
        )
        source = AsyncPostgresProductionSigningStateSource(
            runtime_pool,
            **state_common,
            runtime_role=roles["runtime"],
            clock_probe=lambda: datetime.now(UTC),
        )
        identity = await owner.fetchrow(
            "SELECT * FROM kairos_production_state_v1.identity WHERE singleton=true"
        )
        assert identity is not None and identity["schema_version"] == 3
        await _check_writer_contract(source, runtime_pool, identity)

        async def assert_contract_rejects(grant_sql: str, revoke_sql: str) -> None:
            await owner.execute(grant_sql)
            try:
                with pytest.raises(ProductionStateError):
                    await _check_writer_contract(source, runtime_pool, identity)
            finally:
                await owner.execute(revoke_sql)

        risk_role = roles["risk"]
        risk_table = "kairos_production_state_v1.risk_decisions"
        for privilege in ("UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"):
            await assert_contract_rejects(
                f'GRANT {privilege} ON TABLE {risk_table} TO "{risk_role}"',
                f'REVOKE {privilege} ON TABLE {risk_table} FROM "{risk_role}"',
            )
        await assert_contract_rejects(
            f'GRANT INSERT ON TABLE {risk_table} TO "{roles["operator"]}"',
            f'REVOKE INSERT ON TABLE {risk_table} FROM "{roles["operator"]}"',
        )
        await owner.execute(f'REVOKE SELECT ON TABLE {risk_table} FROM "{risk_role}"')
        try:
            with pytest.raises(ProductionStateError):
                await _check_writer_contract(source, runtime_pool, identity)
        finally:
            await owner.execute(f'GRANT SELECT ON TABLE {risk_table} TO "{risk_role}"')
        exposure_table = "kairos_production_state_v1.exposure_observations"
        await assert_contract_rejects(
            f'GRANT SELECT ON TABLE {exposure_table} TO "{risk_role}"',
            f'REVOKE SELECT ON TABLE {exposure_table} FROM "{risk_role}"',
        )
        state_schema = "kairos_production_state_v1"
        await assert_contract_rejects(
            f'GRANT CREATE ON SCHEMA {state_schema} TO "{risk_role}"',
            f'REVOKE CREATE ON SCHEMA {state_schema} FROM "{risk_role}"',
        )
        await operator.append_owner_arm_async(owner_evidence.owner_arm)
        now_ms = int(datetime.now(UTC).timestamp() * 1000)
        fixture_base_ms = (now_ms // 60_000) * 60_000 - 60_000
        stage_now = datetime.fromtimestamp(now_ms / 1000, tz=UTC)
        monkeypatch.setattr(paper_fixtures, "T0", fixture_base_ms)
        monkeypatch.setattr(risk_fixtures, "T0", fixture_base_ms)
        original_exit_plan = paper_fixtures.ExitPlanV1

        def short_exit_plan(**kwargs):
            kwargs["max_holding_ms"] = 5_000
            return original_exit_plan(**kwargs)

        monkeypatch.setattr(paper_fixtures, "ExitPlanV1", short_exit_plan)
        paper = paper_fixtures.approved_decision()
        review = paper.review
        venue_data = paper.venue_quality.model_dump(mode="python")
        venue_data.update(
            profile=EvedexProfile.PROD,
            symbol="BTCUSD",
            observed_at_ms=fixture_base_ms + 60_300,
            expires_at_ms=int((stage_now + timedelta(seconds=2)).timestamp() * 1000),
            reference_timestamp_ms=fixture_base_ms + 60_000,
            book_timestamp_ms=fixture_base_ms + 60_100,
            measurement_id=None,
            entry_allowed=True,
        )
        venue_quality = VenueQualityV1.model_validate(venue_data)
        allocation = StrategicAllocation(
            source="synthetic-macro-fixture",
            regime=MarketRegime.BULL,
            stable_reserve_pct=0.2,
            strategy_weights={context.adaptive_system_id: 0.8},
            max_gross_leverage=1.0,
            triggered_by=StrategicTrigger.SCHEDULE,
            produced_at=datetime.fromtimestamp((fixture_base_ms + 60_000) / 1000, tz=UTC),
        )
        limits = LiveRiskLimitsV1(
            per_trade_risk_fraction=0.0025,
            aggregate_open_risk_fraction=0.01,
            max_leverage=1.0,
            per_trade_dollar_cap_usd=500.0,
            aggregate_dollar_cap_usd=3_000.0,
            daily_loss_cap_usd=1_000.0,
            max_account_equity_usd=20_000.0,
            max_position_notional_usd=2_000.0,
            min_notional_usd=5.0,
        )
        scope = LiveRiskScopeV1(
            context_sha256=canonical_digest(context),
            source_set_sha256=context.source_set_sha256,
            policy_sha256=context.frozen_policy_sha256,
            risk_limits_sha256=canonical_sha256(limits.model_dump(mode="json")),
            account_id=context.remote_account_id,
            strategy_id=context.adaptive_system_id,
            strategy_revision=review.intent.strategy_revision,
            approved_prod_symbols=((review.intent.symbol, venue_quality.symbol),),
        )
        evaluator = LiveRiskEvaluator(
            scope,
            limits,
            account_verifiers={risk_fixtures.SOURCE: _FreshSyntheticAccountVerifier()},
            input_verifier=risk_fixtures.SyntheticInputsVerifier(),
        )
        entry_publisher = ProductionLiveRiskPublisher(
            evaluator=evaluator,
            risk_writer=risk_writer,
            lifecycle_bindings=bindings,
            custody_binding=custody,
            database_uuid=database_uuid,
            policy_namespace=policy_namespace,
        )

        trades = TradeLifecycleRepository(runtime_pool)
        effects = ExecutionJournalRepository(runtime_pool)
        mutable_clock = _WallClock(stage_now)
        venue = _SyntheticVenue(mutable_clock, context.remote_account_id)
        venue.state["instruments"][0]["updatedAt"] = stage_now.isoformat().replace("+00:00", "Z")
        exit_publisher = ProductionLiveExitRiskPublisher(
            verifier=_ExitVerifier(),
            trades=trades,
            effects=effects,
            risk_writer=risk_writer,
            exposure_writer=exposure_writer,
            lifecycle_bindings=bindings,
            custody_binding=custody,
            database_uuid=database_uuid,
            policy_namespace=policy_namespace,
        )

        # All venue operations are local deterministic fixtures. No SDK/network transport is created.
        async def synthetic_sender(*, method: str, path: str, body: dict[str, object]):
            assert method == "POST"
            if path == "/api/v2/order/limit":
                return venue.partial_entry(body)
            if path == f"/api/tpsl/{body['instrument']}":
                return venue.protect(body)
            if path.startswith("/api/v2/position/") and path.endswith("/close"):
                return venue.close(body)
            raise AssertionError(f"unexpected synthetic transport operation {path}")

        _, _, backend, typed_verifier, _ = setup_signer()
        preconditions = signing_authority._preconditions
        authorization = ProductionSigningAuthorizationVerifier(
            source=source,
            preconditions=preconditions,
            owner_key=signing_authority._owner_key,
            expected_owner_key_sha256=canonical_digest(signing_authority._owner_key),
            expected_owner_identity=signing_authority._owner_key.owner_identity,
            expected_claim_database_uuid=database_uuid,
            maximum_arm_lifetime=timedelta(minutes=10),
            clock_probe=lambda: mutable_clock(),
        )
        signer = ManagedSignerBoundary(
            custody,
            backend=backend,
            verifier=typed_verifier,
            claims=claims,
            authorization=authorization,
        )
        dispatcher = ProductionEffectDispatcher(
            authorization=authorization,
            signature_verifier=SyntheticSignatureVerifier(),
            claims=claims,
            database_uuid=database_uuid,
            context=context,
            clock=mutable_clock,
            sender=synthetic_sender,
        )
        runtime = ProductionExecutionRuntime(
            signer=signer,
            authorization=authorization,
            claims=claims,
            state_source=source,
            dispatcher=dispatcher,
            database_uuid=database_uuid,
            context=context,
            clock=mutable_clock,
        )
        health = ProductionVenueHealthV1(
            chain_id=custody.chain_id,
            exchange_url=profile_params(EvedexProfile.PROD).exchange_url,
            auth_url=profile_params(EvedexProfile.PROD).auth_url,
            sdk_version="1.2.11",
        )
        config = ProductionLifecycleConfigV1(
            context=context,
            custody_binding=custody,
            strategy_revision=review.intent.strategy_revision,
            expected_health=health,
            service_name="synthetic-production-path-test",
            symbol_map={
                "BTCUSDT": "BTCUSD",
                "ETHUSDT": "ETHUSD",
                "SOLUSDT": "SOLUSD",
                "BNBUSDT": "BNBUSD",
                "XRPUSDT": "XRPUSD",
            },
        )
        cancellation_source = _SyntheticCancellationVenueSource(
            context=context, venue=venue, clock=mutable_clock
        )
        cancellations = ProductionCancellationVerifier(
            claims=claims,
            state_source=source,
            bindings=bindings,
            custody_binding=custody,
            trades=trades,
            effects=effects,
            venue_sources={cancellation_source.source_id: cancellation_source},
            transport=_SyntheticCancellationTransport(venue),
            database_uuid=database_uuid,
            context=context,
            preconditions=preconditions,
            owner_key=signing_authority._owner_key,
            expected_owner_key_sha256=canonical_digest(signing_authority._owner_key),
            expected_owner_identity=signing_authority._owner_key.owner_identity,
            maximum_arm_lifetime=timedelta(minutes=10),
            clock=mutable_clock,
        )
        stager = ProductionPreparedExitRiskStager(
            publisher=exit_publisher,
            runtime=runtime,
            evidence_provider=_SyntheticExitProvider(),
            clock=mutable_clock,
        )
        adapter = ManagedProductionLifecycleAdapter(
            runtime=runtime,
            reads=_ProductionReads(venue, mutable_clock, context),
            bindings=bindings,
            trades=trades,
            effects=effects,
            cancellations=cancellations,
            clock=mutable_clock,
        )
        from kairos_execution.production_lifecycle import ProductionLifecycleEngine

        engine = ProductionLifecycleEngine(
            adapter,
            trades,
            effects,
            config,
            runtime,
            clock=mutable_clock,
            sleeper=_no_sleep,
            prepared_exit_risk=stager,
        )
        coordinator = ProductionLiveLifecycleCoordinator(engine=engine, entry_risk=entry_publisher)
        assert await coordinator.initialize_recovery() == ()
        operator_now = datetime.now(UTC)
        arm = owner_evidence.owner_arm.request
        disarmed = owner_evidence.operator.model_copy(
            update={
                "version": 1,
                "state": "DISARMED",
                "arm_nonce": None,
                "arm_request_sha256": None,
                "observed_at": operator_now - timedelta(milliseconds=100),
                "changed_at": operator_now - timedelta(milliseconds=100),
                "expires_at": None,
                "command_sha256": "e" * 64,
                "previous_command_sha256": "f" * 64,
            }
        )
        armed = owner_evidence.operator.model_copy(
            update={
                "version": 2,
                "observed_at": operator_now - timedelta(milliseconds=50),
                "changed_at": operator_now - timedelta(milliseconds=50),
                "arm_nonce": arm.nonce,
                "arm_request_sha256": canonical_digest(arm),
                "expires_at": arm.expires_at,
                "previous_command_sha256": disarmed.command_sha256,
            }
        )
        await operator.append_operator_observation_async(disarmed)
        await operator.append_operator_observation_async(armed)
        if use_service_driver:
            # This local policy gate is explicitly synthetic. The real Risk,
            # journals, claims, owner signatures and FSM still run below; no
            # venue/account source is qualified by the fixture.
            service_driver = build_production_service(
                coordinator=coordinator,
                entry_admission=lambda: True,
                reconciliation_interval_s=60.0,
            )
            status = await service_driver.start()
            assert status.recovery_complete and not status.entries_blocked
            assert status.readiness is False
        # Refresh the entirely synthetic facts only after all DDL, recovery,
        # and component construction so the publisher sees a genuinely fresh
        # two-second quote window rather than a pre-setup timestamp.
        stage_now = datetime.now(UTC)
        now_ms = int(stage_now.timestamp() * 1000)
        fixture_base_ms = (now_ms // 60_000) * 60_000 - 60_000
        monkeypatch.setattr(paper_fixtures, "T0", fixture_base_ms)
        monkeypatch.setattr(risk_fixtures, "T0", fixture_base_ms)
        paper = paper_fixtures.approved_decision()
        review = paper.review
        venue_data = paper.venue_quality.model_dump(mode="python")
        venue_data.update(
            profile=EvedexProfile.PROD,
            symbol="BTCUSD",
            observed_at_ms=now_ms,
            expires_at_ms=now_ms + 2_000,
            reference_timestamp_ms=now_ms,
            book_timestamp_ms=now_ms,
            reference_age_ms=0,
            book_age_ms=0,
            timestamp_skew_ms=0,
            measurement_id=None,
            entry_allowed=True,
        )
        venue_quality = VenueQualityV1.model_validate(venue_data)
        allocation = allocation.model_copy(update={"produced_at": stage_now})
        deadline_at = datetime.fromtimestamp((now_ms + 1_950) / 1_000, tz=UTC)
        entry_inputs = dict(
            raw_account_evidence="synthetic-proof",
            raw_inputs_evidence="synthetic-input-proof",
            source_id=risk_fixtures.SOURCE,
            review=review,
            venue=venue_quality,
            allocation=allocation,
            owner_arm=owner_evidence.owner_arm,
            # Keep the signing deadline inside the independently verified
            # quote's two-second hard freshness limit.
            expires_at=deadline_at,
            system_mode=SystemMode.NORMAL,
        )
        if service_driver is None:
            entry_result = await coordinator.admit_and_handle_entry(**entry_inputs)
        else:
            entry_result = await service_driver.submit(
                ProductionEntryEnvelope(envelope_id="synthetic-native-service-entry", **entry_inputs)
            )
        decision = entry_result.risk_stage.evaluation.decision
        assert decision.approved and decision.trading_mode.value == "LIVE"
        assert any(
            event.event_type.value == "ENTRY_PARTIAL_FILL" for event in entry_result.execution_result.events
        )
        assert venue.calls[:3] == ["ENTRY", "STOP_LOSS", "TAKE_PROFIT"]
        assert await owner.fetchval("SELECT count(*) FROM kairos_production_state_v1.risk_decisions") == 3
        assert (
            await owner.fetchval("SELECT count(*) FROM kairos_production_state_v1.exposure_observations") == 2
        )

        calls_before_replay = list(venue.calls)
        replay = await engine.handle(decision)
        assert replay.events == () and venue.calls == calls_before_replay

        trade = await trades.get(decision.trade_id)
        assert trade is not None
        await asyncio.sleep(max(0.0, (trade.timeout_at - mutable_clock()).total_seconds() + 0.05))
        for _ in range(3):
            if service_driver is None:
                await coordinator.reconcile_once()
            else:
                await service_driver.reconcile_once()
            if "CLOSE" in venue.calls:
                break
        assert "CLOSE" in venue.calls
        assert venue.calls.index("STOP_LOSS") < venue.calls.index("TAKE_PROFIT") < venue.calls.index("CLOSE")
        assert await owner.fetchval("SELECT count(*) FROM kairos_production_state_v1.risk_decisions") == 4
        trade = await trades.get(decision.trade_id)
        assert trade is not None and trade.state is TradeState.FLAT
        closed = await coordinator.reconcile_once()
        assert closed == []
        calls_before_replay = list(venue.calls)
        assert (await engine.handle(decision)).events == ()
        assert venue.calls == calls_before_replay

        reservation = await owner.fetchrow(
            "SELECT r.owner_arm_sha256,r.request_sha256,d.payload "
            "FROM kairos_production_state_v1.risk_reservations r "
            "JOIN kairos_production_state_v1.risk_decisions d ON d.context_sha256=r.context_sha256 "
            "AND d.signing_request_id=r.signing_request_id WHERE r.account_sha256=(SELECT account_sha256 "
            "FROM kairos_production_state_v1.identity WHERE singleton=true) AND r.effect_id=$1",
            entry_result.risk_stage.risk_geometry.effect_id,
        )
        at = datetime.now(UTC)
        entry_filled = Decimal(str(trade.filled_quantity))
        terminal_proof = VenueTerminalEvidenceV2(
            source_id="synthetic-terminal-venue-source",
            source_evidence_sha256="b" * 64,
            context_sha256=canonical_digest(context),
            account_id=context.remote_account_id,
            trade_id=trade.trade_id,
            decision_id=decision.decision_id,
            effect_id=entry_result.risk_stage.risk_geometry.effect_id,
            lifecycle_entry_effect_id=entry_result.risk_stage.lifecycle_binding.lifecycle_effect_id,
            signing_request_id=entry_result.risk_stage.lifecycle_binding.request.request_id,
            client_order_id=trade.entry_client_order_id,
            exchange_parent_order_id=trade.entry_exchange_order_id,
            collection_started_at=at - timedelta(milliseconds=20),
            collection_finished_at=at - timedelta(milliseconds=10),
            observed_at=at,
            complete=True,
            terminal=True,
            entry_filled_quantity=entry_filled,
            closed_quantity=entry_filled,
            entry_notional_usd=entry_filled * Decimal(str(decision.worst_entry_price)),
            exit_notional_usd=entry_filled * Decimal("100.5"),
            entry_fees_usd=Decimal("0.1"),
            exit_fees_usd=Decimal("0.1"),
            residual_position_quantity=Decimal("0"),
            residual_order_count=0,
            residual_protection_count=0,
            unowned_exposure_count=0,
            entry_side=trade.side,
            funding_cost_usd=Decimal("0"),
            funding_complete=True,
            settled_at=at - timedelta(milliseconds=20),
            owner_arm_sha256=reservation["owner_arm_sha256"],
            reservation_request_sha256=reservation["request_sha256"],
        )

        expected_context = context

        class _TerminalVerifier:
            source_id = "synthetic-terminal-venue-source"

            def verify_terminal_evidence(self, raw, *, context, binding):
                assert raw == "synthetic-terminal-proof" and context == expected_context
                assert binding.trade_id == trade.trade_id
                return terminal_proof

        reconciler = ProductionReservationReconciler(
            pool=pools["reconciler"],
            **common,
            expected_role=roles["reconciler"],
            source_verifiers={_TerminalVerifier.source_id: _TerminalVerifier()},
            trades=trades,
            effects=effects,
            schema_version=2,
        )
        accounting = PostgresProductionAccounting(
            pools["accounting"], **common, accounting_role=roles["accounting"]
        )
        close_inputs = dict(
            trade_id=trade.trade_id,
            reconciler=reconciler,
            source_id=_TerminalVerifier.source_id,
            raw_venue_evidence="synthetic-terminal-proof",
            accounting=accounting,
        )
        if service_driver is None:
            release = await coordinator.reconcile_closed_account(**close_inputs)
        else:
            release = await service_driver.reconcile_closed_account(**close_inputs)
        assert release["reservation_released"] is True
        assert release["terminal_receipt"]["created"] is True
        assert (
            await owner.fetchval("SELECT count(*) FROM kairos_production_accounting_v1.accepted_releases")
            == 1
        )
        replay_release = await coordinator.reconcile_closed_account(
            trade_id=trade.trade_id,
            reconciler=reconciler,
            source_id=_TerminalVerifier.source_id,
            raw_venue_evidence="synthetic-terminal-proof",
            accounting=accounting,
        )
        assert replay_release["reservation_released"] is True
        assert replay_release["terminal_receipt"]["created"] is False
        assert (
            await owner.fetchval("SELECT count(*) FROM kairos_production_accounting_v1.accepted_releases")
            == 1
        )

        # A process restart constructs a new engine and a new local exit-stager
        # attempt set over the same durable journals, publishers, and DB roles.
        fresh_stager = ProductionPreparedExitRiskStager(
            publisher=exit_publisher,
            runtime=runtime,
            evidence_provider=_SyntheticExitProvider(),
            clock=mutable_clock,
        )
        fresh_engine = ProductionLifecycleEngine(
            adapter,
            trades,
            effects,
            config,
            runtime,
            clock=mutable_clock,
            sleeper=_no_sleep,
            prepared_exit_risk=fresh_stager,
        )
        fresh_coordinator = ProductionLiveLifecycleCoordinator(
            engine=fresh_engine, entry_risk=entry_publisher
        )
        assert await fresh_coordinator.initialize_recovery() == ()
        claims_before_restart_replay = await owner.fetch(
            "SELECT claim_kind,count(*) AS count FROM kairos_production_evidence_v1.claims "
            "WHERE claim_kind IN ('TYPED_SIGNING','WIRE_DISPATCH') GROUP BY claim_kind"
        )
        claims_before = {row["claim_kind"]: row["count"] for row in claims_before_restart_replay}
        risk_rows_before = await owner.fetchval(
            "SELECT count(*) FROM kairos_production_state_v1.risk_decisions"
        )
        calls_before_restart_replay = list(venue.calls)
        assert (await fresh_engine.handle(decision)).events == ()
        assert await fresh_coordinator.reconcile_once() == []
        assert venue.calls == calls_before_restart_replay
        assert (
            await owner.fetchval("SELECT count(*) FROM kairos_production_state_v1.risk_decisions")
            == risk_rows_before
        )
        claims_after_restart_replay = await owner.fetch(
            "SELECT claim_kind,count(*) AS count FROM kairos_production_evidence_v1.claims "
            "WHERE claim_kind IN ('TYPED_SIGNING','WIRE_DISPATCH') GROUP BY claim_kind"
        )
        assert {row["claim_kind"]: row["count"] for row in claims_after_restart_replay} == claims_before
    finally:
        if service_driver is not None:
            await service_driver.close()
        if persistence is not None:
            await persistence.close()
        for pool in pools.values():
            await pool.close()
        for connection in connections:
            await connection.close()
        await admin.close()
