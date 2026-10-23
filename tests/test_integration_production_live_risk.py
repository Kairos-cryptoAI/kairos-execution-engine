"""Native synthetic-only proof for LIVE risk evidence composition.

This test provisions a fresh disposable PostgreSQL database and exercises the
real evaluator/publisher/state source. It does not authorize, sign, or dispatch
an order and does not contact an exchange or account.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

import asyncpg
import pytest
from kairos_core.contracts import StrategicAllocation, VenueQualityV1, canonical_sha256
from kairos_core.enums import EvedexProfile, MarketRegime, StrategicTrigger, SystemMode
from kairos_risk.live import (
    LiveRiskEvaluator,
    LiveRiskLimitsV1,
    LiveRiskScopeV1,
    VerifiedLiveInputsV1,
)

from kairos_execution.production_accounting import provision_production_accounting_schema
from kairos_execution.production_claims import PostgresProductionClaims, provision_isolated_schema
from kairos_execution.production_history import (
    SOURCE_ID as PINNED_EVEDEX_SOURCE_ID,
)
from kairos_execution.production_history import (
    ProductionHistoryCaptureV1,
    ProductionHistoryComponentV1,
)
from kairos_execution.production_lifecycle_binding import compare_entry_risk_to_decision
from kairos_execution.production_lifecycle_store import PostgresLifecycleBindingStore
from kairos_execution.production_readiness import canonical_digest
from kairos_execution.production_reconciliation import provision_production_reconciliation_schema
from kairos_execution.production_risk import (
    PinnedEvedexLiveAccountVerifier,
    ProductionLiveRiskError,
    ProductionLiveRiskPublisher,
)
from kairos_execution.production_state import (
    AsyncPostgresProductionSigningStateSource,
    PostgresOperatorStateWriter,
    PostgresRiskStateWriter,
    provision_production_state_schema,
)
from tests.test_signing_authorization import fixture as signing_fixture


class _SyntheticInputsVerifier:
    """Test-only verifier binding each exact synthetic upstream input."""

    source_id = "synthetic-live-input-fixture"

    def verify(
        self,
        raw_proof,
        *,
        expected_scope,
        review,
        venue,
        allocation,
        system_mode,
        decided_at_ms,
    ):
        if raw_proof != "synthetic-input-proof":
            raise ValueError("unexpected synthetic input proof")
        return VerifiedLiveInputsV1(
            source_id=self.source_id,
            scope_sha256=expected_scope.scope_sha256,
            evidence_sha256="6" * 64,
            review_sha256=canonical_sha256(review.model_dump(mode="json")),
            venue_sha256=canonical_sha256(venue.model_dump(mode="json")),
            allocation_sha256=(
                canonical_sha256(allocation.model_dump(mode="json")) if allocation is not None else None
            ),
            system_mode=system_mode,
            observed_at_ms=decided_at_ms,
        )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_fresh_native_live_risk_is_staged_and_resolved_without_execution(monkeypatch):
    admin_dsn = os.getenv("KAIROS_PRODUCTION_ACCOUNTING_FIXTURE_ADMIN_DSN")
    if not admin_dsn:
        pytest.skip("explicit fresh disposable PostgreSQL fixture admin DSN required")
    parsed = urlsplit(admin_dsn)
    if parsed.hostname not in {"127.0.0.1", "localhost"} or not parsed.path.startswith(
        "/kairos_execution_test_"
    ):
        pytest.fail("LIVE risk test admin must be the explicit local disposable fixture", pytrace=False)

    # The owner/custody/test signing fixture is created at its own current
    # timestamp. Risk review, quote, account snapshot, and stage times are
    # generated only after all database DDL is complete below.
    _, _, custody, owner_evidence, _ = signing_fixture(
        remote_account_id="kairos-paper-dev-01",
        adaptive_system_id="technical-canary",
    )
    context = custody.context
    database_uuid = uuid4()
    policy_namespace = "synthetic:production-live-risk"
    suffix = uuid4().hex[:12]
    database = f"kairos_production_evidence_{suffix}"
    roles = {
        name: f"live_{name}_{suffix}"
        for name in ("owner", "runtime", "operator", "risk", "exposure", "reconciler", "accounting")
    }
    admin = await asyncpg.connect(admin_dsn)
    connections = []
    pools = {}
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

        await owner.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
        common = dict(
            expected_database=database,
            database_uuid=database_uuid,
            policy_namespace=policy_namespace,
            context=context,
        )
        await provision_isolated_schema(
            owner,
            **{key: value for key, value in common.items() if key != "context"},
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
            owner,
            **common,
            owner_role=roles["owner"],
            reconciler_role=roles["reconciler"],
            schema_version=2,
        )
        await provision_production_accounting_schema(
            owner,
            **common,
            owner_role=roles["owner"],
            accounting_role=roles["accounting"],
        )

        # Minimal existing Persistence AuditRepository schema, including its
        # actual composite primary key; the runtime gets append/read only.
        assert await owner.fetchval("SELECT to_regclass('public.event_audit')") is None
        await owner.execute(
            """CREATE TABLE public.event_audit (
                produced_at timestamptz NOT NULL,
                message_id text NOT NULL,
                topic text NOT NULL,
                source text NOT NULL,
                schema_version text NOT NULL,
                correlation_id text,
                causation_id text,
                payload jsonb NOT NULL,
                persisted_at timestamptz NOT NULL DEFAULT now(),
                PRIMARY KEY (produced_at,message_id)
            )"""
        )
        await owner.execute("REVOKE ALL ON public.event_audit FROM PUBLIC")
        await owner.execute(f'GRANT SELECT,INSERT ON public.event_audit TO "{roles["runtime"]}"')

        claims = PostgresProductionClaims(pools["runtime"], **common, runtime_role=roles["runtime"])
        assert await claims.consume_once_async(
            owner_identity=owner_evidence.owner_arm.request.owner_identity,
            nonce=owner_evidence.owner_arm.request.nonce,
            request_sha256=canonical_digest(owner_evidence.owner_arm.request),
        )
        state_common = dict(**common, state_schema_version=3)
        operator = PostgresOperatorStateWriter(
            pools["operator"], **state_common, expected_role=roles["operator"]
        )
        risk_writer = PostgresRiskStateWriter(pools["risk"], **state_common, expected_role=roles["risk"])
        source = AsyncPostgresProductionSigningStateSource(
            pools["runtime"], **state_common, runtime_role=roles["runtime"]
        )
        bindings = PostgresLifecycleBindingStore(
            pools["runtime"],
            context=context,
            expected_database=database,
            expected_role=roles["runtime"],
        )
        await operator.append_owner_arm_async(owner_evidence.owner_arm)

        # Only the fixture's timestamp constants are patched. All evidence is
        # freshly generated after the slow schema/role provisioning above.
        from tests import paper_fixtures
        from tests import test_production_risk as risk_fixtures

        wall_now_ms = int(datetime.now(UTC).timestamp() * 1_000)
        minute_boundary_ms = (wall_now_ms // 60_000) * 60_000
        target_stage_ms = minute_boundary_ms + 400
        if target_stage_ms <= wall_now_ms:
            target_stage_ms += 60_000
        delay_seconds = max(0.0, (target_stage_ms - wall_now_ms) / 1_000)
        if delay_seconds > 0:
            await asyncio.sleep(delay_seconds)
        stage_now = datetime.fromtimestamp(target_stage_ms / 1_000, tz=UTC)
        fixture_base_ms = target_stage_ms - 60_400
        monkeypatch.setattr(paper_fixtures, "T0", fixture_base_ms)
        monkeypatch.setattr(risk_fixtures, "T0", fixture_base_ms)
        disarmed = owner_evidence.operator.model_copy(
            update=dict(
                version=1,
                state="DISARMED",
                arm_nonce=None,
                arm_request_sha256=None,
                expires_at=None,
                observed_at=stage_now - timedelta(milliseconds=500),
                changed_at=stage_now - timedelta(milliseconds=500),
                command_sha256="f" * 64,
                previous_command_sha256="0" * 64,
            )
        )
        armed = owner_evidence.operator.model_copy(
            update=dict(
                version=2,
                observed_at=stage_now - timedelta(milliseconds=300),
                changed_at=stage_now - timedelta(milliseconds=300),
                arm_nonce=owner_evidence.owner_arm.request.nonce,
                arm_request_sha256=canonical_digest(owner_evidence.owner_arm.request),
                expires_at=owner_evidence.owner_arm.request.expires_at,
                previous_command_sha256=disarmed.command_sha256,
            )
        )
        await operator.append_operator_observation_async(disarmed)
        await operator.append_operator_observation_async(armed)
        paper = paper_fixtures.approved_decision()
        review = paper.review
        venue_data = paper.venue_quality.model_dump(mode="python")
        venue_data.update(
            profile=EvedexProfile.PROD,
            symbol="BTCUSD:PROD",
            observed_at_ms=fixture_base_ms + 60_300,
            expires_at_ms=int((stage_now + timedelta(seconds=2)).timestamp() * 1_000),
            reference_timestamp_ms=fixture_base_ms + 60_000,
            book_timestamp_ms=fixture_base_ms + 60_100,
            measurement_id=None,
            entry_allowed=True,
        )
        venue = VenueQualityV1.model_validate(venue_data)
        allocation = StrategicAllocation(
            source="synthetic-macro-fixture",
            regime=MarketRegime.BULL,
            stable_reserve_pct=0.2,
            strategy_weights={context.adaptive_system_id: 0.8},
            max_gross_leverage=1.0,
            triggered_by=StrategicTrigger.SCHEDULE,
            produced_at=datetime.fromtimestamp((fixture_base_ms + 60_000) / 1_000, tz=UTC),
        )
        synthetic_verifier = risk_fixtures.SyntheticAccountVerifier()
        custody = custody.model_copy(
            update={
                "approved_instruments": (
                    "BTCUSD:PROD",
                    "ETHUSD:PROD",
                    "SOLUSD:PROD",
                    "BNBUSD:PROD",
                    "XRPUSD:PROD",
                )
            }
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
            approved_prod_symbols=((review.intent.symbol, venue.symbol),),
        )
        inputs_verifier = _SyntheticInputsVerifier()
        signing_deadline = stage_now + timedelta(milliseconds=1_500)

        def make_publisher(evaluator):
            return ProductionLiveRiskPublisher(
                evaluator=evaluator,
                risk_writer=risk_writer,
                lifecycle_bindings=bindings,
                custody_binding=custody,
                database_uuid=database_uuid,
                policy_namespace=policy_namespace,
            )

        # The pinned real-source adapter remains explicitly untrusted and must
        # refuse before either SQL-backed append boundary is reached.
        pinned_now = datetime.now(UTC)
        history_payload = "{}"
        pinned_capture = ProductionHistoryCaptureV1(
            context=context,
            account_id=context.remote_account_id,
            collection_started_at=pinned_now - timedelta(milliseconds=10),
            collection_finished_at=pinned_now,
            components=(
                ProductionHistoryComponentV1(
                    path="/synthetic-fixture/history",
                    query_json="{}",
                    payload_json=history_payload,
                    payload_sha256=hashlib.sha256(history_payload.encode()).hexdigest(),
                    started_at=pinned_now - timedelta(milliseconds=10),
                    finished_at=pinned_now,
                ),
            ),
            order_count=0,
            protection_count=0,
        )
        pinned_evaluator = LiveRiskEvaluator(
            scope,
            limits,
            account_verifiers={PINNED_EVEDEX_SOURCE_ID: PinnedEvedexLiveAccountVerifier()},
            input_verifier=inputs_verifier,
        )
        pinned_publisher = make_publisher(pinned_evaluator)
        risk_count_before = await owner.fetchval(
            "SELECT count(*) FROM kairos_production_state_v1.risk_decisions"
        )
        audit_count_before = await owner.fetchval("SELECT count(*) FROM public.event_audit")
        with pytest.raises(ProductionLiveRiskError, match="rejected or outside"):
            await pinned_publisher.evaluate_and_stage_entry(
                pinned_capture,
                "synthetic-input-proof",
                PINNED_EVEDEX_SOURCE_ID,
                review,
                venue,
                allocation,
                canonical_digest(owner_evidence.owner_arm.request),
                signing_deadline,
                stage_now,
                SystemMode.NORMAL,
            )
        assert (
            await owner.fetchval("SELECT count(*) FROM kairos_production_state_v1.risk_decisions")
            == risk_count_before
            == 0
        )
        assert await owner.fetchval("SELECT count(*) FROM public.event_audit") == audit_count_before == 0

        evaluator = LiveRiskEvaluator(
            scope,
            limits,
            account_verifiers={risk_fixtures.SOURCE: synthetic_verifier},
            input_verifier=inputs_verifier,
        )
        publisher = make_publisher(evaluator)
        receipt = await publisher.evaluate_and_stage_entry(
            "synthetic-proof",
            "synthetic-input-proof",
            risk_fixtures.SOURCE,
            review,
            venue,
            allocation,
            canonical_digest(owner_evidence.owner_arm.request),
            signing_deadline,
            stage_now,
            SystemMode.NORMAL,
        )
        assert receipt.evaluation.decision.approved
        assert receipt.evaluation.decision.trading_mode.value == "LIVE"
        assert receipt.evaluation.decision.evedex_profile.value == "PROD"
        assert receipt.binding_inserted
        assert receipt.risk_geometry.context == context

        persisted_binding = await bindings.get(receipt.lifecycle_binding.lifecycle_effect_id)
        assert persisted_binding == receipt.lifecycle_binding
        assert await owner.fetchval("SELECT count(*) FROM kairos_production_state_v1.risk_decisions") == 1
        assert await owner.fetchval("SELECT count(*) FROM public.event_audit") == 1

        resolved = await source.resolve_signing_evidence_async(
            request=persisted_binding.request,
            binding=custody,
            now=stage_now,
        )
        assert resolved.risk == receipt.risk_geometry
        compare_entry_risk_to_decision(
            decision=receipt.evaluation.decision,
            lifecycle=persisted_binding,
            evidence=resolved,
        )
        # This path stages and verifies durable evidence only; no signer or
        # order adapter is instantiated or called.
    finally:
        for pool in pools.values():
            await pool.close()
        for connection in connections:
            await connection.close()
        await admin.close()
