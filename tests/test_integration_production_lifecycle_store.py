"""Native append-only lifecycle binding test on a fresh isolated PG database.

This adds only the minimal ``event_audit`` shape consumed by AuditRepository;
it is not a substitute for installing/running the complete persistence migrations.
No order, signature, network request, or external account access is performed.
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import UUID

import asyncpg
import pytest
from kairos_core.contracts import TradeExecutionEventV1
from kairos_core.enums import (
    EvedexProfile,
    OrderRole,
    TradeExecutionEventType,
    TradeExitReason,
    TradeLifecycleState,
    TradingMode,
)
from kairos_persistence.repository import MessageIdentityConflict
from kairos_persistence.trade_lifecycle import TradeRecord, TradeState

from kairos_execution.production_claims import (
    SCHEMA as CLAIMS_SCHEMA,
)
from kairos_execution.production_claims import (
    PostgresProductionClaims,
    provision_isolated_schema,
)
from kairos_execution.production_lifecycle_store import (
    PostgresLifecycleBindingStore,
)
from kairos_execution.production_readiness import canonical_digest
from kairos_execution.production_reconciliation import (
    SCHEMA as RECONCILIATION_SCHEMA,
)
from kairos_execution.production_reconciliation import (
    ProductionReconciliationError,
    ProductionReservationReconciler,
    ReservationTradeBindingV1,
    VenueTerminalEvidenceV1,
    provision_production_reconciliation_schema,
)
from kairos_execution.production_state import (
    SCHEMA as STATE_SCHEMA,
)
from kairos_execution.production_state import (
    AsyncPostgresProductionSigningStateSource,
    PostgresOperatorStateWriter,
    PostgresRiskStateWriter,
    _account_scope_sha256,
    provision_production_state_schema,
)
from kairos_execution.signing_authorization import signing_effect_id
from tests.test_production_lifecycle_store import _binding
from tests.test_signing_authorization import fixture


class _SyntheticTerminalVerifier:
    """Native SQL test only: fixture verifier, never a venue connection."""

    def __init__(self, evidence):
        self.evidence = evidence

    def verify_terminal_evidence(self, raw_evidence, *, context, binding):
        assert raw_evidence in {"synthetic-native-terminal-v1", "synthetic-native-rebound-v1"}
        evidence = dict(self.evidence)
        evidence["source_evidence_sha256"] = (
            "d" * 64 if raw_evidence == "synthetic-native-terminal-v1" else "e" * 64
        )
        return VenueTerminalEvidenceV1.model_validate(evidence)


class _SyntheticTradeRepository:
    def __init__(self, trade, facts):
        self.trade = trade
        self.facts = facts

    async def get(self, trade_id):
        return self.trade if trade_id == self.trade.trade_id else None

    async def verify_chain(self, trade_id):
        return trade_id == self.trade.trade_id

    async def list_execution_events(self, trade_id):
        return self.facts if trade_id == self.trade.trade_id else []


class _SyntheticEffectsPool:
    def __init__(self, effects):
        self.effects = effects

    async def fetch(self, query, trade_id):
        del query
        return [effect for effect in self.effects if effect["trade_id"] == trade_id]


class _SyntheticEffectRepository:
    def __init__(self, effects):
        self.pool = _SyntheticEffectsPool(effects)

    async def verify_chain(self, effect_key):
        return effect_key == "b" * 64


def _synthetic_trade_facts(*, context, binding, quantity, observed_at):
    environment = f"PROD:{canonical_digest(context)}:LIVE"
    trade = TradeRecord(
        trade_id=binding.trade_id,
        strategy_intent_id="1" * 64,
        risk_decision_id=binding.decision_id,
        risk_decision_payload={"fixture": "synthetic-native-test"},
        strategy_id=context.adaptive_system_id,
        strategy_revision="synthetic-native-test",
        trading_mode="LIVE",
        environment=environment,
        profile="PROD",
        exchange="evedex",
        account_id=context.remote_account_id,
        symbol="BTCUSD",
        venue_symbol="BTCUSD",
        side="BUY",
        quantity=quantity,
        leverage=1,
        stop_price=9500,
        target_price=11000,
        entry_eligible_at=observed_at - timedelta(minutes=1),
        entry_expires_at=observed_at + timedelta(minutes=1),
        max_holding_ms=60_000,
        state=TradeState.FLAT,
        entry_client_order_id=binding.client_order_id,
        entry_exchange_order_id=binding.exchange_parent_order_id,
        stop_client_order_id="synthetic-stop-client-01",
        stop_exchange_order_id="synthetic-stop-venue-01",
        target_client_order_id="synthetic-target-client-01",
        target_exchange_order_id="synthetic-target-venue-01",
        close_client_order_id="synthetic-close-client-01",
        close_exchange_order_id="synthetic-close-venue-01",
        filled_quantity=quantity,
        first_fill_at=observed_at - timedelta(seconds=10),
        timeout_at=None,
        last_reconciled_at=observed_at,
        reconciliation_detail=None,
        state_version=1,
        journal_head_sha256="9" * 64,
    )
    common = {
        "source": "synthetic-native-fixture",
        "occurred_at_ms": int((observed_at - timedelta(seconds=3)).timestamp() * 1000),
        "trading_mode": TradingMode.LIVE,
        "evedex_profile": EvedexProfile.PROD,
        "account_id": context.remote_account_id,
        "venue_symbol": "BTCUSD",
        "strategy_id": context.adaptive_system_id,
        "strategy_revision": "synthetic-native-test",
        "intent_id": "1" * 64,
        "risk_decision_id": binding.decision_id,
        "trade_id": binding.trade_id,
        "requested_quantity": quantity,
        "average_price": 10_000,
        "fee_usd": 0.1,
    }
    entry = TradeExecutionEventV1(
        **common,
        event_seq=1,
        event_type=TradeExecutionEventType.ENTRY_FILLED,
        lifecycle_state=TradeLifecycleState.ACTIVE,
        order_role=OrderRole.ENTRY,
        client_order_id=binding.client_order_id,
        exchange_order_id=binding.exchange_parent_order_id,
        filled_quantity=quantity,
        position_quantity=quantity,
        exit_reason=None,
    )
    exit_fill = TradeExecutionEventV1(
        **{
            **common,
            "occurred_at_ms": int((observed_at - timedelta(seconds=2)).timestamp() * 1000),
        },
        event_seq=2,
        event_type=TradeExecutionEventType.EXIT_FILLED,
        lifecycle_state=TradeLifecycleState.FLAT,
        order_role=OrderRole.TIMEOUT_EXIT,
        client_order_id="synthetic-close-client-01",
        exchange_order_id="synthetic-close-venue-01",
        filled_quantity=quantity,
        position_quantity=0,
        exit_reason=TradeExitReason.TIMEOUT,
    )
    return trade, [entry, exit_fill]


@pytest.mark.integration
@pytest.mark.asyncio
async def test_native_production_lifecycle_store_append_only_least_privilege():
    prefix = "KAIROS_PRODUCTION_LIFECYCLE_TEST_"
    if os.getenv(prefix + "PROVISION") != "1":
        pytest.skip("explicit fresh isolated lifecycle fixture is not enabled")

    claim_names = (
        "OWNER_DSN",
        "RUNTIME_DSN",
        "DATABASE",
        "DATABASE_UUID",
        "POLICY_NAMESPACE",
        "OWNER_ROLE",
        "RUNTIME_ROLE",
    )
    claims_settings = {key: os.getenv(prefix + key) for key in claim_names}
    state_keys = (
        "OPERATOR_WRITER_DSN",
        "RISK_WRITER_DSN",
        "EXPOSURE_WRITER_DSN",
        "OPERATOR_WRITER_ROLE",
        "RISK_WRITER_ROLE",
        "EXPOSURE_WRITER_ROLE",
    )
    state_settings = {key: os.getenv(prefix + key) for key in state_keys}
    if not all(claims_settings.values()) or not all(state_settings.values()):
        pytest.fail("isolated fixture credentials and separate state roles are required", pytrace=False)

    owner = None
    runtime_pool = None
    writer_pools: dict[str, asyncpg.Pool] = {}
    reconciler_pool = None
    try:
        owner = await asyncpg.connect(claims_settings["OWNER_DSN"], timeout=5, command_timeout=5)
        runtime_pool = await asyncpg.create_pool(
            claims_settings["RUNTIME_DSN"], min_size=1, max_size=3, timeout=5, command_timeout=5
        )
        for role, dsn_key in (
            ("operator", "OPERATOR_WRITER_DSN"),
            ("risk", "RISK_WRITER_DSN"),
            ("exposure", "EXPOSURE_WRITER_DSN"),
        ):
            writer_pools[role] = await asyncpg.create_pool(
                state_settings[dsn_key], min_size=1, max_size=1, timeout=5, command_timeout=5
            )
        reconciler_pool = await asyncpg.create_pool(
            os.getenv(prefix + "RECONCILER_DSN"),
            min_size=1,
            max_size=1,
            timeout=5,
            command_timeout=5,
        )

        identity = await owner.fetchrow("SELECT current_database() AS db,current_user AS role")
        if (
            identity is None
            or identity["db"] != claims_settings["DATABASE"]
            or identity["role"] != claims_settings["OWNER_ROLE"]
        ):
            pytest.fail("fresh isolated database owner identity mismatch", pytrace=False)

        authorization, signing_request, custody_binding, fixture_evidence, _ = fixture()
        context = custody_binding.context
        database_uuid = UUID(claims_settings["DATABASE_UUID"])
        claims_kwargs = {
            "expected_database": claims_settings["DATABASE"],
            "database_uuid": database_uuid,
            "policy_namespace": claims_settings["POLICY_NAMESPACE"],
            "runtime_role": claims_settings["RUNTIME_ROLE"],
            "context": context,
        }
        if await owner.fetchval("SELECT to_regnamespace($1)", CLAIMS_SCHEMA) is None:
            await provision_isolated_schema(
                owner,
                expected_database=claims_settings["DATABASE"],
                database_uuid=database_uuid,
                policy_namespace=claims_settings["POLICY_NAMESPACE"],
                owner_role=claims_settings["OWNER_ROLE"],
                runtime_role=claims_settings["RUNTIME_ROLE"],
            )
        claims = PostgresProductionClaims(runtime_pool, **claims_kwargs)
        async with runtime_pool.acquire() as connection:
            await claims.inspect(connection)

        if await owner.fetchval("SELECT to_regnamespace($1)", STATE_SCHEMA) is None:
            await provision_production_state_schema(
                owner,
                expected_database=claims_settings["DATABASE"],
                database_uuid=database_uuid,
                policy_namespace=claims_settings["POLICY_NAMESPACE"],
                context=context,
                owner_role=claims_settings["OWNER_ROLE"],
                runtime_role=claims_settings["RUNTIME_ROLE"],
                operator_writer_role=state_settings["OPERATOR_WRITER_ROLE"],
                risk_writer_role=state_settings["RISK_WRITER_ROLE"],
                exposure_writer_role=state_settings["EXPOSURE_WRITER_ROLE"],
            )

        # The owner-only setup is permitted only in this explicitly fresh CI DB.
        # Use the exact AuditRepository columns/PK, not a mock or production DDL.
        if await owner.fetchval("SELECT to_regclass('public.event_audit')") is not None:
            pytest.fail(
                "event_audit already exists; this native test requires a fresh fixture",
                pytrace=False,
            )
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
        runtime_role = claims_settings["RUNTIME_ROLE"]
        await owner.execute("REVOKE ALL ON public.event_audit FROM PUBLIC")
        await owner.execute(f'GRANT SELECT,INSERT ON public.event_audit TO "{runtime_role}"')

        privileges = await owner.fetchrow(
            """SELECT has_table_privilege($1,'public.event_audit','SELECT') AS can_select,
                      has_table_privilege($1,'public.event_audit','INSERT') AS can_insert,
                      has_table_privilege($1,'public.event_audit','UPDATE') AS can_update,
                      has_table_privilege($1,'public.event_audit','DELETE') AS can_delete,
                      has_table_privilege($1,'public.event_audit','TRUNCATE') AS can_truncate,
                      r.rolsuper,r.rolcreatedb,r.rolcreaterole,r.rolreplication,r.rolbypassrls
                 FROM pg_roles r WHERE r.rolname=$1""",
            runtime_role,
        )
        assert privileges is not None
        assert privileges["can_select"] and privileges["can_insert"]
        assert not any(
            privileges[key]
            for key in (
                "can_update",
                "can_delete",
                "can_truncate",
                "rolsuper",
                "rolcreatedb",
                "rolcreaterole",
                "rolreplication",
                "rolbypassrls",
            )
        )

        if await owner.fetchval("SELECT to_regnamespace($1)", RECONCILIATION_SCHEMA) is not None:
            pytest.fail(
                "reconciliation schema already exists; this native test requires a fresh fixture",
                pytrace=False,
            )
        await provision_production_reconciliation_schema(
            owner,
            expected_database=claims_settings["DATABASE"],
            database_uuid=database_uuid,
            policy_namespace=claims_settings["POLICY_NAMESPACE"],
            context=context,
            owner_role=claims_settings["OWNER_ROLE"],
            reconciler_role=os.getenv(prefix + "RECONCILER_ROLE"),
        )
        # The v2 reservation is intentionally empty. DDL must reference its
        # exact composite identity without changing or seeding it.
        assert await owner.fetchval("SELECT count(*) FROM kairos_production_state_v1.risk_reservations") == 0
        assert await owner.fetchval(f"SELECT count(*) FROM {RECONCILIATION_SCHEMA}.terminal_receipts") == 0
        fk_target = await owner.fetchval(
            """SELECT confrelid::regclass::text FROM pg_constraint
                 WHERE conrelid=$1::regclass AND contype='f'
                   AND confrelid='kairos_production_state_v1.risk_reservations'::regclass""",
            f"{RECONCILIATION_SCHEMA}.terminal_receipts",
        )
        assert fk_target == "kairos_production_state_v1.risk_reservations"

        reconciler_role = os.getenv(prefix + "RECONCILER_ROLE")
        receipt_privileges = await owner.fetchrow(
            """SELECT has_table_privilege($1,$2,'SELECT') AS can_select,
                      has_table_privilege($1,$2,'INSERT') AS can_insert,
                      has_table_privilege($1,$2,'UPDATE') AS can_update,
                      has_table_privilege($1,$2,'DELETE') AS can_delete,
                      has_table_privilege($1,$2,'TRUNCATE') AS can_truncate,
                      has_table_privilege($1,$3,'SELECT') AS identity_select,
                      has_table_privilege($1,$3,'INSERT') AS identity_insert,
                      has_table_privilege($1,'kairos_production_state_v1.risk_reservations',
                                          'SELECT') AS reservation_select,
                      has_table_privilege($1,'kairos_production_state_v1.risk_reservations',
                                          'INSERT') AS reservation_insert,
                      has_table_privilege($1,'kairos_production_state_v1.risk_decisions',
                                          'SELECT') AS decision_select,
                      has_table_privilege($1,'kairos_production_state_v1.risk_decisions',
                                          'INSERT') AS decision_insert,
                      has_schema_privilege($1,$4,'CREATE') AS schema_create,
                      r.rolsuper,r.rolcreatedb,r.rolcreaterole,r.rolreplication,r.rolbypassrls
                 FROM pg_roles r WHERE r.rolname=$1""",
            reconciler_role,
            f"{RECONCILIATION_SCHEMA}.terminal_receipts",
            f"{RECONCILIATION_SCHEMA}.identity",
            RECONCILIATION_SCHEMA,
        )
        assert receipt_privileges is not None
        assert receipt_privileges["can_select"] and receipt_privileges["can_insert"]
        assert receipt_privileges["identity_select"] and not receipt_privileges["identity_insert"]
        assert receipt_privileges["reservation_select"] and not receipt_privileges["reservation_insert"]
        assert receipt_privileges["decision_select"] and not receipt_privileges["decision_insert"]
        assert not any(
            receipt_privileges[key]
            for key in (
                "can_update",
                "can_delete",
                "can_truncate",
                "schema_create",
                "rolsuper",
                "rolcreatedb",
                "rolcreaterole",
                "rolreplication",
                "rolbypassrls",
            )
        )
        assert (
            await reconciler_pool.fetchval(f"SELECT count(*) FROM {RECONCILIATION_SCHEMA}.terminal_receipts")
            == 0
        )

        candidate = _binding(context=context)
        store = PostgresLifecycleBindingStore(
            runtime_pool,
            context=context,
            expected_database=claims_settings["DATABASE"],
            expected_role=runtime_role,
        )
        # Advisory-lock concurrency must produce exactly one immutable insert.
        results = await asyncio.gather(store.put(candidate), store.put(candidate))
        assert sorted(results) == [False, True]
        assert await store.get(candidate.lifecycle_effect_id) == candidate

        # A structurally valid changed request with the same deterministic
        # lifecycle message ID is a rebind attempt, not a benign duplicate.
        message = json.loads(candidate.request.message_json)
        message["quantity"] += 1
        request = candidate.request.model_copy(
            update={
                "message_json": json.dumps(message, sort_keys=True, separators=(",", ":")),
            }
        )
        rebound = candidate.model_copy(
            update={
                "request": request,
                "signing_effect_id": signing_effect_id(
                    request=request, message=message, decision_id=candidate.risk_decision_id
                ),
            }
        )
        with pytest.raises(MessageIdentityConflict):
            await store.put(rebound)

        assert (
            await owner.fetchval(
                "SELECT count(*) FROM public.event_audit WHERE message_id=$1",
                store._message_id(candidate.lifecycle_effect_id),
            )
            == 1
        )

        # Seed through accepted claims + the real operator/risk writers, then
        # stop at authorization's reserve-before-sign boundary (no signer).
        assert await claims.consume_once_async(
            owner_identity=fixture_evidence.owner_nonce_claim.owner_identity,
            nonce=fixture_evidence.owner_nonce_claim.nonce,
            request_sha256=fixture_evidence.owner_nonce_claim.request_sha256,
        )
        state_kwargs = {
            "expected_database": claims_settings["DATABASE"],
            "database_uuid": database_uuid,
            "policy_namespace": claims_settings["POLICY_NAMESPACE"],
            "context": context,
        }
        operator_writer = PostgresOperatorStateWriter(
            writer_pools["operator"],
            **state_kwargs,
            expected_role=state_settings["OPERATOR_WRITER_ROLE"],
        )
        risk_writer = PostgresRiskStateWriter(
            writer_pools["risk"],
            **state_kwargs,
            expected_role=state_settings["RISK_WRITER_ROLE"],
        )
        await operator_writer.append_owner_arm_async(fixture_evidence.owner_arm)
        reserve_now = datetime.now(UTC)
        disarmed = fixture_evidence.operator.model_copy(
            update={
                "version": 1,
                "state": "DISARMED",
                "arm_nonce": None,
                "arm_request_sha256": None,
                "observed_at": reserve_now - timedelta(milliseconds=400),
                "changed_at": reserve_now - timedelta(milliseconds=400),
                "expires_at": None,
                "command_sha256": "f" * 64,
                "previous_command_sha256": "0" * 64,
            }
        )
        armed = fixture_evidence.operator.model_copy(
            update={
                "version": 2,
                "observed_at": reserve_now - timedelta(milliseconds=300),
                "changed_at": reserve_now - timedelta(milliseconds=300),
                "previous_command_sha256": disarmed.command_sha256,
            }
        )
        await operator_writer.append_operator_observation_async(disarmed)
        await operator_writer.append_operator_observation_async(armed)
        request = signing_request.model_copy(update={"expires_at": reserve_now + timedelta(seconds=20)})
        message = json.loads(request.message_json)
        decision_id = "f" * 64
        risk = fixture_evidence.risk.model_copy(
            update={
                "decision_id": decision_id,
                "effect_id": signing_effect_id(request=request, message=message, decision_id=decision_id),
                "observed_at": reserve_now - timedelta(milliseconds=200),
                "valid_until": reserve_now + timedelta(seconds=20),
            }
        )
        await risk_writer.append_risk_decision_async(risk)
        source = AsyncPostgresProductionSigningStateSource(
            runtime_pool,
            expected_database=claims_settings["DATABASE"],
            database_uuid=database_uuid,
            policy_namespace=claims_settings["POLICY_NAMESPACE"],
            runtime_role=runtime_role,
            context=context,
        )
        authorization._source = source
        authorization._claim_database_uuid = database_uuid
        await authorization.verify_request_async(request, custody_binding)
        assert (
            await owner.fetchval(
                "SELECT count(*) FROM kairos_production_state_v1.risk_reservations WHERE account_sha256=$1",
                _account_scope_sha256(context),
            )
            == 1
        )

        terminal_binding = ReservationTradeBindingV1(
            trade_id="e" * 64,
            decision_id=risk.decision_id,
            effect_id=risk.effect_id,
            lifecycle_entry_effect_id="b" * 64,
            signing_request_id=request.request_id,
            client_order_id=message["id"],
            exchange_parent_order_id="synthetic-entry-venue-order-01",
        )
        close_now = datetime.now(UTC)
        quantity = Decimal(str(message["quantity"]))
        trade, facts = _synthetic_trade_facts(
            context=context,
            binding=terminal_binding,
            quantity=quantity,
            observed_at=close_now,
        )
        effects = [
            {
                "effect_key": terminal_binding.lifecycle_entry_effect_id,
                "status": "RECONCILED",
                "trade_id": terminal_binding.trade_id,
                "account_id": context.remote_account_id,
                "environment": f"PROD:{canonical_digest(context)}:LIVE",
                "exchange": "evedex",
                "symbol": message["instrument"],
                "client_order_id": terminal_binding.client_order_id,
                "exchange_effect_id": terminal_binding.exchange_parent_order_id,
                "journal_head_sha256": "8" * 64,
            }
        ]
        evidence = {
            "source_id": "synthetic-native-terminal-verifier",
            "source_evidence_sha256": "d" * 64,
            "context_sha256": canonical_digest(context),
            "account_id": context.remote_account_id,
            "trade_id": terminal_binding.trade_id,
            "decision_id": terminal_binding.decision_id,
            "effect_id": terminal_binding.effect_id,
            "lifecycle_entry_effect_id": terminal_binding.lifecycle_entry_effect_id,
            "signing_request_id": terminal_binding.signing_request_id,
            "client_order_id": terminal_binding.client_order_id,
            "exchange_parent_order_id": terminal_binding.exchange_parent_order_id,
            "collection_started_at": close_now - timedelta(seconds=4),
            "collection_finished_at": close_now - timedelta(seconds=3),
            "observed_at": close_now - timedelta(seconds=2),
            "complete": True,
            "terminal": True,
            "entry_filled_quantity": quantity,
            "closed_quantity": quantity,
            "entry_notional_usd": Decimal("1000"),
            "exit_notional_usd": Decimal("1010"),
            "entry_fees_usd": Decimal("0.1"),
            "exit_fees_usd": Decimal("0.1"),
            "residual_position_quantity": Decimal("0"),
            "residual_order_count": 0,
            "residual_protection_count": 0,
            "unowned_exposure_count": 0,
        }
        reconciler = ProductionReservationReconciler(
            pool=reconciler_pool,
            expected_database=claims_settings["DATABASE"],
            database_uuid=database_uuid,
            policy_namespace=claims_settings["POLICY_NAMESPACE"],
            context=context,
            expected_role=os.getenv(prefix + "RECONCILER_ROLE"),
            source_verifiers={"synthetic-native-terminal-verifier": _SyntheticTerminalVerifier(evidence)},
            trades=_SyntheticTradeRepository(trade, facts),
            effects=_SyntheticEffectRepository(effects),
            clock=lambda: close_now,
        )
        receipt = await reconciler.reconcile_terminal(
            binding=terminal_binding,
            raw_venue_evidence="synthetic-native-terminal-v1",
            source_id="synthetic-native-terminal-verifier",
        )
        assert receipt["created"] is True
        receipt_row = await reconciler_pool.fetchrow(
            f"SELECT receipt_id,venue_source_id,entry_filled_quantity,closed_quantity,"
            f"entry_notional_usd,exit_notional_usd,entry_fees_usd,exit_fees_usd,payload_sha256 "
            f"FROM {RECONCILIATION_SCHEMA}.terminal_receipts "
            "WHERE account_sha256=$1 AND effect_id=$2",
            _account_scope_sha256(context),
            terminal_binding.effect_id,
        )
        assert receipt_row is not None
        assert receipt_row["receipt_id"] == UUID(receipt["receipt_id"])
        assert receipt_row["venue_source_id"] == "synthetic-native-terminal-verifier"
        assert receipt_row["entry_filled_quantity"] == quantity
        assert receipt_row["closed_quantity"] == quantity
        assert receipt_row["entry_notional_usd"] == Decimal("1000")
        assert receipt_row["exit_notional_usd"] == Decimal("1010")
        assert receipt_row["entry_fees_usd"] == Decimal("0.1")
        assert receipt_row["exit_fees_usd"] == Decimal("0.1")
        assert receipt_row["payload_sha256"] == receipt["payload_sha256"]
        replay = await reconciler.reconcile_terminal(
            binding=terminal_binding,
            raw_venue_evidence="synthetic-native-terminal-v1",
            source_id="synthetic-native-terminal-verifier",
        )
        assert replay["created"] is False and replay["receipt_id"] == receipt["receipt_id"]
        with pytest.raises(ProductionReconciliationError, match="rebound"):
            await reconciler.reconcile_terminal(
                binding=terminal_binding,
                raw_venue_evidence="synthetic-native-rebound-v1",
                source_id="synthetic-native-terminal-verifier",
            )
        assert (
            await reconciler_pool.fetchval(
                f"SELECT count(*) FROM {RECONCILIATION_SCHEMA}.terminal_receipts "
                "WHERE account_sha256=$1 AND effect_id=$2",
                _account_scope_sha256(context),
                terminal_binding.effect_id,
            )
            == 1
        )
    except (asyncpg.PostgresError, OSError):
        pytest.fail("fresh isolated native lifecycle store fixture unavailable", pytrace=False)
    finally:
        if runtime_pool is not None:
            await runtime_pool.close()
        for pool in writer_pools.values():
            await pool.close()
        if reconciler_pool is not None:
            await reconciler_pool.close()
        if owner is not None:
            await owner.close()
