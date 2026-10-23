"""Fresh native PG accounting; synthetic authority/history only, no venue calls.

The explicit fixture admin DSN must target a disposable test server. Every run
creates a NEW database and roles, never resets/reuses/deletes prior evidence.
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID, uuid4

import asyncpg
import pytest

from kairos_execution.production_accounting import (
    SCHEMA as ACCOUNTING_SCHEMA,
)
from kairos_execution.production_accounting import (
    PostgresProductionAccounting,
    ProductionAccountingError,
    provision_production_accounting_schema,
    terminal_economics,
)
from kairos_execution.production_claims import PostgresProductionClaims, provision_isolated_schema
from kairos_execution.production_readiness import canonical_digest
from kairos_execution.production_reconciliation import (
    ACCOUNTING_SCHEMA as RECEIPT_SCHEMA,
)
from kairos_execution.production_reconciliation import (
    ProductionReconciliationError,
    ProductionReservationReconciler,
    ReservationTradeBindingV1,
    VenueTerminalEvidenceV2,
    _canonical_sha256,
    provision_production_reconciliation_schema,
)
from kairos_execution.production_state import (
    AsyncPostgresProductionSigningStateSource,
    PostgresOperatorStateWriter,
    PostgresRiskStateWriter,
    ProductionStateError,
    _account_scope_sha256,
    _reservation_totals_query,
    provision_production_state_schema,
)
from kairos_execution.signing_authorization import signing_effect_id
from tests.test_integration_production_lifecycle_store import (
    _synthetic_trade_facts,
    _SyntheticEffectRepository,
    _SyntheticTradeRepository,
)
from tests.test_signing_authorization import fixture


class _SyntheticAccountingVerifier:
    """Explicit fixture authority; this never claims actual EVEDEX coverage."""

    def __init__(self, evidence):
        self.evidence = evidence

    def verify_terminal_evidence(self, raw_evidence, *, context, binding):
        assert raw_evidence == "synthetic-accounting-proof"
        return VenueTerminalEvidenceV2.model_validate(self.evidence)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_fresh_v3_native_accounting_receipts_concurrency_and_loss_floor():
    admin_dsn = os.getenv("KAIROS_PRODUCTION_ACCOUNTING_FIXTURE_ADMIN_DSN")
    if not admin_dsn:
        pytest.skip("explicit fresh disposable PostgreSQL fixture admin DSN required")
    delayed_acceptance = float(os.getenv("KAIROS_PRODUCTION_ACCOUNTING_DELAYED_ACCEPTANCE_SECONDS", "0"))
    if not 0 <= delayed_acceptance <= 180:
        pytest.fail("optional accounting outage probe must be between zero and 180 seconds", pytrace=False)
    parsed = urlsplit(admin_dsn)
    if parsed.hostname not in {"127.0.0.1", "localhost"} or not parsed.path.startswith(
        "/kairos_execution_test_"
    ):
        pytest.fail("accounting test admin must be the explicit local disposable test fixture", pytrace=False)
    suffix = uuid4().hex[:12]
    database = f"kairos_production_evidence_{suffix}"
    roles = {
        name: f"acct_{name}_{suffix}"
        for name in ("owner", "runtime", "operator", "risk", "exposure", "reconciler", "accounting")
    }
    print(f"created accounting fixture database={database} roles={','.join(roles.values())}", flush=True)
    admin = await asyncpg.connect(admin_dsn)
    connections = []
    pools = {}
    try:
        for role in roles.values():
            await admin.execute(f"CREATE ROLE \"{role}\" LOGIN NOINHERIT PASSWORD 'synthetic_fixture_only'")
        await admin.execute(f'CREATE DATABASE "{database}" OWNER "{roles["owner"]}"')
        for name, role in roles.items():
            dsn = urlunsplit(
                (
                    parsed.scheme,
                    f"{role}:synthetic_fixture_only@{parsed.hostname}:{parsed.port}",
                    f"/{database}",
                    "",
                    "",
                )
            )
            if name == "owner":
                owner = await asyncpg.connect(dsn)
                connections.append(owner)
            else:
                pools[name] = await asyncpg.create_pool(dsn, min_size=1, max_size=3)
        await owner.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
        _, original_request, custody_binding, initial, _ = fixture()
        context = custody_binding.context
        database_uuid = uuid4()
        common = dict(
            expected_database=database,
            database_uuid=database_uuid,
            policy_namespace="synthetic:accounting",
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
        claims = PostgresProductionClaims(pools["runtime"], **common, runtime_role=roles["runtime"])
        assert await claims.consume_once_async(
            owner_identity=initial.owner_arm.request.owner_identity,
            nonce=initial.owner_arm.request.nonce,
            request_sha256=canonical_digest(initial.owner_arm.request),
        )
        state_common = dict(**common, state_schema_version=3)
        operator = PostgresOperatorStateWriter(
            pools["operator"], **state_common, expected_role=roles["operator"]
        )
        risk_writer = PostgresRiskStateWriter(pools["risk"], **state_common, expected_role=roles["risk"])
        source = AsyncPostgresProductionSigningStateSource(
            pools["runtime"], **state_common, runtime_role=roles["runtime"]
        )
        accounting = PostgresProductionAccounting(
            pools["accounting"], **common, accounting_role=roles["accounting"]
        )
        await operator.append_owner_arm_async(initial.owner_arm)
        now = datetime.now(UTC)
        disarmed = initial.operator.model_copy(
            update=dict(
                version=1,
                state="DISARMED",
                arm_nonce=None,
                arm_request_sha256=None,
                expires_at=None,
                observed_at=now - timedelta(milliseconds=400),
                changed_at=now - timedelta(milliseconds=400),
                command_sha256="f" * 64,
                previous_command_sha256="0" * 64,
            )
        )
        armed = initial.operator.model_copy(
            update=dict(
                version=2,
                observed_at=now - timedelta(milliseconds=300),
                changed_at=now - timedelta(milliseconds=300),
                previous_command_sha256=disarmed.command_sha256,
            )
        )
        await operator.append_operator_observation_async(disarmed)
        await operator.append_operator_observation_async(armed)

        async def prepare(index, *, notional="60", risk_amount="1"):
            at = datetime.now(UTC)
            message = json.loads(original_request.message_json)
            message.update(
                id=f"00384:ABCDEF0123456789ABCDEF{index:04d}",
                quantity=10**8,
                limitPrice=int(Decimal(notional) * 10**8),
            )
            request = original_request.model_copy(
                update=dict(
                    request_id=f"synthetic-request-{index}",
                    message_json=json.dumps(message),
                    expires_at=at + timedelta(seconds=20),
                )
            )
            decision_id = f"{index:064x}"
            risk = initial.risk.model_copy(
                update=dict(
                    decision_id=decision_id,
                    signing_request_id=request.request_id,
                    client_order_id=message["id"],
                    quantity=message["quantity"],
                    price=message["limitPrice"],
                    effect_id=signing_effect_id(request=request, message=message, decision_id=decision_id),
                    worst_case_loss_usd=Decimal(risk_amount),
                    observed_at=at - timedelta(milliseconds=20),
                    valid_until=at + timedelta(seconds=4),
                )
            )
            await risk_writer.append_risk_decision_async(risk)
            persisted_before = await owner.fetchrow(
                "SELECT * FROM kairos_production_state_v1.risk_decisions "
                "WHERE context_sha256=$1 AND signing_request_id=$2",
                canonical_digest(context),
                risk.signing_request_id,
            )
            assert persisted_before is not None
            persisted_before = dict(persisted_before)
            count_before = await owner.fetchval(
                "SELECT count(*) FROM kairos_production_state_v1.risk_decisions "
                "WHERE context_sha256=$1 AND signing_request_id=$2",
                canonical_digest(context),
                risk.signing_request_id,
            )
            # Exact publication replay is safe under concurrency, but it must
            # not create another immutable decision row or refresh its lease.
            await asyncio.gather(
                risk_writer.append_risk_decision_async(risk),
                risk_writer.append_risk_decision_async(risk),
            )
            persisted_after_replay = await owner.fetchrow(
                "SELECT * FROM kairos_production_state_v1.risk_decisions "
                "WHERE context_sha256=$1 AND signing_request_id=$2",
                canonical_digest(context),
                risk.signing_request_id,
            )
            count_after_replay = await owner.fetchval(
                "SELECT count(*) FROM kairos_production_state_v1.risk_decisions "
                "WHERE context_sha256=$1 AND signing_request_id=$2",
                canonical_digest(context),
                risk.signing_request_id,
            )
            assert persisted_after_replay is not None
            assert dict(persisted_after_replay) == persisted_before
            assert count_after_replay == count_before

            # Reusing the same request identity with changed order geometry is
            # a hard conflict and leaves the original evidence untouched.
            with pytest.raises(ProductionStateError, match="risk signing-request identity was rebound"):
                await risk_writer.append_risk_decision_async(
                    risk.model_copy(update={"quantity": risk.quantity + 1})
                )
            persisted_after = await owner.fetchrow(
                "SELECT * FROM kairos_production_state_v1.risk_decisions "
                "WHERE context_sha256=$1 AND signing_request_id=$2",
                canonical_digest(context),
                risk.signing_request_id,
            )
            count_after = await owner.fetchval(
                "SELECT count(*) FROM kairos_production_state_v1.risk_decisions "
                "WHERE context_sha256=$1 AND signing_request_id=$2",
                canonical_digest(context),
                risk.signing_request_id,
            )
            assert persisted_after is not None
            assert dict(persisted_after) == persisted_before
            assert count_after == count_before
            evidence = initial.model_copy(update=dict(risk=risk, operator=armed))
            return request, evidence

        async def reserve(pair):
            await source.reserve_entry_async(request=pair[0], binding=custody_binding, evidence=pair[1])

        async def terminal(pair, *, trade_digit, entry_notional, exit_notional):
            request, evidence = pair
            risk = evidence.risk
            row = await owner.fetchrow(
                "SELECT * FROM kairos_production_state_v1.risk_reservations WHERE effect_id=$1",
                risk.effect_id,
            )
            binding = ReservationTradeBindingV1(
                trade_id=trade_digit * 64,
                decision_id=risk.decision_id,
                effect_id=risk.effect_id,
                lifecycle_entry_effect_id="b" * 64,
                signing_request_id=request.request_id,
                client_order_id=risk.client_order_id,
                exchange_parent_order_id=f"synthetic-venue-{trade_digit}",
            )
            at = datetime.now(UTC)
            trade, facts = _synthetic_trade_facts(
                context=context, binding=binding, quantity=Decimal("1"), observed_at=at
            )
            effects = [
                dict(
                    effect_key=binding.lifecycle_entry_effect_id,
                    status="RECONCILED",
                    trade_id=binding.trade_id,
                    account_id=context.remote_account_id,
                    environment=f"PROD:{canonical_digest(context)}:LIVE",
                    exchange="evedex",
                    symbol=risk.instrument,
                    client_order_id=binding.client_order_id,
                    exchange_effect_id=binding.exchange_parent_order_id,
                    journal_head_sha256="8" * 64,
                )
            ]
            proof = dict(
                source_id="synthetic-accounting-verifier",
                source_evidence_sha256="d" * 64,
                context_sha256=canonical_digest(context),
                account_id=context.remote_account_id,
                **binding.model_dump(),
                collection_started_at=at - timedelta(milliseconds=5),
                collection_finished_at=at,
                observed_at=at,
                complete=True,
                terminal=True,
                entry_filled_quantity=Decimal("1"),
                closed_quantity=Decimal("1"),
                entry_notional_usd=Decimal(entry_notional),
                exit_notional_usd=Decimal(exit_notional),
                entry_fees_usd=Decimal("0.1"),
                exit_fees_usd=Decimal("0.1"),
                residual_position_quantity=Decimal("0"),
                residual_order_count=0,
                residual_protection_count=0,
                unowned_exposure_count=0,
                entry_side="BUY",
                funding_cost_usd=Decimal("0.1"),
                funding_complete=True,
                settled_at=at,
                owner_arm_sha256=row["owner_arm_sha256"],
                reservation_request_sha256=row["request_sha256"],
            )
            verifier = _SyntheticAccountingVerifier(proof)
            reconciler = ProductionReservationReconciler(
                pool=pools["reconciler"],
                **common,
                expected_role=roles["reconciler"],
                source_verifiers={proof["source_id"]: verifier},
                trades=_SyntheticTradeRepository(trade, facts),
                effects=_SyntheticEffectRepository(effects),
                clock=lambda: at,
                schema_version=2,
            )
            kwargs = dict(
                binding=binding, raw_venue_evidence="synthetic-accounting-proof", source_id=proof["source_id"]
            )
            # Native failure probes are uncommitted throwaway transactions;
            # no existing history is altered or deleted. A forged receipt
            # whose body disagrees with its typed columns cannot release even
            # through direct INSERT, bypassing the Python acceptor.
            payload = VenueTerminalEvidenceV2(**proof).model_dump(mode="json")
            for old, new in (
                ("source_id", "venue_source_id"),
                ("source_evidence_sha256", "venue_evidence_sha256"),
                ("complete", "venue_complete"),
                ("terminal", "venue_terminal"),
            ):
                payload[new] = payload.pop(old)
            payload.pop("account_id")
            payload.update(
                database_uuid=str(database_uuid),
                account_sha256=_account_scope_sha256(context),
                trade_journal_head_sha256="9" * 64,
                execution_facts_sha256="7" * 64,
                owned_effects_sha256="8" * 64,
            )

            async def insert_receipt(receipt_payload, *, forge_body=False, connection=owner):
                receipt_id = uuid4()
                names = ",".join(receipt_payload)
                expressions = ",".join(
                    "x.entry_notional_usd+1" if name == "entry_notional_usd" and forge_body else f"x.{name}"
                    for name in receipt_payload
                )
                await connection.execute(
                    f"INSERT INTO {RECEIPT_SCHEMA}.terminal_receipts "
                    f"(receipt_id,{names},payload,payload_sha256) "
                    f"SELECT $1,{expressions},$2::jsonb,$3 FROM jsonb_populate_record("
                    f"NULL::{RECEIPT_SCHEMA}.terminal_receipts,$2::jsonb) x",
                    receipt_id,
                    json.dumps(receipt_payload),
                    _canonical_sha256(receipt_payload),
                )
                return receipt_id

            # The append-only reconciler cannot backdate an acceptance to make
            # stale evidence look historically fresh. The database stamps its
            # own clock even when the caller explicitly supplies inserted_at.
            async with pools["reconciler"].acquire() as connection:
                transaction = connection.transaction()
                await transaction.start()
                try:
                    stamped_id = await insert_receipt(
                        {**payload, "inserted_at": (at - timedelta(minutes=5)).isoformat()},
                        connection=connection,
                    )
                    stamped = await connection.fetchval(
                        f"SELECT inserted_at FROM {RECEIPT_SCHEMA}.terminal_receipts WHERE receipt_id=$1",
                        stamped_id,
                    )
                    assert stamped >= at
                finally:
                    await transaction.rollback()
                with pytest.raises(asyncpg.RaiseError, match="stale at database acceptance"):
                    async with connection.transaction():
                        await insert_receipt(
                            {
                                **payload,
                                **{
                                    key: (at - timedelta(minutes=3)).isoformat()
                                    for key in (
                                        "collection_started_at",
                                        "collection_finished_at",
                                        "observed_at",
                                        "settled_at",
                                    )
                                },
                                "inserted_at": (at - timedelta(minutes=3)).isoformat(),
                            },
                            connection=connection,
                        )

            with pytest.raises(asyncpg.RaiseError, match="payload/column conflict"):
                async with owner.transaction():
                    forged_id = await insert_receipt(payload, forge_body=True)
                    economics = terminal_economics(payload)
                    fields = {
                        "receipt_id": str(forged_id),
                        "database_uuid": str(database_uuid),
                        **{
                            key: payload[key]
                            for key in (
                                "context_sha256",
                                "account_sha256",
                                "effect_id",
                                "trade_id",
                                "owner_arm_sha256",
                                "reservation_request_sha256",
                                "settled_at",
                            )
                        },
                        "receipt_payload_sha256": _canonical_sha256(payload),
                        **{key: str(value) for key, value in economics.items()},
                    }
                    names = ",".join(fields)
                    await owner.execute(
                        f"INSERT INTO {ACCOUNTING_SCHEMA}.accepted_releases ({names}) "
                        + "SELECT "
                        + ",".join(f"x.{name}" for name in fields)
                        + " FROM jsonb_populate_record("
                        + f"NULL::{ACCOUNTING_SCHEMA}.accepted_releases,$1::jsonb) x",
                        json.dumps(fields),
                    )
            for unknown in (False, None):
                with pytest.raises((asyncpg.CheckViolationError, asyncpg.NotNullViolationError)):
                    async with owner.transaction():
                        await insert_receipt({**payload, "funding_complete": unknown})
            for conflict in (
                {"funding_complete": False},
                {"owner_arm_sha256": "0" * 64},
                {"reservation_request_sha256": "0" * 64},
                {"entry_side": "SELL"},
                {"unowned_exposure_count": 1},
                {"closed_quantity": Decimal("0.5")},
            ):
                verifier.evidence = {**proof, **conflict}
                with pytest.raises(ProductionReconciliationError):
                    await reconciler.reconcile_terminal(**kwargs)
            verifier.evidence = proof
            receipt = await reconciler.reconcile_terminal(**kwargs)
            # An exact immutable replay remains the same receipt after the raw
            # proof's ordinary two-minute collection window has elapsed.
            reconciler._clock = lambda: at + timedelta(minutes=3)
            assert not (await reconciler.reconcile_terminal(**kwargs))["created"]
            if trade_digit == "e" and delayed_acceptance:
                print(
                    f"native original receipt retained during {delayed_acceptance:g}s accounting outage",
                    flush=True,
                )
                await asyncio.sleep(delayed_acceptance)
                reconciler._clock = lambda: datetime.now(UTC)
                replay = await reconciler.reconcile_terminal(**kwargs)
                assert replay == {**receipt, "created": False}
            verifier.evidence = {**proof, "source_evidence_sha256": "e" * 64}
            with pytest.raises(ProductionReconciliationError, match="rebound"):
                await reconciler.reconcile_terminal(**kwargs)
            return receipt

        first = await prepare(1, notional="100")
        await reserve(first)
        first_receipt = await terminal(first, trade_digit="e", entry_notional="100", exit_notional="110")
        # A terminal receipt alone does not release. Missing/unrecognized UUID
        # and conflicting expected receipt hash cannot create accounting rows.
        with pytest.raises(ProductionAccountingError):
            await accounting.accept_terminal_receipt(receipt_id=uuid4(), receipt_payload_sha256="a" * 64)
        with pytest.raises(ProductionAccountingError):
            await accounting.accept_terminal_receipt(
                receipt_id=UUID(first_receipt["receipt_id"]), receipt_payload_sha256="a" * 64
            )
        next_pair = await prepare(2, risk_amount="9.5")
        with pytest.raises(
            ProductionStateError, match="current operator command changed" if delayed_acceptance else None
        ):
            await reserve(next_pair)
        accepted = dict(
            receipt_id=UUID(first_receipt["receipt_id"]),
            receipt_payload_sha256=first_receipt["payload_sha256"],
        )
        releases = await asyncio.gather(
            accounting.accept_terminal_receipt(**accepted), accounting.accept_terminal_receipt(**accepted)
        )
        assert sorted(item["created"] for item in releases) == [False, True]
        assert all(item["loss_charge_usd"] == Decimal("0.3") for item in releases)
        if delayed_acceptance:
            # This explicit real-time outage branch tests recovery only. The
            # default independent fresh fixture covers subsequent admission and
            # loss-floor races without renewing an expired operator lease.
            accepted_row = await owner.fetchrow(
                "SELECT a.accepted_at,t.inserted_at,t.observed_at FROM "
                f"{ACCOUNTING_SCHEMA}.accepted_releases a "
                f"JOIN {RECEIPT_SCHEMA}.terminal_receipts t USING(receipt_id) WHERE receipt_id=$1",
                accepted["receipt_id"],
            )
            assert (
                accepted_row["accepted_at"] - accepted_row["inserted_at"]
            ).total_seconds() >= delayed_acceptance
            assert (accepted_row["inserted_at"] - accepted_row["observed_at"]).total_seconds() <= 120
            assert armed.expires_at <= await owner.fetchval("SELECT clock_timestamp()")
            with pytest.raises(ProductionStateError, match="current operator command changed"):
                await reserve(await prepare(6))
            assert (
                await owner.fetchval("SELECT count(*) FROM kairos_production_state_v1.risk_reservations") == 1
            )
            assert await owner.fetchval(f"SELECT count(*) FROM {RECEIPT_SCHEMA}.terminal_receipts") == 1
            assert await owner.fetchval(f"SELECT count(*) FROM {ACCOUNTING_SCHEMA}.accepted_releases") == 1
            print(
                "delayed original-receipt accounting recovered; expired operator authority stayed expired",
                flush=True,
            )
            return
        # Actual same-account concurrent reservations: exactly one fits. Risk
        # and notional totals are serialized under the shared account lock.
        pairs = await asyncio.gather(prepare(3), prepare(4))
        outcomes = await asyncio.gather(*(reserve(pair) for pair in pairs), return_exceptions=True)
        assert sum(value is None for value in outcomes) == 1
        assert sum(isinstance(value, ProductionStateError) for value in outcomes) == 1
        winner = pairs[next(index for index, value in enumerate(outcomes) if value is None)]
        second_receipt = await terminal(winner, trade_digit="f", entry_notional="60", exit_notional="40")
        await accounting.accept_terminal_receipt(
            receipt_id=UUID(second_receipt["receipt_id"]),
            receipt_payload_sha256=second_receipt["payload_sha256"],
        )
        totals = await owner.fetchrow(_reservation_totals_query(3), _account_scope_sha256(context))
        assert totals["risk_usd"] == totals["notional_usd"] == 0
        assert totals["realized_charge"] == Decimal("20.6")
        assert totals["dollar_cap"] == 100 and totals["daily_stop"] == 10
        with pytest.raises(ProductionStateError):
            await reserve(await prepare(5))
        assert await owner.fetchval("SELECT count(*) FROM kairos_production_state_v1.risk_reservations") == 2
        assert await owner.fetchval(f"SELECT count(*) FROM {ACCOUNTING_SCHEMA}.accepted_releases") == 2
        fk_count = await owner.fetchval(
            "SELECT count(*) FROM pg_constraint WHERE conrelid=$1::regclass AND contype='f'",
            f"{ACCOUNTING_SCHEMA}.accepted_releases",
        )
        assert fk_count == 2
        for role in (roles["runtime"], roles["accounting"], roles["reconciler"]):
            for table in (
                f"{ACCOUNTING_SCHEMA}.accepted_releases",
                f"{RECEIPT_SCHEMA}.terminal_receipts",
                "kairos_production_state_v1.risk_reservations",
            ):
                for privilege in ("UPDATE", "DELETE", "TRUNCATE", "TRIGGER", "REFERENCES"):
                    assert not await owner.fetchval(
                        "SELECT has_table_privilege($1,$2,$3)", role, table, privilege
                    )
        assert not await owner.fetchval(
            "SELECT has_table_privilege($1,$2,'INSERT')",
            roles["runtime"],
            f"{ACCOUNTING_SCHEMA}.accepted_releases",
        )
        with pytest.raises(asyncpg.RaiseError, match="immutable"):
            await owner.execute(f"UPDATE {ACCOUNTING_SCHEMA}.accepted_releases SET loss_charge_usd=0")
    finally:
        for pool in pools.values():
            await pool.close()
        for connection in connections:
            await connection.close()
        await admin.close()
