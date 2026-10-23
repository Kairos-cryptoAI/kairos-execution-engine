"""Native PostgreSQL PROD lifecycle composition with explicitly synthetic authority/venue.

The PostgreSQL execution FSM/journals and managed signer/dispatcher types are
real. Owner/operator/risk evidence, claims, cancellation transport, SDK reader,
and venue are deterministic local doubles; this is not EVEDEX or deployed PROD
qualification evidence.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any
from uuid import UUID

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from kairos_core.enums import EvedexProfile, OrderRole, TradeExecutionEventType, TradeExitReason
from kairos_persistence import (
    ExecutionJournalRepository,
    TradeLifecycleRepository,
    TradeState,
)

from kairos_execution.adapters.evedex_sidecar import EvedexSidecarAdapter
from kairos_execution.managed_signer import (
    CustodyBindingV1,
    ManagedSignerBoundary,
    reviewed_schema_sha256,
)
from kairos_execution.production_cancellation import (
    CancellationOrderFactV1,
    CancellationProtectionFactV1,
    ProductionCancellationVenueSnapshotV1,
    ProductionCancellationVerifier,
)
from kairos_execution.production_dispatch import ProductionEffectDispatcher
from kairos_execution.production_lifecycle import (
    ProductionLifecycleConfigV1,
    ProductionLifecycleEngine,
    ProductionVenueHealthV1,
)
from kairos_execution.production_lifecycle_adapter import ManagedProductionLifecycleAdapter
from kairos_execution.production_lifecycle_binding import build_production_lifecycle_binding
from kairos_execution.production_lifecycle_store import PostgresLifecycleBindingStore
from kairos_execution.production_readiness import (
    ManualArmRequestV1,
    OwnerArmKeyV1,
    PreconditionsV1,
    ProductionContextV1,
    SignedManualArmRequestV1,
    canonical_digest,
)
from kairos_execution.production_runtime import ProductionExecutionRuntime
from kairos_execution.production_state import AcceptedEntryReservationV1, _account_scope_sha256
from kairos_execution.profiles import profile_params
from kairos_execution.signing_authorization import (
    AcceptedManualNonceV1,
    ExposureSnapshotV1,
    LiveOperatorStateV1,
    ProductionSigningAuthorizationVerifier,
    ProductionSigningEvidenceV1,
    RiskGeometryV1,
    signing_effect_id,
)
from tests.paper_fixtures import T0
from tests.test_integration_paper_engine import MutableClock
from tests.test_managed_signer import setup_signer
from tests.test_production_dispatch import SyntheticSignatureVerifier
from tests.test_production_lifecycle_binding import _decision
from tests.test_production_runtime import SyntheticPostgresClaims, SyntheticPostgresStateSource

pytest_plugins = ("tests.test_integration_paper_engine",)
pytestmark = pytest.mark.integration


@pytest.fixture
async def production_pg_runtime(paper_runtime):
    """Reuse the existing disposable PostgreSQL bootstrap and clean our exact PROD scope."""
    database, _, clock = paper_runtime
    decision = _decision()
    context = ProductionContextV1(
        remote_account_id=decision.account_id,
        adaptive_system_id=decision.intent.strategy_id,
        frozen_policy_sha256="1" * 64,
        source_set_sha256="2" * 64,
    )
    environment = f"PROD:{canonical_digest(context)}:LIVE"
    try:
        yield database, clock
    finally:
        pool = database.pool
        await pool.execute(
            "DELETE FROM public_execution_events WHERE trade_id IN "
            "(SELECT trade_id FROM execution_trades WHERE environment=$1)",
            environment,
        )
        await pool.execute(
            "DELETE FROM execution_trade_events WHERE trade_id IN "
            "(SELECT trade_id FROM execution_trades WHERE environment=$1)",
            environment,
        )
        await pool.execute("DELETE FROM execution_trades WHERE environment=$1", environment)
        await pool.execute(
            "DELETE FROM execution_effect_events WHERE effect_key IN "
            "(SELECT effect_key FROM execution_effects WHERE environment=$1)",
            environment,
        )
        await pool.execute("DELETE FROM execution_effects WHERE environment=$1", environment)
        await pool.execute("DELETE FROM execution_recovery_state WHERE environment=$1", environment)
        await pool.execute("DELETE FROM account_equity_state WHERE environment=$1", environment)


class _BindingStore(PostgresLifecycleBindingStore):
    def __init__(self, context: ProductionContextV1, pool) -> None:
        self.context = context
        self.pool = pool
        self.plans: dict[str, Any] = {}

    async def get(self, effect_id: str):
        return self.plans.get(effect_id)


class _ProductionReads(EvedexSidecarAdapter):
    """Test-only SDK read surface; all returned venue data is synthetic."""

    name = "evedex"

    def __init__(self, venue: _SyntheticVenue, clock: MutableClock, context: ProductionContextV1):
        self.venue = venue
        self.clock = clock
        self.context = context

    async def preflight(self) -> dict[str, Any]:
        params = profile_params(EvedexProfile.PROD)
        return {
            "profile": "PROD",
            "chain_id": 161803,
            "exchange_url": params.exchange_url,
            "auth_url": params.auth_url,
            "sdk_version": "1.2.11",
            "auth_age_ms": 500,
            "auth_expires_in_ms": 60_000,
            "local_mutation_rate_limit_reserve": 29,
            "local_mutation_rate_limit_capacity": 30,
            "local_mutation_rate_limit_window_ms": 60_000,
            "local_mutation_compensation_reserve": 4,
            "local_mutation_entry_min_reserve": 7,
            "venue_rate_limit_reserve": None,
            "venue_rate_limit_observable": False,
        }

    async def fetch_paper_state(self) -> dict[str, Any]:
        return copy.deepcopy(self.venue.state)

    async def fetch_depth(self, *, symbol: str, max_level: int = 100) -> dict[str, Any]:
        del symbol, max_level
        now_ms = int(self.clock().timestamp() * 1000)
        return {
            "t": now_ms,
            "asks": [{"price": 100.51, "quantity": 1}],
            "bids": [{"price": 100.49, "quantity": 1}],
        }

    async def drain_events(self, *, limit: int = 1000) -> list[dict[str, Any]]:
        del limit
        return []

    async def find_tpsl_record(self, **kwargs):
        for item in self.venue.state["tpsl"]:
            if kwargs.get("tpsl_id") and item["id"] != kwargs["tpsl_id"]:
                continue
            if kwargs.get("tpsl_type") and item["type"] != kwargs["tpsl_type"]:
                continue
            if kwargs.get("price") is not None and item["price"] != kwargs["price"]:
                continue
            if kwargs.get("parent_order_id") and item["order"] != kwargs["parent_order_id"]:
                continue
            return copy.deepcopy(item)
        return None


class _SyntheticVenue:
    def __init__(self, clock: MutableClock, account_id: str) -> None:
        self.clock = clock
        self.calls: list[str] = []
        self.state: dict[str, Any] = {
            "account": {"id": account_id, "exchangeId": account_id, "marginCall": False},
            "balance": {
                "funding": {"balance": "10000"},
                "availableBalance": "10000",
                "positions": [],
                "openOrders": [],
            },
            "positions": [],
            "orders": [],
            "order_history": [],
            "tpsl": [],
            "instruments": [
                {
                    "name": "BTCUSD",
                    "trading": "all",
                    "visibility": "all",
                    "marketState": "OPEN",
                    "markPrice": 100,
                    "updatedAt": datetime.fromtimestamp((T0 + 60_100) / 1000, UTC)
                    .isoformat()
                    .replace("+00:00", "Z"),
                    "lotSize": "1",
                    "multiplier": "1",
                    "priceIncrement": "0.01",
                    "quantityIncrement": "0.1",
                    "minPrice": "1",
                    "maxPrice": "1000000",
                    "minQuantity": "0.1",
                    "maxQuantity": "100",
                    "minVolume": "5",
                }
            ],
        }

    def partial_entry(self, body: dict[str, Any]) -> dict[str, Any]:
        self.calls.append("ENTRY")
        now = self.clock().isoformat().replace("+00:00", "Z")
        assert body["timeInForce"] == "IOC"
        assert "postOnly" not in body
        quantity = float(body["quantity"])
        filled = quantity / 2
        response = {
            "id": body["id"],
            "instrument": "BTCUSD",
            "side": body["side"],
            "type": "LIMIT",
            "quantity": quantity,
            "unFilledQuantity": quantity - filled,
            "limitPrice": float(body["limitPrice"]),
            "filledAvgPrice": 100,
            "status": "PARTIALLY_FILLED",
            "createdAt": now,
            "updatedAt": now,
        }
        self.entry_client_order_id = body["id"]
        self.state["positions"] = [
            {
                "instrument": "BTCUSD",
                "side": body["side"],
                "quantity": filled,
                "avgPrice": 100,
                "markPrice": 100,
                "leverage": 1,
                "unRealizedPnL": 0,
            }
        ]
        self.state["balance"]["positions"] = [
            {"instrument": "BTCUSD", "side": body["side"], "volume": filled, "initialMargin": 10}
        ]
        self.state["orders"] = [copy.deepcopy(response)]
        self.state["balance"]["openOrders"] = [copy.deepcopy(response)]
        self.state["order_history"] = [copy.deepcopy(response)]
        return response

    def protect(self, body: dict[str, Any]) -> dict[str, Any]:
        role = "STOP_LOSS" if body["type"] == "stop-loss" else "TAKE_PROFIT"
        self.calls.append(role)
        record = {
            "id": f"synthetic-{role.lower()}",
            "instrument": "BTCUSD",
            "side": body["side"],
            "type": body["type"],
            "quantity": 0,
            "price": float(body["price"]),
            "order": body["order"],
            "status": "active",
        }
        self.state["tpsl"].append(record)
        return copy.deepcopy(record)


class _TimedSyntheticPostgresClaims(SyntheticPostgresClaims):
    """Synthetic one-use store with the timestamps the production verifier requires."""

    def __init__(self, *, database_uuid, context, clock):
        super().__init__(database_uuid=database_uuid, context=context)
        self.clock = clock

    async def claim(self, kind, namespace, identity, request_sha256):
        admitted = await super().claim(kind, namespace, identity, request_sha256)
        if admitted:
            self.claims[(kind, namespace, identity)]["claimed_at"] = self.clock()
        return admitted

    async def load_claim(self, *, kind, namespace, identity):
        record = await super().load_claim(kind=kind, namespace=namespace, identity=identity)
        if record is None:
            return None
        return {
            **record,
            "claim_kind": kind,
            "namespace": namespace,
            "identity": identity,
        }


class _SyntheticCancellationVenueSource:
    """Registered typed cancellation snapshot source backed by local venue state."""

    source_id = "synthetic-prod-venue"

    def __init__(self, *, context: ProductionContextV1, venue: _SyntheticVenue, clock: MutableClock):
        self.context = context
        self.venue = venue
        self.clock = clock

    async def read_cancellation_snapshot_async(self, *, context, account_id, instrument):
        if context != self.context or account_id != self.context.remote_account_id or instrument != "BTCUSD":
            raise ValueError("synthetic cancellation scope mismatch")
        state = self.venue.state
        raw_position = state["positions"][0] if state["positions"] else None
        position_quantity = Decimal("0") if raw_position is None else Decimal(str(raw_position["quantity"]))
        position_side = None if raw_position is None else raw_position["side"]
        entry_order = next(
            (row for row in state["orders"] if row["id"] == self.venue.entry_client_order_id), None
        )
        orders = ()
        if entry_order is not None:
            orders = (
                CancellationOrderFactV1(
                    order_id=entry_order["id"],
                    instrument="BTCUSD",
                    role="ENTRY",
                    status="PARTIALLY_FILLED",
                    side=entry_order["side"],
                    remaining_quantity=Decimal(str(entry_order["unFilledQuantity"])),
                    reduce_only=False,
                ),
            )
        protections = tuple(
            CancellationProtectionFactV1(
                protection_id=item["id"],
                instrument="BTCUSD",
                protection_type="STOP_LOSS" if item["type"] == "stop-loss" else "TAKE_PROFIT",
                status="ACTIVE",
                parent_order_id=item["order"],
                covered_quantity=position_quantity,
            )
            for item in state["tpsl"]
            if item["status"] == "active" and position_quantity > 0
        )
        now = self.clock()
        return ProductionCancellationVenueSnapshotV1(
            context=context,
            source_id=self.source_id,
            account_id=account_id,
            instrument=instrument,
            observed_at=now - timedelta(milliseconds=100),
            valid_until=now + timedelta(seconds=2),
            position_side=position_side,
            position_quantity=position_quantity,
            entry_parent_order_id=self.venue.entry_client_order_id,
            orders=orders,
            protections=protections,
        )

    def verify_cancellation_snapshot(self, raw_snapshot, *, context, account_id, instrument):
        snapshot = ProductionCancellationVenueSnapshotV1.model_validate(raw_snapshot)
        if (
            snapshot.context != context
            or snapshot.account_id != account_id
            or snapshot.instrument != instrument
            or snapshot.source_id != self.source_id
        ):
            raise ValueError("synthetic snapshot identity does not match its registered source")
        return snapshot


class _SyntheticCancellationTransport:
    """Narrow typed SDK cancellation operations against the explicit local venue."""

    def __init__(self, venue: _SyntheticVenue):
        self.venue = venue

    async def cancel_order(self, *, effect_id: str, instrument: str, order_id: str):
        assert instrument == "BTCUSD" and effect_id
        self.venue.calls.append("CANCEL_ENTRY")
        self.venue.state["orders"] = [row for row in self.venue.state["orders"] if row["id"] != order_id]
        self.venue.state["balance"]["openOrders"] = []
        for row in self.venue.state["order_history"]:
            if row["id"] == order_id:
                row["status"] = "CANCELED"
        return {"id": order_id, "status": "CANCELED"}

    async def cancel_tpsl(self, *, effect_id: str, instrument: str, protection_id: str):
        assert instrument == "BTCUSD" and effect_id
        self.venue.calls.append("CANCEL_TPSL")
        for row in self.venue.state["tpsl"]:
            if row["id"] == protection_id:
                row["status"] = "cancelled"
        return {"id": protection_id, "status": "CANCELED"}


def _synthetic_authority(
    *, clock: MutableClock, context: ProductionContextV1, binding: CustodyBindingV1, pool
):
    now = clock()
    database_uuid = UUID("31da18d5-2b77-407d-b0dc-5366f03ae10a")
    private = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    owner_key = OwnerArmKeyV1(
        owner_identity="synthetic-test-owner",
        key_id="synthetic-test-owner-key",
        public_key_base64=base64.b64encode(private.public_key().public_bytes_raw()).decode(),
        context=context,
        valid_from=now - timedelta(minutes=1),
        valid_until=now + timedelta(minutes=5),
    )
    preconditions = PreconditionsV1(
        context=context,
        evidence_sha256="a" * 64,
        verified_at=now - timedelta(seconds=1),
        valid_until=now + timedelta(minutes=4),
        owner_identity="synthetic-test-owner",
        dollar_cap=Decimal("100"),
        daily_stop_loss_usd=Decimal("10"),
    )
    manual = ManualArmRequestV1(
        context=context,
        preconditions_sha256=canonical_digest(preconditions),
        nonce="synthetic-test-arm-once",
        owner_identity="synthetic-test-owner",
        created_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(minutes=3),
        dollar_cap=Decimal("100"),
        daily_stop_loss_usd=Decimal("10"),
    )
    arm_domain = b"kairos.signed-manual-arm-request.v1\x00"
    arm_json = json.dumps(manual.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode()
    owner_arm = SignedManualArmRequestV1(
        request=manual,
        key_id=owner_key.key_id,
        signature_base64=base64.b64encode(private.sign(arm_domain + arm_json)).decode(),
    )
    arm_digest = canonical_digest(manual)
    nonce_claim = AcceptedManualNonceV1(
        owner_identity=manual.owner_identity,
        nonce=manual.nonce,
        request_sha256=arm_digest,
        context_sha256=canonical_digest(context),
        database_uuid=database_uuid,
        claimed_at=now - timedelta(milliseconds=100),
    )
    evidence_template = {
        "owner_arm": owner_arm,
        "owner_nonce_claim": nonce_claim,
        "operator": LiveOperatorStateV1(
            context=context,
            version=1,
            state="ARMED",
            arm_nonce=manual.nonce,
            arm_request_sha256=arm_digest,
            observed_at=now - timedelta(milliseconds=100),
            changed_at=now - timedelta(milliseconds=200),
            expires_at=now + timedelta(minutes=2),
            command_sha256="b" * 64,
            previous_command_sha256="c" * 64,
        ),
        "resolved_at": now,
    }
    source = object.__new__(SyntheticPostgresStateSource)
    source.pool = pool
    source.expected_database = "kairos_production_evidence_synthetic_runtime"
    source.database_uuid = database_uuid
    source.policy_namespace = "synthetic-policy"
    source.context = context
    source.context_sha256 = canonical_digest(context)
    source.role_field = "runtime_role"
    source.expected_role = "synthetic-runtime"
    source.runtime_role = "synthetic-runtime"
    source.reservations = []
    source.plans = {}
    source.decision = None
    source.manual_request_sha256 = arm_digest
    source.clock = clock
    source.owner_arm = owner_arm
    source.owner_nonce_claim = nonce_claim
    source.owner_key = owner_key
    source.preconditions = preconditions
    source.entry_reservation = None

    async def resolve_signing_evidence_async(*, request, binding: CustodyBindingV1, now: datetime):
        del binding
        plan = source.plans[request.request_id]
        message = json.loads(request.message_json)
        operation = request.operation
        entry = operation == "New limit order"
        risk_id = plan.risk_decision_id
        risk = RiskGeometryV1(
            context=context,
            decision_id=risk_id,
            signing_request_id=request.request_id,
            effect_id=signing_effect_id(request=request, message=message, decision_id=risk_id),
            client_order_id=message.get("id"),
            operation=operation,
            instrument=message["instrument"],
            side=message.get("side", "BUY"),
            quantity=message["quantity"],
            cash_quantity=None,
            price=message.get("limitPrice", message.get("price")),
            stop_price=None,
            protection_type=message.get("type"),
            trigger_price=message.get("price") if not entry else None,
            parent_order_id=message.get("order"),
            leverage=1,
            worst_case_loss_usd=Decimal(
                str(source.decision.worst_case_loss_usd) if entry and source.decision is not None else "1"
            ),
            account_equity_usd=Decimal("10000"),
            daily_realized_loss_usd=Decimal("0"),
            aggregate_open_risk_usd=Decimal("0"),
            aggregate_open_notional_usd=Decimal("0"),
            approved=True,
            observed_at=now - timedelta(milliseconds=100),
            valid_until=min(request.expires_at, now + timedelta(seconds=4)),
        )
        exposure = (
            None
            if entry
            else ExposureSnapshotV1(
                context=context,
                instrument=message["instrument"],
                position_side=message["side"],
                remaining_quantity=5_000_000,
                parent_order_id=message["order"],
                observed_at=now - timedelta(milliseconds=100),
                valid_until=min(request.expires_at, now + timedelta(seconds=4)),
            )
        )
        return ProductionSigningEvidenceV1(**evidence_template, risk=risk, exposure=exposure)

    source.resolve_signing_evidence_async = resolve_signing_evidence_async

    async def reserve_entry_async(*, request, binding, evidence):
        source.reservations.append({"request": request, "binding": binding, "evidence": evidence})
        risk = evidence.risk
        notional = Decimal(risk.quantity) * Decimal(risk.price) / Decimal(10**16)
        source.entry_reservation = AcceptedEntryReservationV1(
            context_sha256=canonical_digest(context),
            account_sha256=_account_scope_sha256(context),
            effect_id=risk.effect_id,
            signing_request_id=request.request_id,
            decision_id=risk.decision_id,
            client_order_id=risk.client_order_id,
            owner_arm_sha256=arm_digest,
            risk_evidence=risk,
            observed_at=risk.observed_at,
            reserved_at=clock(),
            risk_usd=risk.worst_case_loss_usd,
            notional_usd=notional,
            account_equity_usd=risk.account_equity_usd,
            daily_realized_loss_usd=risk.daily_realized_loss_usd,
            aggregate_open_risk_usd=risk.aggregate_open_risk_usd,
            aggregate_open_notional_usd=risk.aggregate_open_notional_usd,
            dollar_cap=manual.dollar_cap,
            daily_stop_loss_usd=manual.daily_stop_loss_usd,
            evidence_sha256=canonical_digest(evidence),
            request_sha256=hashlib.sha256(
                json.dumps(
                    {
                        "effect_id": risk.effect_id,
                        "request_id": request.request_id,
                        "owner_arm_sha256": arm_digest,
                        "evidence_sha256": canonical_digest(evidence),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest(),
        )

    async def resolve_owner_lineage_async(manual_request_sha256: str):
        if manual_request_sha256 != arm_digest:
            raise ValueError("synthetic owner lineage digest mismatch")
        return owner_arm, nonce_claim

    async def resolve_entry_reservation_async(
        signing_effect_id: str,
        manual_request_sha256: str,
        signing_request_id: str,
        decision_id: str,
    ):
        reservation = source.entry_reservation
        if (
            reservation is None
            or signing_effect_id != reservation.effect_id
            or manual_request_sha256 != reservation.owner_arm_sha256
            or signing_request_id != reservation.signing_request_id
            or decision_id != reservation.decision_id
        ):
            raise ValueError("synthetic entry reservation does not match immutable entry plan")
        return reservation

    source.reserve_entry_async = reserve_entry_async
    source.resolve_owner_lineage_async = resolve_owner_lineage_async
    source.resolve_entry_reservation_async = resolve_entry_reservation_async
    _, _, backend, typed_verifier, _ = setup_signer()
    claims = _TimedSyntheticPostgresClaims(database_uuid=database_uuid, context=context, clock=clock)
    claims.pool = pool
    authorization = ProductionSigningAuthorizationVerifier(
        source=source,
        preconditions=preconditions,
        owner_key=owner_key,
        expected_owner_key_sha256=canonical_digest(owner_key),
        expected_owner_identity=manual.owner_identity,
        expected_claim_database_uuid=database_uuid,
        maximum_arm_lifetime=timedelta(minutes=5),
        clock_probe=clock,
    )
    signer = ManagedSignerBoundary(
        binding,
        backend=backend,
        verifier=typed_verifier,
        claims=claims,
        authorization=authorization,
    )
    return source, claims, authorization, signer, database_uuid, backend


def _runtime(*, clock, context, binding, source, claims, authorization, signer, database_uuid, venue):
    async def synthetic_sender(*, method: str, path: str, body: dict[str, Any]):
        assert method == "POST"
        if path == "/api/v2/order/limit":
            return venue.partial_entry(body)
        if path == f"/api/tpsl/{body['instrument']}":
            return venue.protect(body)
        raise AssertionError(f"unexpected synthetic transport path: {path}")

    dispatcher = ProductionEffectDispatcher(
        authorization=authorization,
        signature_verifier=SyntheticSignatureVerifier(),
        claims=claims,
        database_uuid=database_uuid,
        context=context,
        clock=clock,
        sender=synthetic_sender,
    )
    return ProductionExecutionRuntime(
        signer=signer,
        authorization=authorization,
        claims=claims,
        state_source=source,
        dispatcher=dispatcher,
        database_uuid=database_uuid,
        context=context,
        clock=clock,
    )


@pytest.mark.asyncio
async def test_native_pg_prod_fsm_partial_fill_protect_restart_deduplicate_and_target_close(
    production_pg_runtime,
):
    database, clock = production_pg_runtime
    decision = _decision()
    context = ProductionContextV1(
        remote_account_id=decision.account_id,
        adaptive_system_id=decision.intent.strategy_id,
        frozen_policy_sha256="1" * 64,
        source_set_sha256="2" * 64,
    )
    custody = CustodyBindingV1(
        context=context,
        custody_reference="synthetic:custody",
        wallet_address="0x" + "12" * 20,
        chain_id=161803,
        schema_sha256=reviewed_schema_sha256(161803),
        approved_instruments=("BTCUSD", "ETHUSD", "SOLUSD", "BNBUSD", "XRPUSD"),
        custody_receipt_sha256="3" * 64,
    )
    expected_health = ProductionVenueHealthV1(
        chain_id=custody.chain_id,
        exchange_url=profile_params(EvedexProfile.PROD).exchange_url,
        auth_url=profile_params(EvedexProfile.PROD).auth_url,
        sdk_version="1.2.11",
    )
    config = ProductionLifecycleConfigV1(
        context=context,
        custody_binding=custody,
        strategy_revision=decision.intent.strategy_revision,
        expected_health=expected_health,
        service_name="synthetic-production-lifecycle-test",
        symbol_map={
            "BTCUSDT": "BTCUSD",
            "ETHUSDT": "ETHUSD",
            "SOLUSDT": "SOLUSD",
            "BNBUSDT": "BNBUSD",
            "XRPUSDT": "XRPUSD",
        },
    )
    venue = _SyntheticVenue(clock, context.remote_account_id)
    source, claims, authorization, signer, database_uuid, backend = _synthetic_authority(
        clock=clock, context=context, binding=custody, pool=database.pool
    )
    runtime = _runtime(
        clock=clock,
        context=context,
        binding=custody,
        source=source,
        claims=claims,
        authorization=authorization,
        signer=signer,
        database_uuid=database_uuid,
        venue=venue,
    )
    trades = TradeLifecycleRepository(database.pool)
    effects = ExecutionJournalRepository(database.pool)
    bindings = _BindingStore(context, database.pool)
    cancellation_source = _SyntheticCancellationVenueSource(context=context, venue=venue, clock=clock)
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
        preconditions=source.preconditions,
        owner_key=source.owner_key,
        expected_owner_key_sha256=canonical_digest(source.owner_key),
        expected_owner_identity=source.owner_key.owner_identity,
        maximum_arm_lifetime=timedelta(minutes=5),
        clock=clock,
    )
    adapter = ManagedProductionLifecycleAdapter(
        runtime=runtime,
        reads=_ProductionReads(venue, clock, context),
        bindings=bindings,
        trades=trades,
        effects=effects,
        cancellations=cancellations,
        clock=clock,
    )
    engine = ProductionLifecycleEngine(
        adapter,
        trades,
        effects,
        config,
        runtime,
        clock=clock,
        sleeper=_no_sleep,
    )
    assert await engine.initialize_recovery() == ()

    now = clock()
    expiry = now + timedelta(seconds=4)
    manual_sha = source.manual_request_sha256
    client_ids = {
        role: engine._client_id(decision.trade_id, role, decision.decided_at_ms)
        for role in (OrderRole.ENTRY, OrderRole.STOP_LOSS, OrderRole.TAKE_PROFIT)
    }
    source.plans.clear()
    source.decision = decision
    for role, operation, parent in (
        (OrderRole.ENTRY, "place", None),
        (OrderRole.STOP_LOSS, "create", client_ids[OrderRole.ENTRY]),
        (OrderRole.TAKE_PROFIT, "create", client_ids[OrderRole.ENTRY]),
    ):
        effect_id = engine._effect_id(decision.trade_id, role, operation)
        plan = build_production_lifecycle_binding(
            decision=decision,
            context=context,
            custody_binding=custody,
            role=role.value,
            lifecycle_effect_id=effect_id,
            client_order_id=client_ids[role],
            parent_order_id=parent,
            manual_request_sha256=manual_sha,
            expires_at=expiry,
            now=now,
        )
        bindings.plans[effect_id] = plan
        source.plans[plan.request.request_id] = plan

    opened = await engine.handle(decision)
    assert any(event.event_type is TradeExecutionEventType.ENTRY_PARTIAL_FILL for event in opened.events)
    assert venue.calls == ["ENTRY", "STOP_LOSS", "TAKE_PROFIT"]
    assert len(backend.calls) == 3  # one managed signature for entry and each protection
    trade = await trades.get(decision.trade_id)
    assert trade is not None and trade.state is TradeState.ACTIVE
    assert len(venue.state["tpsl"]) == 2 and all(item["quantity"] == 0 for item in venue.state["tpsl"])
    assert claims.wire_calls == 3

    # Once the original entry deadline passes, only the unfilled remainder is
    # canceled; the partial position remains under both protections.
    clock.value = datetime.fromtimestamp((decision.intent.entry_expires_ts_ms + 1) / 1000, tz=UTC)
    await engine.reconcile_once()
    assert venue.calls.count("CANCEL_ENTRY") == 1
    assert venue.state["positions"][0]["quantity"] == pytest.approx(decision.quantity / 2)

    restarted = ProductionLifecycleEngine(
        adapter,
        trades,
        effects,
        config,
        runtime,
        clock=clock,
        sleeper=_no_sleep,
    )
    assert await restarted.initialize_recovery() == ()
    replay = await restarted.handle(decision)
    assert replay.events == ()
    assert venue.calls.count("ENTRY") == 1
    assert venue.calls.count("STOP_LOSS") == 1
    assert venue.calls.count("TAKE_PROFIT") == 1
    assert venue.calls.count("CANCEL_ENTRY") == 1

    trade = await trades.get(decision.trade_id)
    assert trade is not None and trade.timeout_at is not None
    venue.state["positions"] = []
    venue.state["balance"]["positions"] = []
    for item in venue.state["tpsl"]:
        item["status"] = "done" if item["type"] == "take-profit" else "cancelled"
        if item["status"] == "done":
            item.update(
                triggerOrder="synthetic-target-exit",
                triggeredQuantity=str(decision.quantity / 2),
                cancelledReason="",
            )
        else:
            item.update(triggerOrder=None, triggeredQuantity="0", cancelledReason="oco-sibling")
    venue.state["order_history"].append(
        {
            "id": "synthetic-target-exit",
            "instrument": "BTCUSD",
            "side": "SELL",
            "type": "MARKET",
            "group": "tpsl",
            "quantity": decision.quantity / 2,
            "unFilledQuantity": 0,
            "filledAvgPrice": 105,
            "status": "FILLED",
            "fee": [],
        }
    )
    clock.value = trade.timeout_at + timedelta(milliseconds=1)
    exits = await restarted.reconcile_once()
    assert exits and all(event.exit_reason is TradeExitReason.TARGET for event in exits)
    assert "CLOSE" not in venue.calls
    terminal = await trades.get(decision.trade_id)
    assert terminal is not None and terminal.state is TradeState.FLAT
    snapshot = await restarted.account_snapshot()
    assert snapshot.positions == ()
    assert await restarted.reconcile_once() == []


async def _no_sleep(_: float) -> None:
    return None
