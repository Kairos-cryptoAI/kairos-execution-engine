"""Synthetic receipt and fresh contracts for real-DB execution composition tests.

Never import this module from runtime code. Only the guarded disposable test DB
fixture may call seed_receipt; its historical observations are fabricated test
inputs, NOT proof that any DEV venue has passed a read-only qualification.
"""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from kairos_core import MarketRegime, StrategicAllocation, StrategicTrigger
from kairos_core.contracts import (
    CandidateReviewV1,
    CandidateRouteV1,
    EvidenceReferenceV1,
    ExitPlanV1,
    RiskTradeDecisionV1,
    StrategyIntentV1,
    StrategyProvenanceV1,
    VenueQualityV1,
)
from kairos_persistence.canary_arm import CANARY_RATIONALE
from kairos_persistence.canary_session import (
    SYMBOLS,
    ZERO_SHA,
    BoundedCanaryPlan,
    CanaryScope,
    CanarySessionRepository,
    CanarySlot,
    ReadonlyObservation,
    SymbolObservation,
    digest,
    millis,
    sample_identity,
)
from kairos_persistence.runtime import canonical_payload

from tests.paper_fixtures import _instrument_rule, approved_decision


def session_plan():
    return BoundedCanaryPlan(
        slots=tuple(
            CanarySlot(slot_id=f"slot-{index}", symbol=symbol, side="LONG", scenario=scenario)
            for index, (symbol, scenario) in enumerate(
                zip(SYMBOLS, ("STOP", "TARGET", "TIMEOUT", "RESTART", "ENTRY_CANCEL"), strict=True)
            )
        )
    )


async def seed_receipt(database):
    # Caller must already have validated its disposable DB before any writes.
    suffix = uuid4().hex
    scope = CanaryScope(
        environment="paper-dev",
        account_id=f"kairos-paper-dev-{suffix}",
        remote_account_id=f"synthetic-{suffix}",
        config_sha256="a" * 64,
        recorder_code_sha256="b" * 64,
    )
    now = await database.pool.fetchval("SELECT clock_timestamp()")
    started = now - timedelta(days=1)
    run_id, head = digest({"synthetic-execution-test": suffix}), ZERO_SHA
    rows = []
    for index in range(1441):
        received = started + timedelta(minutes=index)
        observation = ReadonlyObservation(
            observed_at_ms=millis(received),
            unresolved_bar_gaps=0,
            reconciliation_drift=False,
            entry_mutations=0,
            symbols=tuple(
                SymbolObservation(
                    symbol=symbol,
                    available=True,
                    basis_bps=1,
                    spread_bps=2,
                    slippage_bps=3,
                    book_age_ms=100,
                    timestamp_skew_ms=100,
                    book_nonempty=True,
                )
                for symbol in SYMBOLS
            ),
        ).model_dump(mode="json")
        next_head = sample_identity(run_id, index + 1, received, head, observation)
        rows.append((run_id, index + 1, received, canonical_payload(observation)[0], head, next_head))
        head = next_head
    instance = await database.pool.fetchval("SELECT instance_id FROM paper_canary_database_identity")
    async with database.pool.acquire() as connection, connection.transaction():
        await connection.execute(
            """INSERT INTO paper_readonly_runs
               (run_id,scope,scope_sha256,database_instance_id,started_at,sample_period_ms,sample_count,head_sha256)
               VALUES($1,$2::jsonb,$3,$4,$5,60000,1441,$6)""",
            run_id,
            canonical_payload(scope.model_dump(mode="json"))[0],
            digest(scope.model_dump(mode="json")),
            instance,
            started,
            head,
        )
        await connection.executemany(
            """INSERT INTO paper_readonly_samples
               (run_id,seq,received_at,payload,previous_sha256,sample_sha256)
               VALUES($1,$2,$3,$4::jsonb,$5,$6)""",
            rows,
        )
    repo = CanarySessionRepository(database.pool)
    receipt_id = await repo.certify_readonly(run_id, expected_scope=scope)
    plan = session_plan()
    session = await repo.arm_session(
        receipt_id=receipt_id, scope=scope, plan=plan, operator_nonce=f"synthetic-{suffix}"
    )
    return repo, scope, plan, session


def fresh_review(scope, slot, now_ms):
    base = approved_decision()
    eligible = now_ms // 60_000 * 60_000
    exclude_envelope = {"message_id", "correlation_id", "causation_id", "produced_at"}
    rule, _ = _instrument_rule()
    rule["venue_updated_at_ms"] = now_ms
    rule_hash = digest(rule)
    metadata = dict(base.intent.metadata) | {
        "account_id": scope.account_id,
        "instrument_rules_sha256": rule_hash,
        "venue_updated_at_ms": str(now_ms),
    }
    evidence = (
        EvidenceReferenceV1(
            kind="closed_bar",
            reference=f"BINANCE_UM:BTCUSDT:{eligible - 60000}",
            content_sha256="a" * 64,
            observed_at_ms=eligible - 1,
        ),
        EvidenceReferenceV1(
            kind="venue_instrument",
            reference=f"EVEDEX_DEV:BTCUSD:DEV:{now_ms}",
            content_sha256=rule_hash,
            observed_at_ms=now_ms,
        ),
    )
    exit_plan = ExitPlanV1(
        stop_price=100 - slot.stop_distance_bps / 100,
        target_price=100 + slot.target_distance_bps / 100,
        max_holding_ms=slot.max_holding_ms,
    )
    provenance = StrategyProvenanceV1.model_validate(
        base.intent.provenance.model_dump() | {"config_sha256": digest(slot.intent_config())}
    )
    intent = StrategyIntentV1.model_validate(
        base.intent.model_dump(exclude=exclude_envelope | {"intent_id"})
        | {
            "decision_ts_ms": eligible - 1,
            "entry_eligible_ts_ms": eligible,
            "entry_expires_ts_ms": eligible + slot.entry_window_ms,
            "gross_reward_bps": slot.target_distance_bps,
            "exit_plan": exit_plan,
            "provenance": provenance,
            "metadata": tuple(metadata.items()),
            "evidence": evidence,
        }
    )
    route = CandidateRouteV1.model_validate(
        base.review.route.model_dump(exclude=exclude_envelope | {"route_id", "intent_sha256"})
        | {
            "intent": intent,
            "routed_at_ms": eligible - 1,
            "review_deadline_ms": intent.entry_expires_ts_ms,
            "evidence_ids": ("a" * 64, rule_hash),
            "correlation_id": intent.intent_id,
            "causation_id": intent.message_id,
        }
    )
    review = CandidateReviewV1.model_validate(
        base.review.model_dump(exclude=exclude_envelope | {"review_id", "intent_sha256"})
        | {
            "intent": intent,
            "route": route,
            "reviewed_at_ms": eligible,
            "evidence": evidence,
            "correlation_id": intent.intent_id,
            "causation_id": route.message_id,
        }
    )
    identity = dict(
        causation_id=intent.message_id,
        contract_version="technical-canary-allocation.v1",
        correlation_id=intent.intent_id,
        max_gross_leverage=1.0,
        produced_at_ms=eligible,
        regime=MarketRegime.BULL.value,
        rationale=CANARY_RATIONALE,
        schema_version="1.0",
        source="kairos-paper-canary",
        stable_reserve_pct=0.9975,
        strategy_weights={"technical-canary": 0.0025},
        triggered_by="schedule",
    )
    allocation = StrategicAllocation(
        source="kairos-paper-canary",
        message_id=digest(identity),
        correlation_id=intent.intent_id,
        causation_id=intent.message_id,
        produced_at=datetime.fromtimestamp(eligible / 1000, UTC),
        regime=MarketRegime.BULL,
        strategy_weights={"technical-canary": 0.0025},
        stable_reserve_pct=0.9975,
        max_gross_leverage=1,
        rationale=CANARY_RATIONALE,
        triggered_by=StrategicTrigger.SCHEDULE,
    )
    return review, allocation


def fresh_decision(review, scope, consumed_at_ms):
    now = consumed_at_ms
    venue = VenueQualityV1(
        source="synthetic-integration",
        profile="DEV",
        symbol="BTCUSD:DEV",
        observed_at_ms=now,
        expires_at_ms=now + 5000,
        reference_timestamp_ms=now,
        book_timestamp_ms=now,
        reference_mid_price=100,
        best_bid=99.99,
        best_ask=100.01,
        venue_mid_price=100,
        basis_bps=0,
        spread_bps=2,
        assessed_notional_usd=10.001,
        depth_usd=5000,
        buy_slippage_bps=1,
        sell_slippage_bps=1,
        taker_fee_bps=5,
        reference_age_ms=0,
        book_age_ms=0,
        latency_ms=1,
        timestamp_skew_ms=0,
        entry_allowed=True,
    )
    quantity = 0.1
    fees = quantity * (100.01 + review.intent.exit_plan.stop_price) * 5 / 10000
    slippage = quantity * 100 / 10000
    return RiskTradeDecisionV1(
        source="kairos-risk-manager",
        intent=review.intent,
        review=review,
        venue_quality=venue,
        approved=True,
        decided_at_ms=now,
        entry_policy="NEXT_BAR_MARKET",
        trading_mode="PAPER",
        evedex_profile="DEV",
        account_id=scope.account_id,
        venue_symbol="BTCUSD:DEV",
        quantity=quantity,
        leverage=1,
        notional_usd=10.001,
        loss_budget_usd=1,
        worst_case_loss_usd=quantity * abs(100.01 - review.intent.exit_plan.stop_price) + fees + slippage,
        worst_entry_price=100.01,
        estimated_fees_usd=fees,
        estimated_slippage_usd=slippage,
        exit_plan=review.intent.exit_plan,
    )
