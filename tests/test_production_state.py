"""Unit checks for fail-closed, async production-state boundaries.

These tests use synthetic records only; native database acceptance lives in the
opt-in isolated PostgreSQL integration test.
"""

import json
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from kairos_execution.production_readiness import ProductionContextV1
from kairos_execution.production_state import (
    SCHEMA_VERSION,
    AsyncPostgresProductionSigningStateSource,
    PostgresRiskStateWriter,
    ProductionStateError,
    _account_scope_sha256,
    _entry_notional_usd,
    _parse_json_model,
    _payload,
    _python_diagnostic,
    _sql_diagnostic,
    _validate_snapshot_clock,
    _writer_select_tables,
    provision_production_state_schema,
)
from tests.test_signing_authorization import fixture


class _RiskAppendConnection:
    """Small callback double for the risk writer's append transaction."""

    def __init__(self, existing=None) -> None:
        self.existing = existing
        self.fetchval_calls = []
        self.fetchrow_calls = []
        self.execute_calls = []

    async def fetchval(self, query, *args):
        self.fetchval_calls.append((query, args))
        return None

    async def fetchrow(self, query, *args):
        self.fetchrow_calls.append((query, args))
        return self.existing

    async def execute(self, query, *args):
        self.execute_calls.append((query, args))
        return "INSERT 0 1"


def _risk_writer_and_record(context=None, *, state_schema_version=3):
    _, _, binding, evidence, _ = fixture()
    context = binding.context if context is None else context
    writer = PostgresRiskStateWriter(
        object(),  # type: ignore[arg-type]
        expected_database="kairos_production_evidence_123456789abc",
        database_uuid=UUID("31da18d5-2b77-407d-b0dc-5366f03ae10a"),
        policy_namespace="fixture:production-state",
        context=context,
        expected_role="risk_writer",
        state_schema_version=state_schema_version,
    )
    return writer, evidence.risk


def _risk_payload_record(risk):
    data, payload_sha = _payload(risk)
    return {"payload": data, "payload_sha256": payload_sha}


async def _use_risk_append_connection(monkeypatch, writer, connection):
    async def write(callback):
        return await callback(connection)

    monkeypatch.setattr(writer, "_write", write)


class _WrongIdentityConnection:
    def __init__(self) -> None:
        self.ddl_seen = False

    async def fetchrow(self, query: str, *args):
        if "current_database()" in query:
            return {"db": "postgres", "role": "not_owner"}
        raise AssertionError("unexpected query before database/owner identity check")

    async def execute(self, query: str, *args):
        self.ddl_seen = True
        raise AssertionError("provisioning DDL must not run on a wrong database")

    def transaction(self):
        raise AssertionError("provisioning transaction must not start before owner validation")


@pytest.mark.asyncio
async def test_provisioning_refuses_wrong_database_identity_before_ddl():
    _, _, binding, _, _ = fixture()
    source_context = binding.context
    connection = _WrongIdentityConnection()
    with pytest.raises(ProductionStateError, match="owner/database mismatch"):
        await provision_production_state_schema(
            connection,  # type: ignore[arg-type]
            expected_database="kairos_production_evidence_123456789abc",
            database_uuid=UUID("31da18d5-2b77-407d-b0dc-5366f03ae10a"),
            policy_namespace="fixture:production-state",
            context=source_context,
            owner_role="state_owner",
            runtime_role="state_reader",
            operator_writer_role="operator_writer",
            risk_writer_role="risk_writer",
            exposure_writer_role="exposure_writer",
        )
    assert connection.ddl_seen is False


def test_production_context_payload_digest_is_deterministic():
    context = ProductionContextV1(
        remote_account_id="synthetic-account",
        adaptive_system_id="synthetic-adaptive",
        frozen_policy_sha256="b" * 64,
        source_set_sha256="c" * 64,
    )
    first = _payload(context)
    second = _payload(context.model_copy())
    assert first == second
    assert len(first[1]) == 64


def test_reservation_scope_spans_policy_contexts_but_separates_accounts():
    context = ProductionContextV1(
        remote_account_id="synthetic-account",
        adaptive_system_id="synthetic-adaptive-a",
        frozen_policy_sha256="b" * 64,
        source_set_sha256="c" * 64,
    )
    same_account_other_policy = context.model_copy(
        update={"adaptive_system_id": "synthetic-adaptive-b", "frozen_policy_sha256": "d" * 64}
    )
    other_account = context.model_copy(update={"remote_account_id": "synthetic-account-2"})
    assert _account_scope_sha256(context) == _account_scope_sha256(same_account_other_policy)
    assert _account_scope_sha256(context) != _account_scope_sha256(other_account)
    assert SCHEMA_VERSION == 2


def test_risk_writer_select_permissions_are_v2_insert_only_and_v3_replay_scoped():
    assert _writer_select_tables("risk_writer_role", 2) == frozenset({"identity"})
    assert _writer_select_tables("risk_writer_role", 3) == frozenset({"identity", "risk_decisions"})
    assert _writer_select_tables("operator_writer_role", 3) == frozenset(
        {"identity", "owner_arms", "operator_observations"}
    )


def test_reservation_notional_is_exact_decimal_and_rejects_boolean_or_float_amounts():
    assert _entry_notional_usd({"quantity": 10**8, "limitPrice": 2 * 10**8}) == 2
    assert _entry_notional_usd({"cashQuantity": 275_000_000}) == 2.75
    for malformed in (
        {"quantity": True, "limitPrice": 10**8},
        {"quantity": 10**8, "price": 1.5},
        {"cashQuantity": True},
    ):
        with pytest.raises(ProductionStateError):
            _entry_notional_usd(malformed)


def test_source_rejects_longer_than_five_second_freshness_contract():
    _, _, binding, _, _ = fixture()
    with pytest.raises(ValueError, match="may not exceed five seconds"):
        AsyncPostgresProductionSigningStateSource(
            object(),  # type: ignore[arg-type]
            expected_database="kairos_production_evidence_123456789abc",
            database_uuid=UUID("31da18d5-2b77-407d-b0dc-5366f03ae10a"),
            policy_namespace="fixture:production-state",
            runtime_role="state_reader",
            context=binding.context,
            max_snapshot_age=timedelta(seconds=6),
        )


def test_database_snapshot_clock_is_compared_to_post_io_time():
    started = datetime(2026, 10, 21, 12, 0, 0, tzinfo=UTC)
    # A real database resolution must naturally be later than the request's
    # call-start timestamp. The source permits that when post-I/O time advances.
    _validate_snapshot_clock(
        started_at=started,
        resolved_at=started + timedelta(milliseconds=40),
        checked_at=started + timedelta(milliseconds=60),
        max_age=timedelta(seconds=5),
    )

    with pytest.raises(ProductionStateError, match="clock moved backwards"):
        _validate_snapshot_clock(
            started_at=started,
            resolved_at=started,
            checked_at=started - timedelta(milliseconds=1),
            max_age=timedelta(seconds=5),
        )


def test_database_write_diagnostic_uses_only_whitelisted_sqlstate_tokens():
    assert _sql_diagnostic("P0001", "operator ARM lacks its exact signed owner request") == (
        "P0001/operator_owner_arm_link"
    )
    assert _sql_diagnostic("23505", "duplicate key value includes secret-like text") == (
        "23505/unique_constraint"
    )
    assert _sql_diagnostic("not-a-state", "private database detail") == "database_error"


def test_non_database_diagnostic_never_returns_exception_text():
    try:
        raise ValueError("synthetic private detail")
    except ValueError as exc:
        assert _python_diagnostic(exc) == "python_value_error"


def test_database_json_payload_uses_strict_json_mode_for_timestamps():
    _, _, _, evidence, _ = fixture(operation="Position close order")
    records = (
        ("owner arm", evidence.owner_arm),
        ("risk decision", evidence.risk),
        ("exposure snapshot", evidence.exposure),
        ("operator observation", evidence.operator),
    )
    for label, record in records:
        encoded = json.dumps(record.model_dump(mode="json"), separators=(",", ":"))
        restored = _parse_json_model(encoded, type(record), label)
        assert restored == record


@pytest.mark.asyncio
async def test_risk_append_inserts_first_decision_once(monkeypatch):
    writer, risk = _risk_writer_and_record()
    connection = _RiskAppendConnection()
    await _use_risk_append_connection(monkeypatch, writer, connection)

    await writer.append_risk_decision_async(risk)

    assert len(connection.fetchval_calls) == 1  # account-scoped transaction lock
    assert len(connection.fetchrow_calls) == 1
    assert "WHERE context_sha256=$1 AND signing_request_id=$2" in connection.fetchrow_calls[0][0]
    assert connection.fetchrow_calls[0][1] == (writer.context_sha256, risk.signing_request_id)
    assert len(connection.execute_calls) == 1
    query, args = connection.execute_calls[0]
    assert "INSERT INTO kairos_production_state_v1.risk_decisions" in query
    assert args[:5] == (
        writer.context_sha256,
        risk.signing_request_id,
        risk.decision_id,
        risk.observed_at,
        risk.valid_until,
    )


@pytest.mark.asyncio
async def test_v2_risk_append_remains_insert_only_without_select(monkeypatch):
    writer, risk = _risk_writer_and_record(state_schema_version=2)
    connection = _RiskAppendConnection()
    await _use_risk_append_connection(monkeypatch, writer, connection)

    await writer.append_risk_decision_async(risk)

    assert connection.fetchrow_calls == []
    assert len(connection.execute_calls) == 1


@pytest.mark.asyncio
async def test_risk_append_exact_replay_does_not_reinsert_or_refresh_lease(monkeypatch):
    writer, risk = _risk_writer_and_record()
    stored = _risk_payload_record(risk)
    original_row = dict(stored)
    connection = _RiskAppendConnection(existing=stored)
    await _use_risk_append_connection(monkeypatch, writer, connection)

    await writer.append_risk_decision_async(risk)

    assert connection.execute_calls == []
    assert stored == original_row  # replay must leave the persisted validity lease untouched


@pytest.mark.parametrize("corruption", ["hash", "payload"])
@pytest.mark.asyncio
async def test_risk_append_refuses_existing_payload_or_hash_mismatch(monkeypatch, corruption):
    writer, risk = _risk_writer_and_record()
    stored = _risk_payload_record(risk)
    if corruption == "hash":
        stored["payload_sha256"] = "0" * 64
    else:
        stored["payload"]["worst_case_loss_usd"] = "999"
    connection = _RiskAppendConnection(existing=stored)
    await _use_risk_append_connection(monkeypatch, writer, connection)

    with pytest.raises(ProductionStateError, match="risk signing-request identity was rebound"):
        await writer.append_risk_decision_async(risk)

    assert connection.execute_calls == []


@pytest.mark.parametrize(
    "change",
    [
        {"decision_id": "altered-decision"},
        {"quantity": 123456789},
    ],
    ids=["decision", "geometry"],
)
@pytest.mark.asyncio
async def test_risk_append_refuses_rebound_signing_request_even_with_valid_payload(monkeypatch, change):
    writer, risk = _risk_writer_and_record()
    changed_risk = risk.model_copy(update=change)
    connection = _RiskAppendConnection(existing=_risk_payload_record(risk))
    await _use_risk_append_connection(monkeypatch, writer, connection)

    with pytest.raises(ProductionStateError, match="risk signing-request identity was rebound"):
        await writer.append_risk_decision_async(changed_risk)

    assert connection.execute_calls == []


@pytest.mark.asyncio
async def test_risk_append_rejects_different_context_before_database_callback(monkeypatch):
    writer, risk = _risk_writer_and_record()
    connection = _RiskAppendConnection()
    await _use_risk_append_connection(monkeypatch, writer, connection)
    other_context = risk.context.model_copy(update={"adaptive_system_id": "other-synthetic-system"})
    other_risk = risk.model_copy(update={"context": other_context})

    with pytest.raises(ProductionStateError, match="risk context differs from source scope"):
        await writer.append_risk_decision_async(other_risk)

    assert connection.fetchval_calls == []
    assert connection.fetchrow_calls == []
    assert connection.execute_calls == []
