"""Unit tests use an in-memory audit-connection fixture, never a real DB."""

import hashlib
import json
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

import pytest

from kairos_execution.managed_signer import ManagedSigningRequestV1
from kairos_execution.production_lifecycle_binding import ProductionLifecycleBindingV1
from kairos_execution.production_lifecycle_store import (
    SOURCE,
    TOPIC,
    PostgresLifecycleBindingStore,
    ProductionLifecycleStoreError,
)
from kairos_execution.production_readiness import ProductionContextV1, canonical_digest
from kairos_execution.signing_authorization import signing_effect_id

NOW = datetime(2026, 10, 23, 10, 0, tzinfo=UTC)
TEST_DATABASE = "kairos_production_evidence_fixture_123456"


def _json_sha(value):
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _context():
    return ProductionContextV1(
        remote_account_id="synthetic-account",
        adaptive_system_id="synthetic-system",
        frozen_policy_sha256="b" * 64,
        source_set_sha256="c" * 64,
    )


def _binding(context=None, *, lifecycle_effect_id="d" * 64):
    context = context or _context()
    decision_id = "e" * 64
    trade_id = "f" * 64
    decision_sha = "a" * 64
    message = {
        "id": "client-order-synthetic-01",
        "instrument": "BTCUSDT",
        "side": "BUY",
        "leverage": 1,
        "quantity": 200_000_000,
        "limitPrice": 50_000_000_000,
        "chainId": 8453,
    }
    message_json = json.dumps(message, sort_keys=True, separators=(",", ":"))
    request_id = "lifecycle-" + _json_sha(
        {
            "domain": "kairos.production-lifecycle-request.v1",
            "context_sha256": canonical_digest(context),
            "trade_id": trade_id,
            "decision_id": decision_id,
            "decision_sha256": decision_sha,
            "lifecycle_effect_id": lifecycle_effect_id,
            "role": "ENTRY",
        }
    )
    request = ManagedSigningRequestV1(
        request_id=request_id,
        context=context,
        manual_request_sha256="1" * 64,
        custody_receipt_sha256="2" * 64,
        operation="New limit order",
        message_json=message_json,
        expires_at=NOW + timedelta(seconds=20),
    )
    signing_id = signing_effect_id(request=request, message=message, decision_id=decision_id)
    return ProductionLifecycleBindingV1(
        context=context,
        decision_id=decision_id,
        trade_id=trade_id,
        decision_sha256=decision_sha,
        role="ENTRY",
        risk_decision_id=decision_id,
        lifecycle_effect_id=lifecycle_effect_id,
        signing_effect_id=signing_id,
        request=request,
    )


class _Transaction:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _FakeConnection:
    def __init__(self, *, database=TEST_DATABASE, role="synthetic_writer"):
        self.database = database
        self.role = role
        self.rows = []
        self.locks = []

    def transaction(self, *, readonly=False):
        return _Transaction()

    async def fetchrow(self, query, *args):
        if "current_database()" in query:
            return {"db": self.database, "role": self.role}
        raise AssertionError(f"unexpected fetchrow: {query}")

    async def fetchval(self, query, *args):
        raise AssertionError(f"unexpected fetchval: {query}")

    async def execute(self, query, *args):
        compact = " ".join(query.split())
        if "pg_advisory_xact_lock" in compact:
            self.locks.append(args[0])
            return "SELECT 1"
        if compact.startswith("INSERT INTO event_audit"):
            produced_at, message_id, topic, source, version, correlation, causation, payload = args
            decoded = json.loads(payload)
            for row in self.rows:
                if row["produced_at"] == produced_at and row["message_id"] == message_id:
                    return "INSERT 0 0"
            self.rows.append(
                {
                    "produced_at": produced_at,
                    "message_id": message_id,
                    "topic": topic,
                    "source": source,
                    "schema_version": version,
                    "correlation_id": correlation,
                    "causation_id": causation,
                    "payload": decoded,
                }
            )
            return "INSERT 0 1"
        raise AssertionError(f"unexpected execute: {query}")

    async def fetch(self, query, *args):
        compact = " ".join(query.split())
        if "FROM event_audit" not in compact:
            raise AssertionError(f"unexpected fetch: {query}")
        message_id = args[0]
        return [
            {"topic": row["topic"], "payload": row["payload"]}
            for row in self.rows
            if row["message_id"] == message_id
        ]


class _FakePool:
    def __init__(self, connection):
        self.connection = connection

    @asynccontextmanager
    async def acquire(self):
        yield self.connection


def _store(connection=None, *, context=None):
    connection = connection or _FakeConnection()
    return (
        PostgresLifecycleBindingStore(
            _FakePool(connection),
            context=context or _context(),
            expected_database=TEST_DATABASE,
            expected_role="synthetic_writer",
        ),
        connection,
    )


@pytest.mark.asyncio
async def test_put_get_are_exact_idempotent_and_use_stable_deadline():
    store, connection = _store()
    binding = _binding()
    assert await store.put(binding) is True
    assert await store.put(binding) is False
    restored = await store.get(binding.lifecycle_effect_id)
    assert restored == binding
    assert len(connection.rows) == 1
    row = connection.rows[0]
    assert row["topic"] == TOPIC
    assert row["source"] == SOURCE
    assert row["payload"]["produced_at"] == binding.request.expires_at.isoformat()
    assert row["payload"]["message_id"] == store._message_id(binding.lifecycle_effect_id)
    assert len(connection.locks) == 4


@pytest.mark.asyncio
async def test_put_is_context_scoped_and_get_is_not_authority():
    store, _ = _store()
    with pytest.raises(ProductionLifecycleStoreError, match="context differs"):
        await store.put(
            _binding(context=_context().model_copy(update={"remote_account_id": "other-account"}))
        )
    assert await store.get("9" * 64) is None


@pytest.mark.asyncio
async def test_get_rejects_duplicate_historical_audit_ids_and_topic_collision():
    store, connection = _store()
    binding = _binding()
    await store.put(binding)
    connection.rows.append(dict(connection.rows[0], produced_at=NOW + timedelta(seconds=1)))
    with pytest.raises(ProductionLifecycleStoreError, match="duplicate audit rows"):
        await store.get(binding.lifecycle_effect_id)

    connection.rows.pop()
    connection.rows[0]["topic"] = "another.topic"
    with pytest.raises(ProductionLifecycleStoreError, match="another audit topic"):
        await store.get(binding.lifecycle_effect_id)


@pytest.mark.asyncio
async def test_get_revalidates_binding_digests_and_exact_request_geometry():
    store, connection = _store()
    binding = _binding()
    await store.put(binding)
    stored = connection.rows[0]["payload"]["binding"]
    stored["signing_effect_id"] = "0" * 64
    with pytest.raises(ProductionLifecycleStoreError, match="signing effect ID"):
        await store.get(binding.lifecycle_effect_id)


@pytest.mark.asyncio
async def test_put_requires_exact_database_and_role_identity():
    connection = _FakeConnection(database="wrong_db")
    store, _ = _store(connection)
    with pytest.raises(ProductionLifecycleStoreError, match="identity mismatch"):
        await store.put(_binding())
    assert not connection.rows
