"""Offline SQL adapter/order tests; native PostgreSQL is qualified separately."""

import asyncio
from contextlib import asynccontextmanager
from uuid import UUID

import pytest

from kairos_execution.production_claims import PostgresProductionClaims, ProductionClaimError
from tests.production_evidence_fixtures import signed_gate_fixture

DATABASE = "kairos_production_evidence_offline_fixture_1234"
DATABASE_UUID = UUID("019ff67f-4e1c-7512-8d55-329813370a53")


class FakeConnection:
    def __init__(self):
        self.claims, self.terminals = {}, {}
        self.events = []
        self.lock = asyncio.Lock()
        self.commit_lost = False
        self.db = DATABASE
        self.role = "evidence_runtime"
        self.uuid = DATABASE_UUID
        self.owner = "evidence_owner"
        self.schema_owner = self.owner
        self.table_owner = self.owner
        self.unsafe = False
        self.owner_member = False
        self.mutate_privilege = False
        self.schema_create = False
        self.identity_insert = False

    @asynccontextmanager
    async def transaction(self):
        async with self.lock:
            self.events.append("BEGIN")
            try:
                yield
            except BaseException:
                self.events.append("ROLLBACK")
                raise
            self.events.append("COMMIT")
            if self.commit_lost:
                self.commit_lost = False
                raise RuntimeError("DO_NOT_PRINT_NATIVE_DSN")

    async def fetchrow(self, sql, *args):
        if "current_database()" in sql:
            return {"db": self.db, "role": self.role}
        if ".identity WHERE" in sql:
            return {
                "database_uuid": self.uuid,
                "schema_version": 1,
                "policy_namespace": "policy-v1",
                "owner_role": self.owner,
                "runtime_role": self.role,
            }
        if "FROM pg_roles" in sql:
            return {"rolsuper": self.unsafe, "rolcreatedb": False}
        if "INSERT INTO" in sql and ".claims VALUES" in sql:
            kind, namespace, identity, digest, context = args
            key = kind, namespace, identity
            if key in self.claims:
                return None
            self.claims[key] = dict(
                claim_kind=kind,
                namespace=namespace,
                identity=identity,
                request_sha256=digest,
                context_sha256=context,
            )
            self.events.append("INSERT_CLAIM")
            return {"request_sha256": digest}
        if "LEFT JOIN" in sql:
            row = self.claims.get(tuple(args))
            if row is None:
                return None
            return {
                **row,
                **self.terminals.get(tuple(args), {"terminal_status": None, "result_sha256": None}),
            }
        if ".claims " in sql:
            key = tuple(args) if len(args) == 3 else ("TYPED_SIGNING", *args)
            return self.claims.get(key)
        if ".terminals WHERE" in sql:
            return self.terminals.get(("TYPED_SIGNING", *args))
        raise AssertionError("unexpected fixture SELECT")

    async def fetchval(self, sql, *args):
        if "nspowner" in sql:
            return self.schema_owner
        if "relowner" in sql:
            return self.table_owner
        if "pg_has_role" in sql:
            return self.owner_member
        if "has_table_privilege" in sql:
            if "'SELECT'" in sql:
                return True
            if "'INSERT'" in sql:
                return self.identity_insert if args[0].endswith(".identity") else True
            return self.mutate_privilege
        if "has_schema_privilege" in sql:
            return self.schema_create
        raise AssertionError("unexpected fixture privilege query")

    async def execute(self, sql, *args):
        if "SET LOCAL" in sql:
            return "SET"
        if ".terminals VALUES" in sql:
            namespace, identity, digest, status, result = args
            self.terminals.setdefault(
                ("TYPED_SIGNING", namespace, identity),
                {
                    "request_sha256": digest,
                    "terminal_status": status,
                    "result_sha256": result,
                },
            )
            self.events.append("INSERT_TERMINAL")
            return "INSERT"
        raise AssertionError("runtime must never execute DDL")


class FakePool:
    def __init__(self, connection):
        self.connection = connection

    @asynccontextmanager
    async def acquire(self):
        yield self.connection


def claims_fixture(connection=None, **overrides):
    connection = connection or FakeConnection()
    kwargs = dict(
        expected_database=DATABASE,
        database_uuid=DATABASE_UUID,
        policy_namespace="policy-v1",
        runtime_role="evidence_runtime",
        context=signed_gate_fixture()[3],
    )
    return PostgresProductionClaims(FakePool(connection), **{**kwargs, **overrides}), connection


@pytest.mark.asyncio
async def test_concurrent_claim_repeat_and_new_instance_restart_never_reclaim():
    store, connection = claims_fixture()
    kwargs = dict(custody_reference="kms:public-fixture", request_id="once", request_sha256="a" * 64)
    results = await asyncio.gather(*(store.claim_once_async(**kwargs) for _ in range(8)))
    assert results.count(True) == 1 and results.count(False) == 7
    restarted, _ = claims_fixture(connection)
    assert await restarted.claim_once_async(**kwargs) is False
    row = await restarted.load_claim(kind="TYPED_SIGNING", namespace="kms:public-fixture", identity="once")
    assert row["terminal_status"] is None  # UNKNOWN after restart is not retry authority.
    with pytest.raises(ProductionClaimError, match="rebound"):
        await restarted.claim_once_async(**{**kwargs, "request_sha256": "b" * 64})
    assert connection.events.index("INSERT_CLAIM") < connection.events.index("COMMIT")


@pytest.mark.asyncio
async def test_lost_commit_acknowledgment_is_sanitized_and_keeps_claim():
    store, connection = claims_fixture()
    connection.commit_lost = True
    kwargs = dict(owner_identity="owner", nonce="once", request_sha256="a" * 64)
    with pytest.raises(ProductionClaimError, match="unresolved; do not retry") as error:
        await store.consume_once_async(**kwargs)
    assert "DO_NOT_PRINT" not in str(error.value) and error.value.__cause__ is None
    assert await store.consume_once_async(**kwargs) is False


@pytest.mark.asyncio
async def test_terminal_exact_claim_is_immutable_and_unknown_cannot_promote():
    store, _ = claims_fixture()
    kwargs = dict(custody_reference="kms:public-fixture", request_id="once", request_sha256="a" * 64)
    with pytest.raises(ProductionClaimError, match="exact claim"):
        await store.finish_signing_async(**kwargs, terminal_status="COMPLETED", result_sha256="b" * 64)
    assert await store.claim_once_async(**kwargs)
    await store.finish_signing_async(**kwargs, terminal_status="UNRESOLVED", result_sha256=None)
    await store.finish_signing_async(**kwargs, terminal_status="UNRESOLVED", result_sha256=None)
    with pytest.raises(ProductionClaimError, match="conflict"):
        await store.finish_signing_async(**kwargs, terminal_status="COMPLETED", result_sha256="b" * 64)
    assert await store.claim_once_async(**kwargs) is False


@pytest.mark.parametrize(
    "change",
    [
        "db",
        "role",
        "uuid",
        "schema_owner",
        "table_owner",
        "unsafe",
        "owner_member",
        "mutate_privilege",
        "schema_create",
        "identity_insert",
    ],
)
@pytest.mark.asyncio
async def test_exact_positive_database_identity_owner_and_least_privilege(change):
    store, connection = claims_fixture()
    setattr(
        connection,
        change,
        {
            "db": "kairos",
            "role": "foreign",
            "uuid": UUID(int=1),
            "schema_owner": "foreign",
            "table_owner": "foreign",
        }.get(change, True),
    )
    with pytest.raises(ProductionClaimError):
        await store.claim_once_async(
            custody_reference="kms:fixture", request_id="once", request_sha256="a" * 64
        )
    assert connection.claims == {} and not connection.events


@pytest.mark.parametrize("name", ["kairos", "postgres", "kairos_simulator", "kairos_runtime_recovery_clone"])
def test_primary_or_generic_database_never_adopted(name):
    with pytest.raises(ProductionClaimError):
        claims_fixture(expected_database=name)


def test_uuid_is_explicit_and_sql_identity_values_never_interpolated():
    with pytest.raises(ProductionClaimError):
        claims_fixture(database_uuid=str(DATABASE_UUID))


@pytest.mark.asyncio
async def test_bad_inputs_before_any_query_and_observation_exception_sanitized():
    store, connection = claims_fixture()
    with pytest.raises(ProductionClaimError):
        await store.claim_once_async(custody_reference="kms:';SQL", request_id="x", request_sha256="a" * 64)
    assert connection.events == []
    original = connection.fetchrow

    async def failing(sql, *args):
        if "LEFT JOIN" in sql:
            raise RuntimeError("DO_NOT_PRINT_NATIVE_DSN")
        return await original(sql, *args)

    connection.fetchrow = failing
    with pytest.raises(ProductionClaimError, match="unavailable") as error:
        await store.load_claim(kind="TYPED_SIGNING", namespace="kms:fixture", identity="once")
    assert "DO_NOT_PRINT" not in str(error.value)
