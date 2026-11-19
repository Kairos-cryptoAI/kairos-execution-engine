"""Operator-stop authority: synthetic unit checks and opt-in disposable PostgreSQL.

Only KAIROS_SECURITY_TEST_ADMIN_DSN is accepted, on a nondefault loopback port.
The integration fixture creates and drops its own random database and roles; it
never reads deployment manifests, credential files, or starts a trading runtime.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import asyncpg
import pytest

from kairos_execution import production_operator as operator_cli
from kairos_execution import production_provisioning as provisioning
from kairos_execution import production_state as state
from kairos_execution.production_readiness import ProductionContextV1, canonical_digest
from kairos_execution.production_session import OperatorLatch
from kairos_execution.signing_authorization import LiveOperatorStateV1
from tests.test_signing_authorization import fixture as signing_fixture

_PUBLIC_PASSWORD = "public-operator-security-test-only"
_FUNCTION = f"{state.SCHEMA}.enforce_operator_append()"
_TABLE = f"{state.SCHEMA}.operator_observations"

# Exact old invoker body. Compatibility tests exercise explicit upgrade from
# the deployed v2/v3 guard, including its existing lineage/owner-arm checks.
_LEGACY_BODY = """
 DECLARE prior_version bigint; prior_payload jsonb; prior_observed_at timestamptz;
  prior_exists boolean; prior_state text;
 BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended(NEW.context_sha256,0));
  SELECT version,payload,observed_at INTO prior_version,prior_payload,prior_observed_at
   FROM kairos_production_state_v1.operator_observations
   WHERE context_sha256=NEW.context_sha256
   ORDER BY observed_at DESC,inserted_at DESC LIMIT 1;
  prior_exists := FOUND;
  IF NEW.observed_at >= clock_timestamp() THEN
   RAISE EXCEPTION 'operator observation must precede database clock';
  END IF;
  IF NOT prior_exists THEN
   IF NEW.payload->>'state' <> 'DISARMED' THEN
    RAISE EXCEPTION 'operator history must start DISARMED';
   END IF;
  ELSIF NEW.observed_at <= prior_observed_at THEN
   RAISE EXCEPTION 'operator observation time must increase';
  ELSIF NEW.version=prior_version THEN
   IF (NEW.payload-'observed_at') IS DISTINCT FROM (prior_payload-'observed_at') THEN
    RAISE EXCEPTION 'operator command changed without a new revision';
   END IF;
  ELSE
   prior_state := prior_payload->>'state';
   IF NEW.payload->>'state'='ARMED' THEN
    IF prior_state='ARMED'
     OR NEW.payload->>'arm_nonce' IS NULL
     OR NEW.payload->>'arm_request_sha256' IS NULL
     OR NEW.payload->>'expires_at' IS NULL
     OR (NEW.payload->>'expires_at')::timestamptz <= NEW.observed_at THEN
     RAISE EXCEPTION 'operator rearm requires a fresh signed owner arm';
    END IF;
    IF EXISTS (
     SELECT 1 FROM kairos_production_state_v1.operator_observations prior
     WHERE prior.context_sha256=NEW.context_sha256
      AND prior.payload->>'state'='ARMED'
      AND prior.payload->>'arm_nonce'=NEW.payload->>'arm_nonce'
      AND prior.payload->>'arm_request_sha256'=NEW.payload->>'arm_request_sha256'
    ) THEN
     RAISE EXCEPTION 'operator rearm cannot reuse a prior owner nonce';
    END IF;
    IF NOT EXISTS (
     SELECT 1 FROM kairos_production_state_v1.owner_arms arm
     WHERE arm.context_sha256=NEW.context_sha256
      AND arm.request_sha256=NEW.payload->>'arm_request_sha256'
      AND arm.nonce=NEW.payload->>'arm_nonce'
    ) THEN
     RAISE EXCEPTION 'operator ARM lacks its exact signed owner request';
    END IF;
   END IF;
   IF NEW.version<>prior_version+1
   OR NEW.payload->>'previous_command_sha256' IS DISTINCT FROM prior_payload->>'command_sha256'
    OR (NEW.payload->>'changed_at')::timestamptz < (prior_payload->>'changed_at')::timestamptz THEN
    RAISE EXCEPTION 'operator command revision/lineage is not contiguous';
   END IF;
  END IF;
  RETURN NEW;
 END """


@dataclass
class _Database:
    admin: asyncpg.Connection
    owner: asyncpg.Connection
    operator: asyncpg.Connection
    runtime: asyncpg.Connection
    owner_pool: asyncpg.Pool
    operator_pool: asyncpg.Pool
    database: str
    database_uuid: UUID
    roles: dict[str, str]
    context: ProductionContextV1
    policy_namespace: str
    schema_version: int

    def authority(self) -> dict:
        return {
            "expected_database": self.database,
            "database_uuid": self.database_uuid,
            "policy_namespace": self.policy_namespace,
            "context": self.context,
            "owner_role": self.roles["owner"],
        }


def _disposable_admin_target(dsn: str) -> tuple[str, int]:
    parsed = urlsplit(dsn)
    if (
        parsed.scheme != "postgresql"
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or parsed.port is None
        or parsed.port <= 1024
        or parsed.port == 5432
        or parsed.path != "/postgres"
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("security integration requires a disposable loopback PostgreSQL admin target")
    return parsed.hostname, parsed.port


@pytest.fixture(params=[2, 3])
async def control_database(request):
    dsn = os.getenv("KAIROS_SECURITY_TEST_ADMIN_DSN")
    if not dsn:
        pytest.skip("explicit disposable security-test PostgreSQL is not configured")
    host, port = _disposable_admin_target(dsn)
    suffix = uuid4().hex[:18]
    database = "kairos_production_evidence_security_" + suffix
    roles = {
        name: f"kx_security_{name}_{suffix}" for name in ("owner", "runtime", "operator", "risk", "exposure")
    }
    database_uuid = uuid4()
    context = signing_fixture()[2].context
    policy_namespace = "security-operator:" + suffix
    admin = await asyncpg.connect(dsn, timeout=5, command_timeout=5)
    created_roles: list[str] = []
    created_database = False
    connections = []
    pools = []
    try:
        for name in roles.values():
            await admin.execute(
                f'CREATE ROLE "{name}" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE '
                f"NOREPLICATION NOBYPASSRLS NOINHERIT PASSWORD '{_PUBLIC_PASSWORD}'"
            )
            created_roles.append(name)
        await admin.execute(f'CREATE DATABASE "{database}" OWNER "{roles["owner"]}"')
        created_database = True
        await admin.execute(f'REVOKE CONNECT ON DATABASE "{database}" FROM PUBLIC')
        await admin.execute(
            f'GRANT CONNECT ON DATABASE "{database}" TO ' + ",".join(f'"{role}"' for role in roles.values())
        )

        async def connect(role):
            connection = await asyncpg.connect(
                host=host,
                port=port,
                database=database,
                user=roles[role],
                password=_PUBLIC_PASSWORD,
                timeout=5,
                command_timeout=5,
            )
            connections.append(connection)
            return connection

        owner = await connect("owner")
        await state.provision_production_state_schema(
            owner,
            expected_database=database,
            database_uuid=database_uuid,
            policy_namespace=policy_namespace,
            context=context,
            owner_role=roles["owner"],
            runtime_role=roles["runtime"],
            operator_writer_role=roles["operator"],
            risk_writer_role=roles["risk"],
            exposure_writer_role=roles["exposure"],
            state_schema_version=request.param,
        )
        operator, runtime = await connect("operator"), await connect("runtime")
        control_admin = await asyncpg.connect(
            dsn.rsplit("/", 1)[0] + "/" + database, timeout=5, command_timeout=5
        )
        connections.append(control_admin)
        for role in ("owner", "operator"):
            pool = await asyncpg.create_pool(
                host=host,
                port=port,
                database=database,
                user=roles[role],
                password=_PUBLIC_PASSWORD,
                min_size=1,
                max_size=2,
                timeout=5,
                command_timeout=5,
            )
            pools.append(pool)
        yield _Database(
            control_admin,
            owner,
            operator,
            runtime,
            pools[0],
            pools[1],
            database,
            database_uuid,
            roles,
            context,
            policy_namespace,
            request.param,
        )
    finally:
        for pool in reversed(pools):
            await pool.close()
        for connection in reversed(connections):
            await connection.close()
        if created_database:
            await admin.execute(f'DROP DATABASE "{database}" WITH (FORCE)')
        for role in reversed(created_roles):
            await admin.execute(f'DROP ROLE "{role}"')
        await admin.close()


async def _observation(db, value, prior=None, *, arm=None):
    now = await db.operator.fetchval("SELECT clock_timestamp()")
    stamp = now - timedelta(microseconds=1)
    version = 1 if prior is None else prior.version + 1
    return LiveOperatorStateV1(
        context=db.context,
        version=version,
        state=value,
        arm_nonce=None if arm is None else arm.request.nonce,
        arm_request_sha256=None if arm is None else canonical_digest(arm.request),
        observed_at=stamp,
        changed_at=stamp,
        expires_at=None if arm is None else arm.request.expires_at,
        command_sha256=hashlib.sha256(f"{value}:{version}:{uuid4()}".encode()).hexdigest(),
        previous_command_sha256="0" * 64 if prior is None else prior.command_sha256,
    )


async def _append(db, connection, value):
    payload = value.model_dump(mode="json") if isinstance(value, LiveOperatorStateV1) else value
    observed_at = datetime.fromisoformat(payload["observed_at"])
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    await connection.execute(
        f"INSERT INTO {_TABLE} (context_sha256,observation_id,version,observed_at,payload,payload_sha256) "
        "VALUES($1,$2,$3,$4,$5::jsonb,$6)",
        canonical_digest(db.context),
        uuid4(),
        payload["version"],
        observed_at,
        encoded,
        hashlib.sha256(encoded.encode()).hexdigest(),
    )


async def _killed(db):
    disarmed = await _observation(db, "DISARMED")
    await _append(db, db.operator, disarmed)
    killed = await _observation(db, "KILLED", disarmed)
    await _append(db, db.operator, killed)
    return killed


async def _fresh_arm(db):
    signed_arm = signing_fixture(nonce="security-" + uuid4().hex)[3].owner_arm
    writer = state.PostgresOperatorStateWriter(
        db.operator_pool,
        expected_database=db.database,
        database_uuid=db.database_uuid,
        policy_namespace=db.policy_namespace,
        context=db.context,
        expected_role=db.roles["operator"],
        state_schema_version=db.schema_version,
    )
    await writer.append_owner_arm_async(signed_arm)
    return signed_arm


def _runtime_source(db):
    # inspect() receives the real runtime connection explicitly; no pool I/O
    # or claims/trading components are needed for the source contract check.
    return state.AsyncPostgresProductionSigningStateSource(
        object(),
        expected_database=db.database,
        database_uuid=db.database_uuid,
        policy_namespace=db.policy_namespace,
        context=db.context,
        runtime_role=db.roles["runtime"],
        state_schema_version=db.schema_version,
    )


@pytest.mark.asyncio
async def test_operator_latch_requires_separate_owner_authority_to_resume():
    class NoAuthority:
        async def latest_operator_state_async(self):
            pytest.fail("missing owner authority must refuse before reading operator state")

    latch = OperatorLatch(NoAuthority(), signing_fixture()[2].context, lambda: None)
    with pytest.raises(TypeError):
        await latch.resume()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "invalid",
    [
        {"expected_version": True},
        {"expected_version": 0},
        {"expected_version": -1},
        {"expected_command_sha256": "short"},
        {"database_uuid": UUID(int=0)},
    ],
)
async def test_owner_resume_rejects_ambiguous_identity_before_acquiring_database(invalid):
    class NoDatabase:
        def acquire(self):
            pytest.fail("invalid owner resume identity must refuse before database acquisition")

    arguments = {
        "expected_database": "kairos_production_evidence_security_123456789abc",
        "database_uuid": uuid4(),
        "policy_namespace": "security:synthetic-owner-resume",
        "context": signing_fixture()[2].context,
        "owner_role": "synthetic_owner",
        "expected_version": 2,
        "expected_command_sha256": "a" * 64,
    }
    with pytest.raises(state.ProductionStateError):
        await state.resume_operator_after_kill_async(NoDatabase(), **(arguments | invalid))


@pytest.mark.asyncio
async def test_missing_guard_is_refused_by_read_only_inspection():
    class MissingGuard:
        async def fetchrow(self, query):
            return None

        async def execute(self, *args):
            pytest.fail("guard inspection must never repair or install a missing guard")

    with pytest.raises(state.ProductionStateError):
        await state.assert_operator_control_guard(MissingGuard(), owner_role="synthetic_owner")


@pytest.mark.parametrize(
    "dsn",
    [
        "postgresql://public:test@example.com:55432/postgres",
        "postgresql://public:test@127.0.0.1:5432/postgres",
        "postgresql://public:test@127.0.0.1:55432/production",
        "postgresql://public:test@127.0.0.1:55432/postgres?options=unsafe",
    ],
)
def test_security_fixture_refuses_non_disposable_targets(dsn):
    with pytest.raises(ValueError, match="disposable loopback"):
        _disposable_admin_target(dsn)


def _cli_manifest(monkeypatch, tmp_path, *, host="127.0.0.1"):
    context = signing_fixture()[2].context
    manifest = provisioning.ProvisionedDatabaseV1(
        version="kairos.production-database.v1",
        host=host,
        port=65446,
        database="kairos_production_evidence_security_123456789abc",
        database_uuid=str(uuid4()),
        policy_namespace="security:synthetic-owner-cli",
        roles={name: f"synthetic_{name}" for name in provisioning.ROLE_NAMES},
        password_files={
            name: str(tmp_path / f"synthetic-{name}.password") for name in provisioning.ROLE_NAMES
        },
        context=context.model_dump(mode="json"),
    )
    loaded, private_reads = [], []

    def load(cls, path):
        loaded.append(path)
        return manifest

    def private_read(path):
        private_reads.append(path)
        assert path == Path(manifest.password_files["owner"])
        return b"synthetic-test+only:secret\n"

    monkeypatch.setattr(operator_cli.ProvisionedDatabaseV1, "load", classmethod(load))
    monkeypatch.setattr(provisioning, "read_private_file", private_read)
    authority = {
        "expected_database": manifest.database,
        "database_uuid": UUID(manifest.database_uuid),
        "policy_namespace": manifest.policy_namespace,
        "context": context,
        "owner_role": manifest.roles["owner"],
    }
    expected_dsn = (
        f"postgresql://synthetic_owner:synthetic-test%2Bonly%3Asecret@{host}:65446/{manifest.database}"
    )
    return manifest, authority, expected_dsn, loaded, private_reads


@pytest.mark.parametrize(
    "arguments",
    [
        [],
        ["resume", "--manifest", "synthetic.json"],
        ["resume", "--manifest", "synthetic.json", "--expected-version", "2"],
        ["resume", "--manifest", "synthetic.json", "--expected-command-sha256", "a" * 64],
        [
            "resume",
            "--manifest",
            "synthetic.json",
            "--expected-version",
            "two",
            "--expected-command-sha256",
            "a" * 64,
        ],
    ],
)
def test_owner_cli_requires_explicit_operation_and_exact_killed_identity(monkeypatch, arguments):
    async def forbidden(args):
        pytest.fail("incomplete owner command must refuse before invoking any operation")

    monkeypatch.setattr(operator_cli, "run_owner_operation", forbidden)
    with pytest.raises(SystemExit) as rejected:
        operator_cli.main(arguments)
    assert rejected.value.code == 2


def test_owner_cli_resume_uses_only_protected_owner_dsn_and_exact_manifest_authority(
    monkeypatch, tmp_path, capsys
):
    manifest, authority, dsn, loaded, private_reads = _cli_manifest(monkeypatch, tmp_path)
    calls = []

    class Pool:
        async def close(self):
            calls.append("close")

    pool = Pool()

    async def create_pool(target, **options):
        assert target == dsn
        assert options == {"min_size": 1, "max_size": 1, "timeout": 5, "command_timeout": 5}
        calls.append("connect-owner")
        return pool

    async def resume(actual_pool, **arguments):
        assert actual_pool is pool
        assert arguments == authority | {"expected_version": 2, "expected_command_sha256": "a" * 64}
        calls.append("resume")
        return SimpleNamespace(version=3, command_sha256="c" * 64, previous_command_sha256="a" * 64)

    async def forbidden(*args, **kwargs):
        pytest.fail("resume must never implicitly invoke an upgrade or a second connection route")

    monkeypatch.setattr(operator_cli.asyncpg, "create_pool", create_pool)
    monkeypatch.setattr(operator_cli.asyncpg, "connect", forbidden)
    monkeypatch.setattr(operator_cli, "resume_operator_after_kill_async", resume)
    monkeypatch.setattr(operator_cli, "upgrade_operator_control_guard", forbidden)
    manifest_path = tmp_path / "synthetic-manifest.json"
    assert (
        operator_cli.main(
            [
                "resume",
                "--manifest",
                str(manifest_path),
                "--expected-version",
                "2",
                "--expected-command-sha256",
                "a" * 64,
            ]
        )
        == 0
    )
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {
        "outcome": "DISARMED",
        "version": 3,
        "command_sha256": "c" * 64,
        "previous_command_sha256": "a" * 64,
    }
    assert not captured.err
    assert loaded == [manifest_path]
    assert private_reads == [Path(manifest.password_files["owner"])]
    assert calls == ["connect-owner", "resume", "close"]


def test_owner_cli_upgrade_is_explicit_and_never_resumes(monkeypatch, tmp_path, capsys):
    manifest, authority, dsn, loaded, private_reads = _cli_manifest(monkeypatch, tmp_path)
    calls = []

    class Connection:
        async def close(self):
            calls.append("close")

    connection = Connection()

    async def connect(target, **options):
        assert target == dsn and options == {"timeout": 5, "command_timeout": 5}
        calls.append("connect-owner")
        return connection

    async def upgrade(actual_connection, **arguments):
        assert actual_connection is connection and arguments == authority
        calls.append("upgrade")

    async def forbidden(*args, **kwargs):
        pytest.fail("guard upgrade must never implicitly resume or acquire a runtime/operator pool")

    monkeypatch.setattr(operator_cli.asyncpg, "connect", connect)
    monkeypatch.setattr(operator_cli.asyncpg, "create_pool", forbidden)
    monkeypatch.setattr(operator_cli, "upgrade_operator_control_guard", upgrade)
    monkeypatch.setattr(operator_cli, "resume_operator_after_kill_async", forbidden)
    manifest_path = tmp_path / "synthetic-manifest.json"
    assert operator_cli.main(["upgrade-guard", "--manifest", str(manifest_path)]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {"outcome": "GUARD_UPGRADED"}
    assert not captured.err
    assert loaded == [manifest_path]
    assert private_reads == [Path(manifest.password_files["owner"])]
    assert calls == ["connect-owner", "upgrade", "close"]


@pytest.mark.parametrize("operation", ["resume", "upgrade-guard"])
def test_owner_cli_remote_manifest_refuses_before_secret_read_or_connect(
    monkeypatch, tmp_path, capsys, operation
):
    _, _, _, _, private_reads = _cli_manifest(monkeypatch, tmp_path, host="db.example.invalid")

    async def forbidden(*args, **kwargs):
        pytest.fail("a remote manifest must be rejected before any connection")

    monkeypatch.setattr(operator_cli.asyncpg, "connect", forbidden)
    monkeypatch.setattr(operator_cli.asyncpg, "create_pool", forbidden)
    arguments = [operation, "--manifest", str(tmp_path / "synthetic-manifest.json")]
    if operation == "resume":
        arguments += ["--expected-version", "2", "--expected-command-sha256", "a" * 64]
    assert operator_cli.main(arguments) == 2
    assert json.loads(capsys.readouterr().out)["outcome"] == "REFUSED_OR_UNRESOLVED"
    assert not private_reads


@pytest.mark.parametrize("operation", ["resume", "upgrade-guard"])
@pytest.mark.parametrize("failure_stage", ["connect", "operation"])
def test_owner_cli_sanitizes_exceptions_and_closes_open_owner_resource(
    monkeypatch, tmp_path, capsys, operation, failure_stage
):
    _, _, dsn, _, _ = _cli_manifest(monkeypatch, tmp_path)
    closed = []

    class Resource:
        async def close(self):
            closed.append(True)

    async def failed_connection(*args, **kwargs):
        if failure_stage == "operation":
            return Resource()
        await failed_operation()

    async def failed_operation(*args, **kwargs):
        raise RuntimeError(f"synthetic connection failure {dsn} SYNTHETIC_PRIVATE_PATH/owner.password")

    monkeypatch.setattr(operator_cli.asyncpg, "connect", failed_connection)
    monkeypatch.setattr(operator_cli.asyncpg, "create_pool", failed_connection)
    monkeypatch.setattr(operator_cli, "resume_operator_after_kill_async", failed_operation)
    monkeypatch.setattr(operator_cli, "upgrade_operator_control_guard", failed_operation)
    arguments = [operation, "--manifest", str(tmp_path / "synthetic-manifest.json")]
    if operation == "resume":
        arguments += ["--expected-version", "2", "--expected-command-sha256", "a" * 64]
    assert operator_cli.main(arguments) == 2
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {
        "outcome": "REFUSED_OR_UNRESOLVED",
        "detail": "owner operation did not complete",
    }
    assert not captured.err
    assert dsn not in captured.out and "SYNTHETIC_PRIVATE_PATH" not in captured.out
    assert closed == ([True] if failure_stage == "operation" else [])


@pytest.mark.integration
@pytest.mark.asyncio
async def test_direct_sql_operator_cannot_leave_killed(control_database):
    db = control_database
    killed = await _killed(db)
    arm = await _fresh_arm(db)
    disarmed = await _observation(db, "DISARMED", killed)
    armed = await _observation(db, "ARMED", killed, arm=arm)
    missing_state = disarmed.model_dump(mode="json")
    missing_state.pop("state")
    null_state = disarmed.model_dump(mode="json") | {"state": None}
    for attempted in (disarmed, armed, missing_state, null_state):
        with pytest.raises(asyncpg.PostgresError):
            await _append(db, db.operator, attempted)
    latest = await db.operator.fetchval(
        f"SELECT payload->>'state' FROM {_TABLE} ORDER BY version DESC LIMIT 1"
    )
    assert latest == "KILLED"


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.parametrize("isolation", ["read_committed", "repeatable_read", "serializable"])
@pytest.mark.parametrize("attempt", ["disarmed", "armed_new_revision", "armed_refresh"])
async def test_operator_stale_transaction_cannot_hide_committed_kill(control_database, isolation, attempt):
    db = control_database
    prior = await _observation(db, "DISARMED")
    await _append(db, db.operator, prior)
    arm = await _fresh_arm(db)
    if attempt in {"disarmed", "armed_refresh"}:
        armed = await _observation(db, "ARMED", prior, arm=arm)
        await _append(db, db.operator, armed)
        prior = armed

    transaction = db.operator.transaction(isolation=isolation)
    await transaction.start()
    try:
        # The first SELECT pins a repeatable-read/serializable snapshot before
        # the independent owner's global stop. Advisory locks cannot refresh it.
        assert (
            await db.operator.fetchval(
                f"SELECT payload->>'state' FROM {_TABLE} ORDER BY observed_at DESC LIMIT 1"
            )
            == prior.state
        )
        killed = await _observation(db, "KILLED", prior)
        await _append(db, db.owner, killed)
        assert (
            await db.owner.fetchval(
                f"SELECT payload->>'state' FROM {_TABLE} ORDER BY observed_at DESC LIMIT 1"
            )
            == "KILLED"
        )

        if attempt == "armed_refresh":
            stamp = await db.operator.fetchval("SELECT clock_timestamp()")
            stale = prior.model_copy(update={"observed_at": stamp - timedelta(microseconds=1)})
        else:
            stale = await _observation(
                db,
                "DISARMED" if attempt == "disarmed" else "ARMED",
                prior,
                arm=arm if attempt == "armed_new_revision" else None,
            )
        # PostgreSQL may itself abort SERIALIZABLE at INSERT or COMMIT. Either
        # refusal is safe; a committed stale command must never replace KILLED.
        with pytest.raises(asyncpg.PostgresError):
            await _append(db, db.operator, stale)
            await transaction.commit()
    finally:
        if db.operator.is_in_transaction():
            await transaction.rollback()
    assert (
        await db.owner.fetchval(f"SELECT payload->>'state' FROM {_TABLE} ORDER BY observed_at DESC LIMIT 1")
        == "KILLED"
    )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_killed_refresh_and_owner_disarm_preserve_operator_rearm(control_database):
    db = control_database
    killed = await _killed(db)
    refreshed = killed.model_copy(
        update={"observed_at": (await db.operator.fetchval("SELECT clock_timestamp()"))}
    )
    await _append(db, db.operator, refreshed)
    arm = await _fresh_arm(db)
    with pytest.raises(asyncpg.PostgresError):
        await _append(db, db.owner, await _observation(db, "ARMED", refreshed, arm=arm))
    disarmed = await _observation(db, "DISARMED", refreshed)
    await _append(db, db.owner, disarmed)
    armed = await _observation(db, "ARMED", disarmed, arm=arm)
    await _append(db, db.operator, armed)
    await _append(db, db.operator, await _observation(db, "DISARMED", armed))
    assert await db.operator.fetchval(f"SELECT max(version) FROM {_TABLE}") == 5


@pytest.mark.integration
@pytest.mark.asyncio
async def test_owner_resume_is_authenticated_contiguous_and_compare_and_swap(control_database):
    db = control_database
    killed = await _killed(db)
    expected = {"expected_version": killed.version, "expected_command_sha256": killed.command_sha256}
    before = await db.owner.fetchval(f"SELECT count(*) FROM {_TABLE}")
    with pytest.raises(state.ProductionStateError):
        await state.resume_operator_after_kill_async(db.operator_pool, **db.authority(), **expected)
    for stale in (
        expected | {"expected_version": killed.version + 1},
        expected | {"expected_command_sha256": "0" * 64},
    ):
        with pytest.raises(state.ProductionStateError):
            await state.resume_operator_after_kill_async(db.owner_pool, **db.authority(), **stale)
    assert await db.owner.fetchval(f"SELECT count(*) FROM {_TABLE}") == before
    resumed = await state.resume_operator_after_kill_async(db.owner_pool, **db.authority(), **expected)
    assert resumed.state == "DISARMED"
    assert resumed.version == killed.version + 1
    assert resumed.previous_command_sha256 == killed.command_sha256
    assert resumed.observed_at > killed.observed_at
    assert resumed.arm_nonce is resumed.arm_request_sha256 is resumed.expires_at is None
    with pytest.raises(state.ProductionStateError):
        await state.resume_operator_after_kill_async(db.owner_pool, **db.authority(), **expected)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_owner_resume_concurrent_attempts_append_exactly_one_revision(control_database):
    db = control_database
    killed = await _killed(db)
    attempts = await asyncio.gather(
        *(
            state.resume_operator_after_kill_async(
                db.owner_pool,
                **db.authority(),
                expected_version=killed.version,
                expected_command_sha256=killed.command_sha256,
            )
            for _ in range(2)
        ),
        return_exceptions=True,
    )
    assert sum(isinstance(value, LiveOperatorStateV1) for value in attempts) == 1
    assert sum(isinstance(value, state.ProductionStateError) for value in attempts) == 1
    assert await db.owner.fetchval(f"SELECT count(*) FROM {_TABLE} WHERE version=$1", killed.version + 1) == 1


@pytest.mark.integration
@pytest.mark.asyncio
async def test_operator_latch_resumes_only_through_explicit_owner_pool(control_database):
    db = control_database
    killed = await _killed(db)
    writer = state.PostgresOperatorStateWriter(
        db.operator_pool,
        expected_database=db.database,
        database_uuid=db.database_uuid,
        policy_namespace=db.policy_namespace,
        context=db.context,
        expected_role=db.roles["operator"],
        state_schema_version=db.schema_version,
    )
    latch = OperatorLatch(writer, db.context, lambda: None)
    with pytest.raises(state.ProductionStateError):
        await latch.resume(owner_pool=db.operator_pool, owner_role=db.roles["owner"])
    resumed = await latch.resume(owner_pool=db.owner_pool, owner_role=db.roles["owner"])
    assert resumed.state == "DISARMED" and resumed.version == killed.version + 1
    assert await writer.latest_operator_state_async() == resumed


async def _replace_body(db, body):
    await db.owner.execute(
        f"CREATE OR REPLACE FUNCTION {_FUNCTION} RETURNS trigger LANGUAGE plpgsql "
        f"SET search_path=pg_catalog AS $security_test${body}$security_test$"
    )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_old_guard_requires_explicit_authenticated_upgrade(control_database):
    db = control_database
    await _replace_body(db, _LEGACY_BODY)
    legacy = await db.owner.fetchval("SELECT prosrc FROM pg_proc WHERE oid=$1::regprocedure", _FUNCTION)
    with pytest.raises(state.ProductionStateError):
        await state.assert_operator_control_guard(db.runtime, owner_role=db.roles["owner"])
    with pytest.raises(state.ProductionStateError):
        await _runtime_source(db).inspect(db.runtime)
    assert (
        await db.owner.fetchval("SELECT prosrc FROM pg_proc WHERE oid=$1::regprocedure", _FUNCTION) == legacy
    )
    with pytest.raises(state.ProductionStateError):
        await state.upgrade_operator_control_guard(db.operator, **db.authority())
    with pytest.raises(state.ProductionStateError):
        await state.upgrade_operator_control_guard(db.owner, **(db.authority() | {"database_uuid": uuid4()}))
    assert (
        await db.owner.fetchval("SELECT prosrc FROM pg_proc WHERE oid=$1::regprocedure", _FUNCTION) == legacy
    )
    await state.upgrade_operator_control_guard(db.owner, **db.authority())
    await state.assert_operator_control_guard(db.runtime, owner_role=db.roles["owner"])
    await _runtime_source(db).inspect(db.runtime)
    await state.upgrade_operator_control_guard(db.owner, **db.authority())
    assert await db.owner.fetchval(f"SELECT schema_version FROM {state.SCHEMA}.identity") == db.schema_version
    killed = await _killed(db)
    with pytest.raises(asyncpg.PostgresError):
        await _append(db, db.operator, await _observation(db, "DISARMED", killed))


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation", ["body", "disabled", "misbound", "security_definer", "search_path", "wrong_owner"]
)
async def test_guard_inspection_refuses_changed_function_or_trigger(control_database, mutation):
    db = control_database
    await state.assert_operator_control_guard(db.runtime, owner_role=db.roles["owner"])
    if mutation == "body":
        await _replace_body(db, " BEGIN RETURN NEW; END ")
    elif mutation == "disabled":
        await db.owner.execute(f"ALTER TABLE {_TABLE} DISABLE TRIGGER operator_append_guard")
    elif mutation == "security_definer":
        await db.owner.execute(f"ALTER FUNCTION {_FUNCTION} SECURITY DEFINER")
    elif mutation == "search_path":
        await db.owner.execute(f"ALTER FUNCTION {_FUNCTION} SET search_path=public,pg_catalog")
    elif mutation == "wrong_owner":
        await db.admin.execute(f'ALTER FUNCTION {_FUNCTION} OWNER TO "{db.roles["runtime"]}"')
    else:
        await db.owner.execute(
            f"CREATE FUNCTION {state.SCHEMA}.unrelated_guard() RETURNS trigger LANGUAGE plpgsql "
            "AS $$ BEGIN RETURN NEW; END $$"
        )
        await db.owner.execute(f"DROP TRIGGER operator_append_guard ON {_TABLE}")
        await db.owner.execute(
            f"CREATE TRIGGER operator_append_guard BEFORE INSERT ON {_TABLE} "
            f"FOR EACH ROW EXECUTE FUNCTION {state.SCHEMA}.unrelated_guard()"
        )
    with pytest.raises(state.ProductionStateError):
        await state.assert_operator_control_guard(db.runtime, owner_role=db.roles["owner"])
    with pytest.raises(state.ProductionStateError):
        await _runtime_source(db).inspect(db.runtime)
    if mutation == "disabled":
        await state.upgrade_operator_control_guard(db.owner, **db.authority())
        await state.assert_operator_control_guard(db.runtime, owner_role=db.roles["owner"])
        return
    # An explicit migration may only replace the recognized historical guard;
    # an arbitrary body or altered security contract is not silently repaired.
    with pytest.raises(state.ProductionStateError):
        await state.upgrade_operator_control_guard(db.owner, **db.authority())
