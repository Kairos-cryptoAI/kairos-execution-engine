"""Owner-only provisioning of one isolated production-evidence PostgreSQL database.

This composes, in the order the production-path integration test proves, the existing
provisioning functions of this repository and the Persistence runtime migrations:

1. seven separate non-inheriting login roles (owner, runtime, operator, risk, exposure,
   reconciler, accounting), each with its own random password written to a file;
2. a fresh ``kairos_production_evidence_<suffix>`` database owned by the owner role;
3. the Persistence RUNTIME migrations (journals, effects, trades, event audit);
4. the claims, production-state (v3), reconciliation (v2) and accounting schemas;
5. the exact table and sequence grants the runtime role needs.

It never connects to an existing production database, never reuses a schema and never
reads a wallet, API key or owner key. Running it does not arm anything: the database
it creates refuses every entry until an owner arm and operator state are appended.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import secrets
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import quote, urlsplit, urlunsplit
from uuid import UUID, uuid4

import asyncpg  # type: ignore[import-untyped]  # Upstream ships no typing marker/stubs.

from .production_accounting import provision_production_accounting_schema
from .production_claims import provision_isolated_schema
from .production_readiness import ProductionContextV1
from .production_reconciliation import provision_production_reconciliation_schema
from .production_state import provision_production_state_schema
from .protected_files import ProtectedFileError, read_private_file, write_new_private_file

ROLE_NAMES = ("owner", "runtime", "operator", "risk", "exposure", "reconciler", "accounting")
_LOCAL_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_SUFFIX = re.compile(r"[a-z0-9_]{12,40}\Z")

# The runtime role's grants on the Persistence tables, exactly as the production path uses them.
_RUNTIME_GRANTS = (
    "GRANT SELECT,INSERT ON public.event_audit TO {runtime}",
    "GRANT SELECT,INSERT,UPDATE ON public.execution_effects,public.execution_trades,"
    "public.execution_recovery_state,public.account_equity_state,public.execution_runtime_health,"
    "public.message_outbox TO {runtime}",
    "GRANT SELECT,INSERT ON public.execution_effect_events,public.execution_trade_events,"
    "public.public_execution_events TO {runtime}",
    "GRANT SELECT,INSERT ON public.execution_mutation_budget_scopes,"
    "public.execution_mutation_reservations TO {runtime}",
    "GRANT USAGE,SELECT ON SEQUENCE public.execution_trade_events_sequence_seq,"
    "public.execution_effect_events_sequence_seq,public.message_outbox_id_seq TO {runtime}",
)


class ProvisioningError(ValueError):
    """Provisioning refused; messages never contain a DSN or password."""


@dataclass(frozen=True, slots=True)
class ProvisionedDatabaseV1:
    """What a deployment needs to connect, without any secret."""

    version: str
    host: str
    port: int
    database: str
    database_uuid: str
    policy_namespace: str
    roles: dict[str, str]
    password_files: dict[str, str]
    context: dict[str, str]

    def dsn(self, role: str) -> str:
        """The DSN of one role, with its password read from its file now."""
        password = None
        try:
            password = read_private_file(Path(self.password_files[role])).decode("utf-8").strip()
        except (ProtectedFileError, UnicodeError):
            pass
        if password is None:
            raise ProvisioningError("role password file is unavailable or not private")
        netloc = f"{self.roles[role]}:{quote(password, safe='')}@{self.host}:{self.port}"
        return urlunsplit(("postgresql", netloc, f"/{self.database}", "", ""))

    @classmethod
    def load(cls, path: Path) -> ProvisionedDatabaseV1:
        return cls(**json.loads(Path(path).read_text(encoding="utf-8")))


def _admin_target(admin_dsn: str) -> tuple[str, int]:
    parsed = urlsplit(admin_dsn)
    if parsed.scheme not in {"postgresql", "postgres"} or parsed.hostname not in _LOCAL_HOSTS:
        raise ProvisioningError("provisioning accepts only a local PostgreSQL administrator DSN")
    if parsed.query or parsed.fragment or parsed.port is None:
        raise ProvisioningError("the administrator DSN needs an explicit port and no parameters")
    return parsed.hostname, parsed.port


def _write_secret(path: Path, value: str) -> None:
    succeeded = False
    try:
        write_new_private_file(path, value.encode("utf-8"))
        succeeded = True
    except ProtectedFileError:
        pass
    if not succeeded:
        raise ProvisioningError("new role password file could not be created privately")


async def provision_production_database(
    admin_dsn: str,
    *,
    context: ProductionContextV1,
    secrets_dir: Path,
    policy_namespace: str,
    suffix: str | None = None,
) -> ProvisionedDatabaseV1:
    """Create one fresh isolated database and every schema the production path reads."""
    from kairos_persistence import Database, MigrationProfile, PersistenceSettings

    host, port = _admin_target(admin_dsn)
    suffix = suffix or uuid4().hex[:16]
    if _SUFFIX.fullmatch(suffix) is None:
        raise ProvisioningError("suffix must be 12-40 lowercase letters, digits or underscores")
    database = f"kairos_production_evidence_{suffix}"
    roles = {name: f"kx_{name}_{suffix}"[:63] for name in ROLE_NAMES}
    secrets_dir = Path(secrets_dir)
    password_files = {name: str(secrets_dir / f"{database}.{name}.password") for name in ROLE_NAMES}
    passwords = {name: secrets.token_urlsafe(32) for name in ROLE_NAMES}
    for name in ROLE_NAMES:
        if Path(password_files[name]).exists():
            raise ProvisioningError("secret files for this database already exist")
    database_uuid: UUID = uuid4()

    admin = await asyncpg.connect(admin_dsn)
    try:
        if await admin.fetchval("SELECT 1 FROM pg_database WHERE datname=$1", database):
            raise ProvisioningError("the database already exists")
        for name, role in roles.items():
            if await admin.fetchval("SELECT 1 FROM pg_roles WHERE rolname=$1", role):
                raise ProvisioningError("a role of this suffix already exists")
            # Role names are validated identifiers; the password is a quoted literal.
            literal = passwords[name].replace("'", "''")
            await admin.execute(f"CREATE ROLE \"{role}\" LOGIN NOINHERIT PASSWORD '{literal}'")
        await admin.execute(f'CREATE DATABASE "{database}" OWNER "{roles["owner"]}"')
    finally:
        await admin.close()
    for name in ROLE_NAMES:
        _write_secret(Path(password_files[name]), passwords[name])

    manifest = ProvisionedDatabaseV1(
        version="kairos.production-database.v1",
        host=host,
        port=port,
        database=database,
        database_uuid=str(database_uuid),
        policy_namespace=policy_namespace,
        roles=roles,
        password_files=password_files,
        context=context.model_dump(mode="json"),
    )
    # The extension migration 001 needs is created by the administrator, never by the owner.
    extension_admin = await asyncpg.connect(_with_database(admin_dsn, database))
    try:
        await extension_admin.execute("CREATE EXTENSION IF NOT EXISTS timescaledb")
    finally:
        await extension_admin.close()

    persistence = Database(
        PersistenceSettings(database_url=manifest.dsn("owner")), migration_profile=MigrationProfile.RUNTIME
    )
    await persistence.connect()
    try:
        await persistence.migrate()
    finally:
        await persistence.close()

    owner = await asyncpg.connect(manifest.dsn("owner"))
    try:
        await owner.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
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
            expected_database=database,
            database_uuid=database_uuid,
            policy_namespace=policy_namespace,
            context=context,
            owner_role=roles["owner"],
            runtime_role=roles["runtime"],
            operator_writer_role=roles["operator"],
            risk_writer_role=roles["risk"],
            exposure_writer_role=roles["exposure"],
            state_schema_version=3,
        )
        await provision_production_reconciliation_schema(
            owner,
            expected_database=database,
            database_uuid=database_uuid,
            policy_namespace=policy_namespace,
            context=context,
            owner_role=roles["owner"],
            reconciler_role=roles["reconciler"],
            schema_version=2,
        )
        await provision_production_accounting_schema(
            owner,
            expected_database=database,
            database_uuid=database_uuid,
            policy_namespace=policy_namespace,
            context=context,
            owner_role=roles["owner"],
            accounting_role=roles["accounting"],
        )
        runtime = f'"{roles["runtime"]}"'
        for statement in _RUNTIME_GRANTS:
            await owner.execute(statement.format(runtime=runtime))
    finally:
        await owner.close()
    return manifest


def _with_database(dsn: str, database: str) -> str:
    parsed = urlsplit(dsn)
    return urlunsplit((parsed.scheme, parsed.netloc, f"/{database}", "", ""))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--admin-dsn-file", type=Path, required=True, help="file with a local admin DSN")
    parser.add_argument("--secrets-dir", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--context", type=Path, required=True, help="ProductionContextV1 as JSON")
    parser.add_argument("--policy-namespace", required=True)
    parser.add_argument("--suffix")
    args = parser.parse_args(argv)
    if args.manifest.exists():
        print("refusing to overwrite an existing manifest", file=sys.stderr)
        return 2
    context = ProductionContextV1.model_validate_json(args.context.read_text(encoding="utf-8"))
    admin_dsn = args.admin_dsn_file.read_text(encoding="utf-8").strip()
    try:
        manifest = asyncio.run(
            provision_production_database(
                admin_dsn,
                context=context,
                secrets_dir=args.secrets_dir,
                policy_namespace=args.policy_namespace,
                suffix=args.suffix,
            )
        )
    except (ProvisioningError, asyncpg.PostgresError, OSError) as exc:
        print(f"provisioning refused: {type(exc).__name__}: {str(exc)[:200]}", file=sys.stderr)
        return 1
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_text(json.dumps(asdict(manifest), indent=2), encoding="utf-8")
    print(f"provisioned {manifest.database}; manifest {args.manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
