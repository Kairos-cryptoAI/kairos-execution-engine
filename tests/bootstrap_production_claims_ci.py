"""Bootstrap a disposable synthetic claims-test DB in the existing CI service.

This helper is intentionally inert outside the GitHub Actions job and creates
only fixed, isolated test identities in that job's newly-created PostgreSQL
service. All credentials below are public test fixtures, never user secrets.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Mapping
from pathlib import Path
from uuid import UUID, uuid4

DATABASE = "kairos_production_evidence_ci_000000000001"
LIFECYCLE_DATABASE = "kairos_production_evidence_lifecycle_ci_000000000001"
SIMULATOR_DATABASE = "kairos_sim_controller_ci_000000000001"
OWNER_ROLE = "kairos_claim_owner_ci"
RUNTIME_ROLE = "kairos_claim_runtime_ci"
OPERATOR_WRITER_ROLE = "kairos_operator_writer_ci"
RISK_WRITER_ROLE = "kairos_risk_writer_ci"
EXPOSURE_WRITER_ROLE = "kairos_exposure_writer_ci"
RECONCILER_ROLE = "kairos_terminal_reconciler_ci"
OWNER_PASSWORD = "claims-owner-ci-public-test-only"
RUNTIME_PASSWORD = "claims-runtime-ci-public-test-only"
OPERATOR_WRITER_PASSWORD = "operator-writer-ci-public-test-only"
RISK_WRITER_PASSWORD = "risk_writer_ci_public_test_only"
EXPOSURE_WRITER_PASSWORD = "exposure-writer-ci-public-test-only"
RECONCILER_PASSWORD = "terminal-reconciler-ci-public-test-only"
ADMIN_DSN = "postgresql://kairos:kairos_test@localhost:5432/kairos_execution_test_000000000001"


def github_environment_values(
    database_uuid: str,
    lifecycle_database_uuid: str,
    *,
    created_databases: frozenset[str],
) -> dict[str, str]:
    """Return test settings only after each isolated target was created."""
    if not {DATABASE, LIFECYCLE_DATABASE, SIMULATOR_DATABASE}.issubset(created_databases):
        raise ValueError("test database URLs require successful fresh database creation")
    try:
        base_uuid, lifecycle_uuid = UUID(database_uuid), UUID(lifecycle_database_uuid)
    except (TypeError, ValueError):
        raise ValueError("separate valid database UUIDs are required") from None
    if base_uuid.int == 0 or lifecycle_uuid.int == 0 or base_uuid == lifecycle_uuid:
        raise ValueError("claims and lifecycle databases require distinct nonzero UUIDs")
    return {
        "KAIROS_PRODUCTION_CLAIMS_TEST_PROVISION": "1",
        "KAIROS_PRODUCTION_CLAIMS_TEST_OWNER_DSN": (
            f"postgresql://{OWNER_ROLE}:{OWNER_PASSWORD}@localhost:5432/{DATABASE}"
        ),
        "KAIROS_PRODUCTION_CLAIMS_TEST_RUNTIME_DSN": (
            f"postgresql://{RUNTIME_ROLE}:{RUNTIME_PASSWORD}@localhost:5432/{DATABASE}"
        ),
        "KAIROS_PRODUCTION_CLAIMS_TEST_DATABASE": DATABASE,
        "KAIROS_PRODUCTION_CLAIMS_TEST_DATABASE_UUID": database_uuid,
        "KAIROS_PRODUCTION_CLAIMS_TEST_POLICY_NAMESPACE": f"ci-claims:{database_uuid}",
        "KAIROS_PRODUCTION_CLAIMS_TEST_OWNER_ROLE": OWNER_ROLE,
        "KAIROS_PRODUCTION_CLAIMS_TEST_RUNTIME_ROLE": RUNTIME_ROLE,
        "KAIROS_PRODUCTION_STATE_TEST_OPERATOR_WRITER_DSN": (
            f"postgresql://{OPERATOR_WRITER_ROLE}:{OPERATOR_WRITER_PASSWORD}@localhost:5432/{DATABASE}"
        ),
        "KAIROS_PRODUCTION_STATE_TEST_RISK_WRITER_DSN": (
            f"postgresql://{RISK_WRITER_ROLE}:{RISK_WRITER_PASSWORD}@localhost:5432/{DATABASE}"
        ),
        "KAIROS_PRODUCTION_STATE_TEST_EXPOSURE_WRITER_DSN": (
            f"postgresql://{EXPOSURE_WRITER_ROLE}:{EXPOSURE_WRITER_PASSWORD}@localhost:5432/{DATABASE}"
        ),
        "KAIROS_PRODUCTION_STATE_TEST_OPERATOR_WRITER_ROLE": OPERATOR_WRITER_ROLE,
        "KAIROS_PRODUCTION_STATE_TEST_RISK_WRITER_ROLE": RISK_WRITER_ROLE,
        "KAIROS_PRODUCTION_STATE_TEST_EXPOSURE_WRITER_ROLE": EXPOSURE_WRITER_ROLE,
        "KAIROS_PRODUCTION_STATE_TEST_PROVISION": "1",
        "KAIROS_PRODUCTION_LIFECYCLE_TEST_PROVISION": "1",
        "KAIROS_PRODUCTION_LIFECYCLE_TEST_OWNER_DSN": (
            f"postgresql://{OWNER_ROLE}:{OWNER_PASSWORD}@localhost:5432/{LIFECYCLE_DATABASE}"
        ),
        "KAIROS_PRODUCTION_LIFECYCLE_TEST_RUNTIME_DSN": (
            f"postgresql://{RUNTIME_ROLE}:{RUNTIME_PASSWORD}@localhost:5432/{LIFECYCLE_DATABASE}"
        ),
        "KAIROS_PRODUCTION_LIFECYCLE_TEST_DATABASE": LIFECYCLE_DATABASE,
        "KAIROS_PRODUCTION_LIFECYCLE_TEST_DATABASE_UUID": lifecycle_database_uuid,
        "KAIROS_PRODUCTION_LIFECYCLE_TEST_POLICY_NAMESPACE": (f"ci-lifecycle:{lifecycle_database_uuid}"),
        "KAIROS_PRODUCTION_LIFECYCLE_TEST_OWNER_ROLE": OWNER_ROLE,
        "KAIROS_PRODUCTION_LIFECYCLE_TEST_RUNTIME_ROLE": RUNTIME_ROLE,
        "KAIROS_PRODUCTION_LIFECYCLE_TEST_OPERATOR_WRITER_DSN": (
            f"postgresql://{OPERATOR_WRITER_ROLE}:{OPERATOR_WRITER_PASSWORD}"
            f"@localhost:5432/{LIFECYCLE_DATABASE}"
        ),
        "KAIROS_PRODUCTION_LIFECYCLE_TEST_RISK_WRITER_DSN": (
            f"postgresql://{RISK_WRITER_ROLE}:{RISK_WRITER_PASSWORD}@localhost:5432/{LIFECYCLE_DATABASE}"
        ),
        "KAIROS_PRODUCTION_LIFECYCLE_TEST_EXPOSURE_WRITER_DSN": (
            f"postgresql://{EXPOSURE_WRITER_ROLE}:{EXPOSURE_WRITER_PASSWORD}"
            f"@localhost:5432/{LIFECYCLE_DATABASE}"
        ),
        "KAIROS_PRODUCTION_LIFECYCLE_TEST_OPERATOR_WRITER_ROLE": OPERATOR_WRITER_ROLE,
        "KAIROS_PRODUCTION_LIFECYCLE_TEST_RISK_WRITER_ROLE": RISK_WRITER_ROLE,
        "KAIROS_PRODUCTION_LIFECYCLE_TEST_EXPOSURE_WRITER_ROLE": EXPOSURE_WRITER_ROLE,
        "KAIROS_PRODUCTION_LIFECYCLE_TEST_RECONCILER_DSN": (
            f"postgresql://{RECONCILER_ROLE}:{RECONCILER_PASSWORD}@localhost:5432/{LIFECYCLE_DATABASE}"
        ),
        "KAIROS_PRODUCTION_LIFECYCLE_TEST_RECONCILER_ROLE": RECONCILER_ROLE,
        "KAIROS_SIM_CONTROLLER_DATABASE_URL": (
            f"postgresql://kairos:kairos_test@localhost:5432/{SIMULATOR_DATABASE}"
        ),
    }


def bootstrap_sql() -> tuple[str, ...]:
    """Fixed DDL for a fresh, ephemeral service; no caller-controlled identifiers."""
    return (
        f"CREATE ROLE {OWNER_ROLE} LOGIN PASSWORD '{OWNER_PASSWORD}' NOSUPERUSER NOCREATEDB "
        "NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT",
        f"CREATE ROLE {RUNTIME_ROLE} LOGIN PASSWORD '{RUNTIME_PASSWORD}' NOSUPERUSER NOCREATEDB "
        "NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT",
        f"CREATE ROLE {OPERATOR_WRITER_ROLE} LOGIN PASSWORD '{OPERATOR_WRITER_PASSWORD}' NOSUPERUSER "
        "NOCREATEDB "
        "NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT",
        f"CREATE ROLE {RISK_WRITER_ROLE} LOGIN PASSWORD '{RISK_WRITER_PASSWORD}' NOSUPERUSER "
        "NOCREATEDB "
        "NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT",
        f"CREATE ROLE {EXPOSURE_WRITER_ROLE} LOGIN PASSWORD '{EXPOSURE_WRITER_PASSWORD}' NOSUPERUSER "
        "NOCREATEDB "
        "NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT",
        f"CREATE ROLE {RECONCILER_ROLE} LOGIN PASSWORD '{RECONCILER_PASSWORD}' NOSUPERUSER NOCREATEDB "
        "NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT",
        f"CREATE DATABASE {DATABASE} OWNER {OWNER_ROLE}",
        f"REVOKE CONNECT ON DATABASE {DATABASE} FROM PUBLIC",
        f"GRANT CONNECT ON DATABASE {DATABASE} TO {OWNER_ROLE}, {RUNTIME_ROLE}, {OPERATOR_WRITER_ROLE}, "
        f"{RISK_WRITER_ROLE}, {EXPOSURE_WRITER_ROLE}",
        f"CREATE DATABASE {LIFECYCLE_DATABASE} OWNER {OWNER_ROLE}",
        f"REVOKE CONNECT ON DATABASE {LIFECYCLE_DATABASE} FROM PUBLIC",
        f"GRANT CONNECT ON DATABASE {LIFECYCLE_DATABASE} TO {OWNER_ROLE}, {RUNTIME_ROLE}, "
        f"{OPERATOR_WRITER_ROLE}, {RISK_WRITER_ROLE}, {EXPOSURE_WRITER_ROLE}, {RECONCILER_ROLE}",
        f"CREATE DATABASE {SIMULATOR_DATABASE} OWNER kairos",
        f"REVOKE CONNECT ON DATABASE {SIMULATOR_DATABASE} FROM PUBLIC",
        f"GRANT CONNECT ON DATABASE {SIMULATOR_DATABASE} TO kairos",
    )


def validate_ci_environment(environ: Mapping[str, str]) -> str:
    """Fail closed unless invoked by the exact intended GitHub Actions job."""
    expected = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": "Kairos-cryptoAI/kairos-execution-engine",
        "GITHUB_JOB": "execution-journal-integration",
        "KAIROS_PRODUCTION_CLAIMS_CI_BOOTSTRAP": "1",
    }
    if any(environ.get(name) != value for name, value in expected.items()):
        raise SystemExit("synthetic claims bootstrap is restricted to its exact GitHub Actions job")
    github_env = environ.get("GITHUB_ENV")
    if not github_env:
        raise SystemExit("GitHub Actions environment output is unavailable")
    return github_env


async def bootstrap() -> None:
    # Import only after hard gates so this cannot be mistaken for a general
    # provisioning utility or invoked from a developer's local environment.
    github_env = validate_ci_environment(os.environ)

    import asyncpg

    try:
        connection = await asyncpg.connect(ADMIN_DSN, timeout=5, command_timeout=5)
        try:
            identity = await connection.fetchrow("SELECT current_database() AS db, current_user AS role")
            if identity is None or identity["db"] != "kairos_execution_test_000000000001":
                raise RuntimeError("unexpected synthetic CI bootstrap identity")
            if identity["role"] != "kairos":
                raise RuntimeError("unexpected synthetic CI bootstrap identity")
            created_databases: set[str] = set()
            for statement in bootstrap_sql():
                await connection.execute(statement)
                if statement == f"CREATE DATABASE {DATABASE} OWNER {OWNER_ROLE}":
                    created_databases.add(DATABASE)
                elif statement == f"CREATE DATABASE {LIFECYCLE_DATABASE} OWNER {OWNER_ROLE}":
                    created_databases.add(LIFECYCLE_DATABASE)
                elif statement == f"CREATE DATABASE {SIMULATOR_DATABASE} OWNER kairos":
                    created_databases.add(SIMULATOR_DATABASE)
        finally:
            await connection.close()
    except Exception:
        # Never expose a DSN, password, or raw connection/server diagnostic.
        raise SystemExit("fresh synthetic claims database bootstrap failed") from None

    values = github_environment_values(
        str(uuid4()),
        str(uuid4()),
        created_databases=frozenset(created_databases),
    )
    with Path(github_env).open("a", encoding="utf-8", newline="\n") as env_file:
        for name, value in values.items():
            if "\n" in name or "\n" in value or "\r" in value:
                raise SystemExit("invalid GitHub environment value")
            env_file.write(f"{name}={value}\n")


if __name__ == "__main__":
    asyncio.run(bootstrap())
