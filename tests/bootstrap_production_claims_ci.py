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
from uuid import uuid4

DATABASE = "kairos_production_evidence_ci_000000000001"
OWNER_ROLE = "kairos_claim_owner_ci"
RUNTIME_ROLE = "kairos_claim_runtime_ci"
OWNER_PASSWORD = "claims-owner-ci-public-test-only"
RUNTIME_PASSWORD = "claims-runtime-ci-public-test-only"
ADMIN_DSN = "postgresql://kairos:kairos_test@localhost:5432/kairos_execution_test_000000000001"


def github_environment_values(database_uuid: str) -> dict[str, str]:
    """Return the opt-in test settings; values contain synthetic CI credentials only."""
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
    }


def bootstrap_sql() -> tuple[str, ...]:
    """Fixed DDL for a fresh, ephemeral service; no caller-controlled identifiers."""
    return (
        f"CREATE ROLE {OWNER_ROLE} LOGIN PASSWORD '{OWNER_PASSWORD}' NOSUPERUSER NOCREATEDB "
        "NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT",
        f"CREATE ROLE {RUNTIME_ROLE} LOGIN PASSWORD '{RUNTIME_PASSWORD}' NOSUPERUSER NOCREATEDB "
        "NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT",
        f"CREATE DATABASE {DATABASE} OWNER {OWNER_ROLE}",
        f"REVOKE CONNECT ON DATABASE {DATABASE} FROM PUBLIC",
        f"GRANT CONNECT ON DATABASE {DATABASE} TO {OWNER_ROLE}, {RUNTIME_ROLE}",
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
            for statement in bootstrap_sql():
                await connection.execute(statement)
        finally:
            await connection.close()
    except Exception:
        # Never expose a DSN, password, or raw connection/server diagnostic.
        raise SystemExit("fresh synthetic claims database bootstrap failed") from None

    values = github_environment_values(str(uuid4()))
    with Path(github_env).open("a", encoding="utf-8", newline="\n") as env_file:
        for name, value in values.items():
            if "\n" in name or "\n" in value or "\r" in value:
                raise SystemExit("invalid GitHub environment value")
            env_file.write(f"{name}={value}\n")


if __name__ == "__main__":
    asyncio.run(bootstrap())
