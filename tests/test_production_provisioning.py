"""Owner provisioning of an isolated production-evidence database."""

from __future__ import annotations

import os
from pathlib import Path

import asyncpg  # type: ignore[import-untyped]  # Upstream ships no typing marker/stubs.
import pytest

from kairos_execution.production_provisioning import (
    ROLE_NAMES,
    ProvisionedDatabaseV1,
    ProvisioningError,
    provision_production_database,
)
from kairos_execution.production_readiness import ProductionContextV1

CONTEXT = ProductionContextV1(
    remote_account_id="provisioning-selfcheck-account",
    adaptive_system_id="hourly_trend_candidates_v1",
    frozen_policy_sha256="a" * 64,
    source_set_sha256="b" * 64,
)
SCHEMAS = {
    "kairos_production_accounting_v1",
    "kairos_production_evidence_v1",
    "kairos_production_reconciliation_v2",
    "kairos_production_state_v1",
}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("dsn", "suffix", "message"),
    [
        ("postgresql://a:b@db.example.com:5432/postgres", None, "only a local"),
        ("mysql://a:b@127.0.0.1:5432/postgres", None, "only a local"),
        ("postgresql://a:b@127.0.0.1/postgres", None, "explicit port"),
        ("postgresql://a:b@127.0.0.1:5432/postgres?sslmode=disable", None, "explicit port"),
        ("postgresql://a:b@127.0.0.1:5432/postgres", "Short", "suffix"),
    ],
)
async def test_refuses_before_connecting(tmp_path, dsn, suffix, message):
    with pytest.raises(ProvisioningError, match=message):
        await provision_production_database(
            dsn, context=CONTEXT, secrets_dir=tmp_path, policy_namespace="selfcheck", suffix=suffix
        )


@pytest.mark.asyncio
async def test_refuses_to_reuse_existing_secret_files(tmp_path):
    suffix = "existingsecret01"
    (tmp_path / f"kairos_production_evidence_{suffix}.owner.password").write_text("x", encoding="utf-8")
    with pytest.raises(ProvisioningError, match="already exist"):
        await provision_production_database(
            "postgresql://a:b@127.0.0.1:5432/postgres",
            context=CONTEXT,
            secrets_dir=tmp_path,
            policy_namespace="selfcheck",
            suffix=suffix,
        )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_provisions_every_schema_with_separate_roles(tmp_path):
    dsn_file = os.getenv("KAIROS_PRODUCTION_PROVISION_TEST_ADMIN_DSN_FILE")
    if not dsn_file:
        pytest.skip("a local administrator DSN file for disposable provisioning is not configured")
    admin_dsn = Path(dsn_file).read_text(encoding="utf-8").strip()
    manifest = await provision_production_database(
        admin_dsn, context=CONTEXT, secrets_dir=tmp_path / "secrets", policy_namespace="selfcheck"
    )
    try:
        assert set(manifest.roles) == set(ROLE_NAMES) and len(set(manifest.roles.values())) == len(ROLE_NAMES)
        assert ProvisionedDatabaseV1(**_fields(manifest)) == manifest
        owner = await asyncpg.connect(manifest.dsn("owner"), timeout=5)
        try:
            schemas = {
                row["nspname"]
                for row in await owner.fetch("SELECT nspname FROM pg_namespace WHERE nspname LIKE 'kairos_%'")
            }
            assert SCHEMAS <= schemas
        finally:
            await owner.close()
        runtime = await asyncpg.connect(manifest.dsn("runtime"), timeout=5)
        try:
            assert await runtime.fetchval("SELECT count(*) FROM public.event_audit") == 0
            with pytest.raises(asyncpg.InsufficientPrivilegeError):
                await runtime.execute("CREATE TABLE public.not_allowed(x int)")
        finally:
            await runtime.close()
    finally:
        admin = await asyncpg.connect(admin_dsn, timeout=5)
        try:
            await admin.execute(f'DROP DATABASE IF EXISTS "{manifest.database}" WITH (FORCE)')
            for role in manifest.roles.values():
                await admin.execute(f'DROP ROLE IF EXISTS "{role}"')
        finally:
            await admin.close()


def _fields(manifest: ProvisionedDatabaseV1) -> dict:
    return {name: getattr(manifest, name) for name in ProvisionedDatabaseV1.__dataclass_fields__}
