"""Opt-in local Docker provisioning exercise; no exchange requests or keys."""

import asyncio
import hashlib
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID, uuid4

import asyncpg
import pytest

from kairos_execution import auth_observation_cli as cli
from kairos_execution.auth_audit import AuthAuditJournal, authorize_one_auth_followup
from kairos_execution.auth_observation_cli import SOURCE_NAMES, _provision_claims
from kairos_execution.auth_orchestration import _write_new_private_file
from kairos_execution.production_claims import PostgresProductionClaims
from kairos_execution.production_readiness import ProductionContextV1, canonical_digest
from kairos_execution.protected_files import create_private_directory


@pytest.mark.asyncio
async def test_dedicated_claims_roles_are_durable_and_one_use(tmp_path, monkeypatch):
    if os.getenv("KAIROS_AUTH_ORCHESTRATION_DOCKER_TEST") != "1":
        pytest.skip("explicit opt-in for a new local Docker container and named volume required")
    container = "kairos-auth-pytest-" + uuid4().hex[:12]
    volume = container + "-data"
    assert (
        subprocess.run(
            ["docker", "container", "inspect", container], capture_output=True, timeout=10
        ).returncode
        != 0
    )
    assert (
        subprocess.run(["docker", "volume", "inspect", volume], capture_output=True, timeout=10).returncode
        != 0
    )
    runtime = tmp_path / "runtime"
    create_private_directory(runtime)
    pool = None
    try:
        info = await _provision_claims(runtime, container)
        context = ProductionContextV1(
            remote_account_id="synthetic-account",
            adaptive_system_id="synthetic-auth-observer",
            frozen_policy_sha256="1" * 64,
            source_set_sha256="2" * 64,
        )
        node = runtime / "synthetic-node.bin"
        _write_new_private_file(node, b"synthetic-node")
        source_hashes = {
            name: hashlib.sha256(Path(cli.__file__).with_name(name).read_bytes()).hexdigest()
            for name in SOURCE_NAMES
        }
        source_hashes["auth_observation_cli.py"] = "0" * 64
        plan = {
            "context": context.model_dump(mode="json"),
            "claims": info,
            "source_hashes": source_hashes,
            "node": str(node),
            "sidecar": "synthetic",
            "sidecar_hashes": {},
            "node_sha256": hashlib.sha256(node.read_bytes()).hexdigest(),
        }
        original = json.dumps(plan, sort_keys=True).encode()
        _write_new_private_file(runtime / "plan.json", original)
        monkeypatch.setattr(cli, "_sidecar_fingerprint", lambda _path: {})
        await cli.revise_preauth_plan(
            SimpleNamespace(runtime_dir=str(runtime), plan_sha256=hashlib.sha256(original).hexdigest())
        )
        revised = json.loads((runtime / "plan.json").read_bytes())
        assert revised["preauth_revision"]["claims_before_revision"] == 0
        assert list(runtime.glob("plan.pre-auth-*.json"))[0].read_bytes() == original
        context = ProductionContextV1.model_validate(revised["context"])
        dsn = (runtime / "runtime-dsn.txt").read_text().strip()
        pool = await asyncpg.create_pool(dsn, min_size=1, max_size=8)

        def claims():
            return PostgresProductionClaims(
                pool,
                expected_database=info["database"],
                database_uuid=UUID(info["database_uuid"]),
                policy_namespace=info["namespace"],
                runtime_role=info["runtime_role"],
                context=context,
            )

        writer = claims()
        results = await asyncio.gather(
            *(writer.claim("MANUAL_NONCE", "synthetic-auth", "one-attempt", "3" * 64) for _ in range(8))
        )
        assert results.count(True) == 1 and results.count(False) == 7
        await pool.close()
        pool = await asyncpg.create_pool(dsn, min_size=1, max_size=2)
        assert await claims().claim("MANUAL_NONCE", "synthetic-auth", "one-attempt", "3" * 64) is False
        revised["source_hashes"]["auth_observation_cli.py"] = "0" * 64
        encoded = json.dumps(revised).encode()
        (runtime / "plan.json").write_bytes(encoded)
        with pytest.raises(ValueError, match="prior attempt"):
            await cli.revise_preauth_plan(
                SimpleNamespace(runtime_dir=str(runtime), plan_sha256=hashlib.sha256(encoded).hexdigest())
            )
        wallet = "synthetic-wallet"
        old_sha = canonical_digest(context)
        attempt_sha = hashlib.sha256((old_sha + "\n" + wallet).encode()).hexdigest()
        assert await claims().claim("MANUAL_NONCE", "siwe-session:" + old_sha, "one-attempt", attempt_sha)
        assert await claims().claim("MANUAL_NONCE", "siwe:" + "4" * 64, "siwe:" + "5" * 64, "6" * 64)
        revised["wallet"] = wallet
        prior_bytes = json.dumps(revised).encode()
        (runtime / "plan.json").write_bytes(prior_bytes)
        prior_plan_sha = hashlib.sha256(prior_bytes).hexdigest()
        await cli.prepare_auth_followup(
            SimpleNamespace(
                runtime_dir=str(runtime),
                prior_plan_sha256=prior_plan_sha,
                operator_reference="synthetic-operator-approval",
                acknowledge_prior_unknown=True,
            )
        )
        followup_bytes = (runtime / "followup-plan.json").read_bytes()
        followup_plan = json.loads(followup_bytes)
        assert (runtime / "plan.json").read_bytes() == prior_bytes
        assert followup_plan["prior_unknown"]["outcome"] == "UNKNOWN"
        next_context = ProductionContextV1.model_validate(followup_plan["context"])
        next_claims = PostgresProductionClaims(
            pool,
            expected_database=info["database"],
            database_uuid=UUID(info["database_uuid"]),
            policy_namespace=info["namespace"],
            runtime_role=info["runtime_role"],
            context=next_context,
        )

        async def followup():
            try:
                await authorize_one_auth_followup(
                    claims=next_claims,
                    prior_context=context,
                    current_context=next_context,
                    prior_plan_sha256=prior_plan_sha,
                    followup_plan_sha256=hashlib.sha256(followup_bytes).hexdigest(),
                    expected_wallet_address=wallet,
                    operator_reference="synthetic-operator-approval",
                )
                return True
            except PermissionError:
                return False

        approvals = await asyncio.gather(*(followup() for _ in range(8)))
        assert approvals.count(True) == 1 and approvals.count(False) == 7
        journal = AuthAuditJournal(next_claims)
        await journal.record("SIGN_STARTED")
        await journal.record("AUTH_HTTP", http_status=201)
        async with pool.acquire() as connection:
            prior_rows = await connection.fetchval(
                "SELECT count(*) FROM kairos_production_evidence_v1.claims WHERE context_sha256=$1",
                old_sha,
            )
            assert prior_rows == 3
            stages = await connection.fetch(
                "SELECT identity FROM kairos_production_evidence_v1.claims WHERE namespace=$1",
                "auth-stage:" + canonical_digest(next_context),
            )
            assert {row["identity"] for row in stages} == {"SIGN_STARTED", "AUTH_HTTP:201"}
    finally:
        if pool is not None:
            await pool.close()
        subprocess.run(["docker", "stop", container], capture_output=True, timeout=30)
        subprocess.run(["docker", "rm", container], capture_output=True, timeout=30)
        subprocess.run(["docker", "volume", "rm", volume], capture_output=True, timeout=30)
