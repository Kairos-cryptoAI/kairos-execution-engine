"""Explicit database-owner operations for the persistent production operator stop.

No startup path calls these operations. An upgrade changes only a recognized
operator guard; resume consumes one exact KILLED command and leaves DISARMED.
Neither operation signs an arm, starts a host, nor sends a venue request.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
from pathlib import Path
from typing import TypedDict
from uuid import UUID

import asyncpg  # type: ignore[import-untyped]

from .production_provisioning import ProvisionedDatabaseV1
from .production_readiness import ProductionContextV1
from .production_state import resume_operator_after_kill_async, upgrade_operator_control_guard


class _OwnerAuthority(TypedDict):
    expected_database: str
    database_uuid: UUID
    policy_namespace: str
    context: ProductionContextV1
    owner_role: str


async def run_owner_operation(args: argparse.Namespace) -> dict[str, object]:
    if args.operation == "resume" and (
        type(args.expected_version) is not int
        or args.expected_version <= 0
        or not isinstance(args.expected_command_sha256, str)
        or re.fullmatch(r"[a-f0-9]{64}", args.expected_command_sha256) is None
    ):
        raise ValueError("an exact positive KILLED version and command digest are required")
    manifest = ProvisionedDatabaseV1.load(args.manifest)
    if manifest.host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("owner operations require the provisioned local database")
    authority: _OwnerAuthority = {
        "expected_database": manifest.database,
        "database_uuid": UUID(manifest.database_uuid),
        "policy_namespace": manifest.policy_namespace,
        "context": ProductionContextV1.model_validate(manifest.context),
        "owner_role": manifest.roles["owner"],
    }
    if args.operation == "upgrade-guard":
        connection = await asyncpg.connect(manifest.dsn("owner"), timeout=5, command_timeout=5)
        try:
            await upgrade_operator_control_guard(connection, **authority)
        finally:
            await connection.close()
        return {"outcome": "GUARD_UPGRADED"}
    pool = await asyncpg.create_pool(
        manifest.dsn("owner"), min_size=1, max_size=1, timeout=5, command_timeout=5
    )
    try:
        resumed = await resume_operator_after_kill_async(
            pool,
            **authority,
            expected_version=args.expected_version,
            expected_command_sha256=args.expected_command_sha256,
        )
    finally:
        await pool.close()
    return {
        "outcome": "DISARMED",
        "version": resumed.version,
        "command_sha256": resumed.command_sha256,
        "previous_command_sha256": resumed.previous_command_sha256,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m kairos_execution.production_operator", description=__doc__
    )
    commands = parser.add_subparsers(dest="operation", required=True)
    upgrade = commands.add_parser("upgrade-guard", help="owner-only upgrade of a known operator guard")
    upgrade.add_argument("--manifest", type=Path, required=True)
    resume = commands.add_parser("resume", help="owner-only KILLED to DISARMED, never directly ARMED")
    resume.add_argument("--manifest", type=Path, required=True)
    resume.add_argument("--expected-version", type=int, required=True)
    resume.add_argument("--expected-command-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        answer = asyncio.run(run_owner_operation(args))
    except Exception:
        # Connection and file errors can contain a DSN or private deployment path.
        print(json.dumps({"outcome": "REFUSED_OR_UNRESOLVED", "detail": "owner operation did not complete"}))
        return 2
    print(json.dumps(answer))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
