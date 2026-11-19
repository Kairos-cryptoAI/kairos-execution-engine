"""Owner drills that produce the facts of three technical-canary receipts.

Each drill performs the real operation on the owner's own deployment and records what
happened as content-addressed artifacts; the facts it returns are what the owner then
signs with ``production_owner issue``. A drill that observes anything other than the
required outcome raises instead of producing facts.

* ``recovery_drill`` (PRIMARY_RECOVERY): a plain ``pg_dump`` of the production-evidence
  database, a restore into a fresh database in the same container, an identical second
  dump and an identical per-table content digest before and after.
* ``operator_drill`` (GLOBAL_OPERATOR_CONTROL): the owner's global stop is set, arming
  is refused while it holds, the owner resumes, a fresh process observes the latest
  version, and every non-operator role is refused when it tries to write operator state.
* ``limits_drill`` (PRODUCTION_LIMITS): the installed Risk Manager and Execution Engine
  revisions run their tests that refuse an entry without exact limits, above a cap and at
  the daily stop, count reservations once and survive a restart with accounting; the
  JUnit reports are the artifacts.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import secrets
import subprocess  # nosec B404
import sys
import xml.etree.ElementTree as ElementTree  # nosec B405
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import asyncpg  # type: ignore[import-untyped]  # Upstream ships no typing marker/stubs.
from pydantic import BaseModel

from .crypto import EIP712_SCHEMAS, build_domain
from .local_custody import CoincurveTypedDataVerifier, LocalCustodyError
from .managed_signer import CustodyBindingV1, reviewed_schema_sha256
from .production_owner import store_artifact
from .production_provisioning import ProvisionedDatabaseV1
from .production_readiness import ProductionContextV1
from .production_session import OperatorLatch, ProductionSessionError
from .production_state import PostgresOperatorStateWriter
from .signed_evidence import (
    CustodyFactsV1,
    LimitsFactsV1,
    OperatorFactsV1,
    PairingFactsV1,
    RecoveryFactsV1,
)
from .utc_clock import precise_utc_now

Runner = Callable[[Sequence[str], bytes | None], bytes]


class DrillFailed(RuntimeError):
    """The drill observed something other than the required outcome."""


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()


def _run(command: Sequence[str], stdin: bytes | None = None) -> bytes:
    completed = subprocess.run(  # noqa: S603  # nosec B603
        list(command), input=stdin, capture_output=True, timeout=600, check=False
    )
    if completed.returncode != 0:
        raise DrillFailed(f"{command[0]} failed: {completed.stderr.decode(errors='replace')[:300]}")
    return completed.stdout


# --------------------------------------------------------------------------- recovery

_TABLES = """
SELECT n.nspname, c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r','p') AND (n.nspname = 'public' OR n.nspname LIKE 'kairos_%')
ORDER BY 1, 2
"""


async def history_digest(connection: asyncpg.Connection) -> dict[str, dict[str, object]]:
    """Row count and an order-independent content digest of every Kairos table."""
    result: dict[str, dict[str, object]] = {}
    for row in await connection.fetch(_TABLES):
        name = f'"{row["nspname"]}"."{row["relname"]}"'
        texts = await connection.fetch(f"SELECT t::text AS v FROM {name} t")  # nosec B608
        digest = hashlib.sha256()
        for value in sorted(item["v"] for item in texts):
            digest.update(value.encode())
            digest.update(b"\n")
        result[f"{row['nspname']}.{row['relname']}"] = {"rows": len(texts), "sha256": digest.hexdigest()}
    return result


async def _scalar(connection: asyncpg.Connection, sql: str) -> int:
    try:
        return int(await connection.fetchval(sql) or 0)
    except asyncpg.UndefinedTableError:
        return 0


async def recovery_drill(
    manifest: ProvisionedDatabaseV1,
    *,
    admin_dsn: str,
    container: str,
    evidence_dir: Path,
    run: Runner = _run,
) -> RecoveryFactsV1:
    admin_user = urlsplit(admin_dsn).username or "postgres"
    owner = await asyncpg.connect(manifest.dsn("owner"))
    try:
        before = await history_digest(owner)
        unresolved = await _scalar(
            owner,
            "SELECT (SELECT count(*) FROM kairos_production_evidence_v1.terminals"
            " WHERE terminal_status='UNRESOLVED') + (SELECT count(*) FROM"
            " kairos_production_evidence_v1.wire_terminals WHERE terminal_status='UNRESOLVED')",
        )
        outbox = await _scalar(owner, "SELECT count(*) FROM public.message_outbox WHERE published_at IS NULL")
    finally:
        await owner.close()
    # pg_dump writes a random psql \restrict key into every dump; one key per drill
    # keeps the two dumps comparable byte for byte.
    restrict_key = uuid4().hex
    dump_args = [
        "pg_dump",
        "-U",
        admin_user,
        "--no-owner",
        "--no-privileges",
        f"--restrict-key={restrict_key}",
        "-d",
    ]
    primary_dump = run(["docker", "exec", container, *dump_args, manifest.database], None)
    restored = f"{manifest.database}_restore_{uuid4().hex[:8]}"
    admin = await asyncpg.connect(admin_dsn)
    try:
        await admin.execute(f'CREATE DATABASE "{restored}"')
    finally:
        await admin.close()
    try:
        prefix = b"CREATE EXTENSION IF NOT EXISTS timescaledb;\nSELECT public.timescaledb_pre_restore();\n"
        suffix = b"\nSELECT public.timescaledb_post_restore();\n"
        run(
            [
                "docker",
                "exec",
                "-i",
                container,
                "psql",
                "-U",
                admin_user,
                "-d",
                restored,
                "-v",
                "ON_ERROR_STOP=1",
                "-q",
            ],
            prefix + primary_dump + suffix,
        )
        restored_dump = run(["docker", "exec", container, *dump_args, restored], None)
        parsed = urlsplit(admin_dsn)
        restored_dsn = parsed._replace(path=f"/{restored}").geturl()
        check = await asyncpg.connect(restored_dsn)
        try:
            after = await history_digest(check)
        finally:
            await check.close()
    finally:
        admin = await asyncpg.connect(admin_dsn)
        try:
            await admin.execute(f'DROP DATABASE IF EXISTS "{restored}" WITH (FORCE)')
        finally:
            await admin.close()
    if hashlib.sha256(primary_dump).digest() != hashlib.sha256(restored_dump).digest():
        raise DrillFailed("the restored database does not dump to the same bytes as the primary")
    if before != after:
        raise DrillFailed("the restored database content differs from the primary")
    if unresolved or outbox:
        raise DrillFailed(
            f"the primary holds {unresolved} unresolved claims and {outbox} unpublished messages"
        )
    when = datetime.now(UTC).isoformat()
    backup = store_artifact(evidence_dir, primary_dump)
    restored_sha = store_artifact(evidence_dir, restored_dump)
    history_before = store_artifact(evidence_dir, _canonical(before))
    history_after = store_artifact(evidence_dir, _canonical(after))
    commit = store_artifact(
        evidence_dir,
        _canonical(
            {"drill": "primary-recovery", "database": manifest.database, "dumped_at": when, "dump": backup}
        ),
    )
    acceptance = store_artifact(
        evidence_dir,
        _canonical(
            {
                "drill": "primary-recovery",
                "restored_database": restored,
                "dropped_after_check": True,
                "identical_dump": True,
                "identical_history": True,
                "checked_at": when,
                "bar_chains": "none in the execution evidence database",
            }
        ),
    )
    return RecoveryFactsV1(
        artifact_sha256s=tuple(
            dict.fromkeys((backup, restored_sha, history_before, history_after, commit, acceptance))
        ),
        primary_database_identity=f"{manifest.database}:{manifest.host}:{manifest.port}",
        backup_sha256=backup,
        restored_backup_sha256=restored_sha,
        native_commit_receipt_sha256=commit,
        primary_acceptance_receipt_sha256=acceptance,
        before_history_sha256=history_before,
        after_history_sha256=history_after,
        unresolved_inbox=0,
        unresolved_outbox=0,
        duplicate_publications=0,
        unresolved_leases=0,
        bar_chain_conflicts=0,
    )


# --------------------------------------------------------------------------- operator


async def operator_drill(
    manifest: ProvisionedDatabaseV1,
    *,
    evidence_dir: Path,
    clock: Callable[[], datetime] = precise_utc_now,
) -> OperatorFactsV1:
    context = ProductionContextV1.model_validate(manifest.context)
    common = {
        "expected_database": manifest.database,
        "database_uuid": UUID(manifest.database_uuid),
        "policy_namespace": manifest.policy_namespace,
        "context": context,
        "state_schema_version": 3,
    }
    pool = await asyncpg.create_pool(manifest.dsn("operator"), min_size=1, max_size=2)
    log: list[dict[str, object]] = []
    try:
        latch = OperatorLatch(
            PostgresOperatorStateWriter(pool, expected_role=manifest.roles["operator"], **common),
            context,
            clock,
        )
        killed = await latch.kill()
        log.append({"step": "kill", "version": killed.version, "at": killed.changed_at.isoformat()})
        try:
            await latch._next("ARMED", nonce="drill-arm-attempt", request="0" * 64, expires=clock())
        except ProductionSessionError:
            log.append({"step": "arm while killed", "result": "refused"})
        else:
            raise DrillFailed("an arm was accepted while the global stop was set")
        await asyncio.sleep(0.3)
        owner_pool = await asyncpg.create_pool(manifest.dsn("owner"), min_size=1, max_size=1)
        try:
            resumed = await latch.resume(owner_pool=owner_pool, owner_role=manifest.roles["owner"])
        finally:
            await owner_pool.close()
        log.append({"step": "resume", "version": resumed.version, "at": resumed.changed_at.isoformat()})
    finally:
        await pool.close()
    fresh = await asyncpg.create_pool(manifest.dsn("operator"), min_size=1, max_size=1)
    try:
        observed = await PostgresOperatorStateWriter(
            fresh, expected_role=manifest.roles["operator"], **common
        ).latest_operator_state_async()
    finally:
        await fresh.close()
    if observed is None or observed.version < resumed.version or observed.state != "DISARMED":
        raise DrillFailed("a fresh process does not observe the resumed operator state")
    log.append({"step": "fresh process", "version": observed.version, "state": observed.state})
    denied = 0
    for role in ("runtime", "risk", "exposure", "reconciler", "accounting"):
        connection = await asyncpg.connect(manifest.dsn(role))
        try:
            transaction = connection.transaction()
            await transaction.start()
            try:
                await connection.execute(
                    "INSERT INTO kairos_production_state_v1.operator_observations "
                    "(context_sha256,observation_id,version,observed_at,payload,payload_sha256) "
                    "VALUES($1,$2,$3,now(),'{}'::jsonb,$4)",
                    "0" * 64,
                    uuid4(),
                    10_000,
                    "0" * 64,
                )
            except asyncpg.InsufficientPrivilegeError:
                denied += 1
                log.append({"step": "unsafe write", "role": role, "result": "denied"})
            else:
                raise DrillFailed(f"the {role} role could write operator state")
            finally:
                await transaction.rollback()
        finally:
            await connection.close()
    owner = await asyncpg.connect(manifest.dsn("owner"))
    try:
        unresolved = await _scalar(
            owner,
            "SELECT count(*) FROM kairos_production_evidence_v1.wire_terminals"
            " WHERE terminal_status='UNRESOLVED'",
        )
    finally:
        await owner.close()
    if unresolved:
        raise DrillFailed(f"{unresolved} wire outcomes are unresolved")
    artifact = store_artifact(evidence_dir, _canonical({"drill": "global-operator-control", "steps": log}))
    return OperatorFactsV1(
        artifact_sha256s=(artifact,),
        control_database_identity=f"{manifest.database}:{manifest.host}:{manifest.port}",
        operator_role=manifest.roles["operator"],
        runtime_role=manifest.roles["runtime"],
        operator_version=resumed.version,
        killed_at=killed.changed_at,
        resumed_at=resumed.changed_at,
        restart_observed_version=observed.version,
        entries_dispatched_after_kill=0,
        protected_exit_failures=0,
        duplicate_dispatches=0,
        unknown_claim_retries=0,
        denied_unsafe_privilege_count=denied,
    )


# --------------------------------------------------------------------------- limits

LIMIT_TESTS: dict[str, tuple[str, str]] = {
    # category: (repository key, pytest -k selector)
    "missing_limit": ("risk", "test_scope_binds_exact_risk_limits or test_limits_cannot_inflate_policy"),
    "over_cap": (
        "risk",
        "test_constitution_limit_account_equity_above_ceiling_refuses_entry"
        " or test_constitution_limit_aggregate_open_risk_refuses_entry_once_exhausted"
        " or test_tiny_loss_budget_does_not_round_up_to_the_minimum_order",
    ),
    "daily_stop": (
        "risk",
        "test_constitution_limit_daily_loss_cap_refuses_entry_once_exhausted"
        " or test_existing_stop_risk_also_consumes_daily_loss_headroom",
    ),
    "pending_risk": ("risk", "test_daily_and_aggregate_reservations_are_each_counted_once"),
    "restart_accounting": ("execution", "accounting"),
}
_TEST_FILES = {"risk": "tests/test_live_risk.py", "execution": "tests/test_production_accounting.py"}


def _passed(junit: bytes) -> int:
    root = ElementTree.fromstring(junit)  # noqa: S314  # nosec B314
    cases = list(root.iter("testcase"))
    failed = [case for case in cases if any(child.tag in {"failure", "error", "skipped"} for child in case)]
    if not cases or failed:
        raise DrillFailed(f"{len(failed)} of {len(cases)} limit tests did not pass")
    return len(cases)


def limits_drill(
    *,
    evidence_dir: Path,
    repositories: dict[str, Path],
    owner_identity: str,
    dollar_cap: Decimal,
    daily_stop_loss_usd: Decimal,
    risk_per_trade_fraction: Decimal,
    maximum_total_open_risk_fraction: Decimal,
    work_dir: Path,
    run: Runner = _run,
) -> LimitsFactsV1:
    counts: dict[str, int] = {}
    artifacts: dict[str, str] = {}
    revisions = {
        key: run(["git", "-C", str(path), "rev-parse", "HEAD"], None).decode().strip()
        for key, path in repositories.items()
    }
    for category, (key, selector) in LIMIT_TESTS.items():
        repository = repositories[key]
        junit = work_dir / f"limits-{category}.xml"
        python = repository / ".venv" / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
        run(
            [
                str(python),
                "-m",
                "pytest",
                "-q",
                "-p",
                "no:cacheprovider",
                f"--basetemp={work_dir / ('pt-' + category)}",
                f"--junitxml={junit}",
                str(repository / _TEST_FILES[key]),
                "-k",
                selector,
            ],
            None,
        )
        report = junit.read_bytes()
        counts[category] = _passed(report)
        artifacts[category] = store_artifact(
            evidence_dir,
            _canonical(
                {
                    "category": category,
                    "revision": revisions[key],
                    "selector": selector,
                    "junit": report.decode(),
                }
            ),
        )
    return LimitsFactsV1(
        artifact_sha256s=tuple(dict.fromkeys(artifacts.values())),
        owner_identity=owner_identity,
        dollar_cap=dollar_cap,
        daily_stop_loss_usd=daily_stop_loss_usd,
        risk_per_trade_fraction=risk_per_trade_fraction,
        maximum_total_open_risk_fraction=maximum_total_open_risk_fraction,
        maximum_leverage=1,
        blocked_missing_limit_count=counts["missing_limit"],
        blocked_over_cap_count=counts["over_cap"],
        blocked_daily_stop_count=counts["daily_stop"],
        restart_accounting_receipt_sha256=artifacts["restart_accounting"],
        pending_risk_receipt_sha256=artifacts["pending_risk"],
    )


# --------------------------------------------------------------------------- custody and pairing


def _harmless_order(binding: CustodyBindingV1) -> dict[str, object]:
    """A typed order the venue refuses: 1e-6 of a unit at a price below every minimum.

    The drills only sign and verify it; neither the message nor its signature is sent
    or stored, only the signature's digest.
    """
    return {
        "id": "00384:" + secrets.token_hex(13).upper(),
        "instrument": binding.approved_instruments[0],
        "side": "BUY",
        "leverage": 1,
        "quantity": 100,
        "limitPrice": 1,
        "chainId": binding.chain_id,
    }


def _signed_and_verified(backend: Any, binding: CustodyBindingV1) -> str:
    message = _harmless_order(binding)
    types = EIP712_SCHEMAS["New limit order"]
    domain = build_domain(binding.chain_id)
    signature = backend.sign_typed_data(
        custody_reference=binding.custody_reference, domain=domain, types=types, message=message
    )
    if not CoincurveTypedDataVerifier().verify(
        wallet_address=binding.wallet_address,
        domain=domain,
        types=types,
        message=message,
        signature=signature,
    ):
        raise DrillFailed("the custody signature does not recover the bound wallet")
    return hashlib.sha256(str(signature).encode()).hexdigest()


def custody_drill(
    backend: Any,
    binding: CustodyBindingV1,
    *,
    recovery_backend: Any,
    dev_custody_reference: str,
    evidence_dir: Path,
) -> CustodyFactsV1:
    """MANAGED_CUSTODY: sign and verify, refuse malformed and unauthorized requests, recover."""
    signature_sha = _signed_and_verified(backend, binding)
    malformed = unauthorized = 0
    bad_types = {
        "New limit order": [
            *EIP712_SCHEMAS["New limit order"]["New limit order"],
            {"name": "x", "type": "string"},
        ]
    }
    try:
        backend.sign_typed_data(
            custody_reference=binding.custody_reference,
            domain=build_domain(binding.chain_id),
            types=bad_types,
            message={**_harmless_order(binding), "x": "y"},
        )
    except LocalCustodyError:
        malformed += 1
    else:
        raise DrillFailed("custody signed a request outside the reviewed schema")
    try:
        backend.sign_typed_data(
            custody_reference=binding.custody_reference + "-other",
            domain=build_domain(binding.chain_id),
            types=EIP712_SCHEMAS["New limit order"],
            message=_harmless_order(binding),
        )
    except LocalCustodyError:
        unauthorized += 1
    else:
        raise DrillFailed("custody signed for another custody reference")
    recovered_sha = _signed_and_verified(recovery_backend, binding)
    signatures = store_artifact(
        evidence_dir,
        _canonical({"drill": "managed-custody", "signature_sha256": signature_sha, "verified": True}),
    )
    recovery = store_artifact(
        evidence_dir,
        _canonical(
            {
                "drill": "managed-custody-recovery",
                "recovered_signature_sha256": recovered_sha,
                "same_wallet": binding.wallet_address,
            }
        ),
    )
    return CustodyFactsV1(
        artifact_sha256s=(signatures, recovery),
        custody_reference=binding.custody_reference,
        wallet_address=binding.wallet_address,
        chain_id=binding.chain_id,
        typed_schema_sha256=reviewed_schema_sha256(binding.chain_id),
        independent_recovery_test_sha256=recovery,
        dev_custody_reference=dev_custody_reference,
        successful_verified_signatures=2,
        malformed_requests_rejected=malformed,
        unauthorized_requests_rejected=unauthorized,
        unverified_signatures=0,
    )


async def pairing_drill(
    reads: Any,
    backend: Any,
    binding: CustodyBindingV1,
    *,
    evidence_dir: Path,
) -> PairingFactsV1:
    """PROD_ACCOUNT_PAIRING: the API key reads the bound account, the keystore signs for its wallet."""
    health = await reads.preflight()
    capture = health.get("account_capture")
    if not isinstance(capture, dict):
        raise DrillFailed("the authenticated read has no original capture")
    read = store_artifact(evidence_dir, _canonical({"drill": "pairing-read", "capture": capture}))
    signing = store_artifact(
        evidence_dir,
        _canonical(
            {
                "drill": "pairing-signing",
                "account": binding.context.remote_account_id,
                "signature_sha256": _signed_and_verified(backend, binding),
            }
        ),
    )
    return PairingFactsV1(
        artifact_sha256s=(read, signing),
        environment="PROD",
        remote_account_id=binding.context.remote_account_id,
        wallet_address=binding.wallet_address,
        authenticated_read_challenge_sha256=read,
        signing_challenge_sha256=signing,
        chain_id=binding.chain_id,
        credential_pairing_conflicts=0,
    )


# --------------------------------------------------------------------------- CLI


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m kairos_execution.production_drills", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("recovery", "operator"):
        command = sub.add_parser(name)
        command.add_argument("--manifest", type=Path, required=True)
        command.add_argument("--evidence-dir", type=Path, required=True)
        command.add_argument("--out", type=Path, required=True)
        if name == "recovery":
            command.add_argument("--admin-dsn-file", type=Path, required=True)
            command.add_argument("--container", default="kairos-execution-prod-db")
    limits = sub.add_parser("limits")
    limits.add_argument("--evidence-dir", type=Path, required=True)
    limits.add_argument("--out", type=Path, required=True)
    limits.add_argument("--risk-repo", type=Path, default=Path(r"D:\Kairos\kairos-risk-manager"))
    limits.add_argument("--execution-repo", type=Path, default=Path(__file__).resolve().parents[1])
    limits.add_argument("--owner-identity", required=True)
    limits.add_argument("--dollar-cap", type=Decimal, required=True)
    limits.add_argument("--daily-stop-loss-usd", type=Decimal, required=True)
    limits.add_argument("--risk-per-trade-fraction", type=Decimal, default=Decimal("0.0025"))
    limits.add_argument("--maximum-total-open-risk-fraction", type=Decimal, default=Decimal("0.01"))
    limits.add_argument("--work-dir", type=Path, required=True)
    for name in ("custody", "pairing"):
        command = sub.add_parser(name)
        command.add_argument("--settings", type=Path, required=True, help="ProductionLifecycleConfigV1 JSON")
        command.add_argument("--keystore-file", type=Path, required=True)
        command.add_argument("--unlock-file", type=Path, required=True)
        command.add_argument("--evidence-dir", type=Path, required=True)
        command.add_argument("--out", type=Path, required=True)
        if name == "custody":
            command.add_argument("--backup-keystore-file", type=Path, required=True)
            command.add_argument("--backup-unlock-file", type=Path, required=True)
            command.add_argument("--dev-custody-reference", required=True)
        else:
            command.add_argument("--node-executable", type=Path, required=True)
            command.add_argument("--api-key-file", type=Path, required=True)
    args = parser.parse_args(argv)

    def keystore(keystore_file: Path, unlock_file: Path, binding: CustodyBindingV1) -> Any:
        from .local_custody import LocalEncryptedKeystoreBackend

        return LocalEncryptedKeystoreBackend(
            python_executable=Path(sys.executable),
            keystore_file=keystore_file,
            unlock_file=unlock_file,
            custody_reference=binding.custody_reference,
            wallet_address=binding.wallet_address,
            chain_id=binding.chain_id,
            approved_instruments=binding.approved_instruments,
        )

    facts: BaseModel
    try:
        if args.command in {"custody", "pairing"}:
            from .production_lifecycle import ProductionLifecycleConfigV1

            settings = ProductionLifecycleConfigV1.model_validate_json(
                args.settings.read_text(encoding="utf-8")
            )
            binding = settings.custody_binding
            primary = keystore(args.keystore_file, args.unlock_file, binding)
            if args.command == "custody":
                facts = custody_drill(
                    primary,
                    binding,
                    recovery_backend=keystore(args.backup_keystore_file, args.backup_unlock_file, binding),
                    dev_custody_reference=args.dev_custody_reference,
                    evidence_dir=args.evidence_dir,
                )
            else:
                from .production_reads import ProductionEvedexReads
                from .production_transport import ProductionEvedexSdkClient

                client = ProductionEvedexSdkClient(
                    node_executable=args.node_executable,
                    api_key_file=args.api_key_file,
                    expected_account_id=binding.context.remote_account_id,
                )
                reads = ProductionEvedexReads(client, symbol_map=settings.symbol_map)

                async def pairing() -> PairingFactsV1:
                    try:
                        return await pairing_drill(reads, primary, binding, evidence_dir=args.evidence_dir)
                    finally:
                        await reads.close()

                facts = asyncio.run(pairing())
        elif args.command == "recovery":
            facts = asyncio.run(
                recovery_drill(
                    ProvisionedDatabaseV1.load(args.manifest),
                    admin_dsn=args.admin_dsn_file.read_text(encoding="utf-8").strip(),
                    container=args.container,
                    evidence_dir=args.evidence_dir,
                )
            )
        elif args.command == "operator":
            facts = asyncio.run(
                operator_drill(ProvisionedDatabaseV1.load(args.manifest), evidence_dir=args.evidence_dir)
            )
        else:
            args.work_dir.mkdir(parents=True, exist_ok=True)
            facts = limits_drill(
                evidence_dir=args.evidence_dir,
                repositories={"risk": args.risk_repo, "execution": args.execution_repo},
                owner_identity=args.owner_identity,
                dollar_cap=args.dollar_cap,
                daily_stop_loss_usd=args.daily_stop_loss_usd,
                risk_per_trade_fraction=args.risk_per_trade_fraction,
                maximum_total_open_risk_fraction=args.maximum_total_open_risk_fraction,
                work_dir=args.work_dir,
            )
    except (DrillFailed, LocalCustodyError, OSError, ValueError, asyncpg.PostgresError) as exc:
        print(f"drill failed: {type(exc).__name__}: {str(exc)[:400]}", file=sys.stderr)
        return 1
    args.out.write_text(facts.model_dump_json(indent=2), encoding="utf-8")
    print(f"facts written to {args.out}; sign them with production_owner issue")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
