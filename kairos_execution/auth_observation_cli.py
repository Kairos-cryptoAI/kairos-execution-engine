"""Two explicit steps: prepare protected resources, then one bounded login.

Only fixed public/private reads, SIWE authentication and WebSocket observation
are available. This process has no order submission command.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote
from uuid import UUID, uuid4

import aiohttp
import asyncpg

from .auth_audit import AuthAuditJournal, authorize_one_auth_followup
from .auth_orchestration import ProtectedAuthMaterial as Material
from .auth_orchestration import (
    _private_acl,
    _write_new_private_file,
    authenticate_and_capture_once,
    build_auth_custody,
    provision_existing_auth_material,
)
from .evedex_private_ws import EvedexPrivateWsStream
from .local_custody import _regular_protected_file
from .production_claims import PostgresProductionClaims, provision_isolated_schema
from .production_readiness import ProductionContextV1, canonical_digest
from .production_reads import ProductionEvedexReads
from .production_transport import ProductionEvedexSdkClient
from .production_ws_observer import capture_ws_rest_observation
from .siwe_session import WalletSessionRegionForbidden, WalletSessionTwofaRequired, _unique_object

IMAGE = "timescale/timescaledb:2.29.1-pg16"
PARAMS_URL = "https://raw.githubusercontent.com/evedex-official/exchange-bot-sdk/master/src/params.ts"
SOURCE_NAMES = (
    "auth_observation_cli.py", "auth_orchestration.py", "auth_audit.py", "siwe_session.py", "siwe_auth.py",
    "local_custody.py", "_local_custody_worker.py", "evedex_private_ws.py", "production_ws_observer.py",
    "production_reads.py", "production_transport.py", "production_claims.py", "production_readiness.py",
    "crypto.py", "protected_files.py",
)


def _emit(event: str, **values):
    print(json.dumps({"event": event, **values}, separators=(",", ":")), flush=True)


def _command(*arguments):
    return subprocess.run(
        list(arguments), check=True, capture_output=True, text=True, timeout=30
    ).stdout.strip()


def _credential_line(lines, number):
    if type(number) is not int or not 1 <= number <= len(lines):
        raise ValueError("credential line unavailable")
    line = lines[number - 1]
    parts = re.split(r"[:=]", line, maxsplit=1)
    if len(parts) != 2 or not parts[1].strip():
        raise ValueError("credential line format unavailable")
    return parts[1].strip()


def _validate_credential_labels(lines, *, wallet_key_line, wallet_address_line, api_key_line):
    for number, required in (
        (wallet_key_line, r"key|ключ"),
        (wallet_address_line, r"wallet|address|кошел|адрес"),
        (api_key_line, r"evedex.*api.*key"),
    ):
        if not 1 <= number <= len(lines):
            raise ValueError("explicit credential line unavailable")
        label = re.split(r"[:=]", lines[number - 1], maxsplit=1)[0]
        if not re.search(required, label, re.I) or re.search(r"dev|demo|test", label, re.I):
            raise ValueError("production credential label mismatch")
    # Wallet labels can be generic, so require the closest preceding empty
    # section header to identify the EVEDEX production section explicitly.
    for number in (wallet_key_line, wallet_address_line):
        headers = [re.split(r"[:=]", line, maxsplit=1)[0] for line in lines[:number - 1]
                   if len(re.split(r"[:=]", line, maxsplit=1)) == 2
                   and not re.split(r"[:=]", line, maxsplit=1)[1].strip()]
        if (not headers or not re.search(r"evedex", headers[-1], re.I)
                or re.search(r"dev|demo|test", headers[-1], re.I)):
            raise ValueError("production wallet section unavailable")


async def _get_json(url, *, api_key=None):
    async with aiohttp.ClientSession(
        trust_env=False, cookie_jar=aiohttp.DummyCookieJar(),
        timeout=aiohttp.ClientTimeout(total=10),
    ) as session:
        async with session.get(
            url, headers={"x-api-key": api_key} if api_key else {}, allow_redirects=False,
        ) as response:
            if response.status != 200:
                raise ValueError("fixed read refused")
            body = bytearray()
            async for chunk in response.content.iter_chunked(4096):
                body.extend(chunk)
                if len(body) > 1_000_000:
                    raise ValueError("fixed read exceeded bound")
    return bytes(body)


def _dsn(port, database, role, password):
    return f"postgresql://{quote(role, safe='')}:{quote(password, safe='')}@127.0.0.1:{port}/{database}"


async def _provision_claims(runtime: Path, container: str):
    if re.fullmatch(r"kairos-auth-[a-z0-9-]{8,45}", container) is None:
        raise ValueError("explicit isolated container name required")
    volume = container + "-data"
    for kind, name in (("container", container), ("volume", volume)):
        exists = subprocess.run(
            ["docker", kind, "inspect", name], capture_output=True, timeout=10,
        ).returncode == 0
        if exists:
            raise ValueError("auth container/volume already exists; inspect rather than retry")
    admin_password = secrets.token_urlsafe(40)
    password_file = runtime / "postgres-admin-password.txt"
    _write_new_private_file(password_file, (admin_password + "\n").encode())
    _command(
        "docker", "run", "--detach", "--name", container, "--restart", "unless-stopped",
        "--mount", f"type=volume,src={volume},dst=/var/lib/postgresql/data",
        "--mount", f"type=bind,src={password_file},dst=/run/secrets/postgres-password,readonly",
        "--env", "POSTGRES_PASSWORD_FILE=/run/secrets/postgres-password",
        "--publish", "127.0.0.1::5432", IMAGE,
    )
    port_text = _command("docker", "port", container, "5432/tcp")
    match = re.fullmatch(r"127\.0\.0\.1:([0-9]{1,5})", port_text)
    if match is None:
        raise ValueError("local dedicated database port unavailable")
    port = int(match[1])
    admin = None
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            admin = await asyncpg.connect(_dsn(port, "postgres", "postgres", admin_password), timeout=2)
            break
        except (OSError, asyncpg.PostgresError):
            await asyncio.sleep(0.5)
    if admin is None:
        raise ValueError("dedicated database did not become ready")
    suffix = secrets.token_hex(6)
    database = "kairos_production_evidence_auth_" + suffix
    owner, role = "auth_owner_" + suffix, "auth_runtime_" + suffix
    owner_password, role_password = secrets.token_urlsafe(40), secrets.token_urlsafe(40)
    try:
        await admin.execute(f'CREATE ROLE "{owner}" LOGIN PASSWORD \'{owner_password}\'')
        await admin.execute(f'CREATE ROLE "{role}" LOGIN PASSWORD \'{role_password}\'')
        await admin.execute(f'CREATE DATABASE "{database}" OWNER "{owner}"')
    finally:
        await admin.close()
    owner_dsn = _dsn(port, database, owner, owner_password)
    runtime_dsn = _dsn(port, database, role, role_password)
    _write_new_private_file(runtime / "owner-dsn.txt", (owner_dsn + "\n").encode())
    _write_new_private_file(runtime / "runtime-dsn.txt", (runtime_dsn + "\n").encode())
    database_uuid = uuid4()
    namespace = "evedex-auth-observation:" + suffix
    connection = await asyncpg.connect(owner_dsn, timeout=5)
    try:
        await provision_isolated_schema(
            connection, expected_database=database, database_uuid=database_uuid,
            policy_namespace=namespace, owner_role=owner, runtime_role=role,
        )
    finally:
        await connection.close()
    return {"container": container, "volume": volume, "database": database,
            "database_uuid": str(database_uuid), "namespace": namespace, "runtime_role": role}


def _reader(plan, runtime):
    client = ProductionEvedexSdkClient(
        node_executable=Path(plan["node"]), api_key_file=runtime / "auth" / "api-key.txt",
        expected_account_id=plan["context"]["remote_account_id"], script=Path(plan["sidecar"]),
    )
    return client, ProductionEvedexReads(client, symbol_map={"BTCUSDT": "BTCUSD"})


def _sidecar_fingerprint(script: Path) -> dict[str, str]:
    if not script.is_absolute() or script.name != "prod_main.js" or not script.is_file():
        raise ValueError("an absolute reviewed PROD sidecar is required")
    source = Path(__file__).with_name("evedex_sidecar") / "src"
    hashes = {}
    for original in source.rglob("*.js"):
        relative = original.relative_to(source)
        supplied = script.parent / relative
        if supplied.is_symlink() or not supplied.is_file():
            raise ValueError("supplied sidecar source missing or linked")
        digest = hashlib.sha256(original.read_bytes()).hexdigest()
        if hashlib.sha256(supplied.read_bytes()).hexdigest() != digest:
            raise ValueError("supplied sidecar differs from reviewed source")
        hashes[str(relative)] = digest
    if not hashes:
        raise ValueError("reviewed sidecar source unavailable")
    return hashes


async def prepare(args):
    from eth_account import Account
    runtime = Path(args.runtime_dir)
    if not runtime.is_absolute() or runtime.exists() or not runtime.parent.is_dir():
        raise ValueError("a new absolute private runtime directory is required")
    sidecar_hashes = _sidecar_fingerprint(Path(args.sidecar))
    node = Path(args.node)
    if not node.is_absolute() or node.is_symlink() or not node.is_file():
        raise ValueError("explicit trusted Node 22 executable required")
    node_sha256 = hashlib.sha256(node.read_bytes()).hexdigest()
    if re.fullmatch(r"v22\.[0-9]+\.[0-9]+", _command(str(node), "--version")) is None:
        raise ValueError("reviewed Node 22 executable required")
    public_params = await _get_json(PARAMS_URL)
    if hashlib.sha256(public_params).hexdigest() != args.params_sha256:
        raise ValueError("official auth parameter source changed; review before preparing")
    lines = Path(args.keys_file).read_text(encoding="utf-8-sig").splitlines()
    _validate_credential_labels(
        lines, wallet_key_line=args.wallet_key_line, wallet_address_line=args.wallet_address_line,
        api_key_line=args.api_key_line,
    )
    key, api_key = _credential_line(lines, args.wallet_key_line), _credential_line(lines, args.api_key_line)
    wallet = Account.from_key(key).address
    expected_address = _credential_line(lines, args.wallet_address_line)
    if wallet.casefold() != expected_address.casefold():
        raise ValueError("source wallet key/address mismatch")
    identity = json.loads(
        await _get_json("https://exchange-api.evedex.com/api/user/me", api_key=api_key),
        object_pairs_hook=_unique_object,
    )
    if (type(identity) is not dict or not identity.get("exchangeId")
            or str(identity.get("wallet", "")).casefold() != wallet.casefold()):
        raise ValueError("API key and source wallet account differ")
    runtime.mkdir(mode=0o700)
    _private_acl(runtime, directory=True)
    material = provision_existing_auth_material(
        destination=runtime / "auth", wallet_private_key=key, api_key=api_key, expected_wallet_address=wallet,
    )
    claims = await _provision_claims(runtime, args.container)
    policy = {"purpose": "one_wallet_login_readonly_observation", "auth_chain_id": args.auth_chain_id,
              "params_url": PARAMS_URL, "params_sha256": args.params_sha256, "order_methods": []}
    source_hashes = {
        name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
        for name in SOURCE_NAMES
    }
    context = ProductionContextV1(
        remote_account_id=str(identity["exchangeId"]), adaptive_system_id="evedex_auth_observation_v1",
        frozen_policy_sha256=hashlib.sha256(json.dumps(policy, sort_keys=True).encode()).hexdigest(),
        source_set_sha256=hashlib.sha256(json.dumps(source_hashes, sort_keys=True).encode()).hexdigest(),
    )
    plan = {"version": "kairos.auth-observation-plan.v1", "context": context.model_dump(mode="json"),
            "wallet": material.wallet_address, "node": str(Path(args.node)),
            "sidecar": str(Path(args.sidecar)),
            "auth_chain_id": args.auth_chain_id, "policy": policy, "source_hashes": source_hashes,
            "sidecar_hashes": sidecar_hashes, "node_sha256": node_sha256,
            "claims": claims, "created_at": datetime.now(UTC).isoformat()}
    client, reads = _reader(plan, runtime)
    try:
        await reads.preflight()
        original = await reads._read("account_identity")
        if str(original.get("wallet", "")).casefold() != wallet.casefold():
            raise ValueError("SDK wallet identity changed")
    finally:
        await client.close()
    encoded = json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()
    _write_new_private_file(runtime / "plan.json", encoded)
    _emit("PREPARED_NO_AUTH", plan_sha256=hashlib.sha256(encoded).hexdigest(),
          runtime_dir=str(runtime), credentials_private=True, real_auth_attempts=0, trading_authority=False)


def _capture_summary(observation):
    return {"subscribed_channels": len(observation.subscribed_channels),
            "publications": len(observation.publications),
            "finished_at": observation.finished_at.isoformat(), "trading_authority": False,
            "continuity_proven": observation.sequence_continuity_proven}


async def revise_preauth_plan(args):
    """Revise reviewed code only while the durable attempt ledger is empty."""
    runtime = Path(args.runtime_dir)
    plan_file = _regular_protected_file(runtime / "plan.json")
    original = plan_file.read_bytes()
    if hashlib.sha256(original).hexdigest() != args.plan_sha256:
        raise ValueError("original prepared plan differs from reviewed digest")
    plan = json.loads(original, object_pairs_hook=_unique_object)
    if _sidecar_fingerprint(Path(plan["sidecar"])) != plan["sidecar_hashes"]:
        raise ValueError("prepared sidecar changed")
    if hashlib.sha256(Path(plan["node"]).read_bytes()).hexdigest() != plan["node_sha256"]:
        raise ValueError("prepared Node changed")
    context = ProductionContextV1.model_validate(plan["context"])
    if set(plan["source_hashes"]) != set(SOURCE_NAMES):
        raise ValueError("prepared source manifest is incomplete")
    source_hashes = {
        name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
        for name in plan["source_hashes"]
    }
    changed = {name for name, digest in source_hashes.items() if digest != plan["source_hashes"][name]}
    if not changed or not changed <= {"auth_observation_cli.py", "siwe_session.py", "auth_orchestration.py"}:
        raise ValueError("preauth revision source changes exceed reviewed files")
    info = plan["claims"]
    dsn = _regular_protected_file(runtime / "runtime-dsn.txt").read_text().strip()
    pool = await asyncpg.create_pool(dsn, min_size=1, max_size=1)
    claims = PostgresProductionClaims(
        pool, expected_database=info["database"], database_uuid=UUID(info["database_uuid"]),
        policy_namespace=info["namespace"], runtime_role=info["runtime_role"], context=context,
    )
    try:
        async with pool.acquire() as connection:
            await claims.inspect(connection)
            async with connection.transaction():
                await connection.fetchval(
                    "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                    "auth-plan:" + info["database_uuid"],
                )
                if hashlib.sha256(plan_file.read_bytes()).hexdigest() != args.plan_sha256:
                    raise ValueError("prepared plan changed during revision")
                counts = await connection.fetchrow(
                    "SELECT (SELECT count(*) FROM kairos_production_evidence_v1.claims) AS claims,"
                    "(SELECT count(*) FROM kairos_production_evidence_v1.terminals) AS terminals,"
                    "(SELECT count(*) FROM kairos_production_evidence_v1.wire_terminals) AS wire_terminals"
                )
                if any(counts.values()):
                    raise ValueError("preauth revision refused: prior attempt or effect exists")
                backup = runtime / ("plan.pre-auth-" + args.plan_sha256[:16] + ".json")
                _write_new_private_file(backup, original)
                source_digest = hashlib.sha256(json.dumps(source_hashes, sort_keys=True).encode()).hexdigest()
                updated_context = context.model_copy(update={
                    "source_set_sha256": source_digest
                })
                plan["context"] = updated_context.model_dump(mode="json")
                plan["source_hashes"] = source_hashes
                plan["preauth_revision"] = {
                    "original_plan_sha256": args.plan_sha256,
                    "original_context_sha256": canonical_digest(context),
                    "revised_at": datetime.now(UTC).isoformat(),
                    "claims_before_revision": 0,
                }
                encoded = json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()
                pending = runtime / ("plan.next-" + hashlib.sha256(encoded).hexdigest()[:16] + ".json")
                _write_new_private_file(pending, encoded)
                os.replace(pending, plan_file)
        _emit("PREAUTH_PLAN_REVISED_NO_AUTH", plan_sha256=hashlib.sha256(encoded).hexdigest(),
              original_plan_sha256=args.plan_sha256, claims_before_revision=0,
              real_auth_attempts=0, trading_authority=False)
    finally:
        await pool.close()


async def prepare_auth_followup(args):
    """Write a separate reviewed plan, retaining the prior UNKNOWN plan/ledger."""
    if args.acknowledge_prior_unknown is not True:
        raise ValueError("explicit acknowledgement of the prior unknown session required")
    if re.fullmatch(r"[A-Za-z0-9_.:-]{1,120}", args.operator_reference) is None:
        raise ValueError("bounded operator reference required")
    runtime = Path(args.runtime_dir)
    prior_file = _regular_protected_file(runtime / "plan.json")
    original = prior_file.read_bytes()
    if hashlib.sha256(original).hexdigest() != args.prior_plan_sha256:
        raise ValueError("prior unknown plan differs from reviewed digest")
    plan = json.loads(original, object_pairs_hook=_unique_object)
    if (runtime / "followup-plan.json").exists():
        raise ValueError("operator follow-up plan already exists")
    if _sidecar_fingerprint(Path(plan["sidecar"])) != plan["sidecar_hashes"]:
        raise ValueError("reviewed sidecar changed")
    if hashlib.sha256(Path(plan["node"]).read_bytes()).hexdigest() != plan["node_sha256"]:
        raise ValueError("reviewed Node changed")
    prior_context = ProductionContextV1.model_validate(plan["context"])
    info = plan["claims"]
    dsn = _regular_protected_file(runtime / "runtime-dsn.txt").read_text().strip()
    pool = await asyncpg.create_pool(dsn, min_size=1, max_size=1)
    prior_claims = PostgresProductionClaims(
        pool, expected_database=info["database"], database_uuid=UUID(info["database_uuid"]),
        policy_namespace=info["namespace"], runtime_role=info["runtime_role"], context=prior_context,
    )
    try:
        async with pool.acquire() as connection:
            await prior_claims.inspect(connection)
            async with connection.transaction():
                await connection.fetchval(
                    "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                    "auth-plan:" + info["database_uuid"],
                )
                prior = await connection.fetchrow(
                    "SELECT request_sha256,context_sha256 FROM kairos_production_evidence_v1.claims "
                    "WHERE claim_kind='MANUAL_NONCE' AND namespace=$1 AND identity='one-attempt'",
                    "siwe-session:" + canonical_digest(prior_context),
                )
                expected = hashlib.sha256((canonical_digest(prior_context) + "\n" + plan["wallet"]).encode())
                if (prior is None or prior["request_sha256"] != expected.hexdigest()
                        or prior["context_sha256"] != canonical_digest(prior_context)):
                    raise ValueError("retained prior auth attempt does not match")
                used = await connection.fetchval(
                    "SELECT EXISTS(SELECT 1 FROM kairos_production_evidence_v1.claims "
                    "WHERE namespace=$1 AND identity='one-operator-followup')",
                    "auth-followup:" + info["database_uuid"],
                )
                if used:
                    raise ValueError("single operator follow-up already consumed")
                source_hashes = {
                    name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                    for name in SOURCE_NAMES
                }
                followup_policy = {"purpose": "one_operator_auth_followup_after_unknown",
                                   "maximum_attempts": 1,
                                   "prior_plan_sha256": args.prior_plan_sha256, "order_methods": []}
                policy_bytes = json.dumps(followup_policy, sort_keys=True).encode()
                policy_digest = hashlib.sha256(policy_bytes).hexdigest()
                source_digest = hashlib.sha256(json.dumps(source_hashes, sort_keys=True).encode()).hexdigest()
                context = prior_context.model_copy(update={
                    "frozen_policy_sha256": policy_digest,
                    "source_set_sha256": source_digest,
                })
                plan["context"] = context.model_dump(mode="json")
                plan["source_hashes"] = source_hashes
                plan["attempt_mode"] = "OPERATOR_AUTH_FOLLOWUP"
                plan["prior_unknown"] = {"plan_sha256": args.prior_plan_sha256,
                                         "context": prior_context.model_dump(mode="json"),
                                         "outcome": "UNKNOWN", "operator_reference": args.operator_reference}
                plan["followup_policy"] = followup_policy
                encoded = json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()
                _write_new_private_file(runtime / "followup-plan.json", encoded)
        _emit("OPERATOR_AUTH_FOLLOWUP_PREPARED_NO_AUTH", plan_sha256=hashlib.sha256(encoded).hexdigest(),
              prior_plan_sha256=args.prior_plan_sha256, prior_outcome="UNKNOWN", real_auth_attempts=0,
              maximum_followups=1, trading_authority=False)
    finally:
        await pool.close()


async def login_capture(args):
    runtime = Path(args.runtime_dir)
    followup = args.action == "login-followup-capture"
    plan_file = _regular_protected_file(runtime / ("followup-plan.json" if followup else "plan.json"))
    encoded = plan_file.read_bytes()
    if hashlib.sha256(encoded).hexdigest() != args.plan_sha256:
        raise ValueError("prepared plan differs from reviewed digest")
    plan = json.loads(encoded)
    if followup:
        if (args.acknowledge_prior_unknown is not True
                or plan.get("attempt_mode") != "OPERATOR_AUTH_FOLLOWUP"
                or plan.get("prior_unknown", {}).get("outcome") != "UNKNOWN"):
            raise ValueError("explicit reviewed auth follow-up unavailable")
        prior_bytes = _regular_protected_file(runtime / "plan.json").read_bytes()
        if hashlib.sha256(prior_bytes).hexdigest() != plan["prior_unknown"]["plan_sha256"]:
            raise ValueError("retained prior unknown plan changed")
    elif plan.get("attempt_mode") is not None:
        raise ValueError("follow-up plan cannot use the original login command")
    for name, expected in plan["source_hashes"].items():
        if hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest() != expected:
            raise ValueError("prepared authentication source changed")
    if _sidecar_fingerprint(Path(plan["sidecar"])) != plan["sidecar_hashes"]:
        raise ValueError("prepared sidecar source changed")
    if hashlib.sha256(Path(plan["node"]).read_bytes()).hexdigest() != plan["node_sha256"]:
        raise ValueError("prepared Node executable changed")
    context = ProductionContextV1.model_validate(plan["context"])
    material = Material(runtime / "auth", runtime / "auth/wallet.json", runtime / "auth/unlock.txt",
                        runtime / "auth/api-key.txt", plan["wallet"])
    backend = build_auth_custody(
        material, chain_id=plan["auth_chain_id"], custody_reference="auth:existing-wallet"
    )
    if backend.worker != Path(__file__).with_name("_local_custody_worker.py").resolve(strict=True):
        raise ValueError("actual custody worker differs from reviewed source")
    dsn_file = _regular_protected_file(runtime / "runtime-dsn.txt")
    pool = await asyncpg.create_pool(dsn_file.read_text().strip(), min_size=1, max_size=2)
    client, reads = _reader(plan, runtime)
    lease = None
    try:
        await reads.preflight()
        info = plan["claims"]
        claims = PostgresProductionClaims(
            pool, expected_database=info["database"], database_uuid=UUID(info["database_uuid"]),
            policy_namespace=info["namespace"], runtime_role=info["runtime_role"], context=context,
        )
        lease = await pool.acquire(timeout=5)
        await claims.inspect(lease)
        await lease.fetchval(
            "SELECT pg_advisory_lock(hashtextextended($1,0))", "auth-plan:" + info["database_uuid"]
        )
        if hashlib.sha256(plan_file.read_bytes()).hexdigest() != args.plan_sha256:
            raise ValueError("prepared plan changed before authentication")
        if followup:
            await authorize_one_auth_followup(
                claims=claims, current_context=context,
                prior_context=ProductionContextV1.model_validate(plan["prior_unknown"]["context"]),
                prior_plan_sha256=plan["prior_unknown"]["plan_sha256"], followup_plan_sha256=args.plan_sha256,
                expected_wallet_address=material.wallet_address,
                operator_reference=plan["prior_unknown"]["operator_reference"],
            )
        audit = AuthAuditJournal(claims)
        captured = await authenticate_and_capture_once(
            backend=backend, claims=claims, reads=reads, expected_context=context,
            expected_wallet_address=material.wallet_address, allow_session_creation=True,
            audit=audit,
        )
        _emit("AUTH_CAPTURED_SESSION_IN_MEMORY", **_capture_summary(captured.observation))
        deadline = time.monotonic() + args.hold_seconds
        loop = asyncio.get_running_loop()
        commands = asyncio.Queue(maxsize=4)
        slots = threading.BoundedSemaphore(4)

        def input_failed():
            while not commands.empty():
                commands.get_nowait()
            commands.put_nowait(None)

        def enqueue(line):
            if commands.full():
                input_failed()
            else:
                commands.put_nowait(line)

        def read_commands():
            while True:
                if not slots.acquire(timeout=0.1):
                    try:
                        loop.call_soon_threadsafe(input_failed)
                    except RuntimeError:
                        pass
                    return
                line = sys.stdin.readline(4097)
                try:
                    if len(line) > 4096:
                        loop.call_soon_threadsafe(input_failed)
                        return
                    loop.call_soon_threadsafe(enqueue, line)
                except RuntimeError:
                    return
                if not line:
                    return

        # A daemon avoids waiting forever in asyncio.run's executor shutdown
        # when stdin is held open after the bounded observation expires.
        threading.Thread(target=read_commands, daemon=True).start()
        # Keeping the same process retains the session without exporting its
        # tokens. No refresh/relogin or order command exists in this service.
        while time.monotonic() < deadline:
            try:
                line = await asyncio.wait_for(commands.get(), timeout=deadline - time.monotonic())
            except TimeoutError:
                _emit("HOLD_FINISHED_SESSION_NOT_REVOKED", trading_authority=False)
                return
            if line is None:
                raise ValueError("bounded command input unavailable")
            slots.release()
            if not line:
                _emit("STDIN_CLOSED_SESSION_NOT_REVOKED", trading_authority=False)
                return
            command = json.loads(line)
            if command == {"command": "stop"}:
                return
            if command == {"command": "status"}:
                _emit("SESSION_RETAINED", trading_authority=False, refresh_implemented=False)
            elif command == {"command": "capture"}:
                stream = EvedexPrivateWsStream(reads=reads, access_token=captured.session.access_token)
                observation = await capture_ws_rest_observation(
                    reads, stream, timeout_seconds=min(30, deadline - time.monotonic())
                )
                _emit("CAPTURED_SAME_SESSION", **_capture_summary(observation))
            else:
                _emit("COMMAND_REFUSED", trading_authority=False)
    finally:
        await client.close()
        if lease is not None:
            await pool.release(lease)
        await pool.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    prepare_parser = sub.add_parser("prepare")
    for name in ("runtime-dir", "keys-file", "node", "sidecar", "container", "params-sha256"):
        prepare_parser.add_argument("--" + name, required=True)
    for name in ("wallet-key-line", "wallet-address-line", "api-key-line"):
        prepare_parser.add_argument("--" + name, required=True, type=int)
    prepare_parser.add_argument("--auth-chain-id", required=True, type=int, choices=(161803,))
    login_parser = sub.add_parser("login-capture")
    login_parser.add_argument("--runtime-dir", required=True)
    login_parser.add_argument("--plan-sha256", required=True)
    login_parser.add_argument("--hold-seconds", type=int, default=120, choices=range(1, 301))
    revision_parser = sub.add_parser("revise-preauth-plan")
    revision_parser.add_argument("--runtime-dir", required=True)
    revision_parser.add_argument("--plan-sha256", required=True)
    followup_prepare = sub.add_parser("prepare-auth-followup")
    followup_prepare.add_argument("--runtime-dir", required=True)
    followup_prepare.add_argument("--prior-plan-sha256", required=True)
    followup_prepare.add_argument("--operator-reference", required=True)
    followup_prepare.add_argument("--acknowledge-prior-unknown", action="store_true", required=True)
    followup_login = sub.add_parser("login-followup-capture")
    followup_login.add_argument("--runtime-dir", required=True)
    followup_login.add_argument("--plan-sha256", required=True)
    followup_login.add_argument("--hold-seconds", type=int, default=120, choices=range(1, 301))
    followup_login.add_argument("--acknowledge-prior-unknown", action="store_true", required=True)
    args = parser.parse_args()
    failed = False
    twofa_required = False
    region_forbidden = False
    try:
        action = {"prepare": prepare, "login-capture": login_capture,
                  "revise-preauth-plan": revise_preauth_plan, "prepare-auth-followup": prepare_auth_followup,
                  "login-followup-capture": login_capture}[args.action]
        asyncio.run(action(args))
    except WalletSessionTwofaRequired:
        twofa_required = True
    except WalletSessionRegionForbidden:
        region_forbidden = True
    except (Exception, KeyboardInterrupt):
        failed = True
    if twofa_required:
        _emit("AUTH_REQUIRES_TWOFA", action=args.action, code="TWOFA_REQUIRED", trading_authority=False)
        raise SystemExit(3)
    if region_forbidden:
        _emit("AUTH_REGION_FORBIDDEN", action=args.action, code="FORBIDDEN_REGION", trading_authority=False)
        raise SystemExit(4)
    if failed:
        _emit("REFUSED_OR_UNKNOWN_NO_AUTOMATIC_RETRY", action=args.action, trading_authority=False)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
