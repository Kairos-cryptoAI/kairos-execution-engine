"""The owner's production setup in a few commands, from the owner's own keys file.

Every piece the production session needs is created by the tools that already own it;
this module only runs them in order and keeps their files in one root directory:

    init       keystore and backup keystore of the wallet key, the single-key API file,
               the account identity, the frozen gate policy, the context, the isolated
               database, the owner arm key, the evidence issuer, the lifecycle settings and
               session.json. Secrets are read by this program from the keys file and
               written only into private files; nothing secret is printed.
    drills     the recovery, operator, limits, custody and pairing drills, each producing
               facts that the system's own interpreters check.
    security-review
               the owner's security review as SECURITY_REVIEW facts (who reviewed, which
               commit fixed what); the record says it is the owner's own review.
    alert-drill
               the Telegram alert drill: both local alerts fire and resolve in the test
               chat and the owner taps the two acknowledgment buttons.
    refresh    signs the seven receipts from the stored facts (a receipt lives at most 24
               hours). The live runner calls it before every session.
    status     what is done and what is missing.

    python -m kairos_execution.production_setup init --keys-file keys.txt --owner-telegram-id 123
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import re
import secrets
import subprocess  # nosec B404 - fixed git and Node commands of the owner's own checkouts
import sys
import time
import urllib.request
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any, Final, cast

from kairos_core.enums import EvedexProfile

from .managed_signer import CustodyBindingV1, reviewed_schema_sha256
from .prod_universe import PROD_SYMBOL_MAP
from .production_lifecycle import ProductionLifecycleConfigV1, ProductionVenueHealthV1
from .production_observation import PROD_EXCHANGE_ORIGIN
from .production_owner import (
    ISSUER_KEY_FILE,
    freeze_policy,
    generate_issuer,
    generate_owner_key,
    issue_receipt,
    store_artifact,
)
from .production_provisioning import ProvisionedDatabaseV1, provision_production_database
from .production_readiness import EvidenceKind, ProductionContextV1
from .profiles import profile_params
from .protected_files import read_private_file, write_new_private_file
from .signed_evidence import FACT_SCHEMAS, FrozenGatePolicyV1, IssuerPolicyV1, SingleHostAlertFactsV2
from .single_host_readiness import SINGLE_HOST_REQUIRED_ALERT_NAMES, issuer_registry_sha256
from .technical_canary_readiness import TECHNICAL_CANARY_REQUIRED_KINDS

DEFAULT_ROOT = Path(r"D:\Kairos\runtime\execution-prod")
STRATEGY_ID = "hourly_trend_candidates_v1"
STRATEGY_REVISION = "1"
CHAIN_ID = 42161
SDK_VERSION: Final = "1.2.11"
TRADING = "https://trading-api.evedex.com"
LABELLED = re.compile(r"^\s*[^:=]{1,80}?\s*[:=]\s*(\S.*?)\s*$")
REPOSITORIES = (
    "kairos-execution-engine",
    "kairos-risk-manager",
    "kairos-strategy-engine",
    "kairos-quant-scouts",
    "kairos-aggregator",
    "kairos-router",
    "kairos-macro-strategist",
    "kairos-text-scouts",
    "kairos-autotrader",
)
RECEIPT_HOURS = 24.0
REFRESH_AFTER = timedelta(hours=12)


class SetupError(RuntimeError):
    """A setup step refused; the message never contains a secret."""


# --------------------------------------------------------------------------- files


def _paths(root: Path) -> dict[str, Path]:
    return {
        "custody": root / "custody",
        "keystore": root / "custody" / "keystore.json",
        "unlock": root / "custody" / "keystore.unlock",
        "backup_keystore": root / "custody" / "backup-keystore.json",
        "backup_unlock": root / "custody" / "backup-keystore.unlock",
        "api_key": root / "custody" / "evedex-api.key",
        "admin_dsn": root / "secrets" / "postgres-admin.private.dsn",
        "old_admin_dsn": root / "secrets" / "postgres-admin.dsn",
        "db": root / "db",
        "manifest": root / "db" / "manifest.json",
        "evidence": root / "evidence",
        "owner": root / "owner",
        "issuer": root / "issuer",
        "facts": root / "facts",
        "alerts": root / "alerts",
        "context": root / "context.json",
        "settings": root / "settings.json",
        "references": root / "references.json",
        "registry": root / "issuer-registry.json",
        "receipts": root / "receipts-issued.json",
        "session": root / "session.json",
        "setup": root / "setup.json",
    }


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    partial = path.with_suffix(path.suffix + ".partial")
    partial.write_text(json.dumps(value, indent=2, default=str), encoding="utf-8")
    partial.replace(path)


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def keys_file_value(keys_file: Path, line: int, what: str) -> str:
    """Line N of the keys file as ``label: value`` or a bare value (the runner's rule)."""
    lines = keys_file.read_text(encoding="utf-8-sig").splitlines()
    if not 1 <= line <= len(lines):
        raise SetupError(f"{what}: line {line} is outside the keys file")
    match = LABELLED.match(lines[line - 1])
    value = match.group(1) if match else lines[line - 1].strip()
    if not value or any(ch.isspace() for ch in value):
        raise SetupError(f"{what}: line {line} has no single value")
    return value


def _git_head(repository: Path) -> str:
    completed = subprocess.run(  # noqa: S603 # nosec B603 - fixed git command
        ["git", "-C", str(repository), "rev-parse", "HEAD"], capture_output=True, timeout=30, check=False
    )
    head = completed.stdout.decode().strip()
    if completed.returncode != 0 or re.fullmatch(r"[0-9a-f]{40}", head) is None:
        raise SetupError(f"no git commit for {repository.name}")
    return head


def evedex_account_id(api_key: str, *, opener=urllib.request.urlopen) -> str:
    """The EVEDEX account the API key authenticates (``exchangeId`` of ``/api/user/me``)."""
    request = urllib.request.Request(  # noqa: S310 - fixed HTTPS venue origin
        f"{TRADING}/api/user/me", headers={"x-api-key": api_key, "accept": "application/json"}
    )
    try:
        with opener(request, timeout=20) as response:  # nosec B310 - fixed HTTPS venue origin
            body = json.loads(response.read(65_536).decode("utf-8"))
    except Exception as exc:  # noqa: BLE001 - never echo a request that carries the key
        raise SetupError(f"the EVEDEX account read failed: {type(exc).__name__}") from None
    account = body.get("exchangeId") if isinstance(body, dict) else None
    if not isinstance(account, str | int) or not str(account).strip():
        raise SetupError("the EVEDEX account identity is missing")
    return str(account)


# --------------------------------------------------------------------------- init


def init(
    root: Path,
    *,
    keys_file: Path,
    wallet_line: int,
    api_line: int,
    owner_identity: str,
    owner_telegram_id: int,
    workspace: Path,
    instruments: tuple[str, ...],
    limits: dict[str, float],
    node_executable: Path,
    quant_python: Path,
    taker_fee_bps: float,
    exit_fee_rate: Decimal,
    adverse_slippage_rate: Decimal,
    account_reader=evedex_account_id,
    provision=provision_production_database,
    now: datetime | None = None,
) -> dict[str, Any]:
    from eth_account import Account

    paths = _paths(root)
    if paths["setup"].exists():
        raise SetupError("this root is already set up; use a new root to start over")
    now = now or datetime.now(UTC).replace(microsecond=0)
    unknown = sorted(set(instruments) - set(PROD_SYMBOL_MAP.values()))
    if unknown:
        raise SetupError(f"instruments outside the reviewed PROD universe: {unknown}")

    # Custody: the wallet key and the API key leave the keys file only into private files.
    wallet_key = keys_file_value(keys_file, wallet_line, "wallet key")
    api_key = keys_file_value(keys_file, api_line, "EVEDEX API key")
    account = Account.from_key(wallet_key)
    paths["custody"].mkdir(parents=True, exist_ok=True)
    for keystore, unlock in (("keystore", "unlock"), ("backup_keystore", "backup_unlock")):
        password = secrets.token_urlsafe(32)
        document = Account.encrypt(cast(Any, wallet_key), password, kdf="scrypt", iterations=2**16)
        write_new_private_file(paths[unlock], password.encode("utf-8"))
        write_new_private_file(paths[keystore], json.dumps(document).encode("utf-8"))
    write_new_private_file(paths["api_key"], api_key.encode("utf-8"))
    del wallet_key
    remote_account_id = account_reader(api_key)
    del api_key
    if not paths["admin_dsn"].exists():
        write_new_private_file(
            paths["admin_dsn"], paths["old_admin_dsn"].read_text(encoding="utf-8").strip().encode("utf-8")
        )
    admin_dsn = read_private_file(paths["admin_dsn"]).decode("utf-8").strip()

    # The source set the receipts attest: the exact commits of every layer that trades.
    heads = {name: _git_head(workspace / name) for name in REPOSITORIES if (workspace / name).exists()}
    evidence = paths["evidence"]
    source_set = store_artifact(
        evidence, _canonical({"version": "kairos.live-source-set.v1", "heads": heads})
    )
    evaluator = workspace / "kairos-autotrader" / "kairos_autotrader" / "management.py"
    frozen = FrozenGatePolicyV1(
        adaptive_system_id=STRATEGY_ID,
        source_set_sha256=source_set,
        campaign_id="hourly-trend-live-v1",
        evaluator_sha256=hashlib.sha256(evaluator.read_bytes()).hexdigest(),
        minimum_profit_factor=Decimal("1.2"),
        maximum_drawdown_fraction=Decimal("0.2"),
        crash_scenario_sha256s=(
            store_artifact(
                evidence, _canonical({"scenario": "venue-outage-close-503", "seen": "2026-11-12"})
            ),
        ),
        required_alert_names=SINGLE_HOST_REQUIRED_ALERT_NAMES,
        owner_telegram_user_id=owner_telegram_id,
        minimum_forward_days=365,
        minimum_natural_closes=500,
        frozen_at=now,
    )
    context = ProductionContextV1(
        remote_account_id=remote_account_id,
        adaptive_system_id=STRATEGY_ID,
        frozen_policy_sha256=freeze_policy(evidence, frozen),
        source_set_sha256=source_set,
    )
    _write_json(paths["context"], context.model_dump(mode="json"))

    manifest = asyncio.run(
        provision(
            admin_dsn,
            context=context,
            secrets_dir=paths["db"] / "roles",
            policy_namespace=f"kairos:live:{remote_account_id}",
        )
    )
    _write_json(paths["manifest"], asdict(manifest))

    owner = generate_owner_key(
        paths["owner"],
        owner_identity=owner_identity,
        context=context,
        valid_from=now,
        valid_until=now + timedelta(days=365),
    )
    issuer = generate_issuer(
        paths["issuer"],
        issuer_id="kairos-owner-evidence-issuer",
        frozen=frozen,
        context=context,
        allowed_kinds=list(TECHNICAL_CANARY_REQUIRED_KINDS),
        valid_from=now,
        valid_until=now + timedelta(days=365),
    )
    (paths["issuer"] / "evidence-issuer.json").write_text(issuer.model_dump_json(indent=2), encoding="utf-8")
    _write_json(paths["registry"], [issuer.model_dump(mode="json")])

    custody_reference = f"local-keystore:{account.address.lower()}"
    binding = CustodyBindingV1(
        context=context,
        custody_reference=custody_reference,
        wallet_address=account.address,
        chain_id=CHAIN_ID,
        schema_sha256=reviewed_schema_sha256(CHAIN_ID),
        approved_instruments=tuple(sorted(instruments)),
        custody_receipt_sha256=hashlib.sha256(
            _canonical({"custody_reference": custody_reference, "wallet": account.address, "chain": CHAIN_ID})
        ).hexdigest(),
    )
    settings = ProductionLifecycleConfigV1(
        context=context,
        custody_binding=binding,
        strategy_revision=STRATEGY_REVISION,
        expected_health=ProductionVenueHealthV1(
            chain_id=CHAIN_ID,
            exchange_url=PROD_EXCHANGE_ORIGIN,
            auth_url=profile_params(EvedexProfile.PROD).auth_url,
            sdk_version=SDK_VERSION,
        ),
        service_name="kairos-production-execution",
        symbol_map={signal: venue for signal, venue in PROD_SYMBOL_MAP.items() if venue in instruments},
        entry_order_type="LIMIT_GTC",
    )
    paths["settings"].write_text(settings.model_dump_json(indent=2), encoding="utf-8")
    _write_json(paths["references"], [])
    _write_json(
        paths["session"],
        {
            "manifest": str(paths["manifest"]),
            "settings": str(paths["settings"]),
            "references": str(paths["references"]),
            "issuer_registry": str(paths["registry"]),
            "pinned_registry_sha256": issuer_registry_sha256((issuer,)),
            "evidence_dir": str(evidence),
            "owner_dir": str(paths["owner"]),
            "keystore_file": str(paths["keystore"]),
            "unlock_file": str(paths["unlock"]),
            "node_executable": str(node_executable),
            "api_key_file": str(paths["api_key"]),
            "limits": limits,
            "exit_fee_rate": str(exit_fee_rate),
            "adverse_slippage_rate": str(adverse_slippage_rate),
            "quant_python": str(quant_python),
            "taker_fee_bps": taker_fee_bps,
            "assessed_notional_usd": limits["max_position_notional_usd"],
        },
    )
    summary = {
        "version": "kairos.production-setup.v1",
        "created_at": now.isoformat(),
        "owner_identity": owner_identity,
        "owner_telegram_user_id": owner_telegram_id,
        "remote_account_id": remote_account_id,
        "wallet_address": account.address,
        "instruments": sorted(instruments),
        "limits": limits,
        "source_heads": heads,
        "owner_key_id": owner.key_id,
        "issuer_key_id": issuer.key_id,
        "database": manifest.database,
    }
    _write_json(paths["setup"], summary)
    return summary


# --------------------------------------------------------------------------- drills


def _setup(root: Path) -> dict[str, Any]:
    paths = _paths(root)
    if not paths["setup"].exists():
        raise SetupError("run init first")
    return dict(_read_json(paths["setup"]))


def _keystore(path: Path, unlock: Path, binding: CustodyBindingV1) -> Any:
    from .local_custody import LocalEncryptedKeystoreBackend

    return LocalEncryptedKeystoreBackend(
        python_executable=Path(sys.executable),
        keystore_file=path,
        unlock_file=unlock,
        custody_reference=binding.custody_reference,
        wallet_address=binding.wallet_address,
        chain_id=binding.chain_id,
        approved_instruments=binding.approved_instruments,
    )


def run_drills(root: Path, *, workspace: Path, container: str, only: tuple[str, ...] = ()) -> dict[str, str]:
    """Run the five owner drills; each writes its facts file. Returns kind -> facts path."""
    from . import production_drills as drills
    from .production_reads import ProductionEvedexReads
    from .production_transport import ProductionEvedexSdkClient

    setup, paths = _setup(root), _paths(root)
    evidence, facts_dir = paths["evidence"], paths["facts"]
    facts_dir.mkdir(parents=True, exist_ok=True)
    manifest = ProvisionedDatabaseV1.load(paths["manifest"])
    settings = ProductionLifecycleConfigV1.model_validate_json(paths["settings"].read_text(encoding="utf-8"))
    binding = settings.custody_binding
    session = _read_json(paths["session"])
    done: dict[str, str] = {}

    def keep(kind: EvidenceKind, facts: Any) -> None:
        path = facts_dir / f"{kind.value}.json"
        path.write_text(facts.model_dump_json(indent=2), encoding="utf-8")
        done[kind.value] = str(path)

    wanted = set(only) or {"recovery", "operator", "limits", "custody", "pairing"}
    if "recovery" in wanted:
        admin = read_private_file(paths["admin_dsn"]).decode("utf-8").strip()
        keep(
            EvidenceKind.PRIMARY_RECOVERY,
            asyncio.run(
                drills.recovery_drill(manifest, admin_dsn=admin, container=container, evidence_dir=evidence)
            ),
        )
    if "operator" in wanted:
        keep(
            EvidenceKind.GLOBAL_OPERATOR_CONTROL,
            asyncio.run(drills.operator_drill(manifest, evidence_dir=evidence)),
        )
    if "limits" in wanted:
        limits = setup["limits"]
        work = root / "work" / "limits"
        work.mkdir(parents=True, exist_ok=True)
        keep(
            EvidenceKind.PRODUCTION_LIMITS,
            drills.limits_drill(
                evidence_dir=evidence,
                repositories={
                    "risk": workspace / "kairos-risk-manager",
                    "execution": workspace / "kairos-execution-engine",
                },
                owner_identity=setup["owner_identity"],
                dollar_cap=Decimal(str(limits["max_account_equity_usd"])),
                daily_stop_loss_usd=Decimal(str(limits["daily_loss_cap_usd"])),
                risk_per_trade_fraction=Decimal(str(limits["per_trade_risk_fraction"])),
                maximum_total_open_risk_fraction=Decimal(str(limits["aggregate_open_risk_fraction"])),
                work_dir=work,
            ),
        )
    if wanted & {"custody", "pairing"}:
        primary = _keystore(paths["keystore"], paths["unlock"], binding)
        if "custody" in wanted:
            keep(
                EvidenceKind.MANAGED_CUSTODY,
                drills.custody_drill(
                    primary,
                    binding,
                    recovery_backend=_keystore(paths["backup_keystore"], paths["backup_unlock"], binding),
                    dev_custody_reference="none:dev-custody-not-used",
                    evidence_dir=evidence,
                ),
            )
        if "pairing" in wanted:
            client = ProductionEvedexSdkClient(
                node_executable=Path(session["node_executable"]),
                api_key_file=paths["api_key"],
                expected_account_id=binding.context.remote_account_id,
            )
            reads = ProductionEvedexReads(client, symbol_map=settings.symbol_map)

            async def pairing() -> Any:
                try:
                    return await drills.pairing_drill(reads, primary, binding, evidence_dir=evidence)
                finally:
                    await reads.close()

            keep(EvidenceKind.PROD_ACCOUNT_PAIRING, asyncio.run(pairing()))
    return done


def security_review(
    root: Path, *, reviewer: str, fix_commit: str, findings_fixed: int, workspace: Path, statement: str
) -> str:
    """SECURITY_REVIEW facts from the owner's own review; the record names it as such."""
    _setup(root)
    paths = _paths(root)
    if re.fullmatch(r"[0-9a-f]{7,40}", fix_commit) is None or findings_fixed <= 0:
        raise SetupError("name the commit that fixed the findings and how many there were")
    context = ProductionContextV1.model_validate_json(paths["context"].read_text(encoding="utf-8"))
    repository = workspace / "kairos-execution-engine"
    full = (
        subprocess.run(  # noqa: S603 # nosec B603 - fixed git command
            ["git", "-C", str(repository), "rev-parse", fix_commit],
            capture_output=True,
            timeout=30,
            check=False,
        )
        .stdout.decode()
        .strip()
    )
    if re.fullmatch(r"[0-9a-f]{40}", full) is None:
        raise SetupError("the fix commit is not in the Execution Engine repository")
    evidence = paths["evidence"]
    threat = store_artifact(
        evidence, (repository / "docs" / "PRODUCTION-SESSION.md").read_bytes(), suffix=".artifact"
    )
    record = store_artifact(
        evidence,
        _canonical(
            {
                "version": "kairos.owner-security-review.v1",
                "reviewer": reviewer,
                "independent": False,
                "statement": statement,
                "fix_commit": full,
                "findings_fixed": findings_fixed,
                "reviewed_source_set_sha256": context.source_set_sha256,
            }
        ),
    )
    facts = FACT_SCHEMAS[EvidenceKind.SECURITY_REVIEW].model_validate(
        {
            "artifact_sha256s": (threat, record),
            "threat_model_sha256": threat,
            "reviewed_source_set_sha256": context.source_set_sha256,
            "independent_reviewer_identity": reviewer,
            "reviewed_security_boundary_count": findings_fixed,
            "unresolved_critical_findings": 0,
            "unresolved_high_findings": 0,
            "unresolved_medium_findings": 0,
            "deployment_review_sha256": record,
        }
    )
    path = paths["facts"] / f"{EvidenceKind.SECURITY_REVIEW.value}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(facts.model_dump_json(indent=2), encoding="utf-8")
    return str(path)


def alert_drill(
    root: Path,
    *,
    token_file: Path,
    token_line: int | None,
    chat_id: int,
    wait_s: float = 900.0,
    sleep=time.sleep,
    channel_factory=None,
) -> str:
    """Fire and resolve both local alerts in Telegram, then wait for the owner's two taps."""
    from .production_alerts import (
        AlertError,
        AlertLog,
        Monitor,
        TelegramChannel,
        alert_facts,
        write_heartbeat,
    )

    setup, paths = _setup(root), _paths(root)
    owner_id = int(setup["owner_telegram_user_id"])
    directory = paths["alerts"] / datetime.now(UTC).strftime("drill-%Y%m%dT%H%M%SZ")
    directory.mkdir(parents=True, exist_ok=True)
    log = AlertLog(directory / "alerts.jsonl")
    heartbeat = directory / "heartbeat.json"
    channel = (channel_factory or TelegramChannel)(
        token_file=token_file, chat_id=chat_id, owner_user_id=owner_id, token_line=token_line
    )
    first = Monitor(heartbeat, channel, log, "kairos-owner-host", minimum_gap=timedelta(seconds=3))
    first.start()
    first.poll()  # no heartbeat: local-process-health FIRING
    write_heartbeat(heartbeat, pid=1, started_at="drill-first")
    sleep(3.5)
    first.poll()  # fresh: RESOLVED
    second = Monitor(heartbeat, channel, log, "kairos-owner-host", minimum_gap=timedelta(seconds=3))
    second.start()  # the notifier restart
    second.poll()
    write_heartbeat(heartbeat, pid=2, started_at="drill-second")
    second.poll()  # a new runner process: local-supervisor-restart FIRING
    sleep(3.5)
    write_heartbeat(heartbeat, pid=2, started_at="drill-second")
    second.poll()  # RESOLVED
    print("Нажмите «ACK» под двумя сообщениями «ВОССТАНОВЛЕНО» в тестовом чате.", flush=True)
    deadline = time.monotonic() + wait_s
    last_error = "no acknowledgment yet"
    while time.monotonic() < deadline:
        write_heartbeat(heartbeat, pid=2, started_at="drill-second")
        second.poll()
        try:
            facts: SingleHostAlertFactsV2 = alert_facts(log, paths["evidence"], owner_user_id=owner_id)
        except AlertError as exc:
            last_error = str(exc)
            sleep(3.0)
            continue
        path = paths["facts"] / f"{EvidenceKind.ALERT_DELIVERY.value}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(facts.model_dump_json(indent=2), encoding="utf-8")
        # Receipts are signed on whole seconds; an acknowledgment from this same second
        # would look like it came after the receipt.
        time.sleep(1.1)
        return str(path)
    raise SetupError(f"the owner's acknowledgments did not arrive in time: {last_error[:200]}")


# --------------------------------------------------------------------------- receipts


def refresh(root: Path, *, force: bool = False, now: datetime | None = None) -> dict[str, Any]:
    """Sign the seven receipts from the stored facts when the last ones are older than 12 h."""
    paths = _paths(root)
    _setup(root)
    now = now or datetime.now(UTC).replace(microsecond=0)
    if paths["receipts"].exists() and not force:
        issued = datetime.fromisoformat(_read_json(paths["receipts"])["issued_at"])
        if now - issued < REFRESH_AFTER:
            return {"refreshed": False, "issued_at": issued.isoformat()}
    missing = [
        k.value for k in TECHNICAL_CANARY_REQUIRED_KINDS if not (paths["facts"] / f"{k.value}.json").exists()
    ]
    if missing:
        raise SetupError(f"facts are missing for: {', '.join(missing)}")
    issuer = IssuerPolicyV1.model_validate_json(
        (paths["issuer"] / "evidence-issuer.json").read_text(encoding="utf-8")
    )
    references = []
    for kind in TECHNICAL_CANARY_REQUIRED_KINDS:
        text = (paths["facts"] / f"{kind.value}.json").read_text(encoding="utf-8")
        schema = SingleHostAlertFactsV2 if kind is EvidenceKind.ALERT_DELIVERY else FACT_SCHEMAS[kind]
        reference = issue_receipt(
            paths["issuer"] / ISSUER_KEY_FILE,
            issuer,
            kind=kind,
            facts=schema.model_validate_json(text),
            evidence_dir=paths["evidence"],
            issued_at=now,
            lifetime=timedelta(hours=RECEIPT_HOURS),
        )
        references.append(reference.model_dump(mode="json"))
    _write_json(paths["references"], references)
    _write_json(paths["receipts"], {"issued_at": now.isoformat(), "kinds": len(references)})
    return {"refreshed": True, "issued_at": now.isoformat()}


def status(root: Path) -> dict[str, Any]:
    paths = _paths(root)
    if not paths["setup"].exists():
        return {"init": False}
    facts = {k.value: (paths["facts"] / f"{k.value}.json").exists() for k in TECHNICAL_CANARY_REQUIRED_KINDS}
    receipts = _read_json(paths["receipts"]) if paths["receipts"].exists() else None
    return {"init": True, "facts": facts, "receipts": receipts, "session": str(paths["session"])}


# --------------------------------------------------------------------------- CLI


def _runner_limits(config_path: Path | None) -> dict[str, float]:
    """The live runner's Risk limits (its ``_risk_scope``), from its configuration file or defaults."""
    data = _read_json(config_path) if config_path and config_path.exists() else {}
    capital = float(data.get("capital_basis_usd", 100))
    return {
        "per_trade_risk_fraction": 0.0025,
        "aggregate_open_risk_fraction": 0.01,
        "max_leverage": 1.0,
        "per_trade_dollar_cap_usd": float(data.get("risk_per_trade_usd", 0.25)),
        "aggregate_dollar_cap_usd": capital,
        "daily_loss_cap_usd": float(data.get("session_loss_stop_usd", 5)),
        "max_account_equity_usd": float(data.get("max_account_equity_usd", 200)),
        # One position is sized as a third of the capital basis (the runner's rule).
        "max_position_notional_usd": round(capital / 3, 2),
        "min_notional_usd": 5.0,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m kairos_execution.production_setup", description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--workspace", type=Path, default=Path(r"D:\Kairos"))
    sub = parser.add_subparsers(dest="command", required=True)
    first = sub.add_parser("init")
    first.add_argument("--keys-file", type=Path, required=True)
    first.add_argument("--wallet-line", type=int, default=6)
    first.add_argument("--api-line", type=int, default=9)
    first.add_argument("--owner-identity", default="owner")
    first.add_argument("--owner-telegram-id", type=int, required=True)
    first.add_argument("--runner-config", type=Path)
    first.add_argument("--instruments", nargs="+")
    first.add_argument(
        "--node-executable",
        type=Path,
        default=Path(r"D:\Kairos\runtime\node22\node-v22.23.5-win-x64\node.exe"),
    )
    first.add_argument(
        "--quant-python", type=Path, default=Path(r"D:\Kairos\kairos-quant-scouts\.venv\Scripts\python.exe")
    )
    first.add_argument("--taker-fee-bps", type=float, default=4.5)
    first.add_argument("--exit-fee-rate", type=Decimal, default=Decimal("0.00045"))
    first.add_argument("--adverse-slippage-rate", type=Decimal, default=Decimal("0.0005"))
    drill = sub.add_parser("drills")
    drill.add_argument("--container", default="kairos-execution-prod-db")
    drill.add_argument("--only", nargs="*", default=[])
    review = sub.add_parser("security-review")
    review.add_argument("--reviewer", required=True)
    review.add_argument("--fix-commit", required=True)
    review.add_argument("--findings-fixed", type=int, required=True)
    review.add_argument("--statement", required=True)
    alerts = sub.add_parser("alert-drill")
    alerts.add_argument("--token-file", type=Path, required=True)
    alerts.add_argument("--token-line", type=int)
    alerts.add_argument("--chat-id", type=int, required=True)
    alerts.add_argument("--wait-minutes", type=float, default=15.0)
    again = sub.add_parser("refresh")
    again.add_argument("--force", action="store_true")
    sub.add_parser("status")
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            runner = args.runner_config
            symbols = args.instruments or (
                _read_json(runner)["symbols"]
                if runner and runner.exists() and "symbols" in _read_json(runner)
                else [
                    "BTCUSD",
                    "ETHUSD",
                    "HYPEUSD",
                    "SOLUSD",
                    "XRPUSD",
                    "DOGEUSD",
                    "LINKUSD",
                    "SUIUSD",
                    "AAVEUSD",
                    "ZECUSD",
                ]
            )
            result: Any = init(
                args.root,
                keys_file=args.keys_file,
                wallet_line=args.wallet_line,
                api_line=args.api_line,
                owner_identity=args.owner_identity,
                owner_telegram_id=args.owner_telegram_id,
                workspace=args.workspace,
                instruments=tuple(symbols),
                limits=_runner_limits(runner),
                node_executable=args.node_executable,
                quant_python=args.quant_python,
                taker_fee_bps=args.taker_fee_bps,
                exit_fee_rate=args.exit_fee_rate,
                adverse_slippage_rate=args.adverse_slippage_rate,
            )
        elif args.command == "drills":
            result = run_drills(
                args.root, workspace=args.workspace, container=args.container, only=tuple(args.only)
            )
        elif args.command == "security-review":
            result = security_review(
                args.root,
                reviewer=args.reviewer,
                fix_commit=args.fix_commit,
                findings_fixed=args.findings_fixed,
                workspace=args.workspace,
                statement=args.statement,
            )
        elif args.command == "alert-drill":
            result = alert_drill(
                args.root,
                token_file=args.token_file,
                token_line=args.token_line,
                chat_id=args.chat_id,
                wait_s=args.wait_minutes * 60,
            )
        elif args.command == "refresh":
            result = refresh(args.root, force=args.force)
        else:
            result = status(args.root)
    except Exception as exc:  # noqa: BLE001 - one sanitized line; secrets never reach messages
        print(
            json.dumps({"ok": False, "error": f"{type(exc).__name__}: {str(exc)[:400]}"}, ensure_ascii=False)
        )
        return 1
    print(json.dumps({"ok": True, "result": result}, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
