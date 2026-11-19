"""Command line of one automatically armed trade: the live runner hands a candidate here.

    python -m kairos_execution.production_session_cli --config session.json --candidate candidate.json

``session.json`` (prepared once by the owner) names the provisioned database manifest,
the lifecycle settings, the seven receipt references with the pinned issuer registry and
evidence store, the owner key directory, the encrypted wallet keystore and its unlock
file, the Node 22 executable, the API key file, the Risk limits and the exit cost rates.
``candidate.json`` holds the runner's ``CandidateReviewV1``, the optional
``StrategicAllocation`` and the system mode; the five-second PROD ``VenueQualityV1`` is
measured fresh by Quant Scouts (``kairos_quant.venue_now``) right before the entry.

The result is one JSON line on stdout. Exit codes: 0 closed and accounted, 3 refused
before any order, 4 unresolved (the host latched a failure; recovery is needed),
2 configuration refused.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import stat
import sys
from collections.abc import Callable
from decimal import Decimal
from pathlib import Path
from uuid import UUID

import asyncpg  # type: ignore[import-untyped]  # Upstream ships no typing marker/stubs.
from kairos_core.contracts import CandidateReviewV1, StrategicAllocation, VenueQualityV1
from kairos_core.enums import SystemMode
from kairos_risk.live import LiveRiskLimitsV1  # type: ignore[import-untyped]
from pydantic import BaseModel, ConfigDict

from .local_custody import CoincurveTypedDataVerifier, LocalEncryptedKeystoreBackend
from .production_lifecycle import ProductionLifecycleConfigV1
from .production_owner import OWNER_KEY_FILE, OWNER_POLICY_FILE
from .production_provisioning import ProvisionedDatabaseV1
from .production_readiness import OwnerArmKeyV1, ReceiptReferenceV1
from .production_report import closed_trades
from .production_session import (
    AutoArmSigner,
    RolePools,
    TradeCandidate,
    VenueProvider,
    build_rest_session,
    run_one_trade,
)
from .production_transport import ProductionEvedexTransport
from .signed_evidence import DirectoryEvidenceResolver, IssuerPolicyV1
from .technical_canary_readiness import TechnicalCanaryPreconditionsVerifier
from .utc_clock import precise_utc_now

EXIT_CODES = {"CLOSED_AND_ACCOUNTED": 0, "REFUSED": 3, "UNRESOLVED": 4}
_EXIT_REQUEST_MAX_BYTES = 4096


def _open_exit_request(path: Path) -> int:
    """Open without following a final link or waiting for a pipe writer."""
    if os.name != "nt":
        nofollow, nonblock = getattr(os, "O_NOFOLLOW", None), getattr(os, "O_NONBLOCK", None)
        if nofollow is None or nonblock is None:
            raise OSError("the platform cannot safely open an exit request")
        return os.open(path, os.O_RDONLY | nofollow | nonblock)
    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create.restype = wintypes.HANDLE
    kernel.GetFileType.argtypes = (wintypes.HANDLE,)
    kernel.GetFileType.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    # OPEN_EXISTING, OPEN_REPARSE_POINT: inspect the link itself. CreateFile does
    # not wait for named-pipe availability; non-disk handles are never read.
    handle = create(str(path), 0x80000000, 7, None, 3, 0x00200000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if kernel.GetFileType(handle) != 1:  # FILE_TYPE_DISK
            raise OSError("exit request is not a disk file")
        descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except BaseException:
        kernel.CloseHandle(handle)
        raise
    return descriptor  # the CRT descriptor now owns the Windows handle


class SessionConfigV1(BaseModel):
    """Paths and owner parameters of the production session; no secret is inside."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    manifest: Path
    settings: Path
    references: Path
    issuer_registry: Path
    pinned_registry_sha256: str
    evidence_dir: Path
    owner_dir: Path
    keystore_file: Path
    unlock_file: Path
    node_executable: Path
    api_key_file: Path
    limits: dict[str, float]
    exit_fee_rate: Decimal
    adverse_slippage_rate: Decimal
    quant_python: Path
    taker_fee_bps: float
    assessed_notional_usd: float


class CandidateV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    review: CandidateReviewV1
    allocation: StrategicAllocation | None = None
    system_mode: SystemMode = SystemMode.NORMAL
    # The Risk Manager's adaptive per-trade fraction (kairos_risk.adaptive_risk); it can only
    # lower the configured limit, never raise it.
    per_trade_risk_fraction: Decimal | None = None


def candidate_limits(configured: dict[str, float], candidate: CandidateV1) -> LiveRiskLimitsV1 | None:
    """The configured limits with the candidate's adaptive fraction when it is lower; None = no entry."""
    limits = dict(configured)
    if candidate.per_trade_risk_fraction is not None:
        if candidate.per_trade_risk_fraction <= 0:
            return None
        limits["per_trade_risk_fraction"] = min(
            float(limits["per_trade_risk_fraction"]), float(candidate.per_trade_risk_fraction)
        )
    return LiveRiskLimitsV1(**limits)


def quant_venue_provider(
    python: Path, *, taker_fee_bps: float, assessed_notional_usd: float
) -> VenueProvider:
    """A fresh PROD venue measurement from Quant Scouts' own environment (``kairos_quant.venue_now``)."""

    async def provide(review: CandidateReviewV1) -> VenueQualityV1:
        process = await asyncio.create_subprocess_exec(
            str(python),
            "-m",
            "kairos_quant.venue_now",
            "--signal",
            review.intent.symbol,
            "--taker-fee-bps",
            str(taker_fee_bps),
            "--assessed-notional-usd",
            str(assessed_notional_usd),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            out, _ = await asyncio.wait_for(process.communicate(), timeout=4)
        except TimeoutError:
            process.kill()
            raise RuntimeError("the venue measurement did not answer within four seconds") from None
        lines = out.decode("utf-8", errors="replace").strip().splitlines()
        if not lines or '"error"' in lines[-1][:12]:
            raise RuntimeError(f"the venue measurement failed: {(lines or ['no answer'])[-1][:200]}")
        return VenueQualityV1.model_validate_json(lines[-1])

    return provide


async def closed_trade_summary(manifest: ProvisionedDatabaseV1, trade_id: str | None) -> dict[str, object]:
    """The closed trade's R, exit reason and early-exit reason from the single journal.

    A report failure never changes the session's outcome; it is named instead.
    """
    if not trade_id:
        return {}
    try:
        rows = await closed_trades(manifest)
    except (OSError, ValueError, asyncpg.PostgresError) as exc:
        return {"report_error": f"{type(exc).__name__}: {str(exc)[:200]}"}
    row = next((item for item in rows if item["trade_id"] == trade_id), None)
    if row is None:
        return {"report_error": "the closed trade is not in the report yet"}
    return {key: row[key] for key in ("r_multiple", "exit_reason", "early_exit", "net_pnl_usd")}


def exit_request_reader(path: Path | None) -> Callable[[], str | None] | None:
    """The composer's early-exit request: a small text file whose first line is the reason."""
    if path is None:
        return None

    def read() -> str | None:
        try:
            before = path.lstat()
            if not stat.S_ISREG(before.st_mode) or getattr(before, "st_file_attributes", 0) & 0x400:
                return None
            with os.fdopen(_open_exit_request(path), "rb", buffering=0) as stream:
                opened = os.fstat(stream.fileno())
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or getattr(opened, "st_file_attributes", 0) & 0x400
                    or opened.st_size > _EXIT_REQUEST_MAX_BYTES
                    or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
                ):
                    return None
                first = stream.readline(_EXIT_REQUEST_MAX_BYTES)
                after = os.fstat(stream.fileno())
            current = path.lstat()
            if (
                after.st_size > _EXIT_REQUEST_MAX_BYTES
                or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
            ):
                return None
            text = first.decode("utf-8")
        except (OSError, UnicodeError, ValueError):
            return None
        reason = text.splitlines()[0].strip() if text.strip() else ""
        return reason[:200] or None

    return read


def _list(path: Path) -> list[object]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, list):
        raise ValueError(f"{Path(path).name} must hold a JSON list")
    return value


async def run(
    config: SessionConfigV1, candidate: CandidateV1, *, exit_request: Path | None = None
) -> dict[str, object]:
    limits = candidate_limits(config.limits, candidate)
    if limits is None:
        return {"outcome": "REFUSED", "trade_id": None, "detail": "adaptive risk allows no entry"}
    manifest = ProvisionedDatabaseV1.load(config.manifest)
    settings = ProductionLifecycleConfigV1.model_validate_json(config.settings.read_text(encoding="utf-8"))
    binding = settings.custody_binding
    references = tuple(
        ReceiptReferenceV1.model_validate_json(json.dumps(item)) for item in _list(config.references)
    )
    registry = tuple(
        IssuerPolicyV1.model_validate_json(json.dumps(item)) for item in _list(config.issuer_registry)
    )
    canary = TechnicalCanaryPreconditionsVerifier(
        registry,
        DirectoryEvidenceResolver(config.evidence_dir),
        pinned_registry_sha256=config.pinned_registry_sha256,
    )
    owner_key = OwnerArmKeyV1.model_validate_json(
        (config.owner_dir / OWNER_POLICY_FILE).read_text(encoding="utf-8")
    )
    custody = LocalEncryptedKeystoreBackend(
        python_executable=Path(sys.executable),
        keystore_file=config.keystore_file,
        unlock_file=config.unlock_file,
        custody_reference=binding.custody_reference,
        wallet_address=binding.wallet_address,
        chain_id=binding.chain_id,
        approved_instruments=binding.approved_instruments,
    )
    transport = ProductionEvedexTransport.from_deployment(
        context=settings.context,
        custody_binding=binding,
        node_executable=config.node_executable,
        api_key_file=config.api_key_file,
    )
    roles = ("runtime", "operator", "risk", "exposure", "reconciler", "accounting")
    pools = {name: await asyncpg.create_pool(manifest.dsn(name), min_size=1, max_size=4) for name in roles}
    try:
        session = build_rest_session(
            pools=RolePools(
                runtime=pools["runtime"],
                operator=pools["operator"],
                risk=pools["risk"],
                exposure=pools["exposure"],
                reconciliation=pools["reconciler"],
                accounting=pools["accounting"],
                roles={name: manifest.roles[name] for name in roles},
                database=manifest.database,
                database_uuid=UUID(manifest.database_uuid),
                policy_namespace=manifest.policy_namespace,
            ),
            settings=settings,
            references=references,
            canary_verifier=canary,
            owner_key=owner_key,
            custody_backend=custody,
            custody_signature_verifier=CoincurveTypedDataVerifier(),
            wire_signature_verifier=CoincurveTypedDataVerifier(),
            transport=transport,
            limits=limits,
            exit_fee_rate=config.exit_fee_rate,
            adverse_slippage_rate=config.adverse_slippage_rate,
            clock=precise_utc_now,
        )
        result = await run_one_trade(
            session,
            TradeCandidate(candidate.review, candidate.allocation, candidate.system_mode),
            AutoArmSigner(config.owner_dir / OWNER_KEY_FILE, owner_key),
            quant_venue_provider(
                config.quant_python,
                taker_fee_bps=config.taker_fee_bps,
                assessed_notional_usd=config.assessed_notional_usd,
            ),
            early_exit=exit_request_reader(exit_request),
        )
        answer: dict[str, object] = {
            "outcome": result.outcome,
            "trade_id": result.trade_id,
            "detail": result.detail,
        }
        if result.outcome == "CLOSED_AND_ACCOUNTED":
            answer.update(await closed_trade_summary(manifest, result.trade_id))
        return answer
    finally:
        for pool in pools.values():
            await pool.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m kairos_execution.production_session_cli", description=__doc__
    )
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument(
        "--exit-request",
        type=Path,
        help="a file the composer writes to close the open trade early (first line: the reason)",
    )
    args = parser.parse_args(argv)
    try:
        config = SessionConfigV1.model_validate_json(args.config.read_text(encoding="utf-8"))
        candidate = CandidateV1.model_validate_json(args.candidate.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(json.dumps({"outcome": "CONFIG_REFUSED", "detail": f"{type(exc).__name__}: {str(exc)[:300]}"}))
        return 2
    try:
        answer = asyncio.run(run(config, candidate, exit_request=args.exit_request))
    except Exception as exc:  # noqa: BLE001 - one sanitized line for the runner, never a traceback with paths
        print(
            json.dumps(
                {
                    "outcome": "UNRESOLVED",
                    "trade_id": None,
                    "detail": f"{type(exc).__name__}: {str(exc)[:300]}",
                }
            )
        )
        return 4
    print(json.dumps(answer))
    return EXIT_CODES.get(str(answer["outcome"]), 4)


if __name__ == "__main__":
    raise SystemExit(main())
