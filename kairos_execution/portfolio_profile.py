"""Owner mandate for the account-scoped EVEDEX portfolio pilot. Preparation is offline."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess  # nosec B404
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, field_validator, model_validator

from .managed_signer import CustodyBindingV1
from .prod_universe import PROD_INSTRUMENTS
from .production_readiness import ProductionContextV1
from .signed_evidence import PairingFactsV1

OWNER_FINGERPRINT = "40AF365C6682B73D056A6A274DBFF6B65BE9F827"
PILOT_ENTRY_DEADLINE_UTC = datetime(2026, 11, 22, 21, tzinfo=UTC)
MAX_PROFILE_BYTES = 16_384


class PortfolioProfile(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    version: Literal["kairos.portfolio-owner.v1"]
    venue: Literal["EVEDEX_PROD"]
    chain_id: Literal[42161]
    account_id: str = Field(pattern=r"^evedex-prod-[0-9a-f]{20}$")
    signer_wallet_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    remote_account_id: str = Field(min_length=1, max_length=128)
    journal_path: Path
    runner_runtime_dir: Path
    symbols: tuple[str, ...]
    max_positions: Literal[10]
    max_leverage: Literal[30]
    capital_usd: Literal[100]
    max_notional_usd: Literal[25]
    max_trade_loss_usd: Literal["0.25"]
    max_open_risk_usd: Literal[1]
    max_session_loss_usd: Literal[5]
    max_daily_entries: Literal[12]
    entry_deadline_utc: datetime

    _source: Path | None = PrivateAttr(default=None)
    _digest: bytes | None = PrivateAttr(default=None)

    @field_validator("entry_deadline_utc")
    @classmethod
    def fixed_pilot_deadline(cls, value: datetime) -> datetime:
        if value.utcoffset() != timedelta(0) or value != PILOT_ENTRY_DEADLINE_UTC:
            raise ValueError("expected the pilot's fixed UTC deadline")
        return value.astimezone(UTC)

    @field_validator("symbols")
    @classmethod
    def reviewed_symbols(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != 23 or len(set(value)) != 23 or not set(value) <= PROD_INSTRUMENTS:
            raise ValueError("expected 23 distinct production instruments")
        return value

    @field_validator("journal_path", "runner_runtime_dir")
    @classmethod
    def absolute_location(cls, value: Path) -> Path:
        if not value.is_absolute() or value != value.resolve():
            raise ValueError("portfolio paths must be absolute and canonical")
        return value

    @model_validator(mode="after")
    def account_scope(self) -> Self:
        if self.account_id != "evedex-prod-" + self.signer_wallet_sha256[:20]:
            raise ValueError("portfolio signer identity mismatch")
        if self.journal_path != self.runner_runtime_dir.parent / "execution-portfolio" / "portfolio.sqlite3":
            raise ValueError("expected the persistent portfolio journal beside the runtime directory")
        return self


def _gpg() -> str:
    path = shutil.which("gpg")
    if path and Path(path).is_absolute():
        return path
    # Git for Windows bundles GnuPG outside the directory exposed on PATH.
    git = shutil.which("git")
    if os.name == "nt" and git and Path(git).is_absolute():
        bundled = Path(git).resolve().parents[1] / "usr" / "bin" / "gpg.exe"
        if bundled.is_file():
            return str(bundled)
    raise ValueError("GnuPG is required to verify the portfolio profile")


def _require_owner_signature(path: Path, payload: bytes) -> None:
    # Fixed verification command, local keyring, detached signature and exact input bytes.
    result = subprocess.run(  # nosec B603
        [
            _gpg(),
            "--no-options",
            "--batch",
            "--no-auto-key-retrieve",
            "--status-fd=1",
            "--verify",
            str(path) + ".asc",
            "-",
        ],
        input=payload,
        capture_output=True,
        timeout=15,
        check=False,
    )
    records = [
        line.split()
        for line in result.stdout.decode("ascii", errors="replace").splitlines()
        if line.startswith("[GNUPG:] ")
    ]
    valid = [r for r in records if len(r) >= 2 and r[1] == "VALIDSIG"]
    failed = {
        "BADSIG",
        "ERRSIG",
        "EXPSIG",
        "EXPKEYSIG",
        "REVKEYSIG",
        "KEYREVOKED",
        "SIGEXPIRED",
        "KEYEXPIRED",
        "NO_PUBKEY",
        "NODATA",
        "FAILURE",
        "ERROR",
    }
    if (
        result.returncode
        or any(r[1] in failed for r in records if len(r) >= 2)
        or len(valid) != 1
        or len(valid[0]) != 12
        or valid[0][11] != OWNER_FINGERPRINT
        or valid[0][9] not in {"8", "9", "10"}
        or valid[0][10] != "00"
    ):
        raise ValueError("portfolio profile has no valid binary owner signature")


def _unique_fields(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in items:
        if name in result:
            raise ValueError("duplicate JSON field")
        result[name] = value
    return result


def load_portfolio_profile(path: Path) -> PortfolioProfile:
    """Authenticate the document and retain its signed byte identity for re-verification."""
    path = Path(path).absolute()
    if path != path.resolve():
        raise ValueError("owner profile must be at its canonical path")
    with path.open("rb") as handle:
        payload = handle.read(MAX_PROFILE_BYTES + 1)
    if len(payload) > MAX_PROFILE_BYTES:
        raise ValueError("owner profile exceeds its size limit")
    _require_owner_signature(path, payload)
    json.loads(payload, object_pairs_hook=_unique_fields)
    profile = PortfolioProfile.model_validate_json(payload)
    if path != profile.journal_path.with_name("owner.json"):
        raise ValueError("owner.json must be beside the portfolio journal")
    profile._source = path
    profile._digest = hashlib.sha256(payload).digest()
    return profile


def verify_profile(profile: PortfolioProfile) -> PortfolioProfile:
    """Reopen the original file and reject stale, replaced or caller-constructed mandates."""
    if type(profile) is not PortfolioProfile or profile._source is None or profile._digest is None:
        raise ValueError("an owner-signed portfolio profile is required")
    current = load_portfolio_profile(profile._source)
    if current._digest != profile._digest or current.model_dump() != profile.model_dump():
        raise ValueError("the signed portfolio profile changed")
    return current


def prepare_profile(production_root: Path, runner_runtime_dir: Path, entry_deadline_utc: datetime) -> bytes:
    """Build an unsigned draft from the previously paired account and the current instrument list."""
    runtime = runner_runtime_dir.resolve(strict=True)
    context = ProductionContextV1.model_validate_json((production_root / "context.json").read_bytes())
    settings = json.loads((production_root / "settings.json").read_bytes(), object_pairs_hook=_unique_fields)
    configured_context = ProductionContextV1.model_validate(settings["context"])
    binding = CustodyBindingV1.model_validate_json(json.dumps(settings["custody_binding"]))
    pairing = PairingFactsV1.model_validate_json(
        (production_root / "facts/prod_account_pairing.json").read_bytes()
    )
    if (
        configured_context != context
        or binding.context != context
        or pairing.remote_account_id != context.remote_account_id
        or binding.wallet_address.lower() != pairing.wallet_address.lower()
        or binding.chain_id != 42161
        or pairing.chain_id != binding.chain_id
    ):
        raise ValueError("local custody, account pairing and production context disagree")
    runner = json.loads((runtime / "config.json").read_bytes(), object_pairs_hook=_unique_fields)
    wallet_digest = hashlib.sha256(binding.wallet_address.lower().encode("ascii")).hexdigest()
    fields = dict(
        version="kairos.portfolio-owner.v1",
        venue="EVEDEX_PROD",
        chain_id=42161,
        account_id="evedex-prod-" + wallet_digest[:20],
        signer_wallet_sha256=wallet_digest,
        remote_account_id=context.remote_account_id,
        runner_runtime_dir=str(runtime),
        journal_path=str(runtime.parent / "execution-portfolio" / "portfolio.sqlite3"),
        symbols=runner["symbols"],
        entry_deadline_utc=entry_deadline_utc.isoformat(),
        max_positions=10,
        max_leverage=30,
        capital_usd=100,
        max_notional_usd=25,
        max_trade_loss_usd="0.25",
        max_open_risk_usd=1,
        max_session_loss_usd=5,
        max_daily_entries=12,
    )
    profile = PortfolioProfile.model_validate_json(json.dumps(fields))
    return (profile.model_dump_json(indent=2) + "\n").encode()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare", help="write a new unsigned draft without connecting to EVEDEX")
    prepare.add_argument("--production-root", required=True, type=Path)
    prepare.add_argument("--runner-runtime-dir", required=True, type=Path)
    prepare.add_argument("--entry-deadline-utc", required=True, type=datetime.fromisoformat)
    prepare.add_argument("--output", required=True, type=Path, help="new local file for owner review")
    verify = commands.add_parser("verify", help="verify an installed owner.json and its detached .asc")
    verify.add_argument("profile", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            output = prepare_profile(args.production_root, args.runner_runtime_dir, args.entry_deadline_utc)
            with args.output.open("xb") as stream:
                stream.write(output)
            print("Unsigned candidate written for owner review.")
        else:
            load_portfolio_profile(args.profile)
            print("Owner signature and portfolio scope verified.")
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired):
        print(
            "Portfolio profile refused. Check local files, account binding, limits and signature.",
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
