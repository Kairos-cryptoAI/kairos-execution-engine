"""Execution engine configuration."""

from __future__ import annotations

import re
from pathlib import Path

from kairos_core.config import CoreSettings
from pydantic import Field, model_validator

from .profiles import EvedexProfile, TradingMode, profile_params


def _default_evedex_symbol_map() -> dict[str, str]:
    return {
        "BTCUSDT": "BTCUSD",
        "ETHUSDT": "ETHUSD",
        "SOLUSDT": "SOLUSD",
        "BNBUSDT": "BNBUSD",
        "XRPUSDT": "XRPUSD",
    }


def _default_evedex_dev_symbol_map() -> dict[str, str]:
    return {key: f"{value}:DEV" for key, value in _default_evedex_symbol_map().items()}


class ExecSettings(CoreSettings):
    service_name: str = "kairos-execution-engine"

    exchange: str = "evedex"  # evedex | ccxt
    trading_mode: TradingMode = TradingMode.DRY_RUN
    # Deprecated compatibility input. False is never interpreted as a live switch.
    dry_run: bool | None = None
    account_id: str = "primary"
    account_snapshot_interval_s: float = Field(default=15.0, gt=0)
    dry_run_equity_usd: float = Field(default=10_000.0, gt=0)
    idempotency_cache_size: int = Field(default=10_000, ge=1)
    journal_recovery_interval_s: float = Field(default=15.0, gt=0)

    # EVEDEX
    evedex_profile: EvedexProfile = EvedexProfile.DEV
    evedex_exchange_url: str = "https://trading-api.evedex.tech"
    evedex_auth_url: str = "https://auth-api.evedex.tech"
    evedex_websocket_url: str = "wss://ws.evedex.tech/connection/websocket"
    evedex_websocket_prefix: str = "futures-perp-dev"
    evedex_chain_id: int = 16182
    evedex_jwt: str | None = None
    evedex_private_key: str | None = None  # wallet key for EIP-712 signing
    evedex_dev_api_key_file: Path | None = None
    evedex_dev_private_key_file: Path | None = None
    evedex_dev_expected_account_id: str | None = None
    # Non-secret independent receipt/config scope. Missing/invalid means no new
    # canary entries; it must never prevent existing exposure recovery or exits.
    canary_scope_file: Path | None = None
    evedex_sidecar_node: str = "node"
    evedex_sidecar_script: Path = Path(__file__).parent / "evedex_sidecar" / "src" / "main.js"
    evedex_sidecar_timeout_s: float = Field(default=20.0, gt=0, le=120)
    evedex_symbol_map: dict[str, str] = Field(default_factory=_default_evedex_symbol_map)
    evedex_dev_symbol_map: dict[str, str] = Field(default_factory=_default_evedex_dev_symbol_map)

    # CCXT (testing on other venues)
    ccxt_exchange_id: str = "binanceusdm"
    ccxt_api_key: str = ""
    ccxt_secret: str = ""
    ccxt_sandbox: bool = True

    default_trail_pct: float = Field(default=0.01, gt=0, lt=1)  # initial 1% protective distance

    @property
    def is_dry_run(self) -> bool:
        return self.trading_mode is TradingMode.DRY_RUN

    @model_validator(mode="after")
    def validate_execution_boundary(self) -> ExecSettings:
        if self.dry_run is False:
            raise ValueError(
                "KAIROS_DRY_RUN=false is retired; set KAIROS_TRADING_MODE explicitly. "
                "It never enables PAPER or LIVE."
            )
        if self.dry_run is True and self.trading_mode is not TradingMode.DRY_RUN:
            raise ValueError("KAIROS_DRY_RUN=true conflicts with an explicit non-DRY_RUN trading mode")
        if self.trading_mode is TradingMode.LIVE:
            raise ValueError("LIVE is disabled: this release is not LIVE_READY")
        if self.trading_mode is TradingMode.PAPER:
            self._validate_paper_dev()
        return self

    def _validate_paper_dev(self) -> None:
        if self.exchange != "evedex":
            raise ValueError("PAPER supports only the official EVEDEX gateway")
        if self.bus_backend != "redis":
            raise ValueError("PAPER requires durable PostgreSQL inbox/outbox and execution journals")
        if self.evedex_profile is not EvedexProfile.DEV:
            raise ValueError("PAPER is restricted to the EVEDEX DEV profile")
        if self.environment not in {"paper", "paper-dev"}:
            raise ValueError("PAPER environment must be in the normalized paper/paper-dev allowlist")
        if not re.fullmatch(r"kairos-paper-dev-[a-z0-9][a-z0-9-]{0,63}", self.account_id):
            raise ValueError("PAPER account_id must match the normalized kairos-paper-dev-* allowlist")
        if self.evedex_jwt or self.evedex_private_key:
            raise ValueError("PAPER rejects legacy JWT/live signing credentials")
        if self.ccxt_api_key or self.ccxt_secret:
            raise ValueError("PAPER rejects unrelated CCXT credentials")
        if self.evedex_dev_api_key_file is None or self.evedex_dev_private_key_file is None:
            raise ValueError("PAPER requires dedicated EVEDEX DEV API/signing secret files")
        if (
            not self.evedex_dev_api_key_file.is_absolute()
            or not self.evedex_dev_private_key_file.is_absolute()
        ):
            raise ValueError("PAPER secret file paths must be absolute")
        if self.evedex_dev_api_key_file == self.evedex_dev_private_key_file:
            raise ValueError("EVEDEX DEV API and signing secrets must be separate files")
        if (
            not self.evedex_dev_expected_account_id
            or self.evedex_dev_expected_account_id != self.evedex_dev_expected_account_id.strip()
        ):
            raise ValueError("PAPER requires the dedicated EVEDEX DEV remote account identity")
        expected = profile_params(EvedexProfile.DEV)
        configured = (
            self.evedex_exchange_url,
            self.evedex_auth_url,
            self.evedex_websocket_url,
            self.evedex_websocket_prefix,
            self.evedex_chain_id,
        )
        official = (
            expected.exchange_url,
            expected.auth_url,
            expected.websocket_url,
            expected.websocket_prefix,
            expected.chain_id,
        )
        if configured != official:
            raise ValueError("PAPER EVEDEX endpoints and chain must exactly match the DEV allowlist")
        required_symbols = {"BTCUSDT", "ETHUSDT", "SOLUSDT", "BNBUSDT", "XRPUSDT"}
        expected_map = {symbol: f"{symbol.removesuffix('USDT')}USD:DEV" for symbol in required_symbols}
        if set(self.trading_symbols) != required_symbols or self.evedex_dev_symbol_map != expected_map:
            raise ValueError("PAPER requires the exact five-symbol EVEDEX DEV instrument allowlist")
        bundled_script = Path(__file__).parent / "evedex_sidecar" / "src" / "main.js"
        if self.evedex_sidecar_script.resolve() != bundled_script.resolve():
            raise ValueError("PAPER must use the bundled EVEDEX sidecar")
        if self.evedex_sidecar_node.casefold() not in {"node", "node.exe"}:
            raise ValueError("PAPER sidecar executable must be Node.js")
