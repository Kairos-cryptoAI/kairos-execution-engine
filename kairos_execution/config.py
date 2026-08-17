"""Execution engine configuration."""

from __future__ import annotations

from kairos_core.config import CoreSettings
from pydantic import Field


class ExecSettings(CoreSettings):
    service_name: str = "kairos-execution-engine"

    exchange: str = "evedex"  # evedex | ccxt
    dry_run: bool = True  # never sends real orders unless explicitly disabled
    account_id: str = "primary"
    account_snapshot_interval_s: float = Field(default=15.0, gt=0)
    dry_run_equity_usd: float = Field(default=10_000.0, gt=0)
    idempotency_cache_size: int = Field(default=10_000, ge=1)
    journal_recovery_interval_s: float = Field(default=15.0, gt=0)

    # EVEDEX
    evedex_exchange_url: str = "https://exchange-api.evedex.com"
    evedex_chain_id: int = 1
    evedex_jwt: str | None = None
    evedex_private_key: str | None = None  # wallet key for EIP-712 signing

    # CCXT (testing on other venues)
    ccxt_exchange_id: str = "binanceusdm"
    ccxt_api_key: str = ""
    ccxt_secret: str = ""
    ccxt_sandbox: bool = True

    default_trail_pct: float = Field(default=0.01, gt=0, lt=1)  # initial 1% protective distance
