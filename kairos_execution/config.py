"""Execution engine configuration."""
from __future__ import annotations

from typing import Optional

from kairos_core.config import CoreSettings


class ExecSettings(CoreSettings):
    service_name: str = "kairos-execution-engine"

    exchange: str = "evedex"            # evedex | ccxt
    dry_run: bool = True                # never sends real orders unless explicitly disabled

    # EVEDEX
    evedex_exchange_url: str = "https://exchange-api.evedex.com"
    evedex_chain_id: int = 1
    evedex_jwt: Optional[str] = None
    evedex_private_key: Optional[str] = None  # wallet key for EIP-712 signing

    # CCXT (testing on other venues)
    ccxt_exchange_id: str = "binanceusdm"
    ccxt_api_key: str = ""
    ccxt_secret: str = ""
    ccxt_sandbox: bool = True

    default_trail_pct: float = 0.01     # 1% trailing stop
