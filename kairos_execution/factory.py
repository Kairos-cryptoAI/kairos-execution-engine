"""Build the configured exchange adapter."""

from __future__ import annotations

from .adapters.base import ExchangeAdapter
from .config import ExecSettings
from .profiles import TradingMode


def build_adapter(settings: ExecSettings) -> ExchangeAdapter:
    if settings.trading_mode is TradingMode.PAPER:
        if settings.exchange != "evedex":
            raise ValueError("PAPER is restricted to EVEDEX")
        from .adapters.evedex_sidecar import EvedexSidecarAdapter
        from .sidecar import EvedexSidecarClient

        api_key_file = settings.evedex_dev_api_key_file
        signing_key_file = settings.evedex_dev_private_key_file
        expected_account_id = settings.evedex_dev_expected_account_id
        node_runtime = settings.evedex_sidecar_node
        if (
            api_key_file is None
            or signing_key_file is None
            or expected_account_id is None
            or node_runtime is None
        ):
            raise ValueError("PAPER DEV credentials did not pass startup validation")
        client = EvedexSidecarClient(
            node_executable=node_runtime,
            script=settings.evedex_sidecar_script,
            api_key_file=api_key_file,
            private_key_file=signing_key_file,
            expected_account_id=expected_account_id,
            timeout_s=settings.evedex_sidecar_timeout_s,
        )
        return EvedexSidecarAdapter(client, symbol_map=settings.evedex_dev_symbol_map)
    if settings.trading_mode is TradingMode.LIVE:
        raise ValueError("LIVE is disabled: this release is not LIVE_READY")
    if settings.exchange == "evedex":
        from .adapters.evedex import EvedexAdapter

        signer = _NullSigner()
        return EvedexAdapter(
            exchange_base_url=settings.evedex_exchange_url,
            signer=signer,
            chain_id=settings.evedex_chain_id,
            jwt=settings.evedex_jwt,
            dry_run=True,
            dry_run_equity_usd=settings.dry_run_equity_usd,
            symbol_map=settings.evedex_symbol_map,
        )
    if settings.exchange == "ccxt":
        from .adapters.ccxt_adapter import CCXTAdapter

        return CCXTAdapter(
            settings.ccxt_exchange_id,
            api_key=settings.ccxt_api_key,
            secret=settings.ccxt_secret,
            sandbox=settings.ccxt_sandbox,
            dry_run=True,
            dry_run_equity_usd=settings.dry_run_equity_usd,
        )
    raise ValueError(f"Unknown exchange: {settings.exchange!r}")


class _NullSigner:
    """Placeholder signer for dry-run / paper trading (produces a dummy signature)."""

    address = "0x0000000000000000000000000000000000000000"

    def sign_typed_data(self, domain, types, message) -> str:
        return "0x" + "00" * 65
