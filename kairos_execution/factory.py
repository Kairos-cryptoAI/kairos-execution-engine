"""Build the configured exchange adapter."""
from __future__ import annotations

from .adapters.base import ExchangeAdapter
from .config import ExecSettings


def build_adapter(settings: ExecSettings) -> ExchangeAdapter:
    if settings.exchange == "evedex":
        from .adapters.evedex import EvedexAdapter
        from .crypto import EthAccountSigner

        if not settings.dry_run and not settings.evedex_private_key:
            raise ValueError("EVEDEX_PRIVATE_KEY is required when DRY_RUN=false")
        if not settings.dry_run and not settings.evedex_jwt:
            raise ValueError("EVEDEX_JWT is required when DRY_RUN=false")
        use_real_signer = bool(settings.evedex_private_key) and not settings.dry_run
        signer = EthAccountSigner(settings.evedex_private_key) if use_real_signer else _NullSigner()
        return EvedexAdapter(
            exchange_base_url=settings.evedex_exchange_url, signer=signer,
            chain_id=settings.evedex_chain_id, jwt=settings.evedex_jwt, dry_run=settings.dry_run,
        )
    if settings.exchange == "ccxt":
        from .adapters.ccxt_adapter import CCXTAdapter
        if not settings.dry_run and (not settings.ccxt_api_key or not settings.ccxt_secret):
            raise ValueError("CCXT_API_KEY and CCXT_SECRET are required when DRY_RUN=false")
        return CCXTAdapter(
            settings.ccxt_exchange_id, api_key=settings.ccxt_api_key,
            secret=settings.ccxt_secret, sandbox=settings.ccxt_sandbox, dry_run=settings.dry_run,
        )
    raise ValueError(f"Unknown exchange: {settings.exchange!r}")


class _NullSigner:
    """Placeholder signer for dry-run / paper trading (produces a dummy signature)."""

    address = "0x0000000000000000000000000000000000000000"

    def sign_typed_data(self, domain, types, message) -> str:
        return "0x" + "00" * 65
