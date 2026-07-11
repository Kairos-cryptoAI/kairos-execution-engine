"""Fail-closed tests for exchange adapter construction."""
import pytest

from kairos_execution.config import ExecSettings
from kairos_execution.factory import build_adapter


def test_live_evedex_requires_private_key():
    settings = ExecSettings(exchange="evedex", dry_run=False, evedex_jwt="jwt")
    with pytest.raises(ValueError, match="EVEDEX_PRIVATE_KEY"):
        build_adapter(settings)


def test_live_evedex_requires_jwt():
    settings = ExecSettings(
        exchange="evedex", dry_run=False, evedex_private_key="0x" + "11" * 32
    )
    with pytest.raises(ValueError, match="EVEDEX_JWT"):
        build_adapter(settings)


def test_live_ccxt_requires_api_credentials():
    settings = ExecSettings(exchange="ccxt", dry_run=False)
    with pytest.raises(ValueError, match="CCXT_API_KEY"):
        build_adapter(settings)


def test_dry_run_remains_keyless():
    adapter = build_adapter(ExecSettings(exchange="evedex", dry_run=True))
    assert adapter.dry_run is True
