"""Fail-closed tests for exchange adapter construction."""

import pytest
from pydantic import ValidationError

from kairos_execution.config import ExecSettings
from kairos_execution.factory import build_adapter


def test_legacy_false_never_enables_live_evedex():
    with pytest.raises(ValidationError, match="KAIROS_DRY_RUN=false is retired"):
        ExecSettings(exchange="evedex", dry_run=False, evedex_jwt="jwt")


def test_legacy_false_never_enables_live_signing():
    with pytest.raises(ValidationError, match="never enables PAPER or LIVE"):
        ExecSettings(exchange="evedex", dry_run=False, evedex_private_key="0x" + "11" * 32)


def test_legacy_false_never_enables_live_ccxt():
    with pytest.raises(ValidationError, match="KAIROS_DRY_RUN=false is retired"):
        ExecSettings(exchange="ccxt", dry_run=False)


def test_dry_run_remains_keyless():
    adapter = build_adapter(ExecSettings(exchange="evedex", dry_run=True))
    assert adapter.dry_run is True
    assert adapter._venue_symbol("BTCUSDT") == "BTCUSD"
