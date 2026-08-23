"""Fail-closed startup boundary for the strict EVEDEX DEV PAPER mode."""

from __future__ import annotations

from pathlib import Path

import pytest
from kairos_core.enums import EvedexProfile, TradingMode
from pydantic import ValidationError

from kairos_execution.adapters.evedex_sidecar import EvedexSidecarAdapter
from kairos_execution.config import ExecSettings
from kairos_execution.factory import build_adapter
from kairos_execution.profiles import profile_params


def _paper_values(tmp_path: Path) -> dict[str, object]:
    return {
        "trading_mode": TradingMode.PAPER,
        "environment": "paper-dev",
        "bus_backend": "redis",
        "account_id": "kairos-paper-dev-01",
        "evedex_dev_api_key_file": tmp_path / "evedex-api.secret",
        "evedex_dev_private_key_file": tmp_path / "evedex-signing.secret",
        "evedex_dev_expected_account_id": "remote-paper-account-01",
    }


def test_exact_dev_paper_profile_builds_only_the_sidecar(tmp_path: Path) -> None:
    settings = ExecSettings(**_paper_values(tmp_path))

    adapter = build_adapter(settings)

    assert isinstance(adapter, EvedexSidecarAdapter)
    assert settings.evedex_profile is EvedexProfile.DEV
    assert settings.evedex_chain_id == 16182
    assert settings.evedex_exchange_url == "https://trading-api.evedex.tech"
    assert set(adapter.symbol_map.values()) == {
        "BTCUSD:DEV",
        "ETHUSD:DEV",
        "SOLUSD:DEV",
        "BNBUSD:DEV",
        "XRPUSD:DEV",
    }


def test_all_profile_constants_match_the_reviewed_official_sdk_master() -> None:
    assert profile_params(EvedexProfile.DEV).chain_id == 16182
    assert profile_params(EvedexProfile.DEV).instrument_suffix == ":DEV"
    assert profile_params(EvedexProfile.DEMO).exchange_url == "https://trading-api.evedex.io"
    assert profile_params(EvedexProfile.DEMO).auth_url == "https://auth-api.evedex.io"
    assert profile_params(EvedexProfile.DEMO).chain_id == 16182
    assert profile_params(EvedexProfile.DEMO).instrument_suffix == ":DEMO"
    assert profile_params(EvedexProfile.PROD).exchange_url == "https://trading-api.evedex.com"
    assert profile_params(EvedexProfile.PROD).auth_url == "https://auth-api.evedex.com"
    assert profile_params(EvedexProfile.PROD).chain_id == 161803
    assert profile_params(EvedexProfile.PROD).instrument_suffix == ""


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"bus_backend": "memory"}, "durable PostgreSQL"),
        ({"bus_backend": "nats"}, "durable PostgreSQL"),
        ({"exchange": "ccxt"}, "official EVEDEX gateway"),
        ({"environment": "prod"}, "normalized paper/paper-dev allowlist"),
        ({"environment": "production"}, "normalized paper/paper-dev allowlist"),
        ({"environment": "paper-test"}, "normalized paper/paper-dev allowlist"),
        ({"environment": " PAPER-DEV "}, "normalized paper/paper-dev allowlist"),
        ({"account_id": "primary"}, "kairos-paper-dev-"),
        ({"account_id": "paper-account"}, "kairos-paper-dev-"),
        ({"account_id": "Kairos-Paper-Dev-01"}, "kairos-paper-dev-"),
        ({"evedex_profile": EvedexProfile.PROD}, "EVEDEX DEV profile"),
        ({"evedex_exchange_url": "https://trading-api.evedex.com"}, "exactly match"),
        ({"evedex_auth_url": "https://auth-api.evedex.com"}, "exactly match"),
        ({"evedex_chain_id": 421614}, "exactly match"),
        ({"evedex_chain_id": 161803}, "exactly match"),
        ({"evedex_jwt": "legacy-live-token"}, "legacy JWT"),
        ({"evedex_private_key": "0x" + "11" * 32}, "live signing credentials"),
        ({"ccxt_api_key": "wrong-venue-key"}, "CCXT credentials"),
        ({"evedex_dev_expected_account_id": None}, "remote account identity"),
        ({"evedex_dev_expected_account_id": " paper-account "}, "remote account identity"),
        ({"trading_symbols": ["BTCUSDT", "ETHUSDT"]}, "five-symbol"),
        (
            {
                "evedex_dev_symbol_map": {
                    "BTCUSDT": "BTCUSD",
                    "ETHUSDT": "ETHUSD:DEV",
                    "SOLUSDT": "SOLUSD:DEV",
                    "BNBUSDT": "BNBUSD:DEV",
                    "XRPUSDT": "XRPUSD:DEV",
                }
            },
            "five-symbol",
        ),
        (
            {
                "evedex_dev_symbol_map": {
                    "btcusdt": "BTCUSD:DEV",
                    "ETHUSDT": "ETHUSD:DEV",
                    "SOLUSDT": "SOLUSD:DEV",
                    "BNBUSDT": "BNBUSD:DEV",
                    "XRPUSDT": "XRPUSD:DEV",
                }
            },
            "five-symbol",
        ),
        ({"evedex_sidecar_node": "C:/tools/node-wrapper.exe"}, "must be Node.js"),
        ({"evedex_sidecar_node": "C:/tools/node.exe"}, "must be Node.js"),
    ],
)
def test_paper_rejects_every_profile_or_authority_escape(
    tmp_path: Path, override: dict[str, object], message: str
) -> None:
    values = _paper_values(tmp_path)
    values.update(override)

    with pytest.raises(ValidationError, match=message):
        ExecSettings(**values)


def test_paper_rejects_custom_sidecar_script(tmp_path: Path) -> None:
    values = _paper_values(tmp_path)
    values["evedex_sidecar_script"] = tmp_path / "main.js"

    with pytest.raises(ValidationError, match="bundled EVEDEX sidecar"):
        ExecSettings(**values)


def test_paper_requires_two_distinct_absolute_secret_paths(tmp_path: Path) -> None:
    values = _paper_values(tmp_path)
    values["evedex_dev_private_key_file"] = values["evedex_dev_api_key_file"]
    with pytest.raises(ValidationError, match="must be separate"):
        ExecSettings(**values)

    values = _paper_values(tmp_path)
    values["evedex_dev_api_key_file"] = Path("relative.secret")
    with pytest.raises(ValidationError, match="must be absolute"):
        ExecSettings(**values)


def test_live_mode_is_compile_time_disabled() -> None:
    with pytest.raises(ValidationError, match="not LIVE_READY"):
        ExecSettings(trading_mode=TradingMode.LIVE)


def test_legacy_false_is_a_startup_error_not_an_authority_switch() -> None:
    with pytest.raises(ValidationError, match="never enables PAPER or LIVE"):
        ExecSettings(dry_run=False)
