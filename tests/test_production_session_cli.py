"""The runner-facing command refuses bad input with one sanitized JSON line."""

from __future__ import annotations

import json

from kairos_execution import production_session_cli as cli


def test_bad_config_is_refused_with_one_json_line_and_exit_code_2(tmp_path, capsys):
    config = tmp_path / "session.json"
    config.write_text(json.dumps({"manifest": "x"}), encoding="utf-8")
    candidate = tmp_path / "candidate.json"
    candidate.write_text("{}", encoding="utf-8")
    assert cli.main(["--config", str(config), "--candidate", str(candidate)]) == 2
    answer = json.loads(capsys.readouterr().out.strip())
    assert answer["outcome"] == "CONFIG_REFUSED"


def test_a_failed_session_is_reported_as_unresolved_without_a_traceback(tmp_path, capsys, monkeypatch):
    async def explode(config, candidate, **kwargs):
        raise RuntimeError("synthetic failure")

    monkeypatch.setattr(cli, "run", explode)
    monkeypatch.setattr(cli.SessionConfigV1, "model_validate_json", classmethod(lambda cls, text: object()))
    monkeypatch.setattr(cli.CandidateV1, "model_validate_json", classmethod(lambda cls, text: object()))
    (tmp_path / "c.json").write_text("{}", encoding="utf-8")
    assert cli.main(["--config", str(tmp_path / "c.json"), "--candidate", str(tmp_path / "c.json")]) == 4
    answer = json.loads(capsys.readouterr().out.strip())
    assert answer == {"outcome": "UNRESOLVED", "trade_id": None, "detail": "RuntimeError: synthetic failure"}
    assert cli.EXIT_CODES == {"CLOSED_AND_ACCOUNTED": 0, "REFUSED": 3, "UNRESOLVED": 4}


QUANT_PYTHON = __import__("pathlib").Path("D:/Kairos/kairos-quant-scouts/.venv/Scripts/python.exe")


@__import__("pytest").mark.skipif(
    not QUANT_PYTHON.exists(), reason="the Quant Scouts environment is not on this machine"
)
def test_fresh_venue_measurement_comes_from_quant_scouts_within_its_lease(monkeypatch):
    import asyncio
    import os
    import time

    if os.getenv("KAIROS_PUBLIC_NETWORK_TESTS") != "1":
        __import__("pytest").skip("public order books are read only when KAIROS_PUBLIC_NETWORK_TESTS=1")
    from tests.test_production_inputs import _signed_fixture

    review = _signed_fixture()[3]
    started = time.time() * 1000
    venue = asyncio.run(
        cli.quant_venue_provider(QUANT_PYTHON, taker_fee_bps=5.0, assessed_notional_usd=200.0)(review)
    )
    assert venue.symbol == "BTCUSD" and venue.profile.value == "PROD"
    assert started - 1_000 <= venue.observed_at_ms and venue.expires_at_ms - venue.observed_at_ms == 5_000


def test_adaptive_fraction_can_only_lower_the_configured_limit():
    from decimal import Decimal

    from tests.test_production_inputs import _signed_fixture

    review = _signed_fixture()[3]
    configured = {
        "per_trade_risk_fraction": 0.0025,
        "aggregate_open_risk_fraction": 0.01,
        "max_leverage": 1.0,
        "per_trade_dollar_cap_usd": 0.25,
        "aggregate_dollar_cap_usd": 100.0,
        "daily_loss_cap_usd": 5.0,
        "max_account_equity_usd": 200.0,
        "max_position_notional_usd": 33.0,
        "min_notional_usd": 5.0,
    }
    lower = cli.candidate_limits(
        configured, cli.CandidateV1(review=review, per_trade_risk_fraction=Decimal("0.001"))
    )
    higher = cli.candidate_limits(
        configured, cli.CandidateV1(review=review, per_trade_risk_fraction=Decimal("0.01"))
    )
    none = cli.candidate_limits(configured, cli.CandidateV1(review=review))
    assert lower.per_trade_risk_fraction == 0.001
    assert higher.per_trade_risk_fraction == none.per_trade_risk_fraction == 0.0025
    assert (
        cli.candidate_limits(configured, cli.CandidateV1(review=review, per_trade_risk_fraction=Decimal(0)))
        is None
    )


def test_exit_request_file_gives_its_first_line_once_written(tmp_path):
    assert cli.exit_request_reader(None) is None
    path = tmp_path / "candidate.exit-request"
    read = cli.exit_request_reader(path)
    assert read is not None and read() is None
    path.write_text("   \n", encoding="utf-8")
    assert read() is None
    path.write_text("regime BEAR opposes LONG\nsecond line ignored\n", encoding="utf-8")
    assert read() == "regime BEAR opposes LONG"
    path.write_text("x" * 500, encoding="utf-8")
    assert read() == "x" * 200


def test_exit_request_invalid_bytes_and_oversize_are_ignored_then_recover(tmp_path):
    path = tmp_path / "candidate.exit-request"
    read = cli.exit_request_reader(path)
    path.write_bytes(b"\xff\xfe")
    assert read() is None
    path.write_bytes(b"x" * 4097)
    assert read() is None
    path.write_text("close normally\n", encoding="utf-8")
    assert read() == "close normally"


def test_exit_request_rejects_nonregular_files_and_symlinks(tmp_path):
    import os

    import pytest

    assert cli.exit_request_reader(tmp_path)() is None
    target = tmp_path / "target"
    target.write_text("do not follow", encoding="utf-8")
    link = tmp_path / "request"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("this Windows account cannot create symbolic links")
    assert cli.exit_request_reader(link)() is None
    if hasattr(os, "mkfifo"):
        fifo = tmp_path / "fifo"
        os.mkfifo(fifo)
        assert cli.exit_request_reader(fifo)() is None


def test_exit_request_uses_only_first_line_and_keeps_unicode_character_cap(tmp_path):
    path = tmp_path / "request"
    read = cli.exit_request_reader(path)
    path.write_bytes("выход ".encode() + b"\n\xff\xfe")
    assert read() == "выход"
    path.write_text("я" * 500, encoding="utf-8")
    assert read() == "я" * 200
    path.write_text("\nnot a first-line reason", encoding="utf-8")
    assert read() is None


def test_exit_request_rejects_link_swapped_in_after_precheck(tmp_path, monkeypatch):
    import pytest

    path, target = tmp_path / "request", tmp_path / "target"
    path.write_text("original", encoding="utf-8")
    target.write_text("must not be followed", encoding="utf-8")
    probe = tmp_path / "probe"
    try:
        probe.symlink_to(target)
    except OSError:
        pytest.skip("symbolic links are unavailable")
    probe.unlink()
    original = cli._open_exit_request

    def swap_then_open(request):
        request.unlink()
        request.symlink_to(target)
        return original(request)

    monkeypatch.setattr(cli, "_open_exit_request", swap_then_open)
    assert cli.exit_request_reader(path)() is None


def test_closed_trade_summary_takes_the_session_trade_and_names_a_report_failure(monkeypatch):
    import asyncio

    rows = [
        {
            "trade_id": "other",
            "r_multiple": "1",
            "exit_reason": "TARGET",
            "early_exit": None,
            "net_pnl_usd": "1",
        },
        {
            "trade_id": "t1",
            "r_multiple": "-0.12",
            "exit_reason": "TIMEOUT",
            "early_exit": "regime BEAR opposes LONG",
            "net_pnl_usd": "-0.03",
        },
    ]

    async def report(manifest):
        return rows

    monkeypatch.setattr(cli, "closed_trades", report)
    assert asyncio.run(cli.closed_trade_summary(object(), "t1")) == {
        "r_multiple": "-0.12",
        "exit_reason": "TIMEOUT",
        "early_exit": "regime BEAR opposes LONG",
        "net_pnl_usd": "-0.03",
    }
    assert asyncio.run(cli.closed_trade_summary(object(), None)) == {}
    assert "report_error" in asyncio.run(cli.closed_trade_summary(object(), "missing"))

    async def broken(manifest):
        raise OSError("database unavailable")

    monkeypatch.setattr(cli, "closed_trades", broken)
    assert asyncio.run(cli.closed_trade_summary(object(), "t1")) == {
        "report_error": "OSError: database unavailable"
    }
