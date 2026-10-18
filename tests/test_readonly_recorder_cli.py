from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

import pytest

from kairos_execution import readonly_recorder_cli as cli


def configuration(tmp_path: Path, **updates) -> cli.RecorderConfig:
    data = {
        "version": "dev-readonly-recorder.v1",
        "scope": {
            "environment": "paper-dev",
            "account_id": "kairos-paper-dev-observer",
            "remote_account_id": "fixture-account-not-an-authenticated-identity",
            "config_sha256": "a" * 64,
            "recorder_code_sha256": "b" * 64,
        },
        "database_name": "kairos_paper_gate_0123456789ab",
        "database_host": "127.0.0.1",
        "database_port": 5432,
        "database_instance_id": str(uuid4()),
        "database_url_file": str(tmp_path / "database.txt"),
        "jwt_file": str(tmp_path / "jwt.txt"),
        **updates,
    }
    return cli.RecorderConfig.model_validate_json(json.dumps(data))


@pytest.mark.parametrize(
    "name",
    ["kairos", "postgres", "kairos_epoch_69893dc7b7c6", "kairos_sim", "kairos_paper_gate_../primary"],
)
def test_refuses_legacy_epoch_and_sim_database_names(tmp_path, name):
    with pytest.raises(ValueError):
        configuration(tmp_path, database_name=name)


@pytest.mark.parametrize("value", [0, 120_000, True, 15_000.0])
def test_refuses_invalid_cadence(tmp_path, value):
    with pytest.raises(ValueError):
        configuration(tmp_path, sample_period_ms=value)


def test_config_fingerprint_excludes_only_its_two_recursive_digest_fields(tmp_path):
    config = configuration(tmp_path)
    scope = config.scope.model_copy(update={"config_sha256": "c" * 64, "recorder_code_sha256": "d" * 64})
    assert (
        config.model_copy(update={"scope": scope}).expected_config_sha256() == config.expected_config_sha256()
    )
    changed = config.model_copy(update={"sample_period_ms": 30_000})
    assert changed.expected_config_sha256() != config.expected_config_sha256()
    changed = config.model_copy(update={"database_instance_id": uuid4()})
    assert changed.expected_config_sha256() != config.expected_config_sha256()


def test_inspect_reads_no_secret_and_cannot_connect(tmp_path, monkeypatch, capsys):
    config = configuration(tmp_path)
    config_path = tmp_path / "recorder.json"
    config_path.write_text(config.model_dump_json(), encoding="utf-8")

    def tripwire(*args, **kwargs):
        raise AssertionError("no secret access or connection during inspect")

    monkeypatch.setattr(cli, "_secret", tripwire)
    monkeypatch.setattr(cli, "Database", tripwire)
    monkeypatch.setattr(cli, "recorder_code_sha256", lambda: "e" * 64)
    assert cli.main(["inspect-config", "--config", str(config_path)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["trading_authority"] == "NONE"
    assert result["config_sha256"] == config.expected_config_sha256()


def test_record_requires_its_specific_confirmation(tmp_path, monkeypatch, capsys):
    config_path = tmp_path / "recorder.json"
    config_path.write_text(configuration(tmp_path).model_dump_json(), encoding="utf-8")

    async def tripwire(*args, **kwargs):
        raise AssertionError("record must not be invoked")

    monkeypatch.setattr(cli, "record", tripwire)
    assert cli.main(["record", "--config", str(config_path)]) == 1
    assert capsys.readouterr().out.strip() == "DEV_READONLY_RECORDER_REFUSED_NO_RETRY"


@pytest.mark.asyncio
async def test_binding_mismatch_refuses_before_opening_credentials(tmp_path, monkeypatch):
    config = configuration(tmp_path)

    def tripwire(*args, **kwargs):
        raise AssertionError("must not read credentials")

    monkeypatch.setattr(cli, "_secret", tripwire)
    with pytest.raises(ValueError, match="binding differs"):
        await cli.record(config)


def test_error_output_cannot_include_raw_driver_secrets(tmp_path, monkeypatch, capsys):
    path = tmp_path / "config.json"
    path.write_text(configuration(tmp_path).model_dump_json(), encoding="utf-8")

    async def fail(config):
        raise RuntimeError("Bearer fixture-secret-do-not-log postgresql://fixture-password")

    monkeypatch.setattr(cli, "record", fail)
    assert cli.main(["record", "--config", str(path), "--confirm", cli.CONFIRMATION]) == 1
    assert capsys.readouterr().out.strip() == "DEV_READONLY_RECORDER_REFUSED_NO_RETRY"


def test_secret_reader_refuses_multiline_and_does_not_expose_value(tmp_path):
    path = tmp_path / "fixture.txt"
    path.write_text("fixture\nsecret", encoding="utf-8")
    with pytest.raises(ValueError, match="malformed"):
        cli._secret(path)


@pytest.mark.asyncio
async def test_host_port_change_refuses_before_database_connect(tmp_path, monkeypatch):
    config = configuration(tmp_path)
    scope = config.scope.model_copy(
        update={"config_sha256": config.expected_config_sha256(), "recorder_code_sha256": "e" * 64}
    )
    config = config.model_copy(update={"scope": scope})
    monkeypatch.setattr(cli, "recorder_code_sha256", lambda: "e" * 64)
    monkeypatch.setattr(cli, "_secret", lambda path: "postgresql://fixture@127.0.0.1:5433/unused")
    with pytest.raises(ValueError, match="host/port differs"):
        await cli.record(config)
