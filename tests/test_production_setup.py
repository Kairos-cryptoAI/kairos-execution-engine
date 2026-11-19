"""The owner's production setup end to end: real database and drills, synthetic wallet and venue."""

from __future__ import annotations

import asyncio
import json
import secrets
import subprocess
import sys
import time
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest

from kairos_execution import production_reads, production_setup
from kairos_execution.production_alerts import TelegramChannel
from kairos_execution.production_owner import store_artifact
from kairos_execution.production_provisioning import ProvisionedDatabaseV1
from kairos_execution.production_readiness import EvidenceKind, ProductionContextV1, ReceiptReferenceV1
from kairos_execution.signed_evidence import FACT_SCHEMAS, DirectoryEvidenceResolver, IssuerPolicyV1
from kairos_execution.technical_canary_readiness import TechnicalCanaryPreconditionsVerifier
from tests.rest_stand import stand_admin_dsn, stand_container
from tests.test_integration_rest_session import _drop
from tests.test_production_alerts import SYNTHETIC_CHAT_ID, FakeTelegram

OWNER_TELEGRAM_ID = 5


def test_keys_file_values_follow_the_runners_rule(tmp_path):
    keys = tmp_path / "keys.txt"
    keys.write_text("note\nwallet: 0xabc\nAPI = k-1\nspaced: a b\n", encoding="utf-8")
    assert production_setup.keys_file_value(keys, 2, "wallet") == "0xabc"
    assert production_setup.keys_file_value(keys, 3, "api") == "k-1"
    assert production_setup.keys_file_value(keys, 1, "bare") == "note"
    for line in (4, 9):
        with pytest.raises(production_setup.SetupError) as refused:
            production_setup.keys_file_value(keys, line, "api")
        assert "a b" not in str(refused.value)


def test_account_identity_comes_from_user_me_without_echoing_the_key():
    class Answer:
        def __init__(self, body):
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self, limit):
            return json.dumps(self.body).encode()

    seen = []

    def opener(request, timeout):
        seen.append((request.full_url, request.get_header("X-api-key")))
        return Answer({"exchangeId": 4242})

    assert production_setup.evedex_account_id("secret-key", opener=opener) == "4242"
    assert seen == [("https://trading-api.evedex.com/api/user/me", "secret-key")]

    def failing(request, timeout):
        raise OSError("connection refused for secret-key")

    with pytest.raises(production_setup.SetupError) as refused:
        production_setup.evedex_account_id("secret-key", opener=failing)
    assert "secret-key" not in str(refused.value)


def _synthetic_workspace(root: Path) -> Path:
    for name, filename in (
        ("kairos-execution-engine", "docs/PRODUCTION-SESSION.md"),
        ("kairos-autotrader", "kairos_autotrader/management.py"),
    ):
        repo = root / name
        source = repo / filename
        source.parent.mkdir(parents=True)
        source.write_text("# Synthetic setup test source\n", encoding="utf-8")
        subprocess.run(["git", "init", "--quiet", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "add", filename], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "--quiet",
                "--no-gpg-sign",
                "-m",
                "Add synthetic setup fixture",
            ],
            check=True,
        )
    return root


@pytest.mark.integration
def test_setup_produces_seven_receipts_the_system_accepts(tmp_path, monkeypatch):
    admin_dsn = stand_admin_dsn()
    container = stand_container()
    workspace = _synthetic_workspace(tmp_path / "workspace")
    root = tmp_path / "prod"
    (root / "secrets").mkdir(parents=True)
    (root / "secrets" / "postgres-admin.dsn").write_text(admin_dsn, encoding="utf-8")
    keys = tmp_path / "keys.txt"
    wallet_key = "0x" + secrets.token_hex(32)
    keys.write_text(
        "\n".join(["a", "b", "c", "d", "e", f"wallet: {wallet_key}", "g", "h", "evedex api: test-api-key"])
        + "\n",
        encoding="utf-8",
    )
    limits = production_setup._runner_limits(None)
    summary = production_setup.init(
        root,
        keys_file=keys,
        wallet_line=6,
        api_line=9,
        owner_identity="owner",
        owner_telegram_id=OWNER_TELEGRAM_ID,
        workspace=workspace,
        instruments=("SOLUSD", "XRPUSD"),
        limits=limits,
        node_executable=tmp_path / "node",  # FakeReads supplies the venue response.
        quant_python=Path(sys.executable),
        taker_fee_bps=4.5,
        exit_fee_rate=Decimal("0.00045"),
        adverse_slippage_rate=Decimal("0.0005"),
        account_reader=lambda api_key: "synthetic-setup-account",
    )
    paths = production_setup._paths(root)
    manifest = ProvisionedDatabaseV1.load(paths["manifest"])
    try:
        assert wallet_key not in json.dumps(summary)
        for name in ("keystore", "unlock", "backup_keystore", "backup_unlock", "api_key"):
            assert paths[name].exists()
        assert "test-api-key" not in paths["session"].read_text(encoding="utf-8")
        with pytest.raises(production_setup.SetupError):
            production_setup.init(
                root,
                keys_file=keys,
                wallet_line=6,
                api_line=9,
                owner_identity="owner",
                owner_telegram_id=OWNER_TELEGRAM_ID,
                workspace=workspace,
                instruments=("SOLUSD",),
                limits=limits,
                node_executable=Path("x"),
                quant_python=Path("x"),
                taker_fee_bps=4.5,
                exit_fee_rate=Decimal("0.00045"),
                adverse_slippage_rate=Decimal("0.0005"),
                account_reader=lambda api_key: "other",
            )

        class FakeReads:
            def __init__(self, client, *, symbol_map):
                self.client = client

            async def preflight(self):
                return {"account_capture": {"exchangeId": "synthetic-setup-account"}}

            async def close(self):
                return None

        monkeypatch.setattr(production_reads, "ProductionEvedexReads", FakeReads)
        done = production_setup.run_drills(
            root,
            workspace=workspace,
            container=container,
            only=("recovery", "operator", "custody", "pairing"),
        )
        assert len(done) == 4
        # The limits drill runs both repositories' limit suites (minutes); its facts here
        # come from the same schema with stand artifacts.
        artifact = store_artifact(paths["evidence"], b"synthetic limits stand")
        limits_facts = FACT_SCHEMAS[EvidenceKind.PRODUCTION_LIMITS].model_validate(
            {
                "artifact_sha256s": (artifact,),
                "owner_identity": "owner",
                "dollar_cap": Decimal(str(limits["max_account_equity_usd"])),
                "daily_stop_loss_usd": Decimal(str(limits["daily_loss_cap_usd"])),
                "risk_per_trade_fraction": Decimal("0.0025"),
                "maximum_total_open_risk_fraction": Decimal("0.01"),
                "maximum_leverage": 1,
                "blocked_missing_limit_count": 1,
                "blocked_over_cap_count": 1,
                "blocked_daily_stop_count": 1,
                "restart_accounting_receipt_sha256": artifact,
                "pending_risk_receipt_sha256": artifact,
            }
        )
        (paths["facts"] / f"{EvidenceKind.PRODUCTION_LIMITS.value}.json").write_text(
            limits_facts.model_dump_json(), encoding="utf-8"
        )
        production_setup.security_review(
            root,
            reviewer="owner",
            fix_commit=summary["source_heads"]["kairos-execution-engine"],
            findings_fixed=4,
            workspace=workspace,
            statement="synthetic test record",
        )
        with pytest.raises(production_setup.SetupError, match="alert_delivery"):
            production_setup.refresh(root)

        telegram = FakeTelegram(lambda: datetime.now(UTC))
        token = tmp_path / "token.txt"
        token.write_text("bot: 123456:" + "A" * 35 + "\n", encoding="utf-8")

        def owner_taps(seconds):
            for index, message in enumerate(telegram.sent):
                pressed = {p["callback_query"]["data"] for p in telegram.presses}
                if message["text"].startswith("ВОССТАНОВЛЕНО") and message["ack"] not in pressed:
                    telegram.press(index, user_id=OWNER_TELEGRAM_ID)
            time.sleep(seconds)

        production_setup.alert_drill(
            root,
            token_file=token,
            token_line=None,
            chat_id=SYNTHETIC_CHAT_ID,
            wait_s=60,
            sleep=owner_taps,
            channel_factory=lambda **kwargs: TelegramChannel(**kwargs, http=telegram),
        )
        assert production_setup.refresh(root)["refreshed"] is True
        assert production_setup.refresh(root)["refreshed"] is False, "fresh receipts are kept"
        status = production_setup.status(root)
        assert all(status["facts"].values())

        session = json.loads(paths["session"].read_text(encoding="utf-8"))
        registry = tuple(
            IssuerPolicyV1.model_validate_json(json.dumps(item))
            for item in json.loads(paths["registry"].read_text())
        )
        verifier = TechnicalCanaryPreconditionsVerifier(
            registry,
            DirectoryEvidenceResolver(Path(session["evidence_dir"])),
            pinned_registry_sha256=session["pinned_registry_sha256"],
        )
        context = ProductionContextV1.model_validate_json(paths["context"].read_text())
        references = [
            ReceiptReferenceV1.model_validate_json(json.dumps(item))
            for item in json.loads(paths["references"].read_text())
        ]
        verified = verifier.verify(context, references, now=datetime.now(UTC))
        assert verified is not None
        from kairos_execution.production_session_cli import SessionConfigV1

        loaded = SessionConfigV1.model_validate_json(paths["session"].read_text(encoding="utf-8"))
        assert loaded.limits["max_leverage"] == 1.0 and loaded.api_key_file == paths["api_key"]
    finally:
        asyncio.run(_drop(admin_dsn, manifest.database, manifest.roles.values()))
