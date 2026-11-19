"""Offline regression tests for the signed profile boundary. All account identities are synthetic."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from kairos_execution import portfolio_profile as profile
from kairos_execution.prod_universe import PROD_INSTRUMENTS


def write_json(path, obj):
    path.write_text(json.dumps(obj), encoding="utf-8")


@pytest.fixture
def provisioned(tmp_path):
    root = tmp_path / "execution-prod"
    runtime = tmp_path / "runner"
    facts = root / "facts"
    facts.mkdir(parents=True)
    runtime.mkdir()
    wallet = "0x" + "a1" * 20
    digest = "b" * 64
    context = dict(
        remote_account_id="sample-exchange-id",
        adaptive_system_id="test-strategy",
        frozen_policy_sha256=digest,
        source_set_sha256=digest,
    )
    custody = dict(
        context=context,
        custody_reference="sample-custody",
        wallet_address=wallet,
        chain_id=42161,
        schema_sha256=digest,
        approved_instruments=["BTCUSD"],
        custody_receipt_sha256=digest,
    )
    pairing = dict(
        environment="PROD",
        remote_account_id=context["remote_account_id"],
        wallet_address=wallet,
        chain_id=42161,
        authenticated_read_challenge_sha256=digest,
        signing_challenge_sha256=digest,
        artifact_sha256s=[digest],
        credential_pairing_conflicts=0,
    )
    write_json(root / "context.json", context)
    write_json(root / "settings.json", {"context": context, "custody_binding": custody})
    write_json(facts / "prod_account_pairing.json", pairing)
    write_json(runtime / "config.json", {"symbols": sorted(PROD_INSTRUMENTS)[:23]})
    return root, runtime


def test_prepare_is_offline_unsigned_no_overwrite_and_scope_is_exact(provisioned, tmp_path):
    root, runtime = provisioned
    path = tmp_path / "draft"
    args = [
        "prepare",
        "--production-root",
        str(root),
        "--runner-runtime-dir",
        str(runtime),
        "--entry-deadline-utc",
        "2026-11-22T21:00:00Z",
        "--output",
        str(path),
    ]
    assert profile.main(args) == 0
    raw = path.read_bytes()
    parsed = profile.PortfolioProfile.model_validate_json(raw)
    assert parsed.entry_deadline_utc == profile.PILOT_ENTRY_DEADLINE_UTC
    assert parsed.remote_account_id == "sample-exchange-id"
    assert parsed.signer_wallet_sha256 == hashlib.sha256(("0x" + "a1" * 20).encode()).hexdigest()
    assert parsed.journal_path == tmp_path / "execution-portfolio" / "portfolio.sqlite3"
    assert len(parsed.symbols) == 23
    assert not parsed.journal_path.exists()
    assert not Path(str(path) + ".asc").exists()
    assert profile.main(args) == 2
    assert path.read_bytes() == raw
    with pytest.raises(ValueError, match="owner-signed"):
        profile.verify_profile(parsed)


@pytest.mark.parametrize(
    ("field", "val"),
    [
        ("remote_account_id", "other"),
        ("wallet_address", "0x" + "ca" * 20),
        ("chain_id", 1),
        ("credential_pairing_conflicts", 1),
    ],
)
def test_prepare_requires_independent_recorded_pairing(provisioned, field, val):
    root, runtime = provisioned
    pairing_path = root / "facts" / "prod_account_pairing.json"
    pairing = json.loads(pairing_path.read_bytes())
    pairing[field] = val
    write_json(pairing_path, pairing)
    with pytest.raises(ValueError):
        profile.prepare_profile(root, runtime, profile.PILOT_ENTRY_DEADLINE_UTC)


def test_verify_reopens_and_checks_exact_bytes_and_values(provisioned, monkeypatch, tmp_path):
    root, runtime = provisioned
    path = tmp_path / "execution-portfolio" / "owner.json"
    path.parent.mkdir()
    data = profile.prepare_profile(root, runtime, profile.PILOT_ENTRY_DEADLINE_UTC)
    path.write_bytes(data)
    seen = []

    def verified(file, content):
        seen.append((file, content))

    monkeypatch.setattr(profile, "_require_owner_signature", verified)
    loaded = profile.load_portfolio_profile(path)
    assert profile.verify_profile(loaded).model_dump() == loaded.model_dump()
    assert seen == [(path, data), (path, data)]
    with pytest.raises(ValueError, match="changed"):
        profile.verify_profile(loaded.model_copy(update={"max_leverage": 99}))
    path.write_bytes(data + b" ")
    with pytest.raises(ValueError, match="changed"):
        profile.verify_profile(loaded)
    path.write_bytes(data.replace(b'"max_positions":', b'"max_positions": 1, "max_positions":'))
    with pytest.raises(ValueError, match="duplicate"):
        profile.load_portfolio_profile(path)


@pytest.mark.parametrize(
    ("field", "val"),
    [
        ("max_leverage", 31),
        ("capital_usd", 1000),
        ("entry_deadline_utc", "2026-11-22T21:00:00"),
        ("entry_deadline_utc", "2026-11-22T23:00:00+02:00"),
        ("entry_deadline_utc", "2026-11-23T21:00:00Z"),
        ("entry_window_hours", 168),
        ("symbols", ["BTCUSD"] * 23),
        ("signer_wallet_sha256", "0" * 64),
    ],
)
def test_only_fixed_mandate_is_accepted(provisioned, field, val):
    root, runtime = provisioned
    fields = json.loads(profile.prepare_profile(root, runtime, profile.PILOT_ENTRY_DEADLINE_UTC))
    fields[field] = val
    with pytest.raises(ValueError):
        profile.PortfolioProfile.model_validate_json(json.dumps(fields))


@pytest.mark.parametrize(
    ("fingerprint", "hash_id", "kind", "extra", "status", "accepted"),
    [
        (profile.OWNER_FINGERPRINT, "10", "00", "", 0, True),
        ("F" * 40, "10", "00", "", 0, False),
        (profile.OWNER_FINGERPRINT, "2", "00", "", 0, False),
        (profile.OWNER_FINGERPRINT, "10", "01", "", 0, False),
        (profile.OWNER_FINGERPRINT, "10", "00", "[GNUPG:] EXPKEYSIG FAKE expired\n", 0, False),
        (profile.OWNER_FINGERPRINT, "10", "00", "", 1, False),
    ],
)
def test_gpg_status_and_primary_fingerprint(
    monkeypatch, tmp_path, fingerprint, hash_id, kind, extra, status, accepted
):
    monkeypatch.setattr(profile, "_gpg", lambda: "gpg")
    path = tmp_path / "owner.json"

    def verify(args, **opts):
        assert args[-3:] == ["--verify", str(path) + ".asc", "-"]
        assert opts["input"] == b"content"
        record = (
            f"[GNUPG:] VALIDSIG {'F' * 40} 2026-11-19 1795050000 0 4 0 22 {hash_id} {kind} {fingerprint}\n"
        )
        return subprocess.CompletedProcess(args, status, stdout=(record + extra).encode(), stderr=b"")

    monkeypatch.setattr(profile.subprocess, "run", verify)
    if accepted:
        profile._require_owner_signature(path, b"content")
    else:
        with pytest.raises(ValueError):
            profile._require_owner_signature(path, b"content")
