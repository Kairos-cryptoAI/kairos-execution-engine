"""The startup gate replays authenticated closed generations before qualifying a wire route."""

import hashlib
import json
from datetime import UTC, datetime
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from kairos_execution import portfolio_qualification as checks
from kairos_execution.portfolio_evedex import Evedex, EvedexError, Position


@pytest.fixture
def evidence(tmp_path, monkeypatch):
    profile = SimpleNamespace(
        account_id="owner",
        remote_account_id="venue-owner",
        journal_path=tmp_path / "account.db",
        symbols=("BTCUSD", "ETHUSD"),
    )
    monkeypatch.setattr(checks, "verify_profile", lambda q: q)
    folder = tmp_path / "protection-evidence"
    folder.mkdir()
    cases, entries, records = [], {}, {}
    for side in ("BUY", "SELL"):
        for kind in ("stop-loss", "take-profit"):
            version = len(cases)
            entry_id = f"entry-{version}"
            move = dict(before="95", after="99") if side == "BUY" else dict(before="105", after="101")
            exits = {f"{stem}-{version}": f"{stem}-{version}" for stem in ("partial", "partial2", "full")}
            other = "SELL" if side == "BUY" else "BUY"
            terminal = {tid: dict(status="done") for tid in exits}
            terminal["old-stop"] = dict(status="cancelled", type="stop-loss")
            terminal["new-stop"] = dict(status="cancelled", type="stop-loss", side=other, price=move["after"])
            capture = dict(
                schema="kairos.probe-capture.v1",
                history_closed=True,
                version=version,
                terminal_native_orders=terminal,
                receipt=dict(
                    id=entry_id,
                    plan=dict(symbol="BTCUSD", side=side),
                    status="finished",
                    closed_clean=True,
                    sibling_cancelled_by_venue=True,
                    child_ids=dict.fromkeys(terminal),
                    partial_cover_verified=True,
                    stop_move={**move, "from": "old-stop", "to": "new-stop"},
                ),
            )
            payload = json.dumps(capture).encode()
            digest = hashlib.sha256(payload).hexdigest()
            (folder / (digest + ".json")).write_bytes(payload)
            cases.append(
                dict(
                    instrument="BTCUSD",
                    position_version=version,
                    entry_order_id=entry_id,
                    position_side=side,
                    capture_sha256=digest,
                    stop_move=move,
                    closed_clean=True,
                    partial_cover_verified=True,
                    exits=exits,
                )
            )

            def order(oid, qty, group, direction, t):
                return dict(
                    id=oid,
                    quantity=str(qty),
                    unFilledQuantity="0",
                    side=direction,
                    group=group,
                    instrument="BTCUSD",
                    user="venue-owner",
                    updatedAt=f"2026-01-01T10:00:0{t}Z",
                )

            entries[entry_id] = {**order(entry_id, 1, "manually", side, 0), "positionVersions": [version]}
            records[version] = [
                entries[entry_id],
                order(f"partial-{version}", ".2", "take-profit", other, 1),
                order(f"partial2-{version}", ".1", "take-profit", other, 2),
                order(f"full-{version}", ".7", kind, other, 3),
            ]
    manifest = dict(
        version="kairos.evedex-protection.v1",
        adapter="evedex-opposite-side-full-bracket-v1",
        venue="EVEDEX_PROD",
        account_id="owner",
        remote_account_id="venue-owner",
        qualified_at=datetime.now(UTC).isoformat(),
        cases=cases,
    )
    api = Evedex(Mock())
    api.me = AsyncMock(return_value={"exchangeId": "venue-owner"})
    api.order = AsyncMock(side_effect=entries.get)
    api.position_version_closed = AsyncMock(return_value=True)
    api.position_version_orders = AsyncMock(side_effect=lambda symbol, version: records[version])

    async def terminal(symbol, oid):
        for rows in records.values():
            for row in rows:
                if row["id"] == oid:
                    return {
                        **row,
                        "status": "done",
                        "type": row["group"],
                        "triggeredQuantity": row["quantity"],
                    }

    api.protection_for_fill = terminal
    return profile, api, manifest, records


async def test_signed_fill_matrix_and_native_child_admission(evidence, tmp_path, monkeypatch):
    profile, api, manifest, records = evidence
    path = tmp_path / "native-protection.json"
    await api.verify_native_protection(profile)
    assert api.protection_unavailable_for("BTCUSD")
    path.write_text(json.dumps(manifest))
    approve = Mock()
    monkeypatch.setattr(checks, "_require_owner_signature", approve)
    await api.verify_native_protection(profile)
    approve.assert_called_once_with(path, path.read_bytes())
    assert api.protection_unavailable_for("BTCUSD") is None and api.protection_unavailable_for("ETHUSD")
    assert api.native_ladder_qualified_for("BTCUSD")
    api._request = AsyncMock(return_value={})
    api.positions = AsyncMock(return_value=[Position("BTCUSD", "SELL", Decimal(1), Decimal(100))])
    body = {
        "instrument": "BTCUSD",
        "side": "SELL",
        "limitPrice": "100",
        "tpsl": [
            {"type": "stop-loss", "quantity": "0", "side": "BUY", "price": "105"},
            {"type": "take-profit", "quantity": "0", "side": "BUY", "price": "95"},
        ],
    }
    assert await api.post_limit_order(body) == {}
    target = {
        "instrument": "BTCUSD",
        "type": "take-profit",
        "quantity": ".3",
        "side": "BUY",
        "price": "97",
        "order": "existing",
    }
    assert await api.post_partial_target(target) == {}
    for same_side in (body["tpsl"][0], body["tpsl"][1]):
        same_side["side"] = "SELL"
        with pytest.raises(EvedexError):
            await api.post_limit_order(body)
        same_side["side"] = "BUY"
    with pytest.raises(EvedexError):
        await api.post_partial_target({**target, "side": "SELL"})
    assert api._request.await_count == 2
    records[0][1]["side"] = "BUY"
    with pytest.raises(ValueError, match="increased"):
        await api.verify_native_protection(profile)
    assert api.protection_unavailable_for("BTCUSD") and not api.native_ladder_qualified_for("BTCUSD")


async def test_incomplete_signatures_captures_and_fill_history_do_not_qualify(
    evidence, tmp_path, monkeypatch
):
    profile, api, manifest, _ = evidence
    path = tmp_path / "native-protection.json"
    path.write_text(json.dumps(manifest))
    monkeypatch.setattr(checks, "_require_owner_signature", Mock(side_effect=ValueError("invalid signature")))
    with pytest.raises(ValueError, match="signature"):
        await api.verify_native_protection(profile)
    api.me.assert_not_awaited()
    monkeypatch.setattr(checks, "_require_owner_signature", Mock())
    manifest["cases"].pop()
    path.write_text(json.dumps(manifest))
    await api.verify_native_protection(profile)
    assert api.protection_unavailable_for("BTCUSD") and not api.native_ladder_qualified_for("BTCUSD")
    manifest["cases"][0]["capture_sha256"] = "0" * 64
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="evidence"):
        await api.verify_native_protection(profile)
