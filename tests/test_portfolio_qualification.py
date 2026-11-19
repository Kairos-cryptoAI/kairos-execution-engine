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
    triggers = {}

    def order(oid, qty, group, direction, t):
        return dict(
            id=oid,
            quantity=str(qty),
            unFilledQuantity="0",
            side=direction,
            group=group,
            type="MARKET",
            status="FILLED",
            instrument="BTCUSD",
            user="venue-owner",
            updatedAt=f"2026-01-01T10:00:0{t}Z",
        )

    for side in ("BUY", "SELL"):
        for kind in ("stop-loss", "take-profit", "ladder"):
            version = len(cases)
            entry_id = f"entry-{version}"
            other = "SELL" if side == "BUY" else "BUY"
            ladder = kind == "ladder"
            move = (
                ({"before": "95", "after": "99"} if side == "BUY" else {"before": "105", "after": "101"})
                if ladder
                else None
            )
            exits, terminal, cover = {}, {}, {}
            entry = {**order(entry_id, 1, "manually", side, 0), "positionVersions": [version]}
            entries[entry_id] = entry
            records[version] = [entry]
            native_orders = [(".2", "take-profit"), (".1", "take-profit")] if ladder else [("1", kind)]
            remaining = Decimal(1)
            for t, (qty, group) in enumerate(native_orders, start=1):
                oid = f"exit-{version}-{t}"
                exits[oid] = oid
                records[version].append(order(oid, qty, group, other, t))
                triggers[oid] = terminal[oid] = dict(
                    id=oid,
                    instrument="BTCUSD",
                    status="done",
                    type=group,
                    side=other,
                    triggerOrder=entry_id if other == "BUY" else None,
                    triggeredQuantity=qty,
                    quantity=qty if ladder else "0",
                )
                remaining -= Decimal(qty)
                if ladder:
                    cover[oid] = dict(
                        remaining=str(remaining),
                        position_version=version,
                        position_id="position",
                        stops=["new-stop"],
                        remaining_targets=["remaining-target"],
                    )
            terminal["remaining-target"] = dict(status="cancelled", type="take-profit", side=other)
            receipt = dict(
                id=entry_id,
                plan=dict(symbol="BTCUSD", side=side, ladder=ladder),
                status="finished",
                closed_clean=True,
                sibling_cancelled_by_venue=True,
                partial_cover_verified=ladder,
            )
            if ladder:
                close_id = f"timeout-{version}"
                terminal["old-stop"] = dict(status="cancelled", type="stop-loss", side=other)
                terminal["new-stop"] = dict(
                    status="cancelled", type="stop-loss", side=other, price=move["after"]
                )
                records[version].append(
                    {
                        **order(close_id, ".7", "manually", other, 3),
                        "type": "LIMIT" if side == "BUY" else "MARKET",
                    }
                )
                receipt.update(
                    partial_cover_evidence=cover,
                    position_id="position",
                    close_reason="expiry",
                    close_id=close_id,
                    close_qty=".7",
                    close_side=other,
                    stop_move={**move, "from": "old-stop", "to": "new-stop"},
                )
            receipt["child_ids"] = dict.fromkeys(terminal)
            capture = dict(
                schema="kairos.probe-capture.v1",
                history_closed=True,
                version=version,
                terminal_native_orders=terminal,
                receipt=receipt,
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
                    partial_cover_verified=ladder,
                    exits=exits,
                )
            )
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

    api.protection_for_fill = AsyncMock(side_effect=lambda symbol, oid: triggers.get(oid))
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
    assert api.native_ladder_qualified_for("BTCUSD") and api.native_stop_move_qualified_for("BTCUSD")
    api._request = AsyncMock(return_value={})
    api.active_tpsl = AsyncMock(return_value=[])
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
    api.active_tpsl.return_value = [{**target, "quantity": ".7"}]
    with pytest.raises(EvedexError, match="remainder"):
        await api.post_partial_target(target)
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
    assert api.protection_unavailable_for("BTCUSD") is None
    assert not api.native_ladder_qualified_for("BTCUSD") and not api.native_stop_move_qualified_for("BTCUSD")
    stop = {
        "instrument": "BTCUSD",
        "type": "stop-loss",
        "side": "SELL",
        "order": "entry",
        "quantity": "0",
        "price": "95",
    }
    api._request = AsyncMock(return_value={})
    api.positions = AsyncMock(return_value=[Position("BTCUSD", "BUY", Decimal(1), Decimal(100))])
    api.order_with_protections = AsyncMock(
        return_value={"id": "entry", "instrument": "BTCUSD", "side": "BUY", "tpslList": [stop]}
    )
    assert await api.post_tpsl(stop) == {}
    with pytest.raises(EvedexError, match="unqualified stop move"):
        await api.post_tpsl({**stop, "price": "99"})
    assert api._request.await_count == 1
    manifest["cases"][0]["capture_sha256"] = "0" * 64
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="evidence"):
        await api.verify_native_protection(profile)


@pytest.mark.parametrize(
    "field,value",
    [
        ("id", "foreign"),
        ("group", "liquidation"),
        ("side", "BUY"),
        ("type", "STOP"),
        ("status", "CANCELLED"),
    ],
)
async def test_ladder_remainder_accepts_only_its_own_terminal_close(
    evidence, tmp_path, monkeypatch, field, value
):
    profile, api, manifest, records = evidence
    (tmp_path / "native-protection.json").write_text(json.dumps(manifest))
    monkeypatch.setattr(checks, "_require_owner_signature", Mock())
    records[2][-1][field] = value
    with pytest.raises(ValueError):
        await api.verify_native_protection(profile)
    assert api.protection_unavailable_for("BTCUSD")


async def test_ladder_final_does_not_qualify_missing_full_case(evidence, tmp_path, monkeypatch):
    profile, api, manifest, _ = evidence
    del manifest["cases"][0]
    (tmp_path / "native-protection.json").write_text(json.dumps(manifest))
    monkeypatch.setattr(checks, "_require_owner_signature", Mock())
    await api.verify_native_protection(profile)
    assert api.protection_unavailable_for("BTCUSD")


async def test_reviewed_uniform_contract_has_its_own_feature_scope(evidence, tmp_path, monkeypatch):
    profile, api, manifest, _ = evidence
    payload = b"reviewed native protecting-order contract"
    digest = hashlib.sha256(payload).hexdigest()
    (tmp_path / "protection-evidence" / (digest + ".source")).write_bytes(payload)
    manifest["uniform_contract"] = dict(
        instruments=["BTCUSD", "ETHUSD"],
        source_url="https://docs.evedex.com/brackets",
        source_sha256=digest,
        includes_partial_ladder=False,
    )
    (tmp_path / "native-protection.json").write_text(json.dumps(manifest))
    monkeypatch.setattr(checks, "_require_owner_signature", Mock())
    await api.verify_native_protection(profile)
    assert api.protection_unavailable_for("ETHUSD") is None and not api.native_ladder_qualified_for("ETHUSD")
    assert not api.native_stop_move_qualified_for("ETHUSD")


async def test_terminal_native_id_beats_nullable_or_parent_link():
    api = Evedex(Mock())
    rows = [
        {"id": "actual-child", "triggerOrder": "entry", "instrument": "BTCUSD", "status": "done"},
        {"id": "unrelated", "triggerOrder": "actual-child", "instrument": "BTCUSD", "status": "done"},
    ]
    api._request = AsyncMock(return_value={"list": rows, "next": None, "count": len(rows)})
    assert (await api.protection_for_fill("BTCUSD", "actual-child"))["id"] == "actual-child"
