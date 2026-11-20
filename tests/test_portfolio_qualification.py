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
            old_stop, new_stop, remaining_target = (
                f"old-stop-{version}",
                f"new-stop-{version}",
                f"target-{version}",
            )
            stop_price, take_price = ("95", "105") if side == "BUY" else ("105", "95")
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
                    price=stop_price if group == "stop-loss" else take_price,
                )
                remaining -= Decimal(qty)
                if ladder:
                    cover[oid] = dict(
                        remaining=str(remaining),
                        position_version=version,
                        position_id="position",
                        stops=[new_stop],
                        remaining_targets=[remaining_target],
                    )
            if ladder or kind == "stop-loss":
                terminal[remaining_target] = dict(
                    status="cancelled", type="take-profit", side=other, price=take_price
                )
            if ladder or kind == "take-profit":
                terminal[old_stop] = dict(status="cancelled", type="stop-loss", side=other, price=stop_price)
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
                terminal[new_stop] = dict(
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
                    stop_move={
                        **move,
                        "from": old_stop,
                        "to": new_stop,
                        "confirmed_at": "2026-01-01T10:00:00Z",
                    },
                    standalone_partial_ids=list(exits),
                )
            for key, row in terminal.items():
                row.update(id=key, instrument="BTCUSD")
                row.setdefault("quantity", "0")
            receipt["plan"]["children"] = [
                dict(type=k, side=other, quantity="0", price=p)
                for k, p in (("take-profit", take_price), ("stop-loss", stop_price))
            ]
            receipt["child_ids"] = {key: row.copy() for key, row in terminal.items()}
            triggers.update(terminal)
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

    api.target_history = AsyncMock(
        side_effect=lambda symbol, ids: {key: triggers[key] for key in ids if key in triggers}
    )
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
    expected = Position("BTCUSD", "SELL", Decimal(1), Decimal(100), venue_id="generation", user="owner")
    api.positions = AsyncMock(return_value=[expected])
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
        "order": None,
    }
    assert await api.post_partial_target(target, expected=expected) == {}
    with pytest.raises(EvedexError):
        await api.post_partial_target(target)
    with pytest.raises(EvedexError):
        await api.post_partial_target(
            target,
            expected=Position(
                "BTCUSD", "SELL", Decimal(1), Decimal(100), venue_id="replacement", user="owner"
            ),
        )
    with pytest.raises(EvedexError):
        await api.post_partial_target({**target, "order": "filled-parent"}, expected=expected)
    for same_side in (body["tpsl"][0], body["tpsl"][1]):
        same_side["side"] = "SELL"
        with pytest.raises(EvedexError):
            await api.post_limit_order(body)
        same_side["side"] = "BUY"
    with pytest.raises(EvedexError):
        await api.post_partial_target({**target, "side": "SELL"}, expected=expected)
    api.active_tpsl.return_value = [{**target, "quantity": ".7"}]
    with pytest.raises(EvedexError, match="remainder"):
        await api.post_partial_target(target, expected=expected)
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
        "order": None,
        "quantity": "0",
        "price": "95",
    }
    api._request = AsyncMock(return_value={})
    expected = Position("BTCUSD", "BUY", Decimal(1), Decimal(100), venue_id="generation", user="owner")
    api.positions = AsyncMock(return_value=[expected])
    api.order_with_protections = AsyncMock(
        return_value={"id": "entry", "instrument": "BTCUSD", "side": "BUY", "tpslList": [stop]}
    )
    assert await api.post_tpsl(stop, entry_order_id="entry", expected=expected) == {}
    with pytest.raises(EvedexError):
        await api.post_tpsl({**stop, "order": "entry"}, entry_order_id="entry", expected=expected)
    with pytest.raises(EvedexError, match="unqualified stop move"):
        await api.post_tpsl({**stop, "price": "99"}, entry_order_id="entry", expected=expected)
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


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "early_cancel",
        "late_creation",
        "unrelated_generation",
        "uncertain_cancel",
        "wrong_remaining",
        "late_observation",
        "unbound_stop",
        "wrong_final",
        "foreign_child",
        "changed_history",
    ],
)
async def test_retained_bracket_can_be_proved_across_two_fills_from_terminal_lifetimes(
    evidence, tmp_path, monkeypatch, fault
):
    profile, api, manifest, records = evidence
    spec = manifest["cases"][-1]
    assert spec["position_side"] == "SELL"
    version = spec["position_version"]
    path = tmp_path / "protection-evidence"
    capture = json.loads((path / (spec["capture_sha256"] + ".json")).read_bytes())
    r, history = capture["receipt"], capture["terminal_native_orders"]
    first, second = spec["exits"]
    stop = r["stop_move"]["to"]
    final = r["partial_cover_evidence"][first]["remaining_targets"][0]

    def timestamp(seconds):
        return f"2026-01-01T10:00:0{seconds}Z"

    spec.update(partial_cover_interval="owned-trigger-lifetimes-v1", partial_cover_verified=False)
    r["partial_cover_verified"] = False
    for key in ("close_id", "close_qty", "close_reason", "close_side"):
        del r[key]
    del r["partial_cover_evidence"][second]
    cover = r["partial_cover_evidence"][first]
    cover.update(at=timestamp("1.5"), remaining_targets=[second, final])
    r["stop_move"]["confirmed_at"] = timestamp("0.5")
    r["stop_move_request"] = dict(
        wire_scope="position", old_id=r["stop_move"]["from"], new_id=stop, after=r["stop_move"]["after"]
    )
    r.update(standalone_partial_requests={}, standalone_partial_observations={})
    for key, price, done in [(first, "98", "1.1"), (second, "97", "2.1")]:
        row = history[key]
        row.update(createdAt=timestamp("0.1"), updatedAt=timestamp(done), price=price)
        r["standalone_partial_requests"][key] = dict(
            id=key,
            order=spec["entry_order_id"],
            wire_scope="position",
            position_id="position",
            version=version,
            side="BUY",
            quantity=row["quantity"],
            price=price,
        )
        r["standalone_partial_observations"][key] = dict(
            position_id="position", position_version=version, seen_at=timestamp("0.2")
        )
    history[stop].update(
        createdAt=timestamp("0.3"),
        updatedAt=timestamp("3.1"),
        triggeredQuantity="0",
        cancelledReason="Position closed",
    )
    history[final].update(
        createdAt=timestamp("0.1"),
        updatedAt=timestamp("3.1"),
        status="done",
        triggerOrder=None,
        triggeredQuantity=".7",
    )
    spec["exits"][final] = final
    records[version][-1].update(id=final, type="MARKET", group="take-profit")
    other_orders = api.order.side_effect
    details = {row["id"]: {**row, "positionVersions": [version]} for row in records[version]}
    api.order.side_effect = lambda oid: details.get(oid) or other_orders(oid)
    if fault == "early_cancel":
        history[stop]["updatedAt"] = timestamp("1.8")
    if fault == "late_creation":
        history[final]["createdAt"] = timestamp("1.2")
    if fault == "unrelated_generation":
        details[second]["positionVersions"] = [version + 1]
    if fault == "uncertain_cancel":
        history[stop]["cancelledReason"] = ""
    if fault == "wrong_remaining":
        cover["remaining"] = ".7"
    if fault == "late_observation":
        cover["at"] = timestamp("2.1")
    if fault == "unbound_stop":
        cover["stops"] = [r["stop_move"]["from"]]
    if fault == "wrong_final":
        history[final]["quantity"] = ".7"
    if fault == "foreign_child":
        details[first]["user"] = "another-account"
    for row in history.values():
        row.setdefault("cancelledReason", "")
        row.setdefault("triggerOrder", None)
        row.setdefault("triggeredQuantity", "0")
        row.setdefault("createdAt", timestamp("0.1"))
        row.setdefault("updatedAt", timestamp("0.4"))
    capture["terminal_native_lifetimes"] = {key: row.copy() for key, row in history.items()}
    if fault == "changed_history":
        capture["terminal_native_lifetimes"][stop]["updatedAt"] = timestamp("3.2")
    r["child_ids"] = {key: row.copy() for key, row in history.items()}
    other_history = api.target_history.side_effect
    api.target_history.side_effect = lambda sym, ids: (
        {key: history[key] for key in ids} if first in ids else other_history(sym, ids)
    )
    payload = json.dumps(capture).encode()
    spec["capture_sha256"] = hashlib.sha256(payload).hexdigest()
    (path / (spec["capture_sha256"] + ".json")).write_bytes(payload)
    (tmp_path / "native-protection.json").write_text(json.dumps(manifest))
    monkeypatch.setattr(checks, "_require_owner_signature", Mock())
    if fault:
        with pytest.raises(ValueError):
            await api.verify_native_protection(profile)
        assert not api.native_ladder_qualified_for("BTCUSD")
    else:
        await api.verify_native_protection(profile)
        assert api.native_ladder_qualified_for("BTCUSD")


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


@pytest.mark.parametrize("capability", ["move", "partials"])
async def test_independent_management_evidence_with_own_expiry_close(evidence, tmp_path, capability):
    profile, api, manifest, records = evidence
    spec = manifest["cases"][2].copy()
    capture = json.loads((tmp_path / "protection-evidence" / (spec["capture_sha256"] + ".json")).read_bytes())
    r = capture["receipt"]
    if capability == "move":
        spec["partial_cover_verified"] = False
        r["partial_cover_verified"] = False
        del r["partial_cover_evidence"]
        for child in spec["exits"].values():
            del capture["terminal_native_orders"][child]
            del r["child_ids"][child]
        spec["exits"] = {}
        r["close_qty"] = "1"
        records[2][:] = [records[2][0], {**records[2][-1], "quantity": "1"}]
    else:
        spec["stop_move"] = None
        del r["stop_move"]
    case = checks.Case.model_validate_json(json.dumps(spec))
    receipt = checks._check_capture(case, json.dumps(capture).encode())
    result = await checks._case_features(api, case, profile.remote_account_id, receipt)
    assert result == (
        {("BUY", "stop-move")} if capability == "move" else {("BUY", "partial"), ("BUY", "protected-partial")}
    )


async def test_missing_resting_order_route_cannot_qualify_standalone_partials(evidence, tmp_path):
    profile, api, manifest, _ = evidence
    spec = manifest["cases"][2]
    case = checks.Case.model_validate_json(json.dumps(spec))
    payload = (tmp_path / "protection-evidence" / (spec["capture_sha256"] + ".json")).read_bytes()
    receipt = checks._check_capture(case, payload)
    del receipt["standalone_partial_ids"]
    with pytest.raises(ValueError, match="retained protection"):
        await checks._case_features(api, case, profile.remote_account_id, receipt)
