"""Admit a portfolio bracket only after owner review and authenticated venue fill replay."""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections import defaultdict
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field

from .native_protection import reducing_side
from .portfolio_profile import PortfolioProfile, _require_owner_signature, _unique_fields, verify_profile

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class _Record(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class StopMove(_Record):
    before: Decimal = Field(gt=0)
    after: Decimal = Field(gt=0)


class Case(_Record):
    instrument: str
    position_version: int = Field(ge=0)
    entry_order_id: str = Field(min_length=1, max_length=240)
    position_side: Literal["BUY", "SELL"]
    capture_sha256: Digest
    stop_move: StopMove | None
    closed_clean: Literal[True]
    partial_cover_verified: bool = False
    partial_cover_interval: Literal["owned-trigger-lifetimes-v1"] | None = None
    exits: dict[str, str]


class UniformContract(_Record):
    """Signed owner finding that these instruments share the witnessed venue contract."""

    instruments: tuple[str, ...] = Field(min_length=1, max_length=23)
    source_url: str
    source_sha256: Digest
    includes_partial_ladder: bool = False
    includes_stop_move: bool = False


class Qualification(_Record):
    version: Literal["kairos.evedex-protection.v1"]
    adapter: Literal["evedex-opposite-side-full-bracket-v1"]
    venue: Literal["EVEDEX_PROD"]
    account_id: str
    remote_account_id: str
    qualified_at: datetime
    cases: tuple[Case, ...] = Field(min_length=1, max_length=200)
    uniform_contract: UniformContract | None = None


def _capture(root: Path, digest: str, suffix: str) -> bytes:
    path = root / "protection-evidence" / (digest + suffix)
    if path.resolve() != path or not path.is_file():
        raise ValueError("missing original protection evidence")
    with path.open("rb") as stream:
        payload = stream.read(16 * 1024 * 1024 + 1)
    if len(payload) > 16 * 1024 * 1024 or hashlib.sha256(payload).hexdigest() != digest:
        raise ValueError("protection evidence digest changed or exceeds its size bound")
    return payload


def _trigger_shape(row: dict) -> tuple[str, str, Decimal, Decimal]:
    return row["type"], row["side"], Decimal(str(row["quantity"])), Decimal(str(row["price"]))


def _check_capture(case: Case, payload: bytes) -> dict:
    capture = json.loads(payload, object_pairs_hook=_unique_fields)
    receipt = capture["receipt"]
    terminal = capture["terminal_native_orders"]
    if (
        capture["schema"] != "kairos.probe-capture.v1"
        or capture["history_closed"] is not True
        or capture["version"] != case.position_version
        or receipt["id"] != case.entry_order_id
        or receipt["plan"]["symbol"] != case.instrument
        or receipt["plan"]["side"] != case.position_side
        or receipt["status"] != "finished"
        or receipt["closed_clean"] is not True
        or receipt["sibling_cancelled_by_venue"] is not True
        or receipt.get("manual_trigger_cleanup")
        or set(receipt["child_ids"]) != set(terminal)
        or not set(case.exits.values()) <= set(terminal)
        or any(
            row.get("status") != ("done" if tid in case.exits.values() else "cancelled")
            for tid, row in terminal.items()
        )
    ):
        raise ValueError("original probe capture does not match clean owned bracket settlement")
    initial = receipt["plan"]["children"]
    full = [child for child in initial if Decimal(str(child["quantity"])) == 0]
    if len(full) != 2 or {row["type"] for row in full} != {"stop-loss", "take-profit"}:
        raise ValueError("probe lacks its initial full stop and take")
    confirmed = {_trigger_shape(row) for row in terminal.values()}
    for row in full:
        if row["side"] != reducing_side(case.position_side):
            raise ValueError("initial probe protection faces the wrong side")
        if _trigger_shape(row) not in confirmed and not (
            case.stop_move
            and row["type"] == "stop-loss"
            and Decimal(str(row["price"])) == case.stop_move.before
            and receipt["stop_move"]["from"] == receipt["stop_move"]["to"]
        ):
            raise ValueError("initial full protection is absent from owned trigger history")
    if case.stop_move:
        move = receipt["stop_move"]
        prev, new = terminal[move["from"]], terminal[move["to"]]
        if (
            not move.get("confirmed_at")
            or Decimal(move["before"]) != case.stop_move.before
            or Decimal(move["after"]) != case.stop_move.after
            or new["type"] != "stop-loss"
            or prev["type"] != "stop-loss"
            or new["side"] != reducing_side(case.position_side)
            or Decimal(str(new["price"])) != case.stop_move.after
            or (move["from"] != move["to"] and prev["status"] != "cancelled")
        ):
            raise ValueError("original capture lacks the tightened protective stop")
    if case.partial_cover_verified:
        if not receipt["plan"]["ladder"] or receipt.get("partial_cover_verified") is not True:
            raise ValueError("original capture lacks protected partial exits")
        for evidence in receipt["partial_cover_evidence"].values():
            for key, kind in (("stops", "stop-loss"), ("remaining_targets", "take-profit")):
                children = evidence[key]
                if not children or any(
                    child not in terminal
                    or terminal[child]["type"] != kind
                    or terminal[child]["side"] != reducing_side(case.position_side)
                    for child in children
                ):
                    raise ValueError("partial exit lacks its original reducing stop or remaining target")
    if case.partial_cover_interval:
        lifetimes = capture.get("terminal_native_lifetimes")
        if (
            case.partial_cover_verified
            or receipt.get("partial_cover_verified") is not False
            or not receipt["plan"]["ladder"]
            or not case.stop_move
            or receipt.get("close_id")
            or not isinstance(lifetimes, dict)
            or set(lifetimes) != set(terminal)
            or any(
                receipt.get(k)
                for k in (
                    "coverage_missing",
                    "unbound_early_fill",
                    "native_increased_position",
                    "move_refused",
                )
            )
        ):
            raise ValueError("interval proof requires original observations and the bound terminal lifetimes")
        return {**receipt, "_signed_lifetimes": lifetimes}
    return receipt


def _venue_time(value: str) -> datetime:
    t = datetime.fromisoformat(value)
    if t.utcoffset() is None:
        raise ValueError("trigger interval lacks an absolute time")
    return t


async def _verify_cover_interval(
    api, case: Case, owner: str, receipt: dict, history: dict, amounts: list
) -> None:
    """Verify the already-observed stop and take persisted through the second fill until the final take."""
    if len(amounts) != 4 or len(case.exits) != 3 or not receipt.get("position_id"):
        raise ValueError("interval requires one owned entry, two partial fills and one final native exit")
    lifetime_fields = (
        "id",
        "instrument",
        "type",
        "side",
        "quantity",
        "price",
        "status",
        "triggerOrder",
        "triggeredQuantity",
        "cancelledReason",
        "createdAt",
        "updatedAt",
    )
    for target, current in history.items():
        archived = receipt["_signed_lifetimes"][target]
        if any(key not in archived or archived[key] != current.get(key) for key in lifetime_fields):
            raise ValueError("signed trigger lifetimes differ from current authenticated history")
    version, position_id = case.position_version, receipt["position_id"]
    (entered, _, initial, _), (t1, exit1, qty1, _), (t2, exit2, qty2, _), (t3, final, qty3, _) = amounts
    if initial != qty1 + qty2 + qty3:
        raise ValueError("interval residual disagrees with its full native take")
    trigger_ids = [case.exits[oid] for oid in (exit1, exit2, final)]
    first_id, second_id, full_id = trigger_ids
    partials = {first_id, second_id}
    stop_id = receipt["stop_move"]["to"]
    stop = history[stop_id]
    full = history[full_id]
    if (
        len(set(trigger_ids) | {stop_id}) != 4
        or partials != set(receipt["standalone_partial_ids"])
        or stop["type"] != "stop-loss"
        or Decimal(str(stop["quantity"])) != 0
        or stop["status"] != "cancelled"
        or stop.get("cancelledReason") != "Position closed"
        or Decimal(str(stop["triggeredQuantity"])) != 0
        or full["type"] != "take-profit"
        or Decimal(str(full["quantity"])) != 0
        or full["status"] != "done"
        or Decimal(str(full["triggeredQuantity"])) != qty3
        or any(
            history[key]["type"] != "take-profit" or Decimal(str(history[key]["quantity"])) != qty
            for key, qty in ((first_id, qty1), (second_id, qty2))
        )
    ):
        raise ValueError("interval terminal protection does not explain the native reductions")
    coverage = receipt["partial_cover_evidence"]
    if set(coverage) != {exit1}:
        raise ValueError("interval lacks the unique observed remainder before its second native exit")
    prior = coverage[exit1]
    witnessed = _venue_time(prior["at"])
    move_seen = _venue_time(receipt["stop_move"]["confirmed_at"])
    moved = receipt.get("stop_move_request", {})
    if (
        prior["position_id"] != position_id
        or prior["position_version"] != version
        or Decimal(str(prior["remaining"])) != initial - qty1
        or set(prior["stops"]) != {stop_id}
        or set(prior["remaining_targets"]) != {second_id, full_id}
        or moved.get("wire_scope") != "position"
        or moved.get("new_id") != stop_id
        or moved.get("old_id") != receipt["stop_move"]["from"]
        or Decimal(str(moved["after"])) != Decimal(str(stop["price"]))
        or not (
            _venue_time(stop["createdAt"])
            <= move_seen
            < t1
            < witnessed
            < t2
            < t3
            <= _venue_time(stop["updatedAt"])
        )
        or not (_venue_time(full["createdAt"]) <= t1 < t3 <= _venue_time(full["updatedAt"]))
        or any((_venue_time(order["updatedAt"]) - t3).total_seconds() > 2 for order in (full, stop))
        or not (
            entered < t1 <= _venue_time(history[first_id]["updatedAt"]) < witnessed
            and t2 <= _venue_time(history[second_id]["updatedAt"]) < t3
        )
    ):
        raise ValueError("dual-observed stop and full take do not cover the native fill interval")
    ticks = [Decimal(str(history[k]["price"])) for k in trigger_ids]
    if not (
        ticks[0] < ticks[1] < ticks[2] if case.position_side == "BUY" else ticks[0] > ticks[1] > ticks[2]
    ):
        raise ValueError("interval does not contain three distinct ordered take prices")
    for key in partials:
        seen = receipt["standalone_partial_observations"][key]
        request = next(
            (r for r in receipt["standalone_partial_requests"].values() if r.get("id") == key), None
        )
        if (
            not request
            or request.get("wire_scope") != "position"
            or request.get("order") != case.entry_order_id
            or request["position_id"] != position_id
            or request["version"] != version
            or request["side"] != reducing_side(case.position_side)
            or Decimal(str(request["quantity"])) != Decimal(str(history[key]["quantity"]))
            or Decimal(str(request["price"])) != Decimal(str(history[key]["price"]))
            or seen["position_id"] != position_id
            or seen["position_version"] != version
            or not (_venue_time(history[key]["createdAt"]) <= _venue_time(seen["seen_at"]) < t1)
        ):
            raise ValueError("interval partial target was not previously bound to the same generation")
    details = await asyncio.gather(*(api.order(oid) for _, oid, _, _ in amounts[1:]))
    for detail, (when, oid, qty, _) in zip(details, amounts[1:], strict=True):
        if (
            not detail
            or detail.get("id") != oid
            or detail.get("positionVersions") != [version]
            or type(detail["positionVersions"][0]) is not int
            or str(detail.get("user")) != owner
            or detail.get("instrument") != case.instrument
            or detail.get("side") != reducing_side(case.position_side)
            or detail.get("group") != "take-profit"
            or detail.get("type") != "MARKET"
            or detail.get("status") != "FILLED"
            or Decimal(str(detail["quantity"])) != qty
            or Decimal(str(detail["unFilledQuantity"])) != 0
            or _venue_time(detail["updatedAt"]) != when
        ):
            raise ValueError("interval execution is absent from the exact owned position generation")


async def _case_features(api, case: Case, owner: str, receipt: dict) -> set[tuple[str, str]]:
    symbol, version = case.instrument, case.position_version
    closed, rows, entry, history = await asyncio.gather(
        api.position_version_closed(symbol, version),
        api.position_version_orders(symbol, version),
        api.order(case.entry_order_id),
        api.target_history(symbol, set(receipt["child_ids"])),
    )
    if set(history) != set(receipt["child_ids"]) or any(
        actual.get("id") != key
        or actual.get("instrument") != symbol
        or actual.get("side") != reducing_side(case.position_side)
        or actual.get("status") != ("done" if key in case.exits.values() else "cancelled")
        or _trigger_shape(actual) != _trigger_shape(receipt["child_ids"][key])
        for key, actual in history.items()
    ):
        raise ValueError("private native history differs from the owned probe bracket")
    if not (
        closed
        and entry
        and entry.get("id") == case.entry_order_id
        and entry.get("positionVersions") == [version]
        and type(entry["positionVersions"][0]) is int
        and entry.get("instrument") == symbol
        and str(entry.get("user", "")) == owner
        and entry.get("side") == case.position_side
    ):
        raise ValueError("probe entry does not match its closed account generation")
    amounts = []
    seen = set()
    for r in rows:
        oid = r.get("id")
        if not oid or oid in seen or r.get("instrument") != symbol or str(r.get("user", "")) != owner:
            raise ValueError("invalid probe generation order history")
        seen.add(oid)
        qty = Decimal(str(r["quantity"])) - Decimal(str(r["unFilledQuantity"]))
        if not qty.is_finite() or qty < 0:
            raise ValueError("invalid probe fill quantity")
        if qty:
            when = datetime.fromisoformat(r["updatedAt"])
            if when.utcoffset() is None:
                raise ValueError("probe history lacks a venue timestamp")
            amounts.append((when, oid, qty, r))
    # A probe opens once and its remaining fills must monotonically reduce that position.
    amounts.sort(key=lambda row: row[0])
    if (
        not amounts
        or amounts[0][1] != case.entry_order_id
        or (len({when for when, *_ in amounts}) != len(amounts))
    ):
        raise ValueError("ambiguous sequence of probe fills")
    _, _, remaining, first = amounts[0]
    if first.get("side") != case.position_side or first.get("group") != "manually":
        raise ValueError("wrong probe entry direction or origin")
    features: set[tuple[str, str]] = set()
    verified_exits: set[str] = set()
    observed_partials: set[str] = set()
    for _, oid, qty, row in amounts[1:]:
        if row.get("side") != reducing_side(case.position_side) or qty > remaining:
            raise ValueError("probe exit increased or crossed the position")
        remaining -= qty
        group = row.get("group")
        if group not in {"take-profit", "stop-loss"}:
            if not (
                group == "manually"
                and row.get("status") == "FILLED"
                and receipt.get("close_reason") == "expiry"
                and oid == receipt.get("close_id")
                and not remaining
                and row.get("type") in {"MARKET", "LIMIT"}
                and row.get("side") == receipt.get("close_side")
                and qty == Decimal(str(receipt["close_qty"]))
                and (
                    case.stop_move is not None
                    or (case.partial_cover_verified and len(observed_partials) >= 2)
                )
            ):
                raise ValueError("foreign exit in protection probe generation")
            continue
        trigger = history.get(case.exits.get(oid, ""))
        if not (
            trigger
            and oid in case.exits
            and trigger.get("id") == case.exits[oid]
            and (trigger["id"] == oid or trigger.get("triggerOrder") == oid)
            and trigger.get("triggerOrder") in {None, oid, case.entry_order_id}
            and row.get("type") == "MARKET"
            and trigger.get("instrument") == symbol
            and trigger.get("status") == "done"
            and trigger.get("type") == group
            and trigger.get("side") == row.get("side")
            and Decimal(str(trigger["triggeredQuantity"])) == qty
        ):
            raise ValueError("native execution does not match its witnessed terminal trigger")
        verified_exits.add(oid)
        trigger_qty = Decimal(str(trigger["quantity"]))
        if trigger_qty == 0 and not remaining and not receipt["plan"]["ladder"] and not case.stop_move:
            features.add((case.position_side, group))
        elif group == "take-profit" and remaining and trigger_qty == qty:
            features.add((case.position_side, "partial"))
            if case.partial_cover_verified:
                cover = receipt["partial_cover_evidence"][oid]
                if (
                    trigger["id"] not in receipt.get("standalone_partial_ids", ())
                    or Decimal(str(cover["remaining"])) != remaining
                    or cover["position_version"] != version
                    or not receipt.get("position_id")
                    or cover["position_id"] != receipt["position_id"]
                    or not cover["stops"]
                    or not cover["remaining_targets"]
                ):
                    raise ValueError("missing retained protection after the native partial fill")
                observed_partials.add(oid)
    if case.partial_cover_verified:
        if len(observed_partials) < 2:
            raise ValueError("qualified partial ladder requires distinct reducing fills")
        features.add((case.position_side, "protected-partial"))
    if case.partial_cover_interval:
        await _verify_cover_interval(api, case, owner, receipt, history, amounts)
        features.add((case.position_side, "protected-partial"))
    if case.stop_move:
        move = case.stop_move
        tightened = move.after > move.before if case.position_side == "BUY" else move.after < move.before
        if not tightened:
            raise ValueError("probe stop moved away from the owned position")
        features.add((case.position_side, "stop-move"))
    if remaining or not features or verified_exits != set(case.exits):
        raise ValueError("native exit did not reduce a reconciled probe position")
    return features


async def qualified_instruments(
    api, profile: PortfolioProfile
) -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
    profile = verify_profile(profile)
    root = profile.journal_path.parent
    path = root / "native-protection.json"
    if not path.exists():
        return frozenset(), frozenset(), frozenset()
    if path != path.resolve() or path.stat().st_size > 262144:
        raise ValueError("invalid qualification file")
    data = path.read_bytes()
    _require_owner_signature(path, data)
    json.loads(data, object_pairs_hook=_unique_fields)
    q = Qualification.model_validate_json(data)
    if (
        q.account_id != profile.account_id
        or q.remote_account_id != profile.remote_account_id
        or q.qualified_at.utcoffset() is None
        or q.qualified_at > datetime.now(UTC)
        or str((await api.me()).get("exchangeId", "")) != q.remote_account_id
    ):
        raise ValueError("qualification belongs to a different production portfolio or date")
    features = defaultdict(set)
    entries = set()
    for case in q.cases:
        key = (case.instrument, case.position_version)
        if case.instrument not in profile.symbols or key in entries:
            raise ValueError("duplicate or out-of-scope protection evidence")
        entries.add(key)
        receipt = _check_capture(case, _capture(root, case.capture_sha256, ".json"))
        features[case.instrument].update(await _case_features(api, case, q.remote_account_id, receipt))
    required = {(side, kind) for side in ("BUY", "SELL") for kind in ("stop-loss", "take-profit")}
    qualified = {symbol for symbol, actual in features.items() if required <= actual}
    ladder = {
        symbol
        for symbol in qualified
        if all((side, "protected-partial") in features[symbol] for side in ("BUY", "SELL"))
    }
    stop_moves = {
        symbol
        for symbol in qualified
        if all((side, "stop-move") in features[symbol] for side in ("BUY", "SELL"))
    }
    if q.uniform_contract:
        shared = q.uniform_contract
        source = urlparse(shared.source_url)
        if (
            not qualified
            or not qualified <= set(shared.instruments)
            or not set(shared.instruments) <= set(profile.symbols)
            or source.scheme != "https"
            or source.hostname
            not in {"docs.evedex.com", "exchange.evedex.com", "trading-api.evedex.com", "help.evedex.com"}
        ):
            raise ValueError("uniform venue scope lacks a witnessed sample or reviewed source")
        _capture(root, shared.source_sha256, ".source")
        if shared.includes_partial_ladder and ladder:
            ladder.update(shared.instruments)
        if shared.includes_stop_move and stop_moves:
            stop_moves.update(shared.instruments)
        qualified.update(shared.instruments)
    return frozenset(qualified), frozenset(ladder), frozenset(stop_moves)
