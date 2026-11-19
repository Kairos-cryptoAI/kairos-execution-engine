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
    exits: dict[str, str] = Field(min_length=1)


class UniformContract(_Record):
    """Signed owner finding that these instruments share the witnessed venue contract."""

    instruments: tuple[str, ...] = Field(min_length=1, max_length=23)
    source_url: str
    source_sha256: Digest
    includes_partial_ladder: bool = False


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


def _check_capture(case: Case, payload: bytes) -> None:
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
    if case.stop_move:
        move = receipt["stop_move"]
        prev, new = terminal[move["from"]], terminal[move["to"]]
        if (
            Decimal(move["before"]) != case.stop_move.before
            or Decimal(move["after"]) != case.stop_move.after
            or new["type"] != "stop-loss"
            or prev["type"] != "stop-loss"
            or new["side"] != reducing_side(case.position_side)
            or Decimal(str(new["price"])) != case.stop_move.after
            or (move["from"] != move["to"] and prev["status"] != "cancelled")
        ):
            raise ValueError("original capture lacks the tightened protective stop")
    if case.partial_cover_verified and receipt.get("partial_cover_verified") is not True:
        raise ValueError("original capture lacks protected partial exits")


async def _case_features(api, case: Case, owner: str) -> set[tuple[str, str]]:
    symbol, version = case.instrument, case.position_version
    closed, rows, entry = await asyncio.gather(
        api.position_version_closed(symbol, version),
        api.position_version_orders(symbol, version),
        api.order(case.entry_order_id),
    )
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
    features = set()
    verified_exits = set()
    for _, oid, qty, row in amounts[1:]:
        if row.get("side") != reducing_side(case.position_side) or qty > remaining:
            raise ValueError("probe exit increased or crossed the position")
        remaining -= qty
        group = row.get("group")
        if group in {"take-profit", "stop-loss"}:
            trigger = await api.protection_for_fill(symbol, oid)
            if not (
                trigger
                and oid in case.exits
                and trigger.get("id") == case.exits[oid]
                and trigger.get("instrument") == symbol
                and trigger.get("status") == "done"
                and trigger.get("type") == group
                and trigger.get("side") == row.get("side")
                and Decimal(str(trigger["triggeredQuantity"])) == qty
            ):
                raise ValueError("native execution does not match its witnessed terminal trigger")
            verified_exits.add(oid)
        if group in {"take-profit", "stop-loss"} and not remaining:
            features.add((case.position_side, group))
        elif group == "take-profit" and remaining:
            features.add((case.position_side, "partial"))
    if case.partial_cover_verified:
        if sum(1 for *_, r in amounts[1:-1] if r.get("group") == "take-profit") < 2:
            raise ValueError("qualified partial ladder requires distinct reducing fills")
        features.add((case.position_side, "protected-partial"))
    if remaining or not features or verified_exits != set(case.exits):
        raise ValueError("native exit did not reduce a reconciled probe position")
    if case.stop_move:
        move = case.stop_move
        tightened = move.after > move.before if case.position_side == "BUY" else move.after < move.before
        if not tightened:
            raise ValueError("probe stop moved away from the owned position")
        features.add((case.position_side, "stop-move"))
    return features


async def qualified_instruments(api, profile: PortfolioProfile) -> tuple[frozenset[str], frozenset[str]]:
    profile = verify_profile(profile)
    root = profile.journal_path.parent
    path = root / "native-protection.json"
    if not path.exists():
        return frozenset(), frozenset()
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
        _check_capture(case, _capture(root, case.capture_sha256, ".json"))
        features[case.instrument].update(await _case_features(api, case, q.remote_account_id))
    required = {
        (side, kind)
        for side in ("BUY", "SELL")
        for kind in ("stop-loss", "take-profit", "partial", "stop-move")
    }
    qualified = {symbol for symbol, actual in features.items() if required <= actual}
    ladder = {
        symbol
        for symbol in qualified
        if all((side, "protected-partial") in features[symbol] for side in ("BUY", "SELL"))
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
        qualified.update(shared.instruments)
    return frozenset(qualified), frozenset(ladder)
