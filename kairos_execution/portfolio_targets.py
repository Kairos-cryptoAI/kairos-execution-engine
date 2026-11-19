"""Size native partial take-profits and reconcile their identified child orders."""

from __future__ import annotations

from datetime import datetime
from decimal import ROUND_CEILING, ROUND_FLOOR, Decimal
from typing import Any

from .portfolio_evedex import EvedexError, dec, plain


class TargetEvidenceError(EvedexError):
    """Never repeat a target or substitute a software exit on unresolved evidence."""


def partial_target_spec(targets: list[dict], instrument: Any) -> dict:
    previous = total = Decimal(0)
    levels = []
    for target in targets:
        level, fraction = dec(target["at_r"]), dec(target["fraction"])
        if not (level > previous and 0 < fraction < 1):
            raise ValueError("target levels must be increasing and fractions positive")
        previous = level
        total += fraction
        levels.append([str(level), str(fraction)])
    if total >= 1:
        raise ValueError("partial targets must leave a final remainder")
    return dict(
        levels=levels,
        tick=plain(instrument.price_step),
        step=plain(instrument.quantity_step),
        minimum=plain(instrument.min_quantity),
        minimum_volume=plain(instrument.min_volume),
    )


def sized_targets(
    spec: dict, side: str, entry: Decimal, stop: Decimal, take: Decimal, quantity: Decimal
) -> list[dict]:
    sign = 1 if side == "LONG" else -1
    tick, step, minimum = (dec(spec[k]) for k in ("tick", "step", "minimum"))
    minimum_volume = dec(spec["minimum_volume"])
    cumulative = allocated = Decimal(0)
    levels: dict[Decimal, Decimal] = {}
    for raw_r, raw_fraction in spec["levels"]:
        target = entry + sign * abs(entry - stop) * dec(raw_r)
        price = (target / tick).to_integral_value(rounding=ROUND_CEILING if sign > 0 else ROUND_FLOOR) * tick
        if not 0 < sign * (price - entry) < sign * (take - entry):
            continue
        cumulative += dec(raw_fraction)
        intended = min(cumulative * quantity, quantity - minimum)
        amount = (intended / step).to_integral_value(rounding=ROUND_FLOOR) * step - allocated
        if amount <= 0 or amount < minimum or amount * price < minimum_volume:
            continue
        levels[price] = levels.get(price, Decimal(0)) + amount
        allocated += amount
    return [{"price": plain(px), "quantity": plain(qty)} for px, qty in levels.items()]


def target_matches(item: dict, effect: dict, row: dict) -> bool:
    req = effect["request"]
    return (
        effect["kind"] == "PARTIAL_TAKE"
        and effect["status"] == "ACCEPTED"
        and row.get("id") == effect["venue_id"]
        and bool(effect["venue_id"])
        and row.get("instrument") == item["symbol"]
        and row.get("type") == "take-profit"
        and row.get("side") == req["side"]
        and row.get("order") in (None, item["entry_order_id"])
        and dec(row.get("price")) == dec(req["price"])
        and dec(row.get("quantity")) == dec(req["quantity"])
    )


def _timestamp(text: str) -> float:
    value = datetime.fromisoformat(text)
    if value.utcoffset() is None:
        raise TargetEvidenceError("venue target evidence has no UTC offset")
    return value.timestamp()


def target_fills(
    item: dict,
    plan: dict,
    effects: list[dict],
    children: dict[str, dict],
    orders: list[dict],
    account: str,
    remaining: Decimal,
    cancelled: set[str],
) -> dict[str, tuple[str, str, str]]:
    """Require a complete monotonically reducing generation and a unique trigger-to-fill binding."""
    entry_side, exit_side = ("BUY", "SELL") if item["side"] == "LONG" else ("SELL", "BUY")
    by_id = {r["id"]: r for r in orders}
    if len(by_id) != len(orders) or item["entry_order_id"] not in by_id:
        raise TargetEvidenceError("ambiguous native target order inventory")
    initial = dec(plan["initial_quantity"])
    if initial <= 0 or not 0 <= remaining <= initial:
        raise TargetEvidenceError("remaining exposure exceeds the original target generation")
    seen = Decimal(0)
    closes = {}
    for order_id, order in by_id.items():
        if str(order.get("user")) != account or order.get("instrument") != item["symbol"]:
            raise TargetEvidenceError("foreign order in target generation")
        quantity, unfilled = dec(order["quantity"]), dec(order["unFilledQuantity"])
        if not 0 <= unfilled <= quantity:
            raise TargetEvidenceError("invalid remaining quantity in target generation")
        amount = quantity - unfilled
        if order_id == item["entry_order_id"]:
            if (
                amount != initial
                or order["side"] != entry_side
                or dec(order["filledAvgPrice"]) != dec(item["price"])
            ):
                raise TargetEvidenceError("target generation entry does not match its fill")
        elif amount:
            if (
                order["side"] != exit_side
                or order.get("positionVersions") != [plan["version"]]
                or order["status"] != "FILLED"
                or unfilled != 0
            ):
                raise TargetEvidenceError("unexpected or incomplete fill in target generation")
            seen += amount
            # EVEDEX can return hasOpenedPosition=True on a partial take that leaves
            # the original generation open. Prove direction and remaining exposure from fills.
            if seen > initial:
                raise TargetEvidenceError("opposing fills exceeded the owned position")
            closes[order_id] = order
    if initial - seen != remaining:
        raise TargetEvidenceError("native fills do not explain current position")
    terminal = {}
    for effect in effects:
        trigger_id = effect["venue_id"]
        row = children.get(trigger_id)
        if row is None or not target_matches(item, effect, row):
            raise TargetEvidenceError("native target no longer matches its acknowledged trigger identity")
        if row.get("status") in {"active", "waitOrder"}:
            continue
        if row.get("status") == "cancelled" and dec(row.get("triggeredQuantity") or 0) == 0:
            if remaining and trigger_id not in cancelled:
                raise TargetEvidenceError("native target was cancelled while its position remains")
            continue
        if row.get("status") != "done" or dec(row["triggeredQuantity"]) != dec(row["quantity"]):
            raise TargetEvidenceError("native target outcome is not terminal or has an incomplete fill")
        terminal[trigger_id] = row
    fills: dict[str, tuple[str, str, str]] = {}
    for trigger_id, row in terminal.items():
        direct = row.get("triggerOrder")
        # EVEDEX also returns the original entry here for a terminal target.
        if direct == item["entry_order_id"]:
            direct = None
        if trigger_id in closes:
            if direct not in (None, trigger_id):
                raise TargetEvidenceError("native trigger and explicit child order identities conflict")
            direct = trigger_id
        matching = []
        for order_id, order in closes.items():
            if order.get("group") != "take-profit" or dec(order["quantity"]) != dec(row["triggeredQuantity"]):
                continue
            near = direct is None and abs(_timestamp(order["updatedAt"]) - _timestamp(row["updatedAt"])) <= 2
            if near and any(
                key != trigger_id
                and other.get("type") == "take-profit"
                and other.get("status") == "done"
                and other.get("triggerOrder") in (None, item["entry_order_id"], order_id)
                and dec(other.get("triggeredQuantity")) == dec(row["triggeredQuantity"])
                and abs(_timestamp(order["updatedAt"]) - _timestamp(other["updatedAt"])) <= 2
                for key, other in children.items()
            ):
                raise TargetEvidenceError("another bound sibling also matches the native fill")
            if direct == order_id or near:
                matching.append(order_id)
        if len(matching) != 1 or matching[0] in {v[0] for v in fills.values()}:
            raise TargetEvidenceError("native target fill cannot be uniquely linked to its bound trigger")
        px = dec(closes[matching[0]].get("filledAvgPrice"))
        if px <= 0:
            raise TargetEvidenceError("target fill lacks its execution price")
        fills[trigger_id] = (matching[0], plain(dec(row["triggeredQuantity"])), plain(px))
    return fills
