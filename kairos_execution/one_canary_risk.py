"""Independent, operational Risk sizing for a single flat-account canary.

Uses native Risk's pure sizing kernel, but deliberately does not fabricate a
reconciled AccountSnapshotV2 or VerifiedLiveAccountV1. The result is bound to
its concrete inputs and expires; the runner owns one-use admission and I/O.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime
from decimal import ROUND_FLOOR, Decimal, localcontext
from typing import Any, Literal

from kairos_core.contracts import StrategicAllocation, StrategyIntentV1, VenueQualityV1
from kairos_core.enums import EvedexProfile, Side
from kairos_risk.live import LiveRiskEvaluator  # type: ignore[import-untyped]

from .one_canary_account import (
    ASSUMPTIONS,
    CanaryAccountError,
    CanaryAccountObservation,
    _money,
    observed_session_loss_usdt,
)


@dataclass(frozen=True, slots=True)
class CanaryInstrumentRules:
    symbol: str
    observed_at: datetime
    evidence_sha256: str
    tick: Decimal
    quantity_step: Decimal
    min_quantity: Decimal
    max_quantity: Decimal
    min_price: Decimal
    max_price: Decimal
    min_notional_usdt: Decimal

    @classmethod
    def from_native(cls, row: dict[str, Any], *, observed_at: datetime, body_sha256: str):
        if (
            row.get("trading") != "all"
            or row.get("visibility") != "all"
            or row.get("marketState") != "OPEN"
            or _money(row.get("lotSize")) != 1
            or _money(row.get("multiplier")) != 1
        ):
            raise CanaryAccountError("instrument unavailable or unsupported contract economics")
        symbol = row.get("name")
        if not isinstance(symbol, str) or not symbol:
            raise CanaryAccountError("instrument rules missing or inconsistent")
        result = cls(
            symbol,
            observed_at,
            body_sha256,
            *(
                _money(row.get(k))
                for k in (
                    "priceIncrement",
                    "quantityIncrement",
                    "minQuantity",
                    "maxQuantity",
                    "minPrice",
                    "maxPrice",
                    "minVolume",
                )
            ),
        )
        if (
            observed_at.tzinfo is None
            or len(body_sha256) != 64
            or any(c not in "0123456789abcdef" for c in body_sha256)
            or any(
                v <= 0
                for v in (
                    result.tick,
                    result.quantity_step,
                    result.min_quantity,
                    result.max_quantity,
                    result.min_price,
                    result.max_price,
                    result.min_notional_usdt,
                )
            )
            or result.min_quantity > result.max_quantity
            or result.min_price > result.max_price
        ):
            raise CanaryAccountError("instrument rules missing or inconsistent")
        return result


@dataclass(frozen=True, slots=True)
class CanarySizingResult:
    status: Literal["WAIT", "ELIGIBLE"]
    reason: str
    input_binding_sha256: str
    valid_until_ms: int
    quantity: Decimal | None = None
    entry_limit_price: Decimal | None = None
    scenario_entry_price: Decimal | None = None
    scenario_stop_exit_price: Decimal | None = None
    notional_usdt: Decimal | None = None
    cash_required_usdt: Decimal | None = None
    loss_budget_usdt: Decimal | None = None
    estimated_loss_usdt: Decimal | None = None
    estimated_fees_usdt: Decimal | None = None
    observed_session_loss_usdt: Decimal | None = None
    assumptions: tuple[str, ...] = ASSUMPTIONS


@dataclass(frozen=True, slots=True)
class _SizingCashView:
    """Only the two cash attributes consumed by the native pure kernel."""

    equity_usd: float
    available_balance_usd: float


class OperationalFlatCanaryRisk:
    def __init__(self, evaluator: LiveRiskEvaluator) -> None:
        if type(evaluator) is not LiveRiskEvaluator:
            raise TypeError("concrete native Risk evaluator required")
        self._native = evaluator

    def evaluate(
        self,
        *,
        intent: StrategyIntentV1,
        venue: VenueQualityV1,
        allocation: StrategicAllocation,
        observation: CanaryAccountObservation,
        baseline_equity_usdt: Decimal,
        net_deposits_usdt: Decimal,
        instrument: CanaryInstrumentRules,
        entry_slippage_bps: Decimal | None,
        stop_exit_slippage_bps: Decimal | None,
        extra_cost_bound_usdt: Decimal | None,
        now: datetime,
    ) -> CanarySizingResult:
        payload = {
            "policy": "flat-one-canary-100-025-1x-5-v1",
            "intent": intent.model_dump(mode="json"),
            "venue": venue.model_dump(mode="json"),
            "allocation": allocation.model_dump(mode="json"),
            "account": {
                "identity": hashlib.sha256(observation.account_id.encode()).hexdigest(),
                "cash": str(observation.funding_usdt),
                "free": str(observation.available_usdt),
                "started": str(observation.started_at),
                "finished": str(observation.finished_at),
                "reads": tuple(r.body_sha256 for r in observation.reads),
            },
            "rules": asdict(instrument),
            "baseline": str(baseline_equity_usdt),
            "net_deposits": str(net_deposits_usdt),
            "costs": tuple(
                str(x) for x in (entry_slippage_bps, stop_exit_slippage_bps, extra_cost_bound_usdt)
            ),
        }
        binding = hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()
        now_ms = int(now.timestamp() * 1000)
        expiry = min(
            venue.expires_at_ms,
            intent.entry_expires_ts_ms,
            int(observation.started_at.timestamp() * 1000) + 10000,
        )

        def wait(reason):
            return CanarySizingResult("WAIT", reason, binding, expiry)

        try:
            if now.tzinfo is None:
                return wait("clock_invalid")
            observation.require_flat(now=now)
            observation.require_recent(now)
            scope, limits = self._native.scope, self._native.limits
            if (
                observation.account_id != scope.account_id
                or observation.equity_lower_bound_usdt > _money(limits.max_account_equity_usd)
                or intent.strategy_id != scope.strategy_id
                or intent.strategy_revision != scope.strategy_revision
                or venue.profile is not EvedexProfile.PROD
                or not venue.entry_allowed
                or venue.symbol != instrument.symbol
                or scope.venue_symbol_for(intent.symbol) != venue.symbol
                or not intent.entry_eligible_ts_ms <= now_ms < expiry
                or not 0 <= now_ms - venue.observed_at_ms <= 2000
                or not 0 <= now_ms - venue.book_timestamp_ms <= 2000
                or not 0 <= now_ms - venue.reference_timestamp_ms <= 2000
                or not 0 <= (now - instrument.observed_at).total_seconds() <= 5
                or intent.exit_plan.max_holding_ms > 300000
            ):
                return wait("scope_time_or_venue_invalid")
            weights = allocation.strategy_weights
            if (
                intent.strategy_id not in weights
                or any(not _money(v).is_finite() or not 0 <= _money(v) <= 1 for v in weights.values())
                or weights[intent.strategy_id] <= 0
                or not 0 <= (now - allocation.produced_at).total_seconds() <= 26 * 3600
            ):
                return wait("allocation_invalid")
            if None in (entry_slippage_bps, stop_exit_slippage_bps, extra_cost_bound_usdt):
                return wait("cost_bound_missing")
            entry_slip, exit_slip, extra = map(
                _money, (entry_slippage_bps, stop_exit_slippage_bps, extra_cost_bound_usdt)
            )
            if not 0 <= entry_slip < 10000 or not 0 <= exit_slip < 10000 or extra < 0:
                return wait("cost_bound_invalid")
            session_loss = observed_session_loss_usdt(
                baseline_equity_usdt=_money(baseline_equity_usdt),
                current=observation,
                net_deposits_usdt=_money(net_deposits_usdt),
            )
            if baseline_equity_usdt <= 0:
                return wait("baseline_invalid")
            basis = min(Decimal("100"), observation.equity_lower_bound_usdt)
            budget = min(
                Decimal("0.25"),
                basis * Decimal("0.0025"),
                basis * Decimal("0.01"),
                basis * _money(limits.per_trade_risk_fraction),
                basis * _money(limits.aggregate_open_risk_fraction),
                Decimal("5") - session_loss,
                _money(limits.daily_loss_cap_usd) - session_loss,
                _money(limits.per_trade_dollar_cap_usd),
            )
            if budget <= extra or basis <= 0:
                return wait("session_or_trade_budget_exhausted")
            entry = _money(venue.best_ask if intent.side is Side.LONG else venue.best_bid)
            stop, target = _money(intent.exit_plan.stop_price), _money(intent.exit_plan.target_price)
            sign = Decimal(1) if intent.side is Side.LONG else Decimal(-1)
            if not (sign * (entry - stop) > 0 and sign * (target - entry) > 0):
                return wait("exit_geometry_invalid")
            if any(
                p % instrument.tick != 0 or not instrument.min_price <= p <= instrument.max_price
                for p in (entry, stop, target)
            ):
                return wait("price_rules_invalid")
            native_qty, *_ = self._native._size(
                intent=intent,
                venue=venue,
                allocation=allocation,
                account=_SizingCashView(float(basis), float(min(basis, observation.available_usdt))),
                open_notional=0.0,
                reserved_notional=0.0,
                strategy_notional=0.0,
                strategy_reserved_notional=0.0,
                loss_budget=float(budget),
                worst_entry=float(entry),
                instrument_rules=None,
            )
            if native_qty <= 0:
                return wait("native_sizing_rejected")
            with localcontext() as context:
                context.prec = 60
                adjusted_entry = entry * (1 + sign * entry_slip / 10000)
                adjusted_stop = stop * (1 - sign * exit_slip / 10000)
                fee = _money(venue.taker_fee_bps) / 10000
                if not 0 <= fee < 1:
                    return wait("fee_invalid")
                unit_loss = sign * (adjusted_entry - adjusted_stop) + (adjusted_entry + adjusted_stop) * fee
                cash_unit = max(entry, adjusted_entry) * (1 + fee)
                if unit_loss <= 0 or cash_unit <= 0:
                    return wait("cost_geometry_invalid")
                quantity_limit = min(
                    _money(native_qty),
                    (budget - extra) / unit_loss,
                    min(basis, observation.available_usdt) / cash_unit,
                    instrument.max_quantity,
                )
                quantity = (quantity_limit / instrument.quantity_step).to_integral_value(
                    rounding=ROUND_FLOOR
                ) * instrument.quantity_step
                notional = quantity * max(entry, adjusted_entry)
                loss, cash = quantity * unit_loss + extra, quantity * cash_unit
                if (
                    quantity < instrument.min_quantity
                    or quantity * min(entry, adjusted_entry) < instrument.min_notional_usdt
                ):
                    return wait("minimum_lot_exceeds_risk_budget")
                if quantity <= 0 or quantity > _money(native_qty) or loss > budget or cash > basis:
                    return wait("sizing_invariant_invalid")
            return CanarySizingResult(
                status="ELIGIBLE",
                reason="operational_one_canary_only",
                input_binding_sha256=binding,
                valid_until_ms=expiry,
                quantity=quantity,
                entry_limit_price=entry,
                scenario_entry_price=adjusted_entry,
                scenario_stop_exit_price=adjusted_stop,
                notional_usdt=notional,
                cash_required_usdt=cash,
                loss_budget_usdt=budget,
                estimated_loss_usdt=loss,
                estimated_fees_usdt=quantity * (adjusted_entry + adjusted_stop) * fee,
                observed_session_loss_usdt=session_loss,
            )
        except (ArithmeticError, ValueError, TypeError, CanaryAccountError):
            return wait("invalid_or_unknown_inputs")
