"""EVEDEX PROD REST sources for the production path, under an explicit owner trust model.

The pinned sources of this repository refuse on purpose: EVEDEX offers no atomic account
snapshot, no provably complete history, no account funding ledger with settlement
coverage, no TP/SL parent lineage on every row, no recoverable fill stream and no exact
decimal guarantee in the SDK (``production_exposure.GAPS``). On 2026-11-13 the owner chose
to trade EVEDEX PROD through this path anyway, under the weaker model implemented here
and recorded in ``docs/REST-SOURCE-TRUST-MODEL.md``:

* **Single position.** An entry is admitted only while the account is flat: no position,
  no open order, no live TP/SL and no non-terminal Kairos trade. Every order and
  protection on the account is therefore Kairos-owned and identified by the deterministic
  client order IDs the engine sent; funding paid while the trade is open belongs to it.
* **Stable double read.** Account facts are accepted only when two full REST reads, taken
  before and after the engine's reconciled snapshot, agree on balance, positions, open
  orders and live protections. This stands in for the missing atomic snapshot.
* **Exact decimals.** Every number comes from ``ProductionEvedexReads``, which parses the
  original HTTP body with ``Decimal`` and keeps its SHA-256.
* **Lineage from Kairos IDs.** An order is the entry if its ID is the trade's entry client
  order ID and an exit if it is the close ID or a protection's trigger order; anything
  else refuses. A protection without a parent ``order`` refuses.
* **Funding by window.** Terminal funding is the sum of the account's ``fundingRate``
  transfers from the first fill to settlement, complete only because the account held
  this one position (the declared ``funding_complete`` is this model's claim).

Every verifier is synchronous and pure over the raw evidence its provider captured, so
the evidence digest binds exactly what was decided on.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any, Literal

import asyncpg  # type: ignore[import-untyped]  # Upstream ships no typing marker/stubs.
from kairos_core.contracts import (
    AccountSnapshotV2,
    CandidateReviewV1,
    RiskTradeDecisionV1,
    StrategicAllocation,
    VenueQualityV1,
    canonical_sha256,
)
from kairos_core.enums import EvedexProfile, SystemMode, TradingMode
from kairos_persistence import (
    ExecutionEffect,
    ExecutionJournalRepository,
    TradeLifecycleRepository,
    TradeRecord,
    TradeState,
)
from kairos_risk.live import (  # type: ignore[import-untyped]
    LiveRiskScopeV1,
    VerifiedLiveAccountV1,
    VerifiedLiveInputsV1,
)

from .production_cancellation import (
    CancellationOrderFactV1,
    CancellationProtectionFactV1,
    ProductionCancellationVenueSnapshotV1,
)
from .production_exit_risk import VerifiedLiveExitEvidenceV1
from .production_host import PendingTerminalEvidence
from .production_inputs import instrument_rules_from_payload, instrument_timestamp_ms
from .production_lifecycle_binding import LifecycleRole
from .production_readiness import ProductionContextV1, canonical_digest
from .production_reads import ProductionEvedexReads
from .production_reconciliation import ReservationTradeBindingV1, VenueTerminalEvidenceV2
from .production_transport import parse_raw_response_capture
from .signing_authorization import ExposureSnapshotV1

SOURCE_ID = "evedex-prod-rest-v1"
_LEASE = timedelta(seconds=5)
_E8 = Decimal(10**8)
_LIVE_TPSL = frozenset({"waitorder", "active", "process"})
_OPEN_ORDER = frozenset({"NEW", "PARTIALLY_FILLED"})


class RestSourceError(PermissionError):
    """A REST source refused; the message never contains a credential."""


def _d(value: object, label: str) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (int, Decimal, str)):
        raise RestSourceError(f"{label} is not an exact decimal")
    try:
        result = Decimal(value)
    except Exception:
        raise RestSourceError(f"{label} is not an exact decimal") from None
    if not result.is_finite():
        raise RestSourceError(f"{label} is not finite")
    return result


def _side(value: object) -> Literal["BUY", "SELL"]:
    side = str(value).upper()
    if side == "BUY":
        return "BUY"
    if side == "SELL":
        return "SELL"
    raise RestSourceError("side is neither BUY nor SELL")


def _digest(value: object) -> str:
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str, allow_nan=False)
    return hashlib.sha256(text.encode()).hexdigest()


def _utc(value: object, label: str) -> datetime:
    stamp = datetime.fromisoformat(value) if isinstance(value, str) else value
    if not isinstance(stamp, datetime) or stamp.tzinfo is None or stamp.utcoffset() != timedelta(0):
        raise RestSourceError(f"{label} must be explicit UTC")
    return stamp


def _rows(value: object, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not all(isinstance(row, dict) for row in value):
        raise RestSourceError(f"{label} is not a list of objects")
    return value


def _positions(state: Mapping[str, Any], instrument: str | None = None) -> list[dict[str, Any]]:
    return [
        row
        for row in _rows(state.get("positions"), "positions")
        if _d(row.get("quantity"), "position quantity") > 0
        and (instrument is None or str(row.get("instrument", "")).upper() == instrument)
    ]


def _open_orders(state: Mapping[str, Any], instrument: str | None = None) -> list[dict[str, Any]]:
    return [
        row
        for row in _rows(state.get("orders"), "open orders")
        if str(row.get("status", "")).upper().replace("CANCELLED", "CANCELED") in _OPEN_ORDER
        and (instrument is None or str(row.get("instrument", "")).upper() == instrument)
    ]


def _live_tpsl(state: Mapping[str, Any], instrument: str | None = None) -> list[dict[str, Any]]:
    return [
        row
        for row in _rows(state.get("tpsl"), "TP/SL")
        if str(row.get("status", "")).casefold() in _LIVE_TPSL
        and (instrument is None or str(row.get("instrument", "")).upper() == instrument)
    ]


def state_projection(state: Mapping[str, Any]) -> dict[str, Any]:
    """The facts two reads must agree on; marks and clocks may move between them."""
    balance = state.get("balance")
    funding = balance.get("funding") if isinstance(balance, dict) else None
    if not isinstance(funding, dict):
        raise RestSourceError("balance summary lacks its funding object")
    return {
        "balance": str(_d(funding.get("balance"), "funding balance")),
        "positions": sorted(
            (
                str(row.get("instrument")),
                str(row.get("side")),
                str(_d(row.get("quantity"), "position quantity")),
                str(_d(row.get("avgPrice"), "position entry")),
            )
            for row in _positions(state)
        ),
        "orders": sorted(
            (str(row.get("id")), str(row.get("status")), str(_d(row.get("unFilledQuantity"), "remaining")))
            for row in _open_orders(state)
        ),
        "tpsl": sorted((str(row.get("id")), str(row.get("status"))) for row in _live_tpsl(state)),
    }


def _mark(state: Mapping[str, Any], instrument: str) -> Decimal:
    matches = [
        row
        for row in _rows(state.get("instruments"), "instruments")
        if str(row.get("name", "")).upper() == instrument
    ]
    if len(matches) != 1:
        raise RestSourceError("instrument metrics are missing or duplicated")
    metrics = matches[0].get("metrics", matches[0])
    mark = _d(metrics.get("markPrice") if isinstance(metrics, dict) else None, "mark price")
    if mark <= 0:
        raise RestSourceError("mark price is not positive")
    return mark


async def _open_trades(trades: TradeLifecycleRepository, context: ProductionContextV1) -> list[TradeRecord]:
    return [
        trade
        for trade in await trades.recovery_required(
            environment=f"PROD:{canonical_digest(context)}:LIVE", account_id=context.remote_account_id
        )
        if trade.state not in {TradeState.FLAT, TradeState.CANCELLED}
    ]


# --------------------------------------------------------------------------- entry evidence


class RestEntryEvidenceProvider:
    """Capture raw account and input evidence for one entry, just before submission.

    ``account_snapshot`` is the engine's own reconciled ``AccountSnapshotV2`` (venue
    state plus durable lineage and durable day-start/peak equity). It is bracketed by
    two full reads that must agree.
    """

    source_id = SOURCE_ID

    def __init__(
        self,
        *,
        reads: ProductionEvedexReads,
        trades: TradeLifecycleRepository,
        context: ProductionContextV1,
        account_snapshot: Callable[[], Any],
        clock: Callable[[], datetime],
    ) -> None:
        self.reads = reads
        self.trades = trades
        self.context = context
        self._account_snapshot = account_snapshot
        self.clock = clock
        self._instruments_capture: dict[str, Any] | None = None

    async def capture_account(self) -> dict[str, Any]:
        """Account evidence: two agreeing full reads around the engine's reconciled snapshot.

        The second read's original ``instruments`` capture is kept for ``inputs_for``.
        """
        before = state_projection(await self.reads.fetch_paper_state())
        snapshot = await self._account_snapshot()
        after_state = await self.reads.fetch_paper_state()
        self._instruments_capture = dict(self.reads.last_captures["instruments"])
        return {
            "version": "kairos.evedex-rest-account-evidence.v1",
            "before": before,
            "after": state_projection(after_state),
            "snapshot": AccountSnapshotV2.model_validate(snapshot).model_dump(mode="json"),
            "open_trade_ids": sorted(
                trade.trade_id for trade in await _open_trades(self.trades, self.context)
            ),
            "captured_at": self.clock().isoformat(),
        }

    def inputs_for(self, venue: VenueQualityV1) -> dict[str, Any]:
        """Input evidence binding the fresh venue measurement to the instrument capture."""
        if self._instruments_capture is None:
            raise RestSourceError("input evidence needs the account capture first")
        return {
            "version": "kairos.evedex-rest-input-evidence.v1",
            "venue_measurement_id": venue.measurement_id,
            "instruments_capture": self._instruments_capture,
        }

    async def capture(self, *, venue: VenueQualityV1) -> tuple[dict[str, Any], dict[str, Any]]:
        account = await self.capture_account()
        return account, self.inputs_for(venue)


class RestLiveAccountVerifier:
    """``VerifiedLiveAccountV1`` from a flat, stable, reconciled account."""

    source_id = SOURCE_ID

    def verify(
        self, raw_evidence: object, *, source_id: str, expected_scope: LiveRiskScopeV1
    ) -> VerifiedLiveAccountV1:
        if source_id != self.source_id:
            raise RestSourceError("REST account source identity mismatch")
        if not isinstance(raw_evidence, dict) or set(raw_evidence) != {
            "version",
            "before",
            "after",
            "snapshot",
            "open_trade_ids",
            "captured_at",
        }:
            raise RestSourceError("REST account evidence fields are not exact")
        if raw_evidence["version"] != "kairos.evedex-rest-account-evidence.v1":
            raise RestSourceError("REST account evidence version is unknown")
        if raw_evidence["before"] != raw_evidence["after"]:
            raise RestSourceError("account changed between the bracketing reads")
        account = AccountSnapshotV2.model_validate(raw_evidence["snapshot"])
        after = raw_evidence["after"]
        if (
            account.account_id != expected_scope.account_id
            or account.trading_mode is not TradingMode.LIVE
            or account.evedex_profile is not EvedexProfile.PROD
            or not account.reconciled
        ):
            raise RestSourceError("snapshot is not the reconciled LIVE PROD scope account")
        if (
            account.positions
            or account.open_orders
            or raw_evidence["open_trade_ids"]
            or after["positions"]
            or after["orders"]
            or after["tpsl"]
        ):
            raise RestSourceError("single-position model admits an entry only on a flat account")
        unrealized = account.unrealized_pnl_usd
        daily_adverse = max(
            max(0.0, -account.daily_realized_pnl_usd) + max(0.0, -unrealized),
            max(0.0, account.durable_day_start_equity_usd - account.equity_usd),
        )
        return VerifiedLiveAccountV1(
            source_id=self.source_id,
            scope_sha256=expected_scope.scope_sha256,
            evidence_sha256=_digest(raw_evidence),
            as_of_ms=account.captured_at_ms,
            account=account,
            aggregate_open_risk_usd=float(account.total_open_risk_usd),
            aggregate_open_notional_usd=0.0,
            reserved_open_risk_usd=0.0,
            reserved_open_notional_usd=0.0,
            strategy_open_notional_usd=0.0,
            strategy_reserved_notional_usd=0.0,
            daily_adverse_loss_usd=float(daily_adverse),
        )


class RestLiveInputsVerifier:
    """Input proof with authenticated instrument rules from the original HTTP capture."""

    source_id = SOURCE_ID

    def verify(
        self,
        raw_proof: object,
        *,
        expected_scope: LiveRiskScopeV1,
        review: CandidateReviewV1,
        venue: VenueQualityV1,
        allocation: StrategicAllocation | None,
        system_mode: SystemMode,
        decided_at_ms: int,
    ) -> VerifiedLiveInputsV1:
        if not isinstance(raw_proof, dict) or set(raw_proof) != {
            "version",
            "venue_measurement_id",
            "instruments_capture",
        }:
            raise RestSourceError("REST input evidence fields are not exact")
        if raw_proof["version"] != "kairos.evedex-rest-input-evidence.v1":
            raise RestSourceError("REST input evidence version is unknown")
        if raw_proof["venue_measurement_id"] != venue.measurement_id:
            raise RestSourceError("input evidence belongs to another venue measurement")
        capture = raw_proof["instruments_capture"]
        if not isinstance(capture, dict) or not 200 <= capture.get("status", 0) < 300:
            raise RestSourceError("instrument capture is not a successful original response")
        payload = parse_raw_response_capture(
            capture, source="instruments", expected_query={"fields": "metrics"}
        )
        received_ms = instrument_timestamp_ms(capture["received_at"])
        evidence_sha256 = _digest(raw_proof)
        rules = instrument_rules_from_payload(
            payload,
            venue_symbol=venue.symbol,
            source_id=self.source_id,
            scope_sha256=expected_scope.scope_sha256,
            evidence_sha256=evidence_sha256,
            received_ms=received_ms,
        )
        return VerifiedLiveInputsV1(
            source_id=self.source_id,
            scope_sha256=expected_scope.scope_sha256,
            evidence_sha256=evidence_sha256,
            review_sha256=canonical_sha256(review.model_dump(mode="json")),
            venue_sha256=canonical_sha256(venue.model_dump(mode="json")),
            allocation_sha256=canonical_sha256(allocation.model_dump(mode="json")) if allocation else None,
            system_mode=system_mode,
            observed_at_ms=received_ms,
            instrument_rules=rules,
        )


# --------------------------------------------------------------------------- exits


class RestPreparedExitEvidenceProvider:
    """Raw facts for one PREPARED exit effect: its position, book and durable equity."""

    source_id = SOURCE_ID

    def __init__(
        self,
        *,
        reads: ProductionEvedexReads,
        effects: ExecutionJournalRepository,
        trades: TradeLifecycleRepository,
        pool: asyncpg.Pool,
        clock: Callable[[], datetime],
    ) -> None:
        self.reads, self.effects, self.trades, self.pool, self.clock = reads, effects, trades, pool, clock

    async def capture_prepared_exit(
        self, *, context: ProductionContextV1, effect_id: str, now: datetime
    ) -> object:
        effect = await self.effects.get(effect_id)
        if effect is None or effect.trade_id is None:
            raise RestSourceError("prepared exit effect is unknown")
        trade = await self.trades.get(effect.trade_id)
        if trade is None:
            raise RestSourceError("prepared exit trade is unknown")
        state = await self.reads.fetch_paper_state()
        depth = await self.reads.fetch_best_depth(symbol=trade.symbol)
        day_start = await self.pool.fetchval(
            "SELECT day_start_equity_usd FROM public.account_equity_state "
            "WHERE environment=$1 AND account_id=$2 ORDER BY trading_day DESC LIMIT 1",
            trade.environment,
            trade.account_id,
        )
        balance = state["balance"]["funding"]["balance"]
        return {
            "version": "kairos.evedex-rest-exit-evidence.v1",
            "effect_id": effect_id,
            "instrument": trade.venue_symbol,
            "positions": _positions(state, trade.venue_symbol),
            "mark": str(_mark(state, trade.venue_symbol)),
            "balance": str(_d(balance, "funding balance")),
            "best_bid": str(_d(depth["bids"][0]["price"], "best bid")),
            "best_ask": str(_d(depth["asks"][0]["price"], "best ask")),
            "day_start_equity": None if day_start is None else str(Decimal(str(day_start))),
            "observed_at": self.clock().isoformat(),
        }


class RestLiveExitVerifier:
    """``VerifiedLiveExitEvidenceV1`` for the one Kairos position on the instrument."""

    source_id = SOURCE_ID

    def __init__(self, *, exit_fee_rate: Decimal, adverse_slippage_rate: Decimal) -> None:
        if not (Decimal(0) <= exit_fee_rate < 1 and Decimal(0) <= adverse_slippage_rate < 1):
            raise ValueError("exit fee and slippage rates must be fractions in [0, 1)")
        self.exit_fee_rate = exit_fee_rate
        self.adverse_slippage_rate = adverse_slippage_rate

    def verify_exit(
        self,
        raw_evidence: object,
        *,
        expected_context: ProductionContextV1,
        trade: TradeRecord,
        decision: RiskTradeDecisionV1,
        effect: ExecutionEffect,
        role: LifecycleRole,
        now: datetime,
    ) -> VerifiedLiveExitEvidenceV1:
        if (
            not isinstance(raw_evidence, dict)
            or raw_evidence.get("version") != "kairos.evedex-rest-exit-evidence.v1"
        ):
            raise RestSourceError("REST exit evidence is malformed")
        if raw_evidence["effect_id"] != effect.effect_key or raw_evidence["instrument"] != trade.venue_symbol:
            raise RestSourceError("exit evidence belongs to another effect or instrument")
        positions = _rows(raw_evidence["positions"], "positions")
        if len(positions) != 1 or str(positions[0].get("side", "")).upper() != trade.side:
            raise RestSourceError("exactly one same-side position is required for an exit")
        position = positions[0]
        quantity = _d(position.get("quantity"), "position quantity")
        units = quantity * _E8
        if units != units.to_integral_value() or units <= 0:
            raise RestSourceError("position quantity is not an exact positive 1e-8 multiple")
        entry = _d(position.get("avgPrice"), "position entry")
        bid, ask = _d(raw_evidence["best_bid"], "best bid"), _d(raw_evidence["best_ask"], "best ask")
        mark = _d(raw_evidence["mark"], "mark")
        if not 0 < bid < ask or entry <= 0:
            raise RestSourceError("book or entry price is invalid")
        observed = _utc(raw_evidence["observed_at"], "observed_at")
        valid_until = observed + _LEASE
        long_position = trade.side == "BUY"
        unrealized = (mark - entry) * quantity * (1 if long_position else -1)
        equity = _d(raw_evidence["balance"], "funding balance") + min(Decimal(0), unrealized)
        if equity <= 0:
            raise RestSourceError("account equity is not positive")
        day_start = raw_evidence["day_start_equity"]
        daily_loss = max(Decimal(0), _d(day_start, "day start equity") - equity) if day_start else Decimal(0)
        exposure = ExposureSnapshotV1(
            context=expected_context,
            instrument=trade.venue_symbol,
            position_side=_side(trade.side),
            remaining_quantity=int(units),
            parent_order_id=trade.entry_client_order_id,
            observed_at=observed,
            valid_until=valid_until,
        )
        return VerifiedLiveExitEvidenceV1(
            source_id=self.source_id,
            evidence_sha256=_digest(raw_evidence),
            context_sha256=canonical_digest(expected_context),
            trade_id=trade.trade_id,
            original_decision_id=_required(decision.decision_id, "decision id"),
            original_decision_sha256=canonical_digest(decision),
            effect_id=effect.effect_key,
            effect_request_sha256=effect.request_sha256,
            role=role,
            exposure=exposure,
            account_equity_usd=equity,
            daily_realized_loss_usd=daily_loss,
            aggregate_open_risk_usd=quantity * abs(entry - Decimal(str(trade.stop_price))),
            aggregate_open_notional_usd=quantity * mark,
            position_entry_price_usd=entry,
            reference_price_usd=(bid + ask) / 2,
            executable_exit_price_usd=bid if long_position else ask,
            exit_fee_rate=self.exit_fee_rate,
            adverse_slippage_rate=self.adverse_slippage_rate,
            observed_at=observed,
            valid_until=valid_until,
        )


# --------------------------------------------------------------------------- cancellation


class RestCancellationVenueSource:
    """Cancellation snapshot of the one Kairos trade, roles taken from Kairos IDs."""

    source_id = SOURCE_ID

    def __init__(
        self,
        *,
        reads: ProductionEvedexReads,
        trades: TradeLifecycleRepository,
        clock: Callable[[], datetime],
    ) -> None:
        self.reads, self.trades, self.clock = reads, trades, clock

    async def read_cancellation_snapshot_async(
        self, *, context: ProductionContextV1, account_id: str, instrument: str
    ) -> Any:
        state = await self.reads.fetch_paper_state()
        observed = self.clock()
        trades = [
            trade for trade in await _open_trades(self.trades, context) if trade.venue_symbol == instrument
        ]
        return {
            "version": "kairos.evedex-rest-cancellation-evidence.v1",
            "account_id": account_id,
            "instrument": instrument,
            "positions": _positions(state, instrument),
            "orders": _open_orders(state, instrument),
            "tpsl": _live_tpsl(state, instrument),
            "trade": None
            if len(trades) != 1
            else {
                "entry": trades[0].entry_client_order_id,
                "close": trades[0].close_client_order_id,
                "side": trades[0].side,
                "quantity": str(trades[0].quantity),
            },
            "open_trades": len(trades),
            "observed_at": observed.isoformat(),
        }

    def verify_cancellation_snapshot(
        self, raw_snapshot: Any, *, context: ProductionContextV1, account_id: str, instrument: str
    ) -> ProductionCancellationVenueSnapshotV1:
        raw = raw_snapshot
        if (
            not isinstance(raw, dict)
            or raw.get("version") != "kairos.evedex-rest-cancellation-evidence.v1"
            or raw["account_id"] != account_id
            or raw["instrument"] != instrument
        ):
            raise RestSourceError("REST cancellation evidence is malformed or out of scope")
        if raw["open_trades"] != 1 or raw["trade"] is None:
            raise RestSourceError("cancellation needs exactly one open Kairos trade on the instrument")
        lineage = raw["trade"]
        positions = _rows(raw["positions"], "positions")
        if len(positions) > 1:
            raise RestSourceError("duplicate positions for one instrument")
        position_quantity = _d(positions[0]["quantity"], "position quantity") if positions else Decimal(0)
        position_side = _side(positions[0]["side"]) if positions else None
        orders = []
        for row in _rows(raw["orders"], "orders"):
            order_id = str(row.get("id"))
            role: Literal["ENTRY", "EXIT"]
            if order_id == lineage["entry"]:
                role, reduce_only = "ENTRY", False
            elif order_id == lineage["close"]:
                role, reduce_only = "EXIT", True
            else:
                raise RestSourceError("an open order on the instrument is not Kairos-owned")
            status = str(row.get("status")).upper()
            orders.append(
                CancellationOrderFactV1(
                    order_id=order_id,
                    instrument=instrument,
                    role=role,
                    status="OPEN" if status == "NEW" else "PARTIALLY_FILLED",
                    side=_side(row.get("side")),
                    remaining_quantity=_d(row.get("unFilledQuantity"), "remaining quantity"),
                    reduce_only=reduce_only,
                    parent_order_id=None if role == "ENTRY" else lineage["entry"],
                )
            )
        protections = []
        for row in _rows(raw["tpsl"], "TP/SL"):
            parent = row.get("order")
            if not isinstance(parent, str) or not parent:
                raise RestSourceError("a live protection lacks its parent order")
            kind = str(row.get("type", "")).casefold()
            if kind not in {"stop-loss", "take-profit"}:
                raise RestSourceError("a live protection has an unknown type")
            if str(row.get("status", "")).casefold() != "active":
                continue  # Waiting or processing protections do not cover a position yet.
            protections.append(
                CancellationProtectionFactV1(
                    protection_id=str(row.get("id")),
                    instrument=instrument,
                    protection_type="STOP_LOSS" if kind == "stop-loss" else "TAKE_PROFIT",
                    status="ACTIVE",
                    parent_order_id=parent,
                    # A whole-position (quantity 0) protection covers the position; once
                    # the account is flat it still stands for the trade's nominal size.
                    covered_quantity=position_quantity
                    if position_quantity > 0
                    else _d(lineage["quantity"], "trade quantity"),
                )
            )
        observed = _utc(raw["observed_at"], "observed_at")
        return ProductionCancellationVenueSnapshotV1(
            context=context,
            source_id=self.source_id,
            account_id=account_id,
            instrument=instrument,
            observed_at=observed,
            valid_until=observed + _LEASE,
            position_side=position_side if position_quantity > 0 else None,
            position_quantity=position_quantity,
            entry_parent_order_id=None,
            orders=tuple(orders),
            protections=tuple(protections),
        )


# --------------------------------------------------------------------------- terminal


class RestTerminalEvidenceProvider:
    """Terminal facts of one FLAT trade: fills of its entry and exit orders and funding."""

    source_id = SOURCE_ID
    _SETTLE_GRACE = timedelta(seconds=10)

    def __init__(
        self,
        *,
        reads: ProductionEvedexReads,
        trades: TradeLifecycleRepository,
        reservations_pool: asyncpg.Pool,
        context: ProductionContextV1,
        clock: Callable[[], datetime],
    ) -> None:
        self.reads, self.trades, self.pool, self.context, self.clock = (
            reads,
            trades,
            reservations_pool,
            context,
            clock,
        )

    async def __call__(self, trade_id: str, source_id: str) -> object:
        if source_id != self.source_id:
            raise RestSourceError("terminal source identity mismatch")
        started = self.clock()
        trade = await self.trades.get(trade_id)
        if trade is None or trade.state is not TradeState.FLAT or trade.first_fill_at is None:
            raise RestSourceError("terminal evidence needs a FLAT trade with a first fill")
        if trade.last_reconciled_at is not None and started - trade.last_reconciled_at < self._SETTLE_GRACE:
            return PendingTerminalEvidence(trade_id=trade_id, source_id=source_id, observed_at=started)
        state = await self.reads.fetch_paper_state()
        exit_ids = {trade.close_exchange_order_id} if trade.close_exchange_order_id else set()
        for row in _rows(state.get("tpsl"), "TP/SL"):
            if str(row.get("id")) in {trade.stop_exchange_order_id, trade.target_exchange_order_id}:
                trigger = row.get("triggerOrder")
                if isinstance(trigger, str) and trigger:
                    exit_ids.add(trigger)
        entry_fills = await self.reads.fetch_order_fills(
            order_id=_required(trade.entry_exchange_order_id, "entry order id")
        )
        exit_fills = {
            order_id: await self.reads.fetch_order_fills(order_id=order_id) for order_id in sorted(exit_ids)
        }
        funding: list[dict[str, Any]] = []
        after = trade.first_fill_at
        while after < started:
            before = min(after + timedelta(days=1) - timedelta(milliseconds=1), started)
            offset = 0
            while True:
                page = await self.reads.fetch_funding_transfers(
                    after=_ms_z(after),
                    before=_ms_z(before),
                    transfer_type="fundingRate",
                    limit=100,
                    offset=offset,
                )
                rows = _rows(page.get("list"), "funding page")
                funding.extend(rows)
                offset += len(rows)
                if len(rows) < 100:
                    break
            after = before + timedelta(milliseconds=1)
        reservation = await self.pool.fetchrow(
            "SELECT owner_arm_sha256, request_sha256 FROM kairos_production_state_v1.risk_reservations "
            "WHERE context_sha256=$1 AND decision_id=$2",
            canonical_digest(self.context),
            trade.risk_decision_id,
        )
        if reservation is None:
            raise RestSourceError("the trade's risk reservation is not visible to the reconciler")
        return {
            "version": "kairos.evedex-rest-terminal-evidence.v1",
            "trade_id": trade_id,
            "instrument": trade.venue_symbol,
            "entry_side": trade.side,
            "entry_fills": entry_fills,
            "exit_fills": exit_fills,
            "funding": funding,
            "positions": _positions(state, trade.venue_symbol),
            "orders": _open_orders(state, trade.venue_symbol),
            "tpsl": _live_tpsl(state, trade.venue_symbol),
            "foreign_positions": len(_positions(state)) - len(_positions(state, trade.venue_symbol)),
            "owner_arm_sha256": reservation["owner_arm_sha256"],
            "reservation_request_sha256": reservation["request_sha256"],
            "collection_started_at": started.isoformat(),
            "collection_finished_at": self.clock().isoformat(),
        }


def _required(value: str | None, label: str) -> str:
    if not value:
        raise RestSourceError(f"{label} is missing")
    return value


def _ms_z(stamp: datetime) -> str:
    return stamp.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.") + f"{stamp.microsecond // 1000:03d}Z"


def _fill_totals(rows: list[dict[str, Any]], label: str) -> tuple[Decimal, Decimal, Decimal, datetime | None]:
    quantity = notional = fees = Decimal(0)
    last: datetime | None = None
    for row in rows:
        fill_quantity = _d(row.get("fillQuantity"), f"{label} fill quantity")
        fill_price = _d(row.get("fillPrice"), f"{label} fill price")
        if fill_quantity <= 0 or fill_price <= 0:
            raise RestSourceError(f"{label} fill is not positive")
        quantity += fill_quantity
        notional += fill_quantity * fill_price
        for fee in _rows(row.get("fee", []), f"{label} fee"):
            if str(fee.get("coin", "")).casefold() not in {"usdt", "usd"}:
                raise RestSourceError(f"{label} fee is not in USD")
            fees += abs(_d(fee.get("quantity"), f"{label} fee"))
        created = _utc(str(row.get("createdAt", "")).replace("Z", "+00:00"), f"{label} fill time")
        last = created if last is None or created > last else last
    return quantity, notional, fees, last


class RestTerminalEvidenceVerifier:
    """``VenueTerminalEvidenceV2`` from per-order fills, residual state and funding."""

    source_id = SOURCE_ID

    def verify_terminal_evidence(
        self, raw_evidence: Any, *, context: ProductionContextV1, binding: ReservationTradeBindingV1
    ) -> VenueTerminalEvidenceV2:
        raw = raw_evidence
        if not isinstance(raw, dict) or raw.get("version") != "kairos.evedex-rest-terminal-evidence.v1":
            raise RestSourceError("REST terminal evidence is malformed")
        if raw["trade_id"] != binding.trade_id:
            raise RestSourceError("terminal evidence belongs to another trade")
        entry_quantity, entry_notional, entry_fees, _ = _fill_totals(raw["entry_fills"], "entry")
        exit_quantity = exit_notional = exit_fees = Decimal(0)
        settled: datetime | None = None
        for order_id, rows in sorted(raw["exit_fills"].items()):
            quantity, notional, fees, last = _fill_totals(rows, f"exit {order_id}")
            exit_quantity, exit_notional, exit_fees = (
                exit_quantity + quantity,
                exit_notional + notional,
                exit_fees + fees,
            )
            settled = last if settled is None or (last is not None and last > settled) else settled
        if entry_quantity <= 0 or exit_quantity <= 0 or settled is None:
            raise RestSourceError("entry and exit fills are both required")
        funding = Decimal(0)
        for row in _rows(raw["funding"], "funding"):
            if row.get("type") != "fundingRate" or str(row.get("coin", "")).casefold() not in {"usdt", "usd"}:
                raise RestSourceError("funding transfer is not a USD funding payment")
            funding += _d(row.get("quantity"), "funding quantity")
        started = _utc(raw["collection_started_at"], "collection start")
        finished = _utc(raw["collection_finished_at"], "collection finish")
        residual_positions = _rows(raw["positions"], "positions")
        residual_quantity = sum((_d(row["quantity"], "residual") for row in residual_positions), Decimal(0))
        return VenueTerminalEvidenceV2(
            source_id=self.source_id,
            source_evidence_sha256=_digest(raw),
            context_sha256=canonical_digest(context),
            account_id=context.remote_account_id,
            trade_id=binding.trade_id,
            decision_id=binding.decision_id,
            effect_id=binding.effect_id,
            lifecycle_entry_effect_id=binding.lifecycle_entry_effect_id,
            signing_request_id=binding.signing_request_id,
            client_order_id=binding.client_order_id,
            exchange_parent_order_id=binding.exchange_parent_order_id,
            collection_started_at=started,
            collection_finished_at=finished,
            observed_at=finished,
            complete=True,
            terminal=exit_quantity == entry_quantity and residual_quantity == 0,
            entry_filled_quantity=entry_quantity,
            closed_quantity=exit_quantity,
            entry_notional_usd=entry_notional,
            exit_notional_usd=exit_notional,
            entry_fees_usd=entry_fees,
            exit_fees_usd=exit_fees,
            residual_position_quantity=residual_quantity,
            residual_order_count=len(_rows(raw["orders"], "orders")),
            residual_protection_count=len(_rows(raw["tpsl"], "TP/SL")),
            unowned_exposure_count=int(raw["foreign_positions"]),
            entry_side=raw["entry_side"],
            funding_cost_usd=-funding,
            funding_complete=True,
            settled_at=min(settled, finished),
            owner_arm_sha256=raw["owner_arm_sha256"],
            reservation_request_sha256=raw["reservation_request_sha256"],
        )


__all__ = [
    "SOURCE_ID",
    "RestCancellationVenueSource",
    "RestEntryEvidenceProvider",
    "RestLiveAccountVerifier",
    "RestLiveExitVerifier",
    "RestLiveInputsVerifier",
    "RestPreparedExitEvidenceProvider",
    "RestSourceError",
    "RestTerminalEvidenceProvider",
    "RestTerminalEvidenceVerifier",
    "state_projection",
]
