"""Strict immutable inputs and outputs for a model, never observed venue fills."""

from __future__ import annotations

import hashlib
import json
from decimal import Context, Decimal, localcontext
from typing import Annotated, Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

Identifier = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]*$")]
Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Timestamp = Annotated[int, Field(ge=0, le=9_223_372_036_854_775_807)]
PositiveAmount = Annotated[Decimal, Field(gt=0, le=Decimal("1e18"), max_digits=38, decimal_places=18)]
NonnegativeAmount = Annotated[Decimal, Field(ge=0, le=Decimal("1e18"), max_digits=38, decimal_places=18)]
CalculatedNonnegative = Annotated[
    Decimal, Field(ge=0, le=Decimal("1e40"), max_digits=160, decimal_places=120)
]
CalculatedPositive = Annotated[Decimal, Field(gt=0, le=Decimal("1e40"), max_digits=160, decimal_places=120)]
Symbol = Literal["BTCUSDT", "ETHUSDT", "SOLUSDT", "BNBUSDT", "XRPUSDT"]
OrderSide = Literal["BUY", "SELL"]
BookSide = Literal["BID", "ASK"]
MAX_COMMANDS = 1_024


def _canonical_value(value: Any) -> Any:
    if isinstance(value, Decimal):
        if value == 0:
            return "0"
        rendered = format(value, "f")
        return rendered.rstrip("0").rstrip(".") if "." in rendered else rendered
    if isinstance(value, BaseModel):
        return _canonical_value(value.model_dump(mode="python"))
    if isinstance(value, dict):
        return {key: _canonical_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_canonical_value(item) for item in value]
    return value


class ImmutableModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        allow_inf_nan=False,
        revalidate_instances="always",
    )

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            _canonical_value(self),
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")

    def fingerprint(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


class BookLevel(ImmutableModel):
    price: PositiveAmount
    quantity: PositiveAmount


class AcceptedBookFrame(ImmutableModel):
    """Caller-admitted durable TOP_N snapshot; this DTO cannot prove persistence/authenticity."""

    contract_version: Literal["simulated-book-input.v1"] = "simulated-book-input.v1"
    market_data_venue: Literal["BINANCE_UM"] = "BINANCE_UM"
    stream_kind: Literal["TOP_N_SNAPSHOT"] = "TOP_N_SNAPSHOT"
    tape_id: Identifier
    stream_epoch: Identifier
    symbol: Symbol
    sequence: int = Field(gt=0)
    exchange_update_id: int = Field(gt=0)
    exchange_at_ms: Timestamp
    received_at_ms: Timestamp
    persisted_at_ms: Timestamp
    raw_payload_sha256: Sha256
    continuity: Literal["ADMITTED", "GAP", "RECONNECT", "UNKNOWN", "UNAVAILABLE"]
    bids: tuple[BookLevel, ...] = Field(max_length=100)
    asks: tuple[BookLevel, ...] = Field(max_length=100)

    @model_validator(mode="after")
    def coherent_frame(self) -> Self:
        if not self.exchange_at_ms <= self.received_at_ms <= self.persisted_at_ms:
            raise ValueError("frame requires exchange <= received <= persisted timestamps")
        if self.continuity == "ADMITTED" and (not self.bids or not self.asks):
            raise ValueError("admitted book must contain both sides")
        bid_prices = tuple(level.price for level in self.bids)
        ask_prices = tuple(level.price for level in self.asks)
        if bid_prices != tuple(sorted(set(bid_prices), reverse=True)):
            raise ValueError("bids must be unique and strictly descending")
        if ask_prices != tuple(sorted(set(ask_prices))):
            raise ValueError("asks must be unique and strictly ascending")
        if self.bids and self.asks and self.bids[0].price >= self.asks[0].price:
            raise ValueError("book must not be locked or crossed")
        return self


class IOCCommand(ImmutableModel):
    contract_version: Literal["simulated-ioc-command.v1"] = "simulated-ioc-command.v1"
    execution_environment: Literal["SIMULATED"] = "SIMULATED"
    order_type: Literal["IOC_LIMIT"] = "IOC_LIMIT"
    session_id: Identifier
    command_id: Identifier
    symbol: Symbol
    side: OrderSide
    quantity: PositiveAmount
    price_cap: PositiveAmount
    submitted_at_ms: Timestamp
    persisted_at_ms: Timestamp
    eligible_at_ms: Timestamp
    expires_at_ms: Timestamp

    @model_validator(mode="after")
    def coherent_command(self) -> Self:
        if self.persisted_at_ms < self.submitted_at_ms:
            raise ValueError("command persistence cannot predate submission")
        if self.expires_at_ms < self.eligible_at_ms:
            raise ValueError("command expiry cannot predate eligibility")
        return self


class FillAssumptions(ImmutableModel):
    """Explicit model assumptions, not a verified fee tier, queue or venue guarantee."""

    model_version: Literal["causal-taker-ioc.model-v1"] = "causal-taker-ioc.model-v1"
    liquidity_policy: Literal["SESSION_PRICE_DEBIT_NO_REPLENISHMENT"] = "SESSION_PRICE_DEBIT_NO_REPLENISHMENT"
    latency_ms: int = Field(ge=0, le=60_000)
    maximum_book_age_ms: int = Field(gt=0, le=60_000)
    maximum_frame_latency_ms: int = Field(gt=0, le=60_000)
    depth_participation_fraction: Decimal = Field(gt=0, le=1, max_digits=19, decimal_places=18)
    adverse_slippage_bps: NonnegativeAmount
    taker_fee_bps: NonnegativeAmount
    price_tick: PositiveAmount
    quantity_step: PositiveAmount

    @model_validator(mode="after")
    def finite_adverse_costs(self) -> Self:
        if self.adverse_slippage_bps >= 10_000 or self.taker_fee_bps > 10_000:
            raise ValueError("model slippage must be below 100%, fees at most 100%")
        return self


class ConsumedDepth(ImmutableModel):
    """Session-long debit at one side/price; a fresh snapshot cannot replenish it."""

    side: BookSide
    price: PositiveAmount
    quantity: CalculatedPositive


class LevelFill(ImmutableModel):
    book_price: PositiveAmount
    execution_price: CalculatedPositive
    quantity: PositiveAmount
    fee_quote: CalculatedNonnegative


class FillOutcome(ImmutableModel):
    execution_kind: Literal["SIMULATED"] = "SIMULATED"
    quote_asset: Literal["USDT"] = "USDT"
    venue_execution_observed: Literal[False] = False
    alpha_claim: Literal[False] = False
    command_id: Identifier
    command_sha256: Sha256
    assumptions_sha256: Sha256
    # A blocked no-book command has no honest frame provenance.  Normal kernel
    # paths still carry the exact accepted-frame fingerprint, while the
    # controller can retain causal ordering for a terminal NO_ADMITTED_BOOK
    # result without inventing a market-data input.
    frame_sha256: Sha256 | None = None
    status: Literal["WAIT", "FILLED", "PARTIAL", "NO_FILL", "BLOCKED"]
    reason: str = Field(min_length=1, max_length=100)
    arrival_at_ms: Timestamp
    requested_quantity: PositiveAmount
    filled_quantity: NonnegativeAmount
    cancelled_quantity: NonnegativeAmount
    average_price: CalculatedPositive | None = None
    notional_quote: CalculatedNonnegative
    fee_quote: CalculatedNonnegative
    arrival_mid_price: CalculatedPositive | None = None
    implementation_shortfall_quote: CalculatedNonnegative
    level_fills: tuple[LevelFill, ...] = Field(max_length=100)

    @model_validator(mode="after")
    def coherent_outcome(self) -> Self:
        with localcontext(Context(prec=96)):
            quantity = sum((fill.quantity for fill in self.level_fills), Decimal(0))
            notional = sum((fill.quantity * fill.execution_price for fill in self.level_fills), Decimal(0))
            fees = sum((fill.fee_quote for fill in self.level_fills), Decimal(0))
            if (quantity, notional, fees) != (self.filled_quantity, self.notional_quote, self.fee_quote):
                raise ValueError("fill totals must match their immutable level fills")
            if self.status == "WAIT":
                if quantity or self.cancelled_quantity:
                    raise ValueError("WAIT cannot consume or cancel quantity")
            elif quantity + self.cancelled_quantity != self.requested_quantity:
                raise ValueError("terminal quantity must be filled or cancelled exactly once")
            if self.status == "FILLED" and quantity != self.requested_quantity:
                raise ValueError("FILLED requires the entire requested quantity")
            if self.status == "PARTIAL" and not 0 < quantity < self.requested_quantity:
                raise ValueError("PARTIAL requires strictly partial quantity")
            if self.status in {"WAIT", "NO_FILL", "BLOCKED"} and quantity:
                raise ValueError("non-fill statuses cannot contain fills")
            if quantity and self.frame_sha256 is None:
                raise ValueError("a model fill requires its exact accepted book frame")
            if self.average_price != (notional / quantity if quantity else None):
                raise ValueError("average price must match filled notional and quantity")
            if quantity and self.arrival_mid_price is None:
                raise ValueError("a model fill requires its arrival book reference")
            if not quantity and self.implementation_shortfall_quote:
                raise ValueError("no quantity means no execution shortfall")
        return self


class CommandReceipt(ImmutableModel):
    command_id: Identifier
    command_sha256: Sha256
    assumptions_sha256: Sha256
    outcome: FillOutcome


class LiquidityState(ImmutableModel):
    """Caller must persist this atomically; no internal process cache or hidden state."""

    session_id: Identifier
    tape_id: Identifier
    stream_epoch: Identifier
    symbol: Symbol
    assumptions_sha256: Sha256 | None = None
    last_as_of_ms: Timestamp = 0
    last_arrival_at_ms: Timestamp = 0
    last_frame_sequence: int = Field(default=0, ge=0)
    last_exchange_update_id: int = Field(default=0, ge=0)
    last_exchange_at_ms: Timestamp = 0
    last_received_at_ms: Timestamp = 0
    last_frame_sha256: Sha256 | None = None
    barrier_reason: str | None = Field(default=None, min_length=1, max_length=100)
    consumed_depth: tuple[ConsumedDepth, ...] = Field(default=(), max_length=102_400)
    receipts: tuple[CommandReceipt, ...] = Field(default=(), max_length=MAX_COMMANDS)

    @model_validator(mode="after")
    def coherent_state(self) -> Self:
        keys = [(item.side, item.price) for item in self.consumed_depth]
        if len(keys) != len(set(keys)):
            raise ValueError("depth consumption keys must be unique")
        commands = [item.command_id for item in self.receipts]
        if len(commands) != len(set(commands)):
            raise ValueError("command receipts must be unique")
        if (self.last_frame_sequence == 0) != (self.last_frame_sha256 is None):
            raise ValueError("frame cursor requires its immutable hash")
        if (self.last_frame_sequence == 0) != (self.last_exchange_update_id == 0):
            raise ValueError("frame cursor requires its exchange update ID")
        if (self.receipts or self.consumed_depth) and self.assumptions_sha256 is None:
            raise ValueError("used liquidity state requires its immutable model fingerprint")
        if self.last_arrival_at_ms > self.last_as_of_ms:
            raise ValueError("terminal arrivals cannot follow their evaluation clock")
        arrivals = [item.outcome.arrival_at_ms for item in self.receipts]
        if arrivals != sorted(arrivals) or (arrivals and arrivals[-1] != self.last_arrival_at_ms):
            raise ValueError("terminal receipt arrival order must match the causal cursor")
        for receipt in self.receipts:
            if (
                receipt.command_id != receipt.outcome.command_id
                or receipt.command_sha256 != receipt.outcome.command_sha256
                or receipt.assumptions_sha256 != receipt.outcome.assumptions_sha256
                or receipt.assumptions_sha256 != self.assumptions_sha256
                or receipt.outcome.status == "WAIT"
            ):
                raise ValueError("receipt lineage or terminality is inconsistent")
        return self


class ModelStep(ImmutableModel):
    outcome: FillOutcome
    state: LiquidityState
    replayed: bool = False
