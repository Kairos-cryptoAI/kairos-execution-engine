"""Explicit market-IOC admission contracts; no venue verifier is registered here.

Pair slippageLimit is not a caller-signed price/base-quantity cap. A separately
qualified source must prove the complete immutable execution envelope. Existing
account/input Risk, owner/signing, protection and reconciliation stay mandatory.
"""

from __future__ import annotations

from decimal import Decimal, localcontext
from types import MappingProxyType
from typing import Annotated, Literal, Protocol

from kairos_core.contracts import RiskTradeDecisionV1
from kairos_core.enums import Side
from pydantic import Field, StrictInt, field_validator

from .production_readiness import Digest, Identity, ProductionContextV1, StrictRecord, canonical_digest

MARKET_IOC_ENTRY_CONTRACT = "kairos.evedex-bounded-market-ioc-entry.v1"
_Units = Annotated[StrictInt, Field(gt=0, lt=2**96)]
_Price = Annotated[StrictInt, Field(gt=0, lt=2**80)]
_Clock = Annotated[StrictInt, Field(ge=0)]
# Only independently reviewed source implementations may be pinned here by a
# source change. There is deliberately no runtime registration API and no real
# qualified EVEDEX implementation. Tests replace this immutable empty mapping
# with explicitly synthetic fixture types; callers cannot bless their own DTO.
_QUALIFIED_MARKET_IOC_SOURCE_TYPES: MappingProxyType[str, type] = MappingProxyType({})


class MarketIocEntryRequestV1(StrictRecord):
    """Explicit cash request and original proof reference, not an approval."""

    contract: Literal["kairos.evedex-bounded-market-ioc-entry.v1"] = (
        "kairos.evedex-bounded-market-ioc-entry.v1"
    )
    source_id: Identity
    proof_sha256: Digest
    cash_quantity_e8: _Units


class VerifiedMarketIocEnvelopeV1(StrictRecord):
    """Source-verifier result; constructing this DTO does not authenticate it.

    The source must establish bounds over the *whole* IOC, including rounding,
    partial fills and both entry and stop-exit fees. Price bounds cover each
    fill, not only an earlier book or a final average. No real implementation
    is provided by the current EVEDEX diagnostic/REST adapter.
    The lease bounds dispatch start; proven bounds must survive until terminal
    IOC, including partial fills that occur after that dispatch lease expires.
    """

    source_id: Identity
    proof_sha256: Digest
    request_sha256: Digest
    context_sha256: Digest
    decision_sha256: Digest
    observed_at_ms: _Clock
    valid_until_ms: _Clock
    minimum_fill_price_e8: _Price
    maximum_fill_price_e8: _Price
    maximum_base_quantity_e8: _Units
    maximum_fees_usd: Decimal = Field(ge=0)
    cash_notional_cap_enforced: Literal[True]
    base_quantity_includes_rounding: Literal[True]
    price_bounds_cover_each_fill: Literal[True]
    fees_include_entry_and_stop_exit: Literal[True]
    bounds_enforced_through_terminal_ioc: Literal[True]

    @field_validator("maximum_fees_usd")
    @classmethod
    def finite_fees(cls, value: Decimal) -> Decimal:
        if not value.is_finite():
            raise ValueError("finite market-IOC fee bound required")
        return value


class MarketIocEnvelopeVerifier(Protocol):
    source_id: str

    def verify(
        self,
        request: MarketIocEntryRequestV1,
        *,
        context: ProductionContextV1,
        decision: RiskTradeDecisionV1,
        now_ms: int,
    ) -> VerifiedMarketIocEnvelopeV1: ...


def _exact_units(value: float) -> int:
    with localcontext() as context:
        context.prec = 96
        scaled = Decimal(str(value)) * 100_000_000
        if not scaled.is_finite() or scaled <= 0 or scaled != scaled.to_integral_value():
            raise ValueError("Core market envelope bound is not exact at 1e8")
        return int(scaled)


def check_market_ioc_bounds(
    request: MarketIocEntryRequestV1,
    envelope: VerifiedMarketIocEnvelopeV1,
    *,
    context: ProductionContextV1,
    decision: RiskTradeDecisionV1,
    now_ms: int,
) -> VerifiedMarketIocEnvelopeV1:
    """Check bounded geometry only; source verification is independently required."""
    request = MarketIocEntryRequestV1.model_validate(request.model_dump(mode="python"))
    envelope = VerifiedMarketIocEnvelopeV1.model_validate(envelope.model_dump(mode="python"))
    if (
        envelope.source_id != request.source_id
        or envelope.proof_sha256 != request.proof_sha256
        or envelope.request_sha256 != canonical_digest(request)
        or envelope.context_sha256 != canonical_digest(context)
        or envelope.decision_sha256 != canonical_digest(decision)
        or not envelope.observed_at_ms <= now_ms < envelope.valid_until_ms
        or envelope.valid_until_ms - envelope.observed_at_ms > 2_000
        or envelope.minimum_fill_price_e8 > envelope.maximum_fill_price_e8
    ):
        raise ValueError("market-IOC proof scope, clocks or price bounds differ")
    quantity = _exact_units(decision.quantity)
    worst_price = _exact_units(decision.worst_entry_price)
    stop = _exact_units(decision.exit_plan.stop_price)
    target = _exact_units(decision.exit_plan.target_price)
    if (
        not decision.approved
        or decision.leverage != 1
        or envelope.maximum_base_quantity_e8 > quantity
        or request.cash_quantity_e8 * 100_000_000
        > envelope.maximum_base_quantity_e8 * envelope.minimum_fill_price_e8
        or decision.intent.side is Side.LONG
        and envelope.maximum_fill_price_e8 > worst_price
        or decision.intent.side is Side.SHORT
        and envelope.minimum_fill_price_e8 < worst_price
        or decision.intent.side is Side.LONG
        and not stop < envelope.minimum_fill_price_e8 <= envelope.maximum_fill_price_e8 < target
        or decision.intent.side is Side.SHORT
        and not target < envelope.minimum_fill_price_e8 <= envelope.maximum_fill_price_e8 < stop
        or envelope.maximum_fees_usd > Decimal(str(decision.estimated_fees_usd))
    ):
        raise ValueError("market-IOC execution exceeds the immutable Core Risk envelope")
    with localcontext() as arithmetic:
        arithmetic.prec = 96
        if Decimal(request.cash_quantity_e8) / 100_000_000 > Decimal(str(decision.notional_usd)):
            raise ValueError("market-IOC cash notional exceeds the approved Core notional")
    return envelope


class MarketIocAdmission:
    """Explicit verifier injection, with no default/source-registry fallback."""

    def __init__(self, verifier: MarketIocEnvelopeVerifier | None = None):
        self.verifier = verifier

    @property
    def registered(self) -> bool:
        source_id = getattr(self.verifier, "source_id", None)
        return (
            isinstance(source_id, str)
            and self.verifier is not None
            and _QUALIFIED_MARKET_IOC_SOURCE_TYPES.get(source_id) is type(self.verifier)
        )

    def verify(
        self,
        request: MarketIocEntryRequestV1,
        *,
        context: ProductionContextV1,
        decision: RiskTradeDecisionV1,
        now_ms: int,
        expected: VerifiedMarketIocEnvelopeV1 | None = None,
    ) -> VerifiedMarketIocEnvelopeV1:
        if (
            not self.registered
            or self.verifier is None
            or getattr(self.verifier, "source_id", None) != request.source_id
        ):
            raise ValueError("qualified market-IOC envelope verifier is unavailable")
        request = MarketIocEntryRequestV1.model_validate(request.model_dump(mode="python"))
        try:
            envelope = self.verifier.verify(request, context=context, decision=decision, now_ms=now_ms)
            if type(envelope) is not VerifiedMarketIocEnvelopeV1:
                raise ValueError("typed original market-IOC envelope required")
            checked = check_market_ioc_bounds(
                request, envelope, context=context, decision=decision, now_ms=now_ms
            )
            if expected is not None and checked != expected:
                raise ValueError("original market-IOC envelope changed; no renewal/substitution")
            return checked
        except Exception:
            raise ValueError("market-IOC envelope verification failed closed") from None


def validate_market_ioc_ack(response, *, decision, client_order_id, request, envelope):
    """Inspect factual market ACK/fill fields; NEW never becomes a fill."""

    def number(key):
        value = response.get(key)
        if value is None or isinstance(value, bool):
            raise ValueError("market IOC response is missing an exact economic field")
        value = Decimal(str(value))
        if not value.is_finite() or value < 0:
            raise ValueError("market IOC response has an invalid economic field")
        return value

    if (
        response.get("id") != client_order_id
        or response.get("instrument") != decision.venue_symbol
        or response.get("side") != ("BUY" if decision.intent.side is Side.LONG else "SELL")
        or str(response.get("type", "")).upper() != "MARKET"
        or response.get("timeInForce") != "IOC"
        or number("cashQuantity") * 100_000_000 != request.cash_quantity_e8
    ):
        raise ValueError("market IOC response differs from exact signed entry contract")
    quantity, remaining = number("quantity"), number("unFilledQuantity")
    if (
        remaining > quantity
        or quantity * 100_000_000 > envelope.maximum_base_quantity_e8
        or quantity > Decimal(str(decision.quantity))
    ):
        raise ValueError("market IOC response exceeds approved quantity or has incoherent remainder")
    status = str(response.get("status", "")).upper().replace("CANCELLED", "CANCELED")
    if status not in {"NEW", "PARTIALLY_FILLED", "FILLED", "CANCELED", "REJECTED", "EXPIRED"}:
        raise ValueError("unknown market IOC status requires authoritative recovery")
    filled = quantity - remaining
    if response.get("fee") is not None and number("fee") > envelope.maximum_fees_usd:
        raise ValueError("market IOC fee exceeds verified whole-IOC envelope")
    if (
        status == "NEW"
        and filled != 0
        or status == "PARTIALLY_FILLED"
        and not 0 < filled < quantity
        or status == "FILLED"
        and (filled <= 0 or remaining != 0)
    ):
        raise ValueError("market IOC status contradicts its factual quantities")
    average = None
    if filled > 0:
        average = number("filledAvgPrice")
        with localcontext() as context:
            context.prec = 96
            if (
                not envelope.minimum_fill_price_e8 <= average * 100_000_000 <= envelope.maximum_fill_price_e8
                or filled * average * 100_000_000 > request.cash_quantity_e8
                or number("fee") > envelope.maximum_fees_usd
            ):
                raise ValueError("market IOC fill price, notional or fee exceeds verified envelope")
    return client_order_id, status, float(filled), float(average) if average is not None else None
