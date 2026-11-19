"""Explicit price/quantity-capped GTC entry with an immutable cancel deadline."""

from __future__ import annotations

from kairos_core.contracts import RiskTradeDecisionV1
from pydantic import Field

from .production_readiness import StrictRecord

LIMIT_GTC_ENTRY_CONTRACT = "EVEDEX_LIMIT_GTC_BOUNDED_V1"


class LimitGtcEntryV1(StrictRecord):
    contract: str = Field(default=LIMIT_GTC_ENTRY_CONTRACT, pattern="^EVEDEX_LIMIT_GTC_BOUNDED_V1$")
    cancel_after_ms: int = Field(gt=0)


def check_limit_gtc_deadline(entry: LimitGtcEntryV1, decision: RiskTradeDecisionV1, *, now_ms: int) -> None:
    entry = LimitGtcEntryV1.model_validate(entry)
    if (
        type(now_ms) is not int
        or not now_ms < entry.cancel_after_ms <= now_ms + 5_000
        or entry.cancel_after_ms > decision.intent.entry_expires_ts_ms
    ):
        raise ValueError("GTC entry cancellation deadline must be original, future, and within five seconds")
