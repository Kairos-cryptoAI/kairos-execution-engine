"""Pure diagnostic market-IOC draft, disconnected from signing and dispatch.

Official order semantics: https://docs.evedex.com/developers/developers/order_creation
Field schema: https://github.com/evedex-official/exchange-crypto/blob/master/src/utils/crypto.ts
The pinned SDK signs IOC and cashQuantity, not a limit price or base quantity.
Its identity is not current venue/domain approval. A cash ceiling alone cannot
qualify the execution-price/base-quantity envelope or a maximum trading loss.
"""

from __future__ import annotations

import hashlib
import json
from typing import Annotated, Literal, Self

from pydantic import Field, StrictInt, StrictStr, model_validator

from .managed_signer import production_signing_types
from .production_readiness import Digest, StrictRecord, canonical_digest

MARKET_IOC_DIAGNOSTIC_ID: Literal["kairos.evedex-market-ioc-diagnostic.v1"] = (
    "kairos.evedex-market-ioc-diagnostic.v1"
)
_CashUnits = Annotated[StrictInt, Field(gt=0, lt=2**96)]
_PINNED_MARKET_TYPES = {
    "New market order": [
        {"name": name, "type": kind}
        for name, kind in (
            ("id", "string"),
            ("instrument", "string"),
            ("side", "string"),
            ("timeInForce", "string"),
            ("leverage", "uint8"),
            ("cashQuantity", "uint96"),
            ("chainId", "uint256"),
        )
    ]
}


class MarketIocCashInputV1(StrictRecord):
    """Explicit cash units and a diagnostic ceiling, never a Risk approval.

    No base quantity, price, loss cap or leverage increase is inferred. Source
    digests identify caller-supplied originals; they do not authenticate them.
    Client-ID syntax is checked here; actual freshness remains a runtime check.
    """

    client_order_id: StrictStr = Field(pattern=r"^[0-9]{5}:[0-9A-Fa-f]{26}$")
    instrument: StrictStr = Field(pattern=r"^[A-Z0-9]{1,32}$")
    side: Literal["BUY", "SELL"]
    cash_quantity_e8: _CashUnits
    diagnostic_cash_ceiling_e8: _CashUnits
    context_sha256: Digest
    source_evidence_sha256: Digest
    time_in_force: Literal["IOC"] = "IOC"
    leverage: Annotated[StrictInt, Field(ge=1, le=1)] = 1
    chain_id: Annotated[StrictInt, Field(ge=42161, le=42161)] = 42161

    @model_validator(mode="after")
    def cash_within_explicit_ceiling(self) -> Self:
        if self.cash_quantity_e8 > self.diagnostic_cash_ceiling_e8:
            raise ValueError("cash quantity exceeds the explicit diagnostic ceiling")
        return self


class MarketIocContractDiagnosticV1(StrictRecord):
    """An immutable unsigned draft, with hard unqualified admission status."""

    version: Literal["kairos.evedex-market-ioc-diagnostic.v1"] = MARKET_IOC_DIAGNOSTIC_ID
    status: Literal["NON_AUTHORITY_NOT_LIVE"] = "NON_AUTHORITY_NOT_LIVE"
    eligibility: Literal["PRICE_AND_BASE_QUANTITY_ENVELOPE_UNQUALIFIED"] = (
        "PRICE_AND_BASE_QUANTITY_ENVELOPE_UNQUALIFIED"
    )
    signing_domain_qualification: Literal["UNQUALIFIED"] = "UNQUALIFIED"
    provenance: Literal["PINNED_SDK_SCHEMA_NOT_CURRENT_VENUE_APPROVAL"] = (
        "PINNED_SDK_SCHEMA_NOT_CURRENT_VENUE_APPROVAL"
    )
    pinned_sdk_version: Literal["1.2.11"] = "1.2.11"
    pinned_crypto_version: Literal["1.1.0"] = "1.1.0"
    authority: Literal[False] = False
    live_ready: Literal[False] = False
    operation: Literal["New market order"] = "New market order"
    path: Literal["/api/v2/order/market"] = "/api/v2/order/market"
    cash_input: MarketIocCashInputV1
    cash_input_sha256: Digest
    pinned_market_types_sha256: Digest
    typed_message_json: StrictStr
    unsigned_rest_body_json: StrictStr


def _cash_decimal(value: int) -> str:
    whole, fraction = divmod(value, 100_000_000)
    return str(whole) + ("." + f"{fraction:08d}".rstrip("0") if fraction else "")


def build_market_ioc_diagnostic(cash_input: MarketIocCashInputV1) -> MarketIocContractDiagnosticV1:
    """Build exact uint96/1e8 SDK geometry without any I/O or authority issuance.

    This neither converts a limit order nor creates a ManagedSigningRequest,
    Risk decision, signature, wire request, claim, order or account reservation.
    Per-pair slippage settings do not become an invented signed price cap.
    """
    if type(cash_input) is not MarketIocCashInputV1:
        raise TypeError("an exact explicit market-IOC cash input is required")
    # Frozen Pydantic instances can still be forged with model_copy(update=...).
    # Revalidate serialized fields rather than trusting an existing instance.
    cash_input = MarketIocCashInputV1.model_validate(cash_input.model_dump(mode="python"))
    types = production_signing_types("New market order")
    message = {
        "id": cash_input.client_order_id,
        "instrument": cash_input.instrument,
        "side": cash_input.side,
        "timeInForce": cash_input.time_in_force,
        "leverage": cash_input.leverage,
        "cashQuantity": cash_input.cash_quantity_e8,
        "chainId": cash_input.chain_id,
    }
    if types != _PINNED_MARKET_TYPES:
        raise ValueError("pinned market signing schema changed; diagnostic contract requires review")
    rest = {**message, "cashQuantity": _cash_decimal(cash_input.cash_quantity_e8)}
    return MarketIocContractDiagnosticV1(
        cash_input=cash_input,
        cash_input_sha256=canonical_digest(cash_input),
        pinned_market_types_sha256=hashlib.sha256(
            json.dumps(types, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        typed_message_json=json.dumps(message, sort_keys=True, separators=(",", ":")),
        unsigned_rest_body_json=json.dumps(rest, sort_keys=True, separators=(",", ":")),
    )
