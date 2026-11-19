"""Detached V2 UNKNOWN-fee constructor for the coordinated research source set.

Nothing in the shipping factory, service, or lifecycle imports this module.
It does not grant an admission, change publication, or qualify fee evidence.
Enablement requires a durable per-trade version binding and V2-aware outbox
and consumers; a configuration switch by itself is insufficient.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any

# The fee-v2 research source lock supplies this module.
from kairos_core.contracts.execution_fee_v2 import (  # type: ignore[import-not-found]
    ExecutionFeeBundleV2,
    TradeExecutionEventV2,
)
from kairos_core.enums import TradeExecutionEventType, TradeLifecycleState


def build_unknown_execution_event_v2(fields: Mapping[str, Any]) -> TradeExecutionEventV2:
    """Build an observation with unknown fees and no inferred USD valuation.

    ``fields`` are fresh immutable execution facts, not a V1 public payload.
    Caller-supplied accounting, identity or fee data is refused: enriching a
    fee requires a separately attributed, superseding ``FEE_UPDATED`` fact.
    """
    if not isinstance(fields, Mapping):
        raise ValueError("explicit execution fact fields are required")
    if set(fields) & {"contract_version", "event_id", "message_id", "fee", "fee_usd"}:
        raise ValueError("fee and event identity are selected by the V2 contract")
    trade_id = fields.get("trade_id")
    if not isinstance(trade_id, str) or not trade_id:
        raise ValueError("trade lineage is required for UNKNOWN fee")
    client_order_id = fields.get("client_order_id")
    exchange_order_id = fields.get("exchange_order_id")
    order_id = client_order_id or exchange_order_id
    if order_id is not None and not isinstance(order_id, str):
        raise ValueError("order scope must be an exact order ID")
    fee = ExecutionFeeBundleV2(
        scope_kind="ORDER" if order_id is not None else "TRADE",
        scope_reference=order_id if order_id is not None else trade_id,
        coverage="UNKNOWN",
        components=(),
        usd_status="UNKNOWN",
    )
    return TradeExecutionEventV2.model_validate({**dict(fields), "fee_usd": None, "fee": fee})


def execution_fact_key_v2(event: TradeExecutionEventV2, *, namespace: str) -> str:
    """Fingerprint immutable V2 fact data before sequence and observation time.

    A persisted existing fact must still be read and compared in the same
    transaction under a per-trade contract-version lock. This helper alone is
    not an outbox, replay strategy, or permission to switch an existing trade.
    """
    if type(event) is not TradeExecutionEventV2:
        raise ValueError("the exact V2 event model is required")
    event = TradeExecutionEventV2.model_validate(event)
    if not isinstance(namespace, str) or not namespace or namespace != namespace.strip():
        raise ValueError("normalized execution namespace required")
    payload = event.identity_payload()
    payload.pop("event_seq")
    payload.pop("occurred_at_ms")
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    event_type = (
        event.event_type.value if isinstance(event.event_type, TradeExecutionEventType) else event.event_type
    )
    return f"{namespace}:v2:{event_type}:{digest}"


async def append_research_fee_update_v2(
    repository,
    *,
    previous: TradeExecutionEventV2,
    fee: ExecutionFeeBundleV2,
    occurred_at_ms: int,
    namespace: str,
    source_fact_id: str,
) -> TradeExecutionEventV2:
    """Append an incomplete synthetic observation without a trade transition.

    This research path does not establish a qualified venue or FX source: it
    refuses FINAL, NOT_APPLICABLE, exact-original-byte, or USD claims. The
    repository must independently bind the version, last scoped predecessor,
    payload digest and expected trade state inside its append transaction. The
    source fact ID is a stable non-secret SHA-256, never a raw credential.
    """
    if type(previous) is not TradeExecutionEventV2 or type(fee) is not ExecutionFeeBundleV2:
        raise ValueError("typed V2 predecessor and fee observation are required")
    previous = TradeExecutionEventV2.model_validate(previous)
    fee = ExecutionFeeBundleV2.model_validate(fee)
    if (
        fee.coverage not in {"UNKNOWN", "INCOMPLETE"}
        or fee.usd_status != "UNKNOWN"
        or any(item.precision == "EXACT_RAW_DECIMAL" for item in fee.components)
        or fee.supersedes_event_id != previous.event_id
        or fee.scope_kind != previous.fee.scope_kind
        or fee.scope_reference != previous.fee.scope_reference
    ):
        raise ValueError("research fee update lacks a matching incomplete source scope")
    if type(occurred_at_ms) is not int or occurred_at_ms < previous.occurred_at_ms:
        raise ValueError("fee update cannot predate its original observation")
    if not isinstance(source_fact_id, str) or re.fullmatch(r"[a-f0-9]{64}", source_fact_id) is None:
        raise ValueError("stable non-secret SHA-256 fee fact ID required")
    if await repository.get_execution_contract_version(previous.trade_id) != "trade-execution-event.v2":
        raise ValueError("fee update requires an existing V2 trade")
    trade = await repository.get(previous.trade_id)
    if trade is None:
        raise ValueError("fee update trade no longer exists")
    base = previous.model_dump(mode="python")
    for key in ("event_id", "message_id", "correlation_id", "causation_id", "produced_at"):
        base.pop(key, None)
    base.update(
        event_seq=1,
        occurred_at_ms=occurred_at_ms,
        event_type="FEE_UPDATED",
        lifecycle_state=TradeLifecycleState(trade.state.value),
        requested_quantity=None,
        filled_quantity=None,
        position_quantity=None,
        average_price=None,
        exit_reason=None,
        fee_usd=None,
        fee=fee,
        details=(("fee_source_fact_id", source_fact_id),),
    )

    def build(sequence):
        return TradeExecutionEventV2.model_validate({**base, "event_seq": sequence})

    if not isinstance(namespace, str) or not namespace or namespace != namespace.strip():
        raise ValueError("normalized execution namespace required")
    identity = json.dumps(
        {
            "contract_version": "trade-execution-event.v2",
            "trade_id": previous.trade_id,
            "source_fact_id": source_fact_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    fact_key = f"{namespace}:v2:FEE_UPDATED:{hashlib.sha256(identity).hexdigest()}"
    stored_record = await repository.get_execution_event_with_state_version(
        previous.trade_id, fact_key=fact_key
    )
    expected_state_version = trade.state_version
    if stored_record is not None:
        stored, expected_state_version = stored_record
        if type(stored) is not TradeExecutionEventV2:
            raise ValueError("stored fee update has a conflicting event version")
        base["lifecycle_state"] = stored.lifecycle_state
        candidate = build(stored.event_seq)
        if candidate.model_dump(mode="json") != stored.model_dump(mode="json"):
            raise ValueError("fee update replay conflicts with its stored payload")

        def replay(_sequence):
            return stored

        build = replay
    return await repository.append_execution_event(
        previous.trade_id,
        fact_key=fact_key,
        expected_state_version=expected_state_version,
        build=build,
    )
