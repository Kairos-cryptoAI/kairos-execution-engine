from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

import pytest
from kairos_core.contracts import AccountSnapshot, ExecutionReport, OrderIntent
from kairos_core.enums import OrderSide, OrderStatus, OrderType, ReasonCode
from kairos_persistence import (
    EffectPreparation,
    EffectStatus,
    EffectType,
    ExecutionEffect,
    MessageIdentityConflict,
    canonical_payload,
)

from kairos_execution.adapters.base import ExchangeAdapter, ProtectiveStopAck
from kairos_execution.journaled_adapter import (
    JournaledExchangeAdapter,
    ProtectionNoLongerRequired,
)


class FakeJournal:
    def __init__(self) -> None:
        self.effects: dict[str, ExecutionEffect] = {}
        self.transitions: list[tuple[str, EffectStatus]] = []
        self.locks: list[str] = []

    async def prepare(self, **kwargs: Any) -> EffectPreparation:
        key = kwargs["effect_key"]
        _encoded, request_sha = canonical_payload(kwargs["request_payload"])
        current = self.effects.get(key)
        if current is not None:
            if current.request_sha256 != request_sha:
                raise MessageIdentityConflict("changed request")
            return EffectPreparation(effect=current, created=False)
        effect = ExecutionEffect(
            effect_key=key,
            effect_type=kwargs["effect_type"],
            exchange=kwargs["exchange"],
            symbol=kwargs["symbol"],
            client_order_id=kwargs["client_order_id"],
            request_sha256=request_sha,
            request_payload=kwargs["request_payload"],
            status=EffectStatus.PREPARED,
            exchange_effect_id=None,
            response_payload=None,
            error=None,
            journal_head_sha256="0" * 64,
        )
        self.effects[key] = effect
        return EffectPreparation(effect=effect, created=True)

    async def confirm(
        self,
        effect_key: str,
        *,
        exchange_effect_id: str,
        response_payload: dict[str, Any],
    ) -> ExecutionEffect:
        effect = replace(
            self.effects[effect_key],
            status=EffectStatus.CONFIRMED,
            exchange_effect_id=exchange_effect_id,
            response_payload=response_payload,
        )
        self.effects[effect_key] = effect
        self.transitions.append((effect_key, effect.status))
        return effect

    async def reconcile(
        self,
        effect_key: str,
        *,
        exchange_effect_id: str | None = None,
        response_payload: dict[str, Any] | None = None,
    ) -> ExecutionEffect:
        current = self.effects[effect_key]
        effect = replace(
            current,
            status=EffectStatus.RECONCILED,
            exchange_effect_id=exchange_effect_id or current.exchange_effect_id,
            response_payload=response_payload or current.response_payload,
        )
        self.effects[effect_key] = effect
        self.transitions.append((effect_key, effect.status))
        return effect

    async def recovery_required(self, *, exchange: str | None = None) -> list[ExecutionEffect]:
        return [
            effect
            for effect in self.effects.values()
            if effect.status in {EffectStatus.PREPARED, EffectStatus.FAILED}
            and (exchange is None or effect.exchange == exchange)
        ]

    @asynccontextmanager
    async def recovery_lock(self, effect_key: str) -> AsyncIterator[None]:
        self.locks.append(effect_key)
        yield


class FakeAdapter(ExchangeAdapter):
    name = "fake"
    protective_stop_lookup_authoritative = True

    def __init__(self) -> None:
        self.place_calls = 0
        self.close_calls = 0
        self.stop_calls = 0
        self.cancel_calls = 0
        self.active = False
        self.flat = True
        self.existing_stop: ProtectiveStopAck | None = None

    async def place_order(self, intent: OrderIntent) -> ExecutionReport:
        self.place_calls += 1
        return _report(intent, status=OrderStatus.NEW)

    async def cancel_order_by_client_id(self, symbol: str, client_order_id: str) -> None:
        self.cancel_calls += 1
        self.active = False

    async def is_order_active_by_client_id(self, symbol: str, client_order_id: str) -> bool:
        return self.active

    async def is_position_flat(self, symbol: str) -> bool:
        return self.flat

    async def close_position(
        self,
        symbol: str,
        *,
        quantity: float | None = None,
        side: OrderSide | None = None,
        client_order_id: str | None = None,
    ) -> ExecutionReport:
        self.close_calls += 1
        self.flat = True
        return ExecutionReport(
            source="execution-engine",
            client_order_id=client_order_id or "missing",
            exchange_order_id=client_order_id,
            exchange=self.name,
            symbol=symbol,
            side=side or OrderSide.BUY,
            status=OrderStatus.FILLED,
            requested_qty=quantity or 0.0,
            filled_qty=quantity or 0.0,
        )

    async def set_leverage(self, symbol: str, leverage: float) -> None:
        return None

    async def set_protective_stop(
        self,
        symbol: str,
        stop_price: float,
        position_side: OrderSide,
        parent_order_id: str,
    ) -> ProtectiveStopAck:
        self.stop_calls += 1
        self.existing_stop = ProtectiveStopAck("stop-1")
        return self.existing_stop

    async def find_protective_stop(
        self,
        symbol: str,
        stop_price: float,
        position_side: OrderSide,
        parent_order_id: str,
    ) -> ProtectiveStopAck | None:
        return self.existing_stop

    async def fetch_account_snapshot(self, *, account_id: str, peak_equity_usd: float) -> AccountSnapshot:
        raise NotImplementedError


def _intent() -> OrderIntent:
    return OrderIntent(
        source="risk",
        message_id="validated-1",
        produced_at=datetime(2026, 8, 18, tzinfo=UTC),
        client_order_id="krs-client-1",
        symbol="BTCUSDT",
        side=OrderSide.BUY,
        order_type=OrderType.LIMIT,
        quantity=0.1,
        price=100.0,
        reason_code=ReasonCode.ENTER_LONG_TREND,
    )


def _report(intent: OrderIntent, *, status: OrderStatus) -> ExecutionReport:
    return ExecutionReport(
        source="execution-engine",
        client_order_id=intent.client_order_id or "missing",
        exchange_order_id=intent.client_order_id,
        exchange="fake",
        symbol=intent.symbol,
        side=intent.side,
        status=status,
        requested_qty=intent.quantity,
        remaining_qty=intent.quantity if status is OrderStatus.NEW else 0.0,
    )


@pytest.mark.asyncio
async def test_new_place_is_prepared_then_confirmed_and_redelivery_uses_cached_response() -> None:
    raw = FakeAdapter()
    journal = FakeJournal()
    adapter = JournaledExchangeAdapter(raw, journal)
    intent = _intent()

    first = await adapter.place_order(intent)
    second = await adapter.place_order(intent)

    assert first == second
    assert raw.place_calls == 1
    assert next(iter(journal.effects.values())).status is EffectStatus.CONFIRMED


@pytest.mark.asyncio
async def test_prepared_place_is_neutralized_without_resubmission() -> None:
    raw = FakeAdapter()
    raw.active = True
    journal = FakeJournal()
    adapter = JournaledExchangeAdapter(raw, journal)
    intent = _intent()
    await journal.prepare(
        effect_key=adapter._key(EffectType.PLACE_ORDER, intent.client_order_id or ""),
        effect_type=EffectType.PLACE_ORDER,
        exchange="fake",
        symbol=intent.symbol,
        client_order_id=intent.client_order_id,
        request_payload={"intent": intent.to_payload()},
    )

    report = await adapter.place_order(intent)

    assert report.status is OrderStatus.CANCELED
    assert raw.place_calls == 0
    assert raw.cancel_calls == 1
    assert next(iter(journal.effects.values())).status is EffectStatus.RECONCILED


@pytest.mark.asyncio
async def test_prepared_stop_reuses_exact_live_parent_linked_stop() -> None:
    raw = FakeAdapter()
    raw.flat = False
    raw.existing_stop = ProtectiveStopAck("existing-stop")
    journal = FakeJournal()
    adapter = JournaledExchangeAdapter(raw, journal)
    request = {
        "symbol": "BTCUSDT",
        "stop_price_hex": float(90).hex(),
        "position_side": "BUY",
        "parent_order_id": "parent-1",
    }
    await journal.prepare(
        effect_key=adapter._key(EffectType.PROTECTIVE_STOP, "parent-1"),
        effect_type=EffectType.PROTECTIVE_STOP,
        exchange="fake",
        symbol="BTCUSDT",
        client_order_id="parent-1",
        request_payload=request,
    )

    ack = await adapter.set_protective_stop("BTCUSDT", 90, OrderSide.BUY, "parent-1")

    assert ack.exchange_order_id == "existing-stop"
    assert raw.stop_calls == 0
    assert next(iter(journal.effects.values())).status is EffectStatus.RECONCILED


@pytest.mark.asyncio
async def test_prepared_stop_is_created_once_when_position_is_open_and_lookup_proves_absence() -> None:
    raw = FakeAdapter()
    raw.flat = False
    journal = FakeJournal()
    adapter = JournaledExchangeAdapter(raw, journal)
    request = {
        "symbol": "BTCUSDT",
        "stop_price_hex": float(90).hex(),
        "position_side": "BUY",
        "parent_order_id": "parent-1",
    }
    await journal.prepare(
        effect_key=adapter._key(EffectType.PROTECTIVE_STOP, "parent-1"),
        effect_type=EffectType.PROTECTIVE_STOP,
        exchange="fake",
        symbol="BTCUSDT",
        client_order_id="parent-1",
        request_payload=request,
    )

    ack = await adapter.set_protective_stop("BTCUSDT", 90, OrderSide.BUY, "parent-1")

    assert ack.exchange_order_id == "stop-1"
    assert raw.stop_calls == 1
    assert next(iter(journal.effects.values())).status is EffectStatus.CONFIRMED


@pytest.mark.asyncio
async def test_prepared_stop_blocks_when_venue_lookup_is_not_authoritative() -> None:
    raw = FakeAdapter()
    raw.protective_stop_lookup_authoritative = False
    raw.flat = False
    journal = FakeJournal()
    adapter = JournaledExchangeAdapter(raw, journal)
    request = {
        "symbol": "BTCUSDT",
        "stop_price_hex": float(90).hex(),
        "position_side": "BUY",
        "parent_order_id": "parent-1",
    }
    await journal.prepare(
        effect_key=adapter._key(EffectType.PROTECTIVE_STOP, "parent-1"),
        effect_type=EffectType.PROTECTIVE_STOP,
        exchange="fake",
        symbol="BTCUSDT",
        client_order_id="parent-1",
        request_payload=request,
    )

    with pytest.raises(RuntimeError, match="cannot authoritatively deduplicate"):
        await adapter.set_protective_stop("BTCUSDT", 90, OrderSide.BUY, "parent-1")
    assert raw.stop_calls == 0


@pytest.mark.asyncio
async def test_prepared_stop_for_flat_position_is_reconciled_without_creation() -> None:
    raw = FakeAdapter()
    journal = FakeJournal()
    adapter = JournaledExchangeAdapter(raw, journal)
    request = {
        "symbol": "BTCUSDT",
        "stop_price_hex": float(90).hex(),
        "position_side": "BUY",
        "parent_order_id": "parent-1",
    }
    await journal.prepare(
        effect_key=adapter._key(EffectType.PROTECTIVE_STOP, "parent-1"),
        effect_type=EffectType.PROTECTIVE_STOP,
        exchange="fake",
        symbol="BTCUSDT",
        client_order_id="parent-1",
        request_payload=request,
    )

    with pytest.raises(ProtectionNoLongerRequired):
        await adapter.set_protective_stop("BTCUSDT", 90, OrderSide.BUY, "parent-1")

    assert raw.stop_calls == 0
    assert next(iter(journal.effects.values())).status is EffectStatus.RECONCILED


@pytest.mark.asyncio
async def test_effect_key_keeps_identity_stable_and_request_hash_rejects_changed_stop() -> None:
    raw = FakeAdapter()
    raw.flat = False
    journal = FakeJournal()
    adapter = JournaledExchangeAdapter(raw, journal)
    first = adapter._key(EffectType.PROTECTIVE_STOP, "parent-1")
    second = adapter._key(EffectType.PROTECTIVE_STOP, "parent-1")
    assert first == second
    assert len(first.rsplit(":", 1)[1]) == len(sha256(b"parent-1").hexdigest())

    await adapter.set_protective_stop("BTCUSDT", 90, OrderSide.BUY, "parent-1")
    with pytest.raises(MessageIdentityConflict):
        await adapter.set_protective_stop("BTCUSDT", 91, OrderSide.BUY, "parent-1")
