from __future__ import annotations

import os
from datetime import timedelta
from unittest.mock import AsyncMock

import pytest
from kairos_core.enums import OrderSide
from kairos_persistence import (
    Database,
    EffectStatus,
    EffectType,
    ExecutionJournalRepository,
    PersistenceSettings,
)

from kairos_execution.adapters.evedex import EvedexAdapter
from kairos_execution.journaled_adapter import JournaledExchangeAdapter

pytestmark = pytest.mark.integration

PARENT_ORDER_ID = "00390:ABCDEF0123456789ABCDEF0123"


class _Signer:
    address = "0x0000000000000000000000000000000000000000"

    def sign_typed_data(self, domain, types, message) -> str:
        return "0x" + "00" * 65


def _settings() -> PersistenceSettings:
    database_url = os.getenv("KAIROS_PERSISTENCE_DATABASE_URL")
    if not database_url:
        pytest.skip("KAIROS_PERSISTENCE_DATABASE_URL is required")
    return PersistenceSettings(database_url=database_url)


@pytest.mark.asyncio
async def test_crashed_tpsl_create_is_found_by_parent_and_reconciled_without_second_post() -> None:
    database = Database(_settings())
    await database.connect()
    await database.migrate()
    journal = ExecutionJournalRepository(database.pool)
    raw = EvedexAdapter(
        exchange_base_url="https://example.invalid",
        signer=_Signer(),
        chain_id=1,
        jwt="test-only",
        dry_run=False,
    )
    raw._get = AsyncMock(
        return_value={
            "list": [
                {
                    "id": "venue-stop-1",
                    "instrument": "BTCUSDT",
                    "type": "stop-loss",
                    "side": "BUY",
                    "quantity": "0",
                    "price": "64000",
                    "status": "active",
                    "order": PARENT_ORDER_ID,
                }
            ]
        }
    )
    raw._post = AsyncMock(side_effect=AssertionError("recovery must not create a second TP/SL"))
    adapter = JournaledExchangeAdapter(raw, journal)
    effect_key = adapter._key(EffectType.PROTECTIVE_STOP, PARENT_ORDER_ID)
    request = {
        "symbol": "BTCUSDT",
        "stop_price_hex": float(64_000).hex(),
        "position_side": "BUY",
        "parent_order_id": PARENT_ORDER_ID,
    }

    try:
        preparation = await journal.prepare(
            effect_key=effect_key,
            effect_type=EffectType.PROTECTIVE_STOP,
            exchange="evedex",
            symbol="BTCUSDT",
            client_order_id=PARENT_ORDER_ID,
            request_payload=request,
            recovery_delay=timedelta(0),
        )
        assert preparation.created

        ack = await adapter.set_protective_stop("BTCUSDT", 64_000.0, OrderSide.BUY, PARENT_ORDER_ID)

        assert ack.exchange_order_id == "venue-stop-1"
        effect = await journal.get(effect_key)
        assert effect is not None and effect.status is EffectStatus.RECONCILED
        assert await journal.verify_chain(effect_key)
        raw._post.assert_not_awaited()
    finally:
        await database.pool.execute("DELETE FROM execution_effect_events WHERE effect_key=$1", effect_key)
        await database.pool.execute("DELETE FROM execution_effects WHERE effect_key=$1", effect_key)
        await raw.close()
        await database.close()
