"""Durable exchange adapter with recovery before every external mutation."""

from __future__ import annotations

import hashlib
from contextlib import AbstractAsyncContextManager
from typing import Any, Protocol

from kairos_core.contracts import AccountSnapshot, ExecutionReport, OrderIntent
from kairos_core.enums import OrderSide, OrderStatus
from kairos_persistence import (
    EffectPreparation,
    EffectStatus,
    EffectType,
    ExecutionEffect,
)

from .adapters.base import ExchangeAdapter, ProtectiveStopAck


class ExecutionRecoveryError(RuntimeError):
    """An existing prepared venue effect cannot yet be proven safe."""


class EffectJournal(Protocol):
    async def prepare(
        self,
        *,
        effect_key: str,
        effect_type: EffectType,
        exchange: str,
        symbol: str,
        client_order_id: str | None,
        request_payload: dict[str, Any],
    ) -> EffectPreparation: ...

    async def confirm(
        self,
        effect_key: str,
        *,
        exchange_effect_id: str,
        response_payload: dict[str, Any],
    ) -> ExecutionEffect: ...

    async def reconcile(
        self,
        effect_key: str,
        *,
        exchange_effect_id: str | None = None,
        response_payload: dict[str, Any] | None = None,
    ) -> ExecutionEffect: ...

    async def recovery_required(self, *, exchange: str | None = None) -> list[ExecutionEffect]: ...

    def recovery_lock(self, effect_key: str) -> AbstractAsyncContextManager[None]: ...


class JournaledExchangeAdapter(ExchangeAdapter):
    """Journal mutations and suppress/reconcile crash redelivery by effect key."""

    def __init__(self, adapter: ExchangeAdapter, journal: EffectJournal) -> None:
        self.adapter = adapter
        self.journal = journal
        self.name = adapter.name
        self.exchange_order_id_matches_client_order_id = adapter.exchange_order_id_matches_client_order_id
        self.protective_stop_lookup_authoritative = adapter.protective_stop_lookup_authoritative

    async def place_order(self, intent: OrderIntent) -> ExecutionReport:
        client_id = self._client_id(intent.client_order_id, "place order")
        request = {"intent": intent.to_payload()}
        preparation = await self.journal.prepare(
            effect_key=self._key(EffectType.PLACE_ORDER, client_id),
            effect_type=EffectType.PLACE_ORDER,
            exchange=self.name,
            symbol=intent.symbol,
            client_order_id=client_id,
            request_payload=request,
        )
        effect = preparation.effect
        if not preparation.created:
            cached = self._cached_report(effect)
            if cached is not None:
                return cached
            return await self._recover_prepared_place(effect, intent)
        report = await self.adapter.place_order(intent)
        await self.journal.confirm(
            effect.effect_key,
            exchange_effect_id=report.exchange_order_id or client_id,
            response_payload=report.to_payload(),
        )
        return report

    async def close_position(
        self,
        symbol: str,
        *,
        quantity: float | None = None,
        side: OrderSide | None = None,
        client_order_id: str | None = None,
    ) -> ExecutionReport:
        close_id = self._client_id(client_order_id, "close position")
        request = {
            "symbol": symbol,
            "quantity": quantity,
            "side": None if side is None else side.value,
            "client_order_id": close_id,
        }
        preparation = await self.journal.prepare(
            effect_key=self._key(EffectType.CLOSE_POSITION, close_id),
            effect_type=EffectType.CLOSE_POSITION,
            exchange=self.name,
            symbol=symbol,
            client_order_id=close_id,
            request_payload=request,
        )
        effect = preparation.effect
        if not preparation.created:
            cached = self._cached_report(effect)
            if cached is not None:
                return cached
            return await self._recover_prepared_close(effect, quantity=quantity, side=side)
        report = await self.adapter.close_position(
            symbol,
            quantity=quantity,
            side=side,
            client_order_id=close_id,
        )
        await self.journal.confirm(
            effect.effect_key,
            exchange_effect_id=report.exchange_order_id or close_id,
            response_payload=report.to_payload(),
        )
        return report

    async def set_protective_stop(
        self,
        symbol: str,
        stop_price: float,
        position_side: OrderSide,
        parent_order_id: str,
    ) -> ProtectiveStopAck:
        request = {
            "symbol": symbol,
            "stop_price_hex": float(stop_price).hex(),
            "position_side": position_side.value,
            "parent_order_id": parent_order_id,
        }
        effect_key = self._key(EffectType.PROTECTIVE_STOP, parent_order_id)
        preparation = await self.journal.prepare(
            effect_key=effect_key,
            effect_type=EffectType.PROTECTIVE_STOP,
            exchange=self.name,
            symbol=symbol,
            client_order_id=parent_order_id,
            request_payload=request,
        )
        effect = preparation.effect
        if not preparation.created:
            if effect.status in {EffectStatus.CONFIRMED, EffectStatus.RECONCILED}:
                return self._cached_stop(effect)
            if effect.status is EffectStatus.FAILED:
                raise ExecutionRecoveryError(f"protective effect {effect.effect_key} is FAILED")
            return await self._recover_prepared_stop(
                effect,
                stop_price=stop_price,
                position_side=position_side,
                parent_order_id=parent_order_id,
            )
        ack = await self.adapter.set_protective_stop(
            symbol,
            stop_price,
            position_side,
            parent_order_id,
        )
        await self.journal.confirm(
            effect_key,
            exchange_effect_id=ack.exchange_order_id,
            response_payload={"exchange_order_id": ack.exchange_order_id},
        )
        return ack

    async def cancel_order_by_client_id(self, symbol: str, client_order_id: str) -> None:
        effect_key = self._key(EffectType.CANCEL_ORDER, client_order_id)
        preparation = await self.journal.prepare(
            effect_key=effect_key,
            effect_type=EffectType.CANCEL_ORDER,
            exchange=self.name,
            symbol=symbol,
            client_order_id=client_order_id,
            request_payload={"symbol": symbol, "client_order_id": client_order_id},
        )
        effect = preparation.effect
        if not preparation.created:
            if effect.status in {EffectStatus.CONFIRMED, EffectStatus.RECONCILED}:
                return
            if effect.status is EffectStatus.FAILED:
                raise ExecutionRecoveryError(f"cancel effect {effect.effect_key} is FAILED")
        async with self.journal.recovery_lock(effect_key):
            if not await self.adapter.is_order_active_by_client_id(symbol, client_order_id):
                await self.journal.reconcile(
                    effect_key,
                    exchange_effect_id=client_order_id,
                    response_payload={"active": False},
                )
                return
            await self.adapter.cancel_order_by_client_id(symbol, client_order_id)
            if await self.adapter.is_order_active_by_client_id(symbol, client_order_id):
                raise ExecutionRecoveryError(f"order {client_order_id} remains active after cancellation")
            await self.journal.confirm(
                effect_key,
                exchange_effect_id=client_order_id,
                response_payload={"active": False},
            )

    async def set_leverage(self, symbol: str, leverage: float) -> None:
        identity = f"{symbol}:{float(leverage).hex()}"
        effect_key = self._key(EffectType.SET_LEVERAGE, identity)
        preparation = await self.journal.prepare(
            effect_key=effect_key,
            effect_type=EffectType.SET_LEVERAGE,
            exchange=self.name,
            symbol=symbol,
            client_order_id=None,
            request_payload={"symbol": symbol, "leverage_hex": float(leverage).hex()},
        )
        effect = preparation.effect
        if not preparation.created:
            if effect.status in {EffectStatus.CONFIRMED, EffectStatus.RECONCILED}:
                return
            raise ExecutionRecoveryError(f"leverage effect {effect.effect_key} requires reconciliation")
        await self.adapter.set_leverage(symbol, leverage)
        await self.journal.confirm(
            effect_key,
            exchange_effect_id=symbol,
            response_payload={"leverage_hex": float(leverage).hex()},
        )

    async def _recover_prepared_place(
        self,
        effect: ExecutionEffect,
        intent: OrderIntent,
    ) -> ExecutionReport:
        if effect.status is EffectStatus.FAILED:
            raise ExecutionRecoveryError(f"place effect {effect.effect_key} is FAILED")
        async with self.journal.recovery_lock(effect.effect_key):
            submitted_id = self._client_id(intent.client_order_id, "place order")
            if await self.adapter.is_order_active_by_client_id(intent.symbol, submitted_id):
                # The parent PREPARED effect remains the recovery record. Venue
                # cancellation is idempotent and a crash here simply repeats
                # this active-state check on the next recovery pass.
                await self.adapter.cancel_order_by_client_id(intent.symbol, submitted_id)
                if await self.adapter.is_order_active_by_client_id(intent.symbol, submitted_id):
                    raise ExecutionRecoveryError("prepared entry remains active after cancellation")
            if not await self.adapter.is_position_flat(intent.symbol):
                raise ExecutionRecoveryError("prepared entry is inactive but the position is not flat")
            response = self._neutral_report(intent, "prepared entry reconciled inactive and flat")
            await self.journal.reconcile(
                effect.effect_key,
                exchange_effect_id=submitted_id,
                response_payload=response.to_payload(),
            )
            return response

    async def _recover_prepared_close(
        self,
        effect: ExecutionEffect,
        *,
        quantity: float | None,
        side: OrderSide | None,
    ) -> ExecutionReport:
        if effect.status is EffectStatus.FAILED:
            raise ExecutionRecoveryError(f"close effect {effect.effect_key} is FAILED")
        async with self.journal.recovery_lock(effect.effect_key):
            if not await self.adapter.is_position_flat(effect.symbol):
                raise ExecutionRecoveryError("prepared close has not reached a flat position")
            report = ExecutionReport(
                source="execution-engine",
                client_order_id=effect.client_order_id or "unknown",
                exchange_order_id=effect.client_order_id,
                exchange=self.name,
                symbol=effect.symbol,
                side=side or OrderSide.BUY,
                status=OrderStatus.CANCELED,
                requested_qty=quantity or 0.0,
                remaining_qty=0.0,
                message="prepared close reconciled to the flat desired state",
            )
            await self.journal.reconcile(
                effect.effect_key,
                exchange_effect_id=effect.client_order_id,
                response_payload=report.to_payload(),
            )
            return report

    async def _recover_prepared_stop(
        self,
        effect: ExecutionEffect,
        *,
        stop_price: float,
        position_side: OrderSide,
        parent_order_id: str,
    ) -> ProtectiveStopAck:
        async with self.journal.recovery_lock(effect.effect_key):
            if not self.adapter.protective_stop_lookup_authoritative:
                if await self.adapter.is_position_flat(effect.symbol):
                    await self.journal.reconcile(
                        effect.effect_key,
                        response_payload={"position_flat": True, "protective_stop_required": False},
                    )
                    raise ProtectionNoLongerRequired(
                        "position is already flat; protective stop is not required"
                    )
                raise ExecutionRecoveryError(
                    f"{self.name} cannot authoritatively deduplicate a prepared protective stop"
                )
            existing = await self.adapter.find_protective_stop(
                effect.symbol,
                stop_price,
                position_side,
                parent_order_id,
            )
            if existing is not None:
                await self.journal.reconcile(
                    effect.effect_key,
                    exchange_effect_id=existing.exchange_order_id,
                    response_payload={"exchange_order_id": existing.exchange_order_id},
                )
                return existing
            if await self.adapter.is_position_flat(effect.symbol):
                await self.journal.reconcile(
                    effect.effect_key,
                    response_payload={"position_flat": True, "protective_stop_required": False},
                )
                raise ProtectionNoLongerRequired("position is already flat; protective stop is not required")
            ack = await self.adapter.set_protective_stop(
                effect.symbol,
                stop_price,
                position_side,
                parent_order_id,
            )
            await self.journal.confirm(
                effect.effect_key,
                exchange_effect_id=ack.exchange_order_id,
                response_payload={"exchange_order_id": ack.exchange_order_id},
            )
            return ack

    async def recover_pending(self) -> list[str]:
        """Reconcile effects that were PREPARED when the prior process stopped."""
        blockers: list[str] = []
        for effect in await self.journal.recovery_required(exchange=self.name):
            if effect.status is EffectStatus.FAILED:
                blockers.append(f"{effect.effect_key}: FAILED: {effect.error or 'unknown error'}")
                continue
            try:
                await self._recover_effect(effect)
            except ProtectionNoLongerRequired:
                continue
            except Exception as exc:
                blockers.append(f"{effect.effect_key}: {type(exc).__name__}: {exc}")
        return blockers

    async def _recover_effect(self, effect: ExecutionEffect) -> None:
        request = effect.request_payload
        if effect.effect_type is EffectType.PROTECTIVE_STOP:
            await self._recover_prepared_stop(
                effect,
                stop_price=float.fromhex(str(request["stop_price_hex"])),
                position_side=OrderSide(str(request["position_side"])),
                parent_order_id=str(request["parent_order_id"]),
            )
            return
        if effect.effect_type is EffectType.CANCEL_ORDER:
            await self.cancel_order_by_client_id(
                effect.symbol,
                self._client_id(effect.client_order_id, "cancel recovery"),
            )
            return
        if effect.effect_type is EffectType.PLACE_ORDER:
            await self._recover_prepared_place(
                effect,
                OrderIntent.model_validate(request["intent"]),
            )
            return
        if effect.effect_type is EffectType.CLOSE_POSITION:
            await self._recover_prepared_close(
                effect,
                quantity=self._optional_float(request.get("quantity"), "close quantity"),
                side=None if request.get("side") is None else OrderSide(str(request["side"])),
            )
            return
        raise ExecutionRecoveryError(f"{effect.effect_type.value} cannot be reconciled automatically")

    async def is_order_active_by_client_id(self, symbol: str, client_order_id: str) -> bool:
        return await self.adapter.is_order_active_by_client_id(symbol, client_order_id)

    async def is_position_flat(self, symbol: str) -> bool:
        return await self.adapter.is_position_flat(symbol)

    async def find_protective_stop(
        self,
        symbol: str,
        stop_price: float,
        position_side: OrderSide,
        parent_order_id: str,
    ) -> ProtectiveStopAck | None:
        return await self.adapter.find_protective_stop(symbol, stop_price, position_side, parent_order_id)

    async def fetch_account_snapshot(
        self,
        *,
        account_id: str,
        peak_equity_usd: float,
    ) -> AccountSnapshot:
        return await self.adapter.fetch_account_snapshot(
            account_id=account_id, peak_equity_usd=peak_equity_usd
        )

    async def close(self) -> None:
        await self.adapter.close()

    @staticmethod
    def _client_id(value: str | None, operation: str) -> str:
        if value is None or not value.strip():
            raise ValueError(f"{operation} requires a deterministic client order ID")
        return value

    def _key(self, effect_type: EffectType, identity: str) -> str:
        digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()
        return f"{self.name}:{effect_type.value}:{digest}"

    @staticmethod
    def _cached_report(effect: ExecutionEffect) -> ExecutionReport | None:
        if effect.status not in {EffectStatus.CONFIRMED, EffectStatus.RECONCILED}:
            return None
        if effect.response_payload is None:
            raise ExecutionRecoveryError(f"effect {effect.effect_key} has no cached response")
        return ExecutionReport.model_validate(effect.response_payload)

    @staticmethod
    def _cached_stop(effect: ExecutionEffect) -> ProtectiveStopAck:
        if effect.response_payload is None:
            raise ExecutionRecoveryError(f"effect {effect.effect_key} has no cached stop response")
        exchange_order_id = effect.response_payload.get("exchange_order_id")
        if not isinstance(exchange_order_id, str):
            raise ExecutionRecoveryError(f"effect {effect.effect_key} has an invalid cached stop ID")
        return ProtectiveStopAck(exchange_order_id=exchange_order_id)

    @staticmethod
    def _optional_float(value: Any, field: str) -> float | None:
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ExecutionRecoveryError(f"{field} is not numeric")
        return float(value)

    def _neutral_report(self, intent: OrderIntent, detail: str) -> ExecutionReport:
        client_id = self._client_id(intent.client_order_id, "neutral report")
        return ExecutionReport(
            source="execution-engine",
            client_order_id=client_id,
            exchange_order_id=client_id,
            exchange=self.name,
            symbol=intent.symbol,
            side=intent.side,
            status=OrderStatus.CANCELED,
            requested_qty=intent.quantity,
            remaining_qty=0.0,
            message=detail,
        )


class ProtectionNoLongerRequired(ExecutionRecoveryError):
    """A crash-recovered stop belongs to a position that is already flat."""
