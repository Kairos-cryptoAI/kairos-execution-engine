"""The execution core: ValidatedOrder -> exchange action + protective stop."""

from __future__ import annotations

import math
from collections import OrderedDict
from hashlib import sha256
from typing import NoReturn

from kairos_core.contracts import ExecutionReport, OrderIntent, ValidatedOrder
from kairos_core.enums import OrderSide, OrderStatus, SystemMode
from kairos_core.logging import get_logger

from .adapters.base import ExchangeAdapter
from .reason_router import Action, action_for
from .state_machine import client_order_id, is_evedex_client_order_id
from .trailing import TrailingStopManager

log = get_logger("execution")


class ExecutionSafetyError(RuntimeError):
    """The venue could not prove that an unsafe execution state was neutralized."""


class ExecutionEngine:
    def __init__(
        self,
        adapter: ExchangeAdapter,
        *,
        default_trail_pct: float = 0.01,
        allowed_symbols: set[str] | None = None,
        idempotency_cache_size: int = 10_000,
    ) -> None:
        if idempotency_cache_size < 1:
            raise ValueError("idempotency_cache_size must be positive")
        self.adapter = adapter
        self.trailing = TrailingStopManager(default_trail_pct)
        self.allowed_symbols = {symbol.upper() for symbol in (allowed_symbols or set())}
        self.system_mode = SystemMode.NORMAL
        self._idempotency_cache_size = idempotency_cache_size
        self._completed: OrderedDict[str, tuple[str, ExecutionReport | None]] = OrderedDict()

    async def handle(self, order: ValidatedOrder) -> ExecutionReport | None:
        fingerprint = sha256(order.model_dump_json().encode()).hexdigest()
        cached = self._completed.get(order.message_id)
        if cached is not None:
            cached_fingerprint, cached_report = cached
            if cached_fingerprint != fingerprint:
                raise ExecutionSafetyError(
                    f"validated-order ID {order.message_id!r} was reused with a different payload"
                )
            self._completed.move_to_end(order.message_id)
            log.info("execution.duplicate_suppressed", message_id=order.message_id)
            return cached_report.model_copy(deep=True) if cached_report is not None else None

        result = await self._handle_once(order)
        self._completed[order.message_id] = (fingerprint, result)
        if len(self._completed) > self._idempotency_cache_size:
            self._completed.popitem(last=False)
        return result

    async def _handle_once(self, order: ValidatedOrder) -> ExecutionReport | None:
        symbol = order.intent.symbol.upper()
        if symbol not in self.allowed_symbols:
            log.error("execution.symbol_rejected", symbol=symbol)
            return None
        if not order.approved:
            log.info("execution.skip_unapproved", reason=order.reason_code.value)
            return None

        action, side = action_for(order.reason_code)

        # In LOCAL_QUANT_MODE the LLM is detached; only protective actions are allowed.
        if self.system_mode is SystemMode.LOCAL_QUANT_MODE and action is Action.OPEN:
            log.warning("execution.blocked_local_quant_mode", reason=order.reason_code.value)
            return None

        if action is Action.NOOP:
            return None
        if action is Action.CLOSE:
            return await self._close_to_desired_state(order)
        if action is Action.REDUCE:
            await self.adapter.set_leverage(order.intent.symbol, max(1.0, order.intent.leverage / 2))
            return None

        # OPEN: assign idempotency identity before the first exchange call.
        existing_client_id = order.intent.client_order_id
        needs_evedex_id = self.adapter.name.casefold() == "evedex" and (
            existing_client_id is None or not is_evedex_client_order_id(existing_client_id)
        )
        exchange_client_id = (
            client_order_id(
                existing_client_id or order.message_id,
                self.adapter.name,
                occurred_at=order.produced_at,
            )
            if existing_client_id is None or needs_evedex_id
            else existing_client_id
        )
        intent = order.intent.model_copy(
            update={
                "client_order_id": exchange_client_id,
                **({"side": side} if side is not None else {}),
            }
        )
        try:
            report = await self.adapter.place_order(intent)
        except Exception as exc:
            await self._resolve_ambiguous_entry(order, intent, exc)
        ack_error = self._execution_ack_error(
            report,
            intent,
            expected_client_order_id=exchange_client_id,
        )
        if ack_error is not None:
            log.error("execution.malformed_entry_ack", symbol=intent.symbol, detail=ack_error)
            return await self._compensate_unprotected(
                order,
                intent,
                report,
                reason=f"malformed entry acknowledgement: {ack_error}",
                cancel_entry=True,
            )
        if report.status is OrderStatus.REJECTED:
            if report.filled_qty > 0:
                return await self._compensate_unprotected(
                    order,
                    intent,
                    report,
                    reason="rejected entry acknowledgement reported a fill",
                )
            log.warning("execution.order_rejected", symbol=intent.symbol, detail=report.message)
            return report
        if report.status is OrderStatus.CANCELED and report.filled_qty == 0:
            log.info("execution.order_canceled", symbol=intent.symbol)
            return report
        if (
            report.status in {OrderStatus.NEW, OrderStatus.PARTIALLY_FILLED}
            and report.exchange_order_id is None
        ):
            return await self._compensate_unprotected(
                order,
                intent,
                report,
                reason="active entry acknowledgement has no exchange order ID",
            )
        # Market orders carry no intent.price -> fall back to the exchange fill price.
        # If protection cannot be established, compensate by closing immediately.
        entry = report.avg_price or intent.price or 0.0
        if not math.isfinite(entry) or entry <= 0:
            log.error("execution.unprotected_position", symbol=intent.symbol, detail="no entry price")
            return await self._compensate_unprotected(
                order,
                intent,
                report,
                reason="entry submitted without a finite positive protection price",
            )
        trail_pct = None
        if intent.stop_price is not None:
            explicit_trail_pct = abs(entry - intent.stop_price) / entry
            stop_is_protective = (intent.side is OrderSide.BUY and intent.stop_price < entry) or (
                intent.side is OrderSide.SELL and intent.stop_price > entry
            )
            stop_is_protective = (
                stop_is_protective
                and math.isfinite(intent.stop_price)
                and math.isfinite(explicit_trail_pct)
                and 0 < explicit_trail_pct < 1
            )
            if not stop_is_protective:
                log.error(
                    "execution.invalid_protective_stop",
                    symbol=intent.symbol,
                    side=intent.side.value,
                    entry=entry,
                    stop=intent.stop_price,
                )
                return await self._compensate_unprotected(
                    order,
                    intent,
                    report,
                    reason="entry submitted with an invalid protective stop",
                )
            trail_pct = explicit_trail_pct
        try:
            stop = self.trailing.open(intent.symbol, intent.side, entry, trail_pct=trail_pct)
            stop_price = stop.stop_price
            if not math.isfinite(stop_price) or stop_price <= 0:
                raise ValueError("computed protective-stop price must be finite and positive")
            stop_ack = await self.adapter.set_protective_stop(
                intent.symbol,
                stop_price,
                intent.side,
                exchange_client_id,
            )
        except Exception as exc:
            self.trailing.close(intent.symbol)
            log.exception("execution.protection_failed_emergency_close", symbol=intent.symbol)
            return await self._compensate_unprotected(
                order,
                intent,
                report,
                reason=f"protective stop failed: {type(exc).__name__}",
            )
        log.info(
            "execution.armed_protective_stop",
            symbol=intent.symbol,
            stop=round(stop_price, 8),
            exchange_order_id=stop_ack.exchange_order_id,
        )
        log.info("execution.placed", symbol=intent.symbol, side=intent.side.value, status=report.status.value)
        return report

    async def _close_to_desired_state(self, order: ValidatedOrder) -> ExecutionReport:
        """Close exactly once, and acknowledge only a reconciled flat desired state."""
        self.trailing.close(order.intent.symbol)
        close_id = client_order_id(
            f"{order.message_id}:close",
            self.adapter.name,
            occurred_at=order.produced_at,
        )
        if await self._position_is_flat(
            order.intent.symbol,
            context="close-position preflight reconciliation",
        ):
            await self._cancel_if_active(
                order.intent.symbol,
                close_id,
                context="already-flat close preflight",
            )
            return self._desired_state_close_report(order.intent, close_id, "position already flat")

        if await self._order_is_active(
            order.intent.symbol,
            close_id,
            context="close-position preflight order reconciliation",
        ):
            raise ExecutionSafetyError(
                f"deterministic close {close_id} is still active; awaiting venue reconciliation"
            )

        try:
            close_report = await self.adapter.close_position(
                order.intent.symbol,
                quantity=order.intent.quantity,
                side=order.intent.side,
                client_order_id=close_id,
            )
        except Exception as exc:
            return await self._resolve_ambiguous_close(order.intent, close_id, exc)

        ack_error = self._execution_ack_error(
            close_report,
            order.intent,
            expected_client_order_id=close_id,
        )
        position_is_flat = await self._position_is_flat(
            order.intent.symbol,
            context="close-position post-submit reconciliation",
        )
        if ack_error is not None:
            raise ExecutionSafetyError(f"malformed close acknowledgement: {ack_error}")
        if not position_is_flat:
            raise ExecutionSafetyError(
                f"close acknowledgement status={close_report.status.value} did not flatten position"
            )
        await self._cancel_if_active(
            order.intent.symbol,
            close_id,
            context="flat close post-submit reconciliation",
        )
        if close_report.status is OrderStatus.FILLED:
            return close_report
        return self._desired_state_close_report(
            order.intent,
            close_id,
            f"venue position is flat after close status={close_report.status.value}",
        )

    async def _resolve_ambiguous_close(
        self,
        intent: OrderIntent,
        close_id: str,
        mutation_error: Exception,
    ) -> ExecutionReport:
        """Resolve an exception after close submission using only trusted identity/state."""
        position_is_flat = await self._position_is_flat(
            intent.symbol,
            context="ambiguous close position reconciliation",
            cause=mutation_error,
        )
        if position_is_flat:
            await self._cancel_if_active(
                intent.symbol,
                close_id,
                context="ambiguous close already-flat reconciliation",
                cause=mutation_error,
            )
            return self._desired_state_close_report(
                intent,
                close_id,
                f"ambiguous close reconciled flat after {type(mutation_error).__name__}",
            )
        active = await self._order_is_active(
            intent.symbol,
            close_id,
            context="ambiguous close order reconciliation",
            cause=mutation_error,
        )
        detail = "remains active" if active else "is inactive but the position is not flat"
        raise ExecutionSafetyError(
            f"ambiguous close {close_id} after {type(mutation_error).__name__} {detail}"
        ) from mutation_error

    async def _resolve_ambiguous_entry(
        self,
        order: ValidatedOrder,
        intent: OrderIntent,
        mutation_error: Exception,
    ) -> NoReturn:
        """Neutralize an entry whose submission response was not received or trusted."""
        uncertain_report = ExecutionReport(
            source="execution-engine",
            client_order_id=intent.client_order_id or "unknown",
            exchange=self.adapter.name,
            symbol=intent.symbol,
            side=intent.side,
            status=OrderStatus.NEW,
            requested_qty=intent.quantity,
            remaining_qty=intent.quantity,
            message=f"ambiguous place_order after {type(mutation_error).__name__}",
        )
        try:
            await self._compensate_unprotected(
                order,
                intent,
                uncertain_report,
                reason=f"ambiguous entry mutation after {type(mutation_error).__name__}",
                cancel_entry=True,
            )
        except ExecutionSafetyError as exc:
            raise ExecutionSafetyError(str(exc)) from mutation_error
        raise ExecutionSafetyError(
            "ambiguous entry mutation was reconciled inactive and flat; "
            "delivery remains pending for deterministic redelivery"
        ) from mutation_error

    async def _position_is_flat(
        self,
        symbol: str,
        *,
        context: str,
        cause: Exception | None = None,
    ) -> bool:
        try:
            return await self.adapter.is_position_flat(symbol)
        except Exception as exc:
            raise ExecutionSafetyError(f"{context} failed: {type(exc).__name__}") from (cause or exc)

    async def _order_is_active(
        self,
        symbol: str,
        client_id: str,
        *,
        context: str,
        cause: Exception | None = None,
    ) -> bool:
        try:
            return await self.adapter.is_order_active_by_client_id(symbol, client_id)
        except Exception as exc:
            raise ExecutionSafetyError(f"{context} failed: {type(exc).__name__}") from (cause or exc)

    async def _cancel_if_active(
        self,
        symbol: str,
        client_id: str,
        *,
        context: str,
        cause: Exception | None = None,
    ) -> None:
        if not await self._order_is_active(
            symbol,
            client_id,
            context=f"{context} open-order lookup",
            cause=cause,
        ):
            return
        try:
            await self.adapter.cancel_order_by_client_id(symbol, client_id)
        except Exception as exc:
            raise ExecutionSafetyError(f"{context} cancellation failed: {type(exc).__name__}") from (
                cause or exc
            )
        if await self._order_is_active(
            symbol,
            client_id,
            context=f"{context} post-cancel lookup",
            cause=cause,
        ):
            raise ExecutionSafetyError(f"{context}: order {client_id} remains active after cancellation")

    def _desired_state_close_report(
        self,
        intent: OrderIntent,
        close_id: str,
        detail: str,
    ) -> ExecutionReport:
        return ExecutionReport(
            source="execution-engine",
            client_order_id=close_id,
            exchange=self.adapter.name,
            symbol=intent.symbol,
            side=intent.side,
            # No exchange fill was observed on this path.  CANCELED is the
            # only existing terminal status that does not invent one; the
            # reconciled desired state is carried explicitly in ``message``.
            status=OrderStatus.CANCELED,
            requested_qty=intent.quantity,
            filled_qty=0.0,
            remaining_qty=0.0,
            message=f"desired state satisfied: {detail}; no unverified fill is claimed",
        )

    async def _compensate_unprotected(
        self,
        order: ValidatedOrder,
        intent: OrderIntent,
        entry_report: ExecutionReport,
        *,
        reason: str,
        cancel_entry: bool = False,
    ) -> ExecutionReport:
        """Neutralize an entry that cannot be proven protected.

        An active remainder is cancelled and reconciled before any close is
        attempted.  A close acknowledgement alone is never considered proof:
        the venue must subsequently report the position as flat.
        """
        self.trailing.close(intent.symbol)
        if cancel_entry or entry_report.status in {OrderStatus.NEW, OrderStatus.PARTIALLY_FILLED}:
            submitted_client_id = intent.client_order_id
            if not submitted_client_id:
                raise ExecutionSafetyError(
                    f"{reason}; entry has no trusted submitted client ID and cannot be cancelled"
                )
            try:
                await self.adapter.cancel_order_by_client_id(intent.symbol, submitted_client_id)
                if await self.adapter.is_order_active_by_client_id(
                    intent.symbol,
                    submitted_client_id,
                ):
                    raise ExecutionSafetyError(
                        f"{reason}; entry {submitted_client_id} remains active after cancellation"
                    )
            except ExecutionSafetyError:
                raise
            except Exception as exc:
                raise ExecutionSafetyError(
                    f"{reason}; entry cancellation could not be verified: {type(exc).__name__}"
                ) from exc

        try:
            if await self.adapter.is_position_flat(intent.symbol):
                return self._compensated_report(entry_report, intent, reason)
        except Exception as exc:
            raise ExecutionSafetyError(
                f"{reason}; pre-close position reconciliation failed: {type(exc).__name__}"
            ) from exc

        emergency_id = client_order_id(
            f"{order.message_id}:emergency-close",
            self.adapter.name,
            occurred_at=order.produced_at,
        )
        if await self._order_is_active(
            intent.symbol,
            emergency_id,
            context=f"{reason}; emergency-close preflight reconciliation",
        ):
            raise ExecutionSafetyError(f"{reason}; emergency close {emergency_id} remains active")
        try:
            close_report = await self.adapter.close_position(
                intent.symbol,
                client_order_id=emergency_id,
            )
        except ExecutionSafetyError:
            raise
        except Exception as exc:
            position_is_flat = await self._position_is_flat(
                intent.symbol,
                context=f"{reason}; ambiguous emergency-close position reconciliation",
                cause=exc,
            )
            if position_is_flat:
                await self._cancel_if_active(
                    intent.symbol,
                    emergency_id,
                    context=f"{reason}; ambiguous emergency close already flat",
                    cause=exc,
                )
                return self._compensated_report(entry_report, intent, reason)
            active = await self._order_is_active(
                intent.symbol,
                emergency_id,
                context=f"{reason}; ambiguous emergency-close order reconciliation",
                cause=exc,
            )
            detail = "remains active" if active else "is inactive while the position remains open"
            raise ExecutionSafetyError(
                f"{reason}; ambiguous emergency close after {type(exc).__name__} {detail}"
            ) from exc

        ack_error = self._ack_error(
            close_report,
            expected_client_order_id=emergency_id,
            expected_symbol=intent.symbol,
        )
        position_is_flat = await self._position_is_flat(
            intent.symbol,
            context=f"{reason}; emergency-close post-submit reconciliation",
        )
        if ack_error is not None:
            raise ExecutionSafetyError(f"{reason}; malformed emergency-close acknowledgement: {ack_error}")
        if close_report.status in {OrderStatus.REJECTED, OrderStatus.CANCELED}:
            raise ExecutionSafetyError(
                f"{reason}; emergency close status={close_report.status.value}; flat={position_is_flat}"
            )
        if not position_is_flat:
            raise ExecutionSafetyError(
                f"{reason}; emergency close status={close_report.status.value} did not flatten position"
            )
        await self._cancel_if_active(
            intent.symbol,
            emergency_id,
            context=f"{reason}; flat emergency-close reconciliation",
        )
        return self._compensated_report(entry_report, intent, reason)

    def _execution_ack_error(
        self,
        report: ExecutionReport,
        intent: OrderIntent,
        *,
        expected_client_order_id: str,
    ) -> str | None:
        return self._ack_error(
            report,
            expected_client_order_id=expected_client_order_id,
            expected_symbol=intent.symbol,
            expected_side=intent.side,
            expected_requested_qty=intent.quantity,
        )

    def _ack_error(
        self,
        report: ExecutionReport,
        *,
        expected_client_order_id: str,
        expected_symbol: str,
        expected_side: OrderSide | None = None,
        expected_requested_qty: float | None = None,
    ) -> str | None:
        numeric_fields = {
            "requested_qty": report.requested_qty,
            "filled_qty": report.filled_qty,
            "remaining_qty": report.remaining_qty,
            "avg_price": report.avg_price,
            "fees_usd": report.fees_usd,
        }
        for field, value in numeric_fields.items():
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                return f"{field} must be numeric"
            if not math.isfinite(value) or value < 0:
                return f"{field} must be finite and non-negative"
        if not isinstance(report.status, OrderStatus):
            return f"status {report.status!r} is not a recognized OrderStatus"
        if report.client_order_id != expected_client_order_id:
            return f"client_order_id {report.client_order_id!r} does not match {expected_client_order_id!r}"
        if not isinstance(report.exchange, str) or report.exchange.casefold() != self.adapter.name.casefold():
            return f"exchange {report.exchange!r} does not match adapter {self.adapter.name!r}"
        exchange_order_id = report.exchange_order_id
        has_exchange_order_id = isinstance(exchange_order_id, str) and bool(exchange_order_id.strip())
        if report.status is not OrderStatus.REJECTED and not has_exchange_order_id:
            return "exchange_order_id is required for a submitted order acknowledgement"
        if (
            exchange_order_id is not None
            and self.adapter.exchange_order_id_matches_client_order_id
            and exchange_order_id != expected_client_order_id
        ):
            return "exchange_order_id does not match the deterministic submitted order ID"
        if not isinstance(report.symbol, str) or report.symbol.upper() != expected_symbol.upper():
            return f"symbol {report.symbol!r} does not match {expected_symbol!r}"
        if expected_side is not None and report.side != expected_side:
            return f"side {report.side!r} does not match {expected_side.value}"

        tolerance_base = (
            expected_requested_qty if expected_requested_qty is not None else report.requested_qty
        )
        tolerance = max(1e-12, tolerance_base * 1e-9)
        if (
            expected_requested_qty is not None
            and abs(report.requested_qty - expected_requested_qty) > tolerance
        ):
            return "requested_qty does not match the submitted quantity"
        if report.filled_qty > report.requested_qty + tolerance:
            return "filled_qty exceeds requested_qty"
        if report.remaining_qty > report.requested_qty + tolerance:
            return "remaining_qty exceeds requested_qty"
        if report.filled_qty + report.remaining_qty > report.requested_qty + tolerance:
            return "filled_qty plus remaining_qty exceeds requested_qty"
        accounted_qty = report.filled_qty + report.remaining_qty
        if (
            report.status
            in {
                OrderStatus.NEW,
                OrderStatus.PARTIALLY_FILLED,
                OrderStatus.FILLED,
            }
            and abs(accounted_qty - report.requested_qty) > tolerance
        ):
            return f"{report.status.value} filled_qty plus remaining_qty must equal requested_qty"
        if report.status is OrderStatus.FILLED and (
            abs(report.filled_qty - report.requested_qty) > tolerance or report.remaining_qty > tolerance
        ):
            return "FILLED acknowledgement does not account for a complete fill"
        if report.status is OrderStatus.PARTIALLY_FILLED and (
            report.filled_qty <= 0 or report.remaining_qty <= 0
        ):
            return "PARTIALLY_FILLED acknowledgement requires positive filled and remaining quantities"
        return None

    def _compensated_report(
        self,
        entry_report: ExecutionReport,
        intent: OrderIntent,
        reason: str,
    ) -> ExecutionReport:
        safe_filled_qty = (
            min(entry_report.filled_qty, intent.quantity)
            if isinstance(entry_report.filled_qty, (int, float))
            and not isinstance(entry_report.filled_qty, bool)
            and math.isfinite(entry_report.filled_qty)
            and entry_report.filled_qty >= 0
            else 0.0
        )
        safe_avg_price = (
            entry_report.avg_price
            if isinstance(entry_report.avg_price, (int, float))
            and not isinstance(entry_report.avg_price, bool)
            and math.isfinite(entry_report.avg_price)
            and entry_report.avg_price >= 0
            else 0.0
        )
        safe_fees_usd = (
            entry_report.fees_usd
            if isinstance(entry_report.fees_usd, (int, float))
            and not isinstance(entry_report.fees_usd, bool)
            and math.isfinite(entry_report.fees_usd)
            and entry_report.fees_usd >= 0
            else 0.0
        )
        return entry_report.model_copy(
            update={
                "client_order_id": intent.client_order_id or "unknown",
                "exchange_order_id": None,
                "exchange": self.adapter.name,
                "symbol": intent.symbol,
                "side": intent.side,
                "status": OrderStatus.CANCELED,
                "requested_qty": intent.quantity,
                "filled_qty": safe_filled_qty,
                "remaining_qty": 0.0,
                "avg_price": safe_avg_price,
                "fees_usd": safe_fees_usd,
                "message": f"{reason}; entry canceled/closed and venue position reconciled flat",
                "retryable": False,
            }
        )

    def set_mode(self, mode: SystemMode) -> None:
        if mode != self.system_mode:
            log.warning("execution.mode_change", mode=mode.value)
        self.system_mode = mode
