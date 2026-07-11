"""The execution core: ValidatedOrder -> exchange action + protective stop."""
from __future__ import annotations

from kairos_core.contracts import ExecutionReport, ValidatedOrder
from kairos_core.enums import OrderSide, SystemMode
from kairos_core.logging import get_logger

from .adapters.base import ExchangeAdapter
from .reason_router import Action, action_for
from .state_machine import client_order_id
from .trailing import TrailingStopManager

log = get_logger("execution")


class ExecutionEngine:
    def __init__(self, adapter: ExchangeAdapter, *, default_trail_pct: float = 0.01) -> None:
        self.adapter = adapter
        self.trailing = TrailingStopManager(default_trail_pct)
        self.system_mode = SystemMode.NORMAL

    async def handle(self, order: ValidatedOrder) -> ExecutionReport | None:
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
            self.trailing.close(order.intent.symbol)
            return await self.adapter.close_position(order.intent.symbol)
        if action is Action.REDUCE:
            await self.adapter.set_leverage(order.intent.symbol, max(1.0, order.intent.leverage / 2))
            return None

        # OPEN: assign idempotency identity before the first exchange call.
        intent = order.intent.model_copy(update={
            "client_order_id": order.intent.client_order_id
            or client_order_id(order.message_id, self.adapter.name),
            **({"side": side} if side is not None else {}),
        })
        report = await self.adapter.place_order(intent)
        # Market orders carry no intent.price -> fall back to the exchange fill price.
        # If protection cannot be established, compensate by closing immediately.
        entry = report.avg_price or intent.price or 0.0
        if entry <= 0:
            log.error("execution.unprotected_position", symbol=intent.symbol, detail="no entry price")
            await self.adapter.close_position(intent.symbol)
            return report.model_copy(update={
                "message": "entry submitted but no protection price; emergency close requested",
                "retryable": False,
            })
        ts = self.trailing.open(intent.symbol, intent.side, entry)
        stop_side = "SELL" if intent.side is OrderSide.BUY else "BUY"
        try:
            await self.adapter.set_trailing_stop(intent.symbol, ts.stop_price, stop_side)
        except Exception:
            self.trailing.close(intent.symbol)
            log.exception("execution.protection_failed_emergency_close", symbol=intent.symbol)
            await self.adapter.close_position(intent.symbol)
            raise
        log.info("execution.armed_trailing", symbol=intent.symbol, stop=round(ts.stop_price, 2))
        log.info("execution.placed", symbol=intent.symbol, side=intent.side.value, status=report.status.value)
        return report

    def set_mode(self, mode: SystemMode) -> None:
        if mode != self.system_mode:
            log.warning("execution.mode_change", mode=mode.value)
        self.system_mode = mode
