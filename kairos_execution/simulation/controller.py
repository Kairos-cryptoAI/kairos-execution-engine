"""Crash-safe controller for the sealed, offline market-data simulator.

This module coordinates only immutable SIM contracts, the isolated simulator
journal, and the pure Decimal IOC model.  It has neither process-local trade
state nor a market-data connection: every decision is derived from a stored
closed bar and a stored top-N frame selected at the command's logical arrival.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from decimal import ROUND_CEILING, ROUND_FLOOR, Decimal
from typing import Any, Literal, cast

from kairos_core.contracts import (
    ClosedBarEventV1,
    SimulationAdmissionV2,
    SimulationCommandReceiptV1,
    SimulationCommandV1,
    SimulationResultV1,
    SimulationTradeEventV2,
    SimulationTradeV1,
)
from kairos_core.enums import Side
from kairos_persistence import SimulationRepository, SimulationTradeJournal

from .bridge import command_receipt, decimal_from_contract, kernel_assumptions, kernel_command, kernel_frame
from .fill_model import SimulationIdentityConflict, simulate_ioc
from .models import CommandReceipt, FillOutcome, LiquidityState, ModelStep

_STATE_SCHEMA_VERSION = "sim-liquidity-state.v1"
_TERMINAL_STATES = frozenset({"FLAT", "UNRESOLVED", "NO_FILL", "BLOCKED"})
_TradeState = Literal["PENDING", "ACTIVE", "FLAT", "UNRESOLVED", "NO_FILL", "BLOCKED"]
_CommandKind = Literal["ENTRY_IOC", "STOP_EXIT_IOC", "TARGET_EXIT_IOC", "TIMEOUT_EXIT_IOC"]


class SimulationControllerIntegrityError(RuntimeError):
    """A durable SIM record cannot be safely resumed as an immutable fact."""


@dataclass(frozen=True, slots=True)
class SimulationExecutionOutcome:
    """One controller observation; ``receipt=None`` means the command still waits."""

    trade: SimulationTradeV1
    command: SimulationCommandV1
    receipt: SimulationCommandReceiptV1 | None
    lifecycle_state: _TradeState
    replayed: bool

    @property
    def pending(self) -> bool:
        return self.receipt is None


class SimulationExecutionController:
    """Serialize the simulator lifecycle through its own durable repository.

    The controller deliberately does not treat a process restart as a new
    attempt.  A command is prepared before model evaluation; terminal receipts,
    private liquidity state and public lifecycle events commit atomically; and
    recovery reads completed receipts rather than recalculating them.
    """

    def __init__(self, repository: SimulationRepository, *, source: str = "market-simulator") -> None:
        if not source or source != source.strip() or len(source) > 128:
            raise ValueError("source must be a normalized non-empty identifier")
        self._repository = repository
        self._source = source

    async def start_trade(
        self,
        admission: SimulationAdmissionV2,
        *,
        created_at_ms: int,
    ) -> SimulationTradeV1:
        """Persist one decision-bound admission, trade, and root lifecycle fact."""

        self._validate_timestamp("created_at_ms", created_at_ms)
        session = self._session_from_admission(admission)
        intent = self._intent_from_admission(admission)
        if created_at_ms > session.ends_at_ms:
            raise ValueError("simulation trade cannot start after its immutable session ends")
        if created_at_ms > intent.entry_expires_ts_ms:
            raise ValueError("simulation trade cannot start after its immutable intent expires")
        await self._repository.create_admission(admission)
        trade = SimulationTradeV1(source=self._source, admission=admission, created_at_ms=created_at_ms)
        created = await self._repository.create_trade(trade)
        root = SimulationTradeEventV2(
            source=self._source,
            session_id=self._required(trade.session_id, "trade session_id"),
            admission_id=self._required(trade.admission_id, "trade admission_id"),
            intent_id=self._required(trade.intent_id, "trade intent_id"),
            trade_id=self._required(trade.trade_id, "trade trade_id"),
            event_seq=1,
            event_type="ADMITTED",
            to_state="PENDING",
            occurred_at_ms=created_at_ms,
            symbol=self._required(trade.symbol, "trade symbol"),
            side=self._trade_side(trade).value,
            reason_codes=("SIM_ADMISSION",),
        )
        await self._repository.append_trade_event(root)
        journal = await self._journal(trade)
        if created and journal.state != "PENDING":
            raise SimulationControllerIntegrityError("new simulation trade is not pending after admission")
        return trade

    async def submit_entry(
        self,
        trade: SimulationTradeV1,
        *,
        as_of_ms: int,
    ) -> SimulationExecutionOutcome:
        """Prepare and causally evaluate the immutable next-bar IOC entry."""

        return await self._process_command(self._entry_command(trade), as_of_ms=as_of_ms)

    async def process_closed_bar(
        self,
        trade: SimulationTradeV1,
        bar: ClosedBarEventV1,
        *,
        as_of_ms: int,
    ) -> SimulationExecutionOutcome | None:
        """Advance SL/TP/timeout only from one stored, closed Binance UM bar.

        If a candle crosses both target and stop, the frozen ``STOP_WINS``
        policy chooses the adverse stop.  A current top-N frame is still
        required at logical order arrival; a candle alone never creates a fill.
        """

        self._validate_timestamp("as_of_ms", as_of_ms)
        symbol = self._required(trade.symbol, "trade symbol")
        if bar.symbol != symbol or bar.venue != "BINANCE_UM" or bar.bar_sha256 is None:
            raise ValueError(
                "simulation exit processing requires its matching canonical Binance UM closed bar"
            )
        trigger_at_ms = bar.close_time_ms + 1
        if as_of_ms < trigger_at_ms:
            return None
        journal = await self._journal(trade)
        if journal.state != "ACTIVE":
            return None
        session = self._session_from_trade(trade)
        if trigger_at_ms > session.ends_at_ms:
            await self._mark_unresolved(
                trade,
                journal,
                occurred_at_ms=trigger_at_ms,
                reason="SESSION_ENDED_BEFORE_EXIT",
            )
            return None
        entry_event = self._first_entry_event(journal)
        intent = self._intent_from_trade(trade)
        plan = intent.exit_plan
        if plan is None:
            raise SimulationControllerIntegrityError("active simulation trade has no immutable exit plan")
        side = self._trade_side(trade)
        low = decimal_from_contract(bar.low, field="closed_bar_low")
        high = decimal_from_contract(bar.high, field="closed_bar_high")
        close = decimal_from_contract(bar.close, field="closed_bar_close")
        stop = decimal_from_contract(plan.stop_price, field="exit_plan_stop_price")
        target = decimal_from_contract(plan.target_price, field="exit_plan_target_price")
        command_kind: _CommandKind | None = None
        price_cap: Decimal | None = None
        if side is Side.LONG:
            if low <= stop:
                command_kind, price_cap = "STOP_EXIT_IOC", stop
            elif high >= target:
                command_kind, price_cap = "TARGET_EXIT_IOC", target
        elif side is Side.SHORT:
            if high >= stop:
                command_kind, price_cap = "STOP_EXIT_IOC", stop
            elif low <= target:
                command_kind, price_cap = "TARGET_EXIT_IOC", target
        else:
            raise SimulationControllerIntegrityError("active simulation trade is not directional")
        if command_kind is None and trigger_at_ms >= entry_event.occurred_at_ms + plan.max_holding_ms:
            command_kind, price_cap = "TIMEOUT_EXIT_IOC", close
        if command_kind is None or price_cap is None:
            return None
        quantity = self._remaining_quantity(journal)
        if quantity <= 0:
            raise SimulationControllerIntegrityError(
                "active simulation trade has no positive remaining exposure"
            )
        command = self._exit_command(
            trade,
            command_kind=command_kind,
            quantity=quantity,
            price_cap=self._adverse_exit_cap(price_cap, side=side, trade=trade),
            trigger_at_ms=trigger_at_ms,
        )
        return await self._process_command(command, as_of_ms=as_of_ms)

    async def recover_prepared(
        self,
        session_id: str,
        *,
        as_of_ms: int,
    ) -> tuple[SimulationExecutionOutcome, ...]:
        """Resume only prepared commands, then repair terminal result records."""

        self._validate_sha256("session_id", session_id)
        self._validate_timestamp("as_of_ms", as_of_ms)
        outcomes: list[SimulationExecutionOutcome] = []
        for command in await self._repository.list_prepared_commands(session_id):
            outcomes.append(await self._process_command(command, as_of_ms=as_of_ms))
        for trade in await self._repository.list_terminal_trades_without_result(session_id):
            await self._ensure_terminal_result(trade)
        return tuple(outcomes)

    async def _process_command(
        self,
        command: SimulationCommandV1,
        *,
        as_of_ms: int,
    ) -> SimulationExecutionOutcome:
        self._validate_timestamp("as_of_ms", as_of_ms)
        prepared = await self._repository.prepare_command(command)
        stored_command = prepared.command
        journal = await self._journal(stored_command.trade)
        if prepared.status == "COMPLETED":
            receipt = await self._repository.load_command_receipt(
                self._required(stored_command.command_id, "command_id")
            )
            if receipt is None:
                raise SimulationControllerIntegrityError(
                    "completed simulation command has no durable receipt"
                )
            await self._ensure_terminal_result(stored_command.trade)
            refreshed = await self._journal(stored_command.trade)
            return SimulationExecutionOutcome(
                trade=stored_command.trade,
                command=stored_command,
                receipt=receipt,
                lifecycle_state=refreshed.state,
                replayed=True,
            )
        if prepared.status != "PREPARED":
            raise SimulationControllerIntegrityError("simulation command has an unknown durable status")
        receipt, next_state = await self._evaluate_prepared(stored_command, as_of_ms=as_of_ms)
        if receipt is None:
            return SimulationExecutionOutcome(
                trade=stored_command.trade,
                command=stored_command,
                receipt=None,
                lifecycle_state=journal.state,
                replayed=False,
            )
        event = self._event_for_receipt(stored_command, receipt, journal)
        completion = await self._repository.complete_command(
            stored_command,
            receipt,
            model_state_schema_version=_STATE_SCHEMA_VERSION,
            model_state_payload=next_state.model_dump(mode="json"),
            events=(event,),
        )
        if not completion.created and completion.receipt != receipt:
            raise SimulationControllerIntegrityError("simulation command completion differs from its receipt")
        await self._ensure_terminal_result(stored_command.trade)
        refreshed = await self._journal(stored_command.trade)
        return SimulationExecutionOutcome(
            trade=stored_command.trade,
            command=stored_command,
            receipt=completion.receipt,
            lifecycle_state=refreshed.state,
            replayed=not completion.created,
        )

    async def _evaluate_prepared(
        self,
        command: SimulationCommandV1,
        *,
        as_of_ms: int,
    ) -> tuple[SimulationCommandReceiptV1 | None, LiquidityState]:
        session = self._session_from_trade(command.trade)
        assumptions = kernel_assumptions(session)
        state = await self._load_liquidity_state(command)
        kernel = kernel_command(command)
        if as_of_ms < kernel.submitted_at_ms + assumptions.latency_ms:
            return None, state
        if any(receipt.command_id == kernel.command_id for receipt in state.receipts):
            raise SimulationControllerIntegrityError(
                "prepared simulation command is already present in private liquidity state"
            )
        arrival_at_ms = kernel.submitted_at_ms + assumptions.latency_ms
        if arrival_at_ms > command.expires_at_ms:
            step = self._terminal_without_book(
                command,
                state,
                assumptions_sha256=assumptions.fingerprint(),
                as_of_ms=as_of_ms,
                reason="COMMAND_EXPIRED",
                status="NO_FILL",
            )
            return command_receipt(
                command=command, outcome=step.outcome, recorded_frame=None, source=self._source
            ), step.state
        frame = await self._repository.load_latest_book_frame(
            session.tape_id,
            self._required(command.symbol, "command symbol"),
            as_of_ms=arrival_at_ms,
        )
        if frame is None:
            step = self._terminal_without_book(
                command,
                state,
                assumptions_sha256=assumptions.fingerprint(),
                as_of_ms=as_of_ms,
                reason="NO_ADMITTED_BOOK",
                status="BLOCKED",
            )
            return command_receipt(
                command=command, outcome=step.outcome, recorded_frame=None, source=self._source
            ), step.state
        step = simulate_ioc(
            kernel,
            kernel_frame(frame),
            assumptions,
            state,
            as_of_ms=as_of_ms,
        )
        if step.outcome.status == "WAIT":
            return None, state
        return command_receipt(
            command=command,
            outcome=step.outcome,
            recorded_frame=frame,
            source=self._source,
        ), step.state

    async def _load_liquidity_state(self, command: SimulationCommandV1) -> LiquidityState:
        session = self._session_from_trade(command.trade)
        symbol = self._required(command.symbol, "command symbol")
        stored = await self._repository.load_liquidity_state(
            self._required(command.session_id, "command session_id"), symbol
        )
        if stored is None:
            admission = self._admission_from_trade(command.trade)
            selected = admission.decision.selected_book_frame
            if selected is None:
                raise SimulationControllerIntegrityError(
                    "approved simulation admission has no recorded-book stream epoch"
                )
            return LiquidityState(
                session_id=self._required(command.session_id, "command session_id"),
                tape_id=session.tape_id,
                stream_epoch=selected.stream_epoch,
                symbol=symbol,
            )
        schema_version, payload = stored
        if schema_version != _STATE_SCHEMA_VERSION:
            raise SimulationControllerIntegrityError(
                "simulation private liquidity state schema is unsupported"
            )
        try:
            state = LiquidityState.model_validate_json(
                json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
            )
        except Exception as exc:
            raise SimulationControllerIntegrityError(
                "stored simulator liquidity state no longer satisfies its immutable model"
            ) from exc
        if (
            state.session_id != command.session_id
            or state.tape_id != session.tape_id
            or state.symbol != symbol
        ):
            raise SimulationControllerIntegrityError("stored simulator liquidity state has mixed lineage")
        return state

    def _terminal_without_book(
        self,
        command: SimulationCommandV1,
        state: LiquidityState,
        *,
        assumptions_sha256: str,
        as_of_ms: int,
        reason: str,
        status: Literal["NO_FILL", "BLOCKED"],
    ) -> ModelStep:
        """Record an honest terminal command when no usable frame exists.

        There is deliberately no synthetic price, frame hash, or consumed
        depth.  The private receipt advances only the causal command cursor so
        a later command cannot be evaluated before this durable non-fill.
        """

        kernel = kernel_command(command)
        arrival_at_ms = (
            kernel.submitted_at_ms + self._session_from_trade(command.trade).assumptions.latency_ms
        )
        if as_of_ms < arrival_at_ms:
            raise ValueError("a terminal simulator outcome cannot predate command arrival")
        if as_of_ms < state.last_as_of_ms:
            raise ValueError("simulator evaluation clock cannot regress")
        if arrival_at_ms < state.last_arrival_at_ms:
            raise SimulationIdentityConflict(
                "new command arrival predates an already processed terminal command"
            )
        if state.assumptions_sha256 not in {None, assumptions_sha256}:
            raise SimulationIdentityConflict("simulation assumptions changed inside one session")
        command_sha256 = kernel.fingerprint()
        outcome = FillOutcome(
            command_id=kernel.command_id,
            command_sha256=command_sha256,
            assumptions_sha256=assumptions_sha256,
            frame_sha256=None,
            status=status,
            reason=reason,
            arrival_at_ms=arrival_at_ms,
            requested_quantity=kernel.quantity,
            filled_quantity=Decimal("0"),
            cancelled_quantity=kernel.quantity,
            notional_quote=Decimal("0"),
            fee_quote=Decimal("0"),
            implementation_shortfall_quote=Decimal("0"),
            level_fills=(),
        )
        receipt = CommandReceipt(
            command_id=kernel.command_id,
            command_sha256=command_sha256,
            assumptions_sha256=assumptions_sha256,
            outcome=outcome,
        )
        next_state = LiquidityState.model_validate(
            state.model_dump(mode="python")
            | {
                "assumptions_sha256": assumptions_sha256,
                "last_as_of_ms": as_of_ms,
                "last_arrival_at_ms": arrival_at_ms,
                "receipts": (*state.receipts, receipt),
            }
        )
        return ModelStep(outcome=outcome, state=next_state)

    def _event_for_receipt(
        self,
        command: SimulationCommandV1,
        receipt: SimulationCommandReceiptV1,
        journal: SimulationTradeJournal,
    ) -> SimulationTradeEventV2:
        trade = command.trade
        filled = decimal_from_contract(receipt.filled_quantity, field="receipt_filled_quantity")
        if command.command_kind == "ENTRY_IOC":
            if journal.state != "PENDING":
                raise SimulationControllerIntegrityError("simulator entry does not start from PENDING")
            if receipt.status == "FILLED":
                event_type, to_state = "ENTRY_FILLED", "ACTIVE"
            elif receipt.status == "PARTIAL":
                event_type, to_state = "ENTRY_PARTIAL", "ACTIVE"
            elif receipt.status == "NO_FILL":
                event_type, to_state = "ENTRY_NO_FILL", "NO_FILL"
            else:
                event_type, to_state = (
                    ("NO_ADMITTED_BOOK", "BLOCKED")
                    if "NO_ADMITTED_BOOK" in receipt.reason_codes
                    else ("SOURCE_BARRIER", "BLOCKED")
                )
        else:
            if journal.state != "ACTIVE":
                raise SimulationControllerIntegrityError("simulator exit does not start from ACTIVE")
            if receipt.status in {"FILLED", "PARTIAL"}:
                current_exit = self._exit_filled_quantity(journal)
                entry = self._entry_filled_quantity(journal)
                if filled <= 0 or current_exit + filled > entry:
                    raise SimulationControllerIntegrityError("simulator exit receipt exceeds active exposure")
                to_state = "FLAT" if current_exit + filled == entry else "UNRESOLVED"
                event_type = {
                    "STOP_EXIT_IOC": "STOP_TRIGGERED",
                    "TARGET_EXIT_IOC": "TARGET_TRIGGERED",
                    "TIMEOUT_EXIT_IOC": "TIMEOUT_TRIGGERED",
                }[command.command_kind]
            else:
                event_type, to_state = "UNRESOLVED", "UNRESOLVED"
        return SimulationTradeEventV2(
            source=self._source,
            session_id=self._required(trade.session_id, "trade session_id"),
            admission_id=self._required(trade.admission_id, "trade admission_id"),
            intent_id=self._required(trade.intent_id, "trade intent_id"),
            trade_id=self._required(trade.trade_id, "trade trade_id"),
            event_seq=journal.next_event_seq,
            previous_event_sha256=journal.journal_head_sha256,
            event_type=cast(Any, event_type),
            from_state=journal.state,
            to_state=cast(Any, to_state),
            occurred_at_ms=receipt.arrival_at_ms,
            symbol=self._required(trade.symbol, "trade symbol"),
            side=self._trade_side(trade).value,
            command_id=self._required(command.command_id, "command_id"),
            receipt_id=self._required(receipt.receipt_id, "receipt_id"),
            filled_quantity=receipt.filled_quantity,
            average_price=receipt.average_price,
            model_frame_sha256=receipt.model_frame_sha256,
            reason_codes=("SIM_IOC", *receipt.reason_codes),
        )

    async def _mark_unresolved(
        self,
        trade: SimulationTradeV1,
        journal: SimulationTradeJournal,
        *,
        occurred_at_ms: int,
        reason: str,
    ) -> None:
        if journal.state != "ACTIVE":
            return
        event = SimulationTradeEventV2(
            source=self._source,
            session_id=self._required(trade.session_id, "trade session_id"),
            admission_id=self._required(trade.admission_id, "trade admission_id"),
            intent_id=self._required(trade.intent_id, "trade intent_id"),
            trade_id=self._required(trade.trade_id, "trade trade_id"),
            event_seq=journal.next_event_seq,
            previous_event_sha256=journal.journal_head_sha256,
            event_type="UNRESOLVED",
            from_state="ACTIVE",
            to_state="UNRESOLVED",
            occurred_at_ms=occurred_at_ms,
            symbol=self._required(trade.symbol, "trade symbol"),
            side=self._trade_side(trade).value,
            reason_codes=(reason,),
        )
        await self._repository.append_trade_event(event)
        await self._ensure_terminal_result(trade)

    async def _ensure_terminal_result(self, trade: SimulationTradeV1) -> SimulationResultV1 | None:
        journal = await self._journal(trade)
        if journal.state not in _TERMINAL_STATES:
            return None
        if not journal.events:
            raise SimulationControllerIntegrityError("terminal simulation trade has no lifecycle events")
        terminal = journal.events[-1]
        terminal_event_id = self._required(terminal.event_id, "terminal event_id")
        session_id = self._required(trade.session_id, "trade session_id")
        admission_id = self._required(trade.admission_id, "trade admission_id")
        intent_id = self._required(trade.intent_id, "trade intent_id")
        trade_id = self._required(trade.trade_id, "trade trade_id")
        if journal.state in {"NO_FILL", "BLOCKED"}:
            result = SimulationResultV1(
                source=self._source,
                session_id=session_id,
                admission_id=admission_id,
                intent_id=intent_id,
                trade_id=trade_id,
                terminal_event_id=terminal_event_id,
                completed_at_ms=terminal.occurred_at_ms,
                final_state=journal.state,
                entry_filled_quantity=0.0,
                exit_filled_quantity=0.0,
                reason_codes=terminal.reason_codes,
            )
        else:
            entry_quantity, entry_notional, entry_fees = await self._fill_totals(
                journal, {"ENTRY_FILLED", "ENTRY_PARTIAL"}
            )
            exit_quantity, exit_notional, exit_fees = await self._fill_totals(
                journal, {"STOP_TRIGGERED", "TARGET_TRIGGERED", "TIMEOUT_TRIGGERED"}
            )
            if entry_quantity <= 0:
                raise SimulationControllerIntegrityError(
                    "terminal simulation trade has no entry fill evidence"
                )
            if journal.state == "FLAT" and exit_quantity != entry_quantity:
                raise SimulationControllerIntegrityError(
                    "flat simulation trade does not have matched fill quantities"
                )
            if journal.state == "UNRESOLVED" and not 0 <= exit_quantity < entry_quantity:
                raise SimulationControllerIntegrityError(
                    "unresolved simulation trade does not retain positive remaining exposure"
                )
            side = self._trade_side(trade)
            entry_average = entry_notional / entry_quantity
            exit_average = None if exit_quantity == 0 else exit_notional / exit_quantity
            entry_matched_notional = entry_average * exit_quantity
            gross_pnl = (
                exit_notional - entry_matched_notional
                if side is Side.LONG
                else entry_matched_notional - exit_notional
            )
            result = SimulationResultV1(
                source=self._source,
                session_id=session_id,
                admission_id=admission_id,
                intent_id=intent_id,
                trade_id=trade_id,
                terminal_event_id=terminal_event_id,
                completed_at_ms=terminal.occurred_at_ms,
                final_state=journal.state,
                entry_filled_quantity=float(entry_quantity),
                exit_filled_quantity=float(exit_quantity),
                entry_average_price=float(entry_average),
                exit_average_price=None if exit_average is None else float(exit_average),
                model_realized_pnl_quote=float(gross_pnl),
                model_fee_quote=float(entry_fees + exit_fees),
                reason_codes=terminal.reason_codes,
            )
        await self._repository.record_result(result)
        return result

    async def _fill_totals(
        self,
        journal: SimulationTradeJournal,
        event_types: set[str],
    ) -> tuple[Decimal, Decimal, Decimal]:
        quantity = Decimal("0")
        notional = Decimal("0")
        fees = Decimal("0")
        for event in journal.events:
            if event.event_type not in event_types:
                continue
            if event.command_id is None:
                raise SimulationControllerIntegrityError("simulation fill event is missing command lineage")
            receipt = await self._repository.load_command_receipt(event.command_id)
            if receipt is None or receipt.receipt_id != event.receipt_id:
                raise SimulationControllerIntegrityError(
                    "simulation fill event is missing its durable receipt"
                )
            filled = decimal_from_contract(receipt.filled_quantity, field="receipt_filled_quantity")
            if receipt.average_price is None:
                raise SimulationControllerIntegrityError(
                    "simulation fill receipt is missing its average price"
                )
            price = decimal_from_contract(receipt.average_price, field="receipt_average_price")
            quantity += filled
            notional += filled * price
            fees += decimal_from_contract(receipt.fee_quote, field="receipt_fee_quote")
        return quantity, notional, fees

    def _entry_command(self, trade: SimulationTradeV1) -> SimulationCommandV1:
        admission = self._admission_from_trade(trade)
        intent = self._intent_from_admission(admission)
        eligible_at_ms = max(intent.entry_eligible_ts_ms, trade.created_at_ms)
        return SimulationCommandV1(
            source=self._source,
            trade=trade,
            command_kind="ENTRY_IOC",
            quantity=self._required(admission.quantity, "admission quantity"),
            price_cap=self._required(admission.price_cap, "admission price_cap"),
            submitted_at_ms=trade.created_at_ms,
            persisted_at_ms=trade.created_at_ms,
            eligible_at_ms=eligible_at_ms,
            expires_at_ms=intent.entry_expires_ts_ms,
        )

    def _exit_command(
        self,
        trade: SimulationTradeV1,
        *,
        command_kind: _CommandKind,
        quantity: Decimal,
        price_cap: Decimal,
        trigger_at_ms: int,
    ) -> SimulationCommandV1:
        session = self._session_from_trade(trade)
        expires_at_ms = min(trigger_at_ms + session.assumptions.maximum_book_age_ms, session.ends_at_ms)
        return SimulationCommandV1(
            source=self._source,
            trade=trade,
            command_kind=command_kind,
            quantity=float(quantity),
            price_cap=float(price_cap),
            submitted_at_ms=trigger_at_ms,
            persisted_at_ms=trigger_at_ms,
            eligible_at_ms=trigger_at_ms,
            expires_at_ms=expires_at_ms,
        )

    def _adverse_exit_cap(self, price: Decimal, *, side: Side, trade: SimulationTradeV1) -> Decimal:
        tick = decimal_from_contract(
            self._session_from_trade(trade).assumptions.price_tick,
            field="simulation_price_tick",
        )
        rounded = (price / tick).to_integral_value(
            rounding=ROUND_FLOOR if side is Side.LONG else ROUND_CEILING
        ) * tick
        if rounded <= 0:
            raise SimulationControllerIntegrityError("adverse simulator exit price cap is not positive")
        return rounded

    async def _journal(self, trade: SimulationTradeV1) -> SimulationTradeJournal:
        journal = await self._repository.load_trade_journal(self._required(trade.trade_id, "trade trade_id"))
        if journal is None or journal.trade != trade:
            raise SimulationControllerIntegrityError(
                "simulation trade journal is missing or has mixed lineage"
            )
        return journal

    @staticmethod
    def _first_entry_event(journal: SimulationTradeJournal) -> SimulationTradeEventV2:
        entries = [event for event in journal.events if event.event_type in {"ENTRY_FILLED", "ENTRY_PARTIAL"}]
        if len(entries) != 1:
            raise SimulationControllerIntegrityError(
                "active simulation trade must have exactly one entry fill"
            )
        return entries[0]

    @classmethod
    def _entry_filled_quantity(cls, journal: SimulationTradeJournal) -> Decimal:
        return sum(
            (
                decimal_from_contract(event.filled_quantity, field="entry_event_filled_quantity")
                for event in journal.events
                if event.event_type in {"ENTRY_FILLED", "ENTRY_PARTIAL"}
            ),
            Decimal("0"),
        )

    @classmethod
    def _exit_filled_quantity(cls, journal: SimulationTradeJournal) -> Decimal:
        return sum(
            (
                decimal_from_contract(event.filled_quantity, field="exit_event_filled_quantity")
                for event in journal.events
                if event.event_type in {"STOP_TRIGGERED", "TARGET_TRIGGERED", "TIMEOUT_TRIGGERED"}
            ),
            Decimal("0"),
        )

    @classmethod
    def _remaining_quantity(cls, journal: SimulationTradeJournal) -> Decimal:
        return cls._entry_filled_quantity(journal) - cls._exit_filled_quantity(journal)

    @staticmethod
    def _session_from_admission(admission: SimulationAdmissionV2):
        if admission.session is None:
            raise SimulationControllerIntegrityError("simulation admission is missing its immutable session")
        return admission.session

    @staticmethod
    def _intent_from_admission(admission: SimulationAdmissionV2):
        if admission.intent is None:
            raise SimulationControllerIntegrityError("simulation admission is missing its immutable intent")
        return admission.intent

    @classmethod
    def _admission_from_trade(cls, trade: SimulationTradeV1) -> SimulationAdmissionV2:
        if not isinstance(trade.admission, SimulationAdmissionV2):
            raise SimulationControllerIntegrityError("durable simulator controller requires admission.v2")
        return trade.admission

    @classmethod
    def _session_from_trade(cls, trade: SimulationTradeV1):
        return cls._session_from_admission(cls._admission_from_trade(trade))

    @classmethod
    def _intent_from_trade(cls, trade: SimulationTradeV1):
        return cls._intent_from_admission(cls._admission_from_trade(trade))

    @staticmethod
    def _trade_side(trade: SimulationTradeV1) -> Side:
        if trade.side not in {Side.LONG, Side.SHORT}:
            raise SimulationControllerIntegrityError("simulation trade must be directional")
        return trade.side

    @staticmethod
    def _required(value: str | float | None, name: str):
        if value is None:
            raise SimulationControllerIntegrityError(f"simulation {name} is missing")
        return value

    @staticmethod
    def _validate_timestamp(name: str, value: int) -> None:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"{name} must be a non-negative integer Unix timestamp in milliseconds")

    @staticmethod
    def _validate_sha256(name: str, value: str) -> None:
        if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
            raise ValueError(f"{name} must be a lowercase SHA-256 hex string")
