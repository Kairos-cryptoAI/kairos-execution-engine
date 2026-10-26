"""Opt-in EVEDEX lifecycle transport through the existing managed PROD boundary.

No factory uses this adapter. Plans are create-only coordination records, never
Risk approval. The independently persisted owner/operator/Risk/exposure records
are revalidated by the managed runtime before every signature and wire call.
Only the read methods of the existing SDK adapter are delegated; its wallet
mutation methods are deliberately unreachable from this composition.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

from kairos_core.contracts import RiskTradeDecisionV1
from kairos_core.enums import OrderSide
from kairos_persistence import EffectStatus, EffectType

from .adapters.evedex_sidecar import EvedexSidecarAdapter
from .production_lifecycle_binding import (
    ProductionLifecycleBindingV1,
    build_production_lifecycle_binding,
    compare_entry_risk_to_decision,
)
from .production_readiness import canonical_digest
from .production_reads import ProductionEvedexReads
from .production_runtime import ProductionExecutionRuntime
from .production_transport import ProductionEvedexTransport


class ProductionLifecycleRefused(PermissionError):
    """A lifecycle-to-signing association cannot be proved; never retry blindly."""


class ManagedProductionLifecycleAdapter:
    """Reuse native SDK read DTOs and the exact managed signing/wire runtime.

    ``bindings`` is a PostgresLifecycleBindingStore populated by the independent
    decision/Risk publisher, not by this runtime. Missing plans or current Risk
    records fail closed. A transport ACK is returned to the native FSM for its
    normal fill/protection/exit verification, not promoted to reconciliation.
    """

    name = "evedex"
    exchange_order_id_matches_client_order_id = True
    protective_stop_lookup_authoritative = True

    def __init__(self, *, runtime, reads, bindings, trades, effects, cancellations, clock=None):
        from .production_cancellation import ProductionCancellationVerifier
        from .production_lifecycle_store import PostgresLifecycleBindingStore

        if not isinstance(runtime, ProductionExecutionRuntime):
            raise TypeError("an exact managed production runtime is required")
        if not isinstance(reads, EvedexSidecarAdapter) and type(reads) is not ProductionEvedexReads:
            raise TypeError("the reviewed EVEDEX SDK read adapter is required")
        if type(reads) is ProductionEvedexReads:
            transport = getattr(getattr(runtime.dispatcher, "sender", None), "__self__", None)
            if (
                type(transport) is not ProductionEvedexTransport
                or transport.client is not reads.client
                or transport.context != runtime.context
                or transport.custody_binding != runtime.binding
                or reads.expected_account_id != runtime.context.remote_account_id
            ):
                raise ValueError("PROD reads and writes must share the exact transport client/account")
        if not isinstance(bindings, PostgresLifecycleBindingStore):
            raise TypeError("the durable create-only lifecycle binding store is required")
        if not isinstance(cancellations, ProductionCancellationVerifier):
            raise TypeError("the exact owned-effect cancellation verifier is required")
        if bindings.context != runtime.context:
            raise ValueError("lifecycle plan store differs from managed runtime context")
        if getattr(cancellations, "context", None) != runtime.context:
            raise ValueError("cancellation boundary differs from managed runtime context")
        if getattr(cancellations, "claims", None) is not runtime.claims:
            raise ValueError("cancellation and signing must share the exact durable claim store")
        if (
            cancellations.trades is not trades
            or cancellations.effects is not effects
            or cancellations.bindings is not bindings
            or cancellations.state_source is not runtime.state_source
            or cancellations.custody_binding != runtime.binding
        ):
            raise ValueError("cancellation and lifecycle must share the exact durable lineage stores")
        self.runtime = runtime
        self.context = runtime.context
        self.reads = reads
        # A REST projection cannot inherit the old adapter's authoritative
        # protection-parent flag. Unsupported source facts remain unavailable.
        self.protective_stop_lookup_authoritative = reads.protective_stop_lookup_authoritative
        self.bindings = bindings
        self.trades = trades
        self.effects = effects
        self.cancellations = cancellations
        self.clock = clock or (lambda: datetime.now(UTC))
        self.environment = f"PROD:{canonical_digest(self.context)}:LIVE"
        self.namespace = f"prod.v1:{canonical_digest(self.context)}"

    async def preflight(self) -> dict[str, Any]:
        health = await self.reads.preflight()
        # Do not reuse a DEV reader even when logical symbol names overlap.
        if health.get("profile") != "PROD" or health.get("chain_id") != self.runtime.binding.chain_id:
            raise ProductionLifecycleRefused("SDK reader differs from exact PROD custody scope")
        return health

    async def fetch_paper_state(self) -> dict[str, Any]:
        # The inherited method name is historical. No PAPER wallet is called.
        # Account projections are NOT terminal reservation-release authority.
        before = self.clock()
        value = await self.reads.fetch_paper_state()
        after = self.clock()
        if before.tzinfo is None or after < before or (after - before).total_seconds() > 5:
            raise ProductionLifecycleRefused("account projection read exceeded its bounded window")
        account = value.get("account", {})
        if not isinstance(account, dict) or str(account.get("exchangeId")) != self.context.remote_account_id:
            raise ProductionLifecycleRefused("SDK account differs from exact PROD remote account")
        return value

    async def fetch_depth(self, *, symbol: str, max_level: int = 100) -> dict[str, Any]:
        return await self.reads.fetch_depth(symbol=symbol, max_level=max_level)

    async def drain_events(self, *, limit: int = 1000) -> list[dict[str, Any]]:
        return await self.reads.drain_events(limit=limit)

    async def find_tpsl_record(self, **kwargs):
        return await self.reads.find_tpsl_record(**kwargs)

    async def _binding(self, decision, effect_id, *, role, client_id, parent=None, quantity=None):
        candidate = await self.bindings.get(effect_id)
        if candidate is None:
            raise ProductionLifecycleRefused("independent persisted lifecycle signing plan is absent")
        candidate = ProductionLifecycleBindingV1.model_validate(candidate)
        rebuilt = build_production_lifecycle_binding(
            decision=decision,
            context=self.context,
            custody_binding=self.runtime.binding,
            role=role,
            lifecycle_effect_id=effect_id,
            client_order_id=client_id,
            manual_request_sha256=candidate.request.manual_request_sha256,
            expires_at=candidate.request.expires_at,
            now=self.clock(),
            parent_order_id=parent,
            close_quantity=quantity,
            risk_decision_id=candidate.risk_decision_id,
        )
        if candidate != rebuilt:
            raise ProductionLifecycleRefused("persisted signing plan differs from exact durable lifecycle")
        return candidate

    async def inspect_entry(self, decision: RiskTradeDecisionV1, effect_id: str):
        from .state_machine import client_order_id

        decision = RiskTradeDecisionV1.model_validate(decision.to_payload())
        expected_effect = hashlib.sha256(
            f"{self.namespace}:{decision.trade_id}:ENTRY:place".encode()
        ).hexdigest()
        if effect_id != expected_effect:
            raise ProductionLifecycleRefused("entry effect differs from the PROD lifecycle namespace")
        client_id = client_order_id(
            f"{decision.trade_id}:ENTRY",
            "evedex",
            occurred_at=datetime.fromtimestamp(decision.decided_at_ms / 1000, tz=UTC),
        )
        plan = await self._binding(decision, effect_id, role="ENTRY", client_id=client_id)
        evidence = await self.runtime.authorization.inspect_request_async(plan.request, self.runtime.binding)
        compare_entry_risk_to_decision(decision=decision, lifecycle=plan, evidence=evidence)
        return plan

    async def _prepared(self, effect_id, *, types, symbol):
        effect = await self.effects.get(effect_id)
        if effect is None or effect.status is not EffectStatus.PREPARED or effect.effect_type not in types:
            raise ProductionLifecycleRefused("exact PREPARED lifecycle effect is absent")
        trade = await self.trades.get(effect.trade_id)
        if (
            trade is None
            or trade.trading_mode != "LIVE"
            or trade.profile != "PROD"
            or trade.environment != self.environment
            or effect.environment != self.environment
            or trade.account_id != self.context.remote_account_id
            or effect.account_id != trade.account_id
            or effect.exchange != self.name
            or trade.exchange != self.name
            or effect.symbol != symbol
            or trade.symbol != symbol
            or effect.trade_id != trade.trade_id
            or not await self.effects.verify_chain(effect_id)
            or not await self.trades.verify_chain(trade.trade_id)
        ):
            raise ProductionLifecycleRefused("durable PROD trade/effect lineage is invalid")
        decision = RiskTradeDecisionV1.model_validate(trade.risk_decision_payload)
        if decision.trade_id != trade.trade_id or decision.decision_id != trade.risk_decision_id:
            raise ProductionLifecycleRefused("trade does not contain the original canonical Risk decision")
        return effect, trade, decision

    async def _send(self, plan):
        outcome = await self.runtime.dispatch_one_response(plan.request)
        if (
            outcome.receipt.effect_id != plan.signing_effect_id
            or outcome.receipt.decision_id != plan.risk_decision_id
        ):
            raise ProductionLifecycleRefused("managed dispatch receipt differs from persisted signing plan")
        return outcome.response

    async def place_limit(
        self, *, effect_id, client_order_id, symbol, side, quantity, limit_price, leverage, post_only=False
    ):
        effect, trade, decision = await self._prepared(
            effect_id, types={EffectType.PLACE_ORDER}, symbol=symbol
        )
        if (
            post_only is not False
            or leverage != 1
            or effect.order_role != "ENTRY"
            or effect.client_order_id != client_order_id
            or trade.entry_client_order_id != client_order_id
            or quantity != decision.quantity
            or limit_price != decision.worst_entry_price
            or side != OrderSide(trade.side)
        ):
            raise ProductionLifecycleRefused("entry call changed the immutable Risk geometry")
        plan = await self.inspect_entry(decision, effect_id)
        return await self._send(plan)

    async def create_tpsl(self, *, effect_id, symbol, side, tpsl_type, quantity, price, parent_order_id):
        effect, trade, decision = await self._prepared(
            effect_id, types={EffectType.PROTECTIVE_STOP, EffectType.TAKE_PROFIT}, symbol=symbol
        )
        role = "STOP_LOSS" if effect.effect_type is EffectType.PROTECTIVE_STOP else "TAKE_PROFIT"
        expected_price = (
            decision.exit_plan.stop_price if role == "STOP_LOSS" else decision.exit_plan.target_price
        )
        if (
            tpsl_type != role
            or effect.order_role != role
            or quantity != 0
            or price != expected_price
            or side != OrderSide(trade.side)
            or parent_order_id != trade.entry_client_order_id
        ):
            raise ProductionLifecycleRefused("protection call changed the original exit plan/parent")
        plan = await self._binding(
            decision, effect_id, role=role, client_id=effect.client_order_id, parent=parent_order_id
        )
        return await self._send(plan)

    async def paper_close_position(self, *, effect_id, client_order_id, symbol, quantity, leverage):
        effect, trade, decision = await self._prepared(
            effect_id,
            types={EffectType.TIMEOUT_CLOSE, EffectType.EMERGENCY_CLOSE, EffectType.CLOSE_POSITION},
            symbol=symbol,
        )
        role = effect.order_role
        if (
            role not in {"TIMEOUT_EXIT", "EMERGENCY_EXIT"}
            or leverage != 1
            or effect.client_order_id != client_order_id
            or not 0 < quantity <= decision.quantity
            or float.fromhex(effect.request_payload["quantity_hex"]) != quantity
        ):
            raise ProductionLifecycleRefused("close call differs from the exact prepared reduce-only exit")
        plan = await self._binding(
            decision, effect_id, role=role, client_id=client_order_id, quantity=quantity
        )
        return await self._send(plan)

    async def paper_cancel_order(self, *, effect_id, symbol, client_order_id):
        _, trade, _ = await self._prepared(effect_id, types={EffectType.CANCEL_ORDER}, symbol=symbol)
        return await self.cancellations.cancel_entry(
            effect_id=effect_id, symbol=trade.venue_symbol, client_order_id=client_order_id
        )

    async def cancel_tpsl(self, *, effect_id, symbol, tpsl_id):
        _, trade, _ = await self._prepared(effect_id, types={EffectType.CANCEL_TPSL}, symbol=symbol)
        return await self.cancellations.cancel_tpsl(
            effect_id=effect_id, symbol=trade.venue_symbol, tpsl_id=tpsl_id
        )
