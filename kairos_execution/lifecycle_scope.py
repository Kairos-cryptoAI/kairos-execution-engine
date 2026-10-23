"""Internal immutable execution scope and PAPER admission policy.

The public PAPER facade is intentionally specialized to the approved EVEDEX
DEV canary. The separate explicit production composer reuses the internal scope
boundary; it does not make PAPER policy caller-selectable or enable a factory.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Protocol

from kairos_core.contracts import RiskTradeDecisionV1
from kairos_core.enums import EvedexProfile, TradingMode

from .config import ExecSettings


@dataclass(frozen=True, slots=True)
class ExecutionLifecycleScope:
    """Immutable identity tuple used by durable lifecycle and public facts."""

    trading_mode: TradingMode
    profile: EvedexProfile
    environment: str
    account_id: str
    remote_environment: str
    remote_account_id: str | None
    exchange: str
    symbol_map: Mapping[str, str]
    mutation_namespace: str
    event_namespace: str


class LifecycleAdmissionPolicy(Protocol):
    """The engine's internal decision-scope admission boundary."""

    @property
    def scope(self) -> ExecutionLifecycleScope: ...

    def validate_decision_scope(self, decision: RiskTradeDecisionV1) -> None: ...


@dataclass(frozen=True, slots=True)
class PaperDevCanaryPolicy:
    """Fixed scope/admission policy for the existing PAPER DEV canary only."""

    scope: ExecutionLifecycleScope

    @classmethod
    def from_settings(cls, settings: ExecSettings) -> PaperDevCanaryPolicy:
        if settings.trading_mode is not TradingMode.PAPER:
            raise ValueError("PaperExecutionEngine requires TradingMode.PAPER")
        if getattr(settings, "evedex_profile", EvedexProfile.DEV) is not EvedexProfile.DEV:
            raise ValueError("PaperExecutionEngine requires EVEDEX DEV")
        raw_symbol_map = getattr(settings, "evedex_dev_symbol_map", {})
        if not isinstance(raw_symbol_map, dict):
            raise ValueError("PAPER DEV symbol map must be a mapping")
        scope = ExecutionLifecycleScope(
            trading_mode=TradingMode.PAPER,
            profile=EvedexProfile.DEV,
            environment=f"{getattr(settings, 'environment', '')}:EVEDEX:DEV:PAPER",
            account_id=settings.account_id,
            remote_environment="evedex-dev",
            remote_account_id=getattr(settings, "evedex_dev_expected_account_id", None),
            exchange="evedex",
            symbol_map=MappingProxyType(dict(raw_symbol_map)),
            mutation_namespace="paper.v1",
            event_namespace="paper.v1",
        )
        return cls(scope=scope)

    def validate_decision_scope(self, decision: RiskTradeDecisionV1) -> None:
        """Preserve the exact PAPER/DEV/account/symbol checks and diagnostics."""
        if decision.trading_mode is not self.scope.trading_mode:
            raise ValueError("PAPER consumer rejects non-PAPER decisions")
        if decision.evedex_profile is not self.scope.profile:
            raise ValueError("PAPER consumer rejects non-DEV decisions")
        if decision.account_id != self.scope.account_id:
            raise ValueError("risk decision targets a different PAPER account")
        expected_symbol = self.scope.symbol_map.get(decision.intent.symbol)
        if expected_symbol != decision.venue_symbol:
            raise ValueError("risk decision venue symbol is outside the DEV allowlist")
