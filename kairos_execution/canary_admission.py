"""Independent, entry-only expected scope for bounded DEV sessions."""

from __future__ import annotations

from contextlib import AbstractAsyncContextManager
from typing import Protocol

from kairos_core.contracts import RiskTradeDecisionV1
from kairos_persistence.canary_session import CanaryEntryBinding, CanaryScope

from .config import ExecSettings


class CanaryAdmissionRepository(Protocol):
    async def bind_entry(
        self, *, decision: RiskTradeDecisionV1, expected_scope: CanaryScope, effect_id: str
    ) -> CanaryEntryBinding: ...

    def final_dispatch(
        self,
        *,
        decision: RiskTradeDecisionV1,
        expected_scope: CanaryScope,
        effect_id: str,
        max_hold_s: float = 30.0,
    ) -> AbstractAsyncContextManager[CanaryEntryBinding]: ...


def load_expected_scope(settings: ExecSettings, injected: CanaryScope | None = None) -> CanaryScope:
    """Read an operator-provided non-secret JSON snapshot, never the session's own scope.

    This function is pure apart from reading that explicit local file. Callers
    keep a missing/invalid scope as entry-only refusal, not a recovery failure.
    """
    if injected is None:
        path = getattr(settings, "canary_scope_file", None)
        if path is None or not path.is_absolute():
            raise ValueError("an absolute independent canary scope file is required for new entries")
        scope = CanaryScope.model_validate_json(path.read_text(encoding="utf-8"))
    else:
        scope = CanaryScope.model_validate(injected.model_dump(mode="json"))
    if (
        scope.environment != settings.environment
        or scope.account_id != settings.account_id
        or scope.remote_account_id != settings.evedex_dev_expected_account_id
        or scope.exchange_url != settings.evedex_exchange_url
        or scope.auth_url != settings.evedex_auth_url
        or scope.chain_id != settings.evedex_chain_id
    ):
        raise ValueError("canary scope does not match the independently configured DEV runtime")
    return scope
