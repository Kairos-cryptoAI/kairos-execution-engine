"""Entry-only operator fence interface; protective exits never depend on ARM."""

from contextlib import AbstractAsyncContextManager
from typing import Protocol

from kairos_core.contracts import RiskTradeDecisionV1
from kairos_persistence.canary_session import CanaryScope
from kairos_persistence.operator_control import OperatorAdmissionV1


class PaperOperatorControl(Protocol):
    async def check_entry(
        self, *, decision: RiskTradeDecisionV1, expected_scope: CanaryScope, effect_id: str
    ) -> OperatorAdmissionV1: ...

    def final_dispatch_guard(
        self,
        *,
        decision: RiskTradeDecisionV1,
        expected_scope: CanaryScope,
        effect_id: str,
        max_hold_s: float = 30.0,
    ) -> AbstractAsyncContextManager[OperatorAdmissionV1]: ...
