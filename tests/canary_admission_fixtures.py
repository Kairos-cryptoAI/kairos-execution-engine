"""Explicitly layered admission for legacy lifecycle tests, NOT qualification.

The bounded session repository has separate real-clock PostgreSQL tests. Legacy
lifecycle fixtures intentionally use a frozen future clock and inject only this
admission layer, while retaining real journal/trade repositories.
"""

from contextlib import asynccontextmanager
from datetime import UTC, datetime

from kairos_persistence.canary_session import CanaryEntryBinding, CanaryScope


def expected_scope(settings):
    return CanaryScope(
        environment=settings.environment,
        account_id=settings.account_id,
        remote_account_id=settings.evedex_dev_expected_account_id,
        config_sha256="a" * 64,
        recorder_code_sha256="b" * 64,
    )


class LayeredCanaryAdmission:
    """No database evidence, no certification claims, only a test boundary."""

    async def bind_entry(self, *, decision, expected_scope, effect_id):
        assert decision.account_id == expected_scope.account_id
        return CanaryEntryBinding(
            session_id="1" * 64,
            attempt_id="2" * 64,
            effect_id=effect_id,
            risk_decision_id=decision.decision_id,
            trade_id=decision.trade_id,
            entry_deadline_at=datetime.fromtimestamp(decision.intent.entry_expires_ts_ms / 1000, UTC),
            dispatch_claimed=False,
        )

    @asynccontextmanager
    async def final_dispatch(self, *, decision, expected_scope, effect_id, max_hold_s=30):
        yield await self.bind_entry(decision=decision, expected_scope=expected_scope, effect_id=effect_id)
