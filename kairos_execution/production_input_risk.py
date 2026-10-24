"""Explicit composition for the opt-in upstream-input verifier.

This factory only constructs an evaluator. It does not register a producer,
activate a service, establish producer-key qualification, or supply account
truth. The pinned EVEDEX account verifier remains deliberately fail-closed.
"""

from __future__ import annotations

from kairos_risk.live import (  # type: ignore[import-untyped]
    LiveRiskEvaluator,
    LiveRiskLimitsV1,
    LiveRiskScopeV1,
)

from .production_inputs import LiveInputProducerTrustV1, LiveInputsSourceVerifier
from .production_risk import PinnedEvedexLiveAccountVerifier


def build_opt_in_production_live_risk_evaluator(
    *,
    scope: LiveRiskScopeV1,
    limits: LiveRiskLimitsV1,
    producer_trust: LiveInputProducerTrustV1,
    producer_public_key: bytes,
) -> LiveRiskEvaluator:
    """Construct the concrete verifier composition from explicit trusted inputs.

    The trust and public key must be provisioned independently by deployment;
    this helper has no defaults and does not claim either is qualified. The
    existing EVEDEX account verifier is installed under its exact fixed source
    ID and currently refuses to produce verified account economics.
    """

    checked_scope = LiveRiskScopeV1.model_validate(scope.model_dump(mode="json"))
    checked_limits = LiveRiskLimitsV1.model_validate(limits.model_dump(mode="json"))
    checked_trust = LiveInputProducerTrustV1.model_validate(producer_trust.model_dump(mode="python"))
    if (
        checked_trust.source_set_sha256 != checked_scope.source_set_sha256
        or checked_trust.policy_sha256 != checked_scope.policy_sha256
    ):
        raise ValueError("producer trust policy does not match the exact LIVE Risk scope")
    input_verifier = LiveInputsSourceVerifier(trust=checked_trust, public_key=producer_public_key)
    account_verifier = PinnedEvedexLiveAccountVerifier()
    return LiveRiskEvaluator(
        checked_scope,
        checked_limits,
        account_verifiers={account_verifier.source_id: account_verifier},
        input_verifier=input_verifier,
    )


__all__ = ["build_opt_in_production_live_risk_evaluator"]
