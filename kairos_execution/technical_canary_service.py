"""Explicit one-admission manual canary using the existing production driver.

No default CLI path, key loading, source qualification, schema provisioning or
real-money activation is introduced. Calling this function is an explicit
deployment action after genuine safety proofs and owner signing exist.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

from .production_claims import PostgresProductionClaims
from .production_path import ProductionLiveLifecycleCoordinator
from .production_readiness import (
    ReceiptReferenceV1,
    SignedManualArmRequestV1,
    canonical_digest,
    validate_signed_manual_arm_async,
)
from .production_service import ProductionServiceDriver
from .signing_authorization import ProductionSigningAuthorizationVerifier
from .technical_canary_readiness import TechnicalCanaryPreconditionsVerifier


class TechnicalCanaryServiceError(PermissionError):
    """No automatic retry, adoption, nonce release or default LIVE fallback."""


async def start_technical_canary_service(
    *,
    coordinator: ProductionLiveLifecycleCoordinator,
    verifier: TechnicalCanaryPreconditionsVerifier,
    references: Sequence[ReceiptReferenceV1],
    owner_arm: SignedManualArmRequestV1,
) -> ProductionServiceDriver:
    """Reverify safety, consume the shared durable nonce, then recover/start.

    At most one candidate admission belongs to this manually signed session;
    even NO_ENTRY consumes it. Restart cannot renew the original nonce. Entry
    expiry never stops protection/reconciliation maintenance or claims a flat
    account. The driver may remain recovery-blocked and never claims readiness.
    """
    if type(coordinator) is not ProductionLiveLifecycleCoordinator:
        raise TypeError("the exact reviewed production coordinator is required")
    if type(verifier) is not TechnicalCanaryPreconditionsVerifier:
        raise TypeError("the exact technical-canary safety verifier is required")
    runtime = coordinator.runtime
    authorization = runtime.authorization
    claims = runtime.claims
    if (
        type(authorization) is not ProductionSigningAuthorizationVerifier
        or type(claims) is not PostgresProductionClaims
        or claims.database_uuid != runtime.database_uuid
        or authorization._claim_database_uuid != runtime.database_uuid
        or claims.context_sha256 != canonical_digest(runtime.context)
        or coordinator.engine.clock is not runtime._clock
        or authorization._clock is not runtime._clock
    ):
        raise TechnicalCanaryServiceError("canary custody, clock, claims or authorization scope differs")
    clock = runtime._clock
    now = clock()
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() != timedelta(0):
        raise TechnicalCanaryServiceError("canary clock must be explicit UTC")
    preconditions = authorization._preconditions
    # Recheck the exact original verification, without renewing its timestamp.
    # Actual current validity is checked separately before durable nonce use.
    verified = verifier.verify(runtime.context, references, now=preconditions.verified_at)
    if (
        canonical_digest(verified.preconditions) != canonical_digest(preconditions)
        or not preconditions.verified_at <= now < preconditions.valid_until
    ):
        raise TechnicalCanaryServiceError("canary safety proofs differ or expired; no nonce consumed")
    owner_arm = SignedManualArmRequestV1.model_validate_json(owner_arm.model_dump_json())
    try:
        async with asyncio.timeout(5):
            await validate_signed_manual_arm_async(
                owner_arm,
                preconditions,
                owner_key=authorization._owner_key,
                expected_owner_key_sha256=authorization._owner_key_sha256,
                expected_owner_identity=authorization._owner,
                nonce_store=claims,
                now=now,
                maximum_lifetime=min(authorization._arm_lifetime, timedelta(seconds=600)),
            )
    except Exception:
        raise TechnicalCanaryServiceError(
            "manual canary arm/nonce refused or unknown; do not retry"
        ) from None
    previous = now
    deadline = min(owner_arm.request.expires_at, preconditions.valid_until)

    def admitted() -> bool:
        nonlocal previous
        observed = clock()
        if (
            not isinstance(observed, datetime)
            or observed.tzinfo is None
            or observed.utcoffset() != UTC.utcoffset(observed)
            or observed < previous
        ):
            raise TechnicalCanaryServiceError("canary admission clock is invalid or backwards")
        previous = observed
        return observed < deadline

    if not admitted():
        raise TechnicalCanaryServiceError("canary expired during nonce commit; nonce is not released")

    driver = ProductionServiceDriver(
        coordinator,
        entry_admission=admitted,
        queue_capacity=1,
        maximum_admissions=1,
        bound_owner_arm_sha256=canonical_digest(owner_arm),
    )
    # No replacement is returned for an unknown/cancelled startup. The nonce
    # remains in the same isolated durable claims store; it is never released.
    await driver.start()
    return driver
