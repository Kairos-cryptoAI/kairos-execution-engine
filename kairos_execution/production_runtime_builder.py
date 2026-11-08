"""Construct an explicitly provisioned runtime with one shared precise clock.

Construction performs no database, custody or venue I/O and grants no trading
authority. This is a wiring helper, not a deployment composition or proof that
the supplied resources, account, exchange or signing domain are qualified.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

import asyncpg  # type: ignore[import-untyped]

from .managed_signer import CustodyBindingV1, ManagedCustodyBackend, ManagedSignerBoundary, SignatureVerifier
from .production_claims import PostgresProductionClaims
from .production_dispatch import ProductionEffectDispatcher, ProductionSignatureVerifier
from .production_readiness import OwnerArmKeyV1, PreconditionsV1, ProductionContextV1, canonical_digest
from .production_runtime import ProductionExecutionRuntime
from .production_state import ACCOUNTING_STATE_SCHEMA_VERSION, AsyncPostgresProductionSigningStateSource
from .production_transport import ProductionEvedexSdkClient, ProductionEvedexTransport
from .signing_authorization import ProductionSigningAuthorizationVerifier
from .utc_clock import precise_utc_now


def build_clocked_production_runtime(
    *,
    pool: asyncpg.Pool,
    expected_database: str,
    database_uuid: UUID,
    policy_namespace: str,
    runtime_role: str,
    context: ProductionContextV1,
    custody_binding: CustodyBindingV1,
    preconditions: PreconditionsV1,
    owner_key: OwnerArmKeyV1,
    expected_owner_key_sha256: str,
    expected_owner_identity: str,
    maximum_arm_lifetime: timedelta,
    custody_backend: ManagedCustodyBackend,
    custody_signature_verifier: SignatureVerifier,
    wire_signature_verifier: ProductionSignatureVerifier,
    transport: ProductionEvedexTransport,
    clock: Callable[[], datetime] = precise_utc_now,
) -> ProductionExecutionRuntime:
    """Build the exact signer/claims/authorization/dispatch graph without I/O.

    All account-scoped evidence, independent verifiers and an owner arm remain
    separately required. A caller must also provide the other independent
    resources required by ``build_production_host``; this helper neither starts
    that host nor changes its readiness or strategy policy.
    """
    if not callable(clock) or not bool(clock):
        raise ValueError("one explicit callable UTC clock is required")
    if (
        type(transport) is not ProductionEvedexTransport
        or type(transport.client) is not ProductionEvedexSdkClient
    ):
        raise TypeError("the exact provisioned EVEDEX transport and SDK client are required")
    context = ProductionContextV1.model_validate(context)
    custody_binding = CustodyBindingV1.model_validate(custody_binding)
    preconditions = PreconditionsV1.model_validate(preconditions)
    owner_key = OwnerArmKeyV1.model_validate(owner_key)
    if (
        context.environment != "PROD"
        or context.exchange != "EVEDEX"
        or custody_binding.context != context
        or transport.context != context
        or transport.custody_binding != custody_binding
        or preconditions.context != context
        or owner_key.context != context
        or owner_key.owner_identity != expected_owner_identity
        or canonical_digest(owner_key) != expected_owner_key_sha256
    ):
        raise ValueError("runtime custody, transport, owner or preconditions scope differs")

    state_source = AsyncPostgresProductionSigningStateSource(
        pool,
        expected_database=expected_database,
        database_uuid=database_uuid,
        policy_namespace=policy_namespace,
        runtime_role=runtime_role,
        context=context,
        state_schema_version=ACCOUNTING_STATE_SCHEMA_VERSION,
        clock_probe=clock,
    )
    claims = PostgresProductionClaims(
        pool,
        expected_database=expected_database,
        database_uuid=database_uuid,
        policy_namespace=policy_namespace,
        runtime_role=runtime_role,
        context=context,
    )
    authorization = ProductionSigningAuthorizationVerifier(
        source=state_source,
        preconditions=preconditions,
        owner_key=owner_key,
        expected_owner_key_sha256=expected_owner_key_sha256,
        expected_owner_identity=expected_owner_identity,
        expected_claim_database_uuid=database_uuid,
        maximum_arm_lifetime=maximum_arm_lifetime,
        clock_probe=clock,
    )
    # ManagedSignerBoundary accepts the production async claim API at runtime;
    # its constructor annotation currently names only the synchronous protocol.
    claims_for_signer: Any = claims
    signer = ManagedSignerBoundary(
        custody_binding,
        backend=custody_backend,
        verifier=custody_signature_verifier,
        claims=claims_for_signer,
        authorization=authorization,
    )
    dispatcher = ProductionEffectDispatcher(
        authorization=authorization,
        signature_verifier=wire_signature_verifier,
        claims=claims,
        database_uuid=database_uuid,
        context=context,
        clock=clock,
        sender=transport.send_signed_post,
    )
    return ProductionExecutionRuntime(
        signer=signer,
        authorization=authorization,
        claims=claims,
        state_source=state_source,
        dispatcher=dispatcher,
        database_uuid=database_uuid,
        context=context,
        clock=clock,
    )
