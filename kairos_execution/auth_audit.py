"""Safe immutable auth milestones and one explicitly audited follow-up.

Only stage names, HTTP integers and whitelisted public error codes are encoded
in the existing claims ledger. No remote message, nonce, signature or token is
accepted by this interface. The prior UNKNOWN attempt is never changed.
"""

from __future__ import annotations

import hashlib
import json
import re

from .local_custody import LocalCustodyError
from .production_claims import PostgresProductionClaims
from .production_readiness import ProductionContextV1, canonical_digest

STAGES = frozenset(
    {
        "SESSION_ATTEMPT_CLAIMED",
        "NONCE_CLAIMED",
        "SIGN_STARTED",
        "SIGNATURE_RECOVERED",
        "AUTH_POST_STARTED",
        "AUTH_HTTP",
        "AUTH_ERROR_CODE",
        "AUTH_SCHEMA_VALID",
        "BEARER_GET_STARTED",
        "BEARER_HTTP",
        "BEARER_IDENTITY_VALID",
        "WS_CAPTURE_STARTED",
        "WS_CAPTURED",
        "AUTH_UNKNOWN",
    }
)
ERROR_CODES = {
    "twofa_code_required_error": "TWOFA_REQUIRED",
    "twofa_code_not_registered_error": "TWOFA_NOT_REGISTERED",
    "twofa_code_invalid_error": "TWOFA_INVALID",
    "unauthorized_error": "UNAUTHORIZED",
    "forbidden_error": "FORBIDDEN",
    "forbidden_region_error": "FORBIDDEN_REGION",
    "aes_crypt_failed_error": "SERVER_CRYPTO_FAILURE",
}


def public_auth_error_code(value: object) -> str:
    return ERROR_CODES.get(value, "OTHER") if isinstance(value, str) else "OTHER"


class AuthAuditJournal:
    def __init__(self, claims: PostgresProductionClaims):
        if type(claims) is not PostgresProductionClaims:
            raise TypeError("exact durable auth claims adapter required")
        self.claims = claims

    async def record(self, stage: str, *, http_status: int | None = None, code: str | None = None):
        if stage not in STAGES:
            raise LocalCustodyError("unsupported authentication audit stage")
        if http_status is not None and (type(http_status) is not int or not 100 <= http_status <= 599):
            raise LocalCustodyError("invalid authentication HTTP status")
        if code is not None and code not in {*ERROR_CODES.values(), "OTHER"}:
            raise LocalCustodyError("unsupported authentication public error code")
        identity = stage
        if http_status is not None:
            identity += ":" + str(http_status)
        if code is not None:
            identity += ":" + code
        body = {
            "context_sha256": self.claims.context_sha256,
            "stage": stage,
            "http_status": http_status,
            "code": code,
        }
        digest = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
        result = await self.claims.claim(
            "MANUAL_NONCE", "auth-stage:" + self.claims.context_sha256, identity, digest
        )
        if result is not True:
            raise LocalCustodyError("authentication stage already recorded or unavailable")


async def authorize_one_auth_followup(
    *,
    claims: PostgresProductionClaims,
    prior_context: ProductionContextV1,
    current_context: ProductionContextV1,
    prior_plan_sha256: str,
    followup_plan_sha256: str,
    expected_wallet_address: str,
    operator_reference: str,
) -> None:
    """One new auth attempt per claims DB, linked to a retained prior UNKNOWN.

    This is not a retry mechanism for orders. It records a new explicit local
    operator action; old claim rows remain immutable. It must precede nonce,
    signing and auth POST. A failed or lost guard result cannot be retried.
    """
    if (
        type(claims) is not PostgresProductionClaims
        or type(prior_context) is not ProductionContextV1
        or type(current_context) is not ProductionContextV1
        or claims.context_sha256 != canonical_digest(current_context)
        or current_context.remote_account_id != prior_context.remote_account_id
    ):
        raise LocalCustodyError("explicit auth follow-up scope required")
    for value in (prior_plan_sha256, followup_plan_sha256):
        if not isinstance(value, str) or re.fullmatch(r"[a-f0-9]{64}", value) is None:
            raise LocalCustodyError("reviewed auth plan digest required")
    if (
        not isinstance(operator_reference, str)
        or re.fullmatch(r"[A-Za-z0-9_.:-]{1,120}", operator_reference) is None
    ):
        raise LocalCustodyError("bounded operator reference required")
    old = PostgresProductionClaims(
        claims.pool,
        expected_database=claims.expected_database,
        database_uuid=claims.database_uuid,
        policy_namespace=claims.policy_namespace,
        runtime_role=claims.runtime_role,
        context=prior_context,
    )
    old_context_sha256 = canonical_digest(prior_context)
    prior = await old.load_claim(
        kind="MANUAL_NONCE", namespace="siwe-session:" + old_context_sha256, identity="one-attempt"
    )
    expected_hash = hashlib.sha256((old_context_sha256 + "\n" + expected_wallet_address).encode()).hexdigest()
    if prior is None or prior["request_sha256"] != expected_hash:
        raise LocalCustodyError("retained prior auth attempt does not match")
    async with claims._connection() as connection:
        nonces = await connection.fetchval(
            "SELECT count(*) FROM kairos_production_evidence_v1.claims "
            "WHERE claim_kind='MANUAL_NONCE' AND context_sha256=$1 AND namespace LIKE 'siwe:%'",
            old_context_sha256,
        )
        trade_claims = await connection.fetchval(
            "SELECT count(*) FROM kairos_production_evidence_v1.claims "
            "WHERE claim_kind IN ('TYPED_SIGNING','WIRE_DISPATCH')"
        )
        prior_success = await connection.fetchval(
            "SELECT EXISTS(SELECT 1 FROM kairos_production_evidence_v1.claims "
            "WHERE namespace=$1 AND identity='BEARER_IDENTITY_VALID')",
            "auth-stage:" + old_context_sha256,
        )
    if nonces != 1 or trade_claims != 0 or prior_success:
        raise LocalCustodyError("prior auth UNKNOWN is not isolated from trading")
    approval = {
        "prior_context_sha256": old_context_sha256,
        "prior_plan_sha256": prior_plan_sha256,
        "prior_outcome": "UNKNOWN",
        "followup_plan_sha256": followup_plan_sha256,
        "operator_reference": operator_reference,
        "maximum_followups": 1,
        "order_methods": [],
    }
    approved = await claims.claim(
        "MANUAL_NONCE",
        "auth-followup:" + str(claims.database_uuid),
        "one-operator-followup",
        hashlib.sha256(json.dumps(approval, sort_keys=True).encode()).hexdigest(),
    )
    if approved is not True:
        raise LocalCustodyError("the single operator auth follow-up was already consumed")
