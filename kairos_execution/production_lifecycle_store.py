"""Passive durable storage for exact PROD lifecycle-to-signing bindings.

This adapter records a candidate binding; it does not authorize it. Consumers
must still independently resolve the persisted risk decision and signing
evidence before taking any action.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC
from typing import Any

import asyncpg  # type: ignore[import-untyped]  # Upstream ships no typing marker/stubs.
from kairos_persistence import AuditRepository

from .managed_signer import ManagedSigningRequestV1
from .production_claims import _database_name
from .production_lifecycle_binding import ProductionLifecycleBindingV1
from .production_readiness import ProductionContextV1, canonical_digest
from .production_state import _role
from .signing_authorization import signing_effect_id

TOPIC = "kairos.production.lifecycle-binding.v1"
SOURCE = "kairos-execution-engine"
SCHEMA_VERSION = "1.0"


class ProductionLifecycleStoreError(RuntimeError):
    """A lifecycle binding could not be safely stored or resolved."""


class PostgresLifecycleBindingStore:
    """Append-only exact binding store implemented on existing ``event_audit``."""

    def __init__(
        self,
        pool: asyncpg.Pool,
        *,
        context: ProductionContextV1,
        expected_database: str,
        expected_role: str,
    ) -> None:
        self.pool = pool
        self.context = ProductionContextV1.model_validate(context)
        self.expected_database = _database_name(expected_database)
        self.expected_role = _role(expected_role)
        self.context_sha256 = canonical_digest(self.context)
        self.audit = AuditRepository(pool)

    async def put(self, binding: ProductionLifecycleBindingV1) -> bool:
        """Append one exact binding; return False only for an identical replay."""
        binding = ProductionLifecycleBindingV1.model_validate(binding)
        self._validate_binding(binding)
        payload = self._wire_payload(binding)
        canonical_json = _canonical_json(payload)
        async with self.pool.acquire() as connection:
            async with connection.transaction():
                await self._check_identity(connection)
                await connection.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                    self._binding_lock(binding.lifecycle_effect_id),
                )
                # The runtime is INSERT/SELECT-only. The generic strict audit
                # helper uses SELECT FOR UPDATE (requiring UPDATE privilege),
                # so use its canonical-identity checker plus ordinary reads
                # under this stable advisory lock instead. Do not grant UPDATE
                # merely to make passive candidate storage work.
                await connection.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                    f"lifecycle-binding-message:{payload['message_id']}",
                )
                rows = await connection.fetch(
                    "SELECT topic,payload FROM event_audit WHERE message_id=$1", payload["message_id"]
                )
                if rows:
                    self.audit._require_matching_audit_identity(
                        rows, message_id=payload["message_id"], topic=TOPIC, canonical_json=canonical_json
                    )
                    return False
                inserted = await self.audit.append_payload(TOPIC, payload, connection=connection)
                rows = await connection.fetch(
                    "SELECT topic,payload FROM event_audit WHERE message_id=$1", payload["message_id"]
                )
                self.audit._require_matching_audit_identity(
                    rows, message_id=payload["message_id"], topic=TOPIC, canonical_json=canonical_json
                )
                return inserted

    async def get(self, lifecycle_effect_id: str) -> ProductionLifecycleBindingV1 | None:
        """Resolve one exact immutable binding, refusing duplicate or conflicting audit rows."""
        if not _is_digest(lifecycle_effect_id):
            raise ProductionLifecycleStoreError("lifecycle effect ID must be lowercase SHA-256")
        message_id = self._message_id(lifecycle_effect_id)
        async with self.pool.acquire() as connection:
            async with connection.transaction(readonly=True):
                await self._check_identity(connection)
                rows = await connection.fetch(
                    "SELECT topic,payload FROM event_audit WHERE message_id=$1",
                    message_id,
                )
        if not rows:
            return None
        if len(rows) != 1:
            raise ProductionLifecycleStoreError("lifecycle message ID has duplicate audit rows")
        row = rows[0]
        if row["topic"] != TOPIC:
            raise ProductionLifecycleStoreError("lifecycle message ID is bound to another audit topic")
        payload = _payload_object(row["payload"])
        binding = self._parse_payload(payload, lifecycle_effect_id, message_id)
        return binding

    async def _check_identity(self, connection: asyncpg.Connection) -> None:
        identity = await connection.fetchrow("SELECT current_database() AS db,current_user AS role")
        if (
            identity is None
            or identity["db"] != self.expected_database
            or identity["role"] != self.expected_role
        ):
            raise ProductionLifecycleStoreError("lifecycle store database/role identity mismatch")

    def _validate_binding(self, binding: ProductionLifecycleBindingV1) -> None:
        if binding.context != self.context:
            raise ProductionLifecycleStoreError("lifecycle binding context differs from store scope")
        request = ManagedSigningRequestV1.model_validate(binding.request)
        if request.context != self.context:
            raise ProductionLifecycleStoreError("signing request context differs from lifecycle binding")
        try:
            message = json.loads(request.message_json)
        except (TypeError, json.JSONDecodeError):
            raise ProductionLifecycleStoreError("signing request message is malformed") from None
        if not isinstance(message, dict) or _canonical_json(message) != request.message_json:
            raise ProductionLifecycleStoreError("signing request message is not canonical JSON")
        expected_request_id = "lifecycle-" + _sha256_json(
            {
                "domain": "kairos.production-lifecycle-request.v1",
                "context_sha256": self.context_sha256,
                "trade_id": binding.trade_id,
                "decision_id": binding.decision_id,
                "decision_sha256": binding.decision_sha256,
                "lifecycle_effect_id": binding.lifecycle_effect_id,
                "role": binding.role,
            }
        )
        if request.request_id != expected_request_id:
            raise ProductionLifecycleStoreError(
                "lifecycle request identity is not deterministic for its binding"
            )
        if binding.role == "ENTRY" and binding.risk_decision_id != binding.decision_id:
            raise ProductionLifecycleStoreError(
                "entry risk decision differs from its immutable Core decision"
            )
        if (
            signing_effect_id(
                request=request,
                message=message,
                decision_id=binding.risk_decision_id,
            )
            != binding.signing_effect_id
        ):
            raise ProductionLifecycleStoreError(
                "signing effect ID differs from the exact stored request geometry"
            )

    def _wire_payload(self, binding: ProductionLifecycleBindingV1) -> dict[str, Any]:
        expires_at = binding.request.expires_at
        if expires_at.tzinfo is None or expires_at.utcoffset() != UTC.utcoffset(expires_at):
            raise ProductionLifecycleStoreError("binding request expiry must be explicit UTC")
        return {
            "schema_version": SCHEMA_VERSION,
            "message_id": self._message_id(binding.lifecycle_effect_id),
            "correlation_id": binding.trade_id,
            "causation_id": binding.decision_id,
            "produced_at": expires_at.astimezone(UTC).isoformat(),
            "source": SOURCE,
            "binding": binding.model_dump(mode="json"),
        }

    def _parse_payload(
        self, payload: dict[str, Any], lifecycle_effect_id: str, message_id: str
    ) -> ProductionLifecycleBindingV1:
        if (
            payload.get("schema_version") != SCHEMA_VERSION
            or payload.get("source") != SOURCE
            or payload.get("message_id") != message_id
        ):
            raise ProductionLifecycleStoreError("stored lifecycle audit envelope identity mismatch")
        try:
            binding_payload = payload.get("binding")
            binding = ProductionLifecycleBindingV1.model_validate_json(_canonical_json(binding_payload))
            self._validate_binding(binding)
        except ProductionLifecycleStoreError:
            raise
        except Exception as exc:
            raise ProductionLifecycleStoreError(
                f"stored lifecycle binding is invalid ({type(exc).__name__})"
            ) from None
        if binding.context != self.context or binding.lifecycle_effect_id != lifecycle_effect_id:
            raise ProductionLifecycleStoreError("stored lifecycle binding context/effect mismatch")
        wire = self._wire_payload(binding)
        if _canonical_json(wire) != _canonical_json(payload):
            raise ProductionLifecycleStoreError("stored lifecycle audit payload is non-canonical or rebound")
        return binding

    def _message_id(self, lifecycle_effect_id: str) -> str:
        return _sha256_json(
            {
                "domain": "kairos.production-lifecycle-binding-message.v1",
                "context_sha256": self.context_sha256,
                "lifecycle_effect_id": lifecycle_effect_id,
            }
        )

    def _binding_lock(self, lifecycle_effect_id: str) -> str:
        return f"production-lifecycle-binding:{self.context_sha256}:{lifecycle_effect_id}"


def _payload_object(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            raise ProductionLifecycleStoreError("stored lifecycle payload is invalid JSON") from None
    if not isinstance(value, dict):
        raise ProductionLifecycleStoreError("stored lifecycle payload is not an object")
    return value


def _canonical_json(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError):
        raise ProductionLifecycleStoreError("lifecycle payload cannot be canonicalized") from None


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _is_digest(value: str) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )
