"""Test stand for the automatically armed REST session: a venue double, evidence, a database.

Everything here is synthetic and test-only:

* ``FakeEvedex`` answers the exact operations of the PROD Node sidecar
  (``ProductionEvedexSdkClient._call``): preflight, health, original HTTP captures
  with their SHA-256, signed POSTs and cancels. It keeps one account's state and moves
  it the way EVEDEX does: a GTC limit entry fills, TP/SL records appear, a triggered
  take-profit closes the position through its own trigger order.
* ``issue_stand_evidence`` creates the seven technical-canary receipts at the current
  time with the owner tools (``production_owner``). Their facts are labelled synthetic
  and their only artifact says so; they prove nothing about a real deployment.
* ``provision_stand_database`` provisions a disposable ``kairos_production_evidence_*``
  database in the local container and drops it afterwards.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import secrets
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from kairos_execution.managed_signer import reviewed_schema_sha256
from kairos_execution.production_owner import (
    freeze_policy,
    generate_issuer,
    generate_owner_key,
    issue_receipt,
    store_artifact,
)
from kairos_execution.production_readiness import EvidenceKind, ProductionContextV1
from kairos_execution.production_transport import _RAW_CAPTURE_PATHS, _raw_capture_request
from kairos_execution.signed_evidence import (
    FACT_SCHEMAS,
    SINGLE_HOST_REQUIRED_ALERT_NAMES,
    FrozenGatePolicyV1,
)
from kairos_execution.single_host_readiness import issuer_registry_sha256
from kairos_execution.technical_canary_readiness import TECHNICAL_CANARY_REQUIRED_KINDS

SYNTHETIC = b"SYNTHETIC TEST STAND ONLY - NOT EVIDENCE OF ANY REAL DEPLOYMENT OR READINESS"


def stand_admin_dsn() -> str:
    if os.getenv("KAIROS_REST_STAND") != "1":
        pytest.skip("set KAIROS_REST_STAND=1 to run the disposable database stand")
    filename = os.getenv("KAIROS_REST_STAND_ADMIN_DSN_FILE")
    if not filename:
        pytest.skip("set KAIROS_REST_STAND_ADMIN_DSN_FILE for the disposable database server")
    return Path(filename).read_text(encoding="utf-8").strip()


def stand_container() -> str:
    name = os.getenv("KAIROS_REST_STAND_CONTAINER")
    if not name:
        pytest.skip("set KAIROS_REST_STAND_CONTAINER to the disposable database container")
    return name


def iso_ms(stamp: datetime) -> str:
    return stamp.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.") + f"{stamp.microsecond // 1000:03d}Z"


def order_id() -> str:
    return "00384:" + secrets.token_hex(13).upper()


# A test-only secp256k1 key: it signs synthetic orders for the stand and nothing else.
STAND_KEY = bytes.fromhex("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")


class StandCustody:
    """Signs the exact EIP-712 bytes the production verifier recovers, with ``STAND_KEY``."""

    def __init__(self) -> None:
        from eth_account import Account

        self.wallet_address = Account.from_key(STAND_KEY).address
        self.calls = 0

    def sign_typed_data(self, *, custody_reference: str, domain: dict, types: dict, message: dict) -> str:
        from eth_account import Account
        from eth_account.messages import encode_typed_data

        from kairos_execution.local_custody import _domain_fields

        self.calls += 1
        primary = next(iter(types))
        fields = types[primary]
        signed = {field["name"]: message[field["name"]] for field in fields}
        full = {
            "types": {**types, "EIP712Domain": _domain_fields(domain)},
            "primaryType": primary,
            "domain": domain,
            "message": signed,
        }
        signature = Account.sign_message(encode_typed_data(full_message=full), STAND_KEY).signature.hex()
        return signature if signature.startswith("0x") else "0x" + signature


class FakeEvedex:
    """One synthetic EVEDEX PROD account behind the sidecar's operation protocol."""

    def __init__(self, account_id: str, *, balance: str = "1000", bid: str = "100.04", ask: str = "100.05"):
        self.account_id = account_id
        self.balance = Decimal(balance)
        self.bid, self.ask = Decimal(bid), Decimal(ask)
        self.positions: list[dict[str, Any]] = []
        self.open_orders: list[dict[str, Any]] = []
        self.history: list[dict[str, Any]] = []
        self.tpsl: list[dict[str, Any]] = []
        self.fills: dict[str, list[dict[str, Any]]] = {}
        self.funding: list[dict[str, Any]] = []
        self.calls: list[str] = []
        self.fee_rate = Decimal("0.0005")

    # ------------------------------------------------------------ protocol
    async def call(
        self, operation: str, payload: dict[str, Any], *, mutation: bool, wire_token: Any = None
    ) -> Any:
        self.calls.append(operation if operation != "send_signed_post" else payload["path"])
        if operation == "preflight":
            return {"exchangeId": self.account_id, "id": self.account_id}
        if operation == "read_health":
            return self._health()
        if operation == "fetch_raw_capture":
            return self._capture(payload)
        if operation == "send_signed_post":
            return self._post(payload["path"], payload["body"])
        if operation == "cancel_order":
            return self._cancel_order(payload["order_id"])
        if operation == "cancel_tpsl":
            return self._cancel_tpsl(payload["protection_id"])
        raise AssertionError(f"unexpected sidecar operation {operation}")

    def _health(self) -> dict[str, Any]:
        return {
            "ok": True,
            "profile": "PROD",
            "chain_id": 42161,
            "exchange_url": "https://trading-api.evedex.com",
            "auth_url": "https://auth-api.evedex.com",
            "sdk_version": "1.2.11",
            "account_id": self.account_id,
            "auth_age_ms": 500,
            "auth_expires_in_ms": None,
            "local_mutation_rate_limit_observable": True,
            "local_mutation_rate_limit_reserve": 29,
            "local_mutation_rate_limit_capacity": 30,
            "local_mutation_rate_limit_window_ms": 60_000,
            "local_mutation_compensation_reserve": 4,
            "local_mutation_entry_min_reserve": 7,
            "venue_rate_limit_observable": False,
            "venue_rate_limit_reserve": None,
            "preflight_capture": self._wrap("account_identity", "/api/user/me", {}, self._identity()),
        }

    def _identity(self) -> dict[str, Any]:
        return {"id": self.account_id, "exchangeId": self.account_id, "marginCall": False}

    def _wrap(self, source: str, path: str, query: dict[str, Any], body: Any) -> dict[str, Any]:
        raw = json.dumps(body, separators=(",", ":"), default=str).encode()
        now = datetime.now(UTC)
        return {
            "source": source,
            "path": path,
            "query_json": json.dumps({key: str(value) for key, value in query.items()}, sort_keys=True),
            "status": 200,
            "requested_at": iso_ms(now - timedelta(milliseconds=3)),
            "received_at": iso_ms(now),
            "body_bytes": len(raw),
            "body_sha256": hashlib.sha256(raw).hexdigest(),
            "body_base64": base64.b64encode(raw).decode("ascii"),
        }

    def _capture(self, payload: dict[str, Any]) -> dict[str, Any]:
        source = payload["source"]
        _, query = _raw_capture_request(
            source,
            version=payload.get("version"),
            limit=payload.get("limit"),
            offset=payload.get("offset"),
            next_cursor=payload.get("next_cursor"),
            instrument=payload.get("instrument"),
            max_level=payload.get("max_level"),
            order_id=payload.get("order_id"),
            after=payload.get("after"),
            before=payload.get("before"),
            transfer_type=payload.get("transfer_type"),
        )
        if source in _RAW_CAPTURE_PATHS:
            path = _RAW_CAPTURE_PATHS[source][0]
        else:
            path = {
                "order_fills": f"/api/order/{payload.get('order_id')}/fill",
                "funding_transfers": "/api/user/funding-transfer",
                "fill_history": "/api/fill",
                "best_depth": f"/api/market/{payload.get('instrument')}/deep",
                "depth": f"/api/market/{payload.get('instrument')}/deep",
                "order_page": "/api/order",
                "tpsl_page": "/api/tpsl",
            }[source]
        return self._wrap(source, path, query, self._body(source, payload))

    def _body(self, source: str, payload: dict[str, Any]) -> Any:
        now_ms = int(datetime.now(UTC).timestamp() * 1000)
        if source == "account_identity":
            return self._identity()
        if source == "available_balance":
            return {
                "funding": {"currency": "USDT", "balance": str(self.balance)},
                "availableBalance": str(self.balance),
                "position": [
                    {
                        "instrument": p["instrument"],
                        "side": p["side"],
                        "volume": str(Decimal(p["quantity"]) * Decimal(p["avgPrice"])),
                        "initialMargin": str(Decimal(p["quantity"]) * Decimal(p["avgPrice"])),
                    }
                    for p in self.positions
                ],
                "openOrder": [],
            }
        if source == "positions":
            return {"list": copy.deepcopy(self.positions)}
        if source == "open_orders":
            return copy.deepcopy(self.open_orders)
        if source == "instruments":
            return [self._instrument()]
        if source == "tpsl_page":
            return {"count": len(self.tpsl), "list": copy.deepcopy(self.tpsl)}
        if source == "order_page":
            return {"count": len(self.history), "list": copy.deepcopy(self.history)}
        if source in {"best_depth", "depth"}:
            return {
                "t": now_ms,
                "bids": [{"price": str(self.bid), "quantity": "50"}],
                "asks": [{"price": str(self.ask), "quantity": "50"}],
            }
        if source == "order_fills":
            return copy.deepcopy(self.fills.get(payload["order_id"], []))
        if source == "funding_transfers":
            return {"count": len(self.funding), "list": copy.deepcopy(self.funding)}
        if source == "fill_history":
            return {"count": 0, "list": []}
        if source == "funding":
            return {"list": []}
        raise AssertionError(f"unexpected capture source {source}")

    def _instrument(self) -> dict[str, Any]:
        return {
            "name": "BTCUSD",
            "trading": "all",
            "visibility": "all",
            "marketState": "OPEN",
            "markPrice": str((self.bid + self.ask) / 2),
            "updatedAt": "2026-01-01T00:00:00.000Z",
            "lotSize": "1",
            "multiplier": "1",
            "priceIncrement": "0.01",
            "quantityIncrement": "0.1",
            "minPrice": "1",
            "maxPrice": "1000000",
            "minQuantity": "0.1",
            "maxQuantity": "100",
            "minVolume": "5",
        }

    # ------------------------------------------------------------ mutations
    def _fill(self, oid: str, quantity: Decimal, price: Decimal) -> None:
        fee = quantity * price * self.fee_rate
        self.fills.setdefault(oid, []).append(
            {
                "id": f"fill-{secrets.token_hex(6)}",
                "order": oid,
                "fillQuantity": str(quantity),
                "fillPrice": str(price),
                "fee": [{"coin": "usdt", "quantity": str(fee)}],
                "createdAt": iso_ms(datetime.now(UTC)),
            }
        )
        self.balance -= fee

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        now = iso_ms(datetime.now(UTC))
        if path == "/api/v2/order/limit":
            assert body.get("timeInForce", "GTC") == "GTC", body
            quantity, price = Decimal(body["quantity"]), Decimal(body["limitPrice"])
            order = {
                "id": body["id"],
                "instrument": body["instrument"],
                "side": body["side"],
                "type": "LIMIT",
                "timeInForce": "GTC",
                "leverage": body["leverage"],
                "quantity": str(quantity),
                "unFilledQuantity": "0",
                "limitPrice": str(price),
                "filledAvgPrice": str(price),
                "status": "FILLED",
                "createdAt": now,
                "updatedAt": now,
            }
            order["fee"] = [{"coin": "usdt", "quantity": str(quantity * price * self.fee_rate)}]
            self.history.append(copy.deepcopy(order))
            self._fill(body["id"], quantity, price)
            self.positions = [
                {
                    "instrument": body["instrument"],
                    "side": body["side"],
                    "quantity": str(quantity),
                    "avgPrice": str(price),
                    "markPrice": str(price),
                    "leverage": body["leverage"],
                    "unRealizedPnL": "0",
                }
            ]
            return order
        if path.startswith("/api/tpsl/"):
            record = {
                "id": f"tpsl-{secrets.token_hex(6)}",
                "instrument": body["instrument"],
                "side": body["side"],
                "type": body["type"],
                "quantity": 0,
                "price": str(body["price"]),
                "order": body["order"],
                "status": "active",
                "createdAt": now,
                "updatedAt": now,
            }
            self.tpsl.append(record)
            return copy.deepcopy(record)
        if path.startswith("/api/v2/position/") and path.endswith("/close"):
            return self._close(body["id"], Decimal(body["quantity"]), self.bid)
        raise AssertionError(f"unexpected signed POST {path}")

    def _close(self, oid: str, quantity: Decimal, price: Decimal) -> dict[str, Any]:
        position = self.positions[0]
        side = "SELL" if position["side"] == "BUY" else "BUY"
        entry = Decimal(position["avgPrice"])
        sign = Decimal(1) if position["side"] == "BUY" else Decimal(-1)
        self.balance += (price - entry) * quantity * sign
        now = iso_ms(datetime.now(UTC))
        order = {
            "id": oid,
            "instrument": position["instrument"],
            "side": side,
            "type": "MARKET",
            "quantity": str(quantity),
            "unFilledQuantity": "0",
            "filledAvgPrice": str(price),
            "status": "FILLED",
            "fee": [{"coin": "usdt", "quantity": str(quantity * price * self.fee_rate)}],
            "createdAt": now,
            "updatedAt": now,
        }
        self.history.append(copy.deepcopy(order))
        self._fill(oid, quantity, price)
        remaining = Decimal(position["quantity"]) - quantity
        self.positions = [] if remaining <= 0 else [{**position, "quantity": str(remaining)}]
        return order

    def trigger(self, kind: str) -> str:
        """The venue triggers the active ``take-profit`` or ``stop-loss`` record."""
        record = next(r for r in self.tpsl if r["type"] == kind and r["status"] == "active")
        quantity = Decimal(self.positions[0]["quantity"])
        trigger_id = order_id()
        self._close(trigger_id, quantity, Decimal(record["price"]))
        record.update(
            status="done",
            triggerOrder=trigger_id,
            triggeredQuantity=str(quantity),
            cancelledReason="",
            updatedAt=iso_ms(datetime.now(UTC)),
        )
        return trigger_id

    def _cancel_order(self, oid: str) -> dict[str, Any]:
        self.open_orders = [row for row in self.open_orders if row["id"] != oid]
        for row in self.history:
            if row["id"] == oid and row["status"] not in {"FILLED"}:
                row["status"] = "CANCELLED"
        return {"id": oid, "status": "CANCELED"}

    def _cancel_tpsl(self, protection_id: str) -> dict[str, Any]:
        for row in self.tpsl:
            if row["id"] == protection_id and row["status"] == "active":
                row.update(status="cancelled", cancelledReason="user", updatedAt=iso_ms(datetime.now(UTC)))
        return {"id": protection_id, "status": "CANCELED"}


def issue_stand_evidence(
    root: Path,
    *,
    remote_account_id: str,
    adaptive_system_id: str,
    source_set_sha256: str,
    custody_reference: str,
    wallet_address: str,
    chain_id: int,
    owner_identity: str,
    dollar_cap: Decimal,
    daily_stop_loss_usd: Decimal,
    now: datetime,
):
    """Seven synthetic receipts at ``now``; returns (context, references, registry, pin, owner key)."""
    evidence = root / "evidence"
    frozen = FrozenGatePolicyV1(
        adaptive_system_id=adaptive_system_id,
        source_set_sha256=source_set_sha256,
        campaign_id="synthetic-test-stand",
        evaluator_sha256=hashlib.sha256(b"synthetic evaluator").hexdigest(),
        minimum_profit_factor=Decimal("1.2"),
        maximum_drawdown_fraction=Decimal("0.2"),
        crash_scenario_sha256s=(hashlib.sha256(b"synthetic crash").hexdigest(),),
        required_alert_names=SINGLE_HOST_REQUIRED_ALERT_NAMES,
        owner_telegram_user_id=5,
        minimum_forward_days=365,
        minimum_natural_closes=500,
        frozen_at=now - timedelta(days=1),
    )
    context = ProductionContextV1(
        remote_account_id=remote_account_id,
        adaptive_system_id=adaptive_system_id,
        frozen_policy_sha256=freeze_policy(evidence, frozen),
        source_set_sha256=source_set_sha256,
    )
    artifact = store_artifact(evidence, SYNTHETIC)
    issuer = generate_issuer(
        root / "issuer",
        issuer_id="synthetic-stand-issuer",
        frozen=frozen,
        context=context,
        allowed_kinds=list(TECHNICAL_CANARY_REQUIRED_KINDS),
        valid_from=now - timedelta(hours=1),
        valid_until=now + timedelta(days=1),
    )
    base = {"artifact_sha256s": (artifact,)}
    facts: dict[EvidenceKind, Any] = {
        EvidenceKind.PRIMARY_RECOVERY: dict(
            primary_database_identity="synthetic-stand",
            backup_sha256=artifact,
            restored_backup_sha256=artifact,
            native_commit_receipt_sha256=artifact,
            primary_acceptance_receipt_sha256=artifact,
            before_history_sha256=artifact,
            after_history_sha256=artifact,
            unresolved_inbox=0,
            unresolved_outbox=0,
            duplicate_publications=0,
            unresolved_leases=0,
            bar_chain_conflicts=0,
        ),
        EvidenceKind.SECURITY_REVIEW: dict(
            threat_model_sha256=artifact,
            reviewed_source_set_sha256=source_set_sha256,
            independent_reviewer_identity="synthetic-stand-not-a-review",
            reviewed_security_boundary_count=1,
            unresolved_critical_findings=0,
            unresolved_high_findings=0,
            unresolved_medium_findings=0,
            deployment_review_sha256=artifact,
        ),
        EvidenceKind.MANAGED_CUSTODY: dict(
            custody_reference=custody_reference,
            wallet_address=wallet_address,
            chain_id=chain_id,
            typed_schema_sha256=reviewed_schema_sha256(chain_id),
            independent_recovery_test_sha256=artifact,
            dev_custody_reference="synthetic-dev-custody",
            successful_verified_signatures=1,
            malformed_requests_rejected=1,
            unauthorized_requests_rejected=1,
            unverified_signatures=0,
        ),
        EvidenceKind.GLOBAL_OPERATOR_CONTROL: dict(
            control_database_identity="synthetic-stand",
            operator_role="operator",
            runtime_role="runtime",
            operator_version=1,
            killed_at=now - timedelta(minutes=2),
            resumed_at=now - timedelta(minutes=1),
            restart_observed_version=1,
            entries_dispatched_after_kill=0,
            protected_exit_failures=0,
            duplicate_dispatches=0,
            unknown_claim_retries=0,
            denied_unsafe_privilege_count=1,
        ),
        EvidenceKind.PROD_ACCOUNT_PAIRING: dict(
            environment="PROD",
            remote_account_id=remote_account_id,
            wallet_address=wallet_address,
            authenticated_read_challenge_sha256=artifact,
            signing_challenge_sha256=artifact,
            chain_id=chain_id,
            credential_pairing_conflicts=0,
        ),
        EvidenceKind.PRODUCTION_LIMITS: dict(
            owner_identity=owner_identity,
            dollar_cap=dollar_cap,
            daily_stop_loss_usd=daily_stop_loss_usd,
            risk_per_trade_fraction=Decimal("0.0025"),
            maximum_total_open_risk_fraction=Decimal("0.01"),
            maximum_leverage=1,
            blocked_missing_limit_count=1,
            blocked_over_cap_count=1,
            blocked_daily_stop_count=1,
            restart_accounting_receipt_sha256=artifact,
            pending_risk_receipt_sha256=artifact,
        ),
    }
    references = []
    for kind in TECHNICAL_CANARY_REQUIRED_KINDS:
        if kind is EvidenceKind.ALERT_DELIVERY:
            from tests.alert_evidence_fixtures import synthetic_alert_facts

            model: Any = synthetic_alert_facts(now, lambda data: store_artifact(evidence, data))
        else:
            model = FACT_SCHEMAS[kind].model_validate({**base, **facts[kind]})
        references.append(
            issue_receipt(
                root / "issuer" / "evidence-issuer.ed25519",
                issuer,
                kind=kind,
                facts=model,
                evidence_dir=evidence,
                issued_at=now,
                lifetime=timedelta(hours=6),
            )
        )
    owner_key = generate_owner_key(
        root / "owner",
        owner_identity=owner_identity,
        context=context,
        valid_from=now - timedelta(hours=1),
        valid_until=now + timedelta(days=1),
    )
    registry = (issuer,)
    return context, tuple(references), registry, issuer_registry_sha256(registry), owner_key
