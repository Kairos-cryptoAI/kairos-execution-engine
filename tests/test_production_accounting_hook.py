"""Synthetic orchestration only; native accounting is tested separately.

No venue or authority fact is established by these fake method results.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import UUID

import pytest

from kairos_execution.paper_engine import PaperExecutionSafetyError
from kairos_execution.production_accounting import PostgresProductionAccounting, ProductionAccountingError
from tests.test_production_closed_account import _fixture

DB = "kairos_production_evidence_synthetic_hook"
NAMESPACE = "synthetic-accounting-hook"
RECEIPT_ID = UUID("b1ad1b56-3cb5-4aab-b68b-233e21f58de8")
HASH = "a" * 64


class SyntheticAccounting(PostgresProductionAccounting):
    def __init__(self, engine):
        self.context = engine.production_settings.context
        self.database_uuid = engine.production_runtime.database_uuid
        self.expected_database = DB
        self.policy_namespace = NAMESPACE
        self.accept_terminal_receipt = AsyncMock(
            return_value={"created": True, "receipt_id": str(RECEIPT_ID)}
        )


def fixture():
    _, engine, reconciler, _, trade = _fixture()
    engine.production_runtime.state_source = SimpleNamespace(
        expected_database=DB, policy_namespace=NAMESPACE, state_schema_version=3
    )
    reconciler.expected_database = DB
    reconciler.policy_namespace = NAMESPACE
    reconciler.schema_version = 2
    reconciler.reconcile_terminal = AsyncMock(
        return_value={"receipt_id": str(RECEIPT_ID), "payload_sha256": HASH}
    )
    return engine, reconciler, trade, SyntheticAccounting(engine)


async def invoke(engine, reconciler, trade, accounting):
    return await engine.reconcile_closed_account(
        trade_id=trade.trade_id,
        reconciler=reconciler,
        source_id="synthetic-only",
        raw_venue_evidence={"synthetic": True},
        accounting=accounting,
    )


@pytest.mark.asyncio
async def test_exact_accepted_terminal_receipt_is_passed_to_opt_in_accounting_after_reconciliation():
    engine, reconciler, trade, accounting = fixture()
    calls = []

    async def terminal(**_):
        calls.append("terminal")
        return {"receipt_id": str(RECEIPT_ID), "payload_sha256": HASH}

    async def accept(**kwargs):
        calls.append("accounting")
        assert kwargs == {"receipt_id": RECEIPT_ID, "receipt_payload_sha256": HASH}
        return {"created": True, "receipt_id": str(RECEIPT_ID)}

    reconciler.reconcile_terminal.side_effect = terminal
    accounting.accept_terminal_receipt.side_effect = accept
    result = await invoke(engine, reconciler, trade, accounting)
    assert calls == ["terminal", "accounting"]
    assert result["reservation_released"] is True
    assert result["live_ready"] is False
    assert result["accounting_receipt"]["receipt_id"] == str(RECEIPT_ID)


@pytest.mark.asyncio
@pytest.mark.parametrize("conflict", ["database", "namespace", "context", "state_version", "receipt_version"])
async def test_wrong_accounting_composition_refuses_before_creating_a_terminal_receipt(conflict):
    engine, reconciler, trade, accounting = fixture()
    if conflict == "database":
        accounting.expected_database = DB + "_other"
    elif conflict == "namespace":
        accounting.policy_namespace = NAMESPACE + "_other"
    elif conflict == "context":
        accounting.context = accounting.context.model_copy(update={"remote_account_id": "other"})
    elif conflict == "state_version":
        engine.production_runtime.state_source.state_schema_version = 2
    else:
        reconciler.schema_version = 1
    with pytest.raises(PaperExecutionSafetyError, match="fresh v3/v2"):
        await invoke(engine, reconciler, trade, accounting)
    reconciler.reconcile_terminal.assert_not_awaited()
    accounting.accept_terminal_receipt.assert_not_awaited()


@pytest.mark.asyncio
async def test_accounting_failure_does_not_report_release_or_recreate_terminal_evidence():
    engine, reconciler, trade, accounting = fixture()
    accounting.accept_terminal_receipt.side_effect = ProductionAccountingError("synthetic refusal")
    with pytest.raises(ProductionAccountingError):
        await invoke(engine, reconciler, trade, accounting)
    assert reconciler.reconcile_terminal.await_count == 1
    assert accounting.accept_terminal_receipt.await_count == 1


@pytest.mark.asyncio
async def test_terminal_refusal_never_reaches_accounting():
    engine, reconciler, trade, accounting = fixture()
    reconciler.reconcile_terminal.side_effect = PermissionError("synthetic missing coverage")
    with pytest.raises(PermissionError):
        await invoke(engine, reconciler, trade, accounting)
    accounting.accept_terminal_receipt.assert_not_awaited()


@pytest.mark.asyncio
async def test_malformed_terminal_identity_never_reaches_accounting():
    engine, reconciler, trade, accounting = fixture()
    reconciler.reconcile_terminal.return_value = {"receipt_id": "not-a-uuid", "payload_sha256": HASH}
    with pytest.raises(PaperExecutionSafetyError, match="malformed"):
        await invoke(engine, reconciler, trade, accounting)
    accounting.accept_terminal_receipt.assert_not_awaited()
