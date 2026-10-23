"""Synthetic economics and immutable terminal boundaries; never venue evidence."""

from datetime import timedelta
from decimal import Decimal
from uuid import uuid4

import pytest
from pydantic import ValidationError

from kairos_execution.production_accounting import (
    DDL,
    ProductionAccountingError,
    terminal_economics,
    verify_terminal_receipt,
)
from kairos_execution.production_reconciliation import (
    DDL_V2,
    VenueTerminalEvidenceV2,
    _canonical_sha256,
)
from kairos_execution.production_state import (
    DDL as STATE_DDL,
)
from kairos_execution.production_state import (
    DDL_V3,
    SCHEMA_VERSION,
    AsyncPostgresProductionSigningStateSource,
    _reservation_totals_query,
)
from tests.test_production_reconciliation import DB_UUID, NOW, _context, _evidence


def _economics(**changes):
    values = {
        "entry_side": "BUY",
        "entry_notional_usd": "100",
        "exit_notional_usd": "90",
        "entry_fees_usd": "0.1",
        "exit_fees_usd": "0.2",
        "funding_cost_usd": "0.4",
        "funding_complete": True,
    }
    values.update(changes)
    return values


@pytest.mark.parametrize(
    ("side", "exit_value", "funding", "gross", "net", "charge"),
    [
        ("BUY", "90", "0.4", "-10", "-10.7", "10.7"),
        ("SELL", "110", "0.4", "-10", "-10.7", "10.7"),
        ("BUY", "110", "0.4", "10", "9.3", "0.7"),
        ("SELL", "90", "-0.4", "10", "10.1", "0.3"),
        ("BUY", "90", "-50", "-10", "39.7", "10.3"),
    ],
)
def test_actual_long_short_gross_fees_funding_without_loss_offsets(
    side, exit_value, funding, gross, net, charge
):
    result = terminal_economics(
        _economics(entry_side=side, exit_notional_usd=exit_value, funding_cost_usd=funding)
    )
    assert result["gross_pnl_usd"] == Decimal(gross)
    assert result["net_pnl_usd"] == Decimal(net)
    assert result["loss_charge_usd"] == Decimal(charge)


@pytest.mark.parametrize(
    "changes",
    [
        {"funding_complete": False},
        {"funding_cost_usd": None},
        {"entry_side": None},
        {"funding_cost_usd": float("nan")},
        {"entry_fees_usd": "-0.1"},
        {"entry_notional_usd": "0"},
        {"funding_cost_usd": "Infinity"},
        {"exit_notional_usd": "NaN"},
        {"entry_notional_usd": True},
    ],
)
def test_unknown_inexact_or_incomplete_economics_cannot_release(changes):
    with pytest.raises(ProductionAccountingError):
        terminal_economics(_economics(**changes))


def _v2_evidence(**changes):
    values = _evidence().model_dump()
    values.update(
        entry_side="BUY",
        funding_cost_usd=Decimal("0.4"),
        funding_complete=True,
        settled_at=NOW - timedelta(seconds=3),
        owner_arm_sha256="1" * 64,
        reservation_request_sha256="2" * 64,
    )
    values.update(changes)
    return VenueTerminalEvidenceV2(**values)


@pytest.mark.parametrize(
    "missing", ["funding_cost_usd", "settled_at", "owner_arm_sha256", "funding_complete"]
)
def test_v1_receipt_cannot_silently_acquire_missing_v2_facts(missing):
    values = _v2_evidence().model_dump()
    values.pop(missing)
    with pytest.raises(ValidationError):
        VenueTerminalEvidenceV2(**values)


def _receipt(**changes):
    evidence = _v2_evidence()
    payload = evidence.model_dump(mode="json")
    payload["venue_source_id"] = payload.pop("source_id")
    payload["venue_evidence_sha256"] = payload.pop("source_evidence_sha256")
    payload["venue_complete"] = payload.pop("complete")
    payload["venue_terminal"] = payload.pop("terminal")
    payload.pop("account_id")
    payload.update(
        database_uuid=str(DB_UUID),
        account_sha256="3" * 64,
        trade_journal_head_sha256="4" * 64,
        execution_facts_sha256="5" * 64,
        owned_effects_sha256="6" * 64,
    )
    payload.update(changes)
    row = dict(payload)
    row.update(
        receipt_id=uuid4(), payload=dict(payload), payload_sha256=_canonical_sha256(payload), inserted_at=NOW
    )
    row["database_uuid"] = DB_UUID
    for key in (
        "entry_filled_quantity",
        "closed_quantity",
        "entry_notional_usd",
        "exit_notional_usd",
        "entry_fees_usd",
        "exit_fees_usd",
        "funding_cost_usd",
        "residual_position_quantity",
    ):
        row[key] = Decimal(payload[key])
    from datetime import datetime

    for key in ("collection_started_at", "collection_finished_at", "observed_at", "settled_at"):
        row[key] = datetime.fromisoformat(payload[key])
    return row


def test_exact_accepted_receipt_payload_and_every_column_are_required():
    receipt = _receipt()
    assert verify_terminal_receipt(receipt, now=NOW) == receipt["payload"]
    receipt["entry_notional_usd"] += Decimal("1")
    with pytest.raises(ProductionAccountingError, match="column conflict"):
        verify_terminal_receipt(receipt, now=NOW)


def test_receipt_hash_is_not_a_substitute_for_canonical_payload():
    receipt = _receipt()
    receipt["payload"]["funding_cost_usd"] = "0"
    with pytest.raises(ProductionAccountingError, match="integrity"):
        verify_terminal_receipt(receipt, now=NOW)


@pytest.mark.parametrize(
    "changes",
    [
        {"venue_terminal": False},
        {"venue_complete": False},
        {"funding_complete": False},
        {"closed_quantity": "1.9"},
        {"entry_filled_quantity": "0"},
        {"residual_order_count": 1},
        {"residual_protection_count": 1},
        {"residual_position_quantity": "0.01"},
        {"unowned_exposure_count": 1},
    ],
)
def test_ack_partial_unknown_unowned_or_nonflat_receipt_never_releases(changes):
    with pytest.raises(ProductionAccountingError):
        verify_terminal_receipt(_receipt(**changes), now=NOW)


def test_durable_fresh_terminal_acceptance_survives_a_later_accounting_outage():
    receipt = _receipt()
    assert verify_terminal_receipt(receipt, now=NOW + timedelta(days=1)) == receipt["payload"]


def test_receipt_stale_at_original_database_acceptance_is_not_release_authority():
    receipt = _receipt()
    receipt["inserted_at"] = NOW + timedelta(minutes=3)
    with pytest.raises(ProductionAccountingError, match="stale"):
        verify_terminal_receipt(receipt, now=NOW + timedelta(minutes=4))


@pytest.mark.parametrize("inserted", [NOW - timedelta(minutes=1), NOW + timedelta(seconds=1)])
def test_receipt_acceptance_cannot_predate_observation_or_be_in_the_future(inserted):
    receipt = _receipt()
    receipt["inserted_at"] = inserted
    with pytest.raises(ProductionAccountingError, match="temporally incomplete"):
        verify_terminal_receipt(receipt, now=NOW)


def test_v2_default_unchanged_v3_requires_explicit_constructor_and_fresh_schema():
    kwargs = dict(
        expected_database="kairos_production_evidence_123456789abc",
        database_uuid=DB_UUID,
        policy_namespace="synthetic:namespace",
        runtime_role="synthetic_runtime",
        context=_context(),
    )
    assert SCHEMA_VERSION == 2
    assert AsyncPostgresProductionSigningStateSource(object(), **kwargs).state_schema_version == 2
    assert (
        AsyncPostgresProductionSigningStateSource(
            object(), **kwargs, state_schema_version=3
        ).state_schema_version
        == 3
    )
    assert "kairos_production_accounting" not in STATE_DDL
    assert "kairos_production_accounting" not in _reservation_totals_query(2)
    assert "accepted_releases" in DDL_V3
    assert "prior.realized_charge" in DDL_V3
    assert "min(r.dollar_cap)" in _reservation_totals_query(3)
    assert "max(r.aggregate_open_risk_usd)" in _reservation_totals_query(3)


def test_append_only_fk_account_lock_and_no_profit_offset_are_ddl_invariants():
    assert "REFERENCES kairos_production_reconciliation_v2.terminal_receipts(receipt_id)" in DDL
    assert "REFERENCES kairos_production_state_v1.risk_reservations(account_sha256,effect_id)" in DDL
    assert "BEFORE UPDATE OR DELETE" in DDL
    assert "risk-reservation:" in DDL
    assert "greatest(0,-gross_pnl_usd)+fees_usd+greatest(0,funding_cost_usd)" in DDL
    assert "CHECK(schema_version=2)" in DDL_V2
    assert "funding_complete boolean NOT NULL CHECK(funding_complete)" in DDL_V2
    assert "NEW.inserted_at := clock_timestamp()" in DDL_V2
    assert "NEW.inserted_at-NEW.observed_at>interval '2 minutes'" in DDL_V2
    assert "t.inserted_at-t.observed_at>interval '2 minutes'" in DDL
