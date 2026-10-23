"""Honest authority assessment of the pinned EVEDEX account/history source.

This is not an alternate exposure producer. It cannot write signing state and
cannot turn a caller's boolean, double-REST equality or local event counter
into proof. The fixed refusal is shared by terminal verification and a writer
boundary guard; a future venue contract requires a separately reviewed source.
"""

from __future__ import annotations

from typing import Any, Literal

from .production_history import SOURCE_ID, ProductionHistoryCaptureV1
from .production_readiness import ProductionContextV1, StrictRecord
from .production_reconciliation import (
    ProductionReconciliationError,
    ReservationTradeBindingV1,
    VenueTerminalEvidenceV1,
)

GAPS = (
    "no_account_wide_atomic_snapshot_or_shared_revision",
    "offset_or_next_exhaustion_does_not_prove_immutable_history_membership",
    "no_account_funding_payment_ledger_or_settlement_coverage",
    "tpsl_records_do_not_expose_entry_parent_lineage",
    "order_fill_stream_is_nonrecoverable_and_sdk_drops_publication_positions",
    "sdk_json_numbers_are_not_original_exact_decimal_wire_evidence",
)


class EvedexAuthorityAssessmentV1(StrictRecord):
    source_id: Literal["evedex-pinned-sdk-1.2.11-rest-history-v1"] = SOURCE_ID
    terminal_authority: Literal[False] = False
    exposure_authority: Literal[False] = False
    accounting_authority: Literal[False] = False
    reasons: tuple[str, ...] = GAPS


def assess_pinned_history_authority(capture: ProductionHistoryCaptureV1) -> EvedexAuthorityAssessmentV1:
    ProductionHistoryCaptureV1.model_validate(capture)
    return EvedexAuthorityAssessmentV1()


def require_exposure_write_authority(capture: ProductionHistoryCaptureV1) -> None:
    """Call before any existing exposure writer; never emits ExposureSnapshotV1."""
    assessment = assess_pinned_history_authority(capture)
    raise ProductionReconciliationError(
        "pinned EVEDEX history cannot authorize an exposure write: " + ";".join(assessment.reasons)
    )


class PinnedEvedexTerminalEvidenceVerifier:
    """Registerable real-source verifier that refuses uncertifiable v1/v2 proof."""

    source_id = SOURCE_ID

    def verify_terminal_evidence(
        self,
        raw_evidence: Any,
        *,
        context: ProductionContextV1,
        binding: ReservationTradeBindingV1,
    ) -> VenueTerminalEvidenceV1:
        try:
            capture = ProductionHistoryCaptureV1.model_validate(raw_evidence)
        except Exception:
            raise ProductionReconciliationError("pinned EVEDEX raw history is malformed") from None
        if capture.context != context or capture.account_id != context.remote_account_id:
            raise ProductionReconciliationError("pinned EVEDEX history context/account mismatch")
        # Validate lineage format without pretending that history proves it.
        ReservationTradeBindingV1.model_validate(binding)
        assessment = assess_pinned_history_authority(capture)
        raise ProductionReconciliationError(
            "pinned EVEDEX history cannot establish terminal/accounting evidence: "
            + ";".join(assessment.reasons)
        )
