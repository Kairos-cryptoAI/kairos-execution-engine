# EVEDEX PROD REST sources: trust model

Status: owner decision of 2026-11-13. Code: `kairos_execution/production_rest_sources.py`,
source ID `evedex-prod-rest-v1`.

## Why the pinned sources refuse

The pinned sources (`PinnedEvedexLiveAccountVerifier`, `PinnedEvedexLiveExitVerifier`,
`PinnedEvedexTerminalEvidenceVerifier`) refuse every input because EVEDEX PROD cannot
give these guarantees (`production_exposure.GAPS`):

| Gap | What it means |
|---|---|
| `no_account_wide_atomic_snapshot_or_shared_revision` | balance, positions, orders and TP/SL come from separate requests with no shared revision |
| `offset_or_next_exhaustion_does_not_prove_immutable_history_membership` | paging to the end does not prove that no row is missing |
| `no_account_funding_payment_ledger_or_settlement_coverage` | funding transfers carry no instrument, no stable ID and no settlement marker |
| `tpsl_records_do_not_expose_entry_parent_lineage` | not every TP/SL row names its parent order |
| `order_fill_stream_is_nonrecoverable_and_sdk_drops_publication_positions` | there is no recoverable, ordered fill event stream |
| `sdk_json_numbers_are_not_original_exact_decimal_wire_evidence` | SDK numbers are floats |

Those sources stay as they are. They describe what EVEDEX can prove on its own.

## What the owner accepted instead

The REST sources trade those guarantees for a narrower operating model.

1. **Single position.** An entry is admitted only on a flat account: no position, no
   open order, no live TP/SL, no non-terminal Kairos trade. Then every order and
   protection on the account is one that Kairos sent, and every funding payment while
   the trade is open belongs to that trade. Concurrent positions are not possible in
   this model. Closed-account reconciliation in this repository already requires a flat
   account, so the model matches it.
2. **Stable double read instead of an atomic snapshot.** The account verifier accepts
   the engine's reconciled `AccountSnapshotV2` only when two full REST reads, one before
   and one after it, agree on balance, positions, open orders and live protections. A
   change between them refuses the entry. This narrows the gap but does not close it: a
   change and its exact reversal inside the window would not be seen.
3. **Exact decimals from the original body.** All numbers are read through
   `ProductionEvedexReads`, which parses the original HTTP body with `Decimal` and keeps
   its SHA-256. This closes the float gap for these sources.
4. **Lineage from Kairos IDs.** EVEDEX order IDs are the deterministic client order IDs
   the engine sent. An open order is the entry if its ID is the trade's entry ID and an
   exit if it is the trade's close ID; any other open order on the instrument refuses.
   A live protection without a parent `order` refuses.
5. **No event stream.** `drain_events` returns no events. The engine uses events only as
   a supplement to the polled TP/SL list; a protection that disappears from that list
   stays unexplained and fails closed.
6. **Funding by time window.** Terminal funding is the sum of the account's
   `fundingRate` transfers from the first fill to collection. It is called complete only
   because of rule 1. `funding_complete=True` in `VenueTerminalEvidenceV2` is this
   model's claim, not a venue guarantee.
7. **Exit costs are owner parameters.** `RestLiveExitVerifier` takes the exit fee rate
   and the adverse slippage rate from its deployment; the exit-risk publisher applies
   them to the verified book.

## Early exits and stops

An early exit (`PRODUCTION-SESSION.md`) closes the position through the same reviewed
`TIMEOUT_EXIT` close the holding time uses, so the model above is unchanged: the close ID
is the trade's own and the protections are the original two. Moving a stop is not part of
this model; it would add a protection that the lineage rule (4) and the closed-account
reconciliation do not expect.

## What this does not change

- Risk Manager validation, account freshness (5 s), reconciliation failure handling and
  SystemMode restrictions all still apply; the sources only supply facts.
- Instrument rules are required (`require_instrument_rules=True`); they come from the
  original `instruments` HTTP capture.
- A refused or ambiguous step still blocks entries and needs recovery.
- Nothing here is evidence of production readiness.
