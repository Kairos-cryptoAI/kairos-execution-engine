# One automatically armed production trade

Production entry is suspended following a verified EVEDEX full-position take-profit
that sold into an existing short and increased its size. An active trigger, its
parent order and a matching position generation established registration but did
not constrain the direction of the child market order. The production API exposes
no reduce-only field on this trigger. Requalification requires venue evidence of
position-reducing execution for both sides, including partial fills and a position
closed before the trigger fires. Account reads, cancellation and the explicitly
signed position-close endpoint remain available.

Status: built 2026-11-13/14 for the live runner (`kairos-autotrader`, `executor =
"execution_engine"`). Code: `kairos_execution/production_session.py`,
`kairos_execution/production_session_cli.py`, `kairos_execution/production_report.py`.
Nothing here is evidence of production readiness; the seven technical-canary receipts
are still required before the host starts.

## What one session does

1. **Arm.** `AutoArmSigner` signs a manual-arm record with the owner's arm key for at
   most ten minutes. The arm carries exactly the owner's signed limits; a candidate can
   only lower the per-trade risk fraction (`candidate_limits`), never raise it. The
   operator latch (`OperatorLatch`) goes ARMED; KILLED, set by the owner, refuses it.
   Leaving KILLED requires the separate provisioned database-owner LOGIN; the ordinary
   operator role cannot resume or arm directly. Resume consumes the exact KILLED version
   and command digest and leaves DISARMED, never ARMED.
2. **Start.** `build_production_host` composes the production path once; the host checks
   the seven receipts, the custody binding and the transport preflight.
3. **Entry.** Inside the entry provider: two full REST reads of the account (flat, see
   `REST-SOURCE-TRUST-MODEL.md`), a fresh PROD `VenueQualityV1` from Quant Scouts
   (`kairos_quant.venue_now`, five-second life), the inputs with the instrument rules,
   a fresh operator state, then an envelope that expires at the earlier of four seconds
   and 20 ms before the two-second quote window ends. The Risk Manager decides; the entry
   is a bounded `LIMIT_GTC` order cancelled at the envelope's expiry.
4. **Disarm.** The latch goes DISARMED right after the entry attempt. Exits do not need
   an arm.
5. **Life of the position.** The shared lifecycle engine places the stop-loss and the
   take-profit, reconciles, and exits by the stop, the target, the holding time or an
   early exit (below). Terminal evidence is collected within a ten-second settle grace and
   accounting is accepted.
6. **Answer.** One JSON line: `outcome` (`CLOSED_AND_ACCOUNTED`, `REFUSED`, `UNRESOLVED`),
   `trade_id`, `detail`; after a closed trade also `r_multiple`, `exit_reason`,
   `early_exit` and `net_pnl_usd` from the closed-trade journal, or `report_error`. Exit
   codes: 0, 3, 4, and 2 for a refused configuration.

```
python -m kairos_execution.production_session_cli --config session.json --candidate candidate.json \
    --exit-request candidate.exit-request
```

## Owner setup

`kairos_execution.production_setup` prepares everything a session needs from the owner's
keys file, under one root (`D:/Kairos/runtime/execution-prod` by default):

```
python -m kairos_execution.production_setup init --keys-file keys.txt --owner-telegram-id <id> --runner-config config.json
python -m kairos_execution.production_setup drills
python -m kairos_execution.production_setup security-review --reviewer owner --fix-commit <reviewed-fix-commit> --findings-fixed 4 --statement "..."
python -m kairos_execution.production_setup alert-drill --token-file keys.txt --chat-id <test chat>
python -m kairos_execution.production_setup refresh
```

`init` writes the wallet key into an encrypted keystore and a backup keystore with random
unlock files, and the API key into a single-key file, all private; nothing secret is
printed. The two alert acknowledgments are the owner's own taps in Telegram. Receipts
live at most 24 hours; the live runner calls `refresh` before every session.

## Early exit

`--exit-request` names a file the runner writes when it decides to close the position
before its holding time: a newer Macro regime that opposes the position, or a managed
stop that the market crossed. The session reads it on every poll; the first reason it
finds calls `request_early_exit` on the lifecycle engine. The engine then closes the
ACTIVE trade at market through the reviewed `TIMEOUT_EXIT` path with its own exit-risk
staging. The protections stay until the close and are cancelled after it. The reason is
journaled with the `EXITING_TIMEOUT` transition and reported as `early_exit` on the
closed trade (`production_report`). An early exit can only shorten a trade: it never
widens a stop, adds exposure or bypasses reconciliation.

The reader accepts only a bounded first line from a regular non-link file. Invalid
encoding, oversized input and file errors are ignored without stopping maintenance of
the current position; a later valid request can still close it.

## Owner-only stop recovery

Fresh databases install the owner-only guard as an ALWAYS trigger. Runtime inspection
refuses an old, disabled, rebound or altered guard. Updating source does not modify a
retained database or clear its stop automatically. The owner can explicitly upgrade
only the recognized historical v2/v3 guard using protected owner-role credentials:

```
python -m kairos_execution.production_operator upgrade-guard --manifest manifest.json
```

Operator observation inserts require PostgreSQL `READ COMMITTED` isolation. A retained
`REPEATABLE READ` or `SERIALIZABLE` snapshot could otherwise hide a newer KILLED command
even after acquiring the advisory lock. Such inserts are rejected at the database
boundary, including direct SQL writes and same-version ARMED refreshes.

Entry authorization and operator writes require the current guard. Protective exposure
and exit-risk publication, close/SL-TP signing, and historical cancellation provenance
remain independent of operator permission during the explicit upgrade. Their existing
database identity, role, ownership, privilege and evidence checks still apply.

Resume requires the version and digest of the KILLED command the owner reviewed:

```
python -m kairos_execution.production_operator resume --manifest manifest.json \
    --expected-version 7 --expected-command-sha256 <exact-killed-command-sha256>
```

The version above is an example. A stale or repeated resume refuses. These commands
neither create an arm nor start trading; existing protection and exits remain separate.

## Stops are not moved on this path

The protections are exactly the entry's stop and take. Moving a stop would add a third
protection on the venue and then cancel the original; the REST lineage rules, the
cancellation verifier and closed-account reconciliation all assume the original two.
Changing that is a change to `production_exit_risk.py`, `production_cancellation.py`,
`production_rest_sources.py` and the trust model, and belongs to the independent security
review. The runner therefore keeps the hard plan stop here and applies any measured
management policy as a soft stop through the early-exit request.

## Checks

- `tests/test_integration_rest_session.py` provisions an isolated database, issues
  stand evidence and runs three sessions against a venue double with a test EIP-712
  key. Each take-profit, stop-loss and early exit reaches terminal accounting and
  the closed-trade report. Set `KAIROS_REST_STAND=1` and point
  `KAIROS_REST_STAND_ADMIN_DSN_FILE` to a file containing the admin DSN for a
  disposable PostgreSQL server. The setup and recovery drills also use
  `KAIROS_REST_STAND_CONTAINER` for that server's Docker container name.
- `tests/test_integration_paper_engine.py`: the early exit on the shared engine with a
  disposable database.
- `tests/test_production_session.py`, `tests/test_production_session_cli.py`: arm limits,
  the latch, the candidate limits, the exit-request reader and the answer's journal fields.

## For the security review

The review should cover, at least: the arm signer and its ten-minute bound; the operator
latch and its owner-only resume; the entry envelope's expiry against the quote window;
the REST sources under the single-position trust model; the early-exit request (a file
the runner writes, read as a reason string of at most 200 characters, which can only
close); and the custody path (the encrypted keystore child and the wire signature
verifier).
