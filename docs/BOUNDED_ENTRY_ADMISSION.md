# Bounded DEV entry admission

Only technical canary `RiskTradeDecisionV1` messages may enter this PAPER path.
Public trading contracts and strategy fingerprints are unchanged. There is no
automatic alpha strategy, paid model/feed call, or LIVE enablement in this gate.

## Independent configuration

Set `KAIROS_CANARY_SCOPE_FILE` to an absolute path, mounted read-only. It contains
the non-secret `CanaryScope` JSON used by the read-only recorder and Risk session
runner: project, local environment/account, expected remote DEV account, exact
DEV exchange/auth URLs, chain 16182, SDK 1.2.11, configuration SHA-256 and recorder
code SHA-256. It is NOT loaded from the session row that requests admission.

The engine validates that this scope matches its independently configured account,
URLs, chain and environment. Receipt/session storage checks both fingerprints.
No file, malformed JSON, unknown fields, or a foreign scope blocks only new entry
admission. Existing trades can still reconcile, create protection and close.
Do not put signing keys, bearer tokens or the source API file into scope JSON.

## Durable boundaries

1. The persistence repository derives a receipt from stored database-timed,
   hash-chained observations covering all five symbols for 24 hours. A caller's
   `accepted=true` is never an admission receipt. Trusted live recording and
   actual venue qualification remain separate operational requirements.
2. The operator arms one global session per isolated PAPER database. Receipt age
   defaults to one hour and may only be configured stricter. One receipt can arm
   one session; restart never resets its limit of 10 attempts or two-hour deadline.
3. The existing Risk arm and attempt reservation commit in one transaction.
   Failed Risk decisions consume an attempt; only authoritative terminal state
   admits the next fixed slot. Requested scenario names are not coverage proof.
4. Execution binds the exact consumed arm, review, decision, trade and entry
   effect before it creates a new trade or prepares an entry effect.
5. After durable `PREPARED`, fresh venue/account/book and mutation-budget gates,
   a final session dispatch lease rechecks admission. It commits a unique claim
   BEFORE permitting the sidecar call. Journal ACK is retained within that lease.

Lock order for execution is account -> trade -> session dispatch advisory lock
-> short session/attempt row transaction. The dispatch advisory lock is a
session-level lock on a dedicated pool connection, retained across the bounded
external call. Stop takes its compatible transaction-level lock before the
session row, so it cannot race between final admission and dispatch. There is
no uncommitted database transaction spanning the venue call. The lease lasts
at most 30 seconds; release/cancellation never deletes its already committed claim.

Repeated/uncertain entry effects are reconciled, never blindly sent again.
Session expiry/stop does not authorize recovery re-dispatch: only existing
exact effects, positions and protective orders can be reconciled or closed.
SL/TP/timeout and compensation do not acquire new-entry session permission.

## Verification and remaining operations

Unit tests cover scope mismatch, safe failure before PREPARED, final refusal
after PREPARED, claim/call/ACK ordering and late redelivery. The existing lifecycle
suite injects a clearly labelled admission fake while retaining its real journal.
`test_integration_canary_execution.py` instead uses real session/arm/journal
repositories and a fake venue. It is part of the standard guarded PostgreSQL CI
suite, not a real trading test or a qualification receipt.

For local Linux verification, build `tests/Dockerfile.integration` from the
repository root. Its narrowly allowlisted context excludes `.env`, secrets,
Git history and local environments. `uv sync --locked --no-editable` resolves
the committed dependency SHAs; the final image contains only installed packages
and tests. Supply an explicitly guarded disposable execution database to pytest,
never a production or deployed PAPER database. This image does not start services.

Actual read-only recording, accepted five-symbol scenario coverage, a bounded
armed DEV session and seven full days of soak must still be established from
real observations. Neither passing tests nor exhausting a session sets
`PAPER_QUALIFIED=true`, `ALPHA_READY=true` or `LIVE_READY=true`.
