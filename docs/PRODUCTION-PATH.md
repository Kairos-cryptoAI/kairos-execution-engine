# Unified LIVE Risk and protective lifecycle

`ProductionLiveLifecycleCoordinator` is the explicit composition API in
`kairos_execution.production_path`. It requires the existing concrete LIVE Risk
publisher, production engine, managed runtime and a configured per-effect exit
Risk stager. It does not select a service, arm LIVE, create an owner signature,
or qualify an exchange source.

## One path, unchanged authority boundaries

1. Verify the supplied owner-signed arm against the runtime's independently
   pinned public owner key, context and time bounds. Derive its digest; no
   caller-provided digest is accepted as authority by the coordinator.
2. Invoke the actual `LiveRiskEvaluator` through `ProductionLiveRiskPublisher`
   with raw account and upstream-input proofs. Stage request-bound ENTRY Risk
   and its create-only lifecycle binding. Verified input and account timestamps
   cap the five-second proof lease; quote/book/reference each retain their
   two-second cap. No observation timestamp is refreshed by composition.
3. Independently inspect persisted owner/operator/Risk/exposure authority, then
   invoke the existing protected FSM. The FSM owns account/trade locks and
   rechecks authority before signing and one-shot dispatch.
4. Only a **new** journal `PREPARED` for SL, TP, timeout or emergency close calls
   `ProductionPreparedExitRiskStager`, before mutation budget reservation or
   adapter dispatch. Cached effects return without restaging; ambiguous existing
   PREPARED effects require authoritative recovery and never get a new lease.
5. Capture bounded raw exit evidence through a mandatory registered provider;
   the independently configured verifier authenticates exposure and economics.
   The concrete exit publisher derives owner provenance from the immutable
   original ENTRY binding, computes a separate per-effect Risk decision and
   persists exposure, Risk, then passive binding. Entry approval is never reused
   as exit approval. The original ENTRY arm may have expired: accepted original
   ownership is historical lineage, not renewed entry authority.
6. Recheck scope and deadlines after asynchronous writes and independent
   authorization. Then the normal adapter/signing/dispatch checks still run.
   SL precedes TP; failed protection can attempt only a separately authorized
   emergency close. If that source also refuses, the journal remains unresolved
   for recovery instead of inventing an exit approval.
7. Delegate recovery and closed-account reconciliation to the existing engine.
   Fresh state-v3 accounting releases reservations only after exact independent
   terminal/account evidence, once; a transport ACK is never a fill or release.

Runtime, stager and FSM share the same explicit clock callable. When the FSM's
clock argument is omitted it adopts the configured stager clock; a divergent
runtime clock is refused. The stager's callback must not call the FSM's locked APIs (`handle`,
`reconcile_once`, `account_snapshot`) or acquire its account/trade locks. Database
read/write adapters retain separate roles and short transactions. The journal's
atomic new-PREPARED result is the cross-process admission boundary; the local
attempt set is only an additional no-retry guard, not a signing claim. Failed or
unknown source captures/writes remain evidence and cannot be blindly renewed.

Fresh writer-contract validation batches the exact role/table privilege matrix
into one uncached SQL read on each authorization snapshot. No permission check
is omitted or reused between snapshots. Cancellation capture freshness is
checked against monotone post-I/O time, not a clock taken before lineage reads;
the source observation time, five-second cap and final pre-operation recheck
remain unchanged.

For a new PREPARED SL/TP the publisher derives its deterministic client ID from
the original decision; the confirmed trade association may still be unset.
Foreign IDs refuse. PROD redelivery of an existing non-RECEIVED trade checks
the exact durable canonical decision/chain and startup recovery, then uses the
existing recovery path without renewing the old entry quote. New/RECEIVED
entries still require fresh market evidence; this does not change PAPER.

## Explicit upstream verification composition

`build_opt_in_production_live_risk_evaluator` in `production_input_risk`
constructs the actual Risk evaluator with `LiveInputsSourceVerifier` and the
fixed, fail-closed EVEDEX account verifier. Scope, limits, producer trust policy
and a dedicated Ed25519 public key are mandatory constructor inputs; nothing
is registered or activated by default. This composition is available to the
existing `ProductionLiveRiskPublisher`, not a new trading service.

The bounded producer envelope binds the exact native Router/review,
`DecisionContextV1`, Text output, separate raw Macro source/allocation, original
source clocks, provider prompt/response and reservation identities, PROD venue
quality and its two market-source receipts. It checks exact bytes/digests,
signature, scope, native context/evidence identities and original freshness.
Text retains its native 30-minute source / 10-minute planning limits, while
venue/book/reference each retain the two-second execution cap. The envelope's
five-second lease never refreshes an upstream timestamp. Explicit unavailable
fields remain unavailable; an absent required source refuses authorization.

A signature authenticates only the independently trusted capture process's
statement, not a provider signature, profitability, account truth or LIVE
authority. There is still **no qualified, registered real capture producer**
in the default service. A caller signing hand-built DTOs or old source probes
is not qualification. A producer must retain the actual native boundary's
original bytes, receipt clocks and uncached model/budget records and undergo
independent acceptance before deployment may register its dedicated identity.
Observed-SIM intents remain SIM-only. The new composition/negative tests use
explicitly synthetic fixtures; they are not a real-source or venue E2E pass.

## Compatibility and limits

### Explicit service runner and cancellation boundary

`factory.build_production_service` now builds `ProductionServiceDriver` only
from the explicitly assembled coordinator above. `service.run_production_service`
runs that driver with a stop event; it never selects the legacy adapter or its
null signer. The settings-driven CLI still refuses LIVE. Missing deployment
admission defaults to `REJECT_ALL`; a callback is only an additional interlock,
not a replacement for account, owner, operator, Risk or signing authorization.

The driver performs recovery before admission, serializes account work, bounds
its queue, time limits and process-local identity fence, and delegates maintenance
and closed-account reconciliation to the existing coordinator. Its status never
claims readiness. A maintenance error latches entries closed; a later successful
poll does not clear that latch. Service-local entry blocking does not bypass an
underlying recovery-blocked FSM or guarantee that such an FSM can execute exits.

Cancellation is rechecked under the account lock and at the coordinator's
pre-Risk, post-staging and post-authority/pre-engine boundaries. Caller timeout
or cancellation interrupts the worker. An effect already sent or a signer worker
already running may have an unknown outcome: partial proofs/claims are retained,
not renewed. Bounded shutdown reports unresolved tasks instead of claiming clean
completion or allowing a replacement. Envelope IDs are process-local only;
the existing durable trade/effect/signing identities remain restart fences.

The native PostgreSQL production-path test now exercises both direct coordinator
and service-driver paths through partial fill, separate SL/TP/timeout Risk,
flat-account proof and one-time accounting release. The account/venue/signing
facts in that test remain explicitly synthetic, not EVEDEX acceptance.

### Original response bodies, without account-authority promotion

The pinned PROD sidecar has a separate `fetch_raw_capture` operation restricted
to four fixed GET sources: account identity, order page, TP/SL page and funding
balance. It retains the decompressed application response body before JSON
number conversion, exact route/query, original request/receive clocks, HTTP
status and SHA-256. It does not retain headers or credentials. The body limit
is 2 MiB within the existing IPC limit; redirects, proxying and retries remain
disabled. Already-parsed objects cannot be relabelled as original bytes.

Python validates the bounded capture and parses numbers as Decimal without
discarding their original bytes. Non-2xx captures cannot be returned as a
successful account source. Existing parsed SDK methods stay compatible. These
bytes do not prove complete fills, account consistency, funding-payment coverage,
settlement finality, a signing domain, or producer qualification; the existing
history/exposure/account/exit verifier refusals remain unchanged.

Legacy manually assembled lifecycle callers may omit the stager, preserving
existing tests and PAPER behavior. The unified coordinator refuses that
configuration, so its exits cannot silently fall back to caller-staged Risk.
No new database migration, service, queue, paid-provider call or automatic retry
is introduced. Existing real EVEDEX account/exit verifiers still refuse their
unqualified SDK evidence. A synthetic registered verifier/backend is test-only;
it is not a production bypass or evidence of an actual account lifecycle.

All readiness flags remain false and policy remains `REJECT_ALL`. This API and
its isolated database acceptance establish engineering composition only, not
profitability, real-venue acceptance, or permission to place a real order.
