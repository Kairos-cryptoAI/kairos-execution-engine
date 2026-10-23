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

## Compatibility and limits

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
