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

An ordinary complete negative LIVE Risk evaluation returns
`ProductionLiveEntryRefusal` through the coordinator and service, before any
Risk/binding append or engine call. VETO, defensive allocation, exhausted risk
or unavailable verified inputs are no-entry outcomes, not unknown execution
effects. The original envelope identity remains fenced; only a genuinely new
candidate may be evaluated later. Only the exact reviewed publisher, evaluator
and coordinator implementations may attest this no-effect branch. Scope
substitution, malformed evaluations, unknown writes, cancellation and transport
effects still latch admission closed and require recovery; a subclass cannot
write and then hide its outcome as a safe refusal.

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

`production_native_inputs` is the narrow native-call linkage prerequisite. Its
reader consumes the original create-only `kairos-llm` application-boundary
`ATTEMPT_STARTED` and `COMPLETED` records, not reconstructed `LLMResult` objects.
It joins the exact attempt digest, schema/prompt/reply bytes, requested/resolved
model, original provider clocks and original RESERVED/COMMITTED budget identity
and amounts. The provider `cached` flag still denotes input-token caching, not
whole-response reuse. Four optional envelope stages retain both native records
and the exact existing prompt/reply representation. When those records are
present, the envelope independently verifies their full join and rejects reused
call/reservation/request identities. Existing legacy fixtures are not upgraded
to native captures by adding this adapter.

`prepare_native_input_envelope` consumes an already retained canonical capture
manifest plus those original call-record pairs. It preserves source/native
stage bytes and clocks, binds each model call to its exact emitted output, and
returns an **unsigned** preparation. Only an external producer may sign
`native_input_signing_bytes`; `verify_signed_native_input_envelope` finalizes it
through the actual independently pinned `LiveInputsSourceVerifier`. Neither
operation reads or creates keys, performs I/O, registers a producer, refreshes
a lease, or calls a model. The resulting signed proof is the existing publisher/
coordinator input, not new owner/account/operator authority.

`NativeUpstreamComposer` invokes actual native RSS, Text preparation/extraction,
Router policy/window, context store and candidate
review components. It requires original source/extractor capture sinks and
actual `BudgetedLLMGateway` instances retaining original call records through
`NativeLLMCallSinkAdapter`. It does not construct a provider client, connection,
strategy intent, account, route override or trade geometry. One native pipeline
is admitted at a time; the existing durable processing-claim seam fences the
intent before source/model work and selected news before Text dispatch. Unknown
or cancelled calls remain claimed, their reservations remain outstanding, and
no blind retry, release or timestamp renewal is performed. A shared native
capture/review clock and original intent deadline bound the whole invocation;
cancellation interlocks are checked around asynchronous work and persistence.

Fresh Macro work is refused before claims/source/model work when supplied to
this same-intent composition: an allocation created after the original event
cut cannot become causal by changing its timestamp. Only the actual context
store's previously retained eligible Macro observation is projected, with exact
native payload/digest/identity and its original receipt; otherwise allocation
remains unavailable/None. `MACRO_CONTEXT_SELECTION` is an explicit selection
witness, not a new Macro output or a model-call completion. A full source
projector must join that selection back to the original retained Macro
source/model/persistence witnesses, potentially from an earlier session; it
must not bind a current call or renew its receipt time. Native Macro preparation
can still occur separately through its existing component, not this entry path.

News is additionally cut at the unchanged original intent event time before
Text dispatch. Native Text signal time remains the original article publication
time (maximum over its exact input evidence), not extractor completion time.
Post-intent news remains captured but does not spend Text budget for an input
that the native Router would necessarily exclude. No intent, trigger, review
deadline, source TTL or later two-second execution quote/reference is refreshed.

The optional native Text capture seam retains original decompressed RSS response
bytes and native parse/extraction witnesses in the same session. The explicit
`production_native_text` readers verify original body/native-parser bytes and
native Text prompt/schema/result/call-record joins. Text output replay uses the
actual unchanged native model/fallback transform, with exact version-one
`items`/`signals` mapping wrappers and extractor identity; source, input, model
result and output substitution refuse. No persistence timestamp is
invented from a capture timestamp: the durable session store must witness its
own acknowledgement separately. Native Router/review/context output records are
emitted synchronously before a composition result is exposed. Review evidence
accepts the exact actual native combined sentiment/context references, not
arbitrary additions; legacy context-only engineering references remain compatible.

Market and closed-bar DTOs must already match exact retained observations in
the actual `CandidateContextStore`. Its read-only
`require_retained_observation` returns the original first-receive receipt and
refuses missing, evicted, quarantined, substituted, future or expired inputs
before composition claims, RSS work or model calls. Composition no longer
inserts those DTOs with its current clock. `MARKET_BAR_CONTEXT_SELECTION`
retains those original receipts; it is not a raw HTTP source witness or a new
delivery timestamp. The existing native source consumer must retain inputs
before invoking composition.

This does **not** close native capture qualification. Macro context, market/bar
and venue raw sources still need their independent complete source witnesses;
source/native session linkage and signed deployment acceptance remain required.
Passing caller-built DTOs or an old probe manifest to preparation cannot
establish that witness. There is no accepted producer or registration default,
and composition results remain `live_ready=False` / `REJECT_ALL`. Tests using
real native components and synthetic offline transport/model/budget fixtures
establish engineering traversal only, not provider or real-venue acceptance.
No real-source or paid-provider call is part of those tests.

## Automatic dollar budget proposals

The existing `LiveRiskEvaluator.propose_capital_budget` uses its registered
account verifier before calculating dollar ceilings. The pure proposal uses
the original fresh, reconciled LIVE/PROD account and scoped starting ceiling,
explicit bounded percentage policy and supplied venue minimum-notional metadata.
Stop risk and aggregate notional are separate limits: `aggregate_dollar_cap_usd`
caps portfolio notional, while `aggregate_open_risk_fraction` caps stop risk.

Amounts round conservatively; smaller balances shrink ceilings, and deposits or
profits cannot implicitly raise the scoped starting cap. Unknown/stale account
facts and amounts below actual venue minimums refuse. A synthetic $50 example
passes through the actual evaluator in offline tests; it is not a balance or
venue qualification claim. The result is `NON_AUTHORITY_PROPOSAL`: no verifier
registration, scope mutation, reservation, manual arm or order is created.
Changed limits require an independently admitted scope and fresh account
verification. The pinned EVEDEX verifier still refuses unqualified account facts.

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
