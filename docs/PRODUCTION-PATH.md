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

### Explicit technical canary, not full research qualification

`technical_canary_readiness.TechnicalCanaryPreconditionsVerifier` is a separate
fixed seven-gate profile: recovery, security, custody, delivered alerts, global
operator control, PROD account pairing and signed production limits. It retains
the independent issuer pin, original signed proofs and exact account/source
scope. It does not label alpha or LIVE readiness as established. The full
production verifier still requires its existing research and other gates.

`technical_canary_service.start_technical_canary_service` rechecks those exact
proofs and a current owner-signed arm before consuming its nonce in the same
isolated durable claims store as the existing production runtime. A refused,
unknown or expired nonce commit cannot be retried or released. This opt-in
deployment API starts the existing driver, not a second runtime implementation.
It permits at most one candidate admission per signed session, within at most
600 seconds, and binds every envelope to that exact signed arm. Even a no-entry
result consumes that admission. This is not a global account-flatness assertion:
authoritative recovery, current account exposure and all existing Risk gates
still apply independently.

Entry expiry leaves protective lifecycle/reconciliation maintenance available;
it is not a forced close or a claim of successful shutdown. Recovery blockers
remain blockers. No owner arm, real venue qualification, keys, account facts or
operational receipts are manufactured by this API. No settings-driven LIVE
fallback is enabled. A synthetic startup test is not a real-money acceptance.

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
to fixed GET sources: account identity, order/TP-SL pages, funding balance,
available balance, positions, open orders, instruments, depth and explicitly
requested fills/funding-transfer history. It retains the decompressed
application response body before JSON
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

### Native PROD reader and authenticated instrument rules

`ProductionEvedexReads` now supplies the existing lifecycle read DTOs through
the actual PROD SDK client. The managed adapter requires its exact client to
be the same one used by the signed transport, with the same account/context.
The balance projection mirrors the existing SDK mapping from native `position`
and `openOrder` arrays, without replacing missing summaries with zero/empty data.
It retains exact decimals, native currency and original bodies separately.

Per-order fills and explicit fill/funding-transfer pages use documented fixed
GET paths. History intervals are explicit UTC milliseconds, bounded to 24 hours;
these page methods do not automatically run on every lifecycle poll. Funding
rows have no fabricated provider IDs, trade links or finality. Native TP/SL
records are not relabelled as entry-parent evidence. REST reads do not establish
a recoverable event stream: `drain_events` explicitly refuses instead of
returning an invented empty list.

The PROD HTTP boundary now enforces the existing `LocalMutationBudget` before
every actual POST/DELETE. A failed/unknown request consumes its slot; reads,
preflight and replay never refund/reset it. `read_health` reports this actual
counter, not an assumed venue quota. Authentication age derives from the exact
successful original user-info HTTP capture. Venue quota/expiry may remain
unknown. The separate durable account-scoped FSM budget is preserved.

An optional signed `EVEDEX_INSTRUMENT` stage joins the exact original HTTP
metadata capture to the upstream-input envelope. The registered verifier
derives the Risk instrument rules from those bytes, exact symbol and original
clocks, rather than accepting a caller's rules DTO. The PROD Risk builder
requires this stage. Risk rounds quantity down by the actual venue increment,
checks minimum/maximum quantities/notional and immutable entry/stop/target tick
geometry before constructing the decision. It never repairs an already
reviewed intent or rounds an already approved order. Captured metadata remains
fresh for at most five seconds; `updatedAt` is retained as the rule revision
time, not retimed as a fetch clock. The FSM independently joins its current
metadata projection back to original captured bytes and receipt freshness.

### One explicit assembly, with accounting fixed into the path

`production_assembly.build_production_assembly` constructs the existing concrete
read, Risk, cancellation, exit, lifecycle, coordinator, reconciliation-v2 and
accounting components from explicitly supplied pre-provisioned resources. It
checks shared context, database UUID, pools/roles, clock, symbol map and required
instrument rules before I/O. Its only start method delegates to the existing
seven-proof manual technical-canary entry; a synchronous one-attempt latch
prevents concurrent starts or retry/adoption after cancellation/failure.
Running waits for stop and closes that already-started driver without starting
it twice. Terminal reconciliation goes through the driver's account lock with
the attached accounting store mandatory; it cannot silently omit reservation
release accounting.

Actual-constructor tests use synthetic pool/provider handles and no I/O. This
assembly does not provide the still-unqualified account/exit/cancellation/terminal
source implementations, provision databases, register producers, select a
strategy, start a source consumer, mint safety receipts or arm a real account.
The ordinary LIVE CLI/Compose rejection is unchanged. Real private-event
authentication/recovery, fee/funding finality and current signing-domain and
order-semantics acceptance remain external source-contract requirements.
In particular, [official order documentation](https://docs.evedex.com/developers/developers/order_creation)
describes limit orders as GTC and says that this cannot be changed via API.
The PROD Python and SDK-sidecar mutation boundaries now refuse the existing
IOC-limit payload before invoking the SDK. They do not translate it to GTC or
market IOC; this closes an unsupported dispatch path, not the broader
order-semantics or LIVE-readiness gate.

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

### Canonical host and captured-input preparation

`production_host.build_production_host` is the single construction front door
for the same concrete resource graph. Construction performs no I/O or startup.
The explicit seven-proof/owner-arm start is still one-shot; a changed arm,
cancelled or unknown attempt cannot replace the driver. The host admits at most
one original envelope, bound to the exact manual arm, and latches the actual
driver's entry interlock closed on provider, worker or accounting uncertainty.
Public worker-health fields distinguish live maintenance from a stale `started`
flag. Surviving protective maintenance is not stopped just because entries close.

After its exact owned trade naturally reaches the native terminal `FLAT` state,
the running host polls only its fixed registered terminal source. An explicitly
typed, bound `PendingTerminalEvidence` permits bounded read-only waiting; it is
not terminal evidence and cannot release a reservation. The first final proof
goes through the existing independent reconciler and accounting exactly once.
Unknown completion stays fenced; there is no force-close, new arm, alternate
source retry or automatic capital increase. Shutdown is bounded and unresolved
cleanup is reported, not relabelled as a successful restart.

`production_native_producer.NativeProductionInputPreparer` now joins the existing
capture/session projectors, native Text/Router/review/context output and the
existing unsigned input-envelope preflight. It selects exact retained RSS,
EVEDEX instrument/depth, Binance depth and causal Macro input/output identities.
It derives PROD venue quality through the existing Quant calculation from the
actual selected book pair, persists that calculation with both raw parent
digests, and never converts a DEV measurement into PROD. Existing thresholds
and original intent, source, review and two-second execution clocks remain.
Model evidence must be the original persisted budgeted call pair; caller capture
times are not trusted. The result is **unsigned**, unregistered and non-authorizing.

The public Binance adapter performs one fixed bounded unauthenticated depth GET,
retains the exact original body and request/receive clocks through the existing
create-only sink, and uses the original T/E source timestamp. No exchange/account
credential is accepted by that adapter. Macro's new opt-in capture retains exact
application context and allocation, with a stable source/message processing key
claimed through the existing durable processing repository before model work.
Capture/completion failure never releases or resets the claim/budget hold.
Application context is not an official macroeconomic HTTP feed: unavailable
macro/onchain factors stay unavailable. Native model output is joined back to
the exact original context prompt and native response transform.

These APIs do not solve the remaining real source admission. Raw market/bar
authentication, independently accepted producer identity, account/exposure,
protective lineage, fee/funding finality, real private-event recovery and accepted
PROD signing/order semantics remain required. No default LIVE CLI/Compose route,
database, consumer, retired CURRENT owner, real order or paid model is activated.
Strategy selection is deliberately not part of this wiring change.
