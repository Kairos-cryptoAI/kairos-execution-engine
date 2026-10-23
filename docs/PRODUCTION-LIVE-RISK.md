# Optional LIVE risk evidence composition

`kairos_execution.production_risk.ProductionLiveRiskPublisher` is an additive,
opt-in bridge from the concrete `kairos-risk-manager` LIVE evaluator to the
existing managed-signing evidence stores. It is not selected by a service or
factory, does not change PAPER/DEV defaults, and does not claim LIVE readiness.

## Flow and fixed boundaries

The publisher requires an actual `LiveRiskEvaluator`, the separated
`PostgresRiskStateWriter`, the existing append-only `PostgresLifecycleBindingStore`,
the exact custody/context/database scope, and a fresh state-v3 writer with
create-only exact replay. It also requires the caller to supply the observed
`SystemMode`; this composition is not an authenticated operator-state producer.
It requires raw account evidence and a separate raw upstream-input proof, then
calls the evaluator itself. The evaluator binds that proof to the actual review,
venue, allocation, system mode, context, and observation time; a digest alone is
not evidence. There is no input for a caller-approved Core decision or an
approval boolean.
Rejected decisions, SIM intents, stale/unverified account facts, strategy or
scope mismatches, and incomplete economic metrics fail closed.

For an approved decision it derives the same deterministic ENTRY lifecycle
effect/client ID used by `ManagedProductionLifecycleAdapter`, constructs the
existing lifecycle binding/request, and maps only that request's validated
integer quantity, price, side, instrument, and signing-effect digest into
`RiskGeometryV1`. Equity, daily adverse loss, aggregate open risk/notional, and
source/account proof digests come from the evaluator's verified-account result;
they are not guessed or defaulted by this bridge. The risk lease cannot exceed
five seconds or the Core intent and verified-account evidence windows. Quote,
book, and reference observations each impose a hard two-second freshness cap,
in addition to the venue-provided expiry.

It writes the risk row and then the passive lifecycle binding. If the second
write fails, a risk row may remain without a plan; the lifecycle adapter refuses
the missing plan, so no order is authorized. Persistence ambiguity is reported
as unresolved and is not a retry instruction. A stage receipt records the full
evaluation/provenance, the deterministic binding, the exact typed risk record,
and whether the binding was newly inserted.

No signer, wire dispatcher, trade engine, service, owner arm, operator state,
readiness record, or network client is constructed or called by this module.
Staging is not signing authority, deployment evidence, account acceptance,
profitability evidence, or a claim that an order was sent.
The later managed runtime still requires independent current owner and entry
operator checks, including the entry KILL state. Each protective/exit effect
needs its own exact risk and exposure evidence; entry approval is never copied
to exits. Existing KILL/DISARM semantics stop new entries, not already-owned
risk-reducing exits. This is not evidence of a separately qualified global
wire cutoff.

## Current EVEDEX account-source boundary

`PinnedEvedexLiveAccountVerifier` adapts the existing bounded pinned-SDK history
capture only far enough to verify its source and exact account/context. It then
calls the shared fixed `require_exposure_write_authority` refusal before it could
return a `VerifiedLiveAccountV1`. Current history pagination does not establish
the atomic account/open-order snapshot, stable historical membership, complete
funding/accounting, or exact original wire facts required to authenticate equity
and aggregate-risk inputs. Therefore this adapter always refuses current real
captures; it invents no balances, reservation totals, daily losses, or exposure.
Synthetic registered verifiers are suitable only for isolated tests and are not
production-source evidence.

The current independent Risk writer rejects a duplicate signing request unless
the full persisted payload is an exact replay. An unresolved commit remains
unresolved: do not blindly retry it. The binding store is still passive and the
managed runtime independently rechecks current authority before any later
signature or wire operation.
