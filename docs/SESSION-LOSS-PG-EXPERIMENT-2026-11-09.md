# Experimental $5 PostgreSQL session latch

**Research only; no LIVE authority.** The EVEDEX verifier always rejects.
The optional flag defaults off and is not wired to the production builder.
The separate static entry fence remains necessary and must not be disabled on
the basis of this code or its tests. No exchange signing or order is involved.

`production_session_loss` defines a versioned append-only PostgreSQL journal.
Its transaction lock shares the account-scoped reservation lock. A trigger
rejects updates, deletion, truncation, sequence gaps, baseline/session changes,
STOP-to-ACTIVE transitions and ACTIVE observations already beyond the limit.
For newly provisioned tables, database constraints also reject `NaN`, positive
or negative infinity in every monetary field and infinite observation timestamps.
Changing the development DDL does not migrate or validate an existing schema;
any future deployment requires an explicit reviewed migration.
Session loss is baseline equity + change in cumulative external net deposits
minus current equity. A $25 deposit followed by equity of $120 from a $100
baseline is therefore a $5 loss; deposits, process restart and account recovery
do not clear STOP. Replayed identical observations do not append an event.

`reserve_entry_async` can opt in to verifying a source and appending a session
decision inside its existing transaction, before either new or reused entry
reservation. STOP returns from the callback, commits, then raises the refusal;
raising in the callback would roll STOP back. The independent
`observe_session_loss_async` method records observations without a candidate.
It is an API only; no scheduled observer or source is currently wired to it.
Existing reservations are conservatively refused in this experimental mode.
Candidate checks after an ACTIVE observation run inside a savepoint: on an
exception, the original exception is suppressed only if savepoint rollback
completed. Candidate effects roll back, the observation commits in the outer
transaction, and the outward refusal is raised only after commit. A different
exception during savepoint cleanup aborts the outer transaction. An unexpected
candidate failure receives an operational refusal and must not be retried blindly. A
database or commit error still makes the entire outcome unknown; callers must
reconcile without blindly retrying. Source observations lost before this
transaction (including earlier request validation failures, database outages,
or an unknown commit) can cause a sequence gap. This prototype fails closed
on that gap; complete recovery/replay against an independently anchored source
is not implemented.

Reservation uses a separate typed `QualifiedSessionObservationSource.resolve`
contract under its account lock; `ProductionSigningEvidenceV1` itself is not
a session observation. The only concrete registered source currently always
refuses. A protocol implementation or a syntactically valid observation is
not evidence of source qualification.

For a new reservation, projected loss is observed session loss (floored at zero)
plus *incremental* remaining risk from the current mark for all existing open
positions and pending reservations plus the new order's risk. It refuses
projected loss over $5; existing 0.25% per-trade and 1% aggregate limits remain.
Observed equity must already include realised and unrealised PnL, applied fees,
and funding. The future verified source must additionally include all as-yet
unreflected exit fees, funding and other costs in incremental risk, with no
double counting and with a coherent link to the reservation ledger. No value
for missing costs is defaulted to zero. The source contract requires an explicit
remaining-risk value, but the type alone cannot prove that it is complete.

The opt-in PostgreSQL test uses the actual `_StateDB._write` and real
`reserve_entry_async`, a disposable isolated PG, and synthetic records; it
monkeypatches account verification and claims inspection. It demonstrates a
breached STOP is committed before denial, survives reconnect and recovery,
and cannot be removed by update/delete or changed to ACTIVE by a direct INSERT.
It also covers a stale-risk refusal after an ACTIVE observation, and a
deliberately rejected outer commit with no synthetic reservation. This is a
known commit failure, not simulation of a lost commit response.
These are not proof of an exchange account or end-to-end production admission.

Before a live session this schema needs a reviewed provisioner, owner/role and
ACL inspections, immutable external anti-rollback anchoring and recovery,
qualified source binding to fresh account balances/fills/transfers/fees/funding,
reservation lineage and protective exposure, and an actively running observer.
Old workers and already reserved, signing or dispatched entries must be fenced
using a shared, qualified custody/outbox mechanism; an optional Python check
cannot stop them. Current schema provisioning and tests use a privileged local
test user and must not be copied into production. No synthetic verifier or
locally inferred free balance may be promoted into live authority.
