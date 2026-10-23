# Explicit managed production lifecycle

This is opt-in engineering composition, not a running PROD service or real-money
acceptance. `ExecSettings` and the default factory still refuse LIVE. No wallet,
credential, owner arm, readiness flag or research gate is created here.

## One path, existing components

`ProductionLifecycleEngine` reuses the protected EVEDEX lifecycle implementation:

1. A canonical Core LIVE/PROD `RiskTradeDecisionV1` must match the exact adaptive
   system/revision, account, instrument map, 1x policy and fresh venue evidence.
2. `PostgresLifecycleBindingStore` associates the original decision/trade and
   durable lifecycle effect with one exact managed signing request. It uses the
   existing audit repository, stable advisory locks and INSERT/SELECT privileges.
   Candidate storage is not independent Risk approval. Missing candidates or
   missing independent Risk/operator/exposure records refuse the request.
3. `ManagedProductionLifecycleAdapter` rebuilds that association against the
   actual PREPARED effect and original immutable decision. It exposes only the
   existing SDK adapter's read methods; its wallet mutation methods are not used.
4. The existing managed runtime independently checks owner/operator/Risk state,
   reserves entry risk, claims signing once, signs, checks authority again and
   claims the exact wire operation once. Unknown outcomes are never resent.
5. The native FSM validates the ACK, observes actual fills, protects partial
   exposure with SL before TP, cancels only the remaining entry quantity and
   recovers from the existing trade/effect journals. An ACK is not a fill.
6. Venue stop/target facts win over a competing timeout. Direct close still
   requires positive, bounded remaining exposure. Protection quantity zero means
   the whole currently owned position, not permission for a zero-sized entry.
7. `reconcile_closed_account` joins durable FLAT, account-wide reconciliation and
   the independent `ProductionReservationReconciler`. A registered venue verifier
   must establish complete fills, exact parents, costs and zero residual/unowned
   position/order/protection state. Empty account projections alone cannot do it.

PAPER retains its original fixed DEV constructor/policy. PROD is not a caller
option on `PaperExecutionEngine`, and the default service does not select the new
composition. Frozen campaigns, strategy/evaluator code and primary queues are
unaffected.

## Signing, wire and cancellation identities

Lifecycle effect IDs and signing effect IDs are distinct and explicitly stored.
The latter binds the full original request geometry and parent metadata. A
create-only plan cannot renew its deadline or replace an already claimed attempt.

The signed EIP-712 quantities/prices use exact 1e8 integers. REST values are
separately derived as canonical decimal strings, matching pinned SDK 1.2.11,
exchange-crypto 1.1.0 and exchange-api 1.0.70. Fixed unsigned limit `IOC` metadata
is included in the wire claim; false `postOnly` is omitted. No arbitrary extra
wire fields, float rounding, signed-body edits or automatic retries are allowed.

Managed production uses a separately versioned SDK schema profile. The pinned
SDK's TP/SL EIP signature covers instrument/type/side/quantity/price, not the REST
`order` parent. That parent remains mandatory in the full request, independent
Risk/exposure checks, immutable lifecycle association and signing/wire claim
hashes. It is not falsely described as venue-signed. The new profile changes the
reviewed schema digest: previously retained custody bindings are not silently
accepted. Historical/legacy Python schemas and frozen receipts are unchanged.

Unsigned cancellation has a separate narrow verifier, not a forged signing
operation. It checks exact owned PREPARED/origin journal records, completed
signing/wire claims, the original accepted owner lineage and immutable entry
reservation, then independently rechecks fresh registered venue facts after its
one-shot claim. It cannot cancel an active stop without independently established
flatness or an exact competing reduce-only exit. Disarm does not strand legitimate
protective/exit work. No arbitrary DELETE path is accepted.

## Terminal evidence is not automatic capital reuse

Terminal receipts have their own create-only schema and isolated reconciler role.
They preserve both effect IDs, exact reservation/request/order lineage, trade and
effect heads, complete public facts and side-neutral gross notionals/fees. The
reconciler can append but cannot update/delete receipts or mutate Risk records.
Incomplete, stale, unknown, conflicting, partial or unowned state refuses closure.

Schema-v2 reservations remain conservatively counted. This change does **not**
silently deploy a reservation-release/accounting reader or remove old rows. An
accepted terminal receipt is evidence for that future reviewed accounting step,
not permission to recycle capital, reset a daily stop or increase an owner cap.

## Verification boundary

`test_integration_production_lifecycle.py` exercises actual PostgreSQL lifecycle
journals and the real engine, managed signer/dispatcher and cancellation verifier
against explicitly synthetic authority, signature/claims and venue fixtures. It
covers partial fill, protection, remainder cancellation, reconstruction,
redelivery, target-versus-timeout and flat account reconciliation.

`test_integration_production_lifecycle_store.py` uses a separate fresh native
PostgreSQL database and real separated roles. It verifies concurrent create-only
binding storage, immutable reservation/FK/receipt DDL, least privilege and actual
terminal insert/replay/conflict through the reconciler. Venue/journal proof
sources in this test remain explicitly synthetic DTO repositories.

Neither test is evidence of EVEDEX execution, real account PnL, deployed state
producers, profitability, an accepted chain/custody binding or an armed owner.
Real SDK read/mutation transport, independent state producers, account/history
semantics and a signed accepted deployment must still be qualified together.
