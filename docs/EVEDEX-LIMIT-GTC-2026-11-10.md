# Native LIMIT_GTC entry contract

This is an explicit alternative to the unsupported limit-IOC wire policy.
It does not qualify market-IOC per-fill prices or switch an existing profile.
Native limit orders use fixed signed quantity and limitPrice, with no
timeInForce override in the REST body. The EVEDEX default is GTC.

## Required configuration

The same assembled scope must use all of:

- `ProductionLifecycleConfigV1(entry_order_type="LIMIT_GTC", ...)`;
- `ManagedProductionLifecycleAdapter(entry_order_type="LIMIT_GTC", ...)`;
- `build_clocked_production_runtime(limit_time_in_force="GTC", ...)`;
- `ProductionEntryEnvelope(limit_gtc_entry=LimitGtcEntryV1(cancel_after_ms=...), ...)`.

The original cancellation cutoff is part of the immutable lifecycle binding,
its request identity and the execution-effect journal. It must be after initial
admission, at most five seconds later, and no later than the original intent
entry expiry. The signing lease cannot outlive the cutoff. Assembly rejects
mixed runtime/lifecycle policies. Legacy IOC wire serialization remains unchanged.

This cutoff triggers a **local cancellation attempt**. It is not venue-side
expiry, nor a guarantee of cancellation completion within five seconds. The
service must remain running and connected until the entry remainder has a
known terminal outcome and any position has protection or is closed.

## Lifecycle

A valid NEW acknowledgement is durably linked to the exact trade and original
entry effect before cancellation. A no-fill entry is polled until its original
cutoff; then the existing owned-order cancellation verifier, one-shot claim,
terminal acknowledgement and authoritative no-order/no-position checks apply.

An observed partial fill immediately enters the existing protection path. Both
protective orders are installed before cancellation of the remaining entry.
The resulting position is reconciled after cancellation. The model cannot
change signed quantity, limit price, leverage, stop, target or timeout.

A lost cancellation response stays unresolved. Neither a timeout nor a missing
open-order projection is proof of cancellation. The durable recovery fence
blocks new entries. Restart reloads the original cutoff and does not create a
new entry or renew its deadline. Existing owner, signature, session-loss,
independent Risk and exact-account source requirements still apply.

## Validation

Synthetic venue responses and signatures only; no real account mutations:

- Ten contract/wire tests cover immutable deadlines, exact native geometry,
  partial exposure, unknown cancellation and surviving remainders.
- Four tests run the actual protected FSM and repositories on disposable
  PostgreSQL: NEW/deadline/cancel/flat; partial/protect/cancel; unknown cancel;
  restart after an unknown cancel without retry or deadline renewal.
- The existing production partial-fill/protection/restart/close PostgreSQL
  integration remains compatible.
- The sidecar suite exercises the native limit body through SDK dispatch.

These establish local integration behavior, not real-venue execution or an
economic advantage. A concrete one-canary host must still bind observed account
facts, the native Risk decision, authenticated transport and durable authority.

## Lost acknowledgement recovery

A crash after the venue accepts ENTRY can leave its local effect PREPARED for
the two-minute ambiguity interval. An authenticated exact GTC order and a
converged owned position now allow immediate positive recovery: validate the
original fixed geometry and signing/dispatch claim scope, reconcile the local
effect, install SL/TP, then cancel its remainder. The original WIRE terminal
stays absent or UNRESOLVED; ENTRY is never submitted again. This exception
only authorizes the existing reduction/protection path. It does not reconstruct
the raw signed wire body from its retained digest or replace a conflicting
terminal. Cancellation repeats its independent qualified account-source checks.

Native Decimal values are projected losslessly to decimal strings before
hashing and PostgreSQL storage. The record digest remains stable after a DB
roundtrip. Sixteen PostgreSQL GTC cases and the existing production integration,
contract and cancellation suites cover lost ACKs, both unknown terminal forms,
claim/geometry conflicts and ordinary protection/restart behavior (55 targeted
tests in this follow-up). All venue responses/signatures in these tests are
synthetic; the PostgreSQL repositories and protected FSM are real.

Source: [EVEDEX order creation](https://docs.evedex.com/developers/developers/order_creation).
