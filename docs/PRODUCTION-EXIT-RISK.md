# Independent LIVE exit-risk staging

`kairos_execution.production_exit_risk.ProductionLiveExitRiskPublisher` is an
additive, explicit API for staging per-effect Risk geometry, authoritative
exposure, and lifecycle binding records for an already persisted PREPARED exit.
It is not wired into a service, factory, signer, dispatcher, or managed runtime.
PAPER behavior and defaults are unchanged.

## Required durable inputs and verifier

The publisher loads the effect and trade itself from the existing execution
journals, requires PREPARED status, and verifies both journal hash chains. It
checks exact LIVE/PROD account, environment, exchange, strategy, original
approved Core decision, effect namespace/type/role, and exact persisted request
payload. The original decision is always loaded from the trade journal; the API
accepts no caller-supplied Core decision or approval boolean. It refuses stale,
changed, unowned, malformed, or over-sized effects.

Deployment must inject a source verifier implementing
`ProductionExitEvidenceVerifier.verify_exit`. Its raw proof must qualify fresh
account economics and the exact current position, and return
`VerifiedLiveExitEvidenceV1` bound to context, trade, original decision,
effect/request hash, exit role, configured verifier source ID, and source proof
digest. The exposure binds exact instrument, position side, remaining quantity,
and original entry parent. The verifier supplies authenticated position entry
price, a fresh reference and executable exit price, and explicit finite bounds
for exit fees and adverse slippage; the publisher itself computes the loss for
the protective full-order envelope or exact direct-close quantity. For a stop,
it uses the worse of the stop trigger and executable price; for TP/direct close
it uses executable price. It then
applies the adverse-slippage bound in the closing direction and adds the fee
bound to any price loss. Zero or unbounded risk, missing, non-finite, stale, or
unbound economics are rejected; there is no epsilon or entry-budget cap.

These values are qualified source assumptions, not guarantees of fill price.
The calculation cannot bound a market gap, outage, liquidity shortfall, or
slippage beyond the source-provided bound. A future source verifier must
establish why its prices and fee/slippage bounds are authoritative and
conservative for the venue and effect; this bridge alone does not qualify it.

That interface is a contract, not source qualification. The included
`PinnedEvedexLiveExitVerifier` verifies the bounded capture scope and then calls
the shared fixed source-authority guard, which currently refuses. Thus there is
no production-qualified real EVEDEX exit source in this module. Synthetic test
verifiers are fixture-only and cannot establish operational readiness.

## Exact per-effect binding

Only STOP_LOSS, TAKE_PROFIT, TIMEOUT_EXIT, and EMERGENCY_EXIT PREPARED effects
are accepted. Stop/target requests must match the original Core exit trigger,
persisted client ID, whole-position convention, side, and entry parent. Direct
closes must match their persisted client ID and leverage, and the exact integer
quantity must not exceed the verifier's fresh remaining exposure.

Protective-stop and take-profit wire quantity `0` means the venue protects the
whole same-parent position. Their loss envelope therefore uses the full
originally approved entry-order quantity, even when only part has filled at
staging time; the persisted exposure remains the actual qualified remaining
quantity. For conservative entry basis, long positions use the worse (higher)
of the qualified position entry and the original decision's worst entry price;
short positions use the worse (lower). Direct-close loss is computed only for
its exact prepared quantity. Durable filled/position quantity beyond the
original decision is rejected. This bounds same-parent later fills only within
the original approved order quantity and the source's stated price/cost
assumptions; it does not protect against gaps or fills beyond those bounds.

Each accepted effect gets a new risk identity derived from its verified source
proof, request hash, effect journal head, and original decision digest. It is
never the entry decision ID. The request and risk lease are capped at five
seconds and by source/exposure validity and the caller's requested expiry. The
publisher does not require a current entry review, NORMAL entry mode, or spare
entry risk-cap headroom for a risk-reducing exit. It does not extend the caller's
owner-request digest or owner authority: managed signing must still resolve the
accepted owner nonce, original owner arm, fresh Risk and exposure, signature,
and one-shot dispatch through existing downstream boundaries. This producer
does not claim a global wire-cut guarantee. Entry HALT/operator kill still
blocks new entries; a qualified reducing exit is not required to pass those
entry-admission checks.

The bridge appends the exposure snapshot, exact request-bound risk row, and
passive lifecycle binding through the existing separated writers/stores. Any
partial or ambiguous write fails closed; do not blindly retry or dispatch from
an incomplete stage. The receipt is evidence only, not authority to sign or
trade.
