# Unavailable session fence: signer entry denial

The managed signer has an opt-in `require_session_entry_fence=True` constructor
requirement. The current implementation **always denies new limit, market, and
stop-limit orders before authorization, the signing claim, and custody** when
this requirement is selected. No backend is treated as providing atomic session
fencing. The default is unchanged and the production builder does not enable
this requirement. This is a non-LIVE foundation, not a $5 loss limit.

The two allowlisted operations, position close and TP/SL, continue through all
existing independent authorization, claim, signing, and verification checks.
The current EVEDEX lifecycle maps its stop-loss and take-profit to TP/SL, but
this is not a guarantee for every protection path: stop-limit requests are
denied even if a caller uses them protectively. This mode
must not be used to claim that an already-started signing operation is stopped:
changing policy or creating another signer cannot cancel a custody callback
already running in a thread. It does not revoke already produced signatures or
prevent their later submission, nor does it establish an account baseline,
loss ledger, transactionally committed stop, or stop-safe execution path.

Any future entry-enabling implementation needs a qualified durable account and
loss source; atomic reservation and sticky stop; independent enforcement that
covers in-flight custody and wire submission, unknown outcomes and process loss;
and realistic concurrency and recovery verification. A successful preflight,
a boolean returned by a backend, or these synthetic tests are not that proof.

## Verification (2026-11-09)

On the isolated worktree based on `1f5cbe0ba60b6d3f515adec36c7e5f513c34b61e`,
`uv sync --offline --locked --extra evedex` populated a separate environment
from the local cache. The `uv.lock` SHA-256 was
`f20fa8cc7e2611f76ddc671faa0fa71185586885dd4dc52365f97eb990e4cdd8`;
Python was 3.11.15, eth-account 0.13.7, and coincurve 21.0.0. The signer,
authorization and runtime suite passed 95 tests without skips, including the
real authorization verifier exercised against explicitly synthetic state and
claims. These are not live exchange or atomic-fence tests. Existing environment
packages were not modified.

A separate reviewer independently inspected the guard and verified the earlier
signer/claims/authorization suite (94 passed, 3 skipped in its original
minimal environment), and identified the stop-limit protection limitation
documented above. The independent reviewer also requested the real-verifier and
duplicate-claim tests added to the 95-test offline run.
