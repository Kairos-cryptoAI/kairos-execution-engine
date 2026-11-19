# Optional session entry denial across production boundaries

This is an experimental, opt-in, static refusal of new entries. It is not a
$5 session-loss latch, does not calculate PnL, and does not qualify the account
or venue. Default production behavior and release settings are unchanged. No
LIVE process is started or configured by this change.

`build_clocked_production_runtime(require_session_entry_fence=True)` passes the
same explicit flag to the actual account reservation source, managed signer,
and wire dispatcher. The source refuses before database reservation, the
signer refuses before authorization/claim/custody, and the dispatcher refuses a
previously signed entry before wire I/O. The dispatch decision uses the signed
operation rather than the caller's claimed effect type. Position close and
take-profit/stop-loss remain subject to the existing checks and claims. Other
order types, including a stop-limit used as protection, remain denied.

Synthetic contract tests cover direct reservation, pre-signed entry dispatch,
forged effect classifications, exit signing and dispatch, and builder wiring.
These prove behavior of the selected objects, not exchange protection or
account state. This mode is permanently denying entries until a separately
qualified implementation replaces it; passing the flag does not implement or
enable the requested live canary.

The flag is per-process and does not fence older workers, in-flight signing,
already-issued sender calls, other processes, or direct venue access. The
existing advisory lock is not a custody/outbox fence. A real $5 limit still
requires independently verified coherent equity, cashflows, fees, funding and
exposure; an externally anchored durable account-scoped history; atomic
reservation and irreversible STOP with correct commit semantics; and proven
fencing of already-reserved, signed, and in-flight entry effects. Unknowns must
block new entries while authorized protection and exits remain functional.
