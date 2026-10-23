# Single-host engineering profile

This is an engineering contract, not LIVE approval. It records the owner's
revised scope: one deployment host, no mandatory DEMO campaign and no mandatory
purchase of an independent backup host or cloud KMS. It does not assert that a
single host survives its own loss. Historical V1 receipts and research evidence
are not changed or silently adopted into this profile.

## Implemented components

- `SingleHostProductionPreconditionsVerifier` checks the fixed profile and an
  independently pinned, public-only issuer registry. It retains the scientific,
  security, recovery, custody, account-pairing, operator-control and owner-limit
  evidence requirements. Results are validation-only, not a mutation capability.
- The profile excludes the three historical DEV campaign receipts and off-host
  restore from its engineering prerequisite set. Its local alert schema reports
  full-host-loss resilience as `NOT_ESTABLISHED`; it cannot assert that an absent
  independent watchdog or backup passed a test.
- `LocalEncryptedKeystoreBackend` implements the existing managed-custody backend
  interface using a fresh bounded Python child per request. Only that child
  reads a dedicated Ethereum V3 encrypted keystore and a separate protected
  unlock file. The parent passes paths, public binding and fixed typed data;
  it does not load the private key. This is process isolation, not an HSM and
  not a defense against a compromised administrator or same-user application.
- Only the five reviewed order/protection EIP-712 schemas are supported. Raw
  digests, Withdraw, SDK invocation, network access and order submission are not
  exposed by the worker. The configured chain, wallet and exact five-instrument
  universe are checked before key loading. Coincurve independently recovers the
  expected signing address; it shares the reviewed EIP-712 encoding, not the
  signing implementation.
- `ManagedSignerBoundary.sign_async` remains the outer one-use durable-claim,
  authorization and deadline boundary. A worker timeout, failed decrypt, process
  loss or missing terminal acknowledgment does not permit retry. A returned
  signature is excluded from normal record serialization.
- `ProductionSigningAuthorizationVerifier` now evaluates exact owner-signature
  and accepted-nonce identity, request/order/effect geometry, current operator
  state, fixed 0.25% / 1% risk ceilings and explicit owner limits. Signing must
  finish inside the risk lease and, for exits, the exposure lease. Reducing
  exits use authenticated historical arm lineage and current exposure, not a
  still-ARMED entry latch or an entry-notional cap.
- `production_state.py` provides an async PostgreSQL source and explicit
  owner-only provisioning for append-only owner-arm, operator, risk and exposure
  records. It binds the claims schema and production-state schema to one exact
  isolated database UUID, context, database name and reader login. The operator,
  risk and exposure producers have separate database roles and table grants;
  the source verifies grants, ownership, immutable payload digests, newest
  monotonic operator/exposure observations, and reads all evidence plus the
  accepted owner nonce in one bounded read-only repeatable-read transaction.
  This is a concrete persistence/source adapter, not a deployed authoritative
  risk calculator. Pending-risk/notional reservations and independent source
  service provisioning remain unqualified; the adapter does not compute or
  synthesize aggregate exposure.
- Native asynchronous authorization reads run inside the signer's same bounded
  deadline, before the durable signing claim. The verifier rechecks the clock
  and all leases after the read. Async-only state sources cannot be used through
  the synchronous signing API. Cancellation before authorization creates no
  signing claim and never reaches the key worker; this is not permission to
  repeat a later ambiguous signing or exchange dispatch.
- `ExecutionLifecycleScope` extracts existing durable account/event/effect
  identities without making PAPER configurable as PROD. `PaperExecutionEngine`
  still constructs the exact internal DEV canary policy and rejects LIVE/PROD.

Install the `evedex` extra for local custody, and `production-evidence` for signed
evidence verification. No key is imported or migrated automatically. In
particular, a general-purpose `keys.txt` is not an approved encrypted keystore,
and a DEV API key is not evidence of a PROD account/signing association.

## Finite engineering acceptance

`tests/test_nontrading_executor_acceptance.py` composes the real PostgreSQL
lifecycle/effect journal with the existing local venue double. It covers stale
evidence refusal, partial-fill protection, remainder cancellation, reconstruction,
duplicate delivery, disarm and target-versus-timeout resolution. It does not
claim real EVEDEX execution or profitability.

The opt-in native claims test additionally combines actual SQL claims, the
one-shot encrypted-keystore worker and independent signature recovery. It uses
only a public synthetic wallet and a fixture authorization policy; it proves
native claim/signature plumbing, not production authorization. It checks durable
COMPLETED and UNRESOLVED outcomes and replay refusal. Existing CI provisions a
fresh isolated test database; no primary database or legacy queue is involved.

## Explicitly not completed by these components

The default service does not select a production lifecycle executor. An explicit
[managed lifecycle composition](PRODUCTION-LIFECYCLE.md) now reuses the native
FSM through partial fill/protection/cancellation/recovery/close/account proof;
its native-PostgreSQL fixture tests are not real-venue acceptance. Independently
operated PROD state producers, accepted custody/transport and a capability issuer
remain undeployed. The account-scoped reservation is append-only and remains
conservative even after terminal evidence; automatic capital reuse is not added.
The async PostgreSQL reader is a component,
not evidence that its upstream writers are deployed or that risk calculations
are independently qualified. Settings and factory still reject LIVE. A signed
readiness record or presence of keys must not be converted into a permissive
boolean or the old low-level capability.

Before real dispatch, a reviewed composition must bind the future qualified
adaptive strategy, source set, authentic PROD account/wallet/chain, deployed
operator/kill state, one-use owner arm and current account exposure. Owner capital
and daily-loss limits remain mandatory before arming, independent of strategy
confidence. No capital amount is invented during engineering preparation.

The scientific gates are unchanged; the strategy, evaluator, Trial 15 and V2/V4/V5
evidence are untouched. All release readiness flags remain false and the current
strategy policy remains `REJECT_ALL`.
