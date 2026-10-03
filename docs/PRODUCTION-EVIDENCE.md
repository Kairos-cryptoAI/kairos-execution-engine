# Production evidence and one-use claims (engineering only)

`production_readiness.py` now accepts the concrete `SignedReceiptInterpreter`,
not injected boolean/mock interpreter results. The new receipt is explicitly
`kairos.signed-production-evidence.v1`, domain-separated Ed25519 with a public-only
issuer registry. Historical Markdown/GPG receipts are **not** this format and are
never silently adopted as PROD acceptance.

The verifier binds receipt content, kind, issuer/key, exact PROD account, adaptive
identity, frozen policy and source-set hashes, local schema hash, UTC validity,
issuer scope/lifetime, and independently loaded artifact bytes. Duplicate JSON
keys, missing/rebound/tampered artifacts and unknown issuers fail closed. Every
nested observation artifact hash must occur in the declared, resolved artifact
set. The preregistered policy artifact supplies campaign/evaluator identities,
economic thresholds, crash cases, required alerts and scientific counts; a
registry edit cannot silently weaken those thresholds.

The fourteen schemas require substantive observations rather than `accepted=true`:

| Gate | Required structured evidence |
| --- | --- |
| Adaptive forward | Consecutive complete five-symbol days, 1440 closed 1m bars per symbol, no gaps/conflicts, observation after freeze, sealed >=365 days |
| Adaptive trades | >=500 distinct naturally closed trade/intent lifecycles, after freeze, exact evaluator, frozen PF/drawdown limits |
| Crash | Exact preregistered scenario set, positive net accounting including fees/funding/spread/slippage |
| DEV read-only | Continuous >=24h, all five instruments, >=99% availability, <=25 bps quality, age/skew limits, no gaps/empty books/drift/mutations |
| DEV canary | <=10 attempts in <=2h, five completed round trips, one global position/1x, cancel/SL/TP/timeout/restart evidence |
| DEV soak | >=7 days, five instruments, exact reconciled effects and TCA artifact |
| Primary recovery | Backup/restore and history equality, native commit and acceptance artifacts, no unresolved/duplicate effects |
| Security | Exact reviewed source set, independent reviewer/deployment/threat artifacts, no unresolved critical/high/medium findings |
| Custody | Separate DEV/PROD references, wallet/chain, local reviewed EIP-712 schema, recovery/signature/rejection observations |
| Off-host restore | Distinct failure domains, authenticated encryption and custody evidence, exact restored dump, wrong-key rejection |
| Alerts | Exact frozen alert set, firing/resolved delivery plus owner acknowledgment, notifier restart/host-loss evidence |
| Operator control | Separate roles, durable restart/version observations, kill/resume sequence, no entries after kill or protected-exit failures |
| PROD pairing | Exact remote account, wallet/chain and authenticated/read-sign challenge artifacts |
| Limits | Explicit owner cap/stop, unchanged 0.25%/1% risk ceilings and 1x, missing/over-cap/daily-stop rejection and restart/pending-risk artifacts |

Custody and pairing wallet/chain must agree. DEV read-only/canary/soak must use the
same dedicated DEV account, distinct from PROD. A manual request must retain the
exact signed owner/cap/stop values. Schema/signature verification authenticates
the registered producer's structured observations; it does not recompute an
exchange archive, scientific PnL, or every raw operational log. Independent
producer/pipeline qualification and a reviewed, protected issuer registry remain
mandatory external preconditions. Synthetic test producers are not accepted
production authorities.

The return value remains `PRECONDITIONS_VALIDATED_ONLY` with `live_ready=false`
and `mutation_authority=false`. Manual validation returns only
`MANUAL_REQUEST_VALIDATED_ONLY`: it is not owner authentication, arming,
`LiveMutationCapability`, or permission to sign/trade. Config and factory LIVE
rejection remain unconditional.

## Isolated PostgreSQL claims

`production_claims.py` owns `kairos_production_evidence_v1`, outside Persistence
and all primary/simulator migration profiles. There is no database/role creation
or connect-time DDL. `provision_isolated_schema` is an explicit owner-only
operation on a fresh database named
`kairos_production_evidence_[a-z0-9_]{12,80}`. It requires a UUID, policy namespace,
and separate preexisting owner/runtime roles. Known primary/generic database
names are rejected before provisioning.

DDL contains an immutable identity row; one-use claims keyed by
`(claim_kind, namespace, identity)`; immutable terminal rows, bound by foreign key
to the exact claimed request digest; and UPDATE/DELETE rejection triggers.
Public schema/table/function privileges are revoked. Provisioning grants runtime
schema USAGE, table SELECT and INSERT only on claims/terminals. Runtime must be
NOSUPERUSER, NOCREATEROLE, NOCREATEDB, NOREPLICATION, NOBYPASSRLS, not a member of
the owner role, not schema/table owner, and cannot CREATE/UPDATE/DELETE/TRUNCATE/
REFERENCES/TRIGGER or INSERT the identity row. Every operation independently
inspects exact database/user/UUID/namespace/schema/table ownership and privileges.
The immutable identity is an explicit owner-provisioned trust anchor, not an
automatic migration marker.

A short `INSERT ... ON CONFLICT DO NOTHING RETURNING` transaction must acknowledge
COMMIT before any signing callback. Identical repeated claims return false;
identity/request/context rebindings fail. Server-commit/client-ack ambiguity,
process loss or cancellation is irrevocably CLAIMED/UNKNOWN. There is no release,
lease expiry, deletion, reclaim or retry API. UNRESOLVED cannot become COMPLETED.
DB access is bounded to ten seconds; SQL transactions have a five-second
statement timeout. Exceptions are sanitized without DSN/native error text.

`ManagedSignerBoundary.sign_async` uses these async claims, keeps fixed typed
schemas and independent authorization/signature checks, and returns a signature
only after terminal COMMIT acknowledgment and before one shared monotonic deadline
derived from the initial request lifetime, capped at 30 seconds. Authorization
preparation, claim, callback, verification and terminal acknowledgment consume the
same budget; a late terminal acknowledgment cannot release a signature.
Cancellation cannot stop the worker thread; an admitted claim therefore remains
unknown or terminal-but-not-returned and cannot authorize replay. No concrete
KMS/backend, private key loading, generic/raw signing, Withdraw, exchange dispatch
or provider factory is provided. The existing `SigningAuthorizationVerifier`
interface remains unwired: real current operator/risk/manual authorization and
native custody deadline/cancellation/reconciliation must be independently
implemented and qualified before any production wiring. Offline fake callback
tests do not establish native custody readiness.

## Native isolated qualification

The opt-in target is:

`tests/test_production_claims_integration.py::test_native_isolated_claims_races_restart_unknown_and_role_boundary`

Root/operator must first create a **fresh isolated database** and separate
preexisting roles, then supply these ephemeral test environment values without
printing credentials:

- `KAIROS_PRODUCTION_CLAIMS_TEST_PROVISION=1`
- Prefix `KAIROS_PRODUCTION_CLAIMS_TEST_` plus `OWNER_DSN`, `RUNTIME_DSN`, `DATABASE`,
  `DATABASE_UUID`, `POLICY_NAMESPACE`, `OWNER_ROLE`, `RUNTIME_ROLE`

Only this explicit test calls the provisioner. It exercises eight concurrent
claims/exactly one admission, a new pool/adapter restart, unknown replay fences,
request rebinding, UUID mismatch, immutable UNRESOLVED terminal, one-use manual
nonce, denied runtime deletion/truncation, terminal FK mismatch, owner immutable
UPDATE and fail-closed unsafe runtime grant. It leaves inspectable records and
does not remove the database, roles or schema. Re-running requires a new isolated
database; do not recreate/migrate a primary or overwrite prior evidence.

Native isolated pass is an engineering receipt only. Remaining PROD gates include
real protected issuer enrollment, independently qualified evidence producers,
new adaptive sealed gates, accepted runtime recovery, real account/custody
pairing and signed challenge verification, off-host encrypted restore and alert
delivery, current operator/risk/manual authorization and owner-supplied real
capital limits. No historical/synthetic proof substitutes for those conditions.
