# Explicit EVEDEX authentication observation runner

The CLI has two independent deployment steps. `prepare` does authenticated GET
reads, copies the existing wallet/API key into protected new files, provisions
a separate durable PostgreSQL container and named volume with separate owner
and runtime roles, and preflights the existing pinned SDK reader. It does not
sign SIWE or call the auth sign-up endpoint. It refuses existing runtime paths,
containers or volumes rather than resetting them. A preparation failure can
leave partial private resources; inspect those before any retry.

The existing `keys.txt` remains unchanged. Wallet and API credentials must match
the same remotely observed account. Existing public Node 22 and sidecar source
are checked before preparing; copied sidecar `.js` files must match the reviewed
source byte-for-byte. Current official params source is pinned by SHA-256.

Set the paths, key-file line numbers, chain ID and public parameter digest
for the reviewed deployment. The command below uses PowerShell variables so
the operator can supply those values locally.

```powershell
& $python -m kairos_execution.auth_observation_cli prepare `
  --runtime-dir $runtimeDir --keys-file $keysFile `
  --wallet-address-line $addressLine --wallet-key-line $walletKeyLine `
  --api-key-line $apiKeyLine --node $node --sidecar $sidecar `
  --container $containerName --auth-chain-id $authChainId --params-sha256 $paramsDigest
```

The only success output is `PREPARED_NO_AUTH`, the private runtime path and its
plan hash. Inspect that result before the second explicit action. The runtime
directory, database passwords, volume and claims are durable and never removed
automatically. No pre-existing application database is used.

`login-capture --runtime-dir <same> --plan-sha256 <reviewed hash>` performs one
wallet session attempt and one WS/REST observation. It requires the exact plan,
source files, Node and sidecar hashes from prepare. The official current auth
chain `161803` is restricted to this auth observation; it does not modify or
qualify the pinned trading transport's `42161` signing domain.

Run login-capture in a persistent PTY. On capture success it retains the session
tokens in that process for up to 120 seconds (configurable at most 300). It
accepts only bounded JSON stdin commands `{"command":"status"}`,
`{"command":"capture"}` and `{"command":"stop"}`. The same session is reused;
there is no relogin, refresh, reconnect, token export, persistence or order
command. On expiry/unknown the attempt remains consumed. Exiting does not
revoke the remote auth session. This is a bounded proof-of-access stage, not a
continuous trading runtime or proof of stream completeness.

Synthetic tests exercise encryption/ACL, wallet mismatch, context-safe failures,
one login/capture ordering and cancellation. An explicit Docker test provisions
new synthetic claims resources and verifies 1 of 8 concurrent claims succeeds
and reuse still fails after reconnect. Actual account auth has not been invoked
by development or tests. One symlink test is skipped on Windows without symlink
privileges. Parent/root is responsible for reviewing before real prepare/auth.

The official JWT schema requires only `accessToken`; an absent `refreshToken`
is represented as `None` for this bounded capture. A confirmed HTTP 400 with
`twofa_code_required_error` produces only `AUTH_REQUIRES_TWOFA`; no OTP, token,
server message or automatic retry is exposed. The attempt remains consumed.
The current exchange account GET does not expose a 2FA flag; this is UNKNOWN.

Before the very first auth attempt only, `revise-preauth-plan` can update the
reviewed CLI/session source manifest while preserving the original private
plan. It takes the exact original plan SHA, inspects the bound claims role and
requires all three claim/terminal tables to be empty under the same plan lock
that login takes. It atomically replaces the private plan and emits a new
reviewable SHA. It never clears any database entry. Once any attempt exists,
revision refuses. Use the digest returned by the original preparation:

```powershell
& $python -m kairos_execution.auth_observation_cli revise-preauth-plan `
  --runtime-dir $runtimeDir --plan-sha256 $reviewedPlanDigest
```

## One operator-audited authentication follow-up

In an earlier observation, claims had committed but the authentication outcome
was UNKNOWN. The audit data from that attempt could not establish signing
completion, HTTP status or whether a remote session existed. The original
plan and all claims remain retained.

The new `auth_audit` adapter records only whitelisted stage names, integer HTTP
status and public error-code enums as new immutable claims. It records before
and after signing, before the auth POST, the received status before parsing,
validated Auth schema, Bearer identity and WS capture. It accepts successful
2xx auth responses only when the full token/user schema and subsequent Bearer
identity match; account GET still requires 200. A 204/invalid body or redirect
refuses. This does not establish that an unexpected status caused the prior
UNKNOWN. No raw exception, message, signature, nonce or token enters the audit.

Only after a new explicit operator authorization, a separate follow-up plan can
be prepared. It links the exact prior plan/context to the declared UNKNOWN,
keeps the same account, custody files and claims DB, and grants no order method:

```powershell
& $python -m kairos_execution.auth_observation_cli prepare-auth-followup `
  --runtime-dir $runtimeDir --prior-plan-sha256 $reviewedPlanDigest `
  --operator-reference $authorizationReference --acknowledge-prior-unknown
```

This writes only `followup-plan.json` and returns a reviewable digest. The next
separately invoked `login-followup-capture --runtime-dir <same> --plan-sha256
<reviewed followup digest> --acknowledge-prior-unknown` consumes a global-per-DB
`auth-followup:<database_uuid>/one-operator-followup` guard before nonce, signature
or POST. Its maximum is one; source/context changes do not reset that guard.
The original login command refuses a follow-up plan. No automatic relogin,
order retry, refresh, ledger reset, old-plan replacement or claim deletion exists.
Confirmed 2FA-required is surfaced and stops; the runner has no bypass.

Synthetic tests cover auth 200/201 with mandatory schema/binding, 204 invalid
body, redirects, 2FA classification and audit field restrictions. A real local
PostgreSQL test exercises follow-up preparation, preservation of the prior plan
and claims, 1-of-8 concurrent follow-up approvals and persisted safe milestones.
Development did not execute the real follow-up.

## Observed regional refusal

The follow-up reached the venue and received a regional authorization
refusal. It stopped before authenticated identity verification or private
WebSocket capture. No exchange orders were placed by these probes. This
outcome leaves the first attempt UNKNOWN and preserves the original claims.
Account-specific timestamps, records and evidence locations remain private.
See the [authorization outcome](EVEDEX-OBSERVED-AUTH-REFUSAL-2026-11-10.md).

For future code diagnosis, only the exact pair HTTP 451 and
`forbidden_region_error` becomes `WalletSessionRegionForbidden`, producing the
safe CLI event `AUTH_REGION_FORBIDDEN`, code `FORBIDDEN_REGION`, exit status 4.
It exposes no server body, credentials or account details and cannot open a WS.
This classification change does not rewrite any existing evidence or replenish
the consumed follow-up guard. Synthetic tests cover the typed error, stopped
WS path and exact sanitized CLI event without account requests.
