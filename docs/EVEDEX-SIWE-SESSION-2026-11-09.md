# Experimental EVEDEX wallet session preparation

This code is not enabled by any existing production service, does not itself
grant LIVE authority, and was tested only with synthetic credentials. The
real endpoints were not called by these tests. Creating a wallet session is a
separate explicit action: it requires authorization and may create a session
or account via EVEDEX's `/auth/user/sign-up` endpoint.

The new isolated-keystore operation builds one fixed EVEDEX SIWE message with
an EIP-55 wallet, chain, alphanumeric nonce and recent timestamp; it never
signs caller-provided arbitrary text. The worker repeats validation before
opening protected files and the caller verifies the recovered signer. The
nonce is obtained only from the fixed EVEDEX HTTPS endpoint without redirects,
ambient proxy, cookies or retries. A committed one-use PostgreSQL claim must
precede signing. Signing timeout or a lost claim result stays unknown.

`create_evedex_wallet_session` requires `allow_session_creation=True`, a
preflighted exact PROD reader and matching account context and wallet. It
checks the original API-key account's `/api/user/me` wallet and exchange ID,
claims one attempt in the same database/context, creates the SIWE signature,
then sends exactly one sign-up POST to the fixed auth origin. Its returned
token is usable only after a Bearer GET to the fixed exchange origin confirms
the same exchange ID and the auth response confirms the same wallet. Tokens
are retained only in memory, excluded from object representations, and never
written by this code. Errors are sanitized; a lost POST response is unknown
and is not retried. A successful match is an account identity observation,
not proof of trading permission, feed continuity or profitability.

The attempt claim is scoped to the explicitly configured claims database and
production context; other databases and old processes are not fenced. The
code does not provide a recovery mechanism after a spent or ambiguous claim,
does not assert server-side nonce expiry, and does not resolve the open EVEDEX
chain-ID discrepancy. Protected keystore provisioning and token lifetime /
refresh management are not implemented. A real session still requires a
separately authorized call and appropriate account/host security review.

In synthetic testing, one isolated child unexpectedly exited with a sanitized
failure once; its cause was not captured. Eight independent reruns and twenty
subsequent calls using a synthetic-only instrumented worker passed, but these
do not establish the cause or prove that the intermittent failure is fixed.
An independent disposable PostgreSQL exercise tested the existing claims
adapter with SIWE namespaces, restart and concurrent claims; its high-level
signer and checksum were synthetic. The exercise was inline and is not yet a
checked-in end-to-end PostgreSQL integration test. Do not treat it as live
account or production-session evidence.
