# EVEDEX: observed authorization refusal, 10 November 2026

Status: real trading was not started. No exchange trading orders were sent by
this preparation run. A completed end-to-end trading runtime is not claimed.

## Observation and outcome

A read-only account check and a separate wallet authentication attempt
tested different access paths. The read-only check supplied a point-in-time
observation. The reviewed follow-up reached the venue, which refused access
with HTTP 451. The adapter classifies this response as `FORBIDDEN_REGION`.
The attempt stopped before Bearer identity verification or private WebSocket
capture. It created no exchange orders.

The earlier authentication attempt remains UNKNOWN. The follow-up cannot
establish whether that first attempt created a remote session. Its original
claims remain intact. Any subsequent access requires resolution through the
venue's supported process. Account records and per-attempt evidence stay in
operator-controlled storage.

## Local implementation and limits

The working execution branch includes explicit authentication stage auditing,
the typed `WalletSessionRegionForbidden` error, and the sanitized
`AUTH_REGION_FORBIDDEN` CLI result. The exact 451/error-code pair stops before
opening a private stream. Authentication plans grant no trading methods.

After merging the authentication work, the coherent local Python environment
completed 75 tests with 2 skips. The first run encountered a Windows permission
error during pytest temporary-directory cleanup; a dedicated new test directory
completed with exit 0. A pytest cache permission warning remained. These tests
use synthetic authentication responses and are not evidence of exchange access.

The bounded native GTC entry lifecycle and its lost-acknowledgement correction
are integrated. Exact positive order and claim evidence lets startup recovery
protect an observed partial fill before cancelling the remainder, without
waiting out the ordinary two-minute ambiguity grace or sending another ENTRY.
The original unknown wire outcome remains unchanged. Native Decimal values are
stored losslessly before proof hashing and PostgreSQL replay. The feature fix
passed independent review; after integration, 63 focused execution, binding,
dispatch and cancellation tests passed locally. The author also ran 16
disposable-PostgreSQL GTC scenarios; the exchange venue in those tests is
synthetic. This does not qualify actual exchange execution or host-loss safety.

The operational one-canary composition remains separate development work. Its
full deployment, protected delegate execution and complete real recovery cycle
have not been qualified. The ordinary release remains entry-disabled. No claim
is made that the session loss journal alone constitutes a deployed $5 stop.

The intended future canary limits remain a 100 USDT sizing basis, leverage at
most 1x, nominal per-trade risk at most 0.25% of that basis, aggregate open risk
at most 1%, and a $5 session loss threshold stopping new entries while protection
continues. Deposits must not erase prior loss. No candidate or minimum lot may
override these constraints. These intended limits do not establish operational
readiness or bound actual loss under every exchange failure.

This work makes no profitability claim. It does not establish the 30-70%
monthly research objective or a 5% maximum drawdown.
