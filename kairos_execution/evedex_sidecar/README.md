# Kairos EVEDEX DEV sidecar

This private Node process is the only PAPER component that receives the EVEDEX
DEV API key and dedicated signing key. It has no HTTP listener: Python starts it
as a child process and exchanges one JSON object per line over stdin/stdout.

The official `@evedex/exchange-bot-sdk` is pinned to 1.2.11, including npm
integrity data in `package-lock.json`. That published artifact still embeds the
superseded DEV chain `421614`, while the official repository `src/params.ts`
defines DEV chain `16182`. Kairos therefore supplies one compile-time constant
override containing the official DEV URL, auth URL, WebSocket URL, prefix and
chain. It is not configurable through environment variables or protocol input;
the embedded `421614` value is never used.

Startup performs SIWE authentication, API-key authentication, dedicated account
identity matching, an instrument preflight and an authenticated WebSocket
balance subscription. All five allowlisted instruments
must exist with `trading=all`. A failed preflight leaves the process unable to
execute mutations.

Required process-only secret file references:

- `EVEDEX_DEV_API_KEY_FILE`
- `EVEDEX_DEV_PRIVATE_KEY_FILE`
- `EVEDEX_DEV_EXPECTED_ACCOUNT_ID`

Mutations require a durable `effect_id`; order mutations additionally require a
deterministic client order ID. Commands are serialized. Read-only commands may
retry once after full SIWE re-authentication, while mutation commands are never
retried by this wrapper. Version 1 supports only create/cancel TP/SL; update is
intentionally absent.

The `drain_events` read command returns the ordered, monotonic account/order/
fill/TP-SL event buffer for Python reconciliation; the sidecar never opens a
host port.

`health` returns auth age/expiry and the remaining conservative local mutation
budget without returning tokens, keys or wallet data. The published SDK drops
headers on successful REST responses, so venue reserve observability is reported
explicitly as false rather than inventing a quota value.

Install production dependencies from the pinned lockfile with
`npm ci --omit=dev --ignore-scripts`. The SDK needs no dependency install script;
disabling them keeps the container build supply-chain boundary explicit.
