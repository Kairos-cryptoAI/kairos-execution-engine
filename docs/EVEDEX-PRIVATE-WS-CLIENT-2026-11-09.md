# Experimental private EVEDEX WS client

`EvedexPrivateWsStream` implements the existing `PrivateWsStream` observer
interface using aiohttp and the JSON Centrifugo protocol. This is a read-only,
opt-in component, not a service or source of LIVE authority. It is not wired to
the PROD gateway or launched by default, and it has not connected to EVEDEX.

The adapter accepts an existing access token in memory and the exact
preflighted `ProductionEvedexReads` instance. Before opening a WebSocket it
queries the fixed HTTPS `/api/user/me` endpoint with that bearer token and
requires its `exchangeId` to match the bound reader and client account ID.
The observer rejects a different reader instance and repeats its scope check
after the snapshot. Redirects are refused, proxies/cookies are disabled,
and no secret is supplied in a URL, logged, or written to a file. A caller
must protect tokens and returned private payloads held in memory. Python
objects and the reader remain mutable; this is not a protection against a
malicious caller mutating them, inspecting memory, or using a separate client.

The fixed `wss://ws.evedex.com/connection/websocket` destination and the
eight `futures-perp` channel names match the installed EVEDEX SDK. As in that
SDK, the existing access token is sent in subscription `data.accessToken`.
The adapter produces a `SUBSCRIBED` frame only after each actual protocol
reply, maps publications to the observer, answers server-requested heartbeat,
and rejects malformed frames, explicit subscription errors, unqualified
recovery, changed destinations, missing account identity, or incomplete
provider positions. It bounds response sizes and buffered batches. Disconnects
and unsubscribe events end observation; it does not attempt reconnect.
The subscribe response's offset is not used as a publication baseline; only
offset gaps between publications actually observed can be detected by the
observer. The interval between a subscription acknowledgement and its first
publication is therefore not proven continuous.

Tests use fake HTTP, WebSocket and token data. No user token, real session,
socket, order, trade or signing operation was used. The actual EVEDEX server's
bearer response, WS authentication, acknowledgements, disconnect semantics,
and epoch/offset/recovery behavior remain unqualified. An observed stream does
not prove a complete ledger, atomic account state, final fees, or account
recovery. Running the component requires an independently acquired existing
session, a running pinned REST reader and operator-controlled provisioning;
none are created here. The observer always reports trading authority false.

References: [EVEDEX toolkit](https://docs.evedex.com/developers/developers/toolkit),
[personalized channels](https://docs.evedex.com/developers/developers/personalized_user_data),
and [Centrifugo client protocol](https://centrifugal.dev/docs/transports/client_protocol).
