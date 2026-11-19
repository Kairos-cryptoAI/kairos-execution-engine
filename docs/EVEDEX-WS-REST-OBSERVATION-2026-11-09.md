# Experimental private WS / REST observation coordinator

`capture_ws_rest_observation` uses an explicitly supplied read-only stream and
the concrete, preflighted `ProductionEvedexReads.fetch_paper_state()` method.
It opens the stream, waits for observed acknowledgements for all eight private
channels (including fees and transfers), records their local UTC and monotonic
arrival times, captures the REST snapshot while buffering publications, and
observes a short additional interval. Event payloads and the snapshot remain
in memory and are excluded from `repr`; this module writes no account data to
disk. Returned data require private storage controls if a caller persists them.

Disconnected streams, failed recovery, malformed or duplicate acknowledgements,
publications before a channel acknowledgement, observed offset discontinuity
or epoch change, malformed or duplicate-key JSON, time regression, size/count
overflow and timeouts discard the result. A stream that does not promptly honor
cancellation causes refusal; a broken transport may nevertheless continue until
its own shutdown, so its cleanup status is UNKNOWN. Calls to stream entry,
receive, snapshot and stream exit are bounded separately; errors from these
external boundaries are sanitized and the stream cannot suppress a refusal.
UTC and monotonic clocks are checked against every previous recorded step.
The coordinator cannot forcibly terminate an uncooperative Python task.

The coordinator **does not implement an actual private WS transport**, merge
account state, or independently verify a channel acknowledgement. The process
has not connected to private WS, and synthetic frames in tests are not venue
evidence. The stream's read-only nature is an adapter trust requirement, not
something Python's protocol can enforce: a future implementation needs
independent review. Local event sequence is strictly an arrival counter. Optional epoch
and offset are unqualified claims from the transport: detecting no discontinuity
does not prove completeness or recoverability. The result always has
`sequence_continuity_proven=false`, `authoritative_reconciliation=false`,
`history_complete=null`, `fees_final=null`, and `trading_authority=false`.
Neither this module nor its tests create credentials, sign, or submit orders.

The [EVEDEX toolkit](https://docs.evedex.com/developers/developers/toolkit)
documents WS subscription before REST snapshot, followed by merging using
`updatedAt`. Its [personalized data documentation](https://docs.evedex.com/developers/developers/personalized_user_data)
lists private user, funding, transfer, position, order, fill, fee and TP/SL
channels; fee updates are asynchronous. The locally installed SDK 1.2.11 sets
an API-key session for REST, while its private subscription callback retrieves
`session.accessToken`; no access token is returned by an API-key session.
The available PROD runtime implements REST only, and its `drain_events` fails
closed. The DEV sidecar uses a local arrival counter, not a venue sequence.
The SDK's `Balance.listen()` starts subscriptions then REST requests without
waiting for per-channel subscribed acknowledgements and does not subscribe to
order-fee updates. Therefore that method alone is not proof that all eight
channels are subscribed or that a lossless snapshot has been established.

Next work requires an explicitly authorized existing session capable of
private channels, an independently reviewed transport that forwards actual
channel lifecycle, payloads and positions without inventing them, and a venue
test of reconnect/recovery and snapshot timing. No browser token extraction,
new session, new key, trading or account mutation was performed here.
