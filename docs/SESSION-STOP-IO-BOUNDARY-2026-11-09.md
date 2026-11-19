# Experimental STOP barrier for custody and dispatch

`build_clocked_production_runtime(session_stop_id=...)` enables the session
latch and attaches one `PostgresSessionStopBoundary` to signer and dispatcher.
It also forces the existing static entry deny at reservation, signing and
dispatch. Attaching a boundary directly to a signer or dispatcher likewise
forces static entry denial. Runtime construction and use reject mismatched
latch/boundary/static-deny configurations. An ACTIVE row cannot enable entry.

The underlying experimental boundary uses
the same account-derived PostgreSQL advisory transaction lock as risk
reservation and the experimental `kairos_session_loss_v1.events` writer. The
boundary reads the latest row for the account, requires an explicit session,
`ACTIVE`, a positive sequence, and a clock-fresh observation, and holds the
transaction while the caller starts custody or sends the wire request. A
committed STOP acquired first causes refusal; a signing or wire claim already
made remains consumed with an unresolved result. Close and TP/SL go through
the pre-existing authorization and do not enter the new barrier; stop-limit
is classified as entry here. Expiry is rechecked after acquiring the lock.

This experimental supplemental barrier is **not** a complete $5 policy and
does not authorize LIVE. It cannot qualify account equity, flows, funding,
fees, open risk, source provenance, schema ACLs, database continuity or
anti-rollback. A present ACTIVE row is not evidence of a qualified source.
The existing static deny remains mandatory in this mode. Old processes and
direct venue access do not take this lock. A source write waiting behind a
send cannot revoke an already initiated order.

The lock is held only while the PostgreSQL connection and the coroutine are
alive. If the connection is lost, PostgreSQL releases it even while an
external operation continues. `asyncio.to_thread` custody can continue after
coroutine cancellation/timeout and transaction rollback. A network POST may
already have reached the venue when cancellation or a timeout occurs. Such
outcomes remain unresolved and require reconciliation; they are not retried.
No code here makes signing or network I/O reversible, and this mechanism
does not establish an atomic fence across host/process/database failures.

The optional PostgreSQL test uses an explicitly disposable local database and
a reduced events table. It exercises real advisory locks and deliberately
terminates the holder's connection to show that STOP can then commit while
the operation body remains active. Its stubbed production identity inspection
does not test actual schema ownership, grants or a qualified writer. Wiring
tests use synthetic claims, custody, responses, and prices. Some tests set a
private flag false solely to exercise future boundary mechanics; a production
runtime rejects that inconsistent configuration. No test signs or
sends to EVEDEX, deploys this branch, or asserts profitability.
