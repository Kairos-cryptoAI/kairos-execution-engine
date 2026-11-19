# Experimental account-wide entry I/O journal

This is an isolated research change. It does not qualify EVEDEX, deploy a
service, start LIVE, or replace the mandatory static denial of session entries.
The EVEDEX session verifier still refuses; the account state, fees, protection,
signing domain, IOC bounds and reconciliation are not established.

When a future qualified runtime explicitly provisions the experimental journal,
the intended sequence for one entry is:

1. Commit account-scoped `SIGN_STARTED`, bound to the exact pending durable
   signing claim, before invoking custody. A lost COMMIT reply prevents custody;
   if the commit happened, its row survives and blocks further entry.
2. After an exact `COMPLETED` signing claim, commit `SIGNED` before returning the
   signature. If this write is unknown, signing remains unresolved for entry.
3. After the exact durable wire claim, commit `WIRE_STARTED` before POST.
   The journal never treats an ACK as final execution or clears this record.

The journal is append-only. Any journal record blocks native session-mode risk
reservation for the account. No automatic release or reconciliation interface
exists; an actual canary would require a separately qualified source and
terminal reconciliation implementation. The three records for one entry are
the only permitted progression; one account cannot start a different entry.
Close and TP/SL bypass this entry-only journal, while their existing independent
authorization still applies. Stop-limit is classified as an entry.

Each journal write uses the shared account advisory lock and returns only after
the database transaction acknowledges COMMIT. A lease observes PostgreSQL
connection termination and checks connection/transaction state before and
after I/O. This cannot prove lock continuity during an undetected network
partition, cancel an already-received POST, prevent a `to_thread` signer from
finishing after cancellation, or fence older processes that ignore the journal.
A rollback to an older database snapshot, split brain, an unsafe schema owner,
unqualified ACLs, or another direct venue client can defeat the design. The
session and journal schemas still require independent ownership/ACL and
anti-rollback qualification. The real EVEDEX verifier intentionally refuses.

Synthetic tests use explicit isolated PostgreSQL databases, stub the account
verifier and portions of identity inspection, and insert synthetic claims. The
lost-COMMIT-ack test checks a committed STARTED row and account-wide refusal
after reconnect; another test terminates a database backend while the body is
active. These tests do not demonstrate a live exchange order, final fills,
protection, profitability or safe deployment.
