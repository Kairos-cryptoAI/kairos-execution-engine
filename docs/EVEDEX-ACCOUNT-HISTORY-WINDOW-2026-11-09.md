# EVEDEX bounded funding and fill history observation

`collect_history_window` is an opt-in read-only helper using an already
preflighted exact `ProductionEvedexReads`. It brackets the native funding
transfer and fill pages with account identity reads. It preserves each original
SDK wire capture and parsed page, with the same requested UTC interval and
explicit time and page budgets. These contain private account data; callers
must use private retention and must not log them. Sensitive fields are omitted
from the object's `repr`. The helper writes no files and caps the total wire
body size at 8 MB; the existing reader also retains its most recent raw capture
per source in memory.

The implementation refuses an identity mismatch, malformed or changing page
count, truncated nonterminal page, unsupported opaque cursor, duplicate fill
ID across pages, event timestamp outside the requested window, page budget
exhaustion or timeout. The venue funding schema contains no stable ID; identical
funding rows are retained separately and cannot be safely deduplicated. Count
exhaustion does not prove stable ordering or absence of missed events during
offset pagination. The output deliberately sets `history_complete` and
`fees_final` to UNKNOWN, `account_revision_authoritative` and
`trading_authority` to false. It is not wired into Risk or LIVE.

Source contracts: the official [Exchange OpenAPI](https://exchange-api.evedex.com/api/openapi.json)
and [personalized user data documentation](https://docs.evedex.com/developers/developers/personalized_user_data).
The API describes funding balances, transfers, positions, fills and orders but
does not thereby provide a qualified shared snapshot watermark, history
retention/correction rules, complete coverage or fee finality.

## Bounded read-only check

A separate read-only probe exercised a fixed interval on the funding-transfer
endpoint with account identity checks before and after pagination. The
response established that a bounded page could be read. It did not establish
complete history, stable ordering across pages or fee finality. The operator
keeps account-specific observations privately. The production helper's
native wire-capture path was exercised offline.

The official SDK master currently specifies PROD chain ID `161803` in
[`params.ts`](https://raw.githubusercontent.com/evedex-official/exchange-bot-sdk/master/src/params.ts),
whereas the locally pinned SDK/network configuration uses `42161`. Neither
client-side value proves what EVEDEX currently accepts for a real signed order
or what permissions the delegate has. No live signature or order was issued.
