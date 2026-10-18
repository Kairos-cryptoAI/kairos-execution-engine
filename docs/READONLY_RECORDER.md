# Database-bound DEV read-only recorder

This is the missing connection between existing Quant market measurements and
`CanarySessionRepository`. It is not a new observer framework, receipt importer,
trading service, signing preflight or authorization to start a campaign.

Install the optional `recorder` extra from the locked source set. The recorder
reuses Quant's paired-book parsers/comparison for the exact five DEV symbols and
Binance reference. HTTPS origins are fixed, redirects and proxy environment
inheritance are disabled, responses and concurrent connections are bounded.
Both buy and sell depth at the configured notional must exist. The default
USD 1,000 depth probe is a measurement size, **not an owner capital limit**.

The concrete health reader checks the same database's RECORDING run, scope hash
and instance identity, 1,440 contiguous recent one-minute bars for every required
symbol, and no execution/effect/dispatch records. This lifetime-zero condition
is deliberately stricter than a historical counter subtraction: provision a
separate clean gate database, never reuse a legacy, SIM or non-trading epoch DB.
It independently fetches the five authenticated account endpoints, verifies the
exact remote account ID, reconciles their components, and requires a flat account
with no position, order or TP/SL rows. Missing/unknown/stale evidence refuses the
run; an empty SQL table is not interpreted as healthy market coverage.

No network call holds a SQL transaction. A three-connection pool includes one
session advisory lock preventing a duplicate recorder in that database. This
process does not start consumers, migrate schema, reset cursors/leases, create a
database, sign requests or submit orders. Existing schema must be prepared and
accepted independently. Its GET-only account evidence does not certify signing
credentials, rate-limit reserves or production custody.

## Explicit independent configuration

The entry point is `kairos-evedex-record-readonly` (equivalently
`python -m kairos_execution.readonly_recorder_cli`). There is no default target,
default credential file or automatic launch. The non-secret JSON configuration
has these fields:

```json
{
  "version": "dev-readonly-recorder.v1",
  "scope": {
    "environment": "paper-dev",
    "account_id": "kairos-paper-dev-observer",
    "remote_account_id": "REPLACE_WITH_INDEPENDENTLY_VERIFIED_DEV_ACCOUNT",
    "config_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "recorder_code_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  },
  "database_name": "kairos_paper_gate_0123456789ab",
  "database_host": "127.0.0.1",
  "database_port": 5432,
  "database_instance_id": "00000000-0000-4000-8000-000000000001",
  "database_url_file": "C:/protected/kairos/recorder-database-url.txt",
  "jwt_file": "C:/protected/kairos/recorder-jwt.txt",
  "sample_period_ms": 15000,
  "notional_usd": 1000.0,
  "duration_s": 86400.0,
  "operation_timeout_s": 4.0
}
```

All values above are placeholders, not account or database facts. Obtain the
instance ID from the accepted isolated gate database, not an arbitrary new UUID.
Store credential files using the deployment's protected-file procedure; never
pass DSNs/JWTs as command arguments or put them in the JSON. The scope's existing
DEV URL/auth/chain/SDK restrictions cannot be relaxed by this config.

`inspect-config --config <file>` reads only that JSON and installed module bytes;
it prints the two expected fingerprints without reading credentials, connecting
to PostgreSQL or contacting providers. Set the scope fingerprints to those
values; changing a path, cadence, account, target or installed recorder/Quant/
repository implementation invalidates the binding. Configure the execution
runtime independently to the same exact scope before any later canary admission.

Only `record --config <file> --confirm RECORD_DEV_READONLY_ONLY` can start the
observation. That command is intentionally not run by installation, tests or CI.
The target name must match `kairos_paper_gate_<12..32 lowercase alphanumerics>`
and the URL's database, explicit local/container host/port, and server instance
must all match the config. This command does not send database credentials to a
remote host; run it beside the independently provisioned gate database.

## Evidence and stopping

The fixed cadence is 5–60 seconds, further constrained by source timeouts.
All five symbols remain in every persisted sample, including failed/empty/stale
book measurements. Missing intervals count against the existing denominator;
there is no backfill, accelerated 24-hour clock, imported summary or automatic
receipt reuse. Unknown account/runtime health aborts instead of writing zeros.
Cancellation propagates, closes clients/pools and releases the recorder lock;
it cannot certify or automatically restart a partial run.

Certification is delegated unchanged to the existing repository, after at least
24 actual hours and a final current sample. Its 99% availability, 25 bps p95,
five-second book age, two-second skew, chain and mutation checks remain binding.
The repository's receipt is not a canary arm. Empty SOL/BNB/XRP books or absent
official five-instrument account support remain real external blockers.

Offline tests and disposable PostgreSQL fixtures validate engineering mechanics
only. `PAPER_QUALIFIED`, `ALPHA_READY`, `LIVE_READY` remain false and
`STRATEGY_POLICY=REJECT_ALL`; no real observation window is claimed by those tests.
