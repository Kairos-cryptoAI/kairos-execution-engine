# kairos-execution-engine

**Layer 6 — Execution Engine.** The hands of the Kairos system (no LLM). It consumes
risk-validated orders, switches only on their machine-readable `reason_code`, and
deterministically submits orders with exchange-side protective stops.

## Exchanges

- **EVEDEX** (`exchange.evedex.com`) is the production venue. Mutating requests are
  EIP-712 signed and rate-limited to 30 heavy requests per 60 seconds. Client order IDs
  follow EVEDEX's `[0-9]{5}:[0-9A-Fa-f]{26}` format. The prefix is the UTC day count
  since 24 July 2025, while the suffix is stable for the source event. Replays older
  than EVEDEX's accepted today/yesterday window are rejected before any network call.
- **CCXT** supports strategy testing on Binance testnet and other venues.

Both adapters are optional installation extras. The service is in `dry_run` mode by
default and makes no real exchange calls unless that setting is explicitly disabled.
Risk-provided `stop_price` takes priority over the configured fallback distance and is
accepted only on the protective side of the entry. The current service arms an initial
exchange-side stop; it does not claim that stop is dynamically trailed until a reviewed
price-update and replace/cancel loop is wired for the selected venue.

The stop-create adapter contract requires a venue-assigned TP/SL ID. EVEDEX's signed
TP/SL payload includes the documented `order` link to the already verified parent entry
ID; it does not invent a client ID for the TP/SL record itself. The create response must
contain a server ID and a documented live state (`waitOrder` or `active`), then a live
`GET /api/tpsl` must uniquely return that ID in `waitOrder` or `active` before protection
is accepted. `process`, `triggered`, `done`, and `cancelled` are not proof of a still-live
stop; the engine compensates and reconciles the position instead.

For an unprotected `NEW` or `PARTIALLY_FILLED` entry, compensation cancels by the
deterministic ID generated before submission, verifies that it disappeared from open
orders, reconciles the live position, closes it if necessary, and reconciles again. It
never uses an exchange ID copied from a malformed acknowledgement. CCXT first resolves
an exact, unique client ID in open orders and only then sends the venue's server ID to
`cancel_order`; an absent or duplicate identity fails closed. Any ambiguous cancellation
or non-flat position leaves the source message pending and requests an immediate account
refresh so Risk does not continue using the last pre-failure snapshot.

Explicit `CLOSE_POSITION` actions target the reconciled desired state rather than an
acknowledgement label. Redelivery first checks whether the symbol is already flat and,
if so, returns an explicit `CANCELED`, zero-observed-fill desired-state result without
submitting a second close. After submission, a finite identity/accounting-valid
acknowledgement is still required, but `NEW`, `PARTIALLY_FILLED`, `REJECTED`, or
`CANCELED` can converge only when the venue independently proves flat; the result does
not claim an unobserved fill.
A malformed acknowledgement or non-flat position remains pending. An active close with
the same deterministic client ID blocks duplicate submission while reconciliation is
accelerated.

On the normal path, a `NEW` limit entry may remain active after the venue returns the
server ID for its close-position protective stop. Kairos does not reinterpret `NEW` as
a fill: it retains the entry only because stop creation was acknowledged, then relies
on periodic position/open-order reconciliation for actual fill state. This is initial
protection for a future or partial fill, not evidence of execution and not trailing.

## Account reconciliation

Execution is the authoritative producer of `kairos.account.snapshot`. It publishes a
snapshot immediately at startup, every `KAIROS_ACCOUNT_SNAPSHOT_INTERVAL_S` seconds,
and after an exchange action. Risk Manager remains fail-closed until it receives a
fresh `reconciled=true` snapshot.

For EVEDEX, each refresh reads `/api/user/me`, `/api/market/available-balance`,
`/api/position`, `/api/order/opened`, and `/api/tpsl`. Position and open-order totals
must match the available-balance response before the snapshot is trusted. A margin
call, malformed response, mismatch, or failed request produces an explicit
`reconciled=false` snapshot that revokes the previous account view. The service uses
the negative unrealized PnL reported by EVEDEX conservatively when calculating equity.

CCXT refreshes unified balance, positions, and open orders concurrently and records
protective stop IDs. In `dry_run`, a clearly labelled synthetic account is published;
it cannot cause a live order because the adapter does not make exchange calls.

Intraday PnL and peak equity are tracked for the lifetime of the process. Restarting
Execution resets the intraday baseline, so production supervision should avoid
unnecessary restarts and should treat durable accounting history as a follow-up before
unattended capital is enabled.

Every exchange mutation is recorded in the TimescaleDB execution journal before the
venue call. Confirmed responses are replayed from the journal, while unresolved effects
are recovered under a database advisory lock after a two-minute in-flight grace period.
Until recovery is complete, account snapshots are forced to `reconciled=false`, new risk
is blocked, and reduce-only close processing remains available. The bounded in-memory
fingerprint cache remains only a fast path for duplicate deliveries; it is no longer the
durability boundary.

For an unresolved EVEDEX TP/SL request, recovery first reads `GET /api/tpsl` and accepts
only one live, parent-linked stop with exact symbol, side, type, full-position semantics,
and trigger price. Exact absence permits one retry while the position is still open;
ambiguous or duplicate records fail closed. Adapters without an authoritative
parent-linked lookup never retry an unresolved protective stop for an open position.

The remaining venue boundary is deliberately conservative. CCXT has no portable
historical client-ID or parent-linked TP/SL lookup, and an inactive entry with a non-flat
position cannot be classified automatically. Such effects stay blocked for operator
reconciliation instead of being guessed successful. Intraday PnL baseline restoration
also still depends on durable accounting history outside this journal.

Internal Kairos symbols use Binance-style `*USDT` identities. The EVEDEX adapter maps
the configured production universe one-to-one to the venue's `*USD` instruments and
maps reconciled positions back to their logical identities. An unmapped live position
invalidates the account snapshot instead of silently creating a second symbol domain.

Run the GET-only venue qualification without credentials:

```powershell
uv run --locked kairos-evedex-qualify `
  --output $env:TEMP\kairos-evedex-public.json `
  --overwrite
```

For authenticated reconciliation, place the JWT in a local secret file and add
`--jwt-file <path>`. The JWT is never accepted on the command line and is never written
to the report. Qualification performs no POST, PUT, PATCH, DELETE, signing, or order
operation. Its report always contains `live_orders_allowed=false`; missing credentials,
missing quota headers, stale market evidence, or a schema mismatch remain explicitly
`BLOCKED`/`FAIL` until reviewed.

## Prerequisites

- [uv 0.12.3](https://docs.astral.sh/uv/)
- Git access to `Kairos-cryptoAI/kairos-core`

uv installs and selects Python 3.11 from `.python-version`. `uv.lock` also pins
`kairos-core` to the reviewed Git commit used by this service.

## Windows / PowerShell setup

```powershell
Set-Location D:\Kairos\kairos-execution-engine
uv python install 3.11
uv sync --locked
uv run --locked pytest -q --tb=short
```

Install and test both exchange adapters without contacting an exchange:

```powershell
uv sync --locked --all-extras
uv run --locked --all-extras pytest -q --tb=short
```

Run all blocking local checks:

```powershell
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked mypy kairos_execution
uv run --locked bandit -q -r kairos_execution -x tests
uv run --locked pytest -q --tb=short
uv build --no-sources
```

Run safely with the in-memory bus and dry-run execution:

```powershell
$env:KAIROS_BUS_BACKEND = "memory"
$env:KAIROS_DRY_RUN = "true"
uv run --locked python -m kairos_execution
```

The Makefile wraps the same uv commands for environments where `make` is available.
For example, `make check` runs the complete blocking check set.

## Updating dependencies

The lockfile is committed. Do not hand-edit it. Update dependencies deliberately and
review the resulting diff:

```powershell
uv lock --upgrade-package aiohttp
# To update kairos-core, first review and replace its `rev` in pyproject.toml.
uv lock --upgrade-package kairos-core
uv sync --locked
```

Production and CI installs must use `--locked` so they cannot silently re-resolve newer
dependencies.

## Message lifecycle

The service consumes `kairos.risk.validated_order` and `kairos.system.control`, and emits
`kairos.execution.report` plus `kairos.account.snapshot`. A validated order is
acknowledged only after handling succeeds and any execution report is published.
Transient validation, exchange, or publish failures remain pending for at-least-once
redelivery. CLOSE requests carry the exact risk-validated quantity into the exchange
signature; emergency closes first retrieve the live position size.

When `LOCAL_QUANT_MODE` is active, new positions are refused and only protective actions
are allowed.

## Runtime delivery durability

With Redis, consumed IDs, execution reports and completion are committed through
`kairos-persistence`; Redis is ACKed only after PostgreSQL commits. Configure
`KAIROS_PERSISTENCE_DATABASE_URL` through the deployment secret provider. This
transport guarantee complements, but does not replace, the venue-effect journal.

---

Part of the [Kairos](https://github.com/Kairos-cryptoAI/kairos) system. MIT licensed.
