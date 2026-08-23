# kairos-execution-engine

**Layer 6 — Execution Engine.** The deterministic execution and recovery boundary
(no LLM). Legacy `DRY_RUN` consumes `ValidatedOrder`; strict `PAPER` consumes only
`RiskTradeDecisionV1` and preserves full strategy/intent/trade/order lineage.

## Authority modes

- `DRY_RUN` keeps the existing synthetic adapter path unchanged.
- `PAPER` is restricted to the exact EVEDEX DEV URLs, chain `16182`, five `*:DEV`
  instruments, a dedicated account and PostgreSQL inbox/outbox plus journals.
- `LIVE` is compile-time disabled because this release is not `LIVE_READY`.

`KAIROS_DRY_RUN=false` is retired and is always a startup error. It never maps to
`PAPER` or `LIVE`. `PAPER` also rejects the legacy `TacticalCommand -> ValidatedOrder`
mutation route, production/custom endpoints, static JWTs, legacy signing keys, CCXT
credentials and the EVEDEX PROD/DEMO profiles.

## Exchanges

- **EVEDEX legacy DRY_RUN** retains the existing deterministic adapter without network
  mutations. Client order IDs
  follow EVEDEX's `[0-9]{5}:[0-9A-Fa-f]{26}` format. The prefix is the UTC day count
  since 24 July 2025, while the suffix is stable for the source event. Replays older
  than EVEDEX's accepted today/yesterday window are rejected before any network call.
- **EVEDEX DEV PAPER** runs through an internal Node child process using the official
  `@evedex/exchange-bot-sdk` pinned to `1.2.11`. It has no listener or host port and
  receives commands as NDJSON over stdin/stdout. Python owns the durable journal/FSM;
  the sidecar owns SIWE/auth, signing, REST and WebSocket only.
- **CCXT** remains available only on the legacy DRY_RUN path.

The service defaults to explicit `DRY_RUN`. No boolean can enable exchange mutations.
PAPER starts only after authenticated account identity, SDK endpoints, DEV chain and
all five `trading=all` instruments pass a fail-closed preflight.
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

PAPER day-start, latest and peak equity plus reconciliation sequence are durable across
restart. Out-of-order snapshots cannot rewrite the latest or day-start values. Legacy
DRY_RUN keeps its process-local accounting semantics.

PAPER persists the immutable risk decision, lifecycle, first-fill timeout clock,
deterministic client IDs and hash-chained effects. Its state machine is:

`RECEIVED -> ENTRY_PENDING -> PROTECTING -> ACTIVE -> EXITING_* -> FLAT`.

The first non-zero fill is protected with a reconciled full-position STOP before the
TARGET is created. A STOP failure triggers emergency close; a TARGET failure closes
under the already-live STOP. Partial fills are protected immediately and the remaining
entry is cancelled at expiry. STOP, TARGET and timeout transitions are serialized and
all new entries remain blocked until startup recovery reconciles effects, orders,
positions and TP/SL authoritatively.

Trade creation and every FSM transition commit the internal hash-chain entry,
canonical `TradeExecutionEventV1`, audit row and durable outbox row in one PostgreSQL
transaction. Startup scans the full account scope, including `FLAT` and `CANCELLED`
trades, and refuses entry authority if the public event sequence does not cover every
durable lifecycle version. There is no repair-after-crash gap between a lifecycle
transition and its public fact.

Every exchange mutation is recorded in the TimescaleDB execution journal before the
venue call. Confirmed responses are replayed from the journal, while unresolved effects
are recovered under a database advisory lock after a two-minute in-flight grace period.
`PREPARED` is deliberately an internal effect-journal state, not a public lifecycle
event. Absence of the entry effect after `ENTRY_PENDING` proves that no venue mutation
was attempted; an existing effect is reconciled and never blindly resubmitted. A shared,
account-scoped PostgreSQL mutation reservation is taken immediately before the sidecar
call, with the process-local Node limiter serving only as a second barrier.
Until recovery is complete, account snapshots are forced to `reconciled=false`, new risk
is blocked, and reduce-only close processing remains available. The bounded in-memory
fingerprint cache remains only a fast path for duplicate deliveries; it is no longer the
durability boundary.

For an unresolved EVEDEX TP/SL request, recovery first reads the complete paginated
`GET /api/tpsl` projection and accepts only one exact symbol/side/type/price record.
An existing record is reconciled and later cleanup uses its venue ID; an absent,
ambiguous or duplicate record fails closed. A prepared protective mutation is never
retried, even when the position remains open.

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
- Node.js 22.x for EVEDEX PAPER
- Git access to `Kairos-cryptoAI/kairos-core`

uv installs and selects Python 3.11 from `.python-version`. `uv.lock` also pins
`kairos-core` to the reviewed Git commit used by this service.

## Windows / PowerShell setup

```powershell
Set-Location D:\Kairos\kairos-execution-engine
uv python install 3.11
uv sync --locked
uv run --locked pytest -q --tb=short
Set-Location kairos_execution/evedex_sidecar
npm ci --ignore-scripts
npm test
npm audit --omit=dev
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
$env:KAIROS_TRADING_MODE = "DRY_RUN"
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

In `DRY_RUN`, the service consumes `kairos.risk.validated_order` and
`kairos.system.control`, then emits `kairos.execution.report` and
`kairos.account.snapshot`. A validated order is
acknowledged only after handling succeeds and any execution report is published.
Transient validation, exchange, or publish failures remain pending for at-least-once
redelivery. CLOSE requests carry the exact risk-validated quantity into the exchange
signature; emergency closes first retrieve the live position size.

When `LOCAL_QUANT_MODE` is active, new positions are refused and only protective actions
are allowed.

In `PAPER`, the service subscribes only to `kairos.risk.trade_decision.v1`, publishes
`kairos.execution.trade_event.v1` and `kairos.account.snapshot.v2`, and ACKs the source
only after lifecycle facts are placed into the durable outbox. Technical canaries use
the same path; legacy messages cannot reach the sidecar.

The sidecar `health` command exposes only secret-free operational values: SIWE auth age
and expiry plus a conservative local 30-mutation/60-second reserve. Execution copies
them into the structured `execution.paper_operational_telemetry` log and every trade
event's `details`. The SDK
does not expose successful venue rate-limit response headers; therefore
`evedex_venue_rate_limit_observable=false` and its reserve is `unknown` until the real
DEV qualification records authoritative semantics. Entry fill events also include the
decision worst-entry price, average fill and signed execution shortfall in basis points.
The persistence exporter independently derives the 24-hour
`kairos_execution_p95_shortfall_bps` metric from durable decisions and fill events.
Execution also writes account-scoped `ExecutionRuntimeHealth`: auth age and the durable
cross-process mutation reserve are exported directly from PostgreSQL without exposing
either secret value. Sidecar process-local reserve values remain available in the
structured log and persisted event `details` as an independent second-barrier signal.

The following `TradeExecutionEventV1.details` keys are a stable, secret-free exporter
interface and are appended to every emitted PAPER lifecycle event:

| Key | Unit / value |
| --- | --- |
| `evedex_auth_age_ms` | milliseconds since the latest serialized authentication |
| `evedex_auth_expires_in_ms` | milliseconds, or `unknown` when the SDK exposes no expiry |
| `evedex_local_mutation_reserve` | remaining calls in the local mutation window at the latest health preflight |
| `evedex_local_mutation_capacity` | calls per local window; currently `30` |
| `evedex_local_mutation_window_ms` | local window duration; currently `60000` ms |
| `evedex_local_mutation_compensation_reserve` | mutations reserved for stop/cancel/emergency compensation; currently `4` |
| `evedex_local_mutation_entry_min_reserve` | minimum free slots required before entry so STOP and TARGET remain fundable; currently `7` |
| `evedex_venue_rate_limit_observable` | `true` or `false` |
| `evedex_venue_rate_limit_reserve` | venue-reported remaining calls, or `unknown` |

Metric consumers treat a missing, malformed or `unknown` value as unknown rather than
zero. `ENTRY_FILLED` and `ENTRY_PARTIAL_FILL` additionally carry
`decision_worst_entry_price`, `execution_average_price` and
`execution_shortfall_bps`.

## Runtime delivery durability

With Redis, consumed IDs, execution reports and completion are committed through
`kairos-persistence`; Redis is ACKed only after PostgreSQL commits. Configure
`KAIROS_PERSISTENCE_DATABASE_URL` through the deployment secret provider. This
transport guarantee complements, but does not replace, the venue-effect journal.

---

Part of the [Kairos](https://github.com/Kairos-cryptoAI/kairos) system. MIT licensed.
