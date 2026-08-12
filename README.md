# kairos-execution-engine

**Layer 6 — Execution Engine.** The hands of the Kairos system (no LLM). It consumes
risk-validated orders, switches only on their machine-readable `reason_code`, and
deterministically submits orders with protective trailing stops.

## Exchanges

- **EVEDEX** (`exchange.evedex.com`) is the production venue. Mutating requests are
  EIP-712 signed and rate-limited to 30 heavy requests per 60 seconds. Client order IDs
  follow EVEDEX's `[0-9]{5}:[0-9A-Fa-f]{26}` format. The prefix is the UTC day count
  since 24 July 2025, while the suffix is stable for the source event. Replays older
  than EVEDEX's accepted today/yesterday window are rejected before any network call.
- **CCXT** supports strategy testing on Binance testnet and other venues.

Both adapters are optional installation extras. The service is in `dry_run` mode by
default and makes no real exchange calls unless that setting is explicitly disabled.

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

---

Part of the [Kairos](https://github.com/Kairos-cryptoAI/kairos) system. MIT licensed.
