# Causal taker/IOC fill model and isolated simulator controller v1

Status: **ISOLATED, TESTED SIMULATOR COMPONENT**. This package contains a pure
Decimal IOC fill kernel, its strict contract bridge, and a durable
`SimulationExecutionController`. The controller operates only through an injected,
isolated `SimulationRepository` on sealed SIM contracts, closed bars and top-N book
frames. A disposable PostgreSQL integration gate in
[`kairos-deploy`](https://github.com/Kairos-cryptoAI/kairos-deploy/tree/main/tests/sim_gate)
exercises that controller against sealed fixtures.

This is not a continuously running simulator service, an exchange adapter, EVEDEX
DEV qualification, a strategy approval or a PAPER/LIVE readiness claim. It sits
outside `TradingMode` and `PaperExecutionEngine`; it has no EVEDEX adapter, no
market-data connection, no listener, and never reads secrets or submits orders. The
controller may use its injected SIM-only repository, but does not make venue or
provider calls itself. Existing DEV and legacy DRY_RUN contracts are unchanged.
Every result remains `SIMULATED`, with `venue_execution_observed=false`,
`paper_qualification_eligible=false` and no alpha claim.

## Public interface and scope

`kairos_execution.simulation` exports the pure kernel:

```python
simulate_ioc(
    command: IOCCommand,
    frame: AcceptedBookFrame,
    assumptions: FillAssumptions,
    state: LiquidityState,
    *,
    as_of_ms: int,
) -> ModelStep
```

The returned step contains an immutable `FillOutcome`, a new immutable
`LiquidityState`, and an exact-replay flag. Inputs are strict, frozen Pydantic
models with forbidden extra fields. Python inputs require Decimal prices and
quantities and integer timestamps (not floats, booleans or coerced strings).
Non-finite, non-positive and oversized amounts are rejected. JSON round trips use
`model_validate_json`; canonical JSON encodes exact normalized decimals as strings.
The kernel revalidates instances to catch unsafe `model_copy`/`model_construct`
bypasses. Calculations use a fixed 96-digit Decimal context, independent of the
caller's process context. Fingerprints use SHA-256 over canonical JSON.

It also exports `SimulationExecutionController`. Given an already sealed
`SimulationAdmissionV2`, the controller persists a SIM trade and then evaluates
its deterministic next-bar IOC entry. It processes only matching stored
`ClosedBarEventV1` records for stop, target and timeout exits; an ambiguous candle
uses the frozen adverse `STOP_WINS` rule, and a current sealed top-N frame remains
mandatory at each logical order arrival. Prepared commands, terminal receipts,
private liquidity state, lifecycle events and terminal results use the isolated
repository so a restart replays durable evidence rather than recalculating a
completed command.

Scope is deliberately restricted to modelled taker **IOC_LIMIT** commands for
BTCUSDT, ETHUSDT, SOLUSDT, BNBUSDT and XRPUSDT using caller-admitted Binance UM
top-N snapshots. Quantity is base-asset quantity and prices are USDT per base
unit. `notional_quote`, `fee_quote` and `implementation_shortfall_quote` are USDT,
not fiat USD. No USDT/USD parity, collateral conversion or contract-multiplier
assumption is hidden in these names. All outputs explicitly say `SIMULATED`,
`venue_execution_observed=false`, `paper_qualification_eligible=false` and
`alpha_claim=false`.

## Causal admission is a caller responsibility

Each input frame carries a tape ID, stream epoch, tape sequence, exchange update
ID, exchange/receive/persist timestamps, raw-payload checksum and continuity state.
`ADMITTED` means that an upstream recorder has validated and durably committed the
frame. **The DTO and fill function cannot prove that this happened** or that a
supplied raw checksum identifies genuine Binance data. The controller consumes only
the repository's stored, sealed inputs; it does not replace a recorder or validate
an exchange stream.

Before a SIM session invokes this kernel or controller, the upstream recorder and
session runner must:

1. Validate raw frame identity, ordering, continuity, instrument rules and clock
   integrity; durably record frames and explicit gap/reconnect/unknown intervals.
2. Persist immutable commands and timers, and select the last admissible frame
   actually known and durable at simulated order arrival. It must not cherry-pick
   an older favourable snapshot or mark a gap as admitted.
3. Serialize commands in one recorded order for each session/symbol. Equal arrival
   times require a stable caller-owned event-order tie break. All competing
   allocations must share the same state, never independent copies.
4. Atomically store command outcome, receipts and the returned liquidity state.
   A durable lock/CAS and an outcome journal are required for concurrent/restarted
   execution.

The isolated controller and `SimulationRepository` implement the SIM-side
prepared-command, receipt, lifecycle and recovery boundary for already sealed
inputs. Its disposable integration test proves durable replay and trade-chain
verification in a synthetic database. That proof does not establish a live
recorder, continuous service, venue semantics or operator-level multi-process
availability.

The model itself enforces:

- `exchange_at <= received_at <= persisted_at <= arrival_at`. Future or not-yet-
  durable frames cannot fill; there is no interpolation across missing time.
- Explicit order latency, exchange-book age and receive-latency limits. All limits
  are required assumptions, not measured latency or SLA claims. Future exchange
  clock readings are rejected, not silently corrected.
- Non-regressing evaluation clock, terminal command-arrival cursor and selected
  frame sequence/update/timestamps. New backdated commands cannot execute after a
  later terminal command. Exact terminal replays return the original receipt.
- Same selected sequence with different content is a conflict. Later selected
  frames require higher exchange update IDs. Sequence jumps are permitted because
  frames not selected for an order can lie between them: **this is not exchange
  gap detection**. Top-N update-ID jumps do not themselves prove continuity.
- `GAP`, `RECONNECT`, `UNKNOWN`, `UNAVAILABLE`, epoch changes, stale frames and
  ordering/rule conflicts create a sticky fail-closed session barrier. A later
  fresh frame cannot clear it. There is no automatic restart/reconnect reset.

`WAIT` means the explicit evaluation clock precedes arrival. It creates no receipt,
does not advance the kernel clock or reserve depth, and returns unchanged state. The
controller preserves that prepared command in the SIM repository for
`recover_prepared`; an external SIM runner must still supply its wake-up time and
never replace its immutable identity. Expired, premature, not-durable and off-grid
commands terminate as `NO_FILL`; they do not gain extra opportunities by
resubmission under the same ID.

## Fill and cost assumptions

`FillAssumptions` requires latency, maximum book age and receive latency,
depth-participation fraction, adverse slippage, taker fee, price tick and quantity
step. Zero fee/slippage must be explicit, not inferred from missing configuration.
These parameters are model assumptions, not verified venue fee tiers or limits.

The walk visits asks ascending for BUY and bids descending for SELL:

```text
available(side, price) = max(0, displayed_quantity * participation - prior_debit)
capacity = floor(available / quantity_step) * quantity_step
adjusted_price = book_price * (1 +/- adverse_slippage_bps / 10000)
execution_price = adverse tick rounding of adjusted_price
fill_quantity = min(remaining IOC quantity, capacity)
fee_quote = fill_quantity * execution_price * taker_fee_bps / 10000
```

BUY rounds execution price upward; SELL rounds downward. The command's limit cap
applies to the adjusted executable price, not the unadjusted book. Quantity rounds
down. An IOC never rests: unused quantity is cancelled, with full, partial or no
fill possible. The model never invents undisplayed depth or maker queue priority.
Crossed/locked, empty admitted, duplicate-price or unsorted books are rejected;
all displayed levels must match configured price/quantity increments.

Depth is debited **cumulatively for the whole session by side and price**. A new
snapshot, repeated command, or disappearance/reappearance of a price cannot erase
that debit. Larger newly displayed size exposes only capacity above the previous
debit, not a fresh copy of the full visible liquidity. ASK and BID debits are
separate. This is intentionally pessimistic and underfills replenishing markets;
it is not a calibrated queue or market-impact model. Creating a separate state
per allocation, reconnect or restart would invalidate this safety property.

Implementation shortfall uses signed filled notional against the observed arrival
mid and excludes the separately reported fee. Spread, adverse slippage, tick
rounding and walked levels are already present in execution prices; adding spread
again would double count it. No unfilled-opportunity PnL is imputed.

## Replay, limits and honesty

State binds the session, tape, stream epoch, symbol and assumptions fingerprint.
Terminal receipts are immutable and idempotent by command ID plus canonical
payload hash. Reuse with changed command content or policy raises a conflict.
Canonical state serialization preserves consumption and receipts after reload.
There is a hard ceiling of 1,024 terminal commands; reaching it raises an error
instead of evicting idempotency evidence. This bounded in-memory model limit is
not the DEV canary allowance, nor authorization for 1,024 trades.

Serial replay tests validate the pure state transition. Separate controller tests
and the disposable PostgreSQL gate validate SIM-side durable receipts, terminal
trade-chain integrity and prepared-command recovery. They do not demonstrate a
continuous multi-process service, genuine market-data provenance, venue execution
or production-scale availability. A model barrier cannot be bypassed by discarding
state: any later recovery/session admission must preserve evidence and be designed
with lifecycle reconciliation first.

## Implemented isolation and remaining full-pipeline work

The following components now exist only inside the isolated SIM contour:

- Versioned SIM sessions, admissions, commands, receipts, lifecycle events and
  results, including SIM-only source/account/session identities.
- A durable `SimulationExecutionController` that executes entry, stop, target and
  timeout lifecycle transitions from stored bars and stored top-N frames, preserves
  `STOP_WINS` for an ambiguous candle, and leaves an unfilled residual as
  `UNRESOLVED` rather than inventing a close.
- A disposable `kairos-sim` integration gate with a synthetic PostgreSQL database,
  sealed fixture tape and no EVEDEX, PAPER, LIVE, LLM, feed or secret configuration.

The following remains required before Kairos has a complete market-data simulator:

- A continuous genuine book-tape recorder, causal frame selection,
  gap/reconnect admission and clock-skew monitoring from an upstream data source.
- The complete deterministic pipeline
  `closed bar -> strategy -> router -> review -> risk -> SimulationAdmissionV2`.
  The controller can preserve a supplied intent/route/review/simulated-risk
  decision, but the current gate seeds those sealed inputs; runtime services do not
  yet produce them for the simulator.
- Portfolio allocation, funding, collateral/margin, liquidation, leverage, equity
  accounting, calibrated partial-fill protection and any modelled position-close
  accounting beyond the controller's single-trade lifecycle.
- Maker limit orders, queue priority, hidden liquidity, trade-through inference,
  EVEDEX venue semantics, true exchange ACKs, measured latency or calibrated impact.
- A production-like continuous simulator deployment, soak or operational recovery
  qualification. The existing disposable gate is neither a canary nor a
  real-exchange qualification. No alpha result, strategy enablement or readiness
  flag changes follow from any simulator result.

Future full-pipeline work must retain these SIM isolation boundaries. Frozen research
plans, evaluators and historical research results remain unchanged; synthetic model
fills are not a substitute for EVEDEX DEV evidence and cannot alter
`PAPER_QUALIFIED`, `ALPHA_READY` or `LIVE_READY`.

## Local verification

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_simulation_fill_model.py -q -p no:cacheprovider
.\.venv\Scripts\python.exe -m pytest tests/test_simulation_bridge.py tests/test_simulation_controller.py -q -p no:cacheprovider
.\.venv\Scripts\ruff.exe check kairos_execution/simulation tests/test_simulation_fill_model.py tests/test_simulation_bridge.py tests/test_simulation_controller.py
.\.venv\Scripts\mypy.exe kairos_execution/simulation
```

The hermetic tests exercise full/partial/no fill, adverse tick rounding, caps,
fees, depth sharing and non-replenishment, timestamp/order/namespace validation,
gap barriers, exact replay after serialized restart, changed command IDs,
backdated new commands, fixed-context decimal determinism, input/output integrity,
single-trade stop/target/timeout lifecycle, and bounded conservation checks. The
separate `kairos-sim` gate additionally runs
`tests/test_simulation_controller_integration.py` against only a disposable
synthetic database. Neither test layer uses a real or paid API, wallet,
credentials, EVEDEX endpoint or PAPER database.
