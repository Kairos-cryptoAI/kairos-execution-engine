# Operational flat-account source for one EVEDEX canary

`EvedexCanaryAccountSource` owns a fixed-origin HTTPS GET client. Its observation
checks the account identity before and after sequential reads, finite position
quantities, opened orders, all reported TP/SL pages and statuses, pending
withdrawals, current funding from two endpoints, and native balance summaries.
It never treats a missing field as zero, rejects unsupported collateral and
keeps raw private bodies out of logs and returned representations.

The returned `CanaryAccountObservation` is an operational REST observation,
**not** a `VerifiedLiveAccountV1` or a fully reconciled portfolio. Its
`require_flat()` requires a recent capture, no observed exposure/obligations,
funding equal to available USDT, no reported adverse unrealized PnL and at
least $100 available. A current observation can also retain nonflat state for
monitoring; that observation cannot pass flat admission.

`external_flows_since()` rereads the fixed interval from an immutable session
start. It distinguishes external deposits/withdrawals from costs and trading
cash changes and never accumulates locally deduplicated funding rows. Unknown
flow types fail closed. The API's reported page exhaustion is an operational
coverage observation, not proof against retention or late correction.

`observed_session_loss_usdt()` uses the original actual account-equity lower
bound plus net external deposits minus the current lower bound. Funding plus
only adverse reported unrealized PnL is conservative with respect to positive
unrealized gains. The runner must persist the observed starting account value independently of the
capital slice used for sizing. Substituting the slice for the baseline can postpone STOP.

Remaining exit costs/risk must be reserved separately without double counting.
The threshold is a stop trigger and cannot guarantee a maximum realized loss.

## Findings from a read-only check

A bounded check exercised the authenticated REST account source. The
observation met flat-account admission at the time of capture. That result
does not establish current account state or final accounting. Terminal TP/SL
records must be distinguished from active obligations.

The native fill schema omitted fees, and the available historical records did
not support reconciliation to the opening balance. The beginning of available
history and any late corrections remain material to the calculation. A
restricted canary that starts from a fresh cash observation must record that
assumption and attribute subsequent expenses to its fixed session.

This check created no session, signature, order, cancellation or transfer.
The operator retains the original observation and supporting records privately.

## Concrete Risk entrypoint

`OperationalFlatCanaryRisk` consumes the observation, a previously frozen real
account baseline, net deposits, native intent/venue/allocation DTOs and explicit
instrument/cost bounds. It calls the existing `LiveRiskEvaluator._size` pure
kernel using a two-field cash view. It does not forge an `AccountSnapshotV2`
or `reconciled=true` and does not call the full portfolio `evaluate()` path.

The separate result is `WAIT` or `ELIGIBLE` for risk sizing, with a SHA-256
binding of its concrete inputs and an original expiry. It caps the capital
slice at $100, nominal leverage at 1x, and risk at the stricter of native limits,
$0.25/trade, 1% aggregate and the $5 remaining session threshold. Existing
lower fraction/dollar/daily caps cannot be relaxed. Native sizing is followed
by lot rounding and a two-sided fee/slippage bound that can only reduce size.
The extra remaining-cost allowance must be explicit; missing costs return WAIT.

`entry_limit_price` preserves the original tick-compliant book quote. Adjusted
`scenario_entry_price` and `scenario_stop_exit_price` are cost scenarios and
must not be sent as order or stop prices. A possible candidate still requires
the caller's actual strategy/selection admission. The Risk result does not
claim alpha, fill, protection or one-use execution authority.

The source and sizer do not bypass the existing production verifiers or arm
trading. A separately bounded one-canary runner must persist the immutable
baseline/STOP, prevent admission reuse and keep unknown-I/O and protective-exit
interlocks. Standard authenticated REST operational assumptions are an explicit
scope reduction for this one-canary path, not a claim about full portfolio
reconciliation or historical coverage.
