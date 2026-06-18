# kairos-execution-engine

**Layer 6 — Execution Engine.** The hands of the system (no LLM). It consumes a
risk-validated order, switches on its `reason_code`, and places atomic orders — always
arming a **server-side trailing stop** so a position is never left naked if the bot
loses connectivity.

## Exchanges
- **EVEDEX** (`exchange.evedex.com`) — the production venue. Orders are **EIP-712 signed**
  (domain `EVEDEX` v2) and float values normalised with `round(value * 10^8)`, exactly as
  the EVEDEX reference (`exchange-crypto`) specifies. Heavy requests are rate-limited to
  **30 / 60s**; orders below the **$5** min notional are rejected locally.
- **CCXT** — for testing strategies on Binance testnet and other venues.

## Safety
- **`reason_code` only.** The engine never free-interprets model text; it switches on the
  validated code (`ENTER_LONG_TREND` → buy, `CLOSE_POSITION` → close, ...).
- **`LOCAL_QUANT_MODE`.** When the Risk Manager's circuit breaker detaches the LLM, the
  engine refuses to open new positions and only manages protective stops.
- **`dry_run` by default** — it will not send real orders until you explicitly disable it.

## Run
```bash
pip install -e ../kairos-core && pip install -e ".[dev,evedex]"
make test
KAIROS_DRY_RUN=true python -m kairos_execution
```
Consumes `kairos.risk.validated_order` + `kairos.system.control`; emits `kairos.execution.report`.

---
Part of the [Kairos](https://github.com/TheLitis/kairos) system. MIT licensed.
