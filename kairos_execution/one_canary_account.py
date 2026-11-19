"""Operational account observations for exactly one bounded EVEDEX canary.

These authenticated REST reads are sequential, not an atomic portfolio
reconciliation. A caller must freeze a session baseline, keep the existing
protection/unknown-order interlocks, and charge late expenses after baseline.
No method signs, submits, cancels, or clears an unknown trading operation.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from typing import Any

import aiohttp

ORIGIN = "https://exchange-api.evedex.com"
MAX_BODY = 2_000_000
MAX_PAGES = 100
PAGE_SIZE = 100
TERMINAL_TPSL = frozenset({"done", "cancelled"})
KNOWN_TPSL = TERMINAL_TPSL | {"active", "waitOrder", "process", "triggered"}
ASSUMPTIONS = (
    "authenticated sequential REST is the operational state reported by EVEDEX",
    "reported pagination exhaustion is not a settlement or retention guarantee",
    "late fees or funding after baseline are charged to session loss",
    "unknown I/O keeps new entries blocked until independent reconciliation",
)


class CanaryAccountError(PermissionError):
    """Missing, inconsistent or unavailable observations block admission."""


def _money(value: Any) -> Decimal:
    if isinstance(value, bool) or value is None:
        raise CanaryAccountError("account monetary value missing")
    try:
        result = Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        raise CanaryAccountError("account monetary value invalid") from None
    if not result.is_finite():
        raise CanaryAccountError("account monetary value nonfinite")
    return result


def _rows(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        rows = value.get("list")
        if "count" in value and (type(value["count"]) is not int or value["count"] != len(rows or [])):
            raise CanaryAccountError("current-state list is truncated")
    else:
        rows = value
    if not isinstance(rows, list) or len(rows) > 10_000 or any(not isinstance(row, dict) for row in rows):
        raise CanaryAccountError("current-state rows missing or malformed")
    return rows


def _timestamp(value: Any) -> datetime:
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None:
            raise ValueError
        return result.astimezone(UTC)
    except (AttributeError, TypeError, ValueError):
        raise CanaryAccountError("source timestamp missing or invalid") from None


def _utc(value: datetime) -> str:
    if value.tzinfo is None:
        raise CanaryAccountError("explicit UTC time required")
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class RestReadDigest:
    path: str
    started_at: datetime
    finished_at: datetime
    body_sha256: str


@dataclass(frozen=True, slots=True)
class CanaryAccountObservation:
    account_id: str = field(repr=False)
    account_created_at: datetime
    started_at: datetime
    finished_at: datetime
    funding_usdt: Decimal
    available_usdt: Decimal
    adverse_unrealized_usdt: Decimal
    nonzero_positions: int
    open_orders: int
    nonterminal_tpsl: int
    pending_withdrawals: int
    tpsl_status_counts: tuple[tuple[str, int], ...]
    reads: tuple[RestReadDigest, ...]
    assumptions: tuple[str, ...] = ASSUMPTIONS

    @property
    def equity_lower_bound_usdt(self) -> Decimal:
        return self.funding_usdt + self.adverse_unrealized_usdt

    def require_flat(
        self, *, minimum_available: Decimal = Decimal("100"), now: datetime | None = None
    ) -> None:
        """Require the observed flat startup case; never infer missing zeroes."""
        self.require_recent(now or datetime.now(UTC))
        if not minimum_available.is_finite() or minimum_available < 0:
            raise CanaryAccountError("minimum capital invalid")
        if any((self.nonzero_positions, self.open_orders, self.nonterminal_tpsl, self.pending_withdrawals)):
            raise CanaryAccountError("account has current or unknown obligations")
        if self.adverse_unrealized_usdt != 0 or self.available_usdt != self.funding_usdt:
            raise CanaryAccountError("flat account balances are inconsistent")
        if self.available_usdt < minimum_available:
            raise CanaryAccountError("confirmed available capital is insufficient")

    def require_recent(self, now: datetime, *, max_age_seconds: int = 10) -> None:
        if now.tzinfo is None or type(max_age_seconds) is not int or not 1 <= max_age_seconds <= 30:
            raise CanaryAccountError("account freshness configuration invalid")
        if (
            not self.started_at <= self.finished_at <= now
            or (now - self.started_at).total_seconds() > max_age_seconds
        ):
            raise CanaryAccountError("account observation stale or future")


@dataclass(frozen=True, slots=True)
class CanaryExternalFlows:
    since: datetime
    until: datetime
    deposits_usdt: Decimal
    withdrawals_usdt: Decimal
    type_counts: tuple[tuple[str, int], ...]
    reads: tuple[RestReadDigest, ...]
    reported_pages_exhausted: bool = True
    finality_proven: bool = False

    @property
    def net_deposits_usdt(self) -> Decimal:
        return self.deposits_usdt - self.withdrawals_usdt


def observed_session_loss_usdt(
    *, baseline_equity_usdt: Decimal, current: CanaryAccountObservation, net_deposits_usdt: Decimal
) -> Decimal:
    """Fixed-baseline observed loss; depositing or restarting does not reset it.

    The runner must persist the baseline/STOP and separately reserve remaining
    risk and unreflected exit costs. This function cannot authenticate flows.
    """
    if not baseline_equity_usdt.is_finite() or not net_deposits_usdt.is_finite():
        raise CanaryAccountError("session baseline or flows nonfinite")
    return max(Decimal(0), baseline_equity_usdt + net_deposits_usdt - current.equity_lower_bound_usdt)


class EvedexCanaryAccountSource:
    """Concrete GET-only source with one fixed official HTTPS origin.

    Credentials live only in memory. No transport factory or user-supplied URL
    can promote data into an account observation. Tests replace private methods.
    """

    def __init__(self, *, api_key: str, expected_account_id: str) -> None:
        if (
            not isinstance(api_key, str)
            or not 1 <= len(api_key) <= 8192
            or any(not 33 <= ord(c) <= 126 for c in api_key)
        ):
            raise CanaryAccountError("API credential missing or malformed")
        if (
            not isinstance(expected_account_id, str)
            or not 1 <= len(expected_account_id) <= 160
            or expected_account_id != expected_account_id.strip()
        ):
            raise CanaryAccountError("explicit expected account required")
        self._api_key = api_key
        self._account = expected_account_id

    async def _get(
        self, session: aiohttp.ClientSession, path: str, reads: list[RestReadDigest], **params: Any
    ) -> Any:
        start = datetime.now(UTC)
        failed = False
        value = None
        try:
            async with session.get(
                ORIGIN + path,
                params=params,
                headers={"x-api-key": self._api_key, "Accept": "application/json"},
                allow_redirects=False,
            ) as response:
                if response.status != 200:
                    raise ValueError
                body = bytearray()
                async for chunk in response.content.iter_chunked(65536):
                    body.extend(chunk)
                    if len(body) > MAX_BODY:
                        raise ValueError

                def pairs(items):
                    out = {}
                    for k, v in items:
                        if k in out:
                            raise ValueError
                        out[k] = v
                    return out

                def invalid(_):
                    raise ValueError

                value = json.loads(body, parse_float=Decimal, parse_constant=invalid, object_pairs_hook=pairs)
                finished = datetime.now(UTC)
                if finished < start:
                    raise ValueError
                reads.append(RestReadDigest(path, start, finished, hashlib.sha256(body).hexdigest()))
        except Exception:
            failed = True
        if failed:
            raise CanaryAccountError("authenticated account GET failed or returned invalid data")
        return value

    def _identity(self, value: Any) -> datetime:
        if (
            not isinstance(value, dict)
            or isinstance(value.get("exchangeId"), bool)
            or str(value.get("exchangeId")) != self._account
            or value.get("marginCall") is not False
        ):
            raise CanaryAccountError("account identity or margin state differs")
        return _timestamp(value.get("createdAt"))

    async def _pages(self, session, path, reads, *, unique_ids: bool = True, **params):
        expected = None
        result = []
        identities = set()
        for offset in range(0, MAX_PAGES * PAGE_SIZE, PAGE_SIZE):
            page = await self._get(session, path, reads, limit=PAGE_SIZE, offset=offset, **params)
            if not isinstance(page, dict) or type(page.get("count")) is not int:
                raise CanaryAccountError("history page count missing")
            count, rows = page["count"], page.get("list")
            if not 0 <= count <= MAX_PAGES * PAGE_SIZE or not isinstance(rows, list) or len(rows) > PAGE_SIZE:
                raise CanaryAccountError("history page exceeded budget")
            if expected is None:
                expected = count
            if count != expected or page.get("next") is not None:
                raise CanaryAccountError("history count changed or cursor unsupported")
            for row in rows:
                if not isinstance(row, dict):
                    raise CanaryAccountError("history row malformed")
                if unique_ids:
                    identity = row.get("id")
                    if not isinstance(identity, str) or not identity or identity in identities:
                        raise CanaryAccountError("history ID missing or repeated")
                    identities.add(identity)
            result.extend(rows)
            if len(result) == expected:
                return result
            if len(rows) != PAGE_SIZE or len(result) > expected:
                raise CanaryAccountError("history page truncated")
        raise CanaryAccountError("history page budget exceeded")

    async def observe(self) -> CanaryAccountObservation:
        """Capture all present obligations, including pending withdrawals."""
        reads: list[RestReadDigest] = []
        started = datetime.now(UTC)
        async with (
            asyncio.timeout(30),
            aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8), trust_env=False) as session,
        ):
            created = self._identity(await self._get(session, "/api/user/me", reads))
            balance = await self._get(session, "/api/market/available-balance", reads)
            funding_rows = _rows(await self._get(session, "/api/user/funding", reads))
            positions = _rows(await self._get(session, "/api/position", reads))
            orders = _rows(await self._get(session, "/api/order/opened", reads))
            tpsl = await self._pages(session, "/api/tpsl", reads)
            withdrawals = await self._pages(
                session, "/api/transfer", reads, type="transfer-pfutures-balance", status="pending"
            )
            if self._identity(await self._get(session, "/api/user/me", reads)) != created:
                raise CanaryAccountError("account creation identity changed")
        if not isinstance(balance, dict) or not isinstance(balance.get("funding"), dict):
            raise CanaryAccountError("native balance missing")
        if str(balance.get("currency", "")).lower() != "usdt":
            raise CanaryAccountError("canary supports only USDT collateral")
        funding = balance["funding"]
        if str(funding.get("currency", "")).lower() != "usdt":
            raise CanaryAccountError("funding currency differs")
        cash, free = _money(funding.get("balance")), _money(balance.get("availableBalance"))
        native_funding = [r for r in funding_rows if str(r.get("coin", "")).lower() == "usdt"]
        if len(native_funding) != 1 or _money(native_funding[0].get("quantity")) != cash:
            raise CanaryAccountError("funding endpoints disagree")
        if any(
            str(r.get("coin", "")).lower() != "usdt" and _money(r.get("quantity")) != 0 for r in funding_rows
        ):
            raise CanaryAccountError("unvalued collateral balance is present")
        nonzero = sum(_money(row.get("quantity")) != 0 for row in positions)
        # Native arrays are required even when empty; deprecated maps cannot
        # replace them. Cross-checking avoids accepting missing exposure.
        pos_summaries, order_summaries = _rows(balance.get("position")), _rows(balance.get("openOrder"))
        if not nonzero and any(
            _money(r.get("volume")) != 0 or _money(r.get("initialMargin")) != 0 for r in pos_summaries
        ):
            raise CanaryAccountError("position summary contradicts quantities")
        if not orders and any(
            _money(r.get("unFilledVolume")) != 0 or _money(r.get("unFilledInitialMargin")) != 0
            for r in order_summaries
        ):
            raise CanaryAccountError("order summary contradicts opened orders")
        statuses: Counter[str] = Counter()
        for row in tpsl:
            status = row.get("status")
            if status not in KNOWN_TPSL:
                raise CanaryAccountError("unknown TP/SL status")
            _money(row.get("quantity"))
            _money(row.get("triggeredQuantity"))
            statuses[status] += 1
        finished = datetime.now(UTC)
        previous = started
        for read in reads:
            if not previous <= read.started_at <= read.finished_at <= finished:
                raise CanaryAccountError("account capture clocks regressed")
            previous = read.finished_at
        return CanaryAccountObservation(
            self._account,
            created,
            started,
            finished,
            cash,
            free,
            -abs(_money(balance.get("negativeUnPnL"))),
            nonzero,
            len(orders),
            sum(v for k, v in statuses.items() if k not in TERMINAL_TPSL),
            len(withdrawals),
            tuple(sorted(statuses.items())),
            tuple(reads),
        )

    async def external_flows_since(self, since: datetime) -> CanaryExternalFlows:
        """Re-read the fixed session interval; never accumulate/hash-dedup rows."""
        until = datetime.now(UTC)
        if since.tzinfo is None or since >= until:
            raise CanaryAccountError("flow interval invalid")
        reads: list[RestReadDigest] = []
        async with (
            asyncio.timeout(30),
            aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8), trust_env=False) as session,
        ):
            self._identity(await self._get(session, "/api/user/me", reads))
            rows = await self._pages(
                session,
                "/api/user/funding-transfer",
                reads,
                unique_ids=False,
                after=_utc(since),
                before=_utc(until),
            )
            self._identity(await self._get(session, "/api/user/me", reads))
        deposits = withdrawals = Decimal(0)
        counts: Counter[str] = Counter()
        for row in rows:
            if str(row.get("coin", "")).lower() != "usdt":
                raise CanaryAccountError("flow currency unsupported")
            if not since <= _timestamp(row.get("createdAt")) <= until:
                raise CanaryAccountError("flow outside fixed session interval")
            kind, quantity = row.get("type"), _money(row.get("quantity"))
            if not isinstance(kind, str):
                raise CanaryAccountError("flow type missing")
            counts[kind] += 1
            if kind == "deposit":
                if quantity <= 0:
                    raise CanaryAccountError("deposit quantity is nonpositive")
                deposits += quantity
            elif kind == "withdraw":
                withdrawals += abs(quantity)
            elif kind not in {
                "realizedPnl",
                "orderFillFee",
                "fundingRate",
                "liquidationFee",
                "bonusRefund",
                "yieldReward",
                "copyTradingFee",
            }:
                raise CanaryAccountError("unclassified balance-changing flow")
        return CanaryExternalFlows(
            since, until, deposits, withdrawals, tuple(sorted(counts.items())), tuple(reads)
        )
