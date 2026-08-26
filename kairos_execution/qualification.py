"""Read-only EVEDEX DEV qualification with machine-readable fail-closed evidence."""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import tempfile
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from .adapters.evedex import EvedexAdapter

try:
    import aiohttp
except Exception:  # pragma: no cover - dependency is required at runtime
    aiohttp = None  # type: ignore


class CheckStatus(StrEnum):
    PASS = "PASS"  # nosec B105
    BLOCKED = "BLOCKED"
    FAIL = "FAIL"


@dataclass(frozen=True)
class HttpObservation:
    status: int
    latency_ms: float
    headers: dict[str, str]
    payload: Any


@dataclass(frozen=True)
class QualificationCheck:
    name: str
    status: CheckStatus
    detail: str
    latency_ms: float | None = None
    http_status: int | None = None
    observed_headers: dict[str, str] | None = None


@dataclass(frozen=True)
class EvedexQualificationReport:
    schema_version: int
    generated_at: str
    exchange_base_url: str
    symbol_map: dict[str, str]
    authenticated: bool
    checks: tuple[QualificationCheck, ...]
    live_orders_allowed: bool = False

    @property
    def status(self) -> CheckStatus:
        statuses = {item.status for item in self.checks}
        if CheckStatus.FAIL in statuses:
            return CheckStatus.FAIL
        if CheckStatus.BLOCKED in statuses:
            return CheckStatus.BLOCKED
        return CheckStatus.PASS

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "generated_at": self.generated_at,
            "exchange_base_url": self.exchange_base_url,
            "symbol_map": dict(sorted(self.symbol_map.items())),
            "authenticated": self.authenticated,
            "status": self.status.value,
            "live_orders_allowed": False,
            "checks": [asdict(item) for item in self.checks],
        }


Getter = Callable[[str, Mapping[str, str]], Awaitable[HttpObservation]]

_AUTH_PATHS = (
    "/api/user/me",
    "/api/market/available-balance",
    "/api/position",
    "/api/order/opened",
    "/api/tpsl",
)


class _ReadOnlySigner:
    address = "0x0000000000000000000000000000000000000000"

    def sign_typed_data(self, domain: Any, types: Any, message: Any) -> str:
        raise RuntimeError("qualification must never sign or mutate venue state")


def _finite_positive(value: Any, field: str) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{field} is not numeric")
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} is not numeric") from exc
    if not math.isfinite(parsed) or parsed <= 0:
        raise ValueError(f"{field} must be finite and positive")
    return parsed


def _aware_timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} is not an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} is not an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a timezone")
    return parsed.astimezone(UTC)


def _public_headers(headers: Mapping[str, str]) -> dict[str, str]:
    allowed = ("ratelimit", "x-ratelimit", "retry-after")
    return {key.lower(): str(value) for key, value in headers.items() if key.lower().startswith(allowed)}


async def _qualify(
    getter: Getter,
    *,
    exchange_base_url: str,
    symbol_map: dict[str, str],
    jwt: str | None,
    now: datetime,
) -> EvedexQualificationReport:
    checks: list[QualificationCheck] = []
    observations: dict[str, HttpObservation] = {}

    async def fetch(path: str, *, authenticated: bool = False) -> HttpObservation | None:
        headers = {"Authorization": f"Bearer {jwt}"} if authenticated and jwt else {}
        try:
            observation = await getter(path, headers)
        except Exception as exc:
            checks.append(
                QualificationCheck(
                    name=f"http:{path}",
                    status=CheckStatus.FAIL,
                    detail=f"{type(exc).__name__}: {exc}",
                )
            )
            return None
        observations[path] = observation
        if observation.status != 200:
            checks.append(
                QualificationCheck(
                    name=f"http:{path}",
                    status=CheckStatus.FAIL,
                    detail="read-only endpoint did not return HTTP 200",
                    latency_ms=observation.latency_ms,
                    http_status=observation.status,
                    observed_headers=_public_headers(observation.headers),
                )
            )
            return None
        return observation

    market = await fetch("/api/market")
    if market is not None:
        try:
            if not isinstance(market.payload, dict) or market.payload.get("state") != "active":
                raise ValueError("matcher state is not active")
            _aware_timestamp(market.payload.get("updatedAt"), "market.updatedAt")
            checks.append(
                QualificationCheck(
                    name="matcher_state",
                    status=CheckStatus.PASS,
                    detail="matcher reports active",
                    latency_ms=market.latency_ms,
                    http_status=market.status,
                    observed_headers=_public_headers(market.headers),
                )
            )
        except ValueError as exc:
            checks.append(QualificationCheck("matcher_state", CheckStatus.FAIL, str(exc)))

    instruments_response = await fetch("/api/market/instrument")
    instruments_by_name: dict[str, dict[str, Any]] = {}
    if instruments_response is not None:
        payload = instruments_response.payload
        if not isinstance(payload, list) or not all(isinstance(item, dict) for item in payload):
            checks.append(
                QualificationCheck("instrument_contract", CheckStatus.FAIL, "instrument list is malformed")
            )
        else:
            instruments_by_name = {str(item.get("name", "")).upper(): item for item in payload}
            try:
                for logical, venue in symbol_map.items():
                    item = instruments_by_name.get(venue)
                    if item is None:
                        raise ValueError(f"{logical}->{venue} is absent from EVEDEX instruments")
                    if str(item.get("trading")) != "all" or str(item.get("visibility")) != "all":
                        raise ValueError(
                            f"{venue} is not fully tradable/visible: "
                            f"trading={item.get('trading')!r}, visibility={item.get('visibility')!r}"
                        )
                    for field in (
                        "lastPrice",
                        "markPrice",
                        "minQuantity",
                        "maxQuantity",
                        "quantityIncrement",
                        "priceIncrement",
                    ):
                        _finite_positive(item.get(field), f"{venue}.{field}")
                    updated_at = _aware_timestamp(item.get("updatedAt"), f"{venue}.updatedAt")
                    age_seconds = (now - updated_at).total_seconds()
                    # Instrument updatedAt is a version marker, not a heartbeat;
                    # real-time freshness is proven separately by depth/trades.
                    if age_seconds < -300:
                        raise ValueError(f"{venue} instrument snapshot is from the future")
                checks.append(
                    QualificationCheck(
                        "instrument_contract",
                        CheckStatus.PASS,
                        f"validated {len(symbol_map)} mapped instruments and trading rules",
                        latency_ms=instruments_response.latency_ms,
                        http_status=instruments_response.status,
                        observed_headers=_public_headers(instruments_response.headers),
                    )
                )
            except ValueError as exc:
                checks.append(QualificationCheck("instrument_contract", CheckStatus.FAIL, str(exc)))

    for logical, venue in sorted(symbol_map.items()):
        depth_path = f"/api/market/{venue}/deep?marketLevel=1"
        depth = await fetch(depth_path)
        if depth is not None:
            try:
                if not isinstance(depth.payload, dict):
                    raise ValueError("depth payload is not an object")
                bids = depth.payload.get("bids")
                asks = depth.payload.get("asks")
                if not isinstance(bids, list) or not bids or not isinstance(asks, list) or not asks:
                    raise ValueError("best bid/ask is missing")
                bid = _finite_positive(bids[0].get("price"), f"{venue}.bid")
                ask = _finite_positive(asks[0].get("price"), f"{venue}.ask")
                bid_qty = _finite_positive(bids[0].get("quantity"), f"{venue}.bid_quantity")
                ask_qty = _finite_positive(asks[0].get("quantity"), f"{venue}.ask_quantity")
                if bid >= ask:
                    raise ValueError("best bid is not below best ask")
                timestamp = _finite_positive(depth.payload.get("t"), f"{venue}.depth_timestamp")
                age_seconds = now.timestamp() - timestamp / 1000
                if age_seconds < -300 or age_seconds > 30:
                    raise ValueError("depth snapshot is stale or from the future")
                mid = (bid + ask) / 2
                spread_bps = (ask - bid) / mid * 10_000
                checks.append(
                    QualificationCheck(
                        f"depth:{logical}",
                        CheckStatus.PASS,
                        f"{venue} spread={spread_bps:.4f}bps bid_qty={bid_qty:g} ask_qty={ask_qty:g}",
                        latency_ms=depth.latency_ms,
                        http_status=depth.status,
                        observed_headers=_public_headers(depth.headers),
                    )
                )
            except (AttributeError, ValueError) as exc:
                checks.append(QualificationCheck(f"depth:{logical}", CheckStatus.FAIL, str(exc)))

        trades_path = f"/api/market/{venue}/recent-trades"
        trades = await fetch(trades_path)
        if trades is not None:
            try:
                if not isinstance(trades.payload, list):
                    raise ValueError("recent-trades payload is not a list")
                if not trades.payload:
                    checks.append(
                        QualificationCheck(
                            f"recent_trades:{logical}",
                            CheckStatus.BLOCKED,
                            f"{venue} returned no recent trades; real liquidity is unverified",
                        )
                    )
                    continue
                latest = max(
                    _aware_timestamp(item.get("createdAt"), f"{venue}.trade.createdAt")
                    for item in trades.payload
                    if isinstance(item, dict)
                )
                for item in trades.payload:
                    if not isinstance(item, dict) or str(item.get("instrument", "")).upper() != venue:
                        raise ValueError("recent trade has malformed instrument identity")
                    _finite_positive(item.get("fillQuantity"), f"{venue}.fillQuantity")
                    _finite_positive(item.get("fillPrice"), f"{venue}.fillPrice")
                age_seconds = (now - latest).total_seconds()
                if age_seconds < -300 or age_seconds > 300:
                    raise ValueError("latest trade is stale or from the future")
                checks.append(
                    QualificationCheck(
                        f"recent_trades:{logical}",
                        CheckStatus.PASS,
                        f"validated {len(trades.payload)} recent {venue} trades",
                        latency_ms=trades.latency_ms,
                        http_status=trades.status,
                        observed_headers=_public_headers(trades.headers),
                    )
                )
            except (ValueError, TypeError) as exc:
                checks.append(QualificationCheck(f"recent_trades:{logical}", CheckStatus.FAIL, str(exc)))

    if not jwt:
        checks.append(
            QualificationCheck(
                "authenticated_reconciliation",
                CheckStatus.BLOCKED,
                "JWT file was not provided; authenticated read-only endpoints were not contacted",
            )
        )
        checks.append(
            QualificationCheck(
                "observed_account_quota",
                CheckStatus.BLOCKED,
                "authenticated response headers and effective account quota remain unverified",
            )
        )
    else:
        auth_payloads: dict[str, Any] = {}
        for path in _AUTH_PATHS:
            response = await fetch(path, authenticated=True)
            if response is not None:
                auth_payloads[path] = response.payload
        if len(auth_payloads) == len(_AUTH_PATHS):
            adapter = EvedexAdapter(
                exchange_base_url=exchange_base_url,
                signer=_ReadOnlySigner(),
                chain_id=1,
                jwt=jwt,
                dry_run=False,
                symbol_map=symbol_map,
                clock=lambda: now,
            )

            async def recorded_get(path: str) -> Any:
                return auth_payloads[path]

            adapter._get = recorded_get  # type: ignore[method-assign]
            try:
                snapshot = await adapter.fetch_account_snapshot(
                    account_id="qualification",
                    peak_equity_usd=0,
                )
                checks.append(
                    QualificationCheck(
                        "authenticated_reconciliation",
                        CheckStatus.PASS,
                        "cross-checked account, balance, positions, orders, and TP/SL; "
                        f"positions={len(snapshot.positions)} open_orders={len(snapshot.open_order_ids)}",
                    )
                )
            except Exception as exc:
                checks.append(
                    QualificationCheck(
                        "authenticated_reconciliation",
                        CheckStatus.FAIL,
                        f"{type(exc).__name__}: {exc}",
                    )
                )
        quota_headers = {
            key: value
            for path in _AUTH_PATHS
            if path in observations
            for key, value in _public_headers(observations[path].headers).items()
        }
        checks.append(
            QualificationCheck(
                "observed_account_quota",
                CheckStatus.PASS if quota_headers else CheckStatus.BLOCKED,
                (
                    f"observed quota headers: {sorted(quota_headers)}"
                    if quota_headers
                    else "authenticated API emitted no quota headers; effective quota is unverified"
                ),
                observed_headers=quota_headers,
            )
        )

    return EvedexQualificationReport(
        schema_version=1,
        generated_at=now.isoformat(),
        exchange_base_url=exchange_base_url,
        symbol_map=symbol_map,
        authenticated=bool(jwt),
        checks=tuple(checks),
    )


async def qualify_evedex(
    *,
    exchange_base_url: str,
    symbol_map: dict[str, str],
    jwt: str | None = None,
    getter: Getter | None = None,
    now: datetime | None = None,
    timeout_s: float = 15.0,
) -> EvedexQualificationReport:
    """Run GET-only qualification; this function contains no mutating HTTP method."""
    captured_at = (now or datetime.now(UTC)).astimezone(UTC)
    if getter is not None:
        return await _qualify(
            getter,
            exchange_base_url=exchange_base_url.rstrip("/"),
            symbol_map=symbol_map,
            jwt=jwt,
            now=captured_at,
        )
    if aiohttp is None:  # pragma: no cover
        raise RuntimeError("aiohttp is required for EVEDEX qualification")
    timeout = aiohttp.ClientTimeout(total=timeout_s)
    async with aiohttp.ClientSession(timeout=timeout) as session:

        async def http_get(path: str, headers: Mapping[str, str]) -> HttpObservation:
            started = time.perf_counter()
            async with session.get(f"{exchange_base_url.rstrip('/')}{path}", headers=headers) as response:
                payload = await response.json(content_type=None)
                return HttpObservation(
                    status=response.status,
                    latency_ms=(time.perf_counter() - started) * 1000,
                    headers={str(key): str(value) for key, value in response.headers.items()},
                    payload=payload,
                )

        return await _qualify(
            http_get,
            exchange_base_url=exchange_base_url.rstrip("/"),
            symbol_map=symbol_map,
            jwt=jwt,
            now=captured_at,
        )


def _write_report(path: Path, report: EvedexQualificationReport, *, overwrite: bool) -> None:
    resolved = path.resolve()
    if resolved.exists() and not overwrite:
        raise FileExistsError(f"refusing to overwrite qualification report: {resolved}")
    resolved.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(report.to_dict(), sort_keys=True, indent=2, allow_nan=False) + "\n"
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{resolved.name}.", suffix=".tmp", dir=resolved.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, resolved)
    finally:
        if temporary.exists():
            temporary.unlink()


def _read_secret_file(path: Path | None) -> str | None:
    if path is None:
        return None
    value = path.resolve().read_text(encoding="utf-8").strip()
    if not value:
        raise ValueError("JWT file is empty")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run read-only EVEDEX DEV venue qualification")
    parser.add_argument("--exchange-base-url", default="https://trading-api.evedex.tech")
    parser.add_argument("--jwt-file", type=Path, help="read JWT from a file; never pass it on argv")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--overwrite", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    from .config import _default_evedex_dev_symbol_map

    report = asyncio.run(
        qualify_evedex(
            exchange_base_url=args.exchange_base_url,
            symbol_map=_default_evedex_dev_symbol_map(),
            jwt=_read_secret_file(args.jwt_file),
        )
    )
    _write_report(args.output, report, overwrite=args.overwrite)
    print(f"EVEDEX qualification: {report.status.value}; live_orders_allowed=false")
    return 0 if report.status is CheckStatus.PASS else 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
