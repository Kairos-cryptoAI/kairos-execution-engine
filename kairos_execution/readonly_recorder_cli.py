"""Explicit, GET-only DEV observation entry point; never migrates or arms trading."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib
import json
import re
from collections.abc import Sequence
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit
from uuid import UUID

import aiohttp
from kairos_persistence import Database, PersistenceSettings
from kairos_persistence.canary_session import CanaryScope, CanarySessionRepository
from kairos_persistence.database_target import connect_verified_database
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .qualification import HttpObservation
from .readonly_recorder import measure_public_venue_sample, record_readonly_window

CONFIRMATION = "RECORD_DEV_READONLY_ONLY"
_ACCOUNT_PATHS = frozenset(
    {"/api/user/me", "/api/market/available-balance", "/api/position", "/api/order/opened", "/api/tpsl"}
)
_MODULES = (
    "kairos_execution.readonly_recorder_cli",
    "kairos_execution.readonly_recorder",
    "kairos_execution.readonly_health",
    "kairos_execution.qualification",
    "kairos_execution.adapters.evedex",
    "kairos_quant.venue_comparison",
    "kairos_persistence.canary_session",
)


class RecorderConfig(BaseModel):
    """Non-secret, independent operator binding. Paths are not credential values."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, allow_inf_nan=False)
    version: Literal["dev-readonly-recorder.v1"]
    scope: CanaryScope
    database_name: str
    database_host: Literal["127.0.0.1", "localhost", "::1", "timescaledb"]
    database_port: Annotated[int, Field(ge=1, le=65535)]
    database_instance_id: UUID
    database_url_file: Path
    jwt_file: Path
    sample_period_ms: Annotated[int, Field(ge=5_000, le=60_000)] = 15_000
    notional_usd: Annotated[float, Field(gt=0, le=1_000)] = 1_000.0
    duration_s: Annotated[float, Field(ge=86_400, le=172_800)] = 86_400.0
    operation_timeout_s: Annotated[float, Field(gt=0, le=10)] = 4.0

    @model_validator(mode="after")
    def boundary(self) -> RecorderConfig:
        # A separately provisioned PAPER gate, never the legacy, SIM or R7 epoch DB.
        if re.fullmatch(r"kairos_paper_gate_[a-z0-9]{12,32}", self.database_name) is None:
            raise ValueError("a separate explicitly named PAPER gate database is required")
        if any(not path.is_absolute() for path in (self.database_url_file, self.jwt_file)):
            raise ValueError("recorder secret file paths must be absolute")
        if self.database_url_file == self.jwt_file:
            raise ValueError("recorder credentials require separate files")
        if self.operation_timeout_s * 2 + 2 >= self.sample_period_ms / 1_000:
            raise ValueError("cadence must leave room for both bounded source polls and persistence")
        return self

    def expected_config_sha256(self) -> str:
        data = self.model_dump(mode="json")
        data["scope"].pop("config_sha256")
        data["scope"].pop("recorder_code_sha256")
        return _digest(data)


def _digest(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return hashlib.sha256(raw).hexdigest()


def recorder_code_sha256() -> str:
    files = {}
    for name in _MODULES:
        module = importlib.import_module(name)
        path = Path(module.__file__ or "")
        if not path.is_file():
            raise ValueError("installed recorder source identity is unavailable")
        files[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return _digest(files)


def load_config(path: Path) -> RecorderConfig:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024:
        raise ValueError("a bounded regular recorder config file is required")
    return RecorderConfig.model_validate_json(path.read_bytes())


def _secret(path: Path) -> str:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16 * 1024:
        raise ValueError("a bounded regular protected credential file is required")
    value = path.read_text(encoding="utf-8").strip()
    if not value or any(char in value for char in "\r\n\x00"):
        raise ValueError("protected credential file is empty or malformed")
    return value


async def record(config: RecorderConfig) -> tuple[str, str]:
    # Check immutable code/config bindings BEFORE opening credentials or connecting.
    if (
        config.scope.config_sha256 != config.expected_config_sha256()
        or config.scope.recorder_code_sha256 != recorder_code_sha256()
    ):
        raise ValueError("independent recorder scope/code/config binding differs")
    database_url = _secret(config.database_url_file)
    target = urlsplit(database_url)
    if target.hostname != config.database_host or target.port != config.database_port:
        raise ValueError("database host/port differs from the independent recorder target")
    database = Database(
        PersistenceSettings(
            _env_file=None,
            database_url=database_url,
            pool_min_size=1,
            pool_max_size=3,
            command_timeout_s=config.operation_timeout_s,
        )
    )
    jwt = _secret(config.jwt_file)
    try:
        async with asyncio.timeout(config.operation_timeout_s):
            await connect_verified_database(database, config.database_name, local_only=True)
            await database.verify_schema()
            instance = await database.pool.fetchval("SELECT instance_id FROM paper_canary_database_identity")
            if instance != config.database_instance_id:
                raise ValueError("recorder database instance identity differs")
        # Session-level lock prevents a second recorder, without a long SQL transaction.
        async with database.pool.acquire() as lease:
            locked = await lease.fetchval(
                "SELECT pg_try_advisory_lock(hashtextextended($1,0))", "kairos-paper-gate:readonly-recorder"
            )
            if locked is not True:
                raise ValueError("a read-only recorder already owns this isolated database")
            try:
                async with aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=config.operation_timeout_s),
                    connector=aiohttp.TCPConnector(limit=10),
                    trust_env=False,
                ) as session:

                    async def get(path: str, headers: dict) -> HttpObservation:
                        if path not in _ACCOUNT_PATHS or headers:
                            raise ValueError("recorder permits only fixed account GET paths")
                        async with session.get(
                            config.scope.exchange_url + path,
                            headers={"Authorization": "Bearer " + jwt},
                            allow_redirects=False,
                        ) as response:
                            if response.status != 200:
                                raise ValueError("account GET was not accepted")
                            raw = bytearray()
                            async for chunk in response.content.iter_chunked(64 * 1024):
                                raw.extend(chunk)
                                if len(raw) > 1024 * 1024:
                                    raise ValueError("account response exceeded the recorder bound")
                            return HttpObservation(response.status, 0.0, {}, json.loads(raw))

                    from .readonly_health import PostgresReadonlyHealthReader

                    health = PostgresReadonlyHealthReader(
                        database.pool, getter=get, operation_timeout_s=config.operation_timeout_s
                    )
                    symbols = {
                        s: s.removesuffix("USDT") + "USD:DEV"
                        for s in ("BTCUSDT", "ETHUSDT", "SOLUSDT", "BNBUSDT", "XRPUSDT")
                    }

                    async def measure():
                        return await measure_public_venue_sample(
                            symbol_map=symbols,
                            notional_usd=config.notional_usd,
                            timeout_s=config.operation_timeout_s,
                        )

                    return await record_readonly_window(
                        CanarySessionRepository(database.pool),
                        config.scope,
                        measure=measure,
                        read_health=health,
                        sample_period_ms=config.sample_period_ms,
                        duration_s=config.duration_s,
                        operation_timeout_s=config.operation_timeout_s,
                    )
            finally:
                await lease.execute(
                    "SELECT pg_advisory_unlock(hashtextextended($1,0))", "kairos-paper-gate:readonly-recorder"
                )
    finally:
        try:
            async with asyncio.timeout(5):
                await database.close()
        except TimeoutError:
            # asyncpg terminate releases all dedicated session locks even after cancellation.
            database.pool.terminate()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("inspect-config", "record"))
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--confirm")
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
        if args.command == "inspect-config":
            print(
                json.dumps(
                    {
                        "config_sha256": config.expected_config_sha256(),
                        "recorder_code_sha256": recorder_code_sha256(),
                        "trading_authority": "NONE",
                    },
                    sort_keys=True,
                )
            )
        else:
            if args.confirm != CONFIRMATION:
                raise ValueError("explicit read-only observation confirmation is required")
            run_id, receipt_id = asyncio.run(record(config))
            print(json.dumps({"run_id": run_id, "receipt_id": receipt_id, "trading_authority": "NONE"}))
    except KeyboardInterrupt:
        print("DEV_READONLY_RECORDER_CANCELLED_NO_RETRY")
        return 130
    except Exception:
        # Driver/schema/account exceptions may contain DSNs, balances or tokens.
        print("DEV_READONLY_RECORDER_REFUSED_NO_RETRY")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
