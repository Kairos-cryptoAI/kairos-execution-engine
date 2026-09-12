"""Fail-closed access to disposable databases for destructive integration tests.

Create a new local database named ``kairos_execution_test_<12 lowercase hex>``
and set KAIROS_EXECUTION_TEST_DATABASE to that exact name, as well as the
KAIROS_PERSISTENCE_DATABASE_URL DSN. Never opt a deployed PAPER database in.
The test database must be disposable: lifecycle fixtures delete whole tables.
"""

from __future__ import annotations

import os
import re
from urllib.parse import urlsplit

import pytest
from kairos_persistence import Database, PersistenceSettings

_DATABASE_NAME = re.compile(r"kairos_execution_test_[0-9a-f]{12}\Z")
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "timescaledb"})


class DisposableDatabaseError(ValueError):
    """An integration target is unsafe; messages deliberately omit the DSN."""


def require_disposable_database_url(database_url: str, expected_name: str | None) -> str:
    """Validate the complete URL before creating a pool or running migrations.

    Query parameters are forbidden, including dbname/host/options overrides.
    Database names must be literal (not percent-encoded) so the driver's target
    cannot differ from the name inspected here. Encoded credentials are allowed.
    """
    if expected_name is None or _DATABASE_NAME.fullmatch(expected_name) is None:
        raise DisposableDatabaseError(
            "Set KAIROS_EXECUTION_TEST_DATABASE to an isolated "
            "kairos_execution_test_<12 lowercase hex> database before integration tests"
        )
    if (
        not database_url.isascii()
        or any(ord(char) <= 32 or ord(char) == 127 for char in database_url)
        or any(char in database_url for char in "\\?#")
        or re.search(r"%(?![0-9a-fA-F]{2})", database_url)
    ):
        raise DisposableDatabaseError("Integration database URL contains forbidden or ambiguous syntax")
    try:
        parsed = urlsplit(database_url)
        port = parsed.port
        host = parsed.hostname
    except ValueError:
        raise DisposableDatabaseError("Integration database URL is malformed") from None
    if (
        parsed.scheme not in {"postgresql", "postgres"}
        or not parsed.netloc
        or host not in _LOCAL_HOSTS
        or parsed.netloc.count("@") > 1
        or port is None
        or not 1 <= port <= 65535
        or parsed.path != f"/{expected_name}"
    ):
        raise DisposableDatabaseError(
            "Integration database must use an explicit local test host, port, "
            "and the exact confirmed disposable database name"
        )
    return expected_name


def disposable_settings() -> PersistenceSettings:
    database_url = os.getenv("KAIROS_PERSISTENCE_DATABASE_URL")
    if not database_url:
        pytest.skip("KAIROS_PERSISTENCE_DATABASE_URL is required")
    require_disposable_database_url(database_url, os.getenv("KAIROS_EXECUTION_TEST_DATABASE"))
    return PersistenceSettings(database_url=database_url)


async def connect_disposable_database(database: Database) -> None:
    """Check the final settings, then server identity, before any DDL/DELETE.

    The server check also catches a proxy routing a correctly named DSN to a
    different database. On failure the pool is closed without modifying data.
    """
    expected = require_disposable_database_url(
        database.settings.database_url, os.getenv("KAIROS_EXECUTION_TEST_DATABASE")
    )
    await database.connect()
    try:
        if await database.pool.fetchval("SELECT current_database()") != expected:
            raise DisposableDatabaseError("Server database differs from the confirmed disposable database")
        await database.migrate()
    except BaseException:
        await database.close()
        raise
