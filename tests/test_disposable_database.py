"""Hermetic tests: no PostgreSQL connection is made by this module."""

from __future__ import annotations

from unittest.mock import AsyncMock, Mock, call

import pytest
from kairos_persistence import Database, PersistenceSettings

from tests.disposable_database import (
    DisposableDatabaseError,
    connect_disposable_database,
    disposable_settings,
    require_disposable_database_url,
)

NAME = "kairos_execution_test_a012345678bc"
DSN = f"postgresql://test:local-test-only@localhost:5432/{NAME}"


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "[::1]", "timescaledb"])
@pytest.mark.parametrize("scheme", ["postgresql", "postgres"])
def test_accepts_explicit_disposable_database_on_local_test_hosts(host: str, scheme: str) -> None:
    dsn = f"{scheme}://test:test@{host}:5432/{NAME}"
    assert require_disposable_database_url(dsn, NAME) == NAME


def test_encoded_credentials_do_not_change_the_literal_database_target() -> None:
    dsn = f"postgresql://test%40user:password%3F%23%2F%40@localhost:5432/{NAME}"
    assert require_disposable_database_url(dsn, NAME) == NAME


@pytest.mark.parametrize(
    "name",
    [
        "kairos",
        "paper",
        "kairos_paper",
        "kairos-paper-gate",
        "postgres",
        "template1",
        "kairos_execution_test",
        "kairos_execution_test_a012345678b",
        "kairos_execution_test_a012345678bcc",
        "kairos_execution_test_A012345678BC",
        "kairos_execution_test_a012345678bc_backup",
        "kairos_execution_test_a012345678bc\n",
    ],
)
def test_rejects_working_or_nonisolated_names_even_when_explicitly_confirmed(name: str) -> None:
    with pytest.raises(DisposableDatabaseError):
        require_disposable_database_url(f"postgresql://test:test@localhost:5432/{name}", name)


@pytest.mark.parametrize("confirmation", [None, "", "true", "kairos_execution_test_111111111111"])
def test_requires_exact_disposable_confirmation(confirmation: str | None) -> None:
    with pytest.raises(DisposableDatabaseError):
        require_disposable_database_url(DSN, confirmation)


@pytest.mark.parametrize(
    "dsn",
    [
        "postgresql://test:test@localhost:5432/kairos",
        f"postgresql://test:test@prod.example:5432/{NAME}",
        f"postgresql://test:test@localhost.example:5432/{NAME}",
        f"postgresql://test:test@localhost.:5432/{NAME}",
        f"postgresql://test:test@127.1:5432/{NAME}",
        f"postgresql://test:test@%6cocalhost:5432/{NAME}",
        f"postgresql://test:test@localhost:5432,%2Ftmp/{NAME}",
        f"postgresql://localhost@prod.example:5432/{NAME}",
        f"postgresql://test:password@prod.example@localhost:5432/{NAME}",
        DSN + "?dbname=kairos",
        DSN + "?database=kairos",
        DSN + "?host=prod.example",
        DSN + "?options=-csearch_path=public",
        DSN + "?sslmode=disable",
        DSN + "?",
        DSN + "#kairos",
        DSN + "#",
        DSN + "/",
        DSN + "/../kairos",
        DSN.replace(NAME, NAME.replace("kairos", "%6bairos")),
        DSN.replace(NAME, "%256bairos_execution_test_a012345678bc"),
        DSN.replace(NAME, NAME + "%2F..%2Fkairos"),
        DSN.replace(NAME, NAME + "%00"),
        DSN.replace(NAME, NAME + "%"),
        DSN.replace(NAME, NAME + "%GG"),
        DSN.replace(NAME, "../" + NAME),
        DSN.replace(NAME, "/" + NAME),
        " " + DSN,
        DSN + "\n",
        DSN.replace("local-test-only", "local\ttest"),
        DSN.replace("localhost", "local\nhost"),
        DSN.replace("localhost", "local\\host"),
        DSN.replace("local-test-only", "пароль"),
        DSN.replace("local-test-only", "password%GG"),
        DSN.replace("local-test-only", "password%"),
        DSN.replace("5432", "0"),
        DSN.replace("5432", "65536"),
        DSN.replace("5432", "not-a-port"),
        DSN.replace(":5432", ""),
        DSN.replace("postgresql", "sqlite"),
        f"postgresql://[::1:5432/{NAME}",
        f"postgresql://[localhost]:5432/{NAME}",
        f"postgresql:///{NAME}",
        f"dbname={NAME} host=localhost",
        "",
    ],
)
def test_rejects_ambiguous_override_encoded_and_malformed_urls(dsn: str) -> None:
    with pytest.raises(DisposableDatabaseError):
        require_disposable_database_url(dsn, NAME)


def test_rejection_does_not_disclose_the_dsn_or_credentials() -> None:
    dsn = f"postgresql://private-user:private-password@prod.example:5432/{NAME}"
    with pytest.raises(DisposableDatabaseError) as caught:
        require_disposable_database_url(dsn, NAME)
    assert "private-user" not in str(caught.value)
    assert "private-password" not in str(caught.value)
    assert dsn not in str(caught.value)


def test_unconfigured_integration_remains_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KAIROS_PERSISTENCE_DATABASE_URL", raising=False)
    with pytest.raises(pytest.skip.Exception):
        disposable_settings()


def test_configured_unsafe_integration_fails_instead_of_skipping(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KAIROS_PERSISTENCE_DATABASE_URL", "postgresql://localhost:5432/kairos")
    monkeypatch.setenv("KAIROS_EXECUTION_TEST_DATABASE", NAME)
    with pytest.raises(DisposableDatabaseError):
        disposable_settings()


def _database_mock(dsn: str, server_database: str) -> Mock:
    database = Mock(spec=Database)
    database.settings = PersistenceSettings(database_url=dsn)
    database.connect = AsyncMock()
    database.migrate = AsyncMock()
    database.close = AsyncMock()
    database.pool = Mock()
    database.pool.fetchval = AsyncMock(return_value=server_database)
    return database


async def test_bad_final_settings_fail_before_connect_or_migrate(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KAIROS_EXECUTION_TEST_DATABASE", NAME)
    database = _database_mock("postgresql://localhost:5432/kairos", NAME)
    with pytest.raises(DisposableDatabaseError):
        await connect_disposable_database(database)
    database.connect.assert_not_awaited()
    database.pool.fetchval.assert_not_awaited()
    database.migrate.assert_not_awaited()


async def test_server_database_mismatch_closes_before_migrations(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KAIROS_EXECUTION_TEST_DATABASE", NAME)
    database = _database_mock(DSN, "kairos")
    with pytest.raises(DisposableDatabaseError):
        await connect_disposable_database(database)
    database.migrate.assert_not_awaited()
    database.close.assert_awaited_once()
    assert database.mock_calls == [
        call.connect(),
        call.pool.fetchval("SELECT current_database()"),
        call.close(),
    ]


async def test_only_verified_disposable_database_is_migrated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KAIROS_EXECUTION_TEST_DATABASE", NAME)
    database = _database_mock(DSN, NAME)
    await connect_disposable_database(database)
    assert database.mock_calls == [
        call.connect(),
        call.pool.fetchval("SELECT current_database()"),
        call.migrate(),
    ]


async def test_migration_failure_also_closes_the_disposable_pool(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KAIROS_EXECUTION_TEST_DATABASE", NAME)
    database = _database_mock(DSN, NAME)
    database.migrate.side_effect = RuntimeError("test migration failed")
    with pytest.raises(RuntimeError, match="test migration failed"):
        await connect_disposable_database(database)
    database.close.assert_awaited_once()
