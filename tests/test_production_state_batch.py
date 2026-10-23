"""Focused tests for the uncached batched production writer privilege check."""

from __future__ import annotations

from collections.abc import Callable

import pytest

import kairos_execution.production_state as production_state
from kairos_execution.production_state import (
    _TABLES,
    _WRITER_TABLES,
    SCHEMA,
    AsyncPostgresProductionSigningStateSource,
    ProductionStateError,
    _writer_select_tables,
)


def _identity() -> dict[str, str]:
    return {
        "owner_role": "state_owner",
        "runtime_role": "state_runtime",
        "operator_writer_role": "state_operator_writer",
        "risk_writer_role": "state_risk_writer",
        "exposure_writer_role": "state_exposure_writer",
    }


def _valid_matrix(state_schema_version: int) -> list[dict[str, object]]:
    identity = _identity()
    rows: list[dict[str, object]] = []
    for role_field, allowed in _WRITER_TABLES.items():
        for table in _TABLES:
            rows.append(
                {
                    "role_field": role_field,
                    "role_name": identity[role_field],
                    "table_name": table,
                    "has_insert": table in allowed,
                    "has_select": table in _writer_select_tables(role_field, state_schema_version),
                    "has_mutating": False,
                    "can_create_schema": False,
                }
            )
    return rows


class _MatrixConnection:
    def __init__(self, rows: list[dict[str, object]]) -> None:
        self.rows = rows
        self.fetch_calls: list[tuple[str, tuple[object, ...]]] = []
        self.fetchval_calls: list[tuple[str, tuple[object, ...]]] = []

    async def fetch(self, query: str, *args: object) -> list[dict[str, object]]:
        self.fetch_calls.append((query, args))
        return self.rows

    async def fetchval(self, query: str, *args: object) -> object:
        self.fetchval_calls.append((query, args))
        raise AssertionError("writer privilege matrix must not issue per-cell queries")


async def _run_check(
    monkeypatch: pytest.MonkeyPatch,
    rows: list[dict[str, object]],
    *,
    state_schema_version: int = 3,
) -> tuple[_MatrixConnection, list[tuple[str, tuple[str, ...]]]]:
    isolated: list[tuple[str, tuple[str, ...]]] = []

    async def record_isolation(connection: object, role_name: str, protected: tuple[str, ...]) -> None:
        assert isinstance(connection, _MatrixConnection)
        isolated.append((role_name, protected))

    monkeypatch.setattr(production_state, "_check_role_isolated", record_isolation)
    connection = _MatrixConnection(rows)
    checker = object.__new__(AsyncPostgresProductionSigningStateSource)
    checker.state_schema_version = state_schema_version
    await checker._inspect_writer_contract(connection, _identity())
    return connection, isolated


@pytest.mark.asyncio
async def test_writer_contract_batches_exact_role_table_matrix_without_caching(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection, isolated = await _run_check(monkeypatch, _valid_matrix(3))

    assert len(connection.fetch_calls) == 1
    assert connection.fetchval_calls == []
    query, args = connection.fetch_calls[0]
    assert "unnest($1::text[], $2::text[])" in query
    assert "CROSS JOIN unnest($4::text[])" in query
    assert "UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER" in query
    assert args == (
        list(_WRITER_TABLES),
        [_identity()[role_field] for role_field in _WRITER_TABLES],
        SCHEMA,
        list(_TABLES),
    )
    protected = tuple(_identity()[key] for key in ("owner_role", "runtime_role", *_WRITER_TABLES))
    identity = _identity()
    assert isolated == [(identity[role_field], protected) for role_field in _WRITER_TABLES]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda rows: _row(rows, "operator_writer_role", "owner_arms").update(has_insert=False),
            "writer privilege is absent",
        ),
        (
            lambda rows: _row(rows, "risk_writer_role", "owner_arms").update(has_insert=True),
            "crosses its least-privilege boundary",
        ),
        (
            lambda rows: _row(rows, "risk_writer_role", "risk_decisions").update(has_mutating=True),
            "excessive table privileges",
        ),
        (
            lambda rows: _row(rows, "risk_writer_role", "identity").update(has_select=False),
            "SELECT privilege mismatch",
        ),
        (
            lambda rows: _row(rows, "exposure_writer_role", "identity").update(can_create_schema=True),
            "can modify its schema",
        ),
        (
            lambda rows: _row(rows, "risk_writer_role", "risk_decisions").update(has_select=None),
            "SELECT privilege mismatch",
        ),
    ],
)
async def test_writer_contract_rejects_each_privilege_drift(
    monkeypatch: pytest.MonkeyPatch,
    mutate: Callable[[list[dict[str, object]]], object],
    message: str,
) -> None:
    rows = _valid_matrix(3)
    mutate(rows)

    with pytest.raises(ProductionStateError, match=message):
        await _run_check(monkeypatch, rows)


def _row(rows: list[dict[str, object]], role_field: str, table: str) -> dict[str, object]:
    return next(row for row in rows if row["role_field"] == role_field and row["table_name"] == table)


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["missing", "duplicate", "foreign"])
async def test_writer_contract_rejects_incomplete_or_rebound_matrix(
    monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    rows = _valid_matrix(3)
    target = _row(rows, "risk_writer_role", "risk_decisions")
    if mutation == "missing":
        rows.remove(target)
    elif mutation == "duplicate":
        rows.append(dict(target))
    else:
        target["role_name"] = "foreign_writer"

    with pytest.raises(ProductionStateError, match="privilege matrix is incomplete"):
        await _run_check(monkeypatch, rows)


@pytest.mark.asyncio
async def test_writer_contract_preserves_v2_and_v3_risk_select_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    v2, _ = await _run_check(monkeypatch, _valid_matrix(2), state_schema_version=2)
    v3, _ = await _run_check(monkeypatch, _valid_matrix(3), state_schema_version=3)

    for connection, expected in ((v2, False), (v3, True)):
        _, args = connection.fetch_calls[0]
        assert args[3] == list(_TABLES)
        matrix_row = _row(connection.rows, "risk_writer_role", "risk_decisions")
        assert matrix_row["has_select"] is expected
