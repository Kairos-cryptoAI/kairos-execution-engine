"""Contract tests for read-only bounded pagination, never exchange authority."""

from __future__ import annotations

import asyncio
import copy
from unittest.mock import AsyncMock

import pytest

from kairos_execution.production_history_window import collect_history_window
from kairos_execution.production_reads import ProductionEvedexReads, ProductionReadUnavailable

AFTER = "2026-11-08T14:00:00.000Z"
BEFORE = "2026-11-09T14:00:00.000Z"
STAMP = "2026-11-09T12:00:00.000Z"


def funding():
    return {"type": "deposit", "coin": "usdt", "quantity": "5.0", "createdAt": STAMP}


def fill(identity):
    return {"id": identity, "createdAt": STAMP}


def make_reader(funding_pages, fill_pages, *, account_ids=("acct", "acct")):
    # Only the exact reader is used. The fetch seams below emulate responses
    # after native endpoint parsing; those parsers are separately tested.
    reads = object.__new__(ProductionEvedexReads)
    reads._preflight_complete = True
    reads.expected_account_id = "acct"
    reads.last_captures = {}
    identities = iter(account_ids)
    calls = []

    async def identity(source):
        assert source == "account_identity"
        reads.last_captures[source] = {"body_base64": "PRIVATE_IDENTITY", "body_bytes": 16}
        return {"exchangeId": next(identities)}

    async def page(source, sequence, **kwargs):
        offset = kwargs["offset"]
        calls.append((source, offset))
        result = sequence[offset // kwargs["limit"]]
        reads.last_captures[source] = {"path": source, "body_base64": "PRIVATE_HISTORY", "body_bytes": 15}
        return copy.deepcopy(result)

    reads._read = AsyncMock(side_effect=identity)

    async def funding_call(**kw):
        return await page("funding_transfers", funding_pages, **kw)

    async def fill_call(**kw):
        return await page("fill_history", fill_pages, **kw)

    reads.fetch_funding_transfers = AsyncMock(side_effect=funding_call)
    reads.fetch_fill_history = AsyncMock(side_effect=fill_call)
    return reads, calls


@pytest.mark.asyncio
async def test_reads_both_complete_reported_page_sets_without_claiming_history_completeness():
    reads, calls = make_reader(
        [{"count": 3, "list": [funding(), funding()]}, {"count": 3, "list": [funding()]}],
        [{"count": 2, "list": [fill("a"), fill("b")]}],
    )
    capture = await collect_history_window(reads, after=AFTER, before=BEFORE, page_size=2)
    assert calls == [("funding_transfers", 0), ("funding_transfers", 2), ("fill_history", 0)]
    assert sum(len(page["list"]) for page in capture.funding_pages) == 3
    assert capture.history_complete is None and capture.fees_final is None
    assert capture.account_revision_authoritative is False and capture.trading_authority is False
    assert "PRIVATE_HISTORY" not in repr(capture) and "PRIVATE_IDENTITY" not in repr(capture)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad",
    [
        {"count": 4, "list": [funding()]},  # changed count
        {"count": 3, "list": []},  # empty nonterminal
        {"count": 3, "list": [funding()], "next": "opaque"},
    ],
)
async def test_refuses_unstable_or_unusable_pagination(bad):
    reads, _ = make_reader([{"count": 3, "list": [funding(), funding()]}, bad], [])
    with pytest.raises(ProductionReadUnavailable):
        await collect_history_window(reads, after=AFTER, before=BEFORE, page_size=2)


@pytest.mark.asyncio
async def test_refuses_duplicate_fill_ids_across_pages():
    reads, _ = make_reader(
        [{"count": 0, "list": []}],
        [
            {"count": 3, "list": [fill("a"), fill("b")]},
            {"count": 3, "list": [fill("a")]},
        ],
    )
    with pytest.raises(ProductionReadUnavailable, match="repeated across pages"):
        await collect_history_window(reads, after=AFTER, before=BEFORE, page_size=2)


@pytest.mark.asyncio
async def test_refuses_row_outside_window_and_account_change():
    outside = {**funding(), "createdAt": "2026-11-07T12:00:00Z"}
    reads, _ = make_reader([{"count": 1, "list": [outside]}], [])
    with pytest.raises(ProductionReadUnavailable, match="outside"):
        await collect_history_window(reads, after=AFTER, before=BEFORE)
    reads, _ = make_reader(
        [{"count": 0, "list": []}], [{"count": 0, "list": []}], account_ids=("acct", "other")
    )
    with pytest.raises(ProductionReadUnavailable, match="identity"):
        await collect_history_window(reads, after=AFTER, before=BEFORE)


@pytest.mark.asyncio
async def test_refuses_exhausted_page_budget_and_invalid_configuration():
    reads, _ = make_reader([{"count": 3, "list": [funding(), funding()]}], [])
    with pytest.raises(ProductionReadUnavailable, match="page budget"):
        await collect_history_window(reads, after=AFTER, before=BEFORE, page_size=2, max_pages_per_source=1)
    with pytest.raises(ValueError):
        await collect_history_window(reads, after=AFTER, before=BEFORE, page_size=True)


@pytest.mark.asyncio
async def test_timeout_discards_partial_observation():
    reads, _ = make_reader([], [])

    async def stall(**_kwargs):
        await asyncio.sleep(1)

    reads.fetch_funding_transfers = AsyncMock(side_effect=stall)
    with pytest.raises(ProductionReadUnavailable, match="timed out"):
        await collect_history_window(reads, after=AFTER, before=BEFORE, timeout_seconds=0.01)
    reads.fetch_fill_history.assert_not_awaited()


@pytest.mark.asyncio
async def test_cumulative_byte_budget_discards_capture(monkeypatch):
    monkeypatch.setattr("kairos_execution.production_history_window.MAX_WINDOW_BODY_BYTES", 30)
    reads, _ = make_reader([{"count": 0, "list": []}], [])
    with pytest.raises(ProductionReadUnavailable, match="cumulative byte limit"):
        await collect_history_window(reads, after=AFTER, before=BEFORE)
    reads.fetch_fill_history.assert_not_awaited()


@pytest.mark.asyncio
async def test_real_reader_parses_wire_captures_before_collecting_pages():
    from tests.test_production_reads import AFTER as NATIVE_AFTER
    from tests.test_production_reads import BEFORE as NATIVE_BEFORE
    from tests.test_production_reads import fixture

    reads, calls = fixture()
    await reads.preflight()
    observation = await collect_history_window(reads, after=NATIVE_AFTER, before=NATIVE_BEFORE)
    assert len(observation.funding_pages[0]["list"]) == 1
    assert len(observation.fill_pages[0]["list"]) == 1
    assert observation.funding_captures[0]["path"] == "/api/user/funding-transfer"
    assert observation.fill_captures[0]["path"] == "/api/fill"
    assert [call["source"] for call in calls[-4:]] == [
        "account_identity",
        "funding_transfers",
        "fill_history",
        "account_identity",
    ]
