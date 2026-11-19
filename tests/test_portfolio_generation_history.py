from unittest.mock import AsyncMock, Mock

import pytest

from kairos_execution.portfolio_evedex import Evedex, EvedexError


def closed(version):
    return {"instrument": "SOLUSD", "version": version, "closeAt": "2026-11-19T18:32:28Z"}


@pytest.mark.asyncio
async def test_find_first_closed_generation_beyond_unfiltered_history_page():
    api = Evedex(Mock())
    api._request = AsyncMock(
        side_effect=[
            {"count": 1, "list": [closed(v) for v in range(101, 1, -1)]},
            {"count": 1, "list": [closed(1), closed(0)]},
        ]
    )
    assert await api.position_version_closed("SOLUSD", 0)
    assert api._request.await_args.kwargs["params"]["offset"] == 100


@pytest.mark.asyncio
async def test_other_closes_do_not_prove_the_requested_generation_is_closed():
    api = Evedex(Mock())
    api._request = AsyncMock(return_value={"count": 1, "list": [closed(1)]})
    assert not await api.position_version_closed("SOLUSD", 0)
    api._request.return_value = {"count": 1, "list": [closed(0), closed(0)]}
    with pytest.raises(EvedexError, match="ambiguous"):
        await api.position_version_closed("SOLUSD", 0)


@pytest.mark.asyncio
async def test_order_details_distinguish_version_zero_and_a_trailing_cursor():
    api = Evedex(Mock())
    rows = [{"id": name, "instrument": "SOLUSD", "user": "owner"} for name in ("original", "replacement")]
    api._request = AsyncMock(return_value={"count": 2, "next": "end", "list": rows})
    details = [{**row, "positionVersions": [i]} for i, row in enumerate(rows)]
    api.order = AsyncMock(side_effect=details)
    assert await api.position_version_orders("SOLUSD", 0) == [details[0]]
    assert api._request.await_count == 1


@pytest.mark.asyncio
async def test_repeated_order_on_a_later_page_fails_reconciliation():
    api = Evedex(Mock())
    row = {"id": "same", "instrument": "SOLUSD"}
    api._request = AsyncMock(return_value={"count": 2, "next": "again", "list": [row]})
    with pytest.raises(EvedexError, match="repeated"):
        await api.position_version_orders("SOLUSD", 1)
