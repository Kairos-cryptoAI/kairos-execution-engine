import json
from datetime import UTC, datetime

import pytest

from kairos_execution.qualification import (
    CheckStatus,
    EvedexQualificationReport,
    HttpObservation,
    QualificationCheck,
    _read_secret_file,
    _write_report,
    qualify_evedex,
)

NOW = datetime(2026, 8, 18, 0, tzinfo=UTC)
SYMBOL_MAP = {"BTCUSDT": "BTCUSD", "ETHUSDT": "ETHUSD"}


def _responses(*, trading: str = "all", quota_headers: bool = True):
    instruments = [
        {
            "name": venue,
            "trading": trading,
            "visibility": "all",
            "lastPrice": "100",
            "markPrice": "100",
            "minQuantity": "0.01",
            "maxQuantity": "100",
            "quantityIncrement": "0.01",
            "priceIncrement": "0.1",
            "updatedAt": NOW.isoformat(),
        }
        for venue in SYMBOL_MAP.values()
    ]
    payloads = {
        "/api/market": {"state": "active", "updatedAt": NOW.isoformat()},
        "/api/market/instrument": instruments,
        "/api/user/me": {"exchangeId": "account-1", "marginCall": False},
        "/api/market/available-balance": {
            "funding": {"balance": "1000"},
            "availableBalance": "1000",
            "negativeUnPnL": 0,
            "position": [],
            "openOrder": [],
        },
        "/api/position": [],
        "/api/order/opened": [],
        "/api/tpsl": {"list": []},
    }
    for venue in SYMBOL_MAP.values():
        payloads[f"/api/market/{venue}/deep?marketLevel=1"] = {
            "t": int(NOW.timestamp() * 1000),
            "bids": [{"price": 99.9, "quantity": 2}],
            "asks": [{"price": 100.1, "quantity": 3}],
        }
        payloads[f"/api/market/{venue}/recent-trades"] = [
            {
                "instrument": venue,
                "fillQuantity": 1,
                "fillPrice": 100,
                "createdAt": NOW.isoformat(),
            }
        ]
    headers = {"X-RateLimit-Remaining": "29"} if quota_headers else {}
    return payloads, headers


def _getter(payloads, response_headers, calls):
    async def get(path, headers):
        calls.append((path, dict(headers)))
        return HttpObservation(200, 1.5, response_headers, payloads[path])

    return get


@pytest.mark.asyncio
async def test_public_qualification_is_blocked_without_contacting_authenticated_endpoints():
    payloads, headers = _responses()
    calls = []

    report = await qualify_evedex(
        exchange_base_url="https://example.invalid",
        symbol_map=SYMBOL_MAP,
        getter=_getter(payloads, headers, calls),
        now=NOW,
    )

    assert report.status is CheckStatus.BLOCKED
    assert report.live_orders_allowed is False
    assert not any(path.startswith("/api/user") or path == "/api/position" for path, _ in calls)
    assert all(not request_headers for _, request_headers in calls)
    assert {check.status for check in report.checks if check.name.startswith("depth:")} == {CheckStatus.PASS}


@pytest.mark.asyncio
async def test_authenticated_qualification_reconciles_without_exposing_jwt():
    payloads, headers = _responses()
    calls = []

    report = await qualify_evedex(
        exchange_base_url="https://example.invalid",
        symbol_map=SYMBOL_MAP,
        jwt="super-secret-jwt",
        getter=_getter(payloads, headers, calls),
        now=NOW,
    )

    assert report.status is CheckStatus.PASS
    assert report.authenticated is True
    assert report.live_orders_allowed is False
    serialized = json.dumps(report.to_dict())
    assert "super-secret-jwt" not in serialized
    authenticated = [headers for path, headers in calls if path.startswith("/api/user")]
    assert authenticated == [{"Authorization": "Bearer super-secret-jwt"}]


@pytest.mark.asyncio
async def test_qualification_blocks_when_authenticated_api_omits_quota_headers():
    payloads, headers = _responses(quota_headers=False)
    calls = []

    report = await qualify_evedex(
        exchange_base_url="https://example.invalid",
        symbol_map=SYMBOL_MAP,
        jwt="jwt",
        getter=_getter(payloads, headers, calls),
        now=NOW,
    )

    assert report.status is CheckStatus.BLOCKED
    quota = next(check for check in report.checks if check.name == "observed_account_quota")
    assert quota.status is CheckStatus.BLOCKED


@pytest.mark.asyncio
async def test_qualification_fails_closed_for_non_tradable_instrument():
    payloads, headers = _responses(trading="onlyClose")
    calls = []

    report = await qualify_evedex(
        exchange_base_url="https://example.invalid",
        symbol_map=SYMBOL_MAP,
        getter=_getter(payloads, headers, calls),
        now=NOW,
    )

    assert report.status is CheckStatus.FAIL
    contract = next(check for check in report.checks if check.name == "instrument_contract")
    assert "not fully tradable" in contract.detail


def test_report_writer_is_atomic_and_refuses_overwrite(tmp_path):
    evidence = EvedexQualificationReport(
        schema_version=1,
        generated_at=NOW.isoformat(),
        exchange_base_url="https://example.invalid",
        symbol_map=SYMBOL_MAP,
        authenticated=False,
        checks=(QualificationCheck("public", CheckStatus.PASS, "ok"),),
    )
    destination = tmp_path / "qualification.json"

    _write_report(destination, evidence, overwrite=False)

    assert json.loads(destination.read_text(encoding="utf-8"))["live_orders_allowed"] is False
    with pytest.raises(FileExistsError):
        _write_report(destination, evidence, overwrite=False)


def test_secret_file_must_not_be_empty(tmp_path):
    secret = tmp_path / "jwt"
    secret.write_text("\n", encoding="utf-8")
    with pytest.raises(ValueError, match="empty"):
        _read_secret_file(secret)
