import json
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

import kairos_execution.qualification as qualification
from kairos_execution.config import _default_evedex_dev_symbol_map
from kairos_execution.qualification import (
    _EVEDEX_DEV_QUALIFICATION_ORIGIN,
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
        exchange_base_url=_EVEDEX_DEV_QUALIFICATION_ORIGIN,
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
        exchange_base_url=_EVEDEX_DEV_QUALIFICATION_ORIGIN,
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
        exchange_base_url=_EVEDEX_DEV_QUALIFICATION_ORIGIN,
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
        exchange_base_url=_EVEDEX_DEV_QUALIFICATION_ORIGIN,
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


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "unsafe_origin",
    [
        "http://trading-api.evedex.tech",
        "https://trading-api.evedex.tech.evil.example",
        "https://trading-api.evedex.tech:443",
        "https://trading-api.evedex.tech/redirect",
        "https://attacker@example.invalid",
    ],
)
async def test_qualification_rejects_noncanonical_origin_before_any_authenticated_get(
    unsafe_origin: str,
) -> None:
    calls: list[tuple[str, dict[str, str]]] = []

    async def getter(path, headers):
        calls.append((path, dict(headers)))
        raise AssertionError("untrusted origin must not be contacted")

    with pytest.raises(ValueError, match="exact EVEDEX DEV HTTPS origin"):
        await qualify_evedex(
            exchange_base_url=unsafe_origin,
            symbol_map=SYMBOL_MAP,
            jwt="test-jwt",
            getter=getter,
            now=NOW,
        )

    assert calls == []


def test_cli_defaults_to_the_exact_dev_profile(monkeypatch, tmp_path):
    captured = {}

    async def fake_qualify(**kwargs):
        captured.update(kwargs)
        return EvedexQualificationReport(
            schema_version=1,
            generated_at=NOW.isoformat(),
            exchange_base_url=kwargs["exchange_base_url"],
            symbol_map=kwargs["symbol_map"],
            authenticated=False,
            checks=(QualificationCheck("credentials", CheckStatus.BLOCKED, "not supplied"),),
        )

    monkeypatch.setattr(qualification, "qualify_evedex", fake_qualify)
    output = tmp_path / "qualification.json"

    assert qualification.main(["--output", str(output)]) == 2
    assert captured["exchange_base_url"] == "https://trading-api.evedex.tech"
    assert captured["symbol_map"] == _default_evedex_dev_symbol_map()
    assert set(captured["symbol_map"].values()) == {
        "BTCUSD:DEV",
        "ETHUSD:DEV",
        "SOLUSD:DEV",
        "BNBUSD:DEV",
        "XRPUSD:DEV",
    }


def test_cli_rejects_any_origin_override(tmp_path) -> None:
    with pytest.raises(SystemExit) as raised:
        qualification.main(
            [
                "--exchange-base-url",
                "https://example.invalid",
                "--output",
                str(tmp_path / "qualification.json"),
            ]
        )

    assert raised.value.code == 2


@pytest.mark.asyncio
async def test_network_qualification_never_follows_redirects(monkeypatch) -> None:
    calls: list[tuple[str, dict[str, str], bool]] = []

    class Response:
        status = 302
        headers: dict[str, str] = {}

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def json(self, **_kwargs):
            return {}

    class Session:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        def get(self, url, *, headers, allow_redirects):
            calls.append((url, dict(headers), allow_redirects))
            return Response()

    monkeypatch.setattr(
        qualification,
        "aiohttp",
        SimpleNamespace(ClientTimeout=lambda **_kwargs: object(), ClientSession=Session),
    )

    report = await qualify_evedex(
        exchange_base_url=_EVEDEX_DEV_QUALIFICATION_ORIGIN,
        symbol_map=SYMBOL_MAP,
        now=NOW,
    )

    assert report.status is CheckStatus.FAIL
    assert calls
    assert all(allow_redirects is False for _, _, allow_redirects in calls)
