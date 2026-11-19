"""Offline diagnostic geometry and pinned SDK parity; no wallet or venue calls."""

import hashlib
import json
import shutil
import subprocess
from decimal import Decimal, localcontext
from pathlib import Path

import pytest

from kairos_execution.market_ioc_contract import MarketIocCashInputV1, build_market_ioc_diagnostic
from kairos_execution.production_dispatch import production_wire_body
from kairos_execution.production_readiness import canonical_digest


def cash_input(**changes):
    return MarketIocCashInputV1(
        **{
            "client_order_id": "00471:" + "a" * 26,
            "instrument": "BTCUSD",
            "side": "BUY",
            "cash_quantity_e8": 123_456_789,
            "diagnostic_cash_ceiling_e8": 200_000_000,
            "context_sha256": "a" * 64,
            "source_evidence_sha256": "b" * 64,
            **changes,
        }
    )


@pytest.mark.parametrize("units", [1, 100_000_000, 123_456_789, 2**96 - 1])
def test_explicit_uint96_cash_is_exact_in_signing_and_rest_without_rounding(units):
    original = cash_input(cash_quantity_e8=units, diagnostic_cash_ceiling_e8=units)
    result = build_market_ioc_diagnostic(original)
    message, rest = json.loads(result.typed_message_json), json.loads(result.unsigned_rest_body_json)
    assert type(message["cashQuantity"]) is int and message["cashQuantity"] == units
    with localcontext() as context:
        context.prec = 60
        assert Decimal(rest["cashQuantity"]) * 100_000_000 == units
    assert result.cash_input_sha256 == canonical_digest(original)
    assert message["timeInForce"] == "IOC" and message["chainId"] == 42161
    assert set(message) == {"id", "instrument", "side", "timeInForce", "leverage", "cashQuantity", "chainId"}
    assert not {"quantity", "limitPrice", "slippage", "signature"} & set(rest)
    signature = "0x" + "11" * 65  # An inert fixture, never signed or sent.
    assert production_wire_body("New market order", message, signature) == {**rest, "signature": signature}


@pytest.mark.parametrize(
    "changes",
    [
        {"cash_quantity_e8": 0},
        {"cash_quantity_e8": -1},
        {"cash_quantity_e8": 2**96},
        {"cash_quantity_e8": True},
        {"cash_quantity_e8": 1.1},
        {"cash_quantity_e8": "1"},
        {"cash_quantity_e8": Decimal("1.000000001")},
        {"diagnostic_cash_ceiling_e8": 123_456_788},
        {"diagnostic_cash_ceiling_e8": 2**96},
        {"instrument": "BTCUSD:DEV"},
        {"instrument": "btcUSD"},
        {"client_order_id": "market-1"},
        {"side": "LONG"},
        {"chain_id": 161803},
        {"chain_id": "42161"},
        {"leverage": 2},
        {"leverage": True},
        {"time_in_force": "GTC"},
        {"time_in_force": "FOK"},
        {"limitPrice": 100},
        {"quantity": 0.001},
        {"slippage": 0.001},
    ],
)
def test_wrong_units_scope_types_and_unsupported_order_semantics_refuse(changes):
    with pytest.raises(ValueError):
        cash_input(**changes)


def test_diagnostic_stays_non_authority_and_builder_has_no_io(monkeypatch):
    original = cash_input()

    def forbidden(*_args, **_kwargs):
        raise AssertionError("pure diagnostic must not perform I/O, sign or dispatch")

    monkeypatch.setattr("builtins.open", forbidden)
    monkeypatch.setattr("socket.socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    result = build_market_ioc_diagnostic(original)
    assert result.status == "NON_AUTHORITY_NOT_LIVE"
    assert result.eligibility == "PRICE_AND_BASE_QUANTITY_ENVELOPE_UNQUALIFIED"
    assert result.signing_domain_qualification == "UNQUALIFIED"
    assert result.provenance == "PINNED_SDK_SCHEMA_NOT_CURRENT_VENUE_APPROVAL"
    assert result.authority is False and result.live_ready is False
    with pytest.raises(ValueError):
        result.authority = True
    with pytest.raises(TypeError):
        build_market_ioc_diagnostic(original.model_dump())


@pytest.mark.parametrize(
    "changes",
    [
        {"cash_quantity_e8": True},
        {"cash_quantity_e8": 2**96},
        {"cash_quantity_e8": 200_000_001},
        {"leverage": 2},
        {"chain_id": 161803},
        {"side": "LONG"},
    ],
)
def test_builder_revalidates_forged_frozen_model_before_creating_draft(changes):
    forged = cash_input().model_copy(update=changes)
    with pytest.raises(ValueError):
        build_market_ioc_diagnostic(forged)


def test_pinned_market_type_drift_cannot_keep_old_sdk_provenance(monkeypatch):
    from kairos_execution import market_ioc_contract

    original = market_ioc_contract.production_signing_types("New market order")
    original["New market order"][5]["type"] = "uint256"
    monkeypatch.setattr(market_ioc_contract, "production_signing_types", lambda _: original)
    with pytest.raises(ValueError, match="requires review"):
        build_market_ioc_diagnostic(cash_input())


def test_real_pinned_sdk_signing_and_cash_normalization_match_offline():
    node = shutil.which("node")
    root = Path(__file__).resolve().parents[1]
    package = root / "sidecar/node_modules/@evedex/exchange-crypto"
    if node is None or not package.exists():
        pytest.skip("offline pinned Node crypto package unavailable")
    assert json.loads((package / "package.json").read_text(encoding="utf-8"))["version"] == "1.1.0"
    units = [1, 100_000_000, 123_456_789, 2**96 - 1]
    drafts = [
        build_market_ioc_diagnostic(cash_input(cash_quantity_e8=u, diagnostic_cash_ceiling_e8=u))
        for u in units
    ]
    payload = [json.loads(row.unsigned_rest_body_json) for row in drafts]
    # The fake SDK wallet merely records typed data. It has no key/network/client.
    script = r"""
const {signMarketOrder} = require('./node_modules/@evedex/exchange-crypto/dist/cjs/orders.js');
(async () => {
  const outputs=[];
  for (const input of JSON.parse(process.argv[1])) {
    let signed;
    const wallet={getChainId:async()=>42161,
      signTypedData:async(domain,types,message)=>{signed={domain,types,message}; return 'not-a-signature';},
      serializeSignature:value=>value};
    const rest=await signMarketOrder(wallet,input);
    outputs.push({signed,rest});
  }
  process.stdout.write(JSON.stringify(outputs));
})().catch(error => {process.stderr.write(String(error)); process.exitCode=1;});
"""
    completed = subprocess.run(
        [node, "-e", script, json.dumps(payload)],
        text=True,
        capture_output=True,
        cwd=root / "sidecar",
        timeout=20,
        check=True,
    )
    observations = json.loads(completed.stdout)
    for draft, observed in zip(drafts, observations, strict=True):
        message = json.loads(draft.typed_message_json)
        signed = observed["signed"]["message"]
        # SDK uses an exact decimal integer string for EIP uint96; ours uses int.
        assert int(signed.pop("cashQuantity")) == message.pop("cashQuantity")
        assert signed == message
        assert (
            hashlib.sha256(
                json.dumps(observed["signed"]["types"], sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            == draft.pinned_market_types_sha256
        )
        # Big.js may use exponent notation for tiny REST values; value is identical.
        assert Decimal(observed["rest"]["cashQuantity"]) == Decimal(
            json.loads(draft.unsigned_rest_body_json)["cashQuantity"]
        )
