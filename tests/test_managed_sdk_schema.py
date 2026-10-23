"""Offline compatibility checks against the lock-pinned EVEDEX signing SDK."""

import hashlib
import json
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from kairos_execution.crypto import EIP712_SCHEMAS, build_domain
from kairos_execution.local_custody import CoincurveTypedDataVerifier, _validate_contract
from kairos_execution.managed_signer import (
    PRODUCTION_SIGNING_PROFILE,
    CustodyBindingV1,
    ManagedSigningRequestV1,
    _typed_message,
    production_signed_message,
    production_signing_types,
    reviewed_schema_sha256,
)
from kairos_execution.production_readiness import ProductionContextV1
from kairos_execution.signing_authorization import signing_effect_id

pytest.importorskip("eth_account")
from eth_account import Account

pytest.importorskip("coincurve")

CHAIN_ID = 16182
NOW = datetime(2026, 10, 23, tzinfo=UTC)
FIXTURE_KEY = (1).to_bytes(32, "big")
INSTRUMENTS = ("BTCUSD", "ETHUSD", "SOLUSD", "BNBUSD", "XRPUSD")
SIDECAR_ROOT = Path(__file__).parents[1] / "kairos_execution" / "evedex_sidecar"
PINNED_SDK_AVAILABLE = (
    shutil.which("node") is not None
    and (SIDECAR_ROOT / "node_modules" / "@evedex" / "exchange-crypto" / "package.json").is_file()
)
SDK_TYPES = {
    "New limit order": "createLimitOrder",
    "New market order": "createMarketOrder",
    "New stop-limit order": "createStopLimitOrder",
    "Position close order": "createPositionCloseOrder",
    "New take-profit/stop-loss": "createTpSl",
}


def _binding() -> CustodyBindingV1:
    context = ProductionContextV1(
        remote_account_id="sdk-schema-fixture-account",
        adaptive_system_id="sdk-schema-fixture-system",
        frozen_policy_sha256="a" * 64,
        source_set_sha256="b" * 64,
    )
    return CustodyBindingV1(
        context=context,
        custody_reference="local:sdk-schema-fixture",
        wallet_address=Account.from_key(FIXTURE_KEY).address,
        chain_id=CHAIN_ID,
        schema_sha256=reviewed_schema_sha256(CHAIN_ID),
        approved_instruments=INSTRUMENTS,
        custody_receipt_sha256="c" * 64,
    )


def _request(order: str) -> ManagedSigningRequestV1:
    binding = _binding()
    return ManagedSigningRequestV1(
        request_id="sdk-schema-fixture-request",
        context=binding.context,
        manual_request_sha256="d" * 64,
        custody_receipt_sha256=binding.custody_receipt_sha256,
        operation="New take-profit/stop-loss",
        message_json=json.dumps(
            {
                "instrument": "BTCUSD",
                "type": "stop-loss",
                "side": "BUY",
                "quantity": 0,
                "price": 10_012_345_678,
                "order": order,
            },
            separators=(",", ":"),
        ),
        expires_at=NOW + timedelta(seconds=20),
    )


@pytest.mark.skipif(not PINNED_SDK_AVAILABLE, reason="installed pinned Node SDK is required for parity")
def test_production_type_profile_matches_all_five_lock_pinned_sdk_operations():
    script = r"""
const sdk = require('@evedex/exchange-crypto');
const names = {
  'New limit order': 'createLimitOrder',
  'New market order': 'createMarketOrder',
  'New stop-limit order': 'createStopLimitOrder',
  'Position close order': 'createPositionCloseOrder',
  'New take-profit/stop-loss': 'createTpSl',
};
const result = {};
for (const [operation, schemaName] of Object.entries(names)) {
  result[operation] = sdk.utils.EIP712Schemas[schemaName][operation];
}
process.stdout.write(JSON.stringify(result));
"""
    result = subprocess.run(
        ["node", "-e", script],
        cwd=SIDECAR_ROOT,
        capture_output=True,
        text=True,
        check=True,
        timeout=20,
    )
    sdk_types = json.loads(result.stdout)
    assert set(sdk_types) == set(SDK_TYPES)
    for operation in SDK_TYPES:
        assert production_signing_types(operation)[operation] == sdk_types[operation]

    # The legacy public schemas remain untouched and still include the parent
    # TP/SL field; only the new managed-production signing profile omits it.
    assert EIP712_SCHEMAS["New take-profit/stop-loss"]["New take-profit/stop-loss"][-1] == {
        "name": "order",
        "type": "string",
    }
    assert [
        field["name"]
        for field in production_signing_types("New take-profit/stop-loss")["New take-profit/stop-loss"]
    ] == ["instrument", "type", "side", "quantity", "price"]


@pytest.mark.skipif(not PINNED_SDK_AVAILABLE, reason="installed pinned Node SDK is required for parity")
def test_sdk_python_and_coincurve_agree_on_tpsl_signature_but_parent_stays_request_bound():
    parent_id = "00384:ABCDEF0123456789ABCDEF0123"
    sdk_script = r"""
const { Wallet } = require('ethers');
const sdk = require('@evedex/exchange-crypto');
const wallet = new Wallet('0x' + '00'.repeat(31) + '01');
const signer = {
  getChainId: async () => 16182,
  signTypedData: wallet.signTypedData.bind(wallet),
  serializeSignature: (signature) => signature,
};
(async () => {
  const result = await sdk.signTpSl(signer, {
    instrument: 'BTCUSD', type: 'stop-loss', side: 'BUY',
    quantity: '0', price: '100.12345678', order: '00384:ABCDEF0123456789ABCDEF0123',
  });
  process.stdout.write(JSON.stringify(result));
})().catch((error) => { process.stderr.write(String(error)); process.exit(1); });
"""
    sdk_run = subprocess.run(
        ["node", "-e", sdk_script],
        cwd=SIDECAR_ROOT,
        capture_output=True,
        text=True,
        check=True,
        timeout=20,
    )
    sdk_signed = json.loads(sdk_run.stdout)

    binding = _binding()
    request = _request(parent_id)
    types, full_message = _typed_message(request, binding)
    signed_message = production_signed_message(request.operation, full_message)
    python_signature = Account.sign_typed_data(
        FIXTURE_KEY,
        domain_data=build_domain(CHAIN_ID),
        message_types=types,
        message_data=signed_message,
    ).signature.hex()
    if not python_signature.startswith("0x"):
        python_signature = "0x" + python_signature
    assert python_signature.casefold() == sdk_signed["signature"].casefold()
    assert sdk_signed["order"] == parent_id
    assert full_message["order"] == parent_id
    assert CoincurveTypedDataVerifier().verify(
        wallet_address=binding.wallet_address,
        domain=build_domain(CHAIN_ID),
        types=types,
        message=full_message,
        signature=python_signature,
    )
    # Production dispatch passes only the signed EIP-712 fields. The verifier
    # accepts that exact projection while the managed signing request above
    # still requires and binds the parent-order metadata.
    assert CoincurveTypedDataVerifier().verify(
        wallet_address=binding.wallet_address,
        domain=build_domain(CHAIN_ID),
        types=types,
        message=signed_message,
        signature=python_signature,
    )
    altered_signed_message = {**signed_message, "price": 10012345679}
    assert not CoincurveTypedDataVerifier().verify(
        wallet_address=binding.wallet_address,
        domain=build_domain(CHAIN_ID),
        types=types,
        message=altered_signed_message,
        signature=python_signature,
    )

    # The parent is unsigned venue metadata, but remains mandatory and bound by
    # the full signing request and decision/effect digest.
    changed_request = _request("00384:0123456789ABCDEF0123456789")
    changed_types, changed_full_message = _typed_message(changed_request, binding)
    assert changed_types == types
    assert production_signed_message(changed_request.operation, changed_full_message) == signed_message
    changed_signature = Account.sign_typed_data(
        FIXTURE_KEY,
        domain_data=build_domain(CHAIN_ID),
        message_types=changed_types,
        message_data=production_signed_message(changed_request.operation, changed_full_message),
    ).signature.hex()
    assert changed_signature.casefold() == python_signature[2:].casefold()
    original_effect_id = signing_effect_id(request=request, message=full_message, decision_id="e" * 64)
    changed_effect_id = signing_effect_id(
        request=changed_request,
        message=changed_full_message,
        decision_id="e" * 64,
    )
    assert original_effect_id != changed_effect_id

    def request_digest(candidate, candidate_message):
        encoded = json.dumps(
            {
                **candidate.model_dump(mode="json"),
                "message_json": json.dumps(candidate_message, sort_keys=True),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return hashlib.sha256(encoded).hexdigest()

    assert request_digest(request, full_message) != request_digest(changed_request, changed_full_message)
    assert _validate_contract(
        custody_reference=binding.custody_reference,
        expected_custody_reference=binding.custody_reference,
        wallet_address=binding.wallet_address,
        chain_id=binding.chain_id,
        approved_instruments=binding.approved_instruments,
        domain=build_domain(CHAIN_ID),
        types=types,
        message=full_message,
    ) == (request.operation, PRODUCTION_SIGNING_PROFILE)


def test_new_profile_schema_digest_is_versioned_and_not_legacy_digest():
    legacy = hashlib.sha256(
        json.dumps(
            {
                "domain": build_domain(CHAIN_ID),
                "types": {key: EIP712_SCHEMAS[key] for key in sorted(SDK_TYPES)},
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    assert reviewed_schema_sha256(CHAIN_ID) != legacy
