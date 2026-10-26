"""Synthetic native-read composition checks, without SDK processes or authority."""

import base64
import hashlib
import json
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from kairos_execution.paper_engine import PaperExecutionSafetyError
from kairos_execution.production_cancellation import ProductionCancellationVerifier
from kairos_execution.production_lifecycle_adapter import ManagedProductionLifecycleAdapter
from kairos_execution.production_lifecycle_store import PostgresLifecycleBindingStore
from kairos_execution.production_reads import ProductionEvedexReads
from kairos_execution.production_runtime import ProductionExecutionRuntime
from kairos_execution.production_transport import ProductionEvedexSdkClient, ProductionEvedexTransport
from tests.test_production_lifecycle import _bare_engine, _config
from tests.test_production_lifecycle_binding import _decision
from tests.test_production_transport import BINDING, CONTEXT


def assembly(*, different_client=False):
    config = _config()

    def client():
        return ProductionEvedexSdkClient(
            node_executable=Path(__file__).resolve().parent / "fixtures" / "node.exe",
            api_key_file=Path(__file__).resolve().parent / "fixtures" / "not-read.key",
            expected_account_id=CONTEXT.remote_account_id,
        )

    sdk = client()
    reader = ProductionEvedexReads(sdk, symbol_map=config.symbol_map)
    transport = ProductionEvedexTransport(
        context=CONTEXT,
        custody_binding=BINDING,
        client=client() if different_client else sdk,
    )
    runtime = object.__new__(ProductionExecutionRuntime)
    runtime.context = CONTEXT
    runtime.binding = BINDING
    runtime.dispatcher = SimpleNamespace(sender=transport.send_signed_post)
    runtime.claims = object()
    runtime.state_source = object()
    bindings = object.__new__(PostgresLifecycleBindingStore)
    bindings.context = CONTEXT
    trades, effects = object(), object()
    cancellations = object.__new__(ProductionCancellationVerifier)
    cancellations.context = CONTEXT
    cancellations.claims = runtime.claims
    cancellations.trades = trades
    cancellations.effects = effects
    cancellations.bindings = bindings
    cancellations.state_source = runtime.state_source
    cancellations.custody_binding = runtime.binding
    return dict(
        runtime=runtime,
        reads=reader,
        bindings=bindings,
        trades=trades,
        effects=effects,
        cancellations=cancellations,
    )


def test_real_prod_reader_binds_same_client_without_legacy_parent_authority():
    kwargs = assembly()
    adapter = ManagedProductionLifecycleAdapter(**kwargs)
    assert adapter.reads is kwargs["reads"]
    assert adapter.protective_stop_lookup_authoritative is False
    assert adapter.reads._preflight_complete is False


def test_different_read_write_client_is_refused_before_any_source_call():
    with pytest.raises(ValueError, match="exact transport client/account"):
        ManagedProductionLifecycleAdapter(**assembly(different_client=True))


def captured_instrument(engine, decision, *, age_ms=0, body_change=None):
    now = engine.clock()
    received = now - timedelta(milliseconds=age_ms)
    instrument = {
        "name": decision.venue_symbol,
        "trading": "all",
        "visibility": "all",
        "marketState": "OPEN",
        "updatedAt": "2020-01-01T00:00:00+00:00",
        "lotSize": "1",
        "multiplier": "1",
        "priceIncrement": "0.01",
        "quantityIncrement": "0.1",
        "minPrice": "1",
        "maxPrice": "1000000",
        "minQuantity": "0.1",
        "maxQuantity": "100",
        "minVolume": "5",
    }
    if body_change:
        instrument.update(body_change)
    raw = json.dumps([instrument], separators=(",", ":")).encode()
    capture = {
        "source": "instruments",
        "path": "/api/market/instrument",
        "query_json": '{"fields":"metrics"}',
        "status": 200,
        "requested_at": (received - timedelta(milliseconds=10)).isoformat(),
        "received_at": received.isoformat(),
        "body_bytes": len(raw),
        "body_sha256": hashlib.sha256(raw).hexdigest(),
        "body_base64": base64.b64encode(raw).decode(),
    }
    return {"instruments": [instrument], "native_read_captures": {"instruments": capture}}


def test_old_rule_revision_uses_original_fresh_http_clock_not_retimed_updated_at():
    engine = _bare_engine()
    decision = _decision()
    venue = captured_instrument(engine, decision)
    engine._assert_production_instrument(decision, venue)
    assert venue["instruments"][0]["updatedAt"].startswith("2020-")
    assert "evedex_prod_instrument_received_at_ms" in dict(engine.operational_telemetry)


@pytest.mark.parametrize("mutation", ["stale", "future", "projection", "digest", "missing", "status"])
def test_bad_native_instrument_capture_is_not_replaced_with_revision_freshness(mutation):
    engine = _bare_engine()
    decision = _decision()
    venue = captured_instrument(engine, decision, age_ms=5001 if mutation == "stale" else 0)
    capture = venue["native_read_captures"]["instruments"]
    if mutation == "future":
        capture["received_at"] = (engine.clock() + timedelta(seconds=1)).isoformat()
    elif mutation == "projection":
        venue["instruments"][0] = {**venue["instruments"][0], "minVolume": "100"}
    elif mutation == "digest":
        capture["body_sha256"] = "f" * 64
    elif mutation == "missing":
        del venue["native_read_captures"]["instruments"]
    elif mutation == "status":
        capture["status"] = 503
    with pytest.raises(PaperExecutionSafetyError, match="exact fresh original HTTP capture"):
        engine._assert_production_instrument(decision, venue)
