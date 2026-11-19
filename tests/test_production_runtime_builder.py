"""The production runtime builder wires exact objects without acquiring authority."""

from dataclasses import replace

import pytest

from kairos_execution.production_assembly import ProductionAssemblyStatus, build_production_assembly
from kairos_execution.production_host import ProductionHost, build_production_host
from kairos_execution.production_runtime_builder import build_clocked_production_runtime
from kairos_execution.production_state import ProductionStateError
from kairos_execution.utc_clock import precise_utc_now
from tests.test_production_assembly_construction import concrete_resources
from tests.test_signing_authorization import fixture as signing_fixture


@pytest.fixture
def setup():
    resources, pools, provider, backend, client, transport = concrete_resources()
    original = resources.runtime
    state = original.state_source
    authorization = original.authorization
    arguments = {
        "pool": state.pool,
        "expected_database": state.expected_database,
        "database_uuid": original.database_uuid,
        "policy_namespace": state.policy_namespace,
        "runtime_role": state.runtime_role,
        "context": original.context,
        "custody_binding": original.binding,
        "preconditions": authorization._preconditions,
        "owner_key": authorization._owner_key,
        "expected_owner_key_sha256": authorization._owner_key_sha256,
        "expected_owner_identity": authorization._owner,
        "maximum_arm_lifetime": authorization._arm_lifetime,
        "custody_backend": backend,
        "custody_signature_verifier": original.signer._verifier,
        "wire_signature_verifier": original.dispatcher.signature_verifier,
        "transport": transport,
    }
    return resources, pools, provider, backend, client, transport, arguments


def test_builder_constructs_host_resources_with_one_precise_clock_and_no_io(setup):
    resources, pools, provider, backend, client, transport, arguments = setup
    runtime = build_clocked_production_runtime(**arguments)
    assert runtime._clock is runtime.authorization._clock is runtime.state_source._clock_probe
    assert runtime._clock is runtime.dispatcher.clock is precise_utc_now
    assert runtime.claims is runtime.dispatcher.claims is runtime.signer._claims
    assert runtime.authorization is runtime.dispatcher.authorization is runtime.signer._authorization
    assert runtime.dispatcher.sender.__self__ is transport

    # Other independent resources still have to be supplied explicitly. Merely
    # constructing the graph does not start the service or qualify sources.
    assembly = build_production_assembly(replace(resources, runtime=runtime, clock=precise_utc_now))
    assert assembly.status == ProductionAssemblyStatus()
    assert assembly.engine.clock is assembly.reconciler._clock is precise_utc_now

    async def no_entry():
        raise AssertionError("construction must not request a trading entry")

    async def no_terminal(_trade_id, _source_id):
        raise AssertionError("construction must not request terminal evidence")

    host = build_production_host(
        replace(resources, runtime=runtime, clock=precise_utc_now),
        entry_provider=no_entry,
        terminal_evidence_provider=no_terminal,
        terminal_source_id=provider.source_id,
    )
    assert type(host) is ProductionHost
    assert host.assembly.status == ProductionAssemblyStatus()
    assert not host.status.started and not host.status.readiness
    assert host.assembly.engine.clock is precise_utc_now
    assert all(pool.calls == [] for pool in pools)
    assert provider.calls == backend.calls == []
    assert client._process is None and not client._preflight_complete
    assert not transport._preflight_complete


def test_builder_wires_required_unavailable_fence_to_signer_and_dispatcher(setup):
    *_, arguments = setup
    runtime = build_clocked_production_runtime(**arguments, require_session_entry_fence=True)
    assert runtime.signer._require_session_entry_fence is True
    assert runtime.dispatcher._require_session_entry_fence is True
    assert runtime.state_source._require_session_entry_fence is True


@pytest.mark.asyncio
async def test_required_fence_denies_real_reservation_before_database_io(setup):
    _, pools, _, _, _, _, arguments = setup
    runtime = build_clocked_production_runtime(**arguments, require_session_entry_fence=True)
    _, request, binding, evidence, _ = signing_fixture()
    with pytest.raises(ProductionStateError, match="atomic session entry fence is unavailable"):
        await runtime.state_source.reserve_entry_async(request=request, binding=binding, evidence=evidence)
    assert all(pool.calls == [] for pool in pools)


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["Position close order", "New take-profit/stop-loss"])
async def test_required_fence_keeps_exit_reservation_path_available(setup, operation):
    _, pools, _, _, _, _, arguments = setup
    runtime = build_clocked_production_runtime(**arguments, require_session_entry_fence=True)
    _, request, binding, evidence, _ = signing_fixture(operation)
    assert await runtime.state_source.reserve_entry_async(request=request, binding=binding, evidence=evidence) is None
    assert all(pool.calls == [] for pool in pools)


@pytest.mark.parametrize("value", ["false", 0, None])
def test_builder_rejects_ambiguous_fence_configuration(setup, value):
    *_, arguments = setup
    with pytest.raises(TypeError, match="must be boolean"):
        build_clocked_production_runtime(**arguments, require_session_entry_fence=value)


@pytest.mark.parametrize("field", ["preconditions", "owner_key"])
def test_builder_refuses_foreign_account_scope_before_any_io(setup, field):
    _, pools, provider, backend, _, _, arguments = setup
    original = arguments[field]
    foreign = original.context.model_copy(update={"remote_account_id": "different-account"})
    arguments[field] = original.model_copy(update={"context": foreign})
    with pytest.raises(ValueError, match="scope differs"):
        build_clocked_production_runtime(**arguments)
    assert all(pool.calls == [] for pool in pools)
    assert provider.calls == backend.calls == []


def test_builder_refuses_wrong_owner_key_digest(setup):
    *_, arguments = setup
    arguments["expected_owner_key_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="scope differs"):
        build_clocked_production_runtime(**arguments)


def test_builder_refuses_owner_identity_mismatch(setup):
    *_, arguments = setup
    arguments["expected_owner_identity"] = "other-owner"
    with pytest.raises(ValueError, match="scope differs"):
        build_clocked_production_runtime(**arguments)


def test_builder_refuses_transport_substitution_and_invalid_clock(setup):
    *_, arguments = setup
    with pytest.raises(TypeError, match="exact provisioned EVEDEX transport"):
        build_clocked_production_runtime(**(arguments | {"transport": object()}))
    with pytest.raises(ValueError, match="callable UTC clock"):
        build_clocked_production_runtime(**(arguments | {"clock": None}))


def test_builder_refuses_transport_custody_mismatch(setup):
    *_, arguments = setup
    foreign_binding = arguments["custody_binding"].model_copy(update={"custody_reference": "other-custody"})
    arguments["custody_binding"] = foreign_binding
    with pytest.raises(ValueError, match="scope differs"):
        build_clocked_production_runtime(**arguments)
