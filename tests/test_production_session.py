"""The automatically armed REST session builds the exact production graph without I/O."""

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from uuid import UUID

import pytest

from kairos_execution.managed_signer import CustodyBindingV1, reviewed_schema_sha256
from kairos_execution.production_assembly import ProductionAssemblyError
from kairos_execution.production_host import build_production_host
from kairos_execution.production_owner import OWNER_KEY_FILE, generate_owner_key
from kairos_execution.production_readiness import _verify_owner_signed_arm, canonical_digest
from kairos_execution.production_rest_sources import SOURCE_ID
from kairos_execution.production_session import (
    AutoArmSigner,
    ProductionSessionError,
    RolePools,
    build_rest_session,
)
from kairos_execution.production_transport import ProductionEvedexSdkClient, ProductionEvedexTransport
from tests.production_evidence_fixtures import NOW
from tests.test_managed_signer import Backend, Verifier
from tests.test_production_assembly_construction import NoIOPool
from tests.test_production_dispatch import SyntheticSignatureVerifier
from tests.test_production_lifecycle import _config
from tests.test_production_path import Clock
from tests.test_production_risk import _inputs
from tests.test_technical_canary_readiness import _setup_canary


def _session(tmp_path, *, entry_order_type="LIMIT_GTC"):
    canary, references, _resolver, context, *_ = _setup_canary()
    base = _config()
    custody = CustodyBindingV1.model_validate(
        base.custody_binding.model_copy(
            update={"context": context, "chain_id": 42161, "schema_sha256": reviewed_schema_sha256(42161)}
        ).model_dump(mode="python")
    )
    settings = type(base).model_validate(
        base.model_copy(
            update={
                "context": context,
                "custody_binding": custody,
                "strategy_revision": base.strategy_revision,
                "expected_health": base.expected_health.model_copy(update={"chain_id": 42161}),
                "entry_order_type": entry_order_type,
            }
        ).model_dump(mode="python")
    )
    owner_key = generate_owner_key(
        tmp_path / "owner",
        owner_identity="owner",
        context=context,
        valid_from=NOW - timedelta(days=1),
        valid_until=NOW + timedelta(days=30),
    )
    pools = RolePools(
        runtime=NoIOPool(),
        operator=NoIOPool(),
        risk=NoIOPool(),
        exposure=NoIOPool(),
        reconciliation=NoIOPool(),
        accounting=NoIOPool(),
        roles={
            name: f"session_{name}"
            for name in ("runtime", "operator", "risk", "exposure", "reconciler", "accounting")
        },
        database="kairos_production_evidence_session_synthetic",
        database_uuid=UUID("f3fbe25f-6af9-4c51-9fe1-4cd84737b8a2"),
        policy_namespace="synthetic:session",
    )
    client = ProductionEvedexSdkClient(
        node_executable=Path(__file__).resolve().parent / "fixtures" / "node.exe",
        api_key_file=Path(__file__).resolve().parent / "fixtures" / "must-not-be-read.key",
        expected_account_id=context.remote_account_id,
    )
    transport = ProductionEvedexTransport(context=context, custody_binding=custody, client=client)
    limits = _inputs()[6].evaluator.limits
    session = build_rest_session(
        pools=pools,
        settings=settings,
        references=references,
        canary_verifier=canary,
        owner_key=owner_key,
        custody_backend=Backend(),
        custody_signature_verifier=Verifier(),
        wire_signature_verifier=SyntheticSignatureVerifier(),
        transport=transport,
        limits=limits,
        exit_fee_rate=Decimal("0.0005"),
        adverse_slippage_rate=Decimal("0.001"),
        clock=Clock(NOW),
    )
    return session, owner_key, pools


def test_rest_session_assembles_the_exact_graph_and_registers_the_rest_sources(tmp_path):
    session, _owner_key, pools = _session(tmp_path)

    async def never(*args):
        raise AssertionError("no provider call during construction")

    host = build_production_host(
        session.resources,
        entry_provider=never,
        terminal_evidence_provider=never,
        terminal_source_id=SOURCE_ID,
    )
    assert set(host.assembly.reconciler.source_verifiers) == {SOURCE_ID}
    assert session.resources.risk_evaluator._require_instrument_rules is True
    assert set(session.resources.risk_evaluator._account_verifiers) == {SOURCE_ID}
    assert all(not pool.calls for pool in (pools.runtime, pools.risk, pools.exposure))
    assert session.preconditions.dollar_cap == Decimal("10")


def test_automatic_arm_carries_exactly_the_attested_limits_and_verifies(tmp_path):
    session, owner_key, _ = _session(tmp_path)
    signer = AutoArmSigner(tmp_path / "owner" / OWNER_KEY_FILE, owner_key)
    arm = signer.sign(session.preconditions, now=NOW)
    request, _ = _verify_owner_signed_arm(
        arm,
        session.preconditions,
        owner_key=owner_key,
        expected_owner_key_sha256=canonical_digest(owner_key),
        expected_owner_identity="owner",
        now=NOW + timedelta(seconds=1),
        maximum_lifetime=timedelta(minutes=10),
    )
    assert (request.dollar_cap, request.daily_stop_loss_usd) == (
        session.preconditions.dollar_cap,
        session.preconditions.daily_stop_loss_usd,
    )
    assert request.expires_at - request.created_at <= timedelta(minutes=9)
    with pytest.raises(ValueError, match="ten-minute"):
        AutoArmSigner(tmp_path / "owner" / OWNER_KEY_FILE, owner_key, lifetime=timedelta(hours=1))


def test_session_refuses_entry_contracts_other_than_bounded_gtc(tmp_path):
    with pytest.raises((ProductionSessionError, ProductionAssemblyError, ValueError)):
        _session(tmp_path, entry_order_type="MARKET_IOC")


@pytest.mark.asyncio
@pytest.mark.parametrize("invalid", [b"\xff", b"x" * 5000], ids=["invalid-utf8", "oversized"])
async def test_bad_exit_file_keeps_session_supervised_until_a_later_valid_request(
    tmp_path, monkeypatch, invalid
):
    import asyncio
    from types import SimpleNamespace

    from kairos_execution import production_session as module
    from kairos_execution.production_session_cli import exit_request_reader

    path = tmp_path / "trade.exit-request"
    path.write_bytes(invalid)
    events = []

    class Reads:
        async def preflight(self):
            events.append("preflight")

        async def close(self):
            events.append("reads closed")

    class Operator:
        async def arm(self, arm):
            events.append("armed")

        async def disarm(self):
            events.append("disarmed")

    class Host:
        def __init__(self):
            self.status = SimpleNamespace(
                owned_trade_id="owned-trade",
                terminal_accounting_accepted=False,
                supervisor_failure=None,
            )
            self.assembly = SimpleNamespace(
                engine=SimpleNamespace(
                    account_snapshot=lambda: None, request_early_exit=self.request_early_exit
                )
            )

        def request_early_exit(self, trade_id, reason):
            events.append((trade_id, reason))
            self.status.terminal_accounting_accepted = True

        async def start(self, **kwargs):
            events.append("started")

        async def submit_one(self):
            return object()

        async def run(self, *, stop):
            # The invalid request is polled before these maintenance turns.
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            assert not stop.is_set()
            events.append("maintenance survived invalid input")
            path.write_text("regime changed\n", encoding="utf-8")
            await stop.wait()
            events.append("host closed")

    host = Host()
    monkeypatch.setattr(module, "build_production_host", lambda *args, **kwargs: host)
    session = SimpleNamespace(
        clock=lambda: NOW,
        preconditions=object(),
        resources=SimpleNamespace(lifecycle_settings=SimpleNamespace(context=_config().context)),
        reads=Reads(),
        trades=object(),
        terminal=object(),
        operator=Operator(),
        references=(),
    )
    result = await module.run_one_trade(
        session,
        SimpleNamespace(review=object()),
        SimpleNamespace(sign=lambda *args, **kwargs: object()),
        lambda *args: None,
        poll_s=0,
        early_exit=exit_request_reader(path),
    )
    assert result.outcome == "CLOSED_AND_ACCOUNTED"
    assert "maintenance survived invalid input" in events
    assert ("owned-trade", "regime changed") in events
    assert events[-2:] == ["host closed", "reads closed"]
