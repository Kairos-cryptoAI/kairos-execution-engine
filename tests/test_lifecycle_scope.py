"""Regression tests for the private, immutable PAPER DEV lifecycle boundary."""

from types import SimpleNamespace

import pytest
from kairos_core.enums import EvedexProfile, TradingMode

from kairos_execution.lifecycle_scope import PaperDevCanaryPolicy
from kairos_execution.paper_engine import (
    PaperExecutionEngine,
    PaperExecutionSafetyError,
    _EvedexProtectedExecutionEngine,
)
from tests.paper_fixtures import approved_decision
from tests.test_canary_admission import engine_fixture


def test_paper_facade_uses_fixed_immutable_dev_lifecycle_scope(tmp_path):
    engine = engine_fixture(tmp_path)
    scope = engine._lifecycle_scope

    assert type(engine._lifecycle_policy) is PaperDevCanaryPolicy
    assert scope.trading_mode is TradingMode.PAPER
    assert scope.profile is EvedexProfile.DEV
    assert scope.environment == "paper-dev:EVEDEX:DEV:PAPER"
    assert scope.remote_environment == "evedex-dev"
    assert scope.remote_account_id == "remote-paper-account-01"
    assert scope.account_id == "kairos-paper-dev-01"
    assert scope.exchange == "evedex"
    assert scope.symbol_map["BTCUSDT"] == "BTCUSD:DEV"
    assert scope.mutation_namespace == "paper.v1"
    assert scope.event_namespace == "paper.v1"
    engine._validate_decision(approved_decision())

    with pytest.raises(TypeError):
        scope.symbol_map["BTCUSDT"] = "BTCUSD"  # type: ignore[index]


@pytest.mark.parametrize(
    "updates",
    [
        {"trading_mode": TradingMode.LIVE},
        {"evedex_profile": EvedexProfile.PROD},
        {"trading_mode": TradingMode.LIVE, "evedex_profile": EvedexProfile.PROD},
    ],
)
def test_paper_admission_rejects_constructed_live_or_prod_decision(tmp_path, updates):
    engine = engine_fixture(tmp_path)
    forged = approved_decision().model_copy(update=updates)

    with pytest.raises(PaperExecutionSafetyError, match="PAPER consumer rejects"):
        engine._validate_decision(forged)


def test_paper_engine_has_no_caller_selectable_lifecycle_policy(tmp_path):
    engine = engine_fixture(tmp_path)
    prod_shaped_settings = SimpleNamespace(
        trading_mode=TradingMode.LIVE,
        evedex_profile=EvedexProfile.PROD,
        account_id="prod-account",
        evedex_dev_expected_account_id="prod-account",
        evedex_dev_symbol_map={"BTCUSDT": "BTCUSD"},
        environment="prod",
    )
    with pytest.raises(ValueError, match="requires TradingMode.PAPER"):
        PaperDevCanaryPolicy.from_settings(prod_shaped_settings)

    with pytest.raises(TypeError, match="unexpected keyword argument"):
        PaperExecutionEngine(
            engine.adapter,
            engine.trades,
            engine.effects,
            engine.settings,
            lifecycle_policy=PaperDevCanaryPolicy.from_settings(engine.settings),  # type: ignore[call-arg]
        )


def test_internal_lifecycle_seam_requires_explicit_policy_and_does_not_create_canary(tmp_path):
    paper = engine_fixture(tmp_path)

    class ExplicitPolicy:
        scope = paper._lifecycle_scope

        @staticmethod
        def validate_decision_scope(decision):
            return None

    settings = SimpleNamespace(service_name="explicit-lifecycle-test")
    engine = _EvedexProtectedExecutionEngine(
        paper.adapter,
        paper.trades,
        paper.effects,
        settings,
        lifecycle_policy=ExplicitPolicy(),
        mutation_budget=object(),
        runtime_health=object(),
    )

    assert engine.settings is settings
    assert engine._lifecycle_policy is not paper._lifecycle_policy
    assert engine._canary_scope is None
    assert engine._expected_venue_health() == {
        "profile": "DEV",
        "chain_id": 16182,
        "exchange_url": "https://trading-api.evedex.tech",
        "auth_url": "https://auth-api.evedex.tech",
        "sdk_version": "1.2.11",
    }
