"""The reviewed PROD universe is shared by custody, lifecycle and Binance capture."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from kairos_execution.managed_signer import CustodyBindingV1
from kairos_execution.prod_universe import PROD_INSTRUMENTS, PROD_SYMBOL_MAP, valid_instrument_set
from kairos_execution.production_binance_capture import BINANCE_REFERENCE_SYMBOLS
from kairos_execution.production_lifecycle import ProductionLifecycleConfigV1
from tests.test_production_lifecycle import _config

TEN = tuple(PROD_SYMBOL_MAP.values())[:5] + ("AAVEUSD", "DOGEUSD", "HYPEUSD", "LINKUSD", "SUIUSD", "ZECUSD")


def test_universe_is_the_quant_scouts_map_and_the_binance_capture_symbols():
    assert len(PROD_SYMBOL_MAP) == 24
    assert all(venue == signal.removesuffix("T") for signal, venue in PROD_SYMBOL_MAP.items())
    assert frozenset(PROD_SYMBOL_MAP) == BINANCE_REFERENCE_SYMBOLS
    assert PROD_INSTRUMENTS >= frozenset(TEN) and {"LTCUSD", "1000PEPEUSD"} <= PROD_INSTRUMENTS


@pytest.mark.parametrize(
    "instruments",
    [
        (),
        ("BTCUSD", "BTCUSD"),
        ("BTCUSD", "ATOMUSD"),
        ("BTCUSD", "ETHUSD:DEV"),
        ("ATOMUSD:DEV",),
        ("BTCUSD", ""),
        "BTCUSD",
        ("BTCUSD", 1),
    ],
)
def test_instrument_set_refuses_empty_duplicate_and_unreviewed(instruments):
    assert not valid_instrument_set(instruments)


def _binding(instruments):
    binding = _config().custody_binding
    return CustodyBindingV1.model_validate({**binding.model_dump(), "approved_instruments": instruments})


def test_custody_binding_accepts_a_reviewed_subset_and_refuses_outsiders():
    assert _binding(TEN).approved_instruments == TEN
    assert _binding(("ZECUSD",)).approved_instruments == ("ZECUSD",)
    with pytest.raises(ValidationError, match="prod_universe"):
        _binding(("BTCUSD", "ATOMUSD"))


def _lifecycle(symbol_map, instruments):
    config = _config()
    custody = {**config.custody_binding.model_dump(), "approved_instruments": instruments}
    return ProductionLifecycleConfigV1.model_validate(
        {**config.model_dump(), "custody_binding": custody, "symbol_map": symbol_map}
    )


def test_lifecycle_symbol_map_covers_exactly_the_approved_reviewed_pairs():
    everything = tuple(PROD_SYMBOL_MAP.values())
    assert _lifecycle(dict(PROD_SYMBOL_MAP), everything).symbol_map == dict(PROD_SYMBOL_MAP)
    with pytest.raises(ValidationError, match="bijectively cover"):
        _lifecycle({"BTCUSDT": "BTCUSD"}, TEN)
    with pytest.raises(ValidationError, match="leaves the reviewed PROD universe"):
        _lifecycle({"BTCUSDT": "ETHUSD", "ETHUSDT": "BTCUSD"}, ("BTCUSD", "ETHUSD"))
