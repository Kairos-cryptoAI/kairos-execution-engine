import pytest
from kairos_core.enums import OrderSide

from kairos_execution.trailing import TrailingStop, TrailingStopManager


def test_long_trailing_follows_up_only():
    ts = TrailingStop(side=OrderSide.BUY, trail_pct=0.01, anchor=100.0)
    assert round(ts.update(110.0), 4) == round(110 * 0.99, 4)  # anchor moved up
    assert round(ts.update(105.0), 4) == round(110 * 0.99, 4)  # anchor does not retreat
    # stop sits at 110 * 0.99 = 108.9; price below it triggers, above it does not
    assert ts.is_triggered(109.0) is False
    assert ts.is_triggered(108.5) is True


def test_short_trailing_follows_down_only():
    ts = TrailingStop(side=OrderSide.SELL, trail_pct=0.01, anchor=100.0)
    assert round(ts.update(90.0), 4) == round(90 * 1.01, 4)
    assert ts.is_triggered(90.5) is False
    assert ts.is_triggered(91.0) is True


@pytest.mark.parametrize("trail_pct", [0.0, -0.01, 1.0, float("inf"), float("nan")])
def test_invalid_trailing_distance_is_rejected(trail_pct):
    with pytest.raises(ValueError, match="trail_pct"):
        TrailingStop(side=OrderSide.BUY, trail_pct=trail_pct, anchor=100.0)


def test_manager_does_not_silently_replace_explicit_zero_distance():
    manager = TrailingStopManager(0.01)

    with pytest.raises(ValueError, match="trail_pct"):
        manager.open("BTCUSDT", OrderSide.BUY, 100.0, trail_pct=0.0)


@pytest.mark.parametrize("price", [0.0, -1.0, float("inf"), float("nan")])
def test_trigger_check_rejects_invalid_prices(price):
    stop = TrailingStop(side=OrderSide.BUY, trail_pct=0.01, anchor=100.0)

    with pytest.raises(ValueError, match="price"):
        stop.is_triggered(price)


def test_short_update_rejects_overflowing_stop_price():
    stop = TrailingStop(side=OrderSide.SELL, trail_pct=0.99, anchor=1e308)

    with pytest.raises(ValueError, match="finite"):
        stop.update(1e308)
