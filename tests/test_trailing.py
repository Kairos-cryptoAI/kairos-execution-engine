from kairos_core.enums import OrderSide
from kairos_execution.trailing import TrailingStop


def test_long_trailing_follows_up_only():
    ts = TrailingStop(side=OrderSide.BUY, trail_pct=0.01, anchor=100.0)
    assert round(ts.update(110.0), 4) == round(110 * 0.99, 4)   # anchor moved up
    assert round(ts.update(105.0), 4) == round(110 * 0.99, 4)   # anchor does not retreat
    # stop sits at 110 * 0.99 = 108.9; price below it triggers, above it does not
    assert ts.is_triggered(109.0) is False
    assert ts.is_triggered(108.5) is True


def test_short_trailing_follows_down_only():
    ts = TrailingStop(side=OrderSide.SELL, trail_pct=0.01, anchor=100.0)
    assert round(ts.update(90.0), 4) == round(90 * 1.01, 4)
    assert ts.is_triggered(90.5) is False
    assert ts.is_triggered(91.0) is True
