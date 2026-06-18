from kairos_core.enums import OrderSide, ReasonCode
from kairos_execution.reason_router import Action, action_for


def test_entry_codes_map_to_sides():
    assert action_for(ReasonCode.ENTER_LONG_TREND) == (Action.OPEN, OrderSide.BUY)
    assert action_for(ReasonCode.ENTER_SHORT_TREND) == (Action.OPEN, OrderSide.SELL)


def test_no_trade_is_noop():
    assert action_for(ReasonCode.NO_TRADE)[0] is Action.NOOP
    assert action_for(ReasonCode.CLOSE_POSITION)[0] is Action.CLOSE
