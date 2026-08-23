"""Non-configurable EVEDEX deployment profiles and trading modes."""

from __future__ import annotations

from dataclasses import dataclass

from kairos_core.enums import EvedexProfile
from kairos_core.enums import TradingMode as TradingMode


@dataclass(frozen=True, slots=True)
class EvedexProfileParams:
    exchange_url: str
    auth_url: str
    websocket_url: str
    websocket_prefix: str
    chain_id: int
    instrument_suffix: str


EVEDEX_PROFILES = {
    EvedexProfile.DEV: EvedexProfileParams(
        exchange_url="https://trading-api.evedex.tech",
        auth_url="https://auth-api.evedex.tech",
        websocket_url="wss://ws.evedex.tech/connection/websocket",
        websocket_prefix="futures-perp-dev",
        chain_id=16182,
        instrument_suffix=":DEV",
    ),
    EvedexProfile.DEMO: EvedexProfileParams(
        exchange_url="https://trading-api.evedex.io",
        auth_url="https://auth-api.evedex.io",
        websocket_url="wss://ws.evedex.io/connection/websocket",
        websocket_prefix="futures-perp-beta",
        chain_id=16182,
        instrument_suffix=":DEMO",
    ),
    EvedexProfile.PROD: EvedexProfileParams(
        exchange_url="https://trading-api.evedex.com",
        auth_url="https://auth-api.evedex.com",
        websocket_url="wss://ws.evedex.com/connection/websocket",
        websocket_prefix="futures-perp",
        chain_id=161803,
        instrument_suffix="",
    ),
}


def profile_params(profile: EvedexProfile) -> EvedexProfileParams:
    return EVEDEX_PROFILES[profile]
