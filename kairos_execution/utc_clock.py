"""Precise OS UTC clock for explicit production resource composition.

Pass the same ``precise_utc_now`` function to every clock-bearing resource.
Nothing imports this into a runtime by default. Precision does not establish
OS/database synchronization or grant trading authority: the original clock,
freshness and lease checks remain necessary. Wall-clock rollbacks are exposed,
never clamped, offset, retimed against a database, or hidden as monotonic UTC.
"""

from __future__ import annotations

import ctypes
import sys
import time
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from typing import Any

_WINDOWS = sys.platform == "win32"
_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_FILETIME_UNIX_EPOCH_TICKS = 116_444_736_000_000_000
_FILETIME_TICKS_PER_SECOND = 10_000_000


class UtcClockError(RuntimeError):
    """The configured precise UTC source is unavailable or malformed."""


@lru_cache(maxsize=1)
def _windows_reader() -> Any:
    # Lazy: importing the module does not load a system library or select a
    # deployment clock. A Windows installation without the precise API refuses
    # instead of silently returning the coarser CPython 3.11 datetime clock.
    if sys.platform != "win32":
        raise UtcClockError("Windows precise time is unavailable on this platform")
    library = ctypes.WinDLL("kernel32", use_last_error=True)
    reader = library.GetSystemTimePreciseAsFileTime
    reader.argtypes = [ctypes.POINTER(ctypes.c_ulonglong)]
    reader.restype = None
    return reader


def _read_precise_filetime() -> int:
    value = ctypes.c_ulonglong()
    _windows_reader()(ctypes.byref(value))
    return value.value


def _utc_from_filetime(ticks: int) -> datetime:
    if type(ticks) is not int or ticks < _FILETIME_UNIX_EPOCH_TICKS:
        raise UtcClockError("precise UTC source returned an invalid timestamp")
    seconds, remainder = divmod(ticks - _FILETIME_UNIX_EPOCH_TICKS, _FILETIME_TICKS_PER_SECOND)
    return _UNIX_EPOCH + timedelta(seconds=seconds, microseconds=remainder // 10)


def precise_utc_now() -> datetime:
    """Return real UTC to datetime precision; expose failures and rollback."""
    try:
        if _WINDOWS:
            return _utc_from_filetime(_read_precise_filetime())
        timestamp_ns = time.time_ns()
        if type(timestamp_ns) is not int or timestamp_ns < 0:
            raise UtcClockError("precise UTC source returned an invalid timestamp")
        seconds, remainder = divmod(timestamp_ns, 1_000_000_000)
        return _UNIX_EPOCH + timedelta(seconds=seconds, microseconds=remainder // 1_000)
    except Exception:
        raise UtcClockError("precise OS UTC clock is unavailable") from None
