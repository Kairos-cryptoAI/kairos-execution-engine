"""Pure clock conversion/failure checks; no venue, account or runtime startup."""

from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest

from kairos_execution import utc_clock
from kairos_execution.utc_clock import UtcClockError, precise_utc_now


def test_windows_reads_exact_filetime_without_float_rounding(monkeypatch):
    monkeypatch.setattr(utc_clock, "_WINDOWS", True)
    # datetime precision truncates the remaining 100 ns ticks; it never rounds
    # a source timestamp into its future or changes its source epoch.
    ticks = 116_444_736_000_000_000 + 1_800_000_000 * 10_000_000 + 1_234_569
    reader = Mock(return_value=ticks)
    monkeypatch.setattr(utc_clock, "_read_precise_filetime", reader)
    assert precise_utc_now() == datetime(2027, 1, 15, 8, tzinfo=UTC) + timedelta(microseconds=123456)
    reader.assert_called_once_with()


def test_unix_reads_integer_nanoseconds_without_float_rounding(monkeypatch):
    monkeypatch.setattr(utc_clock, "_WINDOWS", False)
    monkeypatch.setattr(utc_clock.time, "time_ns", lambda: 1_800_000_000_123_456_999)
    assert precise_utc_now() == datetime(2027, 1, 15, 8, tzinfo=UTC) + timedelta(microseconds=123456)


def test_windows_api_failure_never_falls_back_to_coarse_time(monkeypatch):
    monkeypatch.setattr(utc_clock, "_WINDOWS", True)
    reader = Mock(side_effect=OSError("internal path must not leak"))
    fallback = Mock()
    monkeypatch.setattr(utc_clock, "_read_precise_filetime", reader)
    monkeypatch.setattr(utc_clock.time, "time_ns", fallback)
    with pytest.raises(UtcClockError, match="precise OS UTC clock is unavailable") as error:
        precise_utc_now()
    assert "internal path" not in str(error.value)
    fallback.assert_not_called()


@pytest.mark.parametrize("value", [True, -1, None, 0, 116_444_736_000_000_000 - 1, 10**40])
def test_invalid_windows_timestamps_refuse(monkeypatch, value):
    monkeypatch.setattr(utc_clock, "_WINDOWS", True)
    monkeypatch.setattr(utc_clock, "_read_precise_filetime", lambda: value)
    with pytest.raises(UtcClockError):
        precise_utc_now()


@pytest.mark.parametrize("value", [True, -1, None, 10**40])
def test_invalid_unix_timestamps_refuse(monkeypatch, value):
    monkeypatch.setattr(utc_clock, "_WINDOWS", False)
    monkeypatch.setattr(utc_clock.time, "time_ns", lambda: value)
    with pytest.raises(UtcClockError):
        precise_utc_now()


def test_wall_clock_rollback_is_visible_to_existing_guards(monkeypatch):
    monkeypatch.setattr(utc_clock, "_WINDOWS", False)
    values = iter([1_800_000_001_000_000_000, 1_800_000_000_000_000_000])
    monkeypatch.setattr(utc_clock.time, "time_ns", lambda: next(values))
    previous = precise_utc_now()
    assert precise_utc_now() < previous


def test_real_os_clock_is_explicit_utc_and_same_exported_identity():
    assert utc_clock.precise_utc_now is precise_utc_now
    assert precise_utc_now().tzinfo is UTC
