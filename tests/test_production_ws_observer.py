"""Synthetic WS frames with actual PROD reader logic, never LIVE authority."""

import asyncio
import traceback
from collections import deque
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import pytest

from kairos_execution.production_ws_observer import (
    CHANNELS,
    WsFrame,
    WsRestObservationError,
    capture_ws_rest_observation,
)
from tests.test_production_reads import fixture


class SyntheticStream:
    def __init__(self, frames=()):
        self.frames = asyncio.Queue()
        for frame in frames:
            self.frames.put_nowait(frame)
        self.closed = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        self.closed = True

    async def receive(self):
        return await self.frames.get()


def acknowledgements():
    return [WsFrame(kind="SUBSCRIBED", channel=channel) for channel in sorted(CHANNELS)]


@pytest.mark.asyncio
async def test_confirmed_channels_bracket_actual_rest_reader_and_preserve_no_authority():
    reads, calls = fixture()
    await reads.preflight()
    stream = SyntheticStream(acknowledgements())
    actual_fetch = reads.fetch_paper_state

    async def snapshot():
        assert stream.frames.empty()
        stream.frames.put_nowait(
            WsFrame(
                kind="PUBLICATION",
                channel="funding",
                epoch="e",
                offset=1,
                payload_json='{"private":"example"}',
            )
        )
        await asyncio.sleep(0)
        return await actual_fetch()

    reads.fetch_paper_state = AsyncMock(side_effect=snapshot)
    capture = await capture_ws_rest_observation(reads, stream, after_snapshot_seconds=0.01)
    assert stream.closed and capture.subscribed_channels == CHANNELS
    assert len(capture.acknowledgements) == 8
    assert all(
        ack.received_monotonic_ns <= capture.snapshot_started_monotonic_ns for ack in capture.acknowledgements
    )
    assert any(call["source"] == "available_balance" for call in calls)
    assert capture.publications[0].channel == "funding"
    assert capture.publications[0].local_sequence == 1
    assert capture.authoritative_reconciliation is False
    assert capture.sequence_continuity_proven is False and capture.history_complete is None
    assert capture.fees_final is None and capture.trading_authority is False
    assert "example" not in repr(capture) and "example" not in repr(capture.publications[0])


@pytest.mark.asyncio
async def test_snapshot_cannot_start_before_all_eight_acknowledgements():
    reads, _ = fixture()
    await reads.preflight()
    stream = SyntheticStream(acknowledgements()[:-1])
    reads.fetch_paper_state = AsyncMock()
    with pytest.raises(WsRestObservationError, match="timed out"):
        await capture_ws_rest_observation(reads, stream, timeout_seconds=0.03)
    reads.fetch_paper_state.assert_not_awaited()
    assert stream.closed


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "frames,reason",
    [
        ([WsFrame(kind="PUBLICATION", channel="funding", payload_json="{}")], "without channel"),
        ([WsFrame(kind="DISCONNECTED")], "disconnected"),
        ([WsFrame(kind="RECOVERY_FAILED")], "recovery failed"),
        (
            [WsFrame(kind="SUBSCRIBED", channel="funding"), WsFrame(kind="SUBSCRIBED", channel="funding")],
            "duplicate",
        ),
    ],
)
async def test_refuses_missing_acknowledgement_or_stream_gap(frames, reason):
    reads, _ = fixture()
    await reads.preflight()
    reads.fetch_paper_state = AsyncMock()
    stream = SyntheticStream(frames)
    with pytest.raises(WsRestObservationError, match=reason):
        await capture_ws_rest_observation(reads, stream, timeout_seconds=1)
    reads.fetch_paper_state.assert_not_awaited()
    assert stream.closed


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "second",
    [
        WsFrame(kind="PUBLICATION", channel="funding", epoch="e", offset=3, payload_json="{}"),
        WsFrame(kind="PUBLICATION", channel="funding", epoch="other", offset=2, payload_json="{}"),
        WsFrame(kind="PUBLICATION", channel="funding", epoch="e", payload_json="{}"),
    ],
)
async def test_refuses_provider_offset_discontinuities_or_partial_cursor(second):
    reads, _ = fixture()
    await reads.preflight()
    stream = SyntheticStream(
        acknowledgements()
        + [
            WsFrame(kind="PUBLICATION", channel="funding", epoch="e", offset=1, payload_json="{}"),
            second,
        ]
    )
    reads.fetch_paper_state = AsyncMock()
    with pytest.raises(WsRestObservationError):
        await capture_ws_rest_observation(reads, stream, timeout_seconds=1)


@pytest.mark.asyncio
async def test_disconnect_during_snapshot_discards_partial_result():
    reads, _ = fixture()
    await reads.preflight()
    stream = SyntheticStream(acknowledgements())

    async def snapshot():
        stream.frames.put_nowait(WsFrame(kind="DISCONNECTED"))
        await asyncio.sleep(0.01)
        return {"private": "partial"}

    reads.fetch_paper_state = AsyncMock(side_effect=snapshot)
    with pytest.raises(WsRestObservationError, match="disconnected"):
        await capture_ws_rest_observation(reads, stream, timeout_seconds=1)
    assert stream.closed


@pytest.mark.asyncio
async def test_overflow_or_invalid_json_discards_snapshot():
    for payloads in [["{}", "{}"], ['{"x": NaN}'], ['{"x":1,"x":2}'], ['{"x":1e400}']]:
        reads, _ = fixture()
        await reads.preflight()
        stream = SyntheticStream(
            acknowledgements()
            + [WsFrame(kind="PUBLICATION", channel="funding", payload_json=p) for p in payloads]
        )
        reads.fetch_paper_state = AsyncMock()
        with pytest.raises(WsRestObservationError):
            await capture_ws_rest_observation(reads, stream, max_publications=1)


@pytest.mark.asyncio
async def test_unresponsive_stream_cancellation_fails_closed():
    reads, _ = fixture()
    await reads.preflight()

    class UnresponsiveStream(SyntheticStream):
        def __init__(self):
            super().__init__(acknowledgements())
            self.release = asyncio.Event()

        async def receive(self):
            try:
                return await self.frames.get()
            except asyncio.CancelledError:
                await self.release.wait()
                raise ConnectionError("stream closed") from None

        async def __aexit__(self, *_):
            self.release.set()
            await asyncio.sleep(0)
            self.closed = True

    stream = UnresponsiveStream()
    reads.fetch_paper_state = AsyncMock(return_value={})
    with pytest.raises(WsRestObservationError, match="did not stop"):
        await capture_ws_rest_observation(reads, stream, after_snapshot_seconds=0)
    assert stream.closed


@pytest.mark.asyncio
@pytest.mark.parametrize("boundary", ["enter", "receive", "snapshot", "exit", "receive_cancel"])
async def test_external_exceptions_never_expose_private_text_or_exception_chain(boundary):
    marker = "SYNTHETIC_PRIVATE_MARKER"
    reads, _ = fixture()
    await reads.preflight()

    class LeakyStream(SyntheticStream):
        async def __aenter__(self):
            if boundary == "enter":
                raise RuntimeError(marker)
            return self

        async def __aexit__(self, *_):
            if boundary == "exit":
                raise RuntimeError(marker)
            return False

        async def receive(self):
            if boundary == "receive":
                # Even a spoofed internal exception must be sanitized.
                raise WsRestObservationError(marker)
            if boundary == "receive_cancel":
                raise asyncio.CancelledError(marker)
            return await self.frames.get()

    stream = LeakyStream(acknowledgements())
    reads.fetch_paper_state = AsyncMock(
        side_effect=RuntimeError(marker) if boundary == "snapshot" else None,
        return_value={},
    )
    with pytest.raises(WsRestObservationError) as captured:
        await capture_ws_rest_observation(reads, stream, after_snapshot_seconds=0)
    error = captured.value
    assert marker not in str(error)
    assert marker not in "".join(traceback.format_exception(error))
    while error is not None:
        assert marker not in str(error)
        error = error.__cause__ or error.__context__


@pytest.mark.asyncio
async def test_external_stream_cannot_suppress_a_failure():
    reads, _ = fixture()
    await reads.preflight()

    class SuppressingStream(SyntheticStream):
        async def __aexit__(self, *_):
            return True

    stream = SuppressingStream([WsFrame(kind="DISCONNECTED")])
    with pytest.raises(WsRestObservationError, match="disconnected"):
        await capture_ws_rest_observation(reads, stream)


@pytest.mark.asyncio
@pytest.mark.parametrize("clock", ["utc", "monotonic"])
async def test_clock_regression_between_publications_is_rejected(monkeypatch, clock):
    reads, _ = fixture()
    await reads.preflight()
    base = datetime(2026, 11, 9, tzinfo=UTC)
    increments = [0, *range(1, 9), 10, 9]
    if clock == "utc":
        times = deque(base + timedelta(seconds=i) for i in increments)

        class SyntheticClock:
            @classmethod
            def now(cls, _tz):
                return times.popleft()

        monkeypatch.setattr("kairos_execution.production_ws_observer.datetime", SyntheticClock)
    else:
        values = deque(increments)
        monkeypatch.setattr(
            "kairos_execution.production_ws_observer.time.monotonic_ns", lambda: values.popleft()
        )
    stream = SyntheticStream(
        acknowledgements()
        + [
            WsFrame(kind="PUBLICATION", channel="funding", payload_json="{}"),
            WsFrame(kind="PUBLICATION", channel="funding", payload_json="{}"),
        ]
    )
    with pytest.raises(WsRestObservationError, match="clock moved backwards"):
        await capture_ws_rest_observation(reads, stream)


@pytest.mark.asyncio
async def test_cancellation_resistant_exit_is_bounded():
    reads, _ = fixture()
    await reads.preflight()
    release = asyncio.Event()

    class HangingExitStream(SyntheticStream):
        async def __aexit__(self, *_):
            try:
                await release.wait()
            except asyncio.CancelledError:
                await release.wait()
            return True

    stream = HangingExitStream([WsFrame(kind="DISCONNECTED")])
    start = asyncio.get_running_loop().time()
    try:
        with pytest.raises(WsRestObservationError, match="could not close|did not stop"):
            await capture_ws_rest_observation(reads, stream, timeout_seconds=0.1)
        assert asyncio.get_running_loop().time() - start < 1.5
    finally:
        release.set()
        await asyncio.sleep(0)


@pytest.mark.asyncio
@pytest.mark.parametrize("boundary", ["enter", "receive", "snapshot"])
async def test_cancellation_resistant_external_calls_are_bounded(boundary):
    reads, _ = fixture()
    await reads.preflight()
    release = asyncio.Event()

    async def resistant():
        try:
            await release.wait()
        except asyncio.CancelledError:
            await release.wait()
        return {}

    class HangingStream(SyntheticStream):
        async def __aenter__(self):
            if boundary == "enter":
                await resistant()
            return self

        async def receive(self):
            if boundary == "receive":
                return await resistant()
            return await self.frames.get()

    stream = HangingStream(acknowledgements())
    if boundary == "snapshot":
        reads.fetch_paper_state = AsyncMock(side_effect=resistant)
    start = asyncio.get_running_loop().time()
    try:
        with pytest.raises(WsRestObservationError):
            await capture_ws_rest_observation(reads, stream, timeout_seconds=0.1)
        assert asyncio.get_running_loop().time() - start < 1.5
    finally:
        release.set()
        await asyncio.sleep(0)
