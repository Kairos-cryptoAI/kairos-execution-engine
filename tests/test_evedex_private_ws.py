"""Synthetic Centrifugo frames only; no token or exchange connection exists."""

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import patch

import aiohttp
import pytest

from kairos_execution.evedex_private_ws import EvedexPrivateWsStream, PrivateWsUnavailable
from kairos_execution.production_ws_observer import CHANNELS, capture_ws_rest_observation
from tests.test_production_reads import fixture

TOKEN = "synthetic-private-token"
URL = "wss://ws.evedex.com/connection/websocket"
IDENTITY_URL = "https://trading-api.evedex.com/api/user/me"


def preflighted(account="acct-prod-1"):
    reads, _ = fixture()
    reads.expected_account_id = account
    reads.client.expected_account_id = account
    reads._preflight_complete = True
    return reads


class IdentityResponse:
    def __init__(self, *, account="acct-prod-1", status=200):
        self.url = IDENTITY_URL
        self.status = status
        self.body = json.dumps({"exchangeId": account}).encode()
        self.content = self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    async def iter_chunked(self, _size):
        yield self.body


class Socket:
    def __init__(self, replies, *, url=URL):
        self._response = SimpleNamespace(url=url)
        self.replies = list(replies)
        self.sent = []
        self.closed = False

    async def send_json(self, item):
        self.sent.append(item)

    async def receive(self):
        if not self.replies:
            await asyncio.Future()
        item = self.replies.pop(0)
        if isinstance(item, BaseException):
            raise item
        return SimpleNamespace(type=aiohttp.WSMsgType.TEXT, data=item)

    async def close(self):
        self.closed = True


class Session:
    def __init__(self, socket, **kwargs):
        self.socket = socket
        self.options = kwargs
        self.closed = False
        self.url = None
        self.ws_options = None
        self.identity = IdentityResponse()
        self.identity_request = None

    def get(self, url, **kwargs):
        self.identity_request = (url, kwargs)
        return self.identity

    async def ws_connect(self, url, **kwargs):
        self.url = url
        self.ws_options = kwargs
        return self.socket

    async def close(self):
        self.closed = True


def connect_reply(*, pong=False):
    return json.dumps({"id": 1, "connect": {"pong": pong}})


def acks(*, epoch=True):
    return [
        json.dumps({"id": i, "subscribe": {"epoch": "test-epoch"} if epoch else {}}) for i in range(2, 10)
    ]


def opened(socket, *, identity=None):
    sessions = []

    def factory(**kwargs):
        result = Session(socket, **kwargs)
        if identity is not None:
            result.identity = identity
        sessions.append(result)
        return result

    return sessions, patch("kairos_execution.evedex_private_ws.aiohttp.ClientSession", factory)


@pytest.mark.asyncio
async def test_real_wire_shape_ack_publication_and_heartbeat_without_secret_output():
    wire = "futures-perp:funding-acct-prod-1"
    publication = json.dumps({"push": {"channel": wire, "pub": {"offset": 1, "data": {"quantity": "1"}}}})
    socket = Socket([connect_reply(pong=True), *acks(), "{}", publication])
    sessions, patched = opened(socket)
    with patched:
        stream = EvedexPrivateWsStream(reads=preflighted(), access_token=TOKEN)
        assert TOKEN not in repr(stream)
        async with stream:
            frames = [await stream.receive() for _ in range(8)]
            assert {frame.channel for frame in frames} == CHANNELS
            frame = await stream.receive()
            assert frame.kind == "PUBLICATION" and frame.channel == "funding"
            assert (frame.epoch, frame.offset, json.loads(frame.payload_json)) == (
                "test-epoch",
                1,
                {"quantity": "1"},
            )
        assert stream._access_token == ""
    assert sessions[0].url == URL and sessions[0].options["trust_env"] is False
    assert sessions[0].identity_request == (
        IDENTITY_URL,
        {"headers": {"Authorization": f"Bearer {TOKEN}"}, "allow_redirects": False},
    )
    assert socket.sent[0] == {"id": 1, "connect": {"name": "js"}}
    assert len(socket.sent) == 10 and socket.sent[-1] == {}
    subscriptions = socket.sent[1:9]
    assert len({entry["subscribe"]["channel"] for entry in subscriptions}) == 8
    assert all(entry["subscribe"]["data"] == {"accessToken": TOKEN} for entry in subscriptions)
    assert socket.closed and sessions[0].closed


@pytest.mark.asyncio
async def test_redirect_trace_stops_redirect_before_following_it():
    socket = Socket([connect_reply(), *acks()])
    sessions, patched = opened(socket)
    with patched:
        async with EvedexPrivateWsStream(reads=preflighted(), access_token=TOKEN):
            handler = sessions[0].options["trace_configs"][0].on_request_redirect[0]
            with pytest.raises(PrivateWsUnavailable, match="redirects are not permitted"):
                await handler(None, None, None)


@pytest.mark.asyncio
async def test_adapter_brackets_actual_reader_with_eight_acknowledgements():
    reads, _ = fixture()
    await reads.preflight()
    wire = "futures-perp:funding-acct-prod-1"
    publication = json.dumps({"push": {"channel": wire, "pub": {"offset": 1, "data": {"quantity": "1"}}}})
    socket = Socket([connect_reply(), *acks(), publication])
    sessions, patched = opened(socket)
    with patched:
        result = await capture_ws_rest_observation(
            reads,
            EvedexPrivateWsStream(reads=reads, access_token=TOKEN),
            timeout_seconds=1,
            after_snapshot_seconds=0.01,
        )
    assert result.subscribed_channels == CHANNELS
    assert result.trading_authority is False and result.sequence_continuity_proven is False
    assert len(result.publications) == 1 and sessions[0].closed


@pytest.mark.asyncio
@pytest.mark.parametrize("identity", [IdentityResponse(account="other"), IdentityResponse(status=401)])
async def test_token_identity_is_checked_before_ws_or_subscriptions(identity):
    socket = Socket([connect_reply(), *acks()])
    sessions, patched = opened(socket, identity=identity)
    with patched, pytest.raises(PrivateWsUnavailable, match="could not start") as exc:
        async with EvedexPrivateWsStream(reads=preflighted(), access_token=TOKEN):
            pass
    assert sessions[0].url is None and not socket.sent and TOKEN not in str(exc.value)


@pytest.mark.asyncio
async def test_identity_context_cannot_suppress_wrong_account():
    class SuppressingIdentity(IdentityResponse):
        async def __aexit__(self, *_):
            return True

    socket = Socket([connect_reply(), *acks()])
    sessions, patched = opened(socket, identity=SuppressingIdentity(account="other"))
    with patched, pytest.raises(PrivateWsUnavailable, match="could not start"):
        async with EvedexPrivateWsStream(reads=preflighted(), access_token=TOKEN):
            pass
    assert sessions[0].url is None and not socket.sent


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body", [b'{"exchangeId":"acct-prod-1","value":1e400}', b" " * 65537], ids=["overflow", "oversized"]
)
async def test_malformed_or_oversized_token_identity_is_refused(body):
    identity = IdentityResponse()
    identity.body = body
    socket = Socket([connect_reply(), *acks()])
    sessions, patched = opened(socket, identity=identity)
    with patched, pytest.raises(PrivateWsUnavailable, match="could not start"):
        async with EvedexPrivateWsStream(reads=preflighted(), access_token=TOKEN):
            pass
    assert sessions[0].url is None and not socket.sent


@pytest.mark.asyncio
async def test_observer_rejects_a_different_rest_reader_even_when_account_ids_match():
    source = preflighted()
    other = preflighted()
    stream = EvedexPrivateWsStream(reads=source, access_token=TOKEN)
    with pytest.raises(PrivateWsUnavailable, match="scopes differ"):
        await capture_ws_rest_observation(other, stream)


@pytest.mark.asyncio
async def test_observer_detects_reader_scope_change_during_snapshot():
    reads = preflighted()
    socket = Socket([connect_reply(), *acks()])
    _, patched = opened(socket)

    async def snapshot():
        reads.expected_account_id = "changed"
        return {}

    reads.fetch_paper_state = snapshot
    with patched, pytest.raises(PrivateWsUnavailable, match="scopes differ"):
        await capture_ws_rest_observation(
            reads,
            EvedexPrivateWsStream(reads=reads, access_token=TOKEN),
            timeout_seconds=1,
            after_snapshot_seconds=0,
        )


@pytest.mark.asyncio
async def test_redirect_is_refused_before_any_protocol_message_or_token_is_sent():
    socket = Socket([], url="wss://other.example/connection/websocket")
    sessions, patched = opened(socket)
    with patched, pytest.raises(PrivateWsUnavailable, match="could not start"):
        async with EvedexPrivateWsStream(reads=preflighted(), access_token=TOKEN):
            pass
    assert not socket.sent and socket.closed and sessions[0].closed


@pytest.mark.asyncio
async def test_disconnect_and_unknown_provider_positions_fail_closed():
    wire = "futures-perp:funding-acct-prod-1"
    bad_position = json.dumps({"push": {"channel": wire, "pub": {"offset": 7, "data": {}}}})
    socket = Socket([connect_reply(), *acks(epoch=False), bad_position])
    _, patched = opened(socket)
    with patched:
        async with EvedexPrivateWsStream(reads=preflighted(), access_token=TOKEN) as stream:
            for _ in range(8):
                await stream.receive()
            with pytest.raises(PrivateWsUnavailable, match="position is incomplete"):
                await stream.receive()


@pytest.mark.asyncio
async def test_unsubscribe_is_reported_as_disconnect_and_no_reconnect():
    socket = Socket([connect_reply(), *acks(), json.dumps({"push": {"unsubscribe": {"code": 1}}})])
    _, patched = opened(socket)
    with patched:
        stream = EvedexPrivateWsStream(reads=preflighted(), access_token=TOKEN)
        async with stream:
            for _ in range(8):
                await stream.receive()
            assert (await stream.receive()).kind == "DISCONNECTED"
        with pytest.raises(PrivateWsUnavailable, match="cannot be reopened"):
            await stream.__aenter__()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad_reply",
    [
        '{"id":2,"id":2,"subscribe":{}}',
        '{"id":2,"subscribe":{"ignored":1e400}}',
        json.dumps({"id": 2, "error": {"message": TOKEN}}),
        json.dumps({"id": 2, "subscribe": {"recovered": True}}),
        json.dumps({"push": {"channel": "wrong", "pub": {"data": {}}}}),
    ],
)
async def test_malformed_refused_or_recovered_reply_never_leaks_payload(bad_reply):
    socket = Socket([connect_reply(), bad_reply])
    _, patched = opened(socket)
    with patched:
        async with EvedexPrivateWsStream(reads=preflighted(), access_token=TOKEN) as stream:
            with pytest.raises(PrivateWsUnavailable) as exc:
                await stream.receive()
            assert TOKEN not in str(exc.value)
            assert exc.value.__context__ is None


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [RuntimeError(TOKEN), PrivateWsUnavailable(TOKEN)])
async def test_external_transport_exception_is_sanitized_without_exception_context(failure):
    socket = Socket([connect_reply(), failure])
    _, patched = opened(socket)
    with patched:
        async with EvedexPrivateWsStream(reads=preflighted(), access_token=TOKEN) as stream:
            with pytest.raises(PrivateWsUnavailable) as exc:
                await stream.receive()
            assert TOKEN not in str(exc.value) and exc.value.__context__ is None


@pytest.mark.parametrize("account", ["", "../bad", "a:b", "a b", "a" * 129])
def test_rejects_untrusted_channel_ids(account):
    with pytest.raises(ValueError):
        EvedexPrivateWsStream(reads=preflighted(account), access_token=TOKEN)


@pytest.mark.parametrize("token", ["", "a\nb", "x" * 8193])
def test_rejects_malformed_token_without_echo(token):
    with pytest.raises(ValueError) as exc:
        EvedexPrivateWsStream(reads=preflighted(), access_token=token)
    assert TOKEN not in str(exc.value)
