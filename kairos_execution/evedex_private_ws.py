"""Bounded, read-only Centrifugo adapter for the EVEDEX PROD observer.

An already issued access token and already verified account ID are inputs; this
module neither obtains a session nor authorizes trading. A successful capture
does not establish stream completeness, account equity, or exchange readiness.
The adapter never reconnects: any connection/subscription loss is terminal.
"""
from __future__ import annotations

import asyncio
import json
import math
import re
from collections import deque
from typing import Any

import aiohttp

from .production_reads import ProductionEvedexReads
from .production_ws_observer import WsFrame

_PROD_WS_URL = "wss://ws.evedex.com/connection/websocket"
_PROD_IDENTITY_URL = "https://trading-api.evedex.com/api/user/me"
_MAX_FRAME_BYTES = 1_000_000
_MAX_BATCH = 32
_CHANNEL_PREFIXES = {
    "account": "user",
    "funding": "funding",
    "transfer": "transfer-update",
    "position": "position",
    "order": "order",
    "fill": "orderFills",
    "fee": "order-fee",
    "tpsl": "tpsl",
}


class PrivateWsUnavailable(PermissionError):
    """A sanitized refusal; remote payloads and credentials are never included."""


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _bad_constant(_value):
    raise ValueError("invalid JSON number")


def _finite_float(value):
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("non-finite JSON number")
    return result


async def _external(operation):
    try:
        return await operation()
    except asyncio.CancelledError:
        raise
    except Exception:
        pass
    # Do not retain an untrusted exception, even if it happens to be the same
    # exception type we use locally. It may contain private headers or data.
    raise PrivateWsUnavailable("private WS transport failed") from None


class EvedexPrivateWsStream:
    """One observation stream bound to one account and one existing token.

    The caller must independently bind the token session to the same account as
    the REST reader before constructing this object. Position and recovery
    semantics are not qualified; no result produced here grants authority.
    """

    def __init__(self, *, reads: ProductionEvedexReads, access_token: str) -> None:
        if type(reads) is not ProductionEvedexReads or not reads._preflight_complete:
            raise ValueError("the exact preflighted PROD reader is required")
        account_id = reads.expected_account_id
        if not isinstance(account_id, str) or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", account_id) is None:
            raise ValueError("a bounded normalized EVEDEX account ID is required")
        if (not isinstance(access_token, str) or not 1 <= len(access_token) <= 8192
                or any(ord(c) < 33 or ord(c) > 126 for c in access_token)):
            raise ValueError("a bounded existing access token is required")
        self._access_token = access_token
        self._reads = reads
        self._account_id = account_id
        self._channels = {
            f"futures-perp:{prefix}-{account_id}": name
            for name, prefix in _CHANNEL_PREFIXES.items()
        }
        self._pending = {index + 2: wire for index, wire in enumerate(self._channels)}
        self._subscribed: set[str] = set()
        self._epochs: dict[str, str] = {}
        self._replies: deque[dict[str, Any]] = deque()
        self._session = None
        self._socket = None
        self._open_attempted = False
        self._closed = False
        self._pong_required = False

    def __repr__(self) -> str:
        return "EvedexPrivateWsStream(<private>)"

    def require_reader(self, reads: ProductionEvedexReads) -> None:
        if (reads is not self._reads or not reads._preflight_complete
                or reads.expected_account_id != self._account_id
                or reads.client.expected_account_id != self._account_id):
            raise PrivateWsUnavailable("private WS and REST reader scopes differ")

    async def __aenter__(self):
        if self._open_attempted:
            raise PrivateWsUnavailable("private WS stream cannot be reopened")
        self._open_attempted = True
        try:
            async def refuse_redirect(_session, _context, _params):
                raise PrivateWsUnavailable("private WS redirects are not permitted")

            trace = aiohttp.TraceConfig()
            trace.on_request_redirect.append(refuse_redirect)
            self._session = aiohttp.ClientSession(
                trust_env=False, cookie_jar=aiohttp.DummyCookieJar(),
                timeout=aiohttp.ClientTimeout(total=30), trace_configs=[trace],
            )
            self.require_reader(self._reads)
            # The token's account must match the preflighted API-key reader.
            # Never follow a redirect with the bearer token in HTTP headers.
            identity_confirmed = False
            async with self._session.get(
                _PROD_IDENTITY_URL, headers={"Authorization": f"Bearer {self._access_token}"},
                allow_redirects=False,
            ) as response:
                if response.status != 200 or str(response.url) != _PROD_IDENTITY_URL:
                    raise PrivateWsUnavailable("private WS token identity is unavailable")
                body = bytearray()
                async for chunk in response.content.iter_chunked(4096):
                    body.extend(chunk)
                    if len(body) > 65536:
                        raise PrivateWsUnavailable("private WS token identity exceeds its bound")
                try:
                    identity = json.loads(
                        bytes(body), object_pairs_hook=_pairs, parse_constant=_bad_constant,
                        parse_float=_finite_float,
                    )
                except (TypeError, ValueError):
                    identity = None
                exchange_id = identity.get("exchangeId") if type(identity) is dict else None
                if (type(exchange_id) not in (int, str) or str(exchange_id) != self._account_id):
                    raise PrivateWsUnavailable("private WS token account differs from REST reader")
                identity_confirmed = True
            if not identity_confirmed:
                raise PrivateWsUnavailable("private WS token identity was not confirmed")
            self.require_reader(self._reads)
            self._socket = await self._session.ws_connect(
                _PROD_WS_URL, max_msg_size=_MAX_FRAME_BYTES, autoping=True,
            )
            # Check the final URL after any HTTP redirect *before* sending the
            # access token or a protocol command to the established socket.
            if str(self._socket._response.url) != _PROD_WS_URL:
                raise PrivateWsUnavailable("private WS destination changed")
            await self._socket.send_json({"id": 1, "connect": {"name": "js"}})
            reply = await self._next_reply()
            if (type(reply.get("id")) is not int or reply["id"] != 1
                    or type(reply.get("connect")) is not dict or "error" in reply):
                raise PrivateWsUnavailable("private WS connection was not acknowledged")
            self._pong_required = reply["connect"].get("pong") is True
            for request_id, wire in self._pending.items():
                await self._socket.send_json({
                    "id": request_id,
                    "subscribe": {"channel": wire, "data": {"accessToken": self._access_token}},
                })
            return self
        except asyncio.CancelledError:
            try:
                await self._close()
            except Exception:
                pass
            raise
        except Exception:
            try:
                await self._close()
            except Exception:
                pass
        # Raise outside the external exception handler: exception objects from
        # an untrusted client may contain headers, tokens, URLs, or payloads.
        raise PrivateWsUnavailable("private WS could not start") from None

    async def __aexit__(self, _exc_type, _exc, _tb):
        failed = False
        try:
            await self._close()
        except Exception:
            failed = True
        if failed:
            raise PrivateWsUnavailable("private WS close outcome is unknown") from None
        return False

    async def _close(self) -> None:
        self._closed = True
        self._access_token = ""
        self._replies.clear()
        try:
            if self._socket is not None:
                await self._socket.close()
        finally:
            if self._session is not None:
                await self._session.close()

    async def _next_reply(self) -> dict[str, Any]:
        while not self._replies:
            if self._closed or self._socket is None:
                raise PrivateWsUnavailable("private WS is closed")
            message = await _external(self._socket.receive)
            if message.type != aiohttp.WSMsgType.TEXT or not isinstance(message.data, str):
                raise PrivateWsUnavailable("private WS disconnected or sent an unsupported frame")
            if len(message.data.encode("utf-8")) > _MAX_FRAME_BYTES:
                raise PrivateWsUnavailable("private WS frame exceeded its bound")
            lines = message.data.splitlines()
            if not lines or len(lines) > _MAX_BATCH:
                raise PrivateWsUnavailable("private WS batch is malformed or too large")
            for line in lines:
                try:
                    item = json.loads(
                        line, object_pairs_hook=_pairs, parse_constant=_bad_constant,
                        parse_float=_finite_float,
                    )
                except (TypeError, ValueError):
                    item = None
                if item is None:
                    raise PrivateWsUnavailable("private WS JSON is malformed")
                if type(item) is not dict:
                    raise PrivateWsUnavailable("private WS reply is malformed")
                self._replies.append(item)
        return self._replies.popleft()

    async def receive(self) -> WsFrame:
        """Map actual subscribe acks/publications, never infer recovery."""
        try:
            while True:
                reply = await self._next_reply()
                if not reply:  # Centrifugo server heartbeat
                    if self._pong_required:
                        await _external(lambda: self._socket.send_json({}))
                    continue
                if "error" in reply:
                    raise PrivateWsUnavailable("private WS request was refused")
                if "id" in reply:
                    request_id = reply["id"]
                    wire = self._pending.pop(request_id, None) if type(request_id) is int else None
                    sub = reply.get("subscribe")
                    if wire is None or type(sub) is not dict or wire in self._subscribed:
                        raise PrivateWsUnavailable("private WS subscription reply is malformed")
                    if sub.get("publications") or sub.get("was_recovering") or sub.get("recovered"):
                        raise PrivateWsUnavailable("private WS recovery has not been qualified")
                    epoch = sub.get("epoch")
                    if epoch is not None:
                        if not isinstance(epoch, str) or not epoch or len(epoch) > 256:
                            raise PrivateWsUnavailable("private WS epoch is malformed")
                        self._epochs[wire] = epoch
                    self._subscribed.add(wire)
                    return WsFrame(kind="SUBSCRIBED", channel=self._channels[wire])
                push = reply.get("push")
                if type(push) is not dict:
                    raise PrivateWsUnavailable("private WS push is malformed")
                if "disconnect" in push or "unsubscribe" in push:
                    return WsFrame(kind="DISCONNECTED")
                wire = push.get("channel")
                publication = push.get("pub")
                if wire not in self._subscribed or type(publication) is not dict or "data" not in publication:
                    raise PrivateWsUnavailable("private WS publication is malformed")
                payload = json.dumps(
                    publication["data"], ensure_ascii=False, allow_nan=False, separators=(",", ":"),
                )
                if len(payload.encode("utf-8")) > _MAX_FRAME_BYTES:
                    raise PrivateWsUnavailable("private WS publication exceeded its bound")
                offset = publication.get("offset")
                epoch = self._epochs.get(wire)
                if offset is not None and (type(offset) is not int or offset < 0 or epoch is None):
                    raise PrivateWsUnavailable("private WS position is incomplete")
                if offset is None:
                    epoch = None
                return WsFrame(kind="PUBLICATION", channel=self._channels[wire],
                               payload_json=payload, epoch=epoch, offset=offset)
        except PrivateWsUnavailable:
            raise
        except Exception:
            pass
        raise PrivateWsUnavailable("private WS reader failed") from None
