"""Single-host alerts to Telegram and the facts of the ALERT_DELIVERY evidence.

A monitor watches the heartbeat that the live runner writes on every loop. It raises
two alerts, the fixed single-host profile (``SINGLE_HOST_REQUIRED_ALERT_NAMES``):

* ``local-process-health``: the heartbeat is older than the bound (the process hangs
  or is down); resolved when it is fresh again;
* ``local-supervisor-restart``: the heartbeat names a new process (the supervisor loop
  of ``start-live.cmd`` restarted it); resolved once the new process is healthy.

Each FIRING and RESOLVED event is a canonical JSON record sent to a Telegram chat with
an "Принято" button; the owner's press is the acknowledgement. Every event, every
Telegram answer and every acknowledgement is appended to an alert log, from which
``alert_facts`` builds ``SingleHostAlertFactsV2`` and stores the artifacts. Host-loss
resilience is not claimed.

The bot token is read from a file at each call and never logged or returned; error
messages carry no URL.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .production_owner import store_artifact
from .signed_evidence import (
    SINGLE_HOST_REQUIRED_ALERT_NAMES,
    SingleHostAlertDeliveryV2,
    SingleHostAlertFactsV2,
    TelegramAcknowledgementV2,
    validate_telegram_callback,
)

HEALTH = "local-process-health"
RESTART = "local-supervisor-restart"
SUPERVISOR = "kairos-autotrader-start-live-loop"
_TELEGRAM = "https://api.telegram.org"
_TOKEN = re.compile(r"(?<![0-9A-Za-z_-])[0-9]{5,15}:[A-Za-z0-9_-]{30,64}(?![0-9A-Za-z_-])")


class AlertError(RuntimeError):
    """An alert could not be sent or read; the message never contains the token."""


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _now() -> datetime:
    return datetime.now(UTC)


Http = Callable[[str, dict[str, Any]], dict[str, Any]]


def _urllib_http(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    request = urllib.request.Request(  # noqa: S310 - fixed https Telegram endpoint
        url, data=canonical(payload), headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=40) as response:  # noqa: S310  # nosec B310
            return dict(json.loads(response.read()))
    except urllib.error.HTTPError as exc:
        raise AlertError(f"Telegram answered HTTP {exc.code}") from None
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        raise AlertError(f"Telegram is unreachable: {type(exc).__name__}") from None


@dataclass
class TelegramChannel:
    """One bot and one chat. ``http`` is replaceable for tests."""

    token_file: Path
    chat_id: int
    owner_user_id: int
    http: Http = _urllib_http
    token_line: int | None = None

    def __post_init__(self) -> None:
        if type(self.owner_user_id) is not int or self.owner_user_id <= 0:
            raise AlertError("a positive owner Telegram user ID must be pinned explicitly")
        if type(self.chat_id) is not int or self.chat_id == 0:
            raise AlertError("a nonzero Telegram chat ID is required")

    def _token(self) -> str:
        """The bot token from its file: on the given 1-based line, or on the only line holding one.

        A shared keys file may hold other secrets and labels; only the one token-shaped
        value is taken, and no line ever appears in a message.
        """
        lines = Path(self.token_file).read_text(encoding="utf-8").splitlines()
        if self.token_line is not None:
            if not 1 <= self.token_line <= len(lines):
                raise AlertError("the bot token line is outside the file")
            found = [_TOKEN.findall(lines[self.token_line - 1])]
        else:
            found = [tokens for tokens in (_TOKEN.findall(line) for line in lines) if tokens]
        if len(found) != 1 or len(found[0]) != 1:
            raise AlertError("the file does not hold exactly one bot token; pass its line number")
        return str(found[0][0])

    def _call(self, method: str, payload: dict[str, Any]) -> dict[str, Any]:
        token = self._token()
        answer = self.http(f"{_TELEGRAM}/bot{token}/{method}", payload)
        if answer.get("ok") is not True:
            raise AlertError(f"Telegram refused {method}: {str(answer.get('description', ''))[:120]}")
        return answer

    def identity(self) -> dict[str, Any]:
        return dict(self._call("getMe", {})["result"])

    def send(self, text: str, *, ack_data: str) -> dict[str, Any]:
        markup = {"inline_keyboard": [[{"text": "Принято", "callback_data": ack_data}]]}
        return dict(
            self._call("sendMessage", {"chat_id": self.chat_id, "text": text, "reply_markup": markup})[
                "result"
            ]
        )

    def acknowledgements(
        self, offset: int, *, deliveries: list[dict[str, Any]], wait_s: int = 0
    ) -> tuple[list[dict[str, Any]], int]:
        answer = self._call(
            "getUpdates", {"offset": offset, "timeout": wait_s, "allowed_updates": ["callback_query"]}
        )
        acks, next_offset = [], offset
        for update in answer.get("result", []):
            next_offset = max(next_offset, int(update["update_id"]) + 1)
            query = update.get("callback_query")
            if not isinstance(query, dict):
                continue
            matches = []
            for delivery in deliveries:
                try:
                    if delivery.get("owner_telegram_user_id") != self.owner_user_id:
                        continue
                    digest = delivery["sha256"]
                    if re.fullmatch(r"[a-f0-9]{64}", digest) is None:
                        continue
                    validate_telegram_callback(
                        query,
                        owner_user_id=self.owner_user_id,
                        chat_id=self.chat_id,
                        message_id=delivery["message_id"],
                        callback_data=f"ack:{digest[:56]}",
                    )
                    if delivery["chat_id"] == self.chat_id:
                        matches.append(delivery)
                except (KeyError, TypeError, ValueError):
                    continue
            if len(matches) != 1:
                continue
            acks.append({"query": query, "delivery": matches[0]})
            try:
                self._call("answerCallbackQuery", {"callback_query_id": query["id"], "text": "Записано"})
            except AlertError:
                pass  # The verified press is recorded; the button spinner is cosmetic.
        return acks, next_offset


@dataclass
class AlertLog:
    """Append-only JSON lines: every event, delivery and acknowledgement."""

    path: Path

    def append(self, record: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, sort_keys=True, default=str) + "\n")

    def records(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        return [
            json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines() if line.strip()
        ]


@dataclass
class Monitor:
    """Turn heartbeat observations into FIRING/RESOLVED alerts with Telegram delivery."""

    heartbeat: Path
    channel: TelegramChannel
    log: AlertLog
    host: str
    stale_after: timedelta = timedelta(seconds=120)
    minimum_gap: timedelta = timedelta(seconds=3)
    clock: Callable[[], datetime] = _now
    _open: dict[str, dict[str, Any]] = field(default_factory=dict)
    _process: str | None = None
    _offset: int = 0

    def start(self) -> None:
        """Record the notifier (re)start with the bot identity: the notifier restart receipt."""
        bot = self.channel.identity()
        self.log.append(
            {
                "type": "NOTIFIER_START",
                "at": self.clock().isoformat(),
                "bot_id": bot.get("id"),
                "host": self.host,
                "owner_telegram_user_id": self.channel.owner_user_id,
                "chat_id": self.channel.chat_id,
            }
        )

    def _beat(self) -> dict[str, Any] | None:
        try:
            beat = json.loads(self.heartbeat.read_text(encoding="utf-8"))
            return beat if isinstance(beat, dict) else None
        except (OSError, ValueError):
            return None

    def _emit(self, name: str, state: str, detail: str) -> None:
        event = {
            "version": "kairos.local-alert-event.v1",
            "alert_name": name,
            "state": state,
            "host": self.host,
            "observed_at": self.clock().isoformat(),
            "detail": detail,
        }
        digest = hashlib.sha256(canonical(event)).hexdigest()
        self.log.append({"type": "EVENT", "sha256": digest, "event": event})
        try:
            message = self.channel.send(
                f"{'ТРЕВОГА' if state == 'FIRING' else 'ВОССТАНОВЛЕНО'}: {name}\n{detail}\n{self.host}",
                ack_data=f"ack:{digest[:56]}",
            )
            received = datetime.fromtimestamp(int(message["date"]), tz=UTC)
            self.log.append(
                {
                    "type": "DELIVERY",
                    "sha256": digest,
                    "message_id": message.get("message_id"),
                    "chat_id": self.channel.chat_id,
                    "owner_telegram_user_id": self.channel.owner_user_id,
                    "received_at": received.isoformat(),
                    "answer_sha256": hashlib.sha256(canonical(message)).hexdigest(),
                    "answer": message,
                }
            )
        except AlertError as exc:
            self.log.append({"type": "UNKNOWN_SEND", "sha256": digest, "error": str(exc)})

    def poll(self) -> None:
        now = self.clock()
        beat = self._beat()
        at = datetime.fromisoformat(beat["at"]) if beat and isinstance(beat.get("at"), str) else None
        healthy = at is not None and now - at <= self.stale_after
        process = f"{beat.get('pid')}@{beat.get('started_at')}" if beat else None
        if not healthy and HEALTH not in self._open:
            self._open[HEALTH] = {"since": now}
            self._emit(HEALTH, "FIRING", f"heartbeat {'missing' if at is None else 'older than the bound'}")
        elif healthy and HEALTH in self._open and now - self._open[HEALTH]["since"] >= self.minimum_gap:
            self._open.pop(HEALTH)
            self._emit(HEALTH, "RESOLVED", "heartbeat is fresh again")
        if healthy and process is not None:
            if self._process is not None and process != self._process and RESTART not in self._open:
                self._open[RESTART] = {"since": now}
                self._emit(RESTART, "FIRING", "the supervisor started a new runner process")
            elif RESTART in self._open and now - self._open[RESTART]["since"] >= self.minimum_gap:
                self._open.pop(RESTART)
                self._emit(RESTART, "RESOLVED", "the restarted runner is healthy")
            self._process = process
        deliveries = [r for r in self.log.records() if r.get("type") == "DELIVERY"]
        acks, self._offset = self.channel.acknowledgements(self._offset, deliveries=deliveries)
        for ack in acks:
            query, delivery = ack["query"], ack["delivery"]
            self.log.append(
                TelegramAcknowledgementV2(
                    event_sha256=delivery["sha256"],
                    at=now,
                    owner_telegram_user_id=self.channel.owner_user_id,
                    chat_id=self.channel.chat_id,
                    message_id=delivery["message_id"],
                    callback_data=query["data"],
                    query=query,
                ).model_dump(mode="json")
            )


def write_heartbeat(path: Path, *, pid: int, started_at: str) -> None:
    """The runner's side: one small file replaced atomically on every loop."""
    temporary = path.with_suffix(".tmp")
    temporary.write_text(
        json.dumps({"pid": pid, "started_at": started_at, "at": _now().isoformat()}), encoding="utf-8"
    )
    temporary.replace(path)


def alert_facts(log: AlertLog, evidence_dir: Path, *, owner_user_id: int) -> SingleHostAlertFactsV2:
    """Facts of the latest complete, acknowledged FIRING/RESOLVED pair of each alert."""
    records = log.records()
    if type(owner_user_id) is not int or owner_user_id <= 0:
        raise AlertError("a positive owner Telegram user ID must be pinned explicitly")
    events = {r["sha256"]: r["event"] for r in records if r["type"] == "EVENT"}
    deliveries = {r["sha256"]: r for r in records if r["type"] == "DELIVERY"}
    acks = [r for r in records if r["type"] == "ACK"]
    try:
        checked_acks = [TelegramAcknowledgementV2.model_validate_json(canonical(r)) for r in acks]
    except ValueError:
        raise AlertError("unbound or malformed owner acknowledgments require a fresh alert drill") from None
    if any(a.owner_telegram_user_id != owner_user_id for a in checked_acks):
        raise AlertError("owner acknowledgment differs from the pinned Telegram user")
    unknown = sum(1 for r in records if r["type"] == "UNKNOWN_SEND")
    starts = [r for r in records if r["type"] == "NOTIFIER_START"]
    if unknown:
        raise AlertError("the log has sends with an unknown outcome; they cannot be attested away")
    if len(starts) < 2:
        raise AlertError("the notifier restart is not observed: start the monitor twice")
    artifacts: list[str] = []

    def keep(value: object) -> str:
        digest = store_artifact(evidence_dir, canonical(value))
        if digest not in artifacts:
            artifacts.append(digest)
        return digest

    result: list[SingleHostAlertDeliveryV2] = []
    receipts: dict[str, str] = {}
    for name in SINGLE_HOST_REQUIRED_ALERT_NAMES:
        pairs = []
        ordered = [(digest, event) for digest, event in events.items() if event["alert_name"] == name]
        for (firing_sha, firing), (resolved_sha, resolved) in zip(ordered, ordered[1:], strict=False):
            if firing["state"] != "FIRING" or resolved["state"] != "RESOLVED":
                continue
            if firing_sha not in deliveries or resolved_sha not in deliveries:
                continue
            firing_at = datetime.fromisoformat(deliveries[firing_sha]["received_at"])
            resolved_at = datetime.fromisoformat(deliveries[resolved_sha]["received_at"])
            for ack in checked_acks:
                acknowledged = ack.at
                delivery = deliveries[resolved_sha]
                if (
                    ack.event_sha256 == resolved_sha
                    and ack.chat_id == delivery["chat_id"]
                    and ack.message_id == delivery["message_id"]
                    and delivery.get("owner_telegram_user_id") == owner_user_id
                    and firing_at < resolved_at <= acknowledged
                ):
                    pairs.append((firing_sha, resolved_sha, ack, firing_at, resolved_at, acknowledged))
                    break
        if not pairs:
            raise AlertError(f"no acknowledged FIRING/RESOLVED pair of {name} is in the log")
        firing_sha, resolved_sha, ack, firing_at, resolved_at, acknowledged = pairs[-1]
        for digest in (firing_sha, resolved_sha):
            if keep(events[digest]) != digest:
                raise AlertError("an event no longer hashes to its logged identity")
            keep(deliveries[digest]["answer"])
        ack_hash = keep(ack.model_dump(mode="json"))
        receipts[name] = keep(
            {"alert": name, "firing": deliveries[firing_sha], "resolved": deliveries[resolved_sha]}
        )
        result.append(
            SingleHostAlertDeliveryV2(
                alert_name=name,
                firing_event_sha256=firing_sha,
                resolved_event_sha256=resolved_sha,
                receiver_identity=f"telegram-chat-{ack.chat_id}",
                firing_received_at=firing_at,
                resolved_received_at=resolved_at,
                owner_acknowledged_at=acknowledged,
                owner_telegram_user_id=owner_user_id,
                telegram_chat_id=ack.chat_id,
                resolved_message_id=ack.message_id,
                callback_data=ack.callback_data,
                acknowledgement_sha256=ack_hash,
                delivery_receipt_sha256=receipts[name],
            )
        )
    notifier_receipt = keep({"notifier_starts": starts[-2:]})
    built = SingleHostAlertFactsV2(
        artifact_sha256s=tuple(artifacts),
        required_alert_names=SINGLE_HOST_REQUIRED_ALERT_NAMES,
        deliveries=tuple(result),
        owner_telegram_user_id=owner_user_id,
        notifier_restart_receipt_sha256=notifier_receipt,
        local_supervisor_identity=SUPERVISOR,
        local_supervisor_restart_receipt_sha256=receipts[RESTART],
        local_health_check_receipt_sha256=receipts[HEALTH],
        unknown_sends=0,
    )
    # Facts production reuses the same raw-artifact checks as receipt validation;
    # no signed envelope is needed to reject a forged log before it is attested.
    from .signed_evidence import DirectoryEvidenceResolver, SingleHostAlertReceiptInterpreter

    verifier = SingleHostAlertReceiptInterpreter((), DirectoryEvidenceResolver(evidence_dir))
    try:
        verifier.validate_artifacts(built, owner_user_id=owner_user_id)
    except (KeyError, TypeError, ValueError, OSError):
        raise AlertError("raw alert delivery or owner acknowledgment binding is invalid") from None
    return built


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m kairos_execution.production_alerts", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("monitor", "test-message"):
        command = sub.add_parser(name)
        command.add_argument("--token-file", type=Path, required=True, help="token file or the keys file")
        command.add_argument("--token-line", type=int, help="1-based line of the token in a shared keys file")
        command.add_argument("--chat-id", type=int, required=True)
        command.add_argument("--owner-user-id", type=int, required=True)
        command.add_argument("--log", type=Path, required=True)
        if name == "monitor":
            command.add_argument("--heartbeat", type=Path, required=True)
            command.add_argument("--host", default="kairos-host")
            command.add_argument("--stale-seconds", type=int, default=120)
            command.add_argument("--interval", type=float, default=5.0)
    facts = sub.add_parser("facts")
    facts.add_argument("--log", type=Path, required=True)
    facts.add_argument("--evidence-dir", type=Path, required=True)
    facts.add_argument("--out", type=Path, required=True)
    facts.add_argument("--owner-user-id", type=int, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "facts":
            built = alert_facts(AlertLog(args.log), args.evidence_dir, owner_user_id=args.owner_user_id)
            args.out.write_text(built.model_dump_json(indent=2), encoding="utf-8")
            print(f"facts written to {args.out}")
            return 0
        channel = TelegramChannel(
            args.token_file, args.chat_id, args.owner_user_id, token_line=args.token_line
        )
        log = AlertLog(args.log)
        if args.command == "test-message":
            bot = channel.identity()
            message = channel.send("Kairos: проверка канала оповещений", ack_data="ack:test")
            log.append({"type": "TEST", "bot_id": bot.get("id"), "message_id": message.get("message_id")})
            print(f"sent message {message.get('message_id')} as bot {bot.get('username')}")
            return 0
        monitor = Monitor(
            args.heartbeat, channel, log, args.host, stale_after=timedelta(seconds=args.stale_seconds)
        )
        monitor.start()
        print("monitor running; Ctrl+C stops it")
        while True:
            try:
                monitor.poll()
            except AlertError as exc:
                log.append({"type": "MONITOR_ERROR", "at": _now().isoformat(), "error": str(exc)})
            time.sleep(args.interval)
    except KeyboardInterrupt:
        return 130
    except (AlertError, OSError, ValueError) as exc:
        print(f"refused: {type(exc).__name__}: {str(exc)[:300]}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
