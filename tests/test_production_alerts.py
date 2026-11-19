"""Heartbeat monitor -> Telegram (synthetic) -> facts -> signed ALERT_DELIVERY receipt."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from kairos_execution.production_alerts import (
    HEALTH,
    RESTART,
    AlertError,
    AlertLog,
    Monitor,
    TelegramChannel,
    alert_facts,
)
from kairos_execution.production_owner import freeze_policy, generate_issuer, issue_receipt
from kairos_execution.production_readiness import EvidenceKind
from kairos_execution.signed_evidence import DirectoryEvidenceResolver, SingleHostAlertReceiptInterpreter
from tests.test_production_owner import NOW, _context, _frozen


class FakeTelegram:
    """Answers like the Bot API; the token never leaves the URL it receives."""

    def __init__(self, clock):
        self.clock = clock
        self.sent: list[dict] = []
        self.presses: list[dict] = []
        self.urls: list[str] = []
        self._update = 0

    def __call__(self, url, payload):
        self.urls.append(url)
        method = url.rsplit("/", 1)[1]
        if method == "getMe":
            return {"ok": True, "result": {"id": 77, "username": "kairos_alert_bot"}}
        if method == "sendMessage":
            message = {
                "message_id": len(self.sent) + 1,
                "date": int(self.clock().timestamp()),
                "chat": {"id": payload["chat_id"]},
                "text": payload["text"],
            }
            self.sent.append(
                {**message, "ack": payload["reply_markup"]["inline_keyboard"][0][0]["callback_data"]}
            )
            return {"ok": True, "result": message}
        if method == "getUpdates":
            updates = [u for u in self.presses if u["update_id"] >= payload["offset"]]
            return {"ok": True, "result": updates}
        if method == "answerCallbackQuery":
            return {"ok": True, "result": True}
        raise AssertionError(method)

    def press(self, message_index: int, user_id: int = 5) -> None:
        self._update += 1
        data = self.sent[message_index]["ack"]
        self.presses.append(
            {
                "update_id": self._update,
                "callback_query": {
                    "id": f"q{self._update}",
                    "data": data,
                    "from": {"id": user_id},
                    "message": {k: v for k, v in self.sent[message_index].items() if k != "ack"},
                },
            }
        )


class Clock:
    def __init__(self, now=NOW):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


def _beat(path, clock, pid, started):
    path.write_text(
        json.dumps({"pid": pid, "started_at": started, "at": clock().isoformat()}), encoding="utf-8"
    )


SYNTHETIC_CHAT_ID = -1005


def _drill(tmp_path, *, now=NOW, chat_id=SYNTHETIC_CHAT_ID):
    clock = Clock(now)
    telegram = FakeTelegram(clock)
    token = tmp_path / "bot.token"
    token.write_text("123456:SYNTHETIC-TOKEN-abcdefghijklmnopqrstuvwxyz", encoding="utf-8")
    channel = TelegramChannel(token, chat_id, 5, http=telegram)
    log = AlertLog(tmp_path / "alerts.jsonl")
    heartbeat = tmp_path / "heartbeat.json"
    monitor = Monitor(heartbeat, channel, log, "kairos-host", clock=clock)
    monitor.start()
    _beat(heartbeat, clock, 100, "a")
    monitor.poll()  # healthy, first process seen
    clock.advance(200)  # the runner hangs: the heartbeat goes stale
    monitor.poll()
    assert [m["text"].split(":")[0] for m in telegram.sent] == ["ТРЕВОГА"]
    clock.advance(30)
    _beat(heartbeat, clock, 200, "b")  # the supervisor started a new process
    monitor.poll()  # health resolves, restart fires
    clock.advance(5)
    _beat(heartbeat, clock, 200, "b")
    monitor.poll()  # restart resolves
    names = [(m["text"].split("\n")[0]) for m in telegram.sent]
    assert names == [
        f"ТРЕВОГА: {HEALTH}",
        f"ВОССТАНОВЛЕНО: {HEALTH}",
        f"ТРЕВОГА: {RESTART}",
        f"ВОССТАНОВЛЕНО: {RESTART}",
    ]
    clock.advance(20)
    telegram.press(1)
    telegram.press(3)
    monitor.poll()
    monitor = Monitor(heartbeat, channel, log, "kairos-host", clock=clock)
    monitor.start()  # the notifier restart
    return log, telegram


def test_monitor_alerts_resolve_and_are_acknowledged_in_order(tmp_path):
    log, telegram = _drill(tmp_path)
    types = [record["type"] for record in log.records()]
    assert types.count("EVENT") == types.count("DELIVERY") == 4
    assert types.count("ACK") == 2 and types.count("NOTIFIER_START") == 2
    assert "SYNTHETIC-TOKEN" not in (tmp_path / "alerts.jsonl").read_text(encoding="utf-8")


def test_other_group_member_cannot_acknowledge_an_alert(tmp_path):
    clock = Clock()
    telegram = FakeTelegram(clock)
    token = tmp_path / "bot.token"
    token.write_text("123456:SYNTHETIC-TOKEN-abcdefghijklmnopqrstuvwxyz", encoding="utf-8")
    channel = TelegramChannel(token, SYNTHETIC_CHAT_ID, 5, http=telegram)
    log = AlertLog(tmp_path / "alerts.jsonl")
    monitor = Monitor(tmp_path / "missing-heartbeat", channel, log, "host", clock=clock)
    monitor.start()
    monitor.poll()
    telegram.press(0, user_id=999)
    monitor.poll()
    assert not [r for r in log.records() if r["type"] == "ACK"]


def test_prefix_only_ack_cannot_make_owner_acknowledged_facts(tmp_path):
    log, _ = _drill(tmp_path)
    changed = AlertLog(tmp_path / "prefix.jsonl")
    for record in log.records():
        if record["type"] == "ACK":
            record["prefix"] = ""
        changed.append(record)
    with pytest.raises(AlertError):
        alert_facts(changed, tmp_path / "prefix-evidence", owner_user_id=5)


@pytest.mark.parametrize(
    "mutation",
    [
        "sender",
        "sender-type",
        "missing-sender",
        "chat",
        "message",
        "missing-message",
        "empty-token",
        "short-token",
        "other-token",
    ],
)
def test_callback_ingest_requires_exact_owner_message_and_token(tmp_path, mutation):
    clock = Clock()
    telegram = FakeTelegram(clock)
    token = tmp_path / "bot.token"
    token.write_text(TOKEN, encoding="utf-8")
    channel = TelegramChannel(token, -1005, 5, http=telegram)
    log = AlertLog(tmp_path / "alerts.jsonl")
    monitor = Monitor(tmp_path / "missing-heartbeat", channel, log, "host", clock=clock)
    monitor.start()
    monitor.poll()
    telegram.press(0)
    query = telegram.presses[-1]["callback_query"]
    if mutation == "sender":
        query["from"]["id"] = 99
    elif mutation == "sender-type":
        query["from"]["id"] = "5"
    elif mutation == "missing-sender":
        query.pop("from")
    elif mutation == "chat":
        query["message"]["chat"] = {"id": -999}
    elif mutation == "message":
        query["message"]["message_id"] = 99
    elif mutation == "missing-message":
        query.pop("message")
    else:
        invalid = {"empty-token": "ack:", "short-token": "ack:a", "other-token": "ack:" + "a" * 56}
        query["data"] = invalid[mutation]
    monitor.poll()
    assert not [r for r in log.records() if r["type"] == "ACK"]
    telegram.press(0)
    monitor.poll()
    assert len([r for r in log.records() if r["type"] == "ACK"]) == 1


@pytest.mark.parametrize("chat_id", [5, -1005])
def test_private_and_group_chats_accept_only_the_pinned_owner(tmp_path, chat_id):
    log, _ = _drill(tmp_path, chat_id=chat_id)
    facts = alert_facts(log, tmp_path / "evidence", owner_user_id=5)
    assert facts.owner_telegram_user_id == 5
    assert all(d.telegram_chat_id == chat_id for d in facts.deliveries)


@pytest.mark.parametrize("owner_user_id", [0, -5, True, "5", None])
def test_owner_pin_must_be_a_positive_integer(tmp_path, owner_user_id):
    with pytest.raises(AlertError, match="positive"):
        TelegramChannel(tmp_path / "unread.token", -1005, owner_user_id)


@pytest.mark.parametrize("mutation", ["sender", "chat", "message", "token", "legacy", "delivery"])
def test_facts_recheck_raw_owner_ack_and_delivery_binding(tmp_path, mutation):
    log, _ = _drill(tmp_path)
    changed = AlertLog(tmp_path / "changed.jsonl")
    for record in log.records():
        if record["type"] == "ACK":
            if mutation == "sender":
                record["query"]["from"]["id"] = 99
            elif mutation == "chat":
                record["query"]["message"]["chat"]["id"] = -999
            elif mutation == "message":
                record["query"]["message"]["message_id"] = 99
            elif mutation == "token":
                record["query"]["data"] = "ack:"
            elif mutation == "legacy":
                record = {"type": "ACK", "prefix": "", "user_id": 5, "at": record["at"]}
        elif record["type"] == "DELIVERY" and mutation == "delivery":
            record["answer"]["chat"]["id"] = -999
        changed.append(record)
    with pytest.raises(AlertError):
        alert_facts(changed, tmp_path / "changed-evidence", owner_user_id=5)


def test_drill_facts_become_a_receipt_the_single_host_interpreter_accepts(tmp_path):
    log, _telegram = _drill(tmp_path)
    evidence = tmp_path / "evidence"
    frozen = _frozen().model_copy(update={"owner_telegram_user_id": 5})
    context = _context(evidence).model_copy(update={"frozen_policy_sha256": freeze_policy(evidence, frozen)})
    facts = alert_facts(log, evidence, owner_user_id=5)
    assert {d.alert_name for d in facts.deliveries} == {HEALTH, RESTART}
    assert all(
        d.firing_received_at < d.resolved_received_at <= d.owner_acknowledged_at for d in facts.deliveries
    )
    assert facts.host_loss_resilience == "NOT_ESTABLISHED"
    policy = generate_issuer(
        tmp_path / "issuer",
        issuer_id="owner-1",
        frozen=frozen,
        context=context,
        allowed_kinds=[EvidenceKind.ALERT_DELIVERY],
        valid_from=NOW - timedelta(hours=1),
        valid_until=NOW + timedelta(days=30),
    )
    reference = issue_receipt(
        tmp_path / "issuer" / "evidence-issuer.ed25519",
        policy,
        kind=EvidenceKind.ALERT_DELIVERY,
        facts=facts,
        evidence_dir=evidence,
        issued_at=NOW + timedelta(minutes=10),
    )
    verified = SingleHostAlertReceiptInterpreter((policy,), DirectoryEvidenceResolver(evidence)).verify(
        reference, context
    )
    assert verified.outcome == "SEALED_PASS"


def test_facts_refuse_without_acknowledgement_restart_or_with_unknown_sends(tmp_path):
    log, _ = _drill(tmp_path)
    records = log.records()
    no_ack = AlertLog(tmp_path / "no-ack.jsonl")
    for record in records:
        if record["type"] != "ACK":
            no_ack.append(record)
    with pytest.raises(AlertError, match="no acknowledged"):
        alert_facts(no_ack, tmp_path / "e1", owner_user_id=5)
    one_start = AlertLog(tmp_path / "one-start.jsonl")
    seen = False
    for record in records:
        if record["type"] == "NOTIFIER_START":
            if seen:
                continue
            seen = True
        one_start.append(record)
    with pytest.raises(AlertError, match="restart"):
        alert_facts(one_start, tmp_path / "e2", owner_user_id=5)
    log.append({"type": "UNKNOWN_SEND", "sha256": "0" * 64, "error": "Telegram is unreachable"})
    with pytest.raises(AlertError, match="unknown outcome"):
        alert_facts(log, tmp_path / "e3", owner_user_id=5)


def test_a_bad_token_file_is_refused_without_echoing_it(tmp_path):
    token = tmp_path / "bot.token"
    token.write_text("not a token/with slash", encoding="utf-8")
    channel = TelegramChannel(token, 1, 5, http=lambda url, payload: {"ok": True, "result": {}})
    with pytest.raises(AlertError) as raised:
        channel.identity()
    assert "slash" not in str(raised.value)
    assert datetime.now(UTC) > NOW - timedelta(days=36_500)


TOKEN = "123456789:AAH-synthetic_bot_token_abcdefghijkl0123"


def test_the_token_is_found_in_a_shared_keys_file_without_using_other_lines(tmp_path):
    keys = tmp_path / "keys.txt"
    lines = ["wallet: not-a-token", "", f"telegram bot: {TOKEN}", "api-key-xyz", ""]
    keys.write_text("\n".join(lines), encoding="utf-8")
    urls: list[str] = []

    def http(url, payload):
        urls.append(url)
        return {"ok": True, "result": {}}

    TelegramChannel(keys, 1, 5, http=http).identity()
    assert urls == [f"https://api.telegram.org/bot{TOKEN}/getMe"]
    assert TelegramChannel(keys, 1, 5, http=http, token_line=3)._token() == TOKEN
    with pytest.raises(AlertError, match="exactly one"):
        TelegramChannel(keys, 1, 5, http=http, token_line=1).identity()
    other = TOKEN.replace("123456789", "222222222")
    keys.write_text("\n".join(["1:short", TOKEN, other]), encoding="utf-8")
    with pytest.raises(AlertError, match="exactly one") as raised:
        TelegramChannel(keys, 1, 5, http=http).identity()
    assert "synthetic" not in str(raised.value)
