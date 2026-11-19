"""Synthetic Telegram artifacts for the pinned-owner single-host V2 contract."""

from datetime import datetime, timedelta

from kairos_execution.signed_evidence import (
    SINGLE_HOST_REQUIRED_ALERT_NAMES,
    SingleHostAlertFactsV2,
    TelegramAcknowledgementV2,
    canonical_bytes,
)


def synthetic_alert_facts(now: datetime, store) -> SingleHostAlertFactsV2:
    artifacts = []

    def keep(value):
        digest = store(canonical_bytes(value))
        if digest not in artifacts:
            artifacts.append(digest)
        return digest

    deliveries, receipts = [], {}
    for index, name in enumerate(SINGLE_HOST_REQUIRED_ALERT_NAMES):
        records = {}
        times = {}
        for state_index, state in enumerate(("FIRING", "RESOLVED")):
            at = now - timedelta(minutes=6 - index * 2 - state_index)
            event = {
                "version": "kairos.local-alert-event.v1",
                "alert_name": name,
                "state": state,
                "host": "synthetic-host",
                "observed_at": at.isoformat(),
                "detail": "SYNTHETIC TEST ONLY",
            }
            digest = keep(event)
            message = {
                "message_id": index * 2 + state_index + 1,
                "date": int(at.timestamp()),
                "chat": {"id": -1005},
                "text": "SYNTHETIC TEST ONLY",
            }
            records[state.lower()] = {
                "type": "DELIVERY",
                "sha256": digest,
                "message_id": message["message_id"],
                "chat_id": -1005,
                "owner_telegram_user_id": 5,
                "received_at": at.isoformat(),
                "answer_sha256": keep(message),
                "answer": message,
            }
            times[state] = at
        resolved = records["resolved"]
        callback = f"ack:{resolved['sha256'][:56]}"
        ack = TelegramAcknowledgementV2(
            event_sha256=resolved["sha256"],
            at=now,
            owner_telegram_user_id=5,
            chat_id=-1005,
            message_id=resolved["message_id"],
            callback_data=callback,
            query={
                "id": f"synthetic-q-{index}",
                "data": callback,
                "from": {"id": 5},
                "message": resolved["answer"],
            },
        )
        ack_hash = keep(ack.model_dump(mode="json"))
        receipts[name] = keep({"alert": name, **records})
        deliveries.append(
            dict(
                alert_name=name,
                firing_event_sha256=records["firing"]["sha256"],
                resolved_event_sha256=resolved["sha256"],
                receiver_identity="telegram-chat--1005",
                firing_received_at=times["FIRING"],
                resolved_received_at=times["RESOLVED"],
                owner_acknowledged_at=now,
                owner_telegram_user_id=5,
                telegram_chat_id=-1005,
                resolved_message_id=resolved["message_id"],
                callback_data=callback,
                acknowledgement_sha256=ack_hash,
                delivery_receipt_sha256=receipts[name],
            )
        )
    notifier = keep(
        {
            "notifier_starts": [
                {
                    "type": "NOTIFIER_START",
                    "owner_telegram_user_id": 5,
                    "chat_id": -1005,
                    "at": (now - timedelta(minutes=10)).isoformat(),
                    "bot_id": 77,
                    "host": "synthetic-host",
                },
                {
                    "type": "NOTIFIER_START",
                    "owner_telegram_user_id": 5,
                    "chat_id": -1005,
                    "at": now.isoformat(),
                    "bot_id": 77,
                    "host": "synthetic-host",
                },
            ]
        }
    )
    return SingleHostAlertFactsV2(
        artifact_sha256s=tuple(artifacts),
        owner_telegram_user_id=5,
        required_alert_names=SINGLE_HOST_REQUIRED_ALERT_NAMES,
        deliveries=tuple(deliveries),
        notifier_restart_receipt_sha256=notifier,
        local_supervisor_identity="synthetic-supervisor",
        local_supervisor_restart_receipt_sha256=receipts["local-supervisor-restart"],
        local_health_check_receipt_sha256=receipts["local-process-health"],
        unknown_sends=0,
    )
