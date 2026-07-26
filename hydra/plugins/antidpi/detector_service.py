"""Plugin-facing orchestration for the pure AntiDPI detector."""
from __future__ import annotations

import ipaddress

from hydra.plugins.antidpi.detection import (
    Observation,
    observe_state,
    record_automatic_ban,
)
from hydra.plugins.antidpi.model import (
    BAN_NOTIFICATION_COOLDOWN,
    format_score,
    get_ban_duration,
    track_notification,
)


def _duration_label(duration: int) -> str:
    if duration < 3600:
        return f"{duration // 60}m"
    if duration < 86400:
        return f"{duration // 3600}h"
    return f"{duration // 86400}d"


class AntiDPIDetectorMixin:
    """Coordinate state, firewall, and notifications around pure decisions."""

    def _alert_fields(self, observation: Observation) -> list[tuple[str, object]]:
        event = observation.event
        fields = [
            ("IP", observation.address),
            *self._security_context(observation.address),
            ("Event", str(event.get("kind", event.get("reason", "anomaly")))),
            ("Protocol", str(event.get("protocol", "L4"))),
            ("Source", observation.source),
            ("Signals", ", ".join(observation.signals)),
            ("Score", format_score(observation.entry["score"])),
        ]
        if not observation.evidence_can_ban:
            fields.append(
                (
                    "Policy",
                    str(
                        event.get(
                            "policy",
                            "alert-only / unverified UDP source",
                        ),
                    ),
                ),
            )
        if (
            observation.entry["verified_score"]
            != observation.entry["score"]
        ):
            fields.append(
                (
                    "Verified score",
                    format_score(observation.entry["verified_score"]),
                ),
            )
        return fields

    def _notify_alert(self, observation: Observation) -> bool:
        try:
            return bool(
                self._notify_security_event(
                    "AntiDPI",
                    "ALERT",
                    self._alert_fields(observation),
                    category="antidpi",
                    reply_markup={
                        "inline_keyboard": [
                            [
                                {
                                    "text": "🚫 Заблокировать",
                                    "callback_data": (
                                        f"antidpi-ban:{observation.address}"
                                    ),
                                },
                            ],
                        ],
                    },
                ),
            )
        except Exception:
            return False

    def _notify_ban(
        self,
        observation: Observation,
        metadata: dict,
    ) -> bool:
        try:
            return bool(
                self._notify_security_event(
                    "AntiDPI",
                    "BAN",
                    [
                        ("IP", observation.address),
                        *self._security_context(observation.address),
                        (
                            "Event",
                            observation.event.get("kind", "anomaly"),
                        ),
                        (
                            "Protocol",
                            observation.event.get("protocol", "L4"),
                        ),
                        ("Source", observation.source),
                        (
                            "Signals",
                            ", ".join(
                                str(value)
                                for value in observation.entry["signals"]
                            ),
                        ),
                        ("Score", format_score(observation.entry["score"])),
                        ("TTL", _duration_label(metadata["duration"])),
                        ("Offense", metadata["offense_count"]),
                    ],
                    category="antidpi",
                ),
            )
        except Exception:
            return False

    def _record_alert(self, data: dict, observation: Observation) -> None:
        delivered = self._notify_alert(observation)
        track_notification(
            data,
            delivered,
            now=observation.timestamp,
        )

    def _record_ban_notice(
        self,
        data: dict,
        observation: Observation,
        metadata: dict,
    ) -> None:
        timestamp = observation.timestamp
        last_notice = float(data.get("last_ban_notification_at", 0) or 0)
        if timestamp - last_notice < BAN_NOTIFICATION_COOLDOWN:
            data["suppressed_ban_notifications"] = int(
                data.get("suppressed_ban_notifications", 0),
            ) + 1
            return
        data["last_ban_notification_at"] = timestamp
        delivered = self._notify_ban(observation, metadata)
        track_notification(data, delivered, now=timestamp)

    def observe_event(
        self,
        ip: str,
        event: dict,
        *,
        now: float | None = None,
    ) -> bool:
        """Record one event and enforce only the pure model's ban decision."""
        try:
            parsed_address = ipaddress.ip_address(str(ip).strip("[]"))
        except ValueError:
            return False
        normalized_event = dict(event) if isinstance(event, dict) else {}
        if normalized_event.get("source") == "kernel-udp-probe":
            return False
        timestamp = self._clock() if now is None else now
        store = self._state_store()
        with self._state_lock():
            data = store.load()
            if self._is_whitelisted(parsed_address, data):
                return False
            observation = observe_state(
                data,
                parsed_address,
                normalized_event,
                timestamp=timestamp,
                max_score_entries=self._max_score_entries(),
            )
            if observation.should_alert:
                self._record_alert(data, observation)
            if observation.active_ban:
                store.save(data)
                return True
            banned = False
            if observation.should_ban:
                ban_counts = data.get("ban_counts", {})
                previous_count = (
                    int(ban_counts.get(observation.address, 0))
                    if isinstance(ban_counts, dict)
                    else 0
                )
                duration = get_ban_duration(previous_count + 1)
                if self._add_firewall_ban(
                    observation.ip,
                    duration=duration,
                ):
                    metadata = record_automatic_ban(data, observation)
                    self._record_ban_notice(data, observation, metadata)
                    banned = True
            store.save(data)
            return banned

