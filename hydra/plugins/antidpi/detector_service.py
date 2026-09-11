"""Plugin-facing orchestration for the pure AntiDPI detector."""
from __future__ import annotations

import ipaddress
import queue
import threading
from dataclasses import dataclass

from hydra.plugins.antidpi.detection import (
    Observation,
    observe_state,
    record_automatic_ban,
)
from hydra.plugins.antidpi.model import (
    BAN_NOTIFICATION_COOLDOWN,
    format_score,
    get_ban_duration,
    record_ban_failure,
    track_notification,
)
from hydra.plugins.antidpi.state_store import (
    AntiDPIStateCorruptError,
    AntiDPIStateStore,
)


def _duration_label(duration: int) -> str:
    if duration < 3600:
        return f"{duration // 60}m"
    if duration < 86400:
        return f"{duration // 3600}h"
    return f"{duration // 86400}d"


@dataclass(frozen=True)
class _PendingNotice:
    """One notification decided under the state lock, delivered outside it."""

    kind: str  # "alert" | "coordination" | "ban"
    observation: Observation
    metadata: dict | None = None


class AntiDPIDetectorMixin:
    """Coordinate state, firewall, and notifications around pure decisions."""

    def _init_notification_delivery(self) -> None:
        self._notification_queue: queue.Queue = queue.Queue(maxsize=256)
        self._notification_worker: threading.Thread | None = None
        self._notification_worker_lock = threading.Lock()

    def _alert_fields(self, observation: Observation) -> list[tuple[str, object]]:
        event = observation.event
        fields = [
            ("IP", observation.address),
            *self._security_context(observation.address),
            ("Event", str(event.get("kind", event.get("reason", "anomaly")))),
            ("Protocol", str(event.get("protocol", "L4"))),
            ("Source", observation.source),
            ("Signals", ", ".join(observation.signals)),
            (
                "Score",
                format_score(
                    observation.entry["score"],
                    threshold=observation.required_score,
                ),
            ),
        ]
        if observation.families:
            fields.append(("Evidence", ", ".join(observation.families)))
        if observation.block_reason == "single_family":
            fields.append(
                (
                    "Policy",
                    "alert-only / улики одного типа, для бана нужен "
                    "второй независимый признак",
                ),
            )
        if observation.coordinated:
            fields.append(
                (
                    "Coordinated",
                    f"{observation.coordinated.get('prefix', '—')} "
                    f"({observation.coordinated.get('members', 0)} адресов)",
                ),
            )
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

    def _notify_coordination(self, observation: Observation) -> bool:
        report = observation.coordinated
        try:
            return bool(
                self._notify_security_event(
                    "AntiDPI",
                    "COORDINATED",
                    [
                        ("Subnet", report.get("prefix", "—")),
                        ("Addresses", report.get("members", 0)),
                        (
                            "Seen",
                            ", ".join(report.get("addresses", ())[:5]),
                        ),
                        ("Window", "10m"),
                        (
                            "Policy",
                            "alert-only / распределённое сканирование, "
                            "адреса банятся только по собственным уликам",
                        ),
                    ],
                    category="antidpi",
                ),
            )
        except Exception:
            return False

    def _deliver_notice(self, notice: _PendingNotice) -> bool:
        if notice.kind == "alert":
            return self._notify_alert(notice.observation)
        if notice.kind == "coordination":
            return self._notify_coordination(notice.observation)
        return self._notify_ban(
            notice.observation,
            notice.metadata or {},
        )

    def _ban_notice_due(self, store: AntiDPIStateStore, timestamp: float) -> bool:
        """Apply the ban-notice cooldown in its own short transaction."""
        with self._state_lock():
            data = store.load()
            last_notice = float(data.get("last_ban_notification_at", 0) or 0)
            if timestamp - last_notice < BAN_NOTIFICATION_COOLDOWN:
                data["suppressed_ban_notifications"] = int(
                    data.get("suppressed_ban_notifications", 0),
                ) + 1
                store.save(data)
                return False
            data["last_ban_notification_at"] = timestamp
            store.save(data)
            return True

    def _deliver_notices(
        self,
        store: AntiDPIStateStore,
        notices: list[_PendingNotice],
    ) -> None:
        """Queue notifications without waiting on the Telegram network."""
        for notice in notices:
            if notice.kind == "ban" and not self._ban_notice_due(
                store,
                notice.observation.enforced_at,
            ):
                continue
            self._ensure_notification_worker()
            try:
                self._notification_queue.put_nowait((store, notice))
            except queue.Full:
                self._record_notification_result(
                    store,
                    delivered=False,
                    timestamp=notice.observation.enforced_at,
                    dropped=True,
                )

    def _ensure_notification_worker(self) -> None:
        with self._notification_worker_lock:
            worker = self._notification_worker
            if worker is not None and worker.is_alive():
                return
            self._notification_worker = threading.Thread(
                target=self._notification_loop,
                name="hydra-antidpi-notifications",
                daemon=True,
            )
            self._notification_worker.start()

    def _notification_loop(self) -> None:
        while True:
            store, notice = self._notification_queue.get()
            try:
                self._record_notification_result(
                    store,
                    delivered=self._deliver_notice(notice),
                    timestamp=notice.observation.enforced_at,
                )
            finally:
                self._notification_queue.task_done()

    def _record_notification_result(
        self,
        store: AntiDPIStateStore,
        *,
        delivered: bool,
        timestamp: float,
        dropped: bool = False,
    ) -> None:
        try:
            with self._state_lock():
                data = store.load()
                track_notification(data, delivered, now=timestamp)
                if dropped:
                    stats = data.setdefault("notification_stats", {})
                    stats["dropped"] = int(stats.get("dropped", 0) or 0) + 1
                store.save(data)
        except (OSError, RuntimeError):
            pass

    def _drain_notifications(self) -> None:
        """Wait for queued delivery in deterministic unit tests."""
        self._notification_queue.join()

    def _revert_ban_intent(
        self,
        data: dict,
        address: str,
        *,
        now: float,
    ) -> None:
        """Undo a recorded ban whose firewall enforcement failed."""
        banned = data.get("banned", {})
        if isinstance(banned, dict):
            banned.pop(address, None)
        counts = data.get("ban_counts", {})
        if isinstance(counts, dict):
            try:
                counts[address] = max(0, int(counts.get(address, 0)) - 1)
            except (TypeError, ValueError):
                pass
        history = data.get("history", [])
        if isinstance(history, list):
            for item in reversed(history):
                if (
                    isinstance(item, dict)
                    and item.get("ip") == address
                    and item.get("status") == "active"
                ):
                    item["status"] = "failed"
                    item["failed_at"] = now
                    break

    def _enforce_ban(
        self,
        store: AntiDPIStateStore,
        data: dict,
        observation: Observation,
    ) -> tuple[bool, _PendingNotice | None]:
        """Persist the ban intent before touching the firewall.

        If the process dies after the intent save, startup reconciliation
        re-applies the ban; if the firewall refuses, the intent is reverted
        so state and ipset never disagree about the address.
        """
        ban_counts = data.get("ban_counts", {})
        previous_count = (
            int(ban_counts.get(observation.address, 0))
            if isinstance(ban_counts, dict)
            else 0
        )
        duration = get_ban_duration(previous_count + 1)
        remaining = int(
            duration
            - max(0.0, observation.enforced_at - observation.timestamp)
        )
        if remaining <= 0:
            store.save(data)
            return False, None
        metadata = record_automatic_ban(
            data,
            observation,
            duration=remaining,
        )
        store.save(data)
        if not self._add_firewall_ban(
            observation.ip,
            duration=remaining,
        ):
            self._revert_ban_intent(
                data,
                observation.address,
                now=observation.enforced_at,
            )
            record_ban_failure(
                data,
                observation.address,
                now=observation.enforced_at,
            )
            store.save(data)
            return False, None
        return True, _PendingNotice("ban", observation, metadata)

    def observe_event(
        self,
        ip: str,
        event: dict,
        *,
        now: float | None = None,
        event_time: float | None = None,
    ) -> bool:
        """Record one event and enforce only the pure model's ban decision."""
        try:
            parsed_address = ipaddress.ip_address(str(ip).strip("[]"))
        except ValueError:
            return False
        normalized_event = dict(event) if isinstance(event, dict) else {}
        enforced_at = self._clock() if now is None else float(now)
        timestamp = enforced_at if event_time is None else float(event_time)
        if timestamp <= 0 or timestamp > enforced_at + 5:
            timestamp = enforced_at
        journal_cursor = str(normalized_event.pop("_journal_cursor", ""))[:4096]
        store = self._state_store()
        try:
            with self._state_lock():
                data = store.load()
                if journal_cursor and data.get("journal_cursor") == journal_cursor:
                    return False
                if normalized_event.get("source") == "kernel-udp-probe":
                    if journal_cursor:
                        data["journal_cursor"] = journal_cursor
                        store.save(data)
                    return False
                if self._is_whitelisted(parsed_address, data):
                    if journal_cursor:
                        data["journal_cursor"] = journal_cursor
                        store.save(data)
                    return False
                observation = observe_state(
                    data,
                    parsed_address,
                    normalized_event,
                    timestamp=timestamp,
                    enforcement_time=enforced_at,
                    max_score_entries=self._max_score_entries(),
                )
                if journal_cursor:
                    data["journal_cursor"] = journal_cursor
                notices: list[_PendingNotice] = []
                if observation.should_alert:
                    notices.append(_PendingNotice("alert", observation))
                if observation.coordinated.get("first_report"):
                    notices.append(_PendingNotice("coordination", observation))
                if observation.active_ban:
                    store.save(data)
                    banned = True
                elif observation.should_ban:
                    banned, notice = self._enforce_ban(store, data, observation)
                    if notice is not None:
                        notices.append(notice)
                else:
                    store.save(data)
                    banned = False
        except AntiDPIStateCorruptError as exc:
            self._fail(str(exc))
            return False
        # Telegram delivery happens after the state transaction: a slow or
        # dead bot API must never stall evidence processing or admin actions.
        self._deliver_notices(store, notices)
        return banned
