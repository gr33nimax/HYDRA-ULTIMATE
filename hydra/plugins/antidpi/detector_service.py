"""Plugin-facing orchestration for the pure AntiDPI detector."""

from __future__ import annotations

import ipaddress
import queue
import threading
from dataclasses import dataclass

from hydra.plugins.antidpi.detection import (
    Observation,
    is_enforcement_evidence,
    observe_state,
    record_automatic_ban,
)
from hydra.plugins.antidpi.model import (
    BAN_NOTIFICATION_COOLDOWN,
    get_ban_duration,
    record_ban_failure,
    track_notification,
)
from hydra.plugins.antidpi.state_store import (
    AntiDPIStateCorruptError,
    AntiDPIStateStore,
)


def _as_int(value: object, default: int = 0) -> int:
    """Return an integer from untrusted persisted state, or ``default``."""
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        try:
            return int(value)
        except (TypeError, ValueError, OverflowError):
            return default
    if isinstance(value, str):
        try:
            return int(value.strip())
        except (TypeError, ValueError):
            return default
    return default


def _as_float(value: object, default: float = 0.0) -> float:
    """Return a float from untrusted input, or ``default``."""
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        try:
            return float(value)
        except (TypeError, ValueError, OverflowError):
            return default
    if isinstance(value, str):
        try:
            return float(value.strip())
        except (TypeError, ValueError):
            return default
    return default


def _duration_label(duration: int) -> str:
    if duration < 3600:
        return f"{duration // 60}m"
    if duration < 86400:
        return f"{duration // 3600}h"
    return f"{duration // 86400}d"


@dataclass(frozen=True)
class _PendingNotice:
    """One notification decided under the state lock, delivered outside it."""

    kind: str  # "ban" — discarded input never notifies
    observation: Observation
    metadata: dict | None = None


def _evidence_fields(observation: Observation) -> list[tuple[str, object]]:
    """Render the bounded, secret-free evidence behind one ban."""
    event = observation.event
    fields: list[tuple[str, object]] = [
        ("Event", str(event.get("kind", "anomaly"))),
        ("Protocol", str(event.get("protocol", "L4"))),
        ("Reason", str(event.get("reason", ""))),
        ("Source", observation.source),
        ("Attribution", str(event.get("attribution", ""))),
    ]
    path = str(event.get("path", ""))
    if path:
        fields.append(("Path", path[:120]))
    return fields


class AntiDPIDetectorMixin:
    """Coordinate state, firewall, and notifications around pure decisions."""

    def _init_notification_delivery(self) -> None:
        self._notification_queue: queue.Queue = queue.Queue(maxsize=256)
        self._notification_worker: threading.Thread | None = None
        self._notification_worker_lock = threading.Lock()

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
                        *_evidence_fields(observation),
                        ("TTL", _duration_label(metadata["duration"])),
                        ("Offense", metadata["offense_count"]),
                    ],
                    category="antidpi",
                ),
            )
        except Exception:
            return False

    def _deliver_notice(self, notice: _PendingNotice) -> bool:
        return self._notify_ban(
            notice.observation,
            notice.metadata or {},
        )

    def _ban_notice_due(self, store: AntiDPIStateStore, timestamp: float) -> bool:
        """Apply the ban-notice cooldown in its own short transaction."""
        with self._state_lock():
            data = store.load()
            last_notice = _as_float(data.get("last_ban_notification_at", 0))
            if timestamp - last_notice < BAN_NOTIFICATION_COOLDOWN:
                data["suppressed_ban_notifications"] = (
                    _as_int(
                        data.get("suppressed_ban_notifications", 0),
                    )
                    + 1
                )
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

    def _advance_cursor(self, store: AntiDPIStateStore, cursor: str) -> None:
        """Remember a discarded record without touching detection state."""
        try:
            with self._state_lock():
                data = store.load()
                if data.get("journal_cursor") == cursor:
                    return
                data["journal_cursor"] = cursor
                store.save(data)
        except (OSError, RuntimeError):
            # A cursor that cannot be stored only costs a replay, and the
            # duplicate is discarded again without side effects.
            return

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
                if isinstance(item, dict) and item.get("ip") == address and item.get("status") == "active":
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
        previous_count = _as_int(ban_counts.get(observation.address, 0)) if isinstance(ban_counts, dict) else 0
        duration = get_ban_duration(previous_count + 1)
        remaining = _as_int(duration - max(0.0, observation.enforced_at - observation.timestamp))
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
        """Enforce only proven AntiScan evidence; discard everything else."""
        normalized_event = dict(event) if isinstance(event, dict) else {}
        journal_cursor = str(normalized_event.pop("_journal_cursor", ""))[:4096]
        store = self._state_store()
        if not is_enforcement_evidence(normalized_event):
            # The record carries no proven protocol reject or decoy scan.  It
            # must not create state, a firewall call or a Telegram message;
            # only the journal cursor is advanced so it is not replayed.
            if journal_cursor:
                self._advance_cursor(store, journal_cursor)
            return False
        try:
            parsed_address = ipaddress.ip_address(str(ip).strip("[]"))
        except ValueError:
            return False
        enforced_at = self._clock() if now is None else _as_float(now)
        timestamp = enforced_at if event_time is None else _as_float(event_time)
        if timestamp <= 0 or timestamp > enforced_at + 5:
            timestamp = enforced_at
        try:
            with self._state_lock():
                data = store.load()
                if journal_cursor and data.get("journal_cursor") == journal_cursor:
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
