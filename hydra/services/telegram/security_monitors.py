"""Security log event parsing and polling workers."""
from __future__ import annotations

import ipaddress
import re
import threading
from collections.abc import Mapping
from typing import Callable

from hydra.services.application import ApplicationService
from hydra.services.security_notifications import (
    format_security_event,
    send_admin_notification,
)


NotificationSender = Callable[..., bool]

def _mapping_projection(value: object) -> dict:
    return dict(value) if isinstance(value, Mapping) else {}

def _process_fail2ban_log_line(
    line: str,
    *,
    notify: NotificationSender = send_admin_notification,
) -> None:
    match = re.search(
        r"NOTICE\s+\[(?P<jail>[^\]]+)\]\s+"
        r"(?P<action>Ban|Unban)\s+(?P<ip>\S+)",
        line,
    )
    if not match:
        return
    jail = match.group("jail")
    action = match.group("action")
    address = match.group("ip")

    fields = [("IP", address)]
    if action == "Ban":
        from hydra.services.security_intel import notification_fields

        fields.extend(notification_fields(address))
    fields.append(("Jail", jail))
    category = "fail2ban" if action == "Ban" else "fail2ban_unban"
    notify(
        format_security_event("Fail2ban", action, fields),
        category=category,
        action=action,
    )

def _process_honeypot_log_line(
    line: str,
    app: ApplicationService,
    *,
    notify: NotificationSender = send_admin_notification,
) -> None:
    match = re.search(
        r"^\[(?P<when>[^]]+)]\s+BAN\s+(?P<ip>\S+)\s+"
        r"backend=(?P<backend>\S+)\s+result=OK",
        str(line).strip(),
    )
    if not match:
        return
    try:
        address = ipaddress.ip_address(
            match.group("ip").strip("[]"),
        ).compressed
    except ValueError:
        return
    try:
        trap_port = _mapping_projection(
            app.plugin_query("honeypot", "management_snapshot"),
        ).get("port", "—")
    except Exception:
        trap_port = "—"
    from hydra.services.security_intel import notification_fields

    notify(
        format_security_event(
            "Honeypot",
            "BAN",
            [
                ("IP", address),
                *notification_fields(address),
                ("Port", f"{trap_port}/TCP"),
                ("Backend", match.group("backend")),
                ("Timestamp", match.group("when")),
            ],
        ),
        category="honeypot",
        action="BAN",
    )

def _projected_lines(value: object) -> list[str]:
    if not isinstance(value, list):
        raise TypeError("plugin log projection must be a list")
    return [str(line) for line in value]

def _log_overlap(previous: list[str], current: list[str]) -> int:
    """Find the retained suffix after a bounded log window advances."""
    for size in range(min(len(previous), len(current)), 0, -1):
        if previous[-size:] == current[:size]:
            return size
    return 0

IDLE_BACKOFF = (2.0, 5.0, 15.0)
BUSY_INTERVAL = 2.0
IDLE_CYCLES_BEFORE_BACKOFF = 5


def _poll_interval(idle_cycles: int) -> float:
    """Return how long to sleep after ``idle_cycles`` quiet polls."""
    step = min(
        len(IDLE_BACKOFF) - 1,
        max(0, idle_cycles // IDLE_CYCLES_BEFORE_BACKOFF),
    )
    return IDLE_BACKOFF[step]


def _follow_plugin_log(
    stop_event: threading.Event,
    fetch: Callable[[], object],
    process: Callable[[str], None],
) -> None:
    """Poll an allowlisted plugin projection without exposing its log path.

    Each poll spawns a journal read, so a quiet host backs off instead of
    running two subprocesses per second forever. Any new line resets the
    cadence, keeping reaction time short exactly when something is happening.
    """
    previous: list[str] | None = None
    idle_cycles = 0
    while not stop_event.is_set():
        try:
            current = _projected_lines(fetch())
        except Exception:
            stop_event.wait(_poll_interval(idle_cycles))
            idle_cycles += 1
            continue
        if previous is None:
            previous = current
        elif current != previous:
            overlap = _log_overlap(previous, current)
            for line in current[overlap:]:
                process(line)
            previous = current
            idle_cycles = 0
            stop_event.wait(BUSY_INTERVAL)
            continue
        idle_cycles += 1
        stop_event.wait(_poll_interval(idle_cycles))

def _fail2ban_monitor_worker(
    stop_event: threading.Event,
    app: ApplicationService,
    *,
    notify: NotificationSender = send_admin_notification,
) -> None:
    _follow_plugin_log(
        stop_event,
        lambda: app.plugin_query("fail2ban", "recent_logs", limit=500),
        lambda line: _process_fail2ban_log_line(line, notify=notify),
    )

def _honeypot_monitor_worker(
    stop_event: threading.Event,
    app: ApplicationService,
    *,
    notify: NotificationSender = send_admin_notification,
) -> None:
    _follow_plugin_log(
        stop_event,
        lambda: app.plugin_query("honeypot", "recent_logs", limit=200),
        lambda line: _process_honeypot_log_line(
            line,
            app,
            notify=notify,
        ),
    )
