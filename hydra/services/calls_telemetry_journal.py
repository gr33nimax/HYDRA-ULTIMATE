"""Categorize Calls journal events without retaining log text."""
from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any


_CATEGORIES = (
    ("udp listener stopped", "udp_listener_stopped"),
    ("authentication rejected", "auth_rejected"),
    ("global session limit reached", "global_session_limit"),
    ("user session limit reached", "user_session_limit"),
    ("pending handshake", "pending_handshake_limit"),
    ("duplicate active worker", "duplicate_worker"),
    ("stale worker epoch", "stale_worker_epoch"),
    ("worker limit reached", "worker_limit"),
    ("server session state was reset", "session_generation_reset"),
    ("native session reconnected", "native_session_reconnected"),
    ("reconnect failed", "native_session_reconnect_failed"),
    ("reconnecting after transport error", "worker_transport_reconnect"),
    ("network changed, rebinding", "client_network_rebind"),
    ("no vk turn worker connected", "worker_pool_connect_timeout"),
    ("vk calls path failed", "vk_auth_fallback"),
    ("captcha required", "vk_captcha"),
    ("all vk turn endpoints failed", "turn_all_endpoints_failed"),
    ("turn auth", "turn_auth_failed"),
    ("turn join", "turn_join_failed"),
    ("tunnel not initialized", "tunnel_init_failed"),
    ("context deadline exceeded", "operation_timeout"),
    ("relay: connect", "relay_tcp_connect"),
    ("read error", "relay_read_error"),
    ("open ", "relay_udp_open_error"),
    ("drop msg", "relay_unknown_connection_drop"),
)


def collect_calls_journal_events(
    host: Any,
    *,
    cursor: str,
    started_at: float,
) -> tuple[list[dict[str, object]], str, bool]:
    command = [
        "journalctl",
        "-u",
        "sing-box",
        "--output=json",
        "--no-pager",
        "--show-cursor",
        "-n",
        "2000",
    ]
    if cursor:
        command.append(f"--after-cursor={cursor}")
    else:
        command.append(f"--since=@{max(0, int(started_at))}")
    try:
        result = host.run(
            command,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception:
        return [], cursor, True
    if result.returncode != 0:
        return [], cursor, True
    events: list[dict[str, object]] = []
    latest_cursor = cursor
    for line in str(result.stdout or "").splitlines():
        if line.startswith("-- cursor: "):
            latest_cursor = line.removeprefix("-- cursor: ").strip() or latest_cursor
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, Mapping):
            continue
        raw_cursor = str(payload.get("__CURSOR", ""))
        if raw_cursor:
            latest_cursor = raw_cursor
        message = str(payload.get("MESSAGE", "")).casefold()
        if not any(token in message for token in ("call", "vk-auth", "relay")):
            continue
        code = _categorize(message)
        if code:
            events.append({
                "kind": "event",
                "timestamp": _journal_timestamp(payload, started_at),
                "source": "sing_box_journal",
                "code": code,
            })
    return events, latest_cursor, False


def _categorize(message: str) -> str:
    for fragment, code in _CATEGORIES:
        if fragment not in message:
            continue
        if code == "relay_tcp_connect" and "failed" not in message:
            continue
        if code in {"relay_read_error", "relay_udp_open_error"} and "relay" not in message:
            continue
        return code
    return ""


def _journal_timestamp(payload: Mapping[str, object], fallback: float) -> float:
    try:
        return max(0.0, int(str(payload.get("__REALTIME_TIMESTAMP", "0"))) / 1_000_000)
    except (TypeError, ValueError):
        return fallback


__all__ = ["collect_calls_journal_events"]
