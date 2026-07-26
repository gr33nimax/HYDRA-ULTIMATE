"""Cursor-aware ingestion of NaiveProxy's structured access logs."""
from __future__ import annotations

import gzip
import json
from collections.abc import Callable
from pathlib import Path
from typing import IO

from hydra.core.state_models import User
from hydra.plugins.context import PluginStateAccess


def access_log_directions(data: dict) -> tuple[int, int]:
    """Return client Rx/Tx from a structured Caddy access-log record."""
    try:
        rx = max(0, int(data.get("size", 0)))
    except (TypeError, ValueError):
        rx = 0
    try:
        tx = max(0, int(data.get("bytes_read", 0)))
    except (TypeError, ValueError):
        tx = 0
    return rx, tx


def _access_log_paths(log_dir: Path) -> list[Path]:
    try:
        return sorted(
            log_dir.glob("access.log*"),
            key=lambda path: path.stat().st_mtime_ns,
        )
    except OSError:
        return []


def _non_negative_int(value: object) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _merge_line(
    line: str,
    users: dict[str, User],
    protocol: str,
    *,
    directions: Callable[[dict], tuple[int, int]],
    normalize: Callable[[object], int],
    json_loads: Callable[[str], object],
) -> None:
    try:
        data = json_loads(line)
        if not isinstance(data, dict):
            return
        username = data.get("user_id") or data.get("user")
        user = users.get(username)
        rx, tx = directions(data)
    except (json.JSONDecodeError, TypeError, ValueError):
        return
    if user is None or not (rx or tx):
        return

    stats = user.credentials.setdefault(protocol, {})
    stats["traffic_used_bytes"] = (
        normalize(stats.get("traffic_used_bytes", 0)) + rx + tx
    )
    stats["traffic_rx_bytes"] = (
        normalize(stats.get("traffic_rx_bytes", 0)) + rx
    )
    stats["traffic_tx_bytes"] = (
        normalize(stats.get("traffic_tx_bytes", 0)) + tx
    )


def _ingest_path(
    path: Path,
    users: dict[str, User],
    cursors: dict,
    protocol: str,
    *,
    directions: Callable[[dict], tuple[int, int]],
    normalize: Callable[[object], int],
    json_loads: Callable[[str], object],
    gzip_open: Callable[..., IO[str]],
) -> None:
    stat = path.stat()
    compressed = path.suffix == ".gz"
    if compressed:
        key = f"gz:{path.name}:{stat.st_mtime_ns}:{stat.st_size}"
        if cursors.get(key) == "done":
            return
        handle = gzip_open(
            path,
            "rt",
            encoding="utf-8",
            errors="replace",
        )
        start = 0
    else:
        key = f"inode:{stat.st_dev}:{stat.st_ino}"
        start = normalize(cursors.get(key, 0))
        if start > stat.st_size:
            start = 0
        handle = path.open(
            "r",
            encoding="utf-8",
            errors="replace",
        )

    with handle:
        if start:
            handle.seek(start)
        for line in handle:
            _merge_line(
                line,
                users,
                protocol,
                directions=directions,
                normalize=normalize,
                json_loads=json_loads,
            )
        cursors[key] = "done" if compressed else handle.tell()


def ingest_access_logs(
    state: PluginStateAccess,
    log_dir: Path,
    derive_username: Callable[[User], str],
    cursors: dict,
    *,
    protocol: str = "naive",
    access_log_paths: Callable[[Path], list[Path]] = _access_log_paths,
    directions: Callable[[dict], tuple[int, int]] = access_log_directions,
    normalize: Callable[[object], int] = _non_negative_int,
    json_loads: Callable[[str], object] = json.loads,
    gzip_open: Callable[..., IO[str]] = gzip.open,
) -> None:
    """Merge unread rotated access records using persisted inode cursors."""
    users = {
        derive_username(user): user
        for user in state.users
    }
    for path in access_log_paths(log_dir):
        try:
            _ingest_path(
                path,
                users,
                cursors,
                protocol,
                directions=directions,
                normalize=normalize,
                json_loads=json_loads,
                gzip_open=gzip_open,
            )
        except OSError:
            continue

    if len(cursors) > 128:
        for key in list(cursors)[:-128]:
            cursors.pop(key, None)
