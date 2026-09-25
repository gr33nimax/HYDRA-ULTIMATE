"""Loopback Prometheus accounting with restart-safe cumulative totals."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path

from hydra.plugins.context import PluginStateAccess

from .credentials import derive_username

_METRIC = re.compile(
    r'^mtproto_user_(?:client_to_upstream|upstream_to_client)_bytes_total\{[^}]*user="([^"]+)"[^}]*}\s+(\d+(?:\.\d+)?)$'
)


def fetch_metrics(*, url: str = "http://127.0.0.1:9400/metrics") -> str:
    with urllib.request.urlopen(url, timeout=2) as response:
        return response.read().decode("utf-8")


def parse_metrics(text: str) -> dict[str, int]:
    totals: dict[str, int] = {}
    for line in text.splitlines():
        match = _METRIC.match(line.strip())
        if match:
            try:
                totals[match[1]] = totals.get(match[1], 0) + int(float(match[2]))
            except ValueError:
                continue
    return totals


def _load(path: Path) -> dict[str, dict[str, int]]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return {key: {name: int(amount) for name, amount in entry.items()} for key, entry in value.items()}
    except (OSError, ValueError, TypeError):
        return {"last": {}, "total": {}}


def traffic(
    state: PluginStateAccess, *, totals_file: Path, metrics: Callable[[], str] = fetch_metrics
) -> tuple[dict[str, int] | None, str]:
    """Return per-user cumulative totals, or ``None`` when the source is unusable.

    A successful HTTP response without any supported series is not a measured
    zero: it means the metrics source is unavailable, so the last good totals
    are kept instead of being overwritten with an empty snapshot.
    """
    saved = _load(totals_file)
    try:
        current = parse_metrics(metrics())
    except (OSError, ValueError, urllib.error.URLError) as exc:
        return None, f"metrics недоступны ({exc.__class__.__name__})"
    if not current:
        return None, "нет поддерживаемых серий mtproto_user_*"
    if not _by_email(state, current):
        return None, "метки пользователей не совпадают с состоянием"
    last, total = saved.get("last", {}), saved.get("total", {})
    for name, value in current.items():
        previous = last.get(name)
        delta = value if previous is None or value < previous else value - previous
        total[name] = total.get(name, 0) + delta
    totals_file.parent.mkdir(parents=True, exist_ok=True)
    pending = totals_file.with_suffix(".pending")
    pending.write_text(json.dumps({"last": current, "total": total}, sort_keys=True), encoding="utf-8")
    pending.replace(totals_file)
    return _by_email(state, total), ""


def _by_email(state: PluginStateAccess, totals: dict[str, int]) -> dict[str, int]:
    result: dict[str, int] = {}
    for user in state.users:
        username = derive_username(user.uuid)
        if username in totals:
            result[user.email] = totals[username]
    return result
