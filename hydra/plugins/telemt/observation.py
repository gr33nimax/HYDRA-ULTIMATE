"""Runtime observation and control-API accounting for Telemt."""

from __future__ import annotations

import json
import shutil
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, Protocol

from hydra.plugins.base import PluginStatus
from hydra.plugins.context import PluginStateAccess

from .constants import API_LISTEN

# Upstream ``GET /v1/stats/users`` returns ``UserInfo[]`` with the cumulative
# ``total_octets`` counter. It is reachable only over the loopback control API.
STATS_URL = f"http://{API_LISTEN}/v1/stats/users"


class HostRunner(Protocol):
    """The subset of the injected HostBackend this module drives."""

    def run(
        self,
        args: Sequence[object],
        *,
        timeout: float = ...,
        check: bool = ...,
        text: bool = ...,
        capture_output: bool = ...,
        encoding: str | None = ...,
        errors: str | None = ...,
    ) -> Any: ...


def installed(bin_path: Path) -> bool:
    return bin_path.exists() or shutil.which("telemt") is not None


def status(
    *,
    host: HostRunner,
    bin_path: Path,
    config_file: Path,
    service_name: str,
    default_port: int,
    is_installed: bool | None = None,
) -> PluginStatus:
    if is_installed is None:
        is_installed = installed(bin_path)
    running = False
    state = ""
    port = default_port
    if is_installed:
        result = host.run(
            ["systemctl", "is-active", service_name],
            capture_output=True,
            text=True,
        )
        state = (result.stdout or "").strip()
        running = state == "active"
        if config_file.exists():
            try:
                for line in config_file.read_text(encoding="utf-8").splitlines():
                    if line.strip().startswith("port ="):
                        port = int(line.split("=")[1].strip())
                        break
            except Exception:
                pass
    return PluginStatus(
        installed=is_installed,
        enabled=config_file.exists(),
        running=running,
        port=port,
        info={"state": state} if state else {},
    )


def fetch_users(url: str = STATS_URL) -> str:
    """Read the control API user counters over loopback."""
    with urllib.request.urlopen(url, timeout=2) as response:
        return response.read().decode("utf-8")


def _parse_user_totals(payload: str) -> dict[str, int]:
    """Map ``username`` to its cumulative ``total_octets`` counter."""
    try:
        data = json.loads(payload)
    except ValueError as exc:
        raise ValueError("тело ответа не является JSON") from exc
    if not isinstance(data, list):
        raise ValueError("ответ не является списком пользователей")
    totals: dict[str, int] = {}
    for entry in data:
        if not isinstance(entry, dict):
            raise ValueError("элемент ответа не является объектом")
        username = entry.get("username")
        total = entry.get("total_octets")
        if not isinstance(username, str) or not username:
            raise ValueError("в ответе нет имени пользователя")
        if not isinstance(total, int) or isinstance(total, bool) or total < 0:
            raise ValueError("в ответе нет корректного total_octets")
        totals[username] = total
    return totals


def traffic(
    state: PluginStateAccess,
    *,
    derive_username: Callable[[str], str],
    fetch: Callable[[], str] = fetch_users,
) -> tuple[dict[str, int] | None, str]:
    """Return per-user cumulative traffic from the control API.

    A parsed answer that names at least one state user is an available source
    even when it does not know a not-yet-applied user (R2a): the found users are
    returned with an empty reason, and the divergence is reported through
    :func:`missing_users`. Any failure, and an answer naming no state user at
    all, stays unavailable (``None``) rather than a measured zero, so the caller
    keeps the last good accumulated totals.
    """
    try:
        payload = fetch()
    except (OSError, ValueError, urllib.error.URLError) as exc:
        return None, f"control API недоступен ({exc.__class__.__name__})"
    try:
        totals = _parse_user_totals(payload)
    except (ValueError, TypeError) as exc:
        return None, f"ответ control API не разобран ({exc})"
    result: dict[str, int] = {}
    missing = 0
    for user in state.users:
        if user.blocked:
            continue
        username = derive_username(user.uuid)
        if username not in totals:
            missing += 1
            continue
        result[user.email] = totals[username]
    if missing and not result:
        return None, f"control API не отдал счётчик для {missing} пользователей"
    return result, ""


def missing_users(
    state: PluginStateAccess,
    totals: dict[str, int] | None,
) -> int | None:
    """Count non-blocked state users an available snapshot did not report (R2a).

    ``None`` means the source was unavailable, so the divergence is unknown and
    the failure reason reports it instead.
    """
    if totals is None:
        return None
    return sum(1 for user in state.users if not user.blocked and user.email not in totals)
