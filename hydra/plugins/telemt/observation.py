"""Runtime observation for Telemt."""
from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Protocol

from hydra.plugins.base import PluginStatus
from hydra.plugins.context import PluginStateAccess


class HostRunner(Protocol):
    def run(self, command: list[str], **kwargs): ...


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
    port = default_port
    if is_installed:
        result = host.run(
            ["systemctl", "is-active", service_name],
            capture_output=True,
            text=True,
        )
        running = result.stdout.strip() == "active"
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
    )


def traffic(
    state: PluginStateAccess,
    *,
    stats_file: Path,
    derive_username,
) -> dict[str, int]:
    if not stats_file.exists():
        return {}
    try:
        users_data = json.loads(
            stats_file.read_text(encoding="utf-8")
        ).get("users", {})
    except Exception:
        return {}
    result: dict[str, int] = {}
    for user in state.users:
        data = users_data.get(derive_username(user.uuid))
        if data is not None:
            result[user.email] = data.get("rx", 0) + data.get("tx", 0)
    return result
