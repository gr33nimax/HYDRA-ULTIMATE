"""Transactional Telemt-owned runtime mutations."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .constants import SERVICE_USER


def apply(
    pending_config: str | None,
    *,
    host: Any,
    config_file: Path,
    service_name: str,
) -> bool:
    """Write only Telemt's config and restart only its unit."""
    if not pending_config:
        return False
    host.ensure_directory(config_file.parent, mode=0o750)
    host.atomic_write(config_file, pending_config, mode=0o640)
    ownership = host.run(["chown", f"root:{SERVICE_USER}", str(config_file)], capture_output=True)
    if ownership.returncode != 0:
        return False
    for action in ("daemon-reload", "enable", "restart"):
        result = host.run(["systemctl", action, service_name], capture_output=True, text=True)
        if result.returncode != 0:
            return False
    health = host.run(["systemctl", "is-active", service_name], capture_output=True, text=True)
    return health.returncode == 0 and health.stdout.strip() == "active"


def snapshot(*, config_file: Path, service_file: Path, running: bool) -> dict[str, bytes | bool | None]:
    return {
        "config": config_file.read_bytes() if config_file.exists() else None,
        "service": service_file.read_bytes() if service_file.exists() else None,
        "running": running,
    }


def rollback(
    previous: dict[str, bytes | bool | None] | None,
    *,
    host: Any,
    config_file: Path,
    service_file: Path,
    service_name: str,
) -> bool:
    restored = previous or {}
    for key, path in (("config", config_file), ("service", service_file)):
        content = restored.get(key)
        if isinstance(content, bytes):
            host.atomic_write(path, content, mode=0o640 if key == "config" else 0o644)
        else:
            host.remove_file(path)
    action = "restart" if restored.get("running") else "stop"
    return host.run(["systemctl", action, service_name], capture_output=True).returncode == 0
