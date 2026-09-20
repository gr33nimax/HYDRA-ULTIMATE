"""Runtime apply and rollback for mtproto.zig."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .constants import SERVICE_USER


def apply(config: str | None, *, host: Any, config_file: Path, service: str, binary: Path) -> bool:
    if not config:
        return False
    host.atomic_write(config_file, config, mode=0o640)
    ownership = host.run(["chown", f"root:{SERVICE_USER}", str(config_file)], capture_output=True)
    if ownership.returncode != 0:
        return False
    check = host.run([str(binary), "--check-config", str(config_file)], capture_output=True)
    if check.returncode != 0:
        return False
    results = (
        host.run(["systemctl", "daemon-reload"], capture_output=True),
        host.run(["systemctl", "enable", service], capture_output=True),
        host.run(["systemctl", "restart", service], capture_output=True),
        host.run(["systemctl", "is-active", service], capture_output=True, text=True),
    )
    return all(result.returncode == 0 for result in results)


def snapshot(*, config_file: Path, service_file: Path, running: bool) -> dict:
    return {
        "config": config_file.read_bytes() if config_file.exists() else None,
        "service": service_file.read_bytes() if service_file.exists() else None,
        "running": running,
    }


def rollback(previous: dict | None, *, host: Any, config_file: Path, service_file: Path, service: str) -> bool:
    for key, target in (("config", config_file), ("service", service_file)):
        content = (previous or {}).get(key)
        if content is None:
            target.unlink(missing_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
    action = "restart" if (previous or {}).get("running") else "stop"
    return host.run(["systemctl", action, service], capture_output=True).returncode == 0
