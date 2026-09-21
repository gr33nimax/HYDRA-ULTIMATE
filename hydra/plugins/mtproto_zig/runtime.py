"""Runtime apply and rollback for mtproto.zig."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from .constants import SERVICE_USER
from .installation import report_stage


def apply(
    config: str | None,
    *,
    host: Any,
    config_file: Path,
    service: str,
    binary: Path,
    on_failure: Callable[[str], None] | None = None,
) -> bool:
    if not config:
        report_stage(on_failure, "конфигурация mtproto.zig не построена")
        return False
    host.atomic_write(config_file, config, mode=0o640)
    ownership = host.run(["chown", f"root:{SERVICE_USER}", str(config_file)], capture_output=True)
    if ownership.returncode != 0:
        report_stage(on_failure, "не удалось назначить владельца конфигурации mtproto.zig")
        return False
    # Upstream runs the proxy as ``mtproto-proxy <config.toml>`` and validates
    # configuration through ``mtbuddy config validate``; there is no proxy-side
    # ``--check-config`` flag. The systemd restart plus ``is-active`` result is
    # the runtime health gate.
    results = (
        host.run(["systemctl", "daemon-reload"], capture_output=True),
        host.run(["systemctl", "enable", service], capture_output=True),
        host.run(["systemctl", "restart", service], capture_output=True),
        host.run(["systemctl", "is-active", service], capture_output=True, text=True),
    )
    if all(result.returncode == 0 for result in results):
        return True
    report_stage(on_failure, "служба mtproto-zig не запустилась: смотрите journalctl -u mtproto-zig")
    return False


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
