"""Runtime apply and rollback for mtproto.zig."""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from hydra.utils.commands import bounded_reason

from .constants import SERVICE_USER
from .installation import report_stage

# A reload that is already in flight is rejected occasionally; one bounded
# retry separates that transient rejection from a real unit problem.
RELOAD_RETRY_SECONDS = 1.0


def _systemctl(host: Any, action: str, service: str = "") -> Any:
    """Run one systemctl action; a unit name is only passed when it applies."""
    command = ["systemctl", action]
    if service:
        command.append(service)
    return host.run(command, capture_output=True, text=True)


def apply(
    config: str | None,
    *,
    host: Any,
    config_file: Path,
    work_dir: Path,
    service: str,
    binary: Path,
    on_failure: Callable[[str], None] | None = None,
) -> bool:
    if not config:
        report_stage(on_failure, "конфигурация mtproto.zig не построена")
        return False
    # The unit grants this directory through ReadWritePaths, so it must exist
    # before systemd loads the unit again.
    host.ensure_directory(work_dir, mode=0o750)
    host.atomic_write(config_file, config, mode=0o640)
    ownership = host.run(["chown", f"root:{SERVICE_USER}", str(config_file)], capture_output=True)
    if ownership.returncode != 0:
        report_stage(on_failure, "не удалось назначить владельца конфигурации mtproto.zig")
        return False
    # Upstream runs the proxy as ``mtproto-proxy <config.toml>`` and validates
    # configuration through ``mtbuddy config validate``; there is no proxy-side
    # ``--check-config`` flag. The systemd restart plus ``is-active`` result is
    # the runtime health gate.
    reload_result = _systemctl(host, "daemon-reload")
    if reload_result.returncode != 0:
        # A reload that is already in flight is rejected occasionally; one
        # bounded retry separates that transient rejection from a unit problem.
        time.sleep(RELOAD_RETRY_SECONDS)
        reload_result = _systemctl(host, "daemon-reload")
    if reload_result.returncode != 0:
        reason = bounded_reason(reload_result)
        suffix = f": {reason}" if reason else ""
        report_stage(on_failure, f"systemctl daemon-reload не выполнился для {service}{suffix}")
        return False
    for action in ("enable", "restart"):
        result = _systemctl(host, action, service)
        if result.returncode != 0:
            reason = bounded_reason(result)
            suffix = f": {reason}" if reason else ""
            report_stage(on_failure, f"systemctl {action} не выполнился для {service}{suffix}")
            return False
    health = _systemctl(host, "is-active", service)
    if health.returncode == 0 and health.stdout.strip() == "active":
        return True
    reason = bounded_reason(health)
    suffix = f" ({reason})" if reason else ""
    report_stage(on_failure, f"служба {service} не запустилась: смотрите journalctl -u {service}{suffix}")
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
