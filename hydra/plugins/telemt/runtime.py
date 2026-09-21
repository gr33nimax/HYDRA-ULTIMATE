"""Transactional Telemt-owned runtime mutations."""

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

# ``Type=simple`` reports the unit active before the process proves itself, so a
# slow start and an instant crash must be told apart by polling.
READY_POLLS = 12
READY_INTERVAL_SECONDS = 0.5


def _service_state(host: Any, service_name: str, *, polls: int = 1) -> tuple[str, Any]:
    """Read the unit state, polling while it is still starting."""
    result = _systemctl(host, "is-active", service_name)
    state = (result.stdout or "").strip()
    for _ in range(max(0, polls - 1)):
        if state == "active":
            return state, result
        time.sleep(READY_INTERVAL_SECONDS)
        result = _systemctl(host, "is-active", service_name)
        state = (result.stdout or "").strip()
    return state, result


def _systemctl(host: Any, action: str, service_name: str = "") -> Any:
    """Run one systemctl action; a unit name is only passed when it applies."""
    command = ["systemctl", action]
    if service_name:
        command.append(service_name)
    return host.run(command, capture_output=True, text=True)


def apply(
    pending_config: str | None,
    *,
    host: Any,
    config_file: Path,
    work_dir: Path,
    service_name: str,
    on_failure: Callable[[str], None] | None = None,
) -> bool:
    """Write only Telemt's config and restart only its unit."""
    if not pending_config:
        report_stage(on_failure, "конфигурация Telemt не построена")
        return False
    host.ensure_directory(config_file.parent, mode=0o750)
    # The unit grants this directory through ReadWritePaths, so it must exist
    # before systemd loads the unit again.
    host.ensure_directory(work_dir, mode=0o750)
    host.atomic_write(config_file, pending_config, mode=0o640)
    ownership = host.run(["chown", f"root:{SERVICE_USER}", str(config_file)], capture_output=True)
    if ownership.returncode != 0:
        report_stage(on_failure, "не удалось назначить владельца конфигурации Telemt")
        return False
    reload_result = _systemctl(host, "daemon-reload")
    if reload_result.returncode != 0:
        # A reload that is already in flight is rejected occasionally; one
        # bounded retry separates that transient rejection from a unit problem.
        time.sleep(RELOAD_RETRY_SECONDS)
        reload_result = _systemctl(host, "daemon-reload")
    if reload_result.returncode != 0:
        reason = bounded_reason(reload_result)
        suffix = f": {reason}" if reason else ""
        report_stage(on_failure, f"systemctl daemon-reload не выполнился для Telemt{suffix}")
        return False
    for action in ("enable", "restart"):
        result = _systemctl(host, action, service_name)
        if result.returncode != 0:
            reason = bounded_reason(result)
            suffix = f": {reason}" if reason else ""
            report_stage(on_failure, f"systemctl {action} не выполнился для Telemt{suffix}")
            return False
    state, result = _service_state(host, service_name, polls=READY_POLLS)
    if state != "active":
        reason = bounded_reason(result)
        suffix = f" ({reason})" if reason else ""
        report_stage(
            on_failure,
            f"служба Telemt не запустилась (state={state or 'unknown'}): смотрите journalctl -u {service_name}{suffix}",
        )
        return False
    # Confirm the process stays up: a unit that dies right after the fork must
    # not be reported as a successful start.
    time.sleep(READY_INTERVAL_SECONDS)
    settled, settled_result = _service_state(host, service_name)
    if settled != "active":
        reason = bounded_reason(settled_result)
        suffix = f" ({reason})" if reason else ""
        report_stage(
            on_failure,
            f"служба Telemt завершилась сразу после запуска (state={settled or 'unknown'}): "
            f"смотрите journalctl -u {service_name}{suffix}",
        )
        return False
    return True


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
