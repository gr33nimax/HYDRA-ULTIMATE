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

# ``Type=simple`` reports the unit active before the process proves itself, so a
# slow start and an instant crash must be told apart by polling.
READY_POLLS = 12
READY_INTERVAL_SECONDS = 0.5


def service_state(host: Any, service: str, *, polls: int = 1) -> tuple[str, Any]:
    """Read the unit state, polling while it is still starting."""
    result = _systemctl(host, "is-active", service)
    state = (result.stdout or "").strip()
    for _ in range(max(0, polls - 1)):
        if state == "active":
            return state, result
        time.sleep(READY_INTERVAL_SECONDS)
        result = _systemctl(host, "is-active", service)
        state = (result.stdout or "").strip()
    return state, result


def ready_probe(check: Callable[[], tuple[bool, str]], *, polls: int = READY_POLLS) -> tuple[bool, str]:
    """Retry one readiness check until it passes or the poll budget is spent.

    ``Type=simple`` reports a unit active before the process has bound its
    socket, so a single refused connection is a race, not a verdict: only an
    exhausted budget fails, and the last reason is preserved.
    """
    budget = max(1, polls)
    healthy, reason = False, ""
    for attempt in range(budget):
        healthy, reason = check()
        if healthy:
            return True, ""
        if attempt + 1 < budget:
            time.sleep(READY_INTERVAL_SECONDS)
    return False, reason


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
    # and belong to the service user before systemd loads the unit again.
    host.ensure_directory(work_dir, mode=0o750)
    work_owner = host.run(["chown", f"{SERVICE_USER}:{SERVICE_USER}", str(work_dir)], capture_output=True)
    if work_owner.returncode != 0:
        report_stage(on_failure, "не удалось назначить владельца рабочего каталога mtproto-zig")
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
    state, result = service_state(host, service, polls=READY_POLLS)
    if state != "active":
        reason = bounded_reason(result)
        suffix = f" ({reason})" if reason else ""
        report_stage(
            on_failure,
            f"служба {service} не запустилась (state={state or 'unknown'}): смотрите journalctl -u {service}{suffix}",
        )
        return False
    # Confirm the process stays up: a unit that dies right after the fork must
    # not be reported as a successful start.
    time.sleep(READY_INTERVAL_SECONDS)
    settled, settled_result = service_state(host, service)
    if settled != "active":
        reason = bounded_reason(settled_result)
        suffix = f" ({reason})" if reason else ""
        report_stage(
            on_failure,
            f"служба {service} завершилась сразу после запуска (state={settled or 'unknown'}): "
            f"смотрите journalctl -u {service}{suffix}",
        )
        return False
    return True


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
