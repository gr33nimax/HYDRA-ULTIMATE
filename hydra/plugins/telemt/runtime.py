"""Applying Telemt configuration and host runtime actions."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Protocol

from hydra.plugins.context import PluginStateAccess

from .constants import DEFAULT_PORT


class HostRuntime(Protocol):
    def atomic_write(self, path: Path, content: str) -> None: ...

    def run(self, command: list[str], **kwargs): ...


def apply_optimizations(
    *,
    host: HostRuntime,
    sysctl_file: Path,
    limits_file: Path,
) -> bool:
    try:
        host.atomic_write(
            sysctl_file,
            "fs.file-max = 2097152\n"
            "net.core.somaxconn = 65535\n"
            "net.ipv4.tcp_max_syn_backlog = 65535\n"
            "net.ipv4.tcp_fin_timeout = 15\n"
            "net.ipv4.tcp_tw_reuse = 1\n"
            "net.ipv4.tcp_rmem = 4096 87380 16777216\n"
            "net.ipv4.tcp_wmem = 4096 65536 16777216\n"
            "net.ipv6.conf.all.disable_ipv6 = 0\n",
        )
        host.atomic_write(
            limits_file,
            "* soft nofile 1048576\n"
            "* hard nofile 1048576\n"
            "root soft nofile 1048576\n"
            "root hard nofile 1048576\n",
        )
        return host.run(
            ["sysctl", "--system"], capture_output=True
        ).returncode == 0
    except Exception:
        return False


def remove_optimizations(
    *,
    host: HostRuntime,
    paths: tuple[Path, ...],
) -> bool:
    try:
        for path in paths:
            path.unlink(missing_ok=True)
        return host.run(
            ["sysctl", "--system"], capture_output=True
        ).returncode == 0
    except Exception:
        return False


def _write_fallback(config_file: Path, config: dict) -> None:
    fallback = config.get("fallback_cfg")
    if not fallback:
        return
    try:
        from .telemt_fallback import FallbackConfig, append_fallback_section

        append_fallback_section(config_file, FallbackConfig(**fallback))
    except Exception as exc:
        print(f"  [telemt] Ошибка записи fallback настроек: {exc}")


def _apply_self_route(config: dict) -> None:
    port = config.get("singbox_integration_port", 10811)
    try:
        from . import telemt_self_route

        if config.get("singbox_integration_enabled", False):
            telemt_self_route.enable(port)
        else:
            telemt_self_route.disable(port)
    except Exception as exc:
        print(f"  [telemt] Ошибка применения правил маршрутизации: {exc}")


def _install_stats(
    *,
    host: HostRuntime,
    cron_file: Path,
    project_root: Path,
    port: int,
) -> None:
    try:
        cron_file.write_text(
            f"*/5 * * * * root PYTHONPATH={project_root} python3 -c "
            "\"from hydra.plugins.telemt.mtproto_stats import "
            "_load_stats, _collect, _save_stats; "
            "d = _load_stats(); d = _collect(d); _save_stats(d)\" "
            ">/dev/null 2>&1\n",
            encoding="utf-8",
        )
        cron_file.chmod(0o644)
        host.run(["systemctl", "restart", "cron"], capture_output=True)
    except Exception as exc:
        print(f"  [telemt] Ошибка создания задания cron: {exc}")
    try:
        from .mtproto_stats import setup_iptables_accounting

        setup_iptables_accounting(port)
    except Exception as exc:
        print(f"  [telemt] Ошибка настройки iptables-учёта: {exc}")


def apply(
    pending_config: str | None,
    state: PluginStateAccess,
    *,
    host: HostRuntime,
    config_dir: Path,
    work_dir: Path,
    config_file: Path,
    cron_file: Path,
    service_name: str,
    project_root: Path,
) -> bool:
    if not pending_config:
        return False
    config_dir.mkdir(parents=True, exist_ok=True)
    work_dir.mkdir(parents=True, exist_ok=True)
    config_file.write_text(pending_config, encoding="utf-8")
    config_file.chmod(0o640)
    protocol = state.protocols.get("telemt")
    config = protocol.config if protocol else {}
    _write_fallback(config_file, config)
    results = (
        host.run(["systemctl", "daemon-reload"], capture_output=True),
        host.run(["systemctl", "enable", service_name], capture_output=True),
        host.run(
            ["systemctl", "reload-or-restart", service_name],
            capture_output=True,
        ),
    )
    if any(result.returncode != 0 for result in results):
        return False
    _apply_self_route(config)
    _install_stats(
        host=host,
        cron_file=cron_file,
        project_root=project_root,
        port=config.get("port", DEFAULT_PORT),
    )
    time.sleep(2)
    return True


def snapshot(
    *,
    config_file: Path,
    service_file: Path,
    cron_file: Path,
    running: bool,
) -> dict:
    return {
        "config": config_file.read_bytes() if config_file.exists() else None,
        "service": service_file.read_bytes() if service_file.exists() else None,
        "cron": cron_file.read_bytes() if cron_file.exists() else None,
        "running": running,
    }


def rollback(
    previous: dict | None,
    *,
    host: HostRuntime,
    config_file: Path,
    service_file: Path,
    cron_file: Path,
    service_name: str,
) -> bool:
    restored = previous or {}
    for key, path in (
        ("config", config_file),
        ("service", service_file),
        ("cron", cron_file),
    ):
        content = restored.get(key)
        if content is None:
            path.unlink(missing_ok=True)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
    action = "restart" if restored.get("running") else "stop"
    return host.run(
        ["systemctl", action, service_name], capture_output=True
    ).returncode == 0
