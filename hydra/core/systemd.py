"""
hydra/core/systemd.py — Управление systemd-юнитами.

Создание, удаление, включение/выключение служб и таймеров.
Используется для Sync Agent, Telegram-ботов и других фоновых служб.
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from hydra.utils.commands import DEFAULT_TIMEOUT
from hydra.core.host import HOST
from hydra.utils.commands import CommandError

SYSTEMD_DIR = HOST.paths.systemd_dir


def _run(args: list[str], *, timeout: float = DEFAULT_TIMEOUT) -> subprocess.CompletedProcess:
    try:
        return HOST.run(args, timeout=timeout)
    except CommandError as exc:
        return subprocess.CompletedProcess(args, 127, "", str(exc))


def _atomic_write(path: Path, content: str) -> None:
    HOST.atomic_write(path, content)


def _reload() -> bool:
    return _run(["systemctl", "daemon-reload"]).returncode == 0


def install_service(name: str, content: str) -> bool:
    """Создаёт и включает systemd-сервис."""
    unit_path = SYSTEMD_DIR / f"{name}.service"
    unit_path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(unit_path, content)
    if not _reload():
        return False
    return _run(["systemctl", "enable", f"{name}.service"]).returncode == 0


def install_timer(name: str, service_content: str, timer_content: str) -> bool:
    """Создаёт systemd-сервис + таймер и активирует таймер."""
    svc_path = SYSTEMD_DIR / f"{name}.service"
    tmr_path = SYSTEMD_DIR / f"{name}.timer"
    _atomic_write(svc_path, service_content)
    _atomic_write(tmr_path, timer_content)
    if not _reload():
        return False
    enabled = _run(["systemctl", "enable", f"{name}.timer"])
    started = _run(["systemctl", "start", f"{name}.timer"])
    return enabled.returncode == 0 and started.returncode == 0


def remove_unit(name: str) -> bool:
    """Останавливает и удаляет systemd-юнит (сервис + таймер)."""
    for suffix in (".service", ".timer"):
        path = SYSTEMD_DIR / f"{name}{suffix}"
        if path.exists():
            _run(["systemctl", "stop", f"{name}{suffix}"])
            _run(["systemctl", "disable", f"{name}{suffix}"])
            path.unlink()
    return _reload()


def is_active(name: str) -> bool:
    """Проверяет, активен ли юнит."""
    try:
        r = _run(["systemctl", "is-active", "--quiet", name])
        return r.returncode == 0
    except FileNotFoundError:
        return False


def start(name: str) -> bool:
    """Запускает юнит."""
    try:
        r = _run(["systemctl", "start", name])
        return r.returncode == 0
    except FileNotFoundError:
        return False


def stop(name: str) -> bool:
    """Останавливает юнит."""
    try:
        r = _run(["systemctl", "stop", name])
        return r.returncode == 0
    except FileNotFoundError:
        return False


def restart(name: str) -> bool:
    """Перезапускает юнит."""
    try:
        r = _run(["systemctl", "restart", name])
        return r.returncode == 0
    except FileNotFoundError:
        return False
