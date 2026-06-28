"""
hydra/core/systemd.py — Управление systemd-юнитами.

Создание, удаление, включение/выключение служб и таймеров.
Используется для Sync Agent, Telegram-ботов и других фоновых служб.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

SYSTEMD_DIR = Path("/etc/systemd/system")


def _reload() -> None:
    subprocess.run(["systemctl", "daemon-reload"], capture_output=True)


def install_service(name: str, content: str) -> bool:
    """Создаёт и включает systemd-сервис."""
    unit_path = SYSTEMD_DIR / f"{name}.service"
    unit_path.parent.mkdir(parents=True, exist_ok=True)
    unit_path.write_text(content)
    _reload()
    subprocess.run(["systemctl", "enable", f"{name}.service"], capture_output=True)
    return True


def install_timer(name: str, service_content: str, timer_content: str) -> bool:
    """Создаёт systemd-сервис + таймер и активирует таймер."""
    svc_path = SYSTEMD_DIR / f"{name}.service"
    tmr_path = SYSTEMD_DIR / f"{name}.timer"
    svc_path.write_text(service_content)
    tmr_path.write_text(timer_content)
    _reload()
    subprocess.run(["systemctl", "enable", f"{name}.timer"], capture_output=True)
    subprocess.run(["systemctl", "start", f"{name}.timer"], capture_output=True)
    return True


def remove_unit(name: str) -> bool:
    """Останавливает и удаляет systemd-юнит (сервис + таймер)."""
    for suffix in (".service", ".timer"):
        path = SYSTEMD_DIR / f"{name}{suffix}"
        if path.exists():
            subprocess.run(
                ["systemctl", "stop", f"{name}{suffix}"],
                capture_output=True,
            )
            subprocess.run(
                ["systemctl", "disable", f"{name}{suffix}"],
                capture_output=True,
            )
            path.unlink()
    _reload()
    return True


def is_active(name: str) -> bool:
    """Проверяет, активен ли юнит."""
    r = subprocess.run(
        ["systemctl", "is-active", "--quiet", name],
    )
    return r.returncode == 0


def start(name: str) -> bool:
    """Запускает юнит."""
    r = subprocess.run(
        ["systemctl", "start", name],
        capture_output=True,
    )
    return r.returncode == 0


def stop(name: str) -> bool:
    """Останавливает юнит."""
    r = subprocess.run(
        ["systemctl", "stop", name],
        capture_output=True,
    )
    return r.returncode == 0


def restart(name: str) -> bool:
    """Перезапускает юнит."""
    r = subprocess.run(
        ["systemctl", "restart", name],
        capture_output=True,
    )
    return r.returncode == 0
