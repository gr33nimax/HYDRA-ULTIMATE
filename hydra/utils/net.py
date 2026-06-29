"""
hydra/utils/net.py — Сетевые утилиты: IP, архитектура, etc.
"""
from __future__ import annotations

import platform
import socket
import subprocess


def public_ip() -> str:
    """curl -s -4 api.ipify.org (timeout 5). Fallback: 127.0.0.1."""
    for cmd in (
        ["curl", "-s", "-4", "--max-time", "5", "https://api.ipify.org"],
        ["curl", "-s", "-4", "--max-time", "5", "https://ifconfig.me"],
    ):
        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True, timeout=8,
            )
            ip = r.stdout.strip().split()[0] if r.stdout.strip() else ""
            if ip and not ip.startswith("127.") and not ip.startswith("::"):
                return ip
        except Exception:
            continue
    return "127.0.0.1"


def local_ip() -> str:
    """IP основного интерфейса через UDP-сокет к 8.8.8.8 (без отправки пакетов)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def detect_arch() -> str:
    """'amd64' | 'arm64' через platform.machine()."""
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "amd64"
    if machine in ("aarch64", "arm64"):
        return "arm64"
    # Fallback — возвращаем как есть (для нестандартных arch)
    return machine


def command_exists(cmd: str) -> bool:
    """Проверяет, доступна ли команда."""
    import shutil
    return shutil.which(cmd) is not None


# ── Совместимость ──────────────────────────────────────────────────────────
# Старый код мог импортировать get_public_ip из network.py.
get_public_ip = public_ip
