"""
hydra/utils/net.py — Сетевые утилиты: IP, архитектура, etc.
"""
from __future__ import annotations

from hydra.core.host import HOST

import ipaddress
import json
import os
import platform
import socket
import subprocess
from functools import lru_cache


def public_ip() -> str:
    """curl -s -4 api.ipify.org (timeout 5). Fallback: 127.0.0.1."""
    for cmd in (
        ["curl", "-s", "-4", "--max-time", "5", "https://api.ipify.org"],
        ["curl", "-s", "-4", "--max-time", "5", "https://ifconfig.me"],
    ):
        try:
            r = HOST.run(
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


@lru_cache(maxsize=16)
def host_ip_addresses(configured: tuple[str, ...] = ()) -> tuple[str, ...]:
    """Return every known address owned by this host.

    Security modules use this shared inventory to prevent the VPS from
    banning itself when traffic loops through its public address.
    """
    values: set[str] = set()

    def add(raw: object) -> None:
        value = str(raw or "").strip().strip("[]")
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return
        if not address.is_unspecified and not address.is_multicast:
            values.add(address.compressed)

    for value in configured:
        add(value)
    add(local_ip())
    if os.name != "nt":
        add(public_ip())
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            add(info[4][0])
    except OSError:
        pass
    try:
        if os.name == "nt":
            return tuple(sorted(values, key=lambda value: (ipaddress.ip_address(value).version, value)))
        result = HOST.run(
            ["ip", "-j", "address", "show"],
            capture_output=True, text=True, timeout=8,
        )
        if result.returncode == 0:
            for interface in json.loads(result.stdout or "[]"):
                if not isinstance(interface, dict):
                    continue
                for item in interface.get("addr_info", []):
                    if isinstance(item, dict):
                        add(item.get("local"))
    except Exception:
        pass
    return tuple(sorted(values, key=lambda value: (ipaddress.ip_address(value).version, value)))


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
