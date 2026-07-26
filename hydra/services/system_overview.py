"""Read-only host metrics and network identity collection."""
from __future__ import annotations

import os
import re
import socket
from pathlib import Path
from typing import Any

from hydra.core.host import HOST
from hydra.core.state_models import AppState
from hydra.services.admin import SystemOverview
from hydra.services.network_info import snapshot as network_snapshot
from hydra.utils.net import local_ip


def collect_system_overview(
    state: AppState,
    *,
    host: Any = HOST,
) -> SystemOverview:
    cpu_percent: float | None = None
    memory_used = 0
    memory_total = 0
    memory_percent: float | None = None
    disk_used = 0
    disk_total = 0
    disk_percent: float | None = None
    uptime_seconds: int | None = None
    load_averages: tuple[float, float] | None = None

    try:
        import psutil

        cpu_percent = float(psutil.cpu_percent(interval=0))
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        memory_used = int(memory.used)
        memory_total = int(memory.total)
        memory_percent = float(memory.percent)
        disk_used = int(disk.used)
        disk_total = int(disk.total)
        disk_percent = float(disk.percent)
        uptime_seconds = max(0, int(__import__("time").time() - psutil.boot_time()))
    except ImportError:
        import shutil

        disk_total, disk_used, _ = shutil.disk_usage("/")
        disk_percent = (
            disk_used / disk_total * 100
            if disk_total > 0
            else 0.0
        )
        if os.name != "nt":
            uptime_seconds = _read_uptime()
            load_averages = _read_load()
            memory_used, memory_total, memory_percent = _read_memory()
    except Exception:
        pass

    network = network_snapshot()
    public_ip = network.public_ip
    if public_ip == "Получение..." and state.network.server_ip:
        public_ip = state.network.server_ip
    try:
        local = local_ip()
    except Exception:
        local = ""

    dnscrypt_active, dnscrypt_servers = _dnscrypt_status(host)
    return SystemOverview(
        hostname=socket.gethostname(),
        cpu_percent=cpu_percent,
        memory_used=memory_used,
        memory_total=memory_total,
        memory_percent=memory_percent,
        disk_used=disk_used,
        disk_total=disk_total,
        disk_percent=disk_percent,
        uptime_seconds=uptime_seconds,
        load_averages=load_averages,
        public_ip=public_ip,
        local_ip=local,
        country_flag=network.country_flag,
        dns=network.dns,
        dnscrypt_active=dnscrypt_active,
        dnscrypt_servers=dnscrypt_servers,
    )


def _read_uptime() -> int | None:
    try:
        return int(float(Path("/proc/uptime").read_text().split()[0]))
    except (OSError, ValueError, IndexError):
        return None


def _read_load() -> tuple[float, float] | None:
    try:
        first, fifth, _ = os.getloadavg()
        return float(first), float(fifth)
    except (AttributeError, OSError):
        return None


def _read_memory() -> tuple[int, int, float | None]:
    try:
        values: dict[str, int] = {}
        for line in Path("/proc/meminfo").read_text().splitlines():
            parts = line.split()
            if len(parts) >= 2:
                values[parts[0].rstrip(":")] = int(parts[1]) * 1024
        total = values.get("MemTotal", 0)
        used = total - values.get("MemFree", 0) - values.get(
            "Buffers",
            0,
        ) - values.get("Cached", 0)
        percent = used / total * 100 if total > 0 else None
        return used, total, percent
    except (OSError, ValueError):
        return 0, 0, None


def _dnscrypt_status(host: Any) -> tuple[bool, tuple[str, ...]]:
    try:
        active = host.run(
            ["systemctl", "is-active", "dnscrypt-proxy"],
            capture_output=True,
            text=True,
            timeout=1,
        )
        if str(active.stdout or "").strip() != "active":
            return False, ()
        config = Path("/etc/dnscrypt-proxy/dnscrypt-proxy.toml")
        if not config.exists():
            return True, ()
        match = re.search(
            r"^server_names\s*=\s*\[(.*?)]",
            config.read_text(encoding="utf-8"),
            flags=re.MULTILINE | re.DOTALL,
        )
        if not match:
            return True, ()
        names = tuple(
            name.strip("'\" ")
            for name in match.group(1).split(",")
            if name.strip("'\" ")
        )
        return True, names
    except Exception:
        return False, ()
