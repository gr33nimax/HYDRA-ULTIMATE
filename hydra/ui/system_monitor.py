"""Linux system metrics and realtime TUI rendering."""
from __future__ import annotations

import shutil
import time
from pathlib import Path
from typing import Callable

from hydra.ui.tui import (
    BOLD,
    CYAN,
    DIM,
    GREEN,
    NC,
    PANEL_W,
    clear,
    error,
    kv,
    panel,
    title,
)


def read_proc_cpu(stat_path: Path = Path("/proc/stat")) -> tuple[float, float]:
    """Return Linux CPU idle and total counters."""
    try:
        line = stat_path.read_text(encoding="utf-8").splitlines()[0]
        if line.startswith("cpu"):
            parts = [float(value) for value in line.split()[1:8]]
            return parts[3] + parts[4], sum(parts)
    except (OSError, IndexError, TypeError, ValueError):
        pass
    return 0.0, 0.0


def read_proc_mem(meminfo_path: Path = Path("/proc/meminfo")) -> tuple[int, int, float]:
    """Return used bytes, total bytes and utilization from Linux meminfo."""
    try:
        meminfo: dict[str, int] = {}
        for line in meminfo_path.read_text(encoding="utf-8").splitlines():
            parts = line.split()
            if len(parts) >= 2:
                meminfo[parts[0].rstrip(":")] = int(parts[1]) * 1024
        total = meminfo.get("MemTotal", 0)
        available = meminfo.get("MemAvailable", 0)
        if not available:
            available = (
                meminfo.get("MemFree", 0)
                + meminfo.get("Buffers", 0)
                + meminfo.get("Cached", 0)
                + meminfo.get("SReclaimable", 0)
                - meminfo.get("Shmem", 0)
            )
        used = max(0, total - available)
        return used, total, (used / total) * 100 if total > 0 else 0.0
    except (OSError, TypeError, ValueError):
        return 0, 0, 0.0


def read_proc_net(
    route_path: Path = Path("/proc/net/route"),
    dev_path: Path = Path("/proc/net/dev"),
) -> tuple[int, int]:
    """Return aggregate Rx/Tx counters for default-route interfaces."""
    try:
        default_ifaces: set[str] = set()
        try:
            for route in route_path.read_text(encoding="utf-8").splitlines()[1:]:
                fields = route.split()
                if (
                    len(fields) >= 4
                    and fields[1] == "00000000"
                    and int(fields[3], 16) & 2
                ):
                    default_ifaces.add(fields[0])
        except (OSError, ValueError):
            pass

        rx = 0
        tx = 0
        for line in dev_path.read_text(encoding="utf-8").splitlines()[2:]:
            if ":" not in line:
                continue
            iface, counters = line.split(":", 1)
            iface = iface.strip()
            if iface == "lo" or (default_ifaces and iface not in default_ifaces):
                continue
            parts = counters.split()
            if len(parts) >= 9:
                rx += int(parts[0])
                tx += int(parts[8])
        return rx, tx
    except (OSError, TypeError, ValueError):
        return 0, 0


def show_realtime(
    *,
    enter_pressed: Callable[[], bool],
    bytes_auto: Callable[[int], str],
    read_cpu: Callable[[], tuple[float, float]] = read_proc_cpu,
    read_mem: Callable[[], tuple[int, int, float]] = read_proc_mem,
    read_net: Callable[[], tuple[int, int]] = read_proc_net,
) -> None:
    """Render realtime host metrics until Enter is pressed."""
    clear()
    print(f"\n  {BOLD}{CYAN}▸ Запуск живого мониторинга...{NC}")
    print(f"  {DIM}Нажмите [Enter] для возврата в меню.{NC}\n")
    time.sleep(0.5)

    try:
        import psutil
    except ImportError:
        psutil = None

    prev_net = read_net()
    prev_cpu_idle, prev_cpu_total = read_cpu()
    last_time = time.time()

    while True:
        try:
            if enter_pressed():
                return

            clear()
            title("📈 Живой мониторинг системы")
            print(f"  {DIM}Нажмите [Enter] для возврата в меню. Обновление каждую секунду.{NC}")
            print()

            if psutil is not None:
                cpu = psutil.cpu_percent(interval=0)
                mem = psutil.virtual_memory()
                disk = psutil.disk_usage("/")
                cpu_str = f"{cpu:.1f}%"
                ram_str = f"{mem.percent:.1f}%  ({bytes_auto(mem.used)} / {bytes_auto(mem.total)})"
                disk_str = f"{disk.percent:.1f}%  ({bytes_auto(disk.used)} / {bytes_auto(disk.total)})"
            else:
                curr_cpu_idle, curr_cpu_total = read_cpu()
                diff_total = curr_cpu_total - prev_cpu_total
                diff_idle = curr_cpu_idle - prev_cpu_idle
                cpu_value = (diff_total - diff_idle) / diff_total * 100 if diff_total > 0 else 0.0
                prev_cpu_idle, prev_cpu_total = curr_cpu_idle, curr_cpu_total
                cpu_str = f"{cpu_value:.1f}%"

                used, total, percent = read_mem()
                ram_str = f"{percent:.1f}%  ({bytes_auto(used)} / {bytes_auto(total)})"
                try:
                    disk_total, disk_used, _ = shutil.disk_usage("/")
                    disk_percent = (disk_used / disk_total) * 100 if disk_total > 0 else 0.0
                    disk_str = f"{disk_percent:.1f}%  ({bytes_auto(disk_used)} / {bytes_auto(disk_total)})"
                except OSError:
                    disk_str = "н/д"

            current_net = read_net()
            now = time.time()
            elapsed = max(now - last_time, 1.0)
            rx_speed = max(0.0, (current_net[0] - prev_net[0]) / elapsed)
            tx_speed = max(0.0, (current_net[1] - prev_net[1]) / elapsed)
            prev_net = current_net
            last_time = now

            panel(
                "Текущие параметры",
                [
                    kv("Загрузка CPU:", cpu_str),
                    kv("Использование RAM:", ram_str),
                    kv("Дисковое пространство:", disk_str),
                    f"  {DIM}{'─' * (PANEL_W - 2)}{NC}",
                    kv("Сетевой вход (Rx):", f"{GREEN}{bytes_auto(int(rx_speed))}/s{NC}"),
                    kv("Сетевой выход (Tx):", f"{CYAN}{bytes_auto(int(tx_speed))}/s{NC}"),
                ],
            )
            time.sleep(1)
        except (KeyboardInterrupt, SystemExit):
            return
        except Exception as exc:
            error(f"Ошибка мониторинга: {exc}")
            time.sleep(2)
