"""Linux/local-host implementation of the system monitoring port."""
from __future__ import annotations

import os
import shutil
import time
from pathlib import Path

from hydra.services.system_monitoring import SystemMetrics, SystemMonitoring


class HostSystemMonitoring(SystemMonitoring):
    """Collect bounded host metrics without leaking procfs into the UI."""

    def cpu_counters(self, stat_path: object | None = None) -> tuple[float, float]:
        path = Path("/proc/stat") if stat_path is None else Path(stat_path)
        try:
            line = path.read_text(encoding="utf-8").splitlines()[0]
            if line.startswith("cpu"):
                parts = [float(value) for value in line.split()[1:8]]
                return parts[3] + parts[4], sum(parts)
        except (OSError, IndexError, TypeError, ValueError):
            pass
        return 0.0, 0.0

    def memory_usage(
        self,
        meminfo_path: object | None = None,
    ) -> tuple[int, int, float]:
        path = Path("/proc/meminfo") if meminfo_path is None else Path(meminfo_path)
        try:
            meminfo: dict[str, int] = {}
            for line in path.read_text(encoding="utf-8").splitlines():
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
            percent = (used / total) * 100 if total > 0 else 0.0
            return used, total, percent
        except (OSError, TypeError, ValueError):
            return 0, 0, 0.0

    def network_counters(
        self,
        route_path: object | None = None,
        dev_path: object | None = None,
    ) -> tuple[int, int]:
        route = Path("/proc/net/route") if route_path is None else Path(route_path)
        devices = Path("/proc/net/dev") if dev_path is None else Path(dev_path)
        try:
            default_ifaces: set[str] = set()
            try:
                for line in route.read_text(encoding="utf-8").splitlines()[1:]:
                    fields = line.split()
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
            for line in devices.read_text(encoding="utf-8").splitlines()[2:]:
                if ":" not in line:
                    continue
                iface, counters = line.split(":", 1)
                iface = iface.strip()
                if iface == "lo" or (
                    default_ifaces and iface not in default_ifaces
                ):
                    continue
                parts = counters.split()
                if len(parts) >= 9:
                    rx += int(parts[0])
                    tx += int(parts[8])
            return rx, tx
        except (OSError, TypeError, ValueError):
            return 0, 0

    def snapshot(self) -> SystemMetrics:
        try:
            import psutil
        except ImportError:
            psutil = None

        if psutil is not None:
            cpu = float(psutil.cpu_percent(interval=0))
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage("/")
            memory_used = int(memory.used)
            memory_total = int(memory.total)
            memory_percent = float(memory.percent)
            disk_used = int(disk.used)
            disk_total = int(disk.total)
            disk_percent = float(disk.percent)
        else:
            cpu = None
            memory_used, memory_total, memory_percent = self.memory_usage()
            try:
                disk_total, disk_used, _ = shutil.disk_usage("/")
                disk_percent = (
                    (disk_used / disk_total) * 100 if disk_total > 0 else 0.0
                )
            except OSError:
                disk_used = 0
                disk_total = 0
                disk_percent = 0.0

        network_rx, network_tx = self.network_counters()
        return SystemMetrics(
            cpu_percent=cpu,
            memory_used=memory_used,
            memory_total=memory_total,
            memory_percent=memory_percent,
            disk_used=disk_used,
            disk_total=disk_total,
            disk_percent=disk_percent,
            network_rx=network_rx,
            network_tx=network_tx,
        )

    def load_averages(self) -> tuple[float, float] | None:
        if os.name == "nt":
            return None
        try:
            average_1, average_5, _ = os.getloadavg()
            return float(average_1), float(average_5)
        except (AttributeError, OSError):
            return None

    def now(self) -> float:
        return time.time()

    def local_time(self, format_string: str) -> str:
        return time.strftime(format_string)

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)

    def maintain_traffic_log(self) -> None:
        from hydra.services.traffic_daemon import maintain_traffic_log

        maintain_traffic_log()

    def sync_agent_log_path(self) -> str:
        return "/var/log/hydra/sync-agent.log"

    def is_windows(self) -> bool:
        return os.name == "nt"


HOST_MONITORING = HostSystemMonitoring()
