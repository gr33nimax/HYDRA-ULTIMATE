"""Transport-neutral system monitoring capabilities."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class SystemMetrics:
    """One host metrics sample suitable for presentation."""

    cpu_percent: float | None
    memory_used: int
    memory_total: int
    memory_percent: float
    disk_used: int
    disk_total: int
    disk_percent: float
    network_rx: int
    network_tx: int


class SystemMonitoring(Protocol):
    """Read-only host metrics plus bounded monitoring maintenance."""

    def cpu_counters(self, stat_path: object | None = None) -> tuple[float, float]: ...

    def memory_usage(
        self,
        meminfo_path: object | None = None,
    ) -> tuple[int, int, float]: ...

    def network_counters(
        self,
        route_path: object | None = None,
        dev_path: object | None = None,
    ) -> tuple[int, int]: ...

    def snapshot(self) -> SystemMetrics: ...

    def load_averages(self) -> tuple[float, float] | None: ...

    def now(self) -> float: ...

    def local_time(self, format_string: str) -> str: ...

    def sleep(self, seconds: float) -> None: ...

    def maintain_traffic_log(self) -> None: ...

    def sync_agent_log_path(self) -> str: ...

    def is_windows(self) -> bool: ...


class UnavailableSystemMonitoring:
    """Default for application instances assembled without host metrics."""

    def __getattr__(self, name: str):
        raise RuntimeError(f"system monitoring is not configured: {name}")
