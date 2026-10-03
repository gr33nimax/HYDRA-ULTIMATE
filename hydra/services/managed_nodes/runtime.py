"""Host-backed runtime proof for node apply receipts and resource observations."""

from __future__ import annotations

import hashlib
import threading
from pathlib import Path
from typing import Any

from hydra.core.host import HostBackend


class ManagedNodeRuntime:
    """Read actual Sing-Box unit/config facts through an injected host boundary."""

    def __init__(
        self,
        *,
        host: HostBackend,
        config_path: Path,
        unit: str = "sing-box.service",
    ) -> None:
        if not config_path.is_absolute() or not unit.endswith(".service"):
            raise ValueError("managed-node runtime target is invalid")
        self._host = host
        self._config_path = config_path
        self._unit = unit
        self._cpu_lock = threading.Lock()
        self._cpu_previous: tuple[int, int] | None = None

    def observe(self) -> dict[str, Any]:
        result = self._host.run(
            ["systemctl", "show", self._unit, "--property=ActiveState", "--property=MainPID", "--property=ActiveEnterTimestampMonotonic"],
            timeout=3,
            text=True,
        )
        facts = self._parse_unit(result.stdout if result.returncode == 0 else "")
        config_digest = self._config_digest()
        active = facts["active_state"] == "active" and facts["main_pid"] > 0 and bool(config_digest)
        runtime_id = ""
        apply_generation = ""
        if active:
            # Billing follows the engine process; apply proof additionally binds config bytes.
            identity = f"{facts['main_pid']}:{facts['active_since']}".encode()
            runtime_id = hashlib.sha256(identity).hexdigest()
            apply_generation = hashlib.sha256(f"{runtime_id}:{config_digest}".encode()).hexdigest()
        vps_uptime = self._vps_uptime()
        service_uptime = None
        if active and vps_uptime is not None:
            try:
                service_uptime = max(0.0, vps_uptime - int(facts["active_since"]) / 1_000_000)
            except (TypeError, ValueError):
                service_uptime = None
        return {
            "engine": "sing-box",
            "engine_active": active,
            "engine_pid": facts["main_pid"] if active else None,
            "engine_started": facts["active_since"] or None,
            "service_uptime_seconds": service_uptime,
            "vps_uptime_seconds": vps_uptime,
            "config_sha256": config_digest or None,
            "runtime_id": runtime_id or None,
            "apply_generation": apply_generation or None,
        }

    def confirms(self, runtime_id: str) -> bool:
        if not isinstance(runtime_id, str) or not runtime_id:
            return False
        sample = self.observe()
        return sample["engine_active"] is True and sample["runtime_id"] == runtime_id

    def metrics(self) -> dict[str, float | int | None]:
        ram_percent = self._ram_percent()
        current = self._cpu_counters()
        cpu_percent: float | None = None
        with self._cpu_lock:
            previous, self._cpu_previous = self._cpu_previous, current
        if previous is not None and current is not None:
            total_delta = current[0] - previous[0]
            idle_delta = current[1] - previous[1]
            if total_delta > 0 and 0 <= idle_delta <= total_delta:
                cpu_percent = round((total_delta - idle_delta) * 100 / total_delta, 1)
        return {"cpu_percent": cpu_percent, "ram_percent": ram_percent}

    def _ram_percent(self) -> float | None:
        try:
            memory = self._host.read_bytes(Path("/proc/meminfo"), max_bytes=64 * 1024).decode("ascii")
            fields = {line.split(":", 1)[0]: int(line.split(":", 1)[1].split()[0]) for line in memory.splitlines() if ":" in line and line.split(":", 1)[1].split() and line.split(":", 1)[1].split()[0].isdigit()}
            total = fields["MemTotal"]
            available = fields["MemAvailable"]
            return round((total - available) * 100 / total, 1) if total else None
        except (OSError, KeyError, UnicodeDecodeError, ValueError):
            return None

    def _vps_uptime(self) -> float | None:
        try:
            return float(self._host.read_bytes(Path("/proc/uptime"), max_bytes=256).decode("ascii").split()[0])
        except (OSError, IndexError, UnicodeDecodeError, ValueError):
            return None

    def _cpu_counters(self) -> tuple[int, int] | None:
        try:
            line = self._host.read_bytes(Path("/proc/stat"), max_bytes=4096).decode("ascii").splitlines()[0]
            fields = line.split()
            if fields[0] != "cpu" or len(fields) < 5:
                return None
            values = [int(item) for item in fields[1:]]
            return sum(values), values[3] + (values[4] if len(values) > 4 else 0)
        except (OSError, IndexError, UnicodeDecodeError, ValueError):
            return None

    def _config_digest(self) -> str | None:
        if self._config_path.is_symlink() or not self._config_path.is_file():
            return None
        try:
            return hashlib.sha256(self._host.read_bytes(self._config_path, max_bytes=8 * 1024 * 1024)).hexdigest()
        except (OSError, ValueError):
            return None

    @staticmethod
    def _parse_unit(output: str) -> dict[str, Any]:
        values: dict[str, str] = {}
        for line in output.splitlines():
            name, separator, value = line.partition("=")
            if separator:
                values[name] = value
        try:
            pid = int(values.get("MainPID", "0"))
        except ValueError:
            pid = 0
        return {
            "active_state": values.get("ActiveState", "unknown"),
            "main_pid": max(pid, 0),
            "active_since": values.get("ActiveEnterTimestampMonotonic", ""),
        }


__all__ = ["ManagedNodeRuntime"]
