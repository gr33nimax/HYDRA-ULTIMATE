"""Linux observation helpers for Hydra VK Tunnel telemetry."""
from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

from hydra.core.host import HostBackend
from hydra.services.system_monitoring import SystemMonitoring


def collect_host_metrics(monitoring: SystemMonitoring) -> dict[str, object]:
    try:
        snapshot = monitoring.snapshot()
        idle, total = monitoring.cpu_counters()
        loads = monitoring.load_averages() or (0.0, 0.0)
        return {
            "cpu_idle": idle,
            "cpu_total": total,
            "cpu_percent": snapshot.cpu_percent,
            "memory_used_bytes": snapshot.memory_used,
            "memory_total_bytes": snapshot.memory_total,
            "memory_percent": snapshot.memory_percent,
            "network_rx_bytes": snapshot.network_rx,
            "network_tx_bytes": snapshot.network_tx,
            "load_1": loads[0],
            "load_5": loads[1],
        }
    except Exception:
        return {}


def collect_runtime_metrics(
    host: HostBackend,
    proc_root: Path,
    *,
    page_size: int,
    clock_ticks_per_second: int,
) -> dict[str, object]:
    values = _systemd_runtime(host)
    pid = _integer(values.get("MainPID"))
    metrics: dict[str, object] = {
        "active": values.get("ActiveState") == "active",
        "pid": pid,
        "restarts": _integer(values.get("NRestarts")),
        "clock_ticks_per_second": clock_ticks_per_second,
    }
    if not pid:
        return metrics
    process_root = proc_root / str(pid)
    try:
        raw = (process_root / "stat").read_text(encoding="utf-8")
        fields = raw[raw.rfind(")") + 2 :].split()
        metrics.update({
            "minor_faults": _field(fields, 7),
            "major_faults": _field(fields, 9),
            "cpu_ticks": _field(fields, 11) + _field(fields, 12),
            "threads": _field(fields, 17),
            "rss_bytes": _field(fields, 21) * page_size,
        })
    except OSError:
        pass
    status = _read_key_values(process_root / "status", separator=":")
    io_values = _read_key_values(process_root / "io", separator=":")
    metrics.update({
        "rss_peak_bytes": _kilobytes(status.get("VmHWM")),
        "swap_bytes": _kilobytes(status.get("VmSwap")),
        "voluntary_context_switches": _integer(status.get("voluntary_ctxt_switches")),
        "involuntary_context_switches": _integer(
            status.get("nonvoluntary_ctxt_switches"),
        ),
        "read_bytes": _integer(io_values.get("read_bytes")),
        "write_bytes": _integer(io_values.get("write_bytes")),
        "read_syscalls": _integer(io_values.get("syscr")),
        "write_syscalls": _integer(io_values.get("syscw")),
        "open_fds": _directory_entries(process_root / "fd"),
    })
    return metrics


def collect_udp_metrics(proc_root: Path, listen_port: int) -> dict[str, int]:
    counters = _read_udp_counters(proc_root / "net" / "snmp")
    queue = 0
    drops = 0
    if listen_port:
        for name in ("udp", "udp6"):
            current_queue, current_drops = _read_udp_listener(
                proc_root / "net" / name,
                listen_port,
            )
            queue += current_queue
            drops += current_drops
    return counters | {
        "listener_rx_queue_bytes": queue,
        "listener_drops": drops,
    }


def collect_kernel_metrics(proc_root: Path, data_dir: Path) -> dict[str, object]:
    result: dict[str, object] = {
        "pressure": {
            name: _read_pressure(proc_root / "pressure" / name)
            for name in ("cpu", "memory", "io")
        },
        "softnet": _read_softnet(proc_root / "net" / "softnet_stat"),
        "interfaces": _read_network_devices(proc_root / "net" / "dev"),
        "system": _read_system_counters(proc_root / "stat"),
        "memory": _read_memory_pressure(proc_root / "meminfo"),
        "conntrack": {
            "count": _read_integer(proc_root / "sys/net/netfilter/nf_conntrack_count"),
            "max": _read_integer(proc_root / "sys/net/netfilter/nf_conntrack_max"),
        },
    }
    try:
        disk = shutil.disk_usage(data_dir)
        result["telemetry_disk"] = {
            "total_bytes": disk.total,
            "used_bytes": disk.used,
            "free_bytes": disk.free,
        }
    except OSError:
        result["telemetry_disk"] = {}
    return result


def collect_environment(
    host: HostBackend,
    proc_root: Path,
    sys_root: Path = Path("/sys"),
) -> dict[str, object]:
    environment: dict[str, object] = {
        "logical_cpus": os.cpu_count() or 0,
        "socket_limits": _socket_limits(proc_root),
        "network_devices": _network_device_shape(sys_root),
    }
    environment["kernel"] = _command_output(host, ["uname", "-srvmo"], timeout=3)
    binary = host.which("sing-box")
    if binary:
        environment["core_version"] = _command_output(
            host,
            [binary, "version"],
            timeout=5,
        ).splitlines()[0:1]
        capabilities = _command_json(
            host,
            [binary, "hydra", "capabilities", "--json"],
            timeout=10,
        )
        environment["core_contract"] = _safe_core_contract(capabilities)
    return environment


def system_clock_ticks() -> int:
    return _sysconf("SC_CLK_TCK", 100)


def system_page_size() -> int:
    return _sysconf("SC_PAGE_SIZE", 4096)


def _systemd_runtime(host: HostBackend) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        result = host.run(
            [
                "systemctl",
                "show",
                "sing-box",
                "--property=MainPID",
                "--property=NRestarts",
                "--property=ActiveState",
            ],
            capture_output=True,
            text=True,
            timeout=3,
        )
        if result.returncode == 0:
            for line in str(result.stdout or "").splitlines():
                key, separator, value = line.partition("=")
                if separator:
                    values[key] = value
    except Exception:
        pass
    return values


def _read_udp_counters(path: Path) -> dict[str, int]:
    empty = {
        "in_datagrams": 0,
        "out_datagrams": 0,
        "in_errors": 0,
        "no_ports": 0,
        "receive_buffer_errors": 0,
        "send_buffer_errors": 0,
        "ignored_multicast": 0,
    }
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return empty
    for index, line in enumerate(lines[:-1]):
        if not line.startswith("Udp:") or not lines[index + 1].startswith("Udp:"):
            continue
        names = line.split()[1:]
        values = lines[index + 1].split()[1:]
        raw = {name: _integer(value) for name, value in zip(names, values)}
        return {
            "in_datagrams": raw.get("InDatagrams", 0),
            "out_datagrams": raw.get("OutDatagrams", 0),
            "in_errors": raw.get("InErrors", 0),
            "no_ports": raw.get("NoPorts", 0),
            "receive_buffer_errors": raw.get("RcvbufErrors", 0),
            "send_buffer_errors": raw.get("SndbufErrors", 0),
            "ignored_multicast": raw.get("IgnoredMulti", 0),
        }
    return empty


def _read_udp_listener(path: Path, listen_port: int) -> tuple[int, int]:
    queue = 0
    drops = 0
    try:
        lines = path.read_text(encoding="utf-8").splitlines()[1:]
    except OSError:
        return queue, drops
    for line in lines:
        fields = line.split()
        try:
            port = int(fields[1].rsplit(":", 1)[1], 16)
            rx_queue = int(fields[4].split(":", 1)[1], 16)
            row_drops = int(fields[-1])
        except (IndexError, TypeError, ValueError):
            continue
        if port == listen_port:
            queue += rx_queue
            drops += row_drops
    return queue, drops


def _read_pressure(path: Path) -> dict[str, object]:
    result: dict[str, object] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return result
    for line in lines:
        fields = line.split()
        if not fields:
            continue
        values: dict[str, float | int] = {}
        for field in fields[1:]:
            key, separator, raw = field.partition("=")
            if not separator:
                continue
            try:
                values[key] = int(raw) if key == "total" else float(raw)
            except ValueError:
                continue
        result[fields[0]] = values
    return result


def _read_softnet(path: Path) -> dict[str, int]:
    totals = {"processed": 0, "dropped": 0, "time_squeeze": 0, "cpu_count": 0}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return totals
    for line in lines:
        fields = line.split()
        if len(fields) < 3:
            continue
        try:
            totals["processed"] += int(fields[0], 16)
            totals["dropped"] += int(fields[1], 16)
            totals["time_squeeze"] += int(fields[2], 16)
            totals["cpu_count"] += 1
        except ValueError:
            continue
    return totals


def _read_network_devices(path: Path) -> dict[str, int]:
    keys = (
        "rx_bytes", "rx_packets", "rx_errors", "rx_drops",
        "tx_bytes", "tx_packets", "tx_errors", "tx_drops",
    )
    totals = {key: 0 for key in keys}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()[2:]
    except OSError:
        return totals
    for line in lines:
        name, separator, raw = line.partition(":")
        fields = raw.split()
        if not separator or name.strip() == "lo" or len(fields) < 16:
            continue
        indexes = (0, 1, 2, 3, 8, 9, 10, 11)
        for key, index in zip(keys, indexes):
            totals[key] += _integer(fields[index])
    return totals


def _read_system_counters(path: Path) -> dict[str, int]:
    wanted = {"ctxt", "processes", "procs_running", "procs_blocked", "intr"}
    result = {key: 0 for key in wanted}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return result
    for line in lines:
        fields = line.split()
        if fields and fields[0] in wanted and len(fields) > 1:
            result[fields[0]] = _integer(fields[1])
    return result


def _read_memory_pressure(path: Path) -> dict[str, int]:
    values = _read_key_values(path, separator=":")
    return {
        "swap_total_bytes": _kilobytes(values.get("SwapTotal")),
        "swap_free_bytes": _kilobytes(values.get("SwapFree")),
        "dirty_bytes": _kilobytes(values.get("Dirty")),
        "writeback_bytes": _kilobytes(values.get("Writeback")),
    }


def _socket_limits(proc_root: Path) -> dict[str, object]:
    names = (
        "core/rmem_default", "core/rmem_max", "core/wmem_default",
        "core/wmem_max", "core/netdev_max_backlog", "core/somaxconn",
    )
    return {name.replace("/", "_"): _read_integer(proc_root / "sys/net" / name) for name in names}


def _network_device_shape(sys_root: Path) -> dict[str, object]:
    mtus: list[int] = []
    try:
        devices = list((sys_root / "class/net").iterdir())
    except OSError:
        devices = []
    for device in devices:
        if device.name == "lo":
            continue
        mtu = _read_integer(device / "mtu")
        if mtu:
            mtus.append(mtu)
    return {
        "count": len(mtus),
        "minimum_mtu": min(mtus, default=0),
        "maximum_mtu": max(mtus, default=0),
    }


def _safe_core_contract(payload: dict[str, object]) -> dict[str, object]:
    return {
        key: payload.get(key, {})
        for key in ("identity", "features", "protocols", "runtime")
        if isinstance(payload.get(key), dict)
    }


def _command_output(host: HostBackend, command: list[str], *, timeout: int) -> str:
    try:
        result = host.run(command, capture_output=True, text=True, timeout=timeout)
    except Exception:
        return ""
    return str(result.stdout or "").strip() if result.returncode == 0 else ""


def _command_json(host: HostBackend, command: list[str], *, timeout: int) -> dict[str, object]:
    try:
        payload = json.loads(_command_output(host, command, timeout=timeout))
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def _read_key_values(path: Path, *, separator: str) -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return result
    for line in lines:
        key, found, value = line.partition(separator)
        if found:
            result[key.strip()] = value.strip()
    return result


def _read_integer(path: Path) -> int:
    try:
        return _integer(path.read_text(encoding="utf-8").strip().split()[0])
    except (IndexError, OSError):
        return 0


def _directory_entries(path: Path) -> int:
    try:
        return sum(1 for _ in path.iterdir())
    except OSError:
        return 0


def _kilobytes(value: object) -> int:
    raw = str(value or "").split()[0:1]
    return _integer(raw[0]) * 1024 if raw else 0


def _field(fields: list[str], index: int) -> int:
    try:
        return max(0, int(fields[index]))
    except (IndexError, ValueError):
        return 0


def _sysconf(name: str, fallback: int) -> int:
    try:
        return max(1, int(os.sysconf(name)))
    except (AttributeError, OSError, TypeError, ValueError):
        return fallback


def _integer(value: object) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


__all__ = [
    "collect_environment",
    "collect_host_metrics",
    "collect_kernel_metrics",
    "collect_runtime_metrics",
    "collect_udp_metrics",
    "system_clock_ticks",
    "system_page_size",
]
