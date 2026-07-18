"""Host-wide network tuning for proxy workloads.

The profile is deliberately limited to networking.  It is safe to apply more
than once, ignores kernel parameters unavailable on the current host and keeps
the original runtime values so an administrator can roll the profile back.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any


SYSCTL_CONF = Path("/etc/sysctl.d/99-hydra-network-tuning.conf")
BACKUP_FILE = Path("/var/lib/hydra/network-tuning-backup.json")
LEGACY_CONF = Path("/etc/sysctl.d/99-hydra-tuning.conf")

_CAPACITY_KEYS = {
    "net.core.somaxconn",
    "net.core.netdev_max_backlog",
    "net.core.rmem_max",
    "net.core.wmem_max",
    "net.ipv4.tcp_max_syn_backlog",
    "net.netfilter.nf_conntrack_max",
}


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True)


def _sysctl_get(key: str) -> str | None:
    try:
        result = _run(["sysctl", "-n", key])
    except (FileNotFoundError, OSError):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def _memory_bytes() -> int:
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        pass
    return 0


def _buffer_size(memory_bytes: int | None = None) -> int:
    """Choose useful buffers without reserving an excessive amount of RAM."""
    total = _memory_bytes() if memory_bytes is None else memory_bytes
    if total and total < 1024**3:
        return 8 * 1024**2
    if total and total < 4 * 1024**3:
        return 16 * 1024**2
    return 32 * 1024**2


def desired_sysctls(memory_bytes: int | None = None) -> dict[str, str]:
    total = _memory_bytes() if memory_bytes is None else memory_bytes
    buffer_size = _buffer_size(total)
    if total and total < 1024**3:
        conntrack_max = 65536
    elif total and total < 4 * 1024**3:
        conntrack_max = 131072
    else:
        conntrack_max = 262144
    return {
        "net.ipv4.ip_forward": "1",
        "net.ipv6.conf.all.forwarding": "1",
        "net.core.default_qdisc": "fq",
        "net.ipv4.tcp_congestion_control": "bbr",
        "net.core.somaxconn": "65535",
        "net.core.netdev_max_backlog": "16384",
        "net.core.rmem_max": str(buffer_size),
        "net.core.wmem_max": str(buffer_size),
        "net.core.rmem_default": "262144",
        "net.core.wmem_default": "262144",
        "net.ipv4.tcp_rmem": f"4096 87380 {buffer_size}",
        "net.ipv4.tcp_wmem": f"4096 65536 {buffer_size}",
        "net.ipv4.udp_rmem_min": "8192",
        "net.ipv4.udp_wmem_min": "8192",
        "net.ipv4.tcp_max_syn_backlog": "65535",
        "net.ipv4.tcp_syncookies": "1",
        "net.ipv4.tcp_tw_reuse": "1",
        "net.ipv4.tcp_fastopen": "3",
        "net.ipv4.tcp_mtu_probing": "1",
        "net.ipv4.tcp_fin_timeout": "15",
        "net.ipv4.tcp_keepalive_time": "600",
        "net.ipv4.tcp_keepalive_intvl": "30",
        "net.ipv4.tcp_keepalive_probes": "5",
        "net.ipv4.ip_local_port_range": "10240 65535",
        "net.netfilter.nf_conntrack_max": str(conntrack_max),
    }


def _read_optional(path: Path) -> dict[str, Any]:
    return {
        "exists": path.exists(),
        "content": path.read_text(encoding="utf-8") if path.exists() else "",
    }


def _ensure_bbr_available() -> bool:
    available = _sysctl_get("net.ipv4.tcp_available_congestion_control") or ""
    if "bbr" in available.split():
        return True
    try:
        _run(["modprobe", "tcp_bbr"])
    except (FileNotFoundError, OSError):
        return False
    available = _sysctl_get("net.ipv4.tcp_available_congestion_control") or ""
    return "bbr" in available.split()


def _write_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(content, encoding="utf-8")
    os.replace(temporary, path)


def apply_network_tuning(memory_bytes: int | None = None) -> dict[str, Any]:
    """Apply and persist the HYDRA proxy networking profile."""
    targets = desired_sysctls(memory_bytes)
    bbr_available = _ensure_bbr_available()
    if not bbr_available:
        targets.pop("net.ipv4.tcp_congestion_control", None)

    current = {key: _sysctl_get(key) for key in targets}
    supported = {key: value for key, value in current.items() if value is not None}

    # Never reduce capacity when the administrator or hosting image already
    # provides a larger queue/table/buffer than the HYDRA baseline.
    for key in _CAPACITY_KEYS:
        old = current.get(key)
        if old is None or key not in targets:
            continue
        try:
            targets[key] = str(max(int(old), int(targets[key])))
        except ValueError:
            pass

    if not BACKUP_FILE.exists():
        backup = {
            "version": 1,
            "values": supported,
            "config": _read_optional(SYSCTL_CONF),
            "legacy_config": _read_optional(LEGACY_CONF),
        }
        _write_atomic(BACKUP_FILE, json.dumps(backup, ensure_ascii=False, indent=2) + "\n")

    results: dict[str, dict[str, Any]] = {}
    persistent: list[str] = ["# Managed by HYDRA. Use the TUI rollback action to restore previous values."]
    errors: list[str] = []

    for key, target in targets.items():
        old = current.get(key)
        if old is None:
            results[key] = {"old": "", "new": "", "changed": False, "skipped": "unsupported"}
            continue
        changed = old != target
        if changed:
            result = _run(["sysctl", "-w", f"{key}={target}"])
            if result.returncode != 0:
                message = (result.stderr or result.stdout).strip() or "sysctl rejected the value"
                errors.append(f"{key}: {message}")
                results[key] = {"old": old, "new": old, "changed": False, "error": message}
                continue
        persistent.append(f"{key} = {target}")
        results[key] = {"old": old, "new": target, "changed": changed}

    _write_atomic(SYSCTL_CONF, "\n".join(persistent) + "\n")
    if LEGACY_CONF.exists():
        LEGACY_CONF.unlink()

    return {
        "success": not errors,
        "sysctl": results,
        "bbr_available": bbr_available,
        "config_path": str(SYSCTL_CONF),
        "errors": errors,
    }


def rollback_network_tuning() -> dict[str, Any]:
    """Restore the values and HYDRA-owned files saved before first apply."""
    if not BACKUP_FILE.exists():
        return {"success": False, "restored": 0, "errors": ["Резервная копия не найдена"]}

    try:
        backup = json.loads(BACKUP_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"success": False, "restored": 0, "errors": [str(exc)]}

    restored = 0
    errors: list[str] = []
    for key, value in backup.get("values", {}).items():
        result = _run(["sysctl", "-w", f"{key}={value}"])
        if result.returncode == 0:
            restored += 1
        else:
            errors.append(f"{key}: {(result.stderr or result.stdout).strip()}")

    for path, saved in (
        (SYSCTL_CONF, backup.get("config", {})),
        (LEGACY_CONF, backup.get("legacy_config", {})),
    ):
        try:
            if saved.get("exists"):
                _write_atomic(path, saved.get("content", ""))
            elif path.exists():
                path.unlink()
        except OSError as exc:
            errors.append(f"{path}: {exc}")

    if not errors:
        BACKUP_FILE.unlink()
    return {"success": not errors, "restored": restored, "errors": errors}


def tuning_is_applied() -> bool:
    return SYSCTL_CONF.exists() and BACKUP_FILE.exists()
