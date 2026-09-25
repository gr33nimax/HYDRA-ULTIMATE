"""Idempotent teardown of pre-native WARP/AmneziaWG sidecars on upgrade.

Older installs ran WARP through a ``wg-quick@wg-warp`` sidecar and AmneziaWG
through ``awg-quick@awg0``/``awg1`` units; the native HydraCore kernel owns both
transports now. This removes only the *conflicting runtime* the old scheme left
behind — systemd units, network interfaces, its iptables rules, and its files —
so the native modules come up clean.

Deliberately NOT touched:
- the ``amneziawg`` kernel module and its apt packages (removing them is risky
  on a live host and unnecessary: the native core does not use them);
- the live native ``fwmark``/nft ``hydra-tproxy`` state (that is the current
  core, not a leftover).

Everything is check-then-remove, so a clean host is a no-op and repeated
upgrades stay idempotent.

ponytail: naive iptables-save line match by interface; safe because the
interface is deleted first, so any missed rule no longer matches traffic.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

# Legacy artifact paths are pinned here rather than imported from the WARP /
# AmneziaWG plugins: hydra.core must not depend on hydra.plugins, and the old
# scheme's locations are frozen (its code is already gone), so a local copy is
# the correct boundary, not shared state.
_LEGACY_UNITS = ("wg-quick@wg-warp", "awg-quick@awg0", "awg-quick@awg1")
_LEGACY_INTERFACES = ("wg-warp", "awg0", "awg1")
_AWG_IPTABLES_INTERFACES = ("awg0", "awg1")
_LEGACY_FILES: tuple[Path, ...] = (
    Path("/etc/wireguard/wg-warp.conf"),
    Path("/usr/local/bin/wgcf"),
    Path("/etc/wireguard/wgcf-profile.conf"),
    Path("/etc/wireguard/wgcf-account.toml"),
    Path("/var/log/hydra/warp_install.log"),
    Path("/etc/amnezia/amneziawg/awg0.conf"),
    Path("/etc/amnezia/amneziawg/awg1.conf"),
    Path("/etc/amnezia/amneziawg/params"),
)
_LEGACY_TREES = (Path("/opt/awg-install"), Path("/tmp/wgcf_config"), Path("/tmp/wgcf"))


def _run(host: Any, args: list[str]) -> tuple[int, str]:
    try:
        result = host.run(args, capture_output=True)
        return int(getattr(result, "returncode", 1)), str(getattr(result, "stdout", "") or "")
    except Exception:
        return 1, ""


def _disable_unit(host: Any, unit: str, removed: dict[str, list[str]]) -> None:
    listed_code, listed = _run(host, ["systemctl", "list-unit-files", f"{unit}.service", "--no-legend"])
    active_code, _active = _run(host, ["systemctl", "is-active", unit])
    present = (listed_code == 0 and listed.strip() != "") or active_code == 0
    if not present:
        return
    _run(host, ["systemctl", "disable", "--now", unit])
    removed["units"].append(unit)


def _delete_interface(host: Any, iface: str, removed: dict[str, list[str]]) -> None:
    if _run(host, ["ip", "link", "show", iface])[0] != 0:
        return
    _run(host, ["ip", "link", "delete", iface])
    removed["interfaces"].append(iface)


def _flush_iptables(host: Any, iface: str, removed: dict[str, list[str]]) -> None:
    for table in ("nat", "filter", "mangle"):
        code, dump = _run(host, ["iptables-save", "-t", table])
        if code != 0:
            continue
        for line in dump.splitlines():
            if not line.startswith("-A "):
                continue
            if f"-o {iface}" not in line and f"-i {iface}" not in line:
                continue
            delete_rule = ("-D " + line[len("-A ") :]).split()
            _run(host, ["iptables", "-t", table, *delete_rule])
            removed["iptables"].append(f"{table} {line}")


def _remove_path(path: Path, removed: dict[str, list[str]]) -> None:
    try:
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        elif path.exists() or path.is_symlink():
            path.unlink(missing_ok=True)
        else:
            return
    except OSError:
        return
    removed["files"].append(str(path))


def purge_legacy_sidecars(host: Any) -> dict[str, list[str]]:
    """Remove leftover wgcf/AmneziaWG sidecar runtime; report what was cleared."""
    removed: dict[str, list[str]] = {"units": [], "interfaces": [], "iptables": [], "files": []}
    for unit in _LEGACY_UNITS:
        _disable_unit(host, unit, removed)
    for iface in _LEGACY_INTERFACES:
        _delete_interface(host, iface, removed)
    for iface in _AWG_IPTABLES_INTERFACES:
        _flush_iptables(host, iface, removed)
    for path in _LEGACY_FILES:
        _remove_path(path, removed)
    for tree in _LEGACY_TREES:
        _remove_path(tree, removed)
    return removed


__all__ = ["purge_legacy_sidecars"]
