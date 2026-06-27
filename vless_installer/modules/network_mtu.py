"""
vless_installer/modules/network_mtu.py
──────────────────────────────────────────────────────────────────────────────
MTU/MSS утилиты для HYDRA (AWG, WARP, exit-ноды).

Используется из do_mtu_tuning() в _core.py и сетевого меню.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

AWG_RECOMMENDED_MTU = 1280
DEFAULT_MTU = 1500
_MSS_STATE = Path("/var/lib/xray-installer/mtu_state.json")


def recommend_mtu_for_awg() -> int:
    """Рекомендуемый MTU для AmneziaWG-туннеля."""
    return AWG_RECOMMENDED_MTU


def get_iface_mtu(iface: str) -> int:
    try:
        r = subprocess.run(
            ["cat", f"/sys/class/net/{iface}/mtu"],
            capture_output=True, text=True, check=False,
        )
        val = (r.stdout or "").strip()
        return int(val) if val.isdigit() else DEFAULT_MTU
    except Exception:
        return DEFAULT_MTU


def apply_link_mtu(iface: str, mtu: int) -> bool:
    if not iface or mtu < 576:
        return False
    r = subprocess.run(
        ["ip", "link", "set", "dev", iface, "mtu", str(mtu)],
        capture_output=True, check=False,
    )
    return r.returncode == 0


def apply_mss_clamp(mtu: int, table: str = "mangle", chain: str = "FORWARD") -> bool:
    """TCP MSS clamp: MSS = MTU - 40 (IPv4)."""
    mss = max(mtu - 40, 536)
    subprocess.run(
        ["iptables", "-t", table, "-D", chain, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
         "-j", "TCPMSS", "--set-mss", str(mss)],
        capture_output=True, check=False,
    )
    r = subprocess.run(
        ["iptables", "-t", table, "-A", chain, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
         "-j", "TCPMSS", "--set-mss", str(mss)],
        capture_output=True, check=False,
    )
    return r.returncode == 0


def clear_mss_clamp(table: str = "mangle", chain: str = "FORWARD") -> None:
    while True:
        r = subprocess.run(
            ["iptables", "-t", table, "-L", chain, "-n", "--line-numbers"],
            capture_output=True, text=True, check=False,
        )
        if r.returncode != 0:
            break
        removed = False
        for line in (r.stdout or "").splitlines():
            if "TCPMSS" in line and "set-mss" in line.lower():
                num = line.split()[0]
                if num.isdigit():
                    subprocess.run(
                        ["iptables", "-t", table, "-D", chain, int(num)],
                        capture_output=True, check=False,
                    )
                    removed = True
                    break
        if not removed:
            break


def save_mtu_state(data: dict) -> None:
    import json
    from datetime import datetime

    _MSS_STATE.parent.mkdir(parents=True, exist_ok=True)
    data.setdefault("timestamp", datetime.now().isoformat())
    _MSS_STATE.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def load_mtu_state() -> dict | None:
    import json
    if not _MSS_STATE.exists():
        return None
    try:
        return json.loads(_MSS_STATE.read_text(encoding="utf-8"))
    except Exception:
        return None
