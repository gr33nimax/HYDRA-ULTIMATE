"""hydra/core/nft.py — nftables TPROXY: заворот трафика транспортов в sing-box."""
from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hydra.plugins.base import ConfigFragment

NFT_TABLE = "hydra-tproxy"


def _ensure_tproxy_modules():
    """Загружает kernel modules, необходимые для nftables TPROXY."""
    for mod in ("nft_tproxy", "nf_tproxy_ipv4", "nf_tproxy_ipv6"):
        subprocess.run(
            ["modprobe", mod],
            capture_output=True,
        )


def _ensure_policy_routing():
    """Настраивает ip rule + ip route для TPROXY (fwmark 0x1 → local routing)."""
    r = subprocess.run(
        ["ip", "rule", "show", "fwmark", "0x1"],
        capture_output=True, text=True,
    )
    if "0x1" not in r.stdout:
        subprocess.run(["ip", "rule", "add", "fwmark", "0x1", "table", "100"],
                       capture_output=True)

    r = subprocess.run(
        ["ip", "route", "show", "table", "100"],
        capture_output=True, text=True,
    )
    if "local" not in r.stdout:
        subprocess.run(
            ["ip", "route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", "100"],
            capture_output=True,
        )


def _cleanup_policy_routing():
    """Удаляет policy routing правила TPROXY."""
    subprocess.run(["ip", "rule", "del", "fwmark", "0x1", "table", "100"],
                   capture_output=True)
    subprocess.run(["ip", "route", "flush", "table", "100"],
                   capture_output=True)


def apply_tproxy(fragments: dict, tproxy_port: int = 1081) -> None:
    _ensure_tproxy_modules()

    ports: set[int] = set()
    ifaces: set[str] = set()
    for frag in fragments.values():
        ports.update(getattr(frag, "nft_tproxy_ports", []))
        ifaces.update(getattr(frag, "nft_tproxy_ifaces", []))

    subprocess.run(
        ["nft", "delete", "table", "inet", NFT_TABLE],
        capture_output=True,
    )

    if not ports and not ifaces:
        _cleanup_policy_routing()
        return

    ruleset = f"table inet {NFT_TABLE} {{\n"
    ruleset += "    chain prerouting {\n"
    ruleset += "        type filter hook prerouting priority mangle; policy accept;\n"
    ruleset += "        meta mark 0xff return\n"
    ruleset += "        ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8 } return\n"

    if ports:
        port_list = ", ".join(str(p) for p in sorted(ports))
        ruleset += (
            f"        meta l4proto {{ tcp, udp }} th dport {{ {port_list} }} "
            f"meta mark set 0x1 tproxy ip to 127.0.0.1:{tproxy_port} accept\n"
        )

    for iface in sorted(ifaces):
        ruleset += (
            f'        iifname "{iface}" meta l4proto {{ tcp, udp }} '
            f"meta mark set 0x1 tproxy ip to 127.0.0.1:{tproxy_port} accept\n"
        )

    ruleset += "    }\n"

    if ports:
        port_list = ", ".join(str(p) for p in sorted(ports))
        ruleset += "    chain output {\n"
        ruleset += "        type route hook output priority mangle; policy accept;\n"
        ruleset += f"        meta l4proto {{ tcp, udp }} th dport {{ {port_list} }} meta mark set 0x1\n"
        ruleset += "    }\n"

    ruleset += "}\n"

    subprocess.run(
        ["nft", "-f", "-"],
        input=ruleset.encode(),
        capture_output=True,
    )

    _ensure_policy_routing()


def clear_tproxy() -> None:
    subprocess.run(
        ["nft", "delete", "table", "inet", NFT_TABLE],
        capture_output=True,
    )
    _cleanup_policy_routing()


def persist() -> None:
    try:
        result = subprocess.run(
            ["nft", "list", "ruleset"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            from pathlib import Path
            Path("/etc/nftables.conf").write_text(result.stdout)
    except Exception:
        pass
