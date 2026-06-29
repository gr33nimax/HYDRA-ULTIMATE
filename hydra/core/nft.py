"""hydra/core/nft.py — nftables TPROXY: заворот трафика транспортов в sing-box."""
from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hydra.plugins.base import ConfigFragment

NFT_TABLE = "hydra-tproxy"


def apply_tproxy(fragments: dict, tproxy_port: int = 1081) -> None:
    ports: set[int] = set()
    for frag in fragments.values():
        ports.update(getattr(frag, "nft_tproxy_ports", []))

    subprocess.run(
        ["nft", "delete", "table", "inet", NFT_TABLE],
        capture_output=True,
    )

    if not ports:
        return

    port_list = ", ".join(str(p) for p in sorted(ports))
    ruleset = f"""
table inet {NFT_TABLE} {{
    chain prerouting {{
        type filter hook prerouting priority mangle; policy accept;
        meta l4proto {{ tcp, udp }} th dport {{ {port_list} }} \\
            meta mark set 0x1 tproxy ip to 127.0.0.1:{tproxy_port} accept
    }}
    chain output {{
        type route hook output priority mangle; policy accept;
        meta l4proto {{ tcp, udp }} th dport {{ {port_list} }} meta mark set 0x1
    }}
}}
"""
    subprocess.run(
        ["nft", "-f", "-"],
        input=ruleset.encode(),
        capture_output=True,
    )


def clear_tproxy() -> None:
    subprocess.run(
        ["nft", "delete", "table", "inet", NFT_TABLE],
        capture_output=True,
    )


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
