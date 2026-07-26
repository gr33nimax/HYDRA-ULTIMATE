"""Runtime side effects and counters for ShadowTLS."""
from __future__ import annotations

from collections.abc import Callable

from hydra.plugins.context import PluginStateAccess


def on_enable(
    state: PluginStateAccess,
    *,
    validate_sni: Callable[[str, PluginStateAccess], str],
    remove_iptables_rules: Callable[[], None],
    add_iptables_rules: Callable[[], None],
) -> None:
    protocol = state.protocols.get("shadowtls")
    if not protocol:
        raise ValueError("ShadowTLS configuration is missing")

    handshake_sni = str(
        protocol.config.get("handshake_sni", "")
    ).strip()
    if not handshake_sni:
        raise ValueError(
            "SNI ShadowTLS не настроен; "
            "задайте handshake_sni перед включением",
        )
    validate_sni(handshake_sni, state)

    from hydra.utils.firewall import open_tcp

    open_tcp(443, "shadowtls")
    remove_iptables_rules()
    add_iptables_rules()


def remove_iptables_rules(host) -> None:
    for chain in ("INPUT", "OUTPUT"):
        result = host.run(
            ["iptables", "-S", chain],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            continue
        for line in result.stdout.splitlines():
            if "shadowtls-" not in line:
                continue
            parts = line.split()
            if parts and parts[0] == "-A":
                parts[0] = "-D"
                host.run(
                    ["iptables"] + parts,
                    capture_output=True,
                )


def add_iptables_rules(host) -> None:
    host.run(
        [
            "iptables",
            "-I",
            "INPUT",
            "1",
            "-p",
            "tcp",
            "--dport",
            "443",
            "-m",
            "comment",
            "--comment",
            "shadowtls-rx",
        ],
        capture_output=True,
    )
    host.run(
        [
            "iptables",
            "-I",
            "OUTPUT",
            "1",
            "-p",
            "tcp",
            "--sport",
            "443",
            "-m",
            "comment",
            "--comment",
            "shadowtls-tx",
        ],
        capture_output=True,
    )


def total_traffic(host) -> int:
    total_bytes = 0
    for chain in ("INPUT", "OUTPUT"):
        result = host.run(
            [
                "iptables",
                "-t",
                "filter",
                "-L",
                chain,
                "-n",
                "-v",
                "-x",
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            continue
        for line in result.stdout.splitlines():
            if "shadowtls-" not in line:
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                total_bytes += int(parts[1])
    return total_bytes
