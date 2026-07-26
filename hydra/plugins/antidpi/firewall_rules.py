"""Pure iptables/ipset rule builders and listener discovery."""
from __future__ import annotations

from hydra.plugins.context import PluginStateAccess

SET_V4, SET_V6 = "hydra_antidpi", "hydra_antidpi6"
RULE_COMMENT = "hydra-antidpi"
SCAN_RULE_COMMENT = "hydra-antidpi-scan"
UDP_PROBE_RULE_COMMENT = "hydra-antidpi-udp-probes"
UDP_PROBE_CHAIN = "HYDRA_ANTIDPI_UDP"
MIERU_PROBE_RULE_COMMENT = "hydra-antidpi-mieru-probes"
MIERU_PORT_RANGE = "2012:2022"


def scan_rule(binary: str, protocol: str) -> list[str]:
    """Build a rate-limited LOG-only rule; the scorer decides whether to ban."""
    version = "6" if binary == "ip6tables" else "4"
    if protocol == "tcp":
        transport = ["-p", "tcp", "--syn"]
        threshold, burst, prefix = "120/minute", "60", "HYDRA_SCAN_TCP "
    elif protocol == "udp":
        transport = ["-p", "udp"]
        threshold, burst, prefix = "300/minute", "150", "HYDRA_SCAN_UDP "
    else:
        raise ValueError(f"unsupported scan telemetry protocol: {protocol}")
    return [
        *transport,
        "-m",
        "conntrack",
        "--ctstate",
        "NEW",
        "-m",
        "hashlimit",
        "--hashlimit-above",
        threshold,
        "--hashlimit-burst",
        burst,
        "--hashlimit-mode",
        "srcip",
        "--hashlimit-name",
        f"hydra_adpi_{protocol}{version}",
        "-m",
        "limit",
        "--limit",
        "30/minute",
        "--limit-burst",
        "20",
        "-m",
        "comment",
        "--comment",
        SCAN_RULE_COMMENT,
        "-j",
        "LOG",
        "--log-prefix",
        prefix,
        "--log-level",
        "4",
    ]


def udp_protocol_ports(state: PluginStateAccess) -> dict[int, str]:
    """Return enabled public UDP listeners relevant to protocol probing."""
    result: dict[int, str] = {}

    def add(raw_port: object, owner: str) -> None:
        try:
            port = int(raw_port)
        except (TypeError, ValueError):
            return
        if not 1 <= port <= 65535:
            return
        owners = set(result.get(port, "").split("/")) - {""}
        owners.add(owner)
        result[port] = "/".join(sorted(owners))

    for name in ("hysteria2", "amneziawg", "wdtt", "naive", "trusttunnel"):
        protocol = state.protocols.get(name)
        if not protocol or not protocol.enabled:
            continue
        config = protocol.config if isinstance(protocol.config, dict) else {}
        if name == "amneziawg":
            profiles = config.get("profiles", {})
            if isinstance(profiles, dict):
                for profile in profiles.values():
                    if isinstance(profile, dict) and profile.get("port"):
                        add(profile["port"], name)
            if not any(name in value.split("/") for value in result.values()):
                add(protocol.port or 51820, name)
        elif name == "hysteria2":
            add(config.get("port", protocol.port or 8443), name)
        elif name == "wdtt":
            add(config.get("dtls_port", 56000), name)
        elif (
            name == "naive"
            and str(config.get("network", "tcp")) in {"quic", "both"}
        ):
            add(443, name)
        elif (
            name == "trusttunnel"
            and str(config.get("transport", "tcp")) in {"quic", "both"}
        ):
            add(443, name)
    return {port: result[port] for port in sorted(result)}


def udp_probe_rule(binary: str, port: int) -> list[str]:
    version = "6" if binary == "ip6tables" else "4"
    return [
        "-p",
        "udp",
        "--dport",
        str(int(port)),
        "-m",
        "conntrack",
        "--ctstate",
        "NEW",
        "-m",
        "hashlimit",
        "--hashlimit-above",
        "12/minute",
        "--hashlimit-burst",
        "4",
        "--hashlimit-mode",
        "srcip",
        "--hashlimit-name",
        f"hadp{version}_{int(port)}",
        "-m",
        "limit",
        "--limit",
        "30/minute",
        "--limit-burst",
        "10",
        "-j",
        "LOG",
        "--log-prefix",
        "HYDRA_UDP_PROBE ",
        "--log-level",
        "4",
    ]


def mieru_probe_rule(binary: str, close_flag: str) -> list[str]:
    """Log repeated Mieru sessions that close after <=1 KiB client traffic."""
    version = "6" if binary == "ip6tables" else "4"
    flag = str(close_flag).upper()
    return [
        "-p",
        "tcp",
        "--dport",
        MIERU_PORT_RANGE,
        "--tcp-flags",
        "FIN,RST",
        flag,
        "-m",
        "conntrack",
        "--ctstate",
        "ESTABLISHED",
        "-m",
        "connbytes",
        "--connbytes",
        "1:1024",
        "--connbytes-dir",
        "original",
        "--connbytes-mode",
        "bytes",
        "-m",
        "hashlimit",
        "--hashlimit-above",
        "2/minute",
        "--hashlimit-burst",
        "2",
        "--hashlimit-mode",
        "srcip",
        "--hashlimit-name",
        f"hadp_mieru_{flag.lower()}{version}",
        "-m",
        "limit",
        "--limit",
        "30/minute",
        "--limit-burst",
        "10",
        "-m",
        "comment",
        "--comment",
        MIERU_PROBE_RULE_COMMENT,
        "-j",
        "LOG",
        "--log-prefix",
        "HYDRA_MIERU_SHORT ",
        "--log-level",
        "4",
    ]

