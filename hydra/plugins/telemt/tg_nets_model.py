"""Telegram network policy, normalization and persistence."""
from __future__ import annotations

import ipaddress
import re
import time
from datetime import datetime
from pathlib import Path

NETS_FILE = Path("/etc/telemt/tg_nets.txt")
WARN_DAYS = 30
STALE_DAYS = 90
HTTP_TIMEOUT = 20
TG_ASNS = [62041, 59930, 44907, 211157, 42065, 62014]
TG_MNT = "MNT-TELEGRAM"
USER_AGENT = "hydra-ultimate/telemt-tg-nets"
BUILTIN_NETS = [
    "91.108.4.0/22", "91.108.8.0/22", "91.108.56.0/22",
    "95.161.64.0/20", "149.154.160.0/22", "149.154.164.0/22",
    "91.108.12.0/22", "149.154.172.0/22", "91.108.20.0/22",
    "91.105.192.0/23", "185.76.151.0/24", "109.239.140.0/24",
    "91.108.16.0/22", "149.154.168.0/22", "2001:67c:4e8::/48",
    "2001:b28:f23d::/48", "2001:b28:f23c::/48",
    "2a0a:f280:203::/48", "2001:b28:f23f::/48",
]
TG_SUPERNETS = [
    ipaddress.ip_network(network)
    for network in (
        "91.108.4.0/22", "91.108.8.0/22", "91.108.12.0/22",
        "91.108.16.0/22", "91.108.20.0/22", "91.108.56.0/22",
        "149.154.160.0/22", "149.154.164.0/22", "149.154.168.0/22",
        "149.154.172.0/22", "95.161.64.0/20", "91.105.192.0/23",
        "185.76.151.0/24", "109.239.140.0/24",
        "2001:67c:4e8::/48", "2001:b28:f23c::/46",
        "2a0a:f280:203::/48",
    )
]
_RE_V4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}/([0-9]|[12]\d|3[012])$")
_RE_V6 = re.compile(r"^[0-9a-fA-F:]+/(\d{1,3})$")


def valid_cidr(cidr: str) -> bool:
    cidr = cidr.strip()
    return bool(cidr and (_RE_V4.match(cidr) or _RE_V6.match(cidr)))


def remove_more_specific(networks: list[str]) -> list[str]:
    parsed: dict[int, list] = {4: [], 6: []}
    for network in networks:
        try:
            item = ipaddress.ip_network(network.strip())
            parsed[item.version].append(item)
        except ValueError:
            pass
    result: list[str] = []
    for version in (4, 6):
        kept = []
        for item in sorted(parsed[version], key=lambda value: value.prefixlen):
            if not any(item != parent and item.subnet_of(parent) for parent in kept):
                kept.append(item)
        result.extend(str(item) for item in sorted(kept))
    return result


def dedup(networks: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for network in networks:
        network = network.strip()
        if valid_cidr(network) and network not in seen:
            seen.add(network)
            result.append(network)
    return result


def in_telegram_space(cidr: str) -> bool:
    try:
        network = ipaddress.ip_network(cidr)
        return any(
            network.version == parent.version
            and (network == parent or network.subnet_of(parent))
            for parent in TG_SUPERNETS
        )
    except ValueError:
        return False


def load_from_file(path: Path = NETS_FILE) -> list[str] | None:
    if not path.exists():
        return None
    networks = [
        line.split("#")[0].strip()
        for line in path.read_text(encoding="utf-8").splitlines()
    ]
    networks = [network for network in networks if valid_cidr(network)]
    return networks or None


def save_to_file(
    networks: list[str],
    sources: list[str],
    raw_count: int = 0,
    removed_count: int = 0,
    *,
    path: Path = NETS_FILE,
) -> None:
    del removed_count
    path.parent.mkdir(parents=True, exist_ok=True)
    ipv4 = [network for network in networks if ":" not in network]
    ipv6 = [network for network in networks if ":" in network]
    lines = [
        "# Telegram IP networks",
        f"# Updated : {datetime.now():%Y-%m-%d %H:%M:%S}",
        f"# Total   : {len(networks)} ({len(ipv4)} IPv4, {len(ipv6)} IPv6)",
        f"# Raw     : {raw_count} -> normalized: {len(networks)}",
        f"# Sources : {', '.join(sources) if sources else 'builtin'}",
        f"# ASN     : {' '.join('AS' + str(asn) for asn in TG_ASNS)}",
        "#",
        "# IPv4",
        *ipv4,
    ]
    if ipv6:
        lines += ["", "# IPv6", *ipv6]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    path.chmod(0o644)


def file_age_days(path: Path = NETS_FILE) -> int | None:
    if not path.exists():
        return None
    return int((time.time() - path.stat().st_mtime) / 86400)
