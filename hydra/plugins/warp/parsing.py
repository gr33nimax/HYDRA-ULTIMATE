"""Pure parsing and validation helpers for WireGuard-backed WARP profiles."""

from __future__ import annotations

import ipaddress
import re


def is_ip_or_cidr(token: str) -> bool:
    try:
        if "/" in token:
            ipaddress.ip_network(token, strict=False)
        else:
            ipaddress.ip_address(token)
        return True
    except ValueError:
        return False


def is_valid_domain(token: str) -> bool:
    if not token or len(token) > 253:
        return False
    if re.fullmatch(r"\.[a-zA-Z]{2,24}", token):
        return True
    pattern = r"^\.?[a-zA-Z0-9][-a-zA-Z0-9._]*\.[a-zA-Z]{2,24}$"
    return re.match(pattern, token) is not None


def parse_endpoint(raw_endpoint: str) -> tuple[str, int] | None:
    """Parse WireGuard host:port, including bracketed IPv6 addresses."""
    value = raw_endpoint.strip()
    if value.startswith("["):
        match = re.fullmatch(r"\[([^]]+)]:(\d+)", value)
        if not match:
            return None
        host, port_text = match.groups()
    else:
        if ":" not in value:
            return None
        host, port_text = value.rsplit(":", 1)
    try:
        port = int(port_text)
    except ValueError:
        return None
    if not host or not 1 <= port <= 65535:
        return None
    return host, port


def parse_wg_conf(text: str) -> dict | None:
    """Parse the shared WireGuard/AmneziaWG subset used by the plugin."""
    result: dict[str, dict[str, str]] = {"interface": {}, "peer": {}}
    current_section: str | None = None
    for raw_line in text.splitlines():
        line = re.sub(r"[#;].*$", "", raw_line).strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            current_section = line[1:-1].lower()
            continue
        if current_section not in result or "=" not in line:
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        key = key.lower()
        current = result[current_section]
        if key in {"address", "allowedips"} and current.get(key):
            current[key] += f", {value}"
        else:
            current[key] = value

    if not all(result["interface"].get(k) for k in {"privatekey", "address"}):
        return None
    if not all(result["peer"].get(k) for k in {"publickey", "endpoint"}):
        return None
    return result


def load_warp_config(profile, *, parse_config=parse_wg_conf, validate_ip=is_ip_or_cidr):
    """Read and normalize a wgcf profile into Sing-Box input fields."""
    if not profile.exists():
        return None
    try:
        text = profile.read_text(encoding="utf-8")
    except Exception:
        return None
    parsed = parse_config(text)
    if parsed is None:
        return None

    addresses = []
    for value in parsed["interface"]["address"].split(","):
        address = value.strip()
        if address and validate_ip(address):
            addresses.append(
                address if "/" in address else address + ("/128" if ":" in address else "/32")
            )
    if not addresses:
        return None
    return {
        "private_key": parsed["interface"]["privatekey"],
        "addresses": addresses,
        "endpoint": parsed["peer"]["endpoint"],
        "public_key": parsed["peer"]["publickey"],
        "allowed_ips": [
            value.strip()
            for value in parsed["peer"].get(
                "allowedips",
                "0.0.0.0/0, ::/0",
            ).split(",")
            if validate_ip(value.strip())
        ],
        "mtu": parsed["interface"].get("mtu", "1280"),
    }


__all__ = [
    "is_ip_or_cidr",
    "is_valid_domain",
    "load_warp_config",
    "parse_endpoint",
    "parse_wg_conf",
]
