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
    """Accept a domain or a domain suffix, including IDN and punycode forms."""
    if not token or len(token) > 253:
        return False
    leading_dot = token.startswith(".")
    try:
        body = token.removeprefix(".").encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return False
    normalized = f".{body}" if leading_dot else body
    suffix = r"\.[a-zA-Z0-9-]{2,63}"
    domain = r"\.?[a-zA-Z0-9][-a-zA-Z0-9._]*\.[a-zA-Z0-9-]{2,63}"
    return re.fullmatch(suffix, normalized) is not None or (re.fullmatch(domain, normalized) is not None)


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


__all__ = [
    "is_ip_or_cidr",
    "is_valid_domain",
    "parse_endpoint",
    "parse_wg_conf",
]
