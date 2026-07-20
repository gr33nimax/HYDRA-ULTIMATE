"""Protocol-log adapters for the anti-DPI event schema.

These parsers intentionally emit evidence, not verdicts.  The central scorer
combines them with rate and temporal context before touching the firewall.
"""
from __future__ import annotations

import ipaddress
import re

_IP = r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{3,})"

PATTERNS: tuple[tuple[str, str, str], ...] = (
    ("amneziawg", rf"(?:Invalid MAC|Invalid handshake|Unknown message).*?{_IP}", "handshake_failure"),
    ("sing-box", rf"(?:handshake failed|invalid handshake|protocol error).*?{_IP}", "handshake_failure"),
    ("anytls", rf"(?:authentication failed|invalid password|handshake).*?{_IP}", "handshake_failure"),
    ("shadowtls", rf"(?:handshake failed|invalid client hello|unexpected).*?{_IP}", "malformed_tls"),
    ("trusttunnel", rf"(?:handshake failed|protocol error|invalid).*?{_IP}", "protocol_mismatch"),
    ("hysteria2", rf"(?:handshake failed|invalid packet|QUIC).*?{_IP}", "invalid_first_packet"),
    ("mieru", rf"(?:handshake failed|authentication failed|invalid).*?{_IP}", "handshake_failure"),
    ("snell", rf"(?:handshake failed|invalid).*?{_IP}", "handshake_failure"),
    ("telemt", rf"(?:handshake failed|invalid).*?{_IP}", "handshake_failure"),
)


def parse_protocol_line(service: str, line: str) -> tuple[str, dict] | None:
    """Parse one journal line into a normalized event, if it is evidence."""
    service = str(service or "").lower()
    text = str(line or "")
    for owner, pattern, kind in PATTERNS:
        if owner not in service and owner not in text.lower():
            continue
        match = re.search(pattern, text, re.IGNORECASE)
        if not match:
            continue
        raw_ip = match.group("ip")
        try:
            ip = ipaddress.ip_address(raw_ip).compressed
        except ValueError:
            continue
        return ip, {"protocol": owner, "kind": kind, "handshake_ok": False, "source": "journal"}
    return None
