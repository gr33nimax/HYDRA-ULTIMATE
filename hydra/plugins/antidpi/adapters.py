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
    ("anytls", rf"(?:authentication failed|invalid password|unauthorized|auth error).*?{_IP}", "auth_failure"),
    ("trusttunnel", rf"(?:authentication failed|invalid token|unauthorized|auth error).*?{_IP}", "auth_failure"),
    ("shadowtls", rf"(?:handshake failed|invalid client hello|unexpected).*?{_IP}", "malformed_tls"),
    ("hysteria2", rf"(?:handshake failed|invalid packet|QUIC).*?{_IP}", "invalid_first_packet"),
    ("mieru", rf"(?:handshake failed|authentication failed|invalid).*?{_IP}", "auth_failure"),
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


def normalize_tls_auth_failure(record: dict) -> tuple[str, dict] | None:
    """Recognize TLS/Inbound authentication failure in structured JSON records."""
    if not isinstance(record, dict):
        return None
    remote = str(record.get("remote", record.get("remote_ip", record.get("client_ip", ""))))
    if not remote:
        return None
    raw_ip = remote.split(":")[0].strip("[]")
    try:
        ip = ipaddress.ip_address(raw_ip).compressed
    except ValueError:
        return None
    text = " ".join(str(record.get(k, "")) for k in ("msg", "error", "err", "reason")).lower()
    if any(token in text for token in ("auth_failure", "authentication failed", "invalid password", "unauthorized", "bad credentials")):
        proto = str(record.get("protocol", record.get("service", "tls"))).lower()
        return ip, {"protocol": proto, "kind": "auth_failure", "handshake_ok": False, "source": "auth_log"}
    return None
