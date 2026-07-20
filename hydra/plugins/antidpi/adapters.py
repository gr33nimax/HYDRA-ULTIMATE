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
    ("naive", rf"(?:authentication failed|invalid|malformed|protocol error).*?{_IP}", "auth_failure"),
    ("wdtt", rf"(?:invalid handshake|authentication failed|invalid packet).*?{_IP}", "handshake_failure"),
    # BAN is the result of the preceding CONNECT, not independent evidence.
    ("honeypot", rf"CONNECT\s+{_IP}", "active_decoy_probe"),
)

_KERNEL_SCAN = re.compile(
    r"HYDRA_SCAN_(?P<protocol>TCP|UDP)\b.*?SRC=(?P<ip>[^\s]+)(?:.*?DPT=(?P<port>\d+))?",
    re.IGNORECASE,
)


def _remote_ip(value: object) -> str | None:
    raw = str(value or "").strip()
    if raw.startswith("[") and "]" in raw:
        raw = raw[1:raw.index("]")]
    else:
        try:
            return ipaddress.ip_address(raw).compressed
        except ValueError:
            raw = raw.rsplit(":", 1)[0]
    try:
        return ipaddress.ip_address(raw).compressed
    except ValueError:
        return None



def _extract_ip(text: str) -> str | None:
    candidates = []
    candidates.extend(re.findall(r"\[([0-9a-fA-F:]+)\](?::\d+)?", text))
    candidates.extend(re.findall(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?::\d+)?", text))
    candidates.extend(token.strip("[](),;") for token in text.split() if ":" in token)
    for candidate in candidates:
        value = str(candidate)
        try:
            return ipaddress.ip_address(value).compressed
        except ValueError:
            if value.count(":") == 1:
                try:
                    return ipaddress.ip_address(value.rsplit(":", 1)[0]).compressed
                except ValueError:
                    pass
    return None

def parse_protocol_line(service: str, line: str) -> tuple[str, dict] | None:
    """Parse one journal line into a normalized event, if it is evidence."""
    service = str(service or "").lower()
    text = str(line or "")
    for owner, pattern, kind in PATTERNS:
        if owner not in service and owner not in text.lower():
            continue
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            try:
                ip = ipaddress.ip_address(match.group("ip")).compressed
            except ValueError:
                ip = _extract_ip(text)
        else:
            evidence_pattern = pattern.split(".*?", 1)[0]
            if not re.search(evidence_pattern, text, re.IGNORECASE):
                continue
            ip = _extract_ip(text)
        if ip is None:
            continue
        event = {"protocol": owner, "kind": kind, "source": "journal"}
        if kind == "handshake_failure":
            event["handshake_ok"] = False
        return ip, event
    return None


def normalize_tls_auth_failure(record: dict) -> tuple[str, dict] | None:
    """Recognize TLS/Inbound authentication failure in structured JSON records."""
    if not isinstance(record, dict):
        return None
    remote = str(record.get("remote", record.get("remote_ip", record.get("client_ip", ""))))
    if not remote:
        return None
    ip = _remote_ip(remote)
    if ip is None:
        return None
    text = " ".join(str(record.get(k, "")) for k in ("msg", "error", "err", "reason")).lower()
    if any(token in text for token in ("auth_failure", "authentication failed", "invalid password", "unauthorized", "bad credentials")):
        proto = str(record.get("protocol", record.get("service", "tls"))).lower()
        return ip, {"protocol": proto, "kind": "auth_failure", "source": "auth_log"}
    return None


def parse_kernel_scan_line(line: str) -> tuple[str, dict] | None:
    """Normalize a rate-limited kernel firewall scan signal."""
    match = _KERNEL_SCAN.search(str(line or ""))
    if not match:
        return None
    raw_ip = match.group("ip").strip("[]")
    try:
        address = ipaddress.ip_address(raw_ip).compressed
    except ValueError:
        return None
    protocol = match.group("protocol").lower()
    event = {
        "protocol": protocol,
        "kind": "port_scan",
        "source": "kernel-firewall",
        "connections_10s": 12,
    }
    if match.group("port"):
        event["destination_port"] = int(match.group("port"))
    return address, event
