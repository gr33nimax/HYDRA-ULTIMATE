"""Protocol-log adapters for the anti-DPI event schema.

These parsers intentionally emit evidence, not verdicts.  The central scorer
combines them with rate and temporal context before touching the firewall.
"""
from __future__ import annotations

import ipaddress
import json
import re

PATTERNS: tuple[tuple[str, str, str], ...] = (
    ("amneziawg", r"(?:Invalid MAC|Invalid handshake|Unknown message)", "handshake_failure"),
    ("sing-box", r"(?:handshake failed|invalid handshake|protocol error)", "handshake_failure"),
    ("anytls", r"(?:authentication failed|invalid password|unknown user password|unauthorized|auth error)", "auth_failure"),
    ("anytls", r"(?:process connection.*?EOF: fallback disabled)", "invalid_first_packet"),
    ("trusttunnel", r"(?:authentication failed|authorization failed|invalid token|unauthorized|auth error)", "auth_failure"),
    (
        "shadowtls",
        r"inbound/trojan\[shadowtls-trojan-in\].*"
        r"(?:authentication failed|invalid password|unknown user|unauthorized|"
        r"bad request: fallback disabled)",
        "auth_failure",
    ),
    (
        "shadowtls",
        r"(?:handshake failed|invalid client hello|read client handshake: unexpected EOF|"
        r"extract server name: tls: handshake message .* exceeds maximum)",
        "malformed_tls",
    ),
    ("hysteria2", r"(?:handshake failed|invalid packet|authentication failed|failed to parse QUIC)", "invalid_first_packet"),
    ("mieru", r"(?:handshake failed|authentication failed|invalid credentials)", "auth_failure"),
    ("snell", r"(?:process connection .*: malformed HTTP request)", "invalid_first_packet"),
    ("snell", r"(?:handshake failed|invalid client handshake)", "handshake_failure"),
    ("telemt", r"(?:handshake failed|invalid)", "handshake_failure"),
    ("naive", r"(?:authentication failed|invalid credentials|malformed request|protocol error)", "auth_failure"),
    ("wdtt", r"(?:invalid handshake|handshake failed|authentication failed|auth failed|invalid packet)", "handshake_failure"),
)

_KERNEL_SCAN = re.compile(
    r"HYDRA_SCAN_(?P<protocol>TCP|UDP)\b.*?SRC=(?P<ip>[^\s]+)(?:.*?DPT=(?P<port>\d+))?",
    re.IGNORECASE,
)
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


def decode_log_message(value: object) -> str:
    """Decode journald's JSON byte-array representation used by sing-box.

    Some sing-box-extended builds write ``[]byte`` to stdout. systemd stores
    that as an array in JSON output instead of a normal MESSAGE string.
    """
    candidate = value
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.startswith("[") and stripped.endswith("]") and len(stripped) <= 1_000_000:
            try:
                candidate = json.loads(stripped)
            except (TypeError, ValueError):
                candidate = value
    if (
        isinstance(candidate, list)
        and len(candidate) <= 262_144
        and all(isinstance(item, int) and 0 <= item <= 255 for item in candidate)
    ):
        text = bytes(candidate).decode("utf-8", errors="replace")
    else:
        text = str(value or "")
    return _ANSI_ESCAPE.sub("", text)


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



def _extract_endpoint(text: str) -> tuple[str | None, int | None]:
    candidates = []
    candidates.extend((ip, port) for ip, port in re.findall(r"\[([0-9a-fA-F:]+)\](?::(\d+))?", text))
    candidates.extend((ip, port) for ip, port in re.findall(
        r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?::(\d+))?", text,
    ))
    for candidate, raw_port in candidates:
        value = str(candidate)
        try:
            return ipaddress.ip_address(value).compressed, int(raw_port) if raw_port else None
        except ValueError:
            continue
    return None, None


def _extract_ip(text: str) -> str | None:
    return _extract_endpoint(text)[0]

def parse_protocol_line(service: str, line: object) -> tuple[str, dict] | None:
    """Parse one journal line into a normalized event, if it is evidence."""
    service = str(service or "").lower()
    text = decode_log_message(line)
    for owner, pattern, kind in PATTERNS:
        if owner not in service and owner not in text.lower():
            continue
        if not re.search(pattern, text, re.IGNORECASE):
            continue
        ip, peer_port = _extract_endpoint(text)
        if ip is None:
            continue
        event = {"protocol": owner, "kind": kind, "source": "journal"}
        if (
            peer_port is not None
            and owner in {"anytls", "trusttunnel", "shadowtls"}
            and ipaddress.ip_address(ip).is_loopback
        ):
            event["peer_port"] = peer_port
        if kind == "handshake_failure":
            event["handshake_ok"] = False
        return ip, event
    return None


def parse_unattributed_protocol_line(service: str, line: object) -> dict | None:
    """Return strict native evidence whose log record omits the peer endpoint."""
    service = str(service or "").lower()
    text = decode_log_message(line)
    lowered = text.lower()
    if (
        ("sing-box" in service or "shadowtls" in lowered)
        and "inbound/shadowtls[" in lowered
        and "client hello verify failed: hmac mismatch" in lowered
    ):
        return {
            "protocol": "shadowtls", "kind": "auth_failure",
            "source": "journal",
        }
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
