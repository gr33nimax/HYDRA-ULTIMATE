"""Protocol-log adapters for the anti-DPI event schema.

These parsers intentionally emit evidence, not verdicts.  The central scorer
combines them with rate and temporal context before touching the firewall.
"""
from __future__ import annotations

import ipaddress
import json
import re

PATTERNS: tuple[tuple[str, str, str], ...] = (
    (
        "amneziawg",
        r"(?:Invalid MAC(?: of handshake)?|Invalid handshake|Unknown message|unknown peer)",
        "handshake_failure",
    ),
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
_KERNEL_UDP_PROBE = re.compile(
    r"HYDRA_UDP_PROBE\b.*?SRC=(?P<ip>[^\s]+).*?DPT=(?P<port>\d+)",
    re.IGNORECASE,
)
_KERNEL_MIERU_SHORT = re.compile(
    r"HYDRA_MIERU_SHORT\b.*?SRC=(?P<ip>[^\s]+).*?SPT=(?P<source_port>\d+).*?DPT=(?P<port>\d+)",
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
        owner_visible = owner in service or owner in text.lower()
        # AmneziaWG emits native rejection diagnostics through the kernel
        # journal. Some builds identify records as WireGuard or only by awgN.
        if owner == "amneziawg" and service in {"kernel", "kernel-journal"}:
            owner_visible = bool(re.search(pattern, text, re.IGNORECASE)) and bool(
                re.search(r"(?:wireguard|amnezia|\bawg\d*\b)", text, re.IGNORECASE)
            )
        if not owner_visible:
            continue
        if not re.search(pattern, text, re.IGNORECASE):
            continue
        ip, peer_port = _extract_endpoint(text)
        if ip is None:
            continue
        event = {"protocol": owner, "kind": kind, "source": "journal"}
        if owner in {"amneziawg", "hysteria2", "wdtt"}:
            # Direct UDP source addresses are spoofable until a protocol log
            # explicitly proves address validation. Keep these events useful
            # for alerting without allowing them to trigger an IP ban alone.
            event["ban_eligible"] = False
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
    mieru = _KERNEL_MIERU_SHORT.search(str(line or ""))
    if mieru:
        try:
            address = ipaddress.ip_address(mieru.group("ip").strip("[]")).compressed
            source_port = int(mieru.group("source_port"))
            destination_port = int(mieru.group("port"))
        except ValueError:
            return None
        return address, {
            "protocol": "mieru", "kind": "low_volume_session",
            "source": "kernel-mieru", "source_port": source_port,
            "destination_port": destination_port, "ban_eligible": False,
            "policy": "alert-only / inferred low-volume TCP rejection",
        }
    udp_probe = _KERNEL_UDP_PROBE.search(str(line or ""))
    if udp_probe:
        try:
            address = ipaddress.ip_address(udp_probe.group("ip").strip("[]")).compressed
            port = int(udp_probe.group("port"))
        except ValueError:
            return None
        return address, {
            "protocol": "udp", "kind": "udp_probe",
            "source": "kernel-udp-probe", "destination_port": port,
            "ban_eligible": False,
        }
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
    if protocol == "udp":
        event["ban_eligible"] = False
    if match.group("port"):
        event["destination_port"] = int(match.group("port"))
    return address, event
