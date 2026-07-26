"""Structured log normalization for AntiDPI evidence."""
from __future__ import annotations

import ipaddress

from hydra.plugins.antidpi.adapters import remote_ip


def normalize_caddy_record(record: dict) -> tuple[str, dict] | None:
    """Convert a caddy-l4 JSON log record into ``(ip, event)``."""
    if not isinstance(record, dict):
        return None
    remote = str(record.get("remote", record.get("remote_ip", "")))
    if not remote:
        return None
    address = remote_ip(remote)
    if address is None:
        return None
    text = " ".join(
        str(record.get(key, "")) for key in ("msg", "error", "err")
    ).lower()
    event = {"protocol": "tls", "handshake_ok": False}
    if any(
        token in text
        for token in ("no certificate", "unknown sni", "unrecognized server name")
    ):
        event.update(kind="unknown_sni", sni_known=False)
    elif any(
        token in text
        for token in ("clienthello", "malformed", "record header", "unexpected message")
    ):
        event["kind"] = "malformed_tls"
    elif any(token in text for token in ("eof", "handshake", "tls alert")):
        event["kind"] = "handshake_failure"
    else:
        return None
    return address, event


def normalize_decoy_record(record: dict) -> tuple[str, dict] | None:
    """Recognize active scanner behaviour in a Caddy HTTP access record."""
    request = record.get("request", {}) if isinstance(record, dict) else {}
    if not isinstance(request, dict):
        return None
    address = remote_ip(
        request.get("remote_ip", request.get("remote_addr", "")),
    )
    if address is None:
        return None
    method = str(request.get("method", "GET")).upper()
    uri = str(request.get("uri", request.get("path", ""))).lower()
    suspicious = method in {"CONNECT", "TRACE", "TRACK"} or any(
        token in uri
        for token in (
            "/.env",
            "/wp-login",
            "/xmlrpc.php",
            "/actuator",
            "/cgi-bin/",
            "/server-status",
        )
    )
    if not suspicious:
        return None
    return address, {
        "protocol": "https",
        "kind": "active_decoy_probe",
        "source": "caddy-decoy",
    }


def _naive_auth_event(address: str | None, request: dict) -> tuple[str, dict] | None:
    if address is None:
        return None
    event = {
        "protocol": "naive",
        "kind": "auth_failure",
        "source": "caddy-naive",
    }
    if ipaddress.ip_address(address).is_loopback:
        try:
            peer_port = int(request.get("remote_port", 0))
        except (TypeError, ValueError):
            peer_port = 0
        if peer_port > 0:
            event["peer_port"] = peer_port
    return address, event


def normalize_naive_decoy_record(record: dict) -> tuple[str, dict] | None:
    """Recognize scanner paths without treating valid Naive CONNECT as probes."""
    request = record.get("request", {}) if isinstance(record, dict) else {}
    if not isinstance(request, dict):
        return None
    address = remote_ip(
        request.get("remote_ip", request.get("remote_addr", "")),
    )
    try:
        status = int(record.get("status", 0))
    except (TypeError, ValueError):
        status = 0
    method = str(request.get("method", "GET")).upper()
    user_id = str(request.get("user_id", record.get("user_id", ""))).lower()
    if user_id.startswith("invalid:"):
        return _naive_auth_event(address, request)
    if method == "CONNECT":
        if status in {401, 407}:
            return _naive_auth_event(address, request)
        return None
    normalized = normalize_decoy_record(record)
    if normalized is not None:
        normalized[1]["source"] = "caddy-naive-decoy"
        return normalized
    if status in {401, 407}:
        return _naive_auth_event(address, request)
    return None


def normalize_trusttunnel_record(record: dict) -> tuple[str, dict] | None:
    """Recognize completed TrustTunnel auth failures in its dedicated log."""
    request = record.get("request", {}) if isinstance(record, dict) else {}
    if not isinstance(request, dict):
        return None
    address = remote_ip(
        request.get("remote_ip", request.get("client_ip", "")),
    )
    if address is None:
        return None
    method = str(request.get("method", "")).upper()
    try:
        status = int(record.get("status", 0))
    except (TypeError, ValueError):
        status = 0
    if method == "CONNECT" and status >= 400:
        return address, {
            "protocol": "trusttunnel",
            "kind": "auth_failure",
            "source": "caddy-trusttunnel",
        }
    normalized = normalize_decoy_record(record)
    if normalized is not None:
        normalized[1]["source"] = "caddy-trusttunnel-decoy"
        return normalized
    return None

