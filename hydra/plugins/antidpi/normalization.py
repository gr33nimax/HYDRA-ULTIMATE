"""Structured log normalization for AntiDPI evidence."""
from __future__ import annotations

import ipaddress
from collections.abc import Callable

from hydra.plugins.antidpi.adapters import remote_ip
from hydra.plugins.context import PluginStateAccess

Normalizer = Callable[[dict], "tuple[str, dict] | None"]

# Statuses that mean the endpoint refused the caller. Upstream failures (5xx)
# are excluded: a restarting backend must not look like a probe.
VLESS_PROBE_STATUSES = frozenset({400, 401, 403, 404, 405, 407, 421, 426})


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


def vless_endpoint(
    state: PluginStateAccess | None,
) -> tuple[str, tuple[str, ...]]:
    """Return the enabled VLESS domain and its XHTTP paths, if any."""
    protocol = state.protocols.get("vless") if state is not None else None
    if not protocol or not protocol.enabled:
        return "", ()
    config = protocol.config if isinstance(protocol.config, dict) else {}
    domain = str(config.get("domain", "")).strip().lower().rstrip(".")
    path = str(config.get("xhttp_path", "") or "").strip().rstrip("/")
    if not domain or not path.startswith("/"):
        return "", ()
    return domain, (path,)


def _request_path(request: dict) -> str:
    raw = str(request.get("uri", request.get("path", "")))
    return raw.split("?", 1)[0].split("#", 1)[0].rstrip("/") or "/"


def _covers(paths: tuple[str, ...], value: str) -> bool:
    return any(
        value == path or value.startswith(f"{path}/")
        for path in paths
        if path
    )


def normalize_vless_record(
    record: dict,
    *,
    domain: str = "",
    paths: tuple[str, ...] = (),
) -> tuple[str, dict] | None:
    """Recognize probing of the VLESS XHTTP endpoint and its decoy site.

    Caddy terminates TLS for the VLESS domain and forwards the request to the
    local HTTP server over PROXY v2, so this access record carries the real
    client address — unlike the sing-box journal, which only ever sees the
    loopback hop.
    """
    request = record.get("request", {}) if isinstance(record, dict) else {}
    if not isinstance(request, dict) or not domain:
        return None
    host = str(request.get("host", "")).strip().lower().split(":", 1)[0]
    if host.rstrip(".") != domain:
        return None
    address = remote_ip(
        request.get("remote_ip", request.get("remote_addr", "")),
    )
    if address is None:
        return None
    try:
        status = int(record.get("status", 0))
    except (TypeError, ValueError):
        status = 0
    if _covers(paths, _request_path(request)):
        if status not in VLESS_PROBE_STATUSES:
            return None
        return address, {
            "protocol": "vless",
            "kind": "auth_failure",
            "source": "caddy-vless",
        }
    normalized = normalize_decoy_record(record)
    if normalized is None:
        return None
    normalized[1]["source"] = "caddy-vless-decoy"
    return normalized


def vless_normalizer(
    domain: str,
    paths: tuple[str, ...],
) -> Normalizer | None:
    """Bind the VLESS normalizer to one deployment, or disable it."""
    if not domain or not paths:
        return None

    def normalize(record: dict) -> tuple[str, dict] | None:
        return normalize_vless_record(record, domain=domain, paths=paths)

    return normalize


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
