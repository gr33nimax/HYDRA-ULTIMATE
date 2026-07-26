"""Stable runtime facade for the Caddy L4 SNI router."""
from __future__ import annotations

import json
import re
import socket
import ssl
from collections.abc import Callable
from pathlib import Path
from typing import Any

from hydra.core import sni_router_reconcile as _reconcile
from hydra.core.sni_router_runtime_models import (
    RuntimeOperations,
    RuntimeSettings,
)
from hydra.core.state_models import AppState


def is_active(
    settings: RuntimeSettings,
    host: Any,
    *,
    is_installed: Callable[[], bool],
) -> bool:
    """Return whether the Caddy L4 systemd service is active."""
    if not is_installed():
        return False
    result = host.run(
        ["systemctl", "is-active", settings.caddy_service_name],
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() == "active"


def config_had_quic_proxy(config_path: Path) -> bool:
    """Inspect whether the current artifact owns public UDP/443."""
    try:
        current = json.loads(config_path.read_text(encoding="utf-8"))
        servers = current.get("apps", {}).get("layer4", {}).get("servers", {})
        return "quic_mux" in servers
    except (OSError, ValueError, TypeError):
        return False


def configured_loopback_ports(config_path: Path) -> set[int]:
    """Discover plugin-owned loopback ports from Hydra's current artifact."""
    try:
        document = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return set()
    ports: set[int] = set()
    pattern = re.compile(r"^(?:tcp/|udp/)?127\.0\.0\.1:(\d{1,5})$")

    def visit(value: object) -> None:
        if isinstance(value, dict):
            for nested in value.values():
                visit(nested)
        elif isinstance(value, list):
            for nested in value:
                visit(nested)
        elif isinstance(value, str):
            match = pattern.fullmatch(value)
            if match and 1 <= int(match.group(1)) <= 65535:
                ports.add(int(match.group(1)))

    visit(document)
    return ports


def probe_tls_route(
    domain: str,
    *,
    address: str = "127.0.0.1",
    port: int = 443,
    timeout: float = 3.0,
) -> tuple[bool, str]:
    """Verify the active local TLS route, hostname and HTTP/2 negotiation."""
    normalized = str(domain or "").strip().lower().rstrip(".")
    if not normalized:
        return False, "TLS route domain is missing"
    context = ssl.create_default_context()
    context.set_alpn_protocols(["h2"])
    try:
        with socket.create_connection(
            (address, port),
            timeout=timeout,
        ) as connection:
            with context.wrap_socket(
                connection,
                server_hostname=normalized,
            ) as tls:
                negotiated = tls.selected_alpn_protocol()
    except (OSError, ValueError) as exc:
        return False, f"TLS route probe failed for {normalized}: {exc}"
    if negotiated != "h2":
        return (
            False,
            "TLS route negotiated ALPN "
            f"{negotiated or 'none'} instead of h2",
        )
    return True, ""


def rebuild(
    state: AppState,
    settings: RuntimeSettings,
    host: Any,
    operations: RuntimeOperations,
) -> bool:
    """Render, validate, and transactionally apply the desired SNI runtime."""
    return _reconcile.rebuild(state, settings, host, operations)


def stop(
    settings: RuntimeSettings,
    host: Any,
    *,
    is_installed: Callable[[], bool],
    remove_source_service: Callable[[], None],
    remove_relay_service: Callable[[], None],
) -> None:
    """Stop the router and clean up loopback isolation and routing units."""
    try:
        configured_ports = configured_loopback_ports(settings.caddy_config)
        if is_installed():
            host.run(
                ["systemctl", "stop", settings.caddy_service_name],
                capture_output=True,
            )
            host.run(
                ["systemctl", "disable", settings.caddy_service_name],
                capture_output=True,
            )
        for port in settings.internal_ports.values():
            for protocol in ("tcp", "udp"):
                host.run(
                    [
                        "iptables",
                        "-D",
                        "INPUT",
                        "-p",
                        protocol,
                        "--dport",
                        str(port),
                        "!",
                        "-i",
                        "lo",
                        "-j",
                        "DROP",
                    ],
                    capture_output=True,
                )
        for port in settings.decoy_ports.values():
            host.run(
                [
                    "iptables",
                    "-D",
                    "INPUT",
                    "-p",
                    "tcp",
                    "--dport",
                    str(port),
                    "!",
                    "-i",
                    "lo",
                    "-j",
                    "DROP",
                ],
                capture_output=True,
            )
        static_ports = {
            *settings.internal_ports.values(),
            *settings.decoy_ports.values(),
        }
        for port in sorted(configured_ports - static_ports):
            for protocol in ("tcp", "udp"):
                host.run(
                    [
                        "iptables",
                        "-D",
                        "INPUT",
                        "-p",
                        protocol,
                        "--dport",
                        str(port),
                        "!",
                        "-i",
                        "lo",
                        "-m",
                        "comment",
                        "--comment",
                        "hydra-caddy-dynamic-loopback",
                        "-j",
                        "DROP",
                    ],
                    capture_output=True,
                )
    except Exception:
        pass
    try:
        remove_source_service()
        remove_relay_service()
        from hydra.core import source_transparency

        source_transparency.clear()
    except Exception:
        pass


def uninstall_haproxy(host: Any) -> None:
    """Stop HAProxy and remove legacy Hydra loopback-isolation rules."""
    try:
        host.run(["systemctl", "stop", "haproxy"], capture_output=True)
        host.run(["systemctl", "disable", "haproxy"], capture_output=True)
        for port in (10443, 10444, 10445, 9443):
            host.run(
                [
                    "iptables",
                    "-D",
                    "INPUT",
                    "-p",
                    "tcp",
                    "--dport",
                    str(port),
                    "!",
                    "-i",
                    "lo",
                    "-j",
                    "DROP",
                ],
                capture_output=True,
            )
    except Exception:
        pass


__all__ = [
    "RuntimeOperations",
    "RuntimeSettings",
    "config_had_quic_proxy",
    "configured_loopback_ports",
    "is_active",
    "probe_tls_route",
    "rebuild",
    "stop",
    "uninstall_haproxy",
]
