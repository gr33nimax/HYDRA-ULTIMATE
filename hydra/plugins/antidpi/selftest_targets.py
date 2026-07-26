"""Target discovery and protocol-specific payloads for AntiDPI self-tests."""
from __future__ import annotations

import struct
from collections.abc import Callable
from dataclasses import dataclass

from hydra.core.state_models import AppState

SUPPORTED_PROTOCOLS = (
    "amneziawg",
    "anytls",
    "trusttunnel",
    "shadowtls",
    "hysteria2",
    "mieru",
    "naive",
    "snell",
    "telemt",
    "wdtt",
)
JOURNAL_UNITS = {
    "amneziawg": ("amneziawg",),
    "anytls": ("sing-box",),
    "trusttunnel": ("sing-box",),
    "shadowtls": ("sing-box",),
    "hysteria2": ("sing-box", "hysteria2"),
    "mieru": ("sing-box",),
    "naive": ("caddy-naive", "caddy-l4"),
    "snell": ("sing-box", "snell"),
    "telemt": ("telemt",),
    "wdtt": ("wdtt",),
}


@dataclass(frozen=True)
class Target:
    transport: str
    port: int
    host: str = "127.0.0.1"
    sni: str = ""


def targets(
    state: AppState,
    protocol: str,
    *,
    effective_port: Callable[[str, AppState], int],
) -> list[Target]:
    """Return local endpoints that exercise one enabled protocol parser."""
    plugin_state = state.protocols.get(protocol)
    config = plugin_state.config if plugin_state else {}
    if protocol == "amneziawg":
        ports = [
            int(profile["port"])
            for profile in config.get("profiles", {}).values()
            if isinstance(profile, dict) and profile.get("port")
        ]
        if not ports:
            ports.append(
                int(
                    plugin_state.port
                    if plugin_state and plugin_state.port
                    else 51820,
                ),
            )
        return [Target("udp", port) for port in sorted(set(ports))]
    if protocol == "hysteria2":
        fallback = (
            plugin_state.port
            if plugin_state and plugin_state.port
            else 8443
        )
        return [Target("udp", int(config.get("port", fallback)))]
    if protocol == "wdtt":
        return [Target("udp", int(config.get("dtls_port", 56000)))]
    if protocol == "mieru":
        port = plugin_state.port if plugin_state and plugin_state.port else 2012
        return [Target("tcp", int(port))]
    if protocol == "snell":
        ports = {
            int(user.credentials.get("snell", {}).get("port", 0))
            for user in state.users
            if not user.blocked
        }
        ports.discard(0)
        return [Target("tcp", port) for port in sorted(ports)[:3]]
    if protocol == "telemt":
        fallback = (
            plugin_state.port
            if plugin_state and plugin_state.port
            else 8443
        )
        return [Target("tcp", int(config.get("port", fallback)))]
    if (
        protocol == "trusttunnel"
        and str(config.get("transport", "tcp")) in {"quic", "both"}
    ):
        port = effective_port(protocol, state)
        result = [Target("udp", port)]
        if config.get("transport") == "both":
            result.append(Target("tcp", port))
        return result
    if protocol in {"anytls", "trusttunnel", "shadowtls", "naive"}:
        port = effective_port(protocol, state)
        domain = str(
            config.get(
                "domain",
                state.network.domain if protocol == "naive" else "",
            ),
        ).strip()
        mode = (
            str(config.get("network", "tcp"))
            if protocol == "naive"
            else "tcp"
        )
        result = []
        if mode in {"tcp", "both"}:
            result.append(Target("tcp", port))
        if protocol == "naive" and mode in {"quic", "both"}:
            result.append(Target("udp", port))
        if domain and port != 443:
            result.append(Target("tls", 443, sni=domain))
        return result
    return []


def awg_handshake_payload(state: AppState, target: Target) -> bytes:
    """Build a structurally sized, invalid AWG initiation for one profile."""
    plugin_state = state.protocols.get("amneziawg")
    profiles = plugin_state.config.get("profiles", {}) if plugin_state else {}
    for profile in profiles.values():
        if (
            not isinstance(profile, dict)
            or int(profile.get("port", 0) or 0) != target.port
        ):
            continue
        obfuscation = profile.get("obfuscation", {})
        if not isinstance(obfuscation, dict):
            obfuscation = {}
        try:
            header = int(obfuscation.get("H1", 1)) & 0xFFFFFFFF
            padding = max(0, min(int(obfuscation.get("S1", 0)), 1024))
        except (TypeError, ValueError):
            header, padding = 1, 0
        return struct.pack("<I", header) + bytes(144 + padding)
    return struct.pack("<I", 1) + bytes(144)
