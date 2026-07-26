"""Pure SNI-router policy, backend discovery, and ownership validation."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Any

from hydra.core.state_models import AppState


@dataclass(frozen=True)
class CaddyRouteAudit:
    """Read-only consistency report for the TLS/SNI multiplexer."""

    ok: bool
    required: bool
    config_present: bool
    service_active: bool | None
    expected: tuple[str, ...]
    actual: tuple[str, ...]
    missing: tuple[str, ...] = ()
    stale: tuple[str, ...] = ()
    certificate_errors: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def antidpi_enabled(state: AppState) -> bool:
    """Return the canonical desired AntiDPI state."""
    protocol = state.protocols.get("antidpi")
    return bool(protocol and protocol.enabled)


def get_internal_port(plugin_name: str, internal_ports: Mapping[str, int]) -> int:
    """Return the internal listener port assigned to a plugin."""
    return internal_ports.get(plugin_name, 0)


def get_decoy_http_port(plugin_name: str, decoy_ports: Mapping[str, int]) -> int:
    """Return the loopback HTTP decoy port assigned to a plugin."""
    return decoy_ports.get(plugin_name, 0)


def needs_mux(state: AppState, internal_ports: Mapping[str, int]) -> bool:
    """Decide whether the public TCP/443 SNI multiplexer is required."""
    for name in ("anytls", "trusttunnel", "hysteria2"):
        proto = state.protocols.get(name)
        if proto and proto.enabled and proto.config.get("domain"):
            return True

    count = 0
    for name in internal_ports:
        if name == "sub_server":
            continue
        proto = state.protocols.get(name)
        if not (proto and proto.enabled):
            continue
        if name == "naive":
            domain = state.network.domain
        elif name == "shadowtls":
            domain = proto.config.get("handshake_sni")
        else:
            domain = proto.config.get("domain")
        if domain:
            count += 1

    sub_domain = getattr(state.network, "sub_domain", "")
    if sub_domain:
        count += 1
    return count >= 2 or bool(sub_domain)


def get_quic_owners(state: AppState, prospective: str | None = None) -> list[str]:
    """Return every enabled/prospective protocol claiming public UDP/443."""
    owners: list[str] = []
    naive = state.protocols.get("naive")
    if naive and (naive.enabled or prospective == "naive"):
        if naive.config.get("network", "tcp") in ("quic", "both"):
            owners.append("naive")

    trusttunnel = state.protocols.get("trusttunnel")
    if trusttunnel and (trusttunnel.enabled or prospective == "trusttunnel"):
        if trusttunnel.config.get("transport", "tcp") in ("quic", "both"):
            owners.append("trusttunnel")
    return owners


def get_quic_owner(state: AppState, prospective: str | None = None) -> str | None:
    """Return the sole UDP/443 owner, rejecting ambiguous ownership."""
    owners = get_quic_owners(state, prospective=prospective)
    if len(owners) > 1:
        labels = ", ".join(owners)
        raise ValueError(
            "UDP/443 одновременно запрошен несколькими "
            f"QUIC-протоколами: {labels}"
        )
    return owners[0] if owners else None


def has_sub_domain(state: AppState) -> bool:
    """Return whether the subscription endpoint has a dedicated SNI."""
    return bool(getattr(state.network, "sub_domain", ""))


def collect_backends(
    state: AppState,
    internal_ports: Mapping[str, int],
) -> list[dict[str, Any]]:
    """Project persisted protocol state into renderer-friendly backends."""
    backends: list[dict[str, Any]] = []
    for name, port in internal_ports.items():
        if name == "sub_server":
            continue
        proto = state.protocols.get(name)
        if not (proto and proto.enabled):
            continue
        if name == "naive":
            domain = state.network.domain
        elif name == "shadowtls":
            domain = proto.config.get("handshake_sni", "")
        else:
            domain = proto.config.get("domain", "")
        if not domain:
            continue
        backends.append({
            "name": name,
            "domain": domain,
            "port": port,
            "cert_file": proto.config.get("cert_file", ""),
            "key_file": proto.config.get("key_file", ""),
            "network_mode": (
                proto.config.get("network", "tcp")
                if name == "naive"
                else (
                    proto.config.get("transport", "tcp")
                    if name == "trusttunnel"
                    else ""
                )
            ),
        })

    sub_domain = getattr(state.network, "sub_domain", "")
    if sub_domain:
        backends.append({
            "name": "sub_server",
            "domain": sub_domain,
            "port": internal_ports["sub_server"],
            "cert_file": "",
            "key_file": "",
        })
    return backends


def has_source_preservation(config: object) -> bool:
    """Inspect a rendered document without touching the filesystem."""
    if isinstance(config, dict):
        if config.get("local_address") == ["{l4.conn.remote_addr}"]:
            return True
        return any(has_source_preservation(value) for value in config.values())
    if isinstance(config, list):
        return any(has_source_preservation(value) for value in config)
    return False


def source_preservation_ports(
    backends: list[dict[str, Any]],
    quic_owner: str | None,
    *,
    enabled: bool,
    internal_ports: Mapping[str, int],
    decoy_ports: Mapping[str, int],
    preserved_backends: frozenset[str],
) -> tuple[set[int], set[int]]:
    """Plan transparent-source routing ports."""
    if not enabled:
        return set(), set()
    tcp_ports: set[int] = set()
    udp_ports: set[int] = set()
    names = {str(backend["name"]) for backend in backends}
    if "naive" in names:
        tcp_ports.add(internal_ports["naive"])
    if "anytls" in names:
        tcp_ports.update((internal_ports["anytls"], decoy_ports["anytls"]))
    if "trusttunnel" in names:
        tcp_ports.add(decoy_ports["trusttunnel"])
    if quic_owner in preserved_backends:
        udp_ports.add(internal_ports[quic_owner])
    return tcp_ports, udp_ports


def relay_routes(
    backends: list[dict[str, Any]],
    state: AppState,
    relay_ports: Mapping[str, int],
) -> list[tuple[str, int, int]]:
    """Plan TCP exact-source relay routes."""
    if not antidpi_enabled(state):
        return []
    return [
        (str(backend["name"]), relay_ports[str(backend["name"])], int(backend["port"]))
        for backend in backends
        if backend["name"] in relay_ports
    ]


def udp_relay_routes(
    backends: list[dict[str, Any]],
    state: AppState,
    udp_relay_ports: Mapping[str, int],
) -> list[tuple[str, int, int]]:
    """Plan the sole UDP exact-source relay route."""
    owner = get_quic_owner(state)
    if not antidpi_enabled(state) or owner not in udp_relay_ports:
        return []
    backend = next((item for item in backends if item["name"] == owner), None)
    if backend is None:
        return []
    return [(owner, udp_relay_ports[owner], int(backend["port"]))]
