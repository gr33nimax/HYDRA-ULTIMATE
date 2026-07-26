"""Pure SNI-router policy, backend discovery, and ownership validation."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Any

from hydra.core.state_models import AppState


_DYNAMIC_ROUTE_KEY = "_tls_http_decoy_route"
_DYNAMIC_ROUTE_KIND = "http_path_proxy"
_DECOY_THEMES = frozenset({"landing", "blog", "docs", "media", "status"})


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
    if any(
        protocol.enabled
        and protocol.config.get("domain")
        and isinstance(protocol.config.get(_DYNAMIC_ROUTE_KEY), Mapping)
        and protocol.config[_DYNAMIC_ROUTE_KEY].get("kind")
        == _DYNAMIC_ROUTE_KIND
        for protocol in state.protocols.values()
    ):
        return True

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
    *,
    reserved_ports: set[int] | frozenset[int] = frozenset(),
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

    occupied_ports = {
        *(int(item) for item in internal_ports.values()),
        *(int(item) for item in reserved_ports),
    }
    for name, proto in sorted(state.protocols.items()):
        if name in internal_ports or not proto.enabled:
            continue
        route = proto.config.get(_DYNAMIC_ROUTE_KEY)
        if route is None:
            continue
        backend = _dynamic_backend(
            name,
            proto.config,
            route,
            occupied_ports,
        )
        backends.append(backend)
        occupied_ports.update(
            (int(backend["port"]), int(backend["decoy_port"])),
        )

    sub_domain = getattr(state.network, "sub_domain", "")
    if sub_domain:
        backends.append({
            "name": "sub_server",
            "domain": sub_domain,
            "port": internal_ports["sub_server"],
            "cert_file": "",
            "key_file": "",
        })
    _validate_unique_domains(backends)
    return backends


def _validate_unique_domains(backends: list[dict[str, Any]]) -> None:
    owners: dict[str, str] = {}
    for backend in backends:
        domain = str(backend.get("domain", "")).strip().lower().rstrip(".")
        if not domain:
            continue
        previous = owners.get(domain)
        if previous is not None:
            raise ValueError(
                f"TLS domain {domain} is assigned to both "
                f"{previous} and {backend['name']}",
            )
        owners[domain] = str(backend["name"])


def _route_error(name: str, detail: str) -> ValueError:
    return ValueError(f"Invalid plugin-owned TLS route for {name}: {detail}")


def _route_port(
    name: str,
    value: object,
    field: str,
    occupied_ports: set[int],
) -> int:
    if isinstance(value, bool):
        raise _route_error(name, f"{field} must be an integer port")
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise _route_error(name, f"{field} must be an integer port")
    if not 1024 <= port <= 65535 or port in {80, 443}:
        raise _route_error(name, f"{field} must be a private high port")
    if port in occupied_ports:
        raise _route_error(name, f"{field} conflicts with port {port}")
    return port


def _dynamic_backend(
    name: str,
    config: Mapping[str, Any],
    route: object,
    occupied_ports: set[int],
) -> dict[str, Any]:
    if (
        not isinstance(route, Mapping)
        or route.get("kind") != _DYNAMIC_ROUTE_KIND
    ):
        raise _route_error(name, f"kind must be {_DYNAMIC_ROUTE_KIND}")
    domain = str(config.get("domain", "")).strip()
    if not domain:
        raise _route_error(name, "domain is required")
    internal_port = _route_port(
        name,
        route.get("internal_port"),
        "internal_port",
        occupied_ports,
    )
    decoy_port = _route_port(
        name,
        route.get("decoy_http_port"),
        "decoy_http_port",
        occupied_ports | {internal_port},
    )
    root = str(route.get("decoy_root", ""))
    root_parts = root.split("/")[1:]
    if (
        not root.startswith("/var/www/decoy-")
        or "\\" in root
        or any(part in {"", ".", ".."} for part in root_parts)
    ):
        raise _route_error(name, "decoy_root must be under /var/www/decoy-*")
    theme = str(route.get("decoy_theme", ""))
    if theme not in _DECOY_THEMES:
        raise _route_error(name, "decoy_theme is not supported")
    path_key = route.get("path_config")
    if not isinstance(path_key, str) or not path_key:
        raise _route_error(name, "path_config must name a config field")
    proxy_path = str(config.get(path_key, "")).strip().rstrip("/")
    path_parts = proxy_path.split("/")[1:]
    if (
        not proxy_path.startswith("/")
        or proxy_path == ""
        or any(character.isspace() for character in proxy_path)
        or any(character in proxy_path for character in "?#*%\\")
        or any(part in {"", ".", ".."} for part in path_parts)
    ):
        raise _route_error(name, f"{path_key} is not a valid HTTP path")
    return {
        "name": name,
        "domain": domain,
        "port": internal_port,
        "cert_file": config.get("cert_file", ""),
        "key_file": config.get("key_file", ""),
        "network_mode": "",
        "route_kind": _DYNAMIC_ROUTE_KIND,
        "decoy_port": decoy_port,
        "decoy_root": root,
        "decoy_theme": theme,
        "proxy_path": proxy_path,
    }


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
