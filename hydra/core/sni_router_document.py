"""Pure, section-oriented Caddy document rendering for the SNI router."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from hydra.core.sni_router_http import http_servers
from hydra.core.state_models import AppState


Backend = dict[str, Any]
ProxyFactory = Callable[..., dict[str, Any]]


@dataclass(frozen=True)
class RenderSettings:
    """Values needed to render Caddy configuration without host access."""

    internal_ports: Mapping[str, int]
    decoy_ports: Mapping[str, int]
    relay_ports: Mapping[str, int]
    udp_relay_ports: Mapping[str, int]
    preserved_backends: frozenset[str]
    source_preservation_enabled: bool
    decoy_log: str
    trusttunnel_log: str
    admin_address: str


def proxy_handler(
    address: str,
    *,
    source_preservation_enabled: bool,
    preserve_source: bool = False,
    proxy_protocol: bool = False,
) -> dict[str, Any]:
    """Build a Caddy L4 proxy handler."""
    upstream: dict[str, Any] = {"dial": [address]}
    if preserve_source and source_preservation_enabled:
        upstream["local_address"] = ["{l4.conn.remote_addr}"]
    handler: dict[str, Any] = {
        "handler": "proxy",
        "upstreams": [upstream],
    }
    if proxy_protocol:
        handler["proxy_protocol"] = "v2"
    return handler


def decoy_listener_wrappers() -> list[dict[str, Any]]:
    """Accept L4 PROXY headers only from loopback interfaces."""
    return [
        {
            "wrapper": "proxy_protocol",
            "timeout": "1s",
            "allow": ["127.0.0.0/8", "::1/128"],
            "fallback_policy": "require",
        },
    ]


def _logging(settings: RenderSettings) -> dict[str, Any]:
    return {
        "logs": {
            "default": {"writer": {"output": "discard"}},
            "decoy": {
                "writer": {
                    "output": "file",
                    "filename": settings.decoy_log,
                },
                "include": ["http.log.access.decoy"],
                "level": "INFO",
            },
            "antidpi": {
                "writer": {
                    "output": "file",
                    "filename": "/var/log/caddy-l4/antidpi.jsonl",
                },
                "include": ["layer4"],
                "level": "INFO",
            },
            "trusttunnel": {
                "writer": {
                    "output": "file",
                    "filename": settings.trusttunnel_log,
                },
                "include": ["http.log.access.trusttunnel"],
                "level": "INFO",
            },
        },
    }


def _tls_app(backends: list[Backend]) -> dict[str, Any]:
    certificates = [
        {
            "certificate": backend["cert_file"],
            "key": backend["key_file"],
        }
        for backend in backends
        if (
            backend["name"]
            in ("anytls", "trusttunnel", "hysteria2")
            and backend["cert_file"]
            and backend["key_file"]
        )
    ]
    return (
        {"certificates": {"load_files": certificates}}
        if certificates
        else {}
    )


def _tls_route(
    backend: Backend,
    settings: RenderSettings,
    *,
    relay_enabled: bool,
    proxy_factory: ProxyFactory,
) -> dict[str, Any] | None:
    name = backend["name"]
    domain = backend["domain"]
    port = backend["port"]
    match = [{"tls": {"sni": [domain]}}]

    if name == "naive":
        handlers = [
            proxy_factory(f"127.0.0.1:{port}", proxy_protocol=True),
        ]
    elif name == "shadowtls":
        target = (
            settings.relay_ports["shadowtls"]
            if relay_enabled
            else port
        )
        handlers = [
            proxy_factory(
                f"127.0.0.1:{target}",
                proxy_protocol=relay_enabled,
            ),
        ]
    elif name == "anytls":
        target = (
            settings.relay_ports["anytls"]
            if relay_enabled
            else port
        )
        handlers = [
            {"handler": "tls"},
            {
                "handler": "subroute",
                "routes": [
                    {
                        "match": [{"not": [{"http": []}]}],
                        "handle": [
                            proxy_factory(
                                f"127.0.0.1:{target}",
                                proxy_protocol=relay_enabled,
                            ),
                        ],
                    },
                    {
                        "handle": [
                            proxy_factory(
                                "127.0.0.1:"
                                f"{settings.decoy_ports['anytls']}",
                                proxy_protocol=True,
                            ),
                        ],
                    },
                ],
            },
        ]
    elif name in ("trusttunnel", "hysteria2"):
        handlers = [
            {"handler": "tls"},
            proxy_factory(
                f"127.0.0.1:{settings.decoy_ports[name]}",
                proxy_protocol=True,
            ),
        ]
    elif name == "sub_server":
        handlers = [proxy_factory(f"127.0.0.1:{port}")]
    else:
        return None
    return {"match": match, "handle": handlers}


def _tls_routes(
    backends: list[Backend],
    settings: RenderSettings,
    *,
    relay_enabled: bool,
    proxy_factory: ProxyFactory,
) -> list[dict[str, Any]]:
    routes = [
        route
        for backend in backends
        if (
            route := _tls_route(
                backend,
                settings,
                relay_enabled=relay_enabled,
                proxy_factory=proxy_factory,
            )
        )
    ]
    fallback = next(
        (
            item
            for item in backends
            if item["name"] in ("anytls", "trusttunnel")
        ),
        None,
    )
    if fallback:
        fallback_port = settings.decoy_ports[str(fallback["name"])]
        routes.append(
            {
                "handle": [
                    {"handler": "tls"},
                    proxy_factory(
                        f"127.0.0.1:{fallback_port}",
                        proxy_protocol=True,
                    ),
                ],
            },
        )
    return routes


def _quic_server(
    backends: list[Backend],
    state: AppState,
    settings: RenderSettings,
    *,
    relay_enabled: bool,
    quic_owner: Callable[[AppState], str | None],
    proxy_factory: ProxyFactory,
) -> dict[str, Any] | None:
    owner = quic_owner(state)
    if not owner:
        return None
    backend = next(
        (item for item in backends if item["name"] == owner),
        None,
    )
    if not backend:
        raise ValueError(f"QUIC backend {owner} отсутствует в Caddy config")
    udp_relay_enabled = (
        relay_enabled and backend["name"] in settings.udp_relay_ports
    )
    target_port = (
        settings.udp_relay_ports[str(backend["name"])]
        if udp_relay_enabled
        else backend["port"]
    )
    return {
        "listen": ["udp/:443"],
        "routes": [
            {
                "handle": [
                    proxy_factory(
                        f"udp/127.0.0.1:{target_port}",
                        preserve_source=(
                            backend["name"] in settings.preserved_backends
                        ),
                        proxy_protocol=udp_relay_enabled,
                    ),
                ],
            },
        ],
    }


def generate_config(
    backends: list[Backend],
    state: AppState,
    settings: RenderSettings,
    *,
    antidpi_enabled: Callable[[AppState], bool],
    quic_owner: Callable[[AppState], str | None],
    proxy_factory: ProxyFactory,
    listener_wrappers: Callable[[], list[dict[str, Any]]],
) -> dict[str, Any]:
    """Render a complete Caddy document from an already validated plan."""
    relay_enabled = antidpi_enabled(state)
    servers: dict[str, Any] = {
        "tls_mux": {
            "listen": [":443"],
            "routes": _tls_routes(
                backends,
                settings,
                relay_enabled=relay_enabled,
                proxy_factory=proxy_factory,
            ),
        },
    }
    quic = _quic_server(
        backends,
        state,
        settings,
        relay_enabled=relay_enabled,
        quic_owner=quic_owner,
        proxy_factory=proxy_factory,
    )
    if quic:
        servers["quic_mux"] = quic

    apps: dict[str, Any] = {
        "layer4": {"servers": servers},
        "http": {
            "servers": http_servers(
                backends,
                settings,
                relay_enabled=relay_enabled,
                listener_wrappers=listener_wrappers,
            ),
        },
    }
    if tls := _tls_app(backends):
        apps["tls"] = tls
    return {
        "admin": {"listen": settings.admin_address},
        "logging": _logging(settings),
        "apps": apps,
    }


__all__ = [
    "RenderSettings",
    "decoy_listener_wrappers",
    "generate_config",
    "proxy_handler",
]
