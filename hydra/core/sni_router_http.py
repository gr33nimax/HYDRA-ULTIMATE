"""Pure HTTP decoy-server sections for the Caddy SNI document."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol


Backend = dict[str, Any]


class RenderSettings(Protocol):
    internal_ports: dict[str, int]
    decoy_ports: dict[str, int]
    relay_ports: dict[str, int]


def _redirect_server() -> dict[str, Any]:
    return {
        "listen": [":80"],
        "automatic_https": {
            "disable": True,
            "disable_redirects": True,
        },
        "routes": [
            {
                "handle": [
                    {
                        "handler": "static_response",
                        "status_code": 308,
                        "headers": {
                            "Location": [
                                "https://{http.request.host}"
                                "{http.request.uri}",
                            ],
                        },
                    },
                ],
            },
        ],
    }


def _static_decoy_server(
    backend: Backend,
    *,
    listen_port: int,
    root: str,
    logger: str,
    listener_wrappers: Callable[[], list[dict[str, Any]]],
) -> dict[str, Any]:
    return {
        "listen": [f"127.0.0.1:{listen_port}"],
        "listener_wrappers": listener_wrappers(),
        "automatic_https": {
            "disable": True,
            "disable_redirects": True,
        },
        "routes": [
            {
                "handle": [
                    {"handler": "file_server", "root": root},
                ],
            },
        ],
        "logs": {"logger_names": {backend["domain"]: logger}},
    }


def _trusttunnel_server(
    backend: Backend,
    settings: RenderSettings,
    *,
    relay_enabled: bool,
    listener_wrappers: Callable[[], list[dict[str, Any]]],
) -> dict[str, Any]:
    relay = relay_enabled and "trusttunnel" in settings.relay_ports
    upstream_port = (
        settings.relay_ports["trusttunnel"]
        if relay
        else settings.internal_ports["trusttunnel"]
    )
    transport: dict[str, Any] = {
        "protocol": "http",
        "versions": ["2"],
        "response_header_timeout": "5s",
        "tls": {"insecure_skip_verify": True},
    }
    if relay:
        transport["proxy_protocol"] = "v2"
        transport["keep_alive"] = {"enabled": False}
    decoy_handler = {
        "handler": "file_server",
        "root": "/var/www/decoy-c",
    }
    return {
        "listen": [
            f"127.0.0.1:{settings.decoy_ports['trusttunnel']}",
        ],
        "listener_wrappers": listener_wrappers(),
        "automatic_https": {
            "disable": True,
            "disable_redirects": True,
        },
        "routes": [
            {
                "match": [{"method": ["CONNECT"]}],
                "handle": [
                    {
                        "handler": "reverse_proxy",
                        "upstreams": [
                            {"dial": f"127.0.0.1:{upstream_port}"},
                        ],
                        "transport": transport,
                        "headers": {
                            "request": {
                                "set": {
                                    "Proxy-Authorization": [
                                        "{http.request.header."
                                        "Proxy-Authorization}",
                                    ],
                                    "Authorization": [
                                        "{http.request.header.Authorization}",
                                    ],
                                    "Host": ["{http.request.hostport}"],
                                },
                            },
                        },
                        "handle_response": [
                            {
                                "match": {
                                    "status_code": [502, 503, 504],
                                },
                                "routes": [
                                    {
                                        "handle": [
                                            decoy_handler.copy(),
                                        ],
                                    },
                                ],
                            },
                        ],
                    },
                ],
            },
            {"handle": [decoy_handler.copy()]},
        ],
        "errors": {
            "routes": [{"handle": [decoy_handler.copy()]}],
        },
        "logs": {
            "logger_names": {
                backend["domain"]: "trusttunnel",
            },
        },
    }


def http_servers(
    backends: list[Backend],
    settings: RenderSettings,
    *,
    relay_enabled: bool,
    listener_wrappers: Callable[[], list[dict[str, Any]]],
) -> dict[str, Any]:
    """Render redirect and protocol decoy servers."""
    servers = {"https_redirect": _redirect_server()}
    by_name = {str(item["name"]): item for item in backends}
    if anytls := by_name.get("anytls"):
        servers["anytls_decoy"] = _static_decoy_server(
            anytls,
            listen_port=settings.decoy_ports["anytls"],
            root="/var/www/decoy-b",
            logger="decoy",
            listener_wrappers=listener_wrappers,
        )
    if trusttunnel := by_name.get("trusttunnel"):
        servers["trusttunnel_decoy"] = _trusttunnel_server(
            trusttunnel,
            settings,
            relay_enabled=relay_enabled,
            listener_wrappers=listener_wrappers,
        )
    if hysteria2 := by_name.get("hysteria2"):
        servers["hysteria2_decoy"] = _static_decoy_server(
            hysteria2,
            listen_port=settings.decoy_ports["hysteria2"],
            root="/var/www/decoy-hysteria2",
            logger="decoy",
            listener_wrappers=listener_wrappers,
        )
    return servers


__all__ = ["http_servers"]
