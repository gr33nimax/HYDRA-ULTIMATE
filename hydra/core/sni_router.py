"""Compatibility facade and composition root for Hydra's Caddy L4 SNI router."""
from __future__ import annotations

import urllib.request
from pathlib import Path

from hydra.core import (
    sni_router_audit as _audit,
    sni_router_install as _installer,
    sni_router_planning as _planning,
    sni_router_document as _rendering,
    sni_router_runtime as _runtime,
    sni_router_units as _units,
)
from hydra.core.host import HOST
from hydra.core.install_layout import project_root
from hydra.core.sni_router_planning import CaddyRouteAudit
from hydra.core.state_models import AppState


CADDY_BIN = Path("/usr/local/bin/caddy-l4")
CADDY_CFG = Path("/etc/caddy-l4/config.json")
CADDY_CFG_DIR = Path("/etc/caddy-l4")
CADDY_LOG_DIR = Path("/var/log/caddy-l4")
DECOY_LOG = CADDY_LOG_DIR / "decoy-access.log"
TRUSTTUNNEL_LOG = CADDY_LOG_DIR / "trusttunnel-access.log"
SERVICE_NAME = "caddy-l4"
SERVICE_FILE = Path("/etc/systemd/system/caddy-l4.service")
CADDY_ADMIN_ADDRESS = "127.0.0.1:2021"
SOURCE_SERVICE_NAME = "hydra-caddy-source"
SOURCE_SERVICE_FILE = Path(
    f"/etc/systemd/system/{SOURCE_SERVICE_NAME}.service"
)
RELAY_SERVICE_NAME = "hydra-source-relay"
RELAY_SERVICE_FILE = Path(
    f"/etc/systemd/system/{RELAY_SERVICE_NAME}.service"
)
FRONTEND_PORT = 443
CADDY_L4_VERSION = "42db5690dea199f930a6f08005fe2e4aab10dcc9"
GO_VERSION = "1.25.1"
GO_RELEASES_URL = "https://go.dev/dl/?mode=json&include=all"
CADDY_BUILD_TIMEOUT = 900

_INTERNAL_PORTS = {
    "naive": 10443,
    "anytls": 20444,
    "trusttunnel": 20445,
    "shadowtls": 20446,
    "hysteria2": 20447,
    "sub_server": 9443,
}
_DECOY_HTTP_PORTS = {
    "anytls": 10801,
    "trusttunnel": 10802,
    "hysteria2": 10803,
}
_SOURCE_RELAY_PORTS = {
    "anytls": 21444,
    "trusttunnel": 21445,
    "shadowtls": 21446,
    "vless": 21448,
}
_UDP_SOURCE_RELAY_PORTS = {
    "naive": 21443,
    "trusttunnel": 21445,
}
_SOURCE_PRESERVED_BACKENDS = frozenset(
    {"naive", "anytls", "trusttunnel", "shadowtls"}
)
# Non-local loopback source binding is disabled on supported production kernels.
# Runtime rollback remains in place to clean up hosts that used the experiment.
SOURCE_PRESERVATION_ENABLED = False


def _install_settings() -> _installer.InstallSettings:
    return _installer.InstallSettings(
        binary=CADDY_BIN,
        caddy_l4_version=CADDY_L4_VERSION,
        go_version=GO_VERSION,
        go_releases_url=GO_RELEASES_URL,
        build_timeout=CADDY_BUILD_TIMEOUT,
    )


def _unit_settings() -> _units.UnitSettings:
    return _units.UnitSettings(
        caddy_binary=CADDY_BIN,
        caddy_config=CADDY_CFG,
        caddy_admin_address=CADDY_ADMIN_ADDRESS,
        caddy_service_name=SERVICE_NAME,
        caddy_service_file=SERVICE_FILE,
        source_service_name=SOURCE_SERVICE_NAME,
        source_service_file=SOURCE_SERVICE_FILE,
        relay_service_name=RELAY_SERVICE_NAME,
        relay_service_file=RELAY_SERVICE_FILE,
        project_root=project_root(
            Path(__file__).resolve().parent.parent.parent,
        ),
    )


def _runtime_settings() -> _runtime.RuntimeSettings:
    return _runtime.RuntimeSettings(
        caddy_binary=CADDY_BIN,
        caddy_config=CADDY_CFG,
        caddy_config_dir=CADDY_CFG_DIR,
        caddy_log_dir=CADDY_LOG_DIR,
        caddy_service_name=SERVICE_NAME,
        caddy_service_file=SERVICE_FILE,
        source_service_name=SOURCE_SERVICE_NAME,
        source_service_file=SOURCE_SERVICE_FILE,
        relay_service_name=RELAY_SERVICE_NAME,
        relay_service_file=RELAY_SERVICE_FILE,
        internal_ports=_INTERNAL_PORTS,
        decoy_ports=_DECOY_HTTP_PORTS,
    )


def _render_settings() -> _rendering.RenderSettings:
    return _rendering.RenderSettings(
        internal_ports=_INTERNAL_PORTS,
        decoy_ports=_DECOY_HTTP_PORTS,
        relay_ports=_SOURCE_RELAY_PORTS,
        udp_relay_ports=_UDP_SOURCE_RELAY_PORTS,
        preserved_backends=_SOURCE_PRESERVED_BACKENDS,
        source_preservation_enabled=SOURCE_PRESERVATION_ENABLED,
        decoy_log=str(DECOY_LOG),
        trusttunnel_log=str(TRUSTTUNNEL_LOG),
        admin_address=CADDY_ADMIN_ADDRESS,
    )


def _runtime_operations() -> _runtime.RuntimeOperations:
    """Resolve facade functions at call time to preserve legacy patch seams."""
    return _runtime.RuntimeOperations(
        get_quic_owner=get_quic_owner,
        config_had_quic_proxy=_caddy_config_had_quic_proxy,
        collect_backends=_collect_backends,
        needs_mux=needs_mux,
        stop=stop,
        is_installed=is_installed,
        install=install,
        generate_config=_generate_config,
        has_source_preservation=_has_source_preservation,
        restore_binary=_restore_previous_caddy_binary,
        source_ports=_source_preservation_ports,
        relay_routes=_relay_routes,
        udp_relay_routes=_udp_relay_routes,
        install_source_service=_install_source_service,
        remove_source_service=_remove_source_service,
        install_relay_service=_install_relay_service,
        remove_relay_service=_remove_relay_service,
        install_caddy_service=_install_service,
        restore_unit_file=_restore_unit_file,
        is_active=is_active,
    )


def _proxy_handler(
    address: str,
    *,
    preserve_source: bool = False,
    proxy_protocol: bool = False,
) -> dict:
    return _rendering.proxy_handler(
        address,
        source_preservation_enabled=SOURCE_PRESERVATION_ENABLED,
        preserve_source=preserve_source,
        proxy_protocol=proxy_protocol,
    )


def _decoy_listener_wrappers() -> list[dict]:
    return _rendering.decoy_listener_wrappers()


def _antidpi_enabled(state: AppState) -> bool:
    return _planning.antidpi_enabled(state)


def get_internal_port(plugin_name: str) -> int:
    return _planning.get_internal_port(plugin_name, _INTERNAL_PORTS)


def get_decoy_http_port(plugin_name: str) -> int:
    return _planning.get_decoy_http_port(plugin_name, _DECOY_HTTP_PORTS)


def needs_mux(state: AppState) -> bool:
    return _planning.needs_mux(state, _INTERNAL_PORTS)


def get_effective_port(plugin_name: str, state: AppState) -> int:
    return get_internal_port(plugin_name) if needs_mux(state) else FRONTEND_PORT


def get_quic_owners(
    state: AppState,
    prospective: str | None = None,
) -> list[str]:
    return _planning.get_quic_owners(state, prospective=prospective)


def get_quic_owner(
    state: AppState,
    prospective: str | None = None,
) -> str | None:
    return _planning.get_quic_owner(state, prospective=prospective)


def _has_sub_domain(state: AppState) -> bool:
    return _planning.has_sub_domain(state)


def _collect_backends(state: AppState) -> list[dict]:
    reserved_ports = {
        *_DECOY_HTTP_PORTS.values(),
        *_SOURCE_RELAY_PORTS.values(),
        *_UDP_SOURCE_RELAY_PORTS.values(),
        2021,
    }
    return _planning.collect_backends(
        state,
        _INTERNAL_PORTS,
        reserved_ports=reserved_ports,
    )


def audit_routes(state: AppState) -> CaddyRouteAudit:
    return _audit.audit_routes(
        state,
        config_path=CADDY_CFG,
        service_name=SERVICE_NAME,
        collect_backends=_collect_backends,
        needs_mux=needs_mux,
        is_active=is_active,
    )


def _generate_config(backends: list[dict], state: AppState) -> dict:
    return _rendering.generate_config(
        backends,
        state,
        _render_settings(),
        antidpi_enabled=_antidpi_enabled,
        quic_owner=get_quic_owner,
        proxy_factory=_proxy_handler,
        listener_wrappers=_decoy_listener_wrappers,
    )


def _has_source_preservation(config: object) -> bool:
    return _planning.has_source_preservation(config)


def _source_preservation_ports(
    backends: list[dict],
    quic_owner: str | None,
) -> tuple[set[int], set[int]]:
    return _planning.source_preservation_ports(
        backends,
        quic_owner,
        enabled=SOURCE_PRESERVATION_ENABLED,
        internal_ports=_INTERNAL_PORTS,
        decoy_ports=_DECOY_HTTP_PORTS,
        preserved_backends=_SOURCE_PRESERVED_BACKENDS,
    )


def _relay_routes(
    backends: list[dict],
    state: AppState,
) -> list[tuple[str, int, int]]:
    return _planning.relay_routes(backends, state, _SOURCE_RELAY_PORTS)


def _udp_relay_routes(
    backends: list[dict],
    state: AppState,
) -> list[tuple[str, int, int]]:
    return _planning.udp_relay_routes(
        backends,
        state,
        _UDP_SOURCE_RELAY_PORTS,
    )


def is_installed() -> bool:
    return _installer.is_installed(CADDY_BIN)


def _official_go_digest(go_filename: str) -> str | None:
    return _installer.official_go_digest(
        go_filename,
        releases_url=GO_RELEASES_URL,
        urlopen=urllib.request.urlopen,
    )


def _ensure_modern_go() -> bool:
    return _installer.ensure_modern_go(
        _install_settings(),
        HOST,
        official_digest=_official_go_digest,
    )


def _run_caddy_build(args: list[str], env: dict[str, str]):
    return _installer.run_caddy_build(
        args,
        env,
        host=HOST,
        timeout=CADDY_BUILD_TIMEOUT,
    )


def install(
    state: AppState | None = None,
    *,
    force: bool = False,
) -> bool:
    return _installer.install(
        state,
        _install_settings(),
        HOST,
        force=force,
        installed=is_installed,
        ensure_go=_ensure_modern_go,
        build=_run_caddy_build,
    )


def _restore_previous_caddy_binary() -> bool:
    return _installer.restore_previous_binary(CADDY_BIN)


def is_active() -> bool:
    return _runtime.is_active(
        _runtime_settings(),
        HOST,
        is_installed=is_installed,
    )


def probe_tls_route(domain: str) -> tuple[bool, str]:
    return _runtime.probe_tls_route(domain)


def _caddy_config_had_quic_proxy() -> bool:
    return _runtime.config_had_quic_proxy(CADDY_CFG)


def _install_source_service(
    tcp_ports: set[int],
    udp_ports: set[int],
) -> None:
    _units.install_source_service(
        tcp_ports,
        udp_ports,
        _unit_settings(),
        HOST,
    )


def _remove_source_service() -> None:
    _units.remove_source_service(_unit_settings(), HOST)


def _install_relay_service(
    routes: list[tuple[str, int, int]],
    udp_routes: list[tuple[str, int, int]] | None = None,
) -> None:
    _units.install_relay_service(
        routes,
        list(udp_routes or []),
        _unit_settings(),
        HOST,
    )


def _remove_relay_service() -> None:
    _units.remove_relay_service(_unit_settings(), HOST)


def _restore_unit_file(path: Path, content: bytes | None) -> None:
    _units.restore_unit_file(path, content)


def _install_service(
    *,
    source_required: bool = False,
    relay_required: bool = False,
) -> bool:
    return _units.install_caddy_service(
        _unit_settings(),
        HOST,
        source_required=source_required,
        relay_required=relay_required,
    )


def rebuild(state: AppState) -> bool:
    return _runtime.rebuild(
        state,
        _runtime_settings(),
        HOST,
        _runtime_operations(),
    )


def stop() -> None:
    _runtime.stop(
        _runtime_settings(),
        HOST,
        is_installed=is_installed,
        remove_source_service=_remove_source_service,
        remove_relay_service=_remove_relay_service,
    )


def uninstall_haproxy() -> None:
    _runtime.uninstall_haproxy(HOST)


__all__ = [
    "CADDY_ADMIN_ADDRESS",
    "CADDY_BIN",
    "CADDY_BUILD_TIMEOUT",
    "CADDY_CFG",
    "CaddyRouteAudit",
    "DECOY_LOG",
    "GO_RELEASES_URL",
    "TRUSTTUNNEL_LOG",
    "audit_routes",
    "get_decoy_http_port",
    "get_effective_port",
    "get_internal_port",
    "get_quic_owner",
    "get_quic_owners",
    "install",
    "is_active",
    "is_installed",
    "needs_mux",
    "probe_tls_route",
    "rebuild",
    "stop",
    "uninstall_haproxy",
]
