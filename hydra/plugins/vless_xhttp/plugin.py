"""VLESS over XHTTP for the shtorm-7 sing-box-extended core."""
from __future__ import annotations

import json
import re
import urllib.parse

from hydra.core.state_models import User
from hydra.plugins.base import (
    BasePlugin,
    ConfigFragment,
    HealthResult,
    PluginCategory,
    PluginMeta,
    PluginStatus,
)
from hydra.plugins.context import PluginStateAccess
from hydra.utils.tls import resolve_tls_material


INTERNAL_PORT = 20448
DECOY_HTTP_PORT = 10804
DECOY_DIR = "/var/www/decoy-vless"
DEFAULT_PATH = "/xhttp"
DEFAULT_MODE = "stream-up"
ROUTE_CONFIG_KEY = "_tls_http_decoy_route"
XHTTP_MODES = frozenset({"stream-up", "packet-up", "stream-one"})


def _validate_path(value: object) -> str:
    path = str(value or "").strip()
    segments = path.split("/")[1:]
    if (
        not path.startswith("/")
        or path == "/"
        or len(path) > 256
        or any(character.isspace() for character in path)
        or any(character in path for character in "?#*%\\")
        or any(
            segment in {"", ".", ".."}
            or not re.fullmatch(r"[A-Za-z0-9._~-]+", segment)
            for segment in segments
        )
    ):
        raise ValueError(
            "XHTTP path must start with '/', identify a non-root path, "
            "and contain no whitespace, query, or fragment",
        )
    return path.rstrip("/")


def _validate_mode(value: object) -> str:
    mode = str(value or "").strip().lower()
    if mode not in XHTTP_MODES:
        allowed = ", ".join(sorted(XHTTP_MODES))
        raise ValueError(f"XHTTP mode must be one of: {allowed}")
    return mode


def _normalize_domain(value: object) -> str:
    domain = str(value or "").strip().lower().rstrip(".")
    labels = domain.split(".")
    if (
        not domain
        or len(domain) > 253
        or "://" in domain
        or any(character.isspace() for character in domain)
        or len(labels) < 2
        or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in labels
        )
    ):
        raise ValueError("VLESS XHTTP domain is invalid")
    return domain


class VlessXhttpPlugin(BasePlugin):
    """Multi-user VLESS/XHTTP endpoint behind Caddy TLS routing."""

    meta = PluginMeta(
        name="vless",
        display_name="VLESS + XHTTP",
        description=(
            "VLESS over XHTTP from sing-box-extended with a dedicated "
            "TLS domain and decoy website"
        ),
        category=PluginCategory.TRANSPORT,
        version="1.0.0",
        needs_domain=True,
        required_commands=("sing-box",),
        commands=("set_domain", "set_path", "set_mode"),
        tls_domain_source="protocol",
        config_defaults=(
            ("xhttp_mode", DEFAULT_MODE),
            ("xhttp_path", DEFAULT_PATH),
            (ROUTE_CONFIG_KEY, {
                "kind": "http_path_proxy",
                "internal_port": INTERNAL_PORT,
                "decoy_http_port": DECOY_HTTP_PORT,
                "decoy_root": DECOY_DIR,
                "decoy_theme": "media",
                "path_config": "xhttp_path",
            }),
        ),
        connection_source="tracked",
    )

    @staticmethod
    def route_config() -> dict[str, object]:
        """Return a fresh copy of the declarative Caddy route defaults."""
        return dict(dict(VlessXhttpPlugin.meta.config_defaults)[ROUTE_CONFIG_KEY])

    def install(self) -> bool:
        from hydra.core import singbox

        return singbox.install()

    def uninstall(self) -> bool:
        return True

    def configure(self, state: PluginStateAccess) -> ConfigFragment:
        protocol = state.protocols.get("vless")
        if protocol is None:
            return ConfigFragment()
        raw_domain = str(protocol.config.get("domain", "")).strip()
        if not raw_domain:
            return ConfigFragment()
        domain = _normalize_domain(raw_domain)
        cert, key = resolve_tls_material(domain, protocol.config)
        users = [
            {"name": user.email, "uuid": user.uuid}
            for user in state.users
            if not user.blocked
        ]
        if not cert or not key or not users:
            return ConfigFragment()

        inbound = {
            "type": "vless",
            "tag": "vless-xhttp-in",
            "listen": "127.0.0.1",
            "listen_port": INTERNAL_PORT,
            "users": users,
            "tls": {
                "enabled": True,
                "server_name": domain,
                "alpn": ["h2"],
                "certificate_path": cert,
                "key_path": key,
            },
            "transport": self._transport(protocol.config, client=False),
        }
        return ConfigFragment(inbounds=[inbound])

    @staticmethod
    def _transport(
        config: dict,
        *,
        client: bool,
        domain: str = "",
    ) -> dict[str, object]:
        transport: dict[str, object] = {
            "type": "xhttp",
            "mode": _validate_mode(
                config.get("xhttp_mode", DEFAULT_MODE),
            ),
            "host": domain if client else "",
            "path": _validate_path(
                config.get("xhttp_path", DEFAULT_PATH),
            ),
            "headers": {},
            "x_padding_bytes": "100-1000",
            "no_sse_header": False,
            "sc_max_each_post_bytes": 1_000_000,
            "sc_max_buffered_posts": 30,
            "sc_stream_up_server_secs": "20-80",
            "server_max_header_bytes": 8192,
        }
        if not client:
            transport["trusted_x_forwarded_for"] = []
        return transport

    def generate_client_config(
        self,
        user: User,
        state: PluginStateAccess,
    ) -> str:
        protocol = state.protocols.get("vless")
        if protocol is None:
            return ""
        raw_domain = str(protocol.config.get("domain", "")).strip()
        if not raw_domain:
            return ""
        domain = _normalize_domain(raw_domain)
        outbound = {
            "type": "vless",
            "tag": f"vless-xhttp-{user.email}",
            "server": domain,
            "server_port": 443,
            "uuid": user.uuid,
            "tls": {
                "enabled": True,
                "server_name": domain,
                "alpn": ["h2"],
            },
            "transport": self._transport(
                protocol.config,
                client=True,
                domain=domain,
            ),
        }
        return json.dumps(
            {
                "log": {"level": "info"},
                "outbounds": [
                    outbound,
                    {"type": "direct", "tag": "direct"},
                ],
                "route": {"final": outbound["tag"]},
            },
            indent=2,
        )

    def client_link(self, user: User, state: PluginStateAccess) -> str:
        protocol = state.protocols.get("vless")
        if protocol is None:
            return ""
        raw_domain = str(protocol.config.get("domain", "")).strip()
        if not raw_domain:
            return ""
        domain = _normalize_domain(raw_domain)
        query = urllib.parse.urlencode(
            {
                "encryption": "none",
                "security": "tls",
                "sni": domain,
                "alpn": "h2",
                "type": "xhttp",
                "host": domain,
                "path": _validate_path(
                    protocol.config.get("xhttp_path", DEFAULT_PATH),
                ),
                "mode": _validate_mode(
                    protocol.config.get("xhttp_mode", DEFAULT_MODE),
                ),
            },
        )
        uuid = urllib.parse.quote(user.uuid, safe="")
        tag = urllib.parse.quote(f"{user.email} VLESS XHTTP", safe="")
        return f"vless://{uuid}@{domain}:443?{query}#{tag}"

    def on_enable(self, state: PluginStateAccess) -> None:
        protocol = state.protocols.get("vless")
        if protocol is None:
            raise ValueError("VLESS XHTTP configuration is missing")
        domain = _normalize_domain(protocol.config.get("domain"))
        cert, key = resolve_tls_material(domain, protocol.config)
        if not cert or not key:
            raise ValueError(
                f"TLS material for {domain} must be prepared "
                "by the application service",
            )
        _validate_path(protocol.config.get("xhttp_path", DEFAULT_PATH))
        _validate_mode(protocol.config.get("xhttp_mode", DEFAULT_MODE))

        from hydra.utils.firewall import open_tcp

        open_tcp(80, "vless-xhttp-http")
        open_tcp(443, "vless-xhttp")

    def on_disable(self, state: PluginStateAccess) -> None:
        from hydra.utils.firewall import close_tcp

        close_tcp(80, "vless-xhttp-http")
        close_tcp(443, "vless-xhttp")

    def status(
        self,
        state: PluginStateAccess | None = None,
    ) -> PluginStatus:
        from hydra.core import singbox, sni_router

        installed = singbox.is_installed()
        protocol = (
            state.protocols.get("vless")
            if state is not None
            else None
        )
        enabled = bool(protocol and protocol.enabled)
        running = (
            installed
            and enabled
            and singbox.is_running()
            and sni_router.is_active()
        )
        info = {}
        if protocol:
            info = {
                "Domain": protocol.config.get("domain", ""),
                "XHTTP path": protocol.config.get(
                    "xhttp_path",
                    DEFAULT_PATH,
                ),
                "XHTTP mode": protocol.config.get(
                    "xhttp_mode",
                    DEFAULT_MODE,
                ),
            }
        return PluginStatus(installed, enabled, running, 443, info)

    def healthcheck_for_state(
        self,
        state: PluginStateAccess,
    ) -> HealthResult:
        from hydra.core import singbox, sni_router

        service_active = singbox.is_running()
        inbound_configured = singbox.has_configured_inbound(
            "vless-xhttp-in",
        )
        caddy_active = sni_router.is_active()
        healthy = service_active and inbound_configured and caddy_active
        detail = ""
        if not service_active:
            detail = "sing-box service is not active"
        elif not inbound_configured:
            detail = "VLESS XHTTP inbound is missing from Sing-Box config"
        elif not caddy_active:
            detail = "Caddy L4 service is not active"
        return HealthResult(
            healthy,
            detail,
            "ok" if healthy else "error",
            {
                "sing_box": service_active,
                "vless_xhttp_inbound": inbound_configured,
                "caddy_l4": caddy_active,
            },
        )

    def set_domain(
        self,
        state: PluginStateAccess,
        domain: str,
    ) -> bool:
        protocol = state.protocols.get("vless")
        if protocol is None:
            return False
        normalized = _normalize_domain(domain)
        if normalized != protocol.config.get("domain"):
            protocol.config["domain"] = normalized
            protocol.config.pop("cert_file", None)
            protocol.config.pop("key_file", None)
        return True

    def set_path(
        self,
        state: PluginStateAccess,
        path: str,
    ) -> bool:
        normalized = _validate_path(path)
        protocol = state.protocols.get("vless")
        if protocol is None:
            return False
        protocol.config["xhttp_path"] = normalized
        return True

    def set_mode(
        self,
        state: PluginStateAccess,
        mode: str,
    ) -> bool:
        normalized = _validate_mode(mode)
        protocol = state.protocols.get("vless")
        if protocol is None:
            return False
        protocol.config["xhttp_mode"] = normalized
        return True


__all__ = [
    "DEFAULT_MODE",
    "DEFAULT_PATH",
    "DECOY_DIR",
    "DECOY_HTTP_PORT",
    "INTERNAL_PORT",
    "ROUTE_CONFIG_KEY",
    "VlessXhttpPlugin",
]
