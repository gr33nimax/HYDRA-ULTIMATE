"""VLESS over XHTTP for the shtorm-7 sing-box-extended core."""
from __future__ import annotations

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
from hydra.plugins.decoy_support import DecoyThemeSupport
from hydra.plugins.vless_xhttp.client import (
    PUBLIC_PORT,
    profile as client_profile,
    share_link as client_share_link,
)
from hydra.plugins.vless_xhttp.health import INBOUND_TAG, check as health_check
from hydra.plugins.vless_xhttp.security import (
    DECOY_ROUTE_KEY,
    DEFAULT_HANDSHAKE,
    HANDSHAKE_CONFIG_KEY,
    MODE_TLS,
    apply_reality_mode,
    apply_tls_mode,
    handshake_target,
    is_reality,
    normalize_domain,
    security_mode,
    server_tls,
    validate_handshake,
    validate_security,
    validate_short_id,
)
from hydra.plugins.vless_xhttp.presets import (
    apply_preset,
    current_preset,
    get_preset,
)
from hydra.plugins.vless_xhttp.tuning import (
    DEFAULT_MODE,
    DEFAULT_PATH,
    FIELDS,
    TUNING_DEFAULTS,
    XHTTP_MODES,
    apply_settings,
    effective as effective_tuning,
    summary as tuning_summary,
    transport as build_transport,
    validate_mode as _validate_mode,
    validate_path as _validate_path,
)
from hydra.utils.tls import resolve_tls_material


INTERNAL_PORT = 20448
DECOY_HTTP_PORT = 10804
DECOY_DIR = "/var/www/decoy-vless"
ROUTE_CONFIG_KEY = DECOY_ROUTE_KEY

_normalize_domain = normalize_domain


class VlessXhttpPlugin(DecoyThemeSupport, BasePlugin):
    """Multi-user VLESS/XHTTP endpoint in certificate or Reality mode."""

    decoy_default_theme = "media"

    meta = PluginMeta(
        name="vless",
        display_name="VLESS + XHTTP",
        description=(
            "VLESS over XHTTP from sing-box-extended, served either behind a "
            "certificate on your own domain or with a borrowed Reality "
            "handshake"
        ),
        category=PluginCategory.TRANSPORT,
        version="1.1.0",
        needs_domain=True,
        required_commands=("sing-box",),
        commands=(
            "set_domain",
            "set_path",
            "set_mode",
            "set_tuning",
            "set_preset",
            "set_decoy_theme",
            "set_security",
        ),
        queries=("get_tuning",),
        tls_domain_source="protocol",
        config_defaults=(
            ("security", MODE_TLS),
            ("xhttp_mode", DEFAULT_MODE),
            ("xhttp_path", DEFAULT_PATH),
            ("decoy_theme", "media"),
            *TUNING_DEFAULTS,
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

    def needs_tls_domain(self, state: PluginStateAccess) -> bool:
        """Reality borrows a handshake, so it owns neither domain nor cert."""
        protocol = state.protocols.get("vless")
        return not is_reality(protocol.config if protocol else {})

    def configure(self, state: PluginStateAccess) -> ConfigFragment:
        protocol = state.protocols.get("vless")
        if protocol is None:
            return ConfigFragment()
        users = [
            {"name": user.email, "uuid": user.uuid}
            for user in state.users
            if not user.blocked
        ]
        if not users:
            return ConfigFragment()
        if is_reality(protocol.config):
            inbound = self._reality_inbound(state, protocol.config, users)
        else:
            inbound = self._certificate_inbound(protocol.config, users)
        return ConfigFragment(inbounds=[inbound]) if inbound else ConfigFragment()

    def _certificate_inbound(
        self,
        config: dict,
        users: list[dict],
    ) -> dict[str, object] | None:
        raw_domain = str(config.get("domain", "")).strip()
        if not raw_domain:
            return None
        domain = _normalize_domain(raw_domain)
        cert, key = resolve_tls_material(domain, config)
        if not cert or not key:
            return None
        return {
            "type": "vless",
            "tag": INBOUND_TAG,
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
            "transport": self._transport(config, client=False),
        }

    def _reality_inbound(
        self,
        state: PluginStateAccess,
        config: dict,
        users: list[dict],
    ) -> dict[str, object] | None:
        from hydra.core.sni_router import needs_mux

        try:
            tls = server_tls(config)
        except ValueError:
            return None
        behind_mux = needs_mux(state)
        return {
            "type": "vless",
            "tag": INBOUND_TAG,
            "listen": "127.0.0.1" if behind_mux else "::",
            "listen_port": INTERNAL_PORT if behind_mux else PUBLIC_PORT,
            "users": users,
            "tls": tls,
            "transport": self._transport(config, client=False),
        }

    @staticmethod
    def _transport(
        config: dict,
        *,
        client: bool,
        domain: str = "",
    ) -> dict[str, object]:
        return build_transport(config, client=client, domain=domain)

    def _endpoint(
        self,
        state: PluginStateAccess,
        config: dict,
    ) -> tuple[str, str]:
        """Return the (server, host) pair a client should dial."""
        if is_reality(config):
            server = str(getattr(state.network, "server_ip", "") or "").strip()
            if not server:
                return "", ""
            return server, handshake_target(config)
        raw_domain = str(config.get("domain", "")).strip()
        if not raw_domain:
            return "", ""
        domain = _normalize_domain(raw_domain)
        return domain, domain

    def generate_client_config(
        self,
        user: User,
        state: PluginStateAccess,
    ) -> str:
        protocol = state.protocols.get("vless")
        if protocol is None:
            return ""
        server, host = self._endpoint(state, protocol.config)
        if not server:
            return ""
        return client_profile(
            user,
            protocol.config,
            server=server,
            host=host,
        )

    def client_link(self, user: User, state: PluginStateAccess) -> str:
        protocol = state.protocols.get("vless")
        if protocol is None:
            return ""
        server, host = self._endpoint(state, protocol.config)
        if not server:
            return ""
        return client_share_link(
            user,
            protocol.config,
            server=server,
            host=host,
        )

    def on_enable(self, state: PluginStateAccess) -> None:
        protocol = state.protocols.get("vless")
        if protocol is None:
            raise ValueError("VLESS XHTTP configuration is missing")
        config = protocol.config
        _validate_path(config.get("xhttp_path", DEFAULT_PATH))
        _validate_mode(config.get("xhttp_mode", DEFAULT_MODE))
        effective_tuning(config)

        from hydra.utils.firewall import open_tcp

        if is_reality(config):
            server_tls(config)
            if not str(getattr(state.network, "server_ip", "") or "").strip():
                raise ValueError(
                    "Публичный IP сервера неизвестен: клиентам Reality "
                    "некуда подключаться",
                )
            open_tcp(443, "vless-xhttp")
            return

        domain = _normalize_domain(config.get("domain"))
        cert, key = resolve_tls_material(domain, config)
        if not cert or not key:
            raise ValueError(
                f"TLS material for {domain} must be prepared "
                "by the application service",
            )
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
        reality = bool(protocol and is_reality(protocol.config))
        running = (
            installed
            and enabled
            and singbox.is_running()
            and (reality or sni_router.is_active())
        )
        info = {}
        if protocol:
            try:
                preset = current_preset(protocol.config)
                summary = tuning_summary(protocol.config)
            except ValueError as exc:
                preset, summary = "invalid", str(exc)
            info = {
                "Security": security_mode(protocol.config),
                "Domain": (
                    handshake_target(protocol.config)
                    if reality
                    else protocol.config.get("domain", "")
                ),
                "XHTTP path": protocol.config.get("xhttp_path", DEFAULT_PATH),
                "XHTTP mode": protocol.config.get("xhttp_mode", DEFAULT_MODE),
                "XHTTP preset": preset,
                "XHTTP tuning": summary,
            }
        return PluginStatus(installed, enabled, running, 443, info)

    def healthcheck_for_state(
        self,
        state: PluginStateAccess,
    ) -> HealthResult:
        return health_check(state)

    def set_domain(
        self,
        state: PluginStateAccess,
        domain: str,
    ) -> bool:
        protocol = state.protocols.get("vless")
        if protocol is None:
            return False
        if is_reality(protocol.config):
            raise ValueError(
                "В режиме Reality домен не используется; сначала переключите "
                "security на tls",
            )
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

    def set_tuning(
        self,
        state: PluginStateAccess,
        **parameters: object,
    ) -> bool:
        """Update one or more XHTTP transport knobs atomically."""
        protocol = state.protocols.get("vless")
        if protocol is None:
            return False
        apply_settings(protocol.config, parameters)
        return True

    def set_preset(
        self,
        state: PluginStateAccess,
        preset: str,
    ) -> bool:
        """Replace mode and tuning with one declared XHTTP profile."""
        name = get_preset(preset).name
        protocol = state.protocols.get("vless")
        if protocol is None:
            return False
        apply_preset(protocol.config, name)
        return True

    def set_security(
        self,
        state: PluginStateAccess,
        mode: str,
        handshake: str = "",
        short_id: str = "",
    ) -> bool:
        """Switch between a certificate on your domain and a Reality handshake."""
        normalized = validate_security(mode)
        protocol = state.protocols.get("vless")
        if protocol is None:
            return False
        if normalized == MODE_TLS:
            apply_tls_mode(
                protocol.config,
                decoy_route=self.route_config(),
            )
            return True

        import secrets

        from hydra.core.singbox_keys import generate_reality_keypair

        config = protocol.config
        target = validate_handshake(
            handshake or config.get(HANDSHAKE_CONFIG_KEY)
            or DEFAULT_HANDSHAKE,
        )
        private_key = str(config.get("reality_private_key", "")).strip()
        public_key = str(config.get("reality_public_key", "")).strip()
        if not private_key or not public_key:
            private_key, public_key = generate_reality_keypair()
        identifier = validate_short_id(
            short_id
            or config.get("reality_short_id")
            or secrets.token_hex(4),
        )
        apply_reality_mode(
            config,
            handshake=target,
            private_key=private_key,
            public_key=public_key,
            short_id=identifier,
            internal_port=INTERNAL_PORT,
        )
        return True

    def get_tuning(self, state: PluginStateAccess) -> dict[str, object]:
        """Return the effective XHTTP transport settings for operators."""
        protocol = state.protocols.get("vless")
        config = protocol.config if protocol is not None else {}
        values = effective_tuning(config)
        return {
            "security": security_mode(config),
            "preset": current_preset(config),
            "mode": _validate_mode(config.get("xhttp_mode", DEFAULT_MODE)),
            "path": _validate_path(config.get("xhttp_path", DEFAULT_PATH)),
            **{
                field.param: values[field.key]
                for field in FIELDS
            },
        }


__all__ = [
    "DEFAULT_MODE",
    "DEFAULT_PATH",
    "DECOY_DIR",
    "DECOY_HTTP_PORT",
    "INTERNAL_PORT",
    "ROUTE_CONFIG_KEY",
    "XHTTP_MODES",
    "VlessXhttpPlugin",
]
