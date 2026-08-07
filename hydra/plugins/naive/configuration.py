"""Desired NaiveProxy configuration and deterministic Caddyfile rendering."""
from __future__ import annotations

import copy
from pathlib import Path

from hydra.plugins.base import ConfigFragment
from hydra.plugins.context import PluginStateAccess


def render_caddyfile(
    *,
    domain: str,
    port: int,
    users: list[dict],
    decoy_dir: Path,
    log_dir: Path,
    cert_file: str = "",
    key_file: str = "",
    accept_proxy_protocol: bool = False,
) -> str:
    """Render a complete Caddyfile without reading or mutating the host."""
    auth_lines = "".join(
        "            basic_auth "
        f"{user['username']} {user['password']}\n"
        for user in users
    )
    tls_line = (
        f"    tls {cert_file} {key_file}\n"
        if cert_file and key_file
        else ""
    )
    probe_line = "            probe_resistance\n" if auth_lines else ""
    listener_wrappers = ""
    if accept_proxy_protocol:
        listener_wrappers = """\
    servers {
        listener_wrappers {
            proxy_protocol {
                timeout 1s
                allow 127.0.0.0/8 ::1/128
                fallback_policy require
            }
            tls
        }
    }
"""

    return f"""\
{{
    http_port 0
    auto_https disable_redirects
{listener_wrappers}    order forward_proxy before file_server
}}

:{port}, {domain}:{port} {{
{tls_line}    forward_proxy {{
{auth_lines}            hide_ip
            hide_via
{probe_line}            upstream socks5://127.0.0.1:1080
    }}
    file_server {{
        root {decoy_dir.as_posix()}
    }}
    log {{
        output file {log_dir}/access.log {{
            roll_size 10mb
            roll_keep 3
        }}
    }}
}}
"""


class NaiveConfigurationMixin:
    """Plugin methods that validate and render desired configuration."""

    _pending_cfg: str | None

    def configure(self, state: PluginStateAccess) -> ConfigFragment:
        from hydra.core.sni_router import (
            get_effective_port,
            get_internal_port,
        )

        domain = state.network.domain
        if not domain:
            self._pending_cfg = None
            return ConfigFragment()

        users = [
            {
                "username": self._derive_username(user),
                "password": self._derive_password(user.uuid),
            }
            for user in state.users
            if not user.blocked
        ]
        protocol = state.protocols.get("naive")
        config = protocol.config if protocol and protocol.config else {}
        cert_file, key_file = self._resolve_certs(domain, protocol)
        if not cert_file or not key_file:
            self._pending_cfg = None
            return ConfigFragment()

        port = get_effective_port("naive", state)
        self._pending_cfg = self._build_caddyfile(
            domain=domain,
            port=port,
            users=users,
            fake_site_dir=str(self._runtime_layout().fake_site_dir),
            cert_file=cert_file,
            key_file=key_file,
            decoy_url=str(config.get("decoy_url", "")),
            accept_proxy_protocol=port == get_internal_port("naive"),
        )
        return ConfigFragment()

    def set_transport(
        self,
        state: PluginStateAccess,
        network: str,
    ) -> bool:
        """Validate and update the desired TCP/QUIC transport."""
        if network not in ("tcp", "quic", "both"):
            return False

        protocol = state.protocols.get("naive")
        if protocol is None:
            return False
        if network == protocol.config.get("network", "tcp"):
            return True

        if network in ("quic", "both"):
            from hydra.core.sni_router import get_quic_owner

            try:
                prospective_state = copy.deepcopy(state)
                prospective_state.protocols["naive"].config[
                    "network"
                ] = network
                get_quic_owner(prospective_state)
            except ValueError:
                return False
        protocol.config["network"] = network
        return True

    def set_domain(
        self,
        state: PluginStateAccess,
        domain: str,
    ) -> bool:
        """Validate and update the shared NaiveProxy TLS domain."""
        normalized = str(domain or "").strip().lower().rstrip(".")
        if (
            not normalized
            or "://" in normalized
            or any(character.isspace() for character in normalized)
        ):
            raise ValueError(
                "Некорректный домен NaiveProxy: укажите имя без схемы "
                "и пробелов",
            )
        state.network.domain = normalized
        return True

    def on_enable(self, state: PluginStateAccess) -> None:
        protocol = state.protocols.get("naive")
        if protocol is None:
            raise ValueError("NaiveProxy configuration is missing")

        domain = str(state.network.domain or "").strip()
        if not domain:
            raise ValueError(
                "Домен NaiveProxy не настроен; задайте network.domain "
                "перед включением",
            )
        cert_file, key_file = self._resolve_certs(domain, protocol)
        if not cert_file or not key_file:
            raise ValueError(
                f"TLS-сертификат для домена {domain} не подготовлен",
            )

        network = protocol.config.get("network", "tcp")
        if network in ("quic", "both"):
            from hydra.core.sni_router import get_quic_owner

            get_quic_owner(state, prospective="naive")

    def _resolve_certs(self, domain: str, protocol) -> tuple[str, str]:
        config = (
            protocol.config
            if protocol is not None and protocol.config
            else {}
        )
        return self._resolve_tls_material(domain, config)

    def _build_caddyfile(
        self,
        domain: str,
        port: int,
        users: list[dict],
        probe_secret: str = "",
        fake_site_dir: str = "/var/www/naive-fake",
        cert_file: str = "",
        key_file: str = "",
        decoy_url: str = "",
        accept_proxy_protocol: bool = False,
    ) -> str:
        del probe_secret, decoy_url
        from hydra.core.decoy import DECOY_DIRS

        layout = self._runtime_layout()
        return render_caddyfile(
            domain=domain,
            port=port,
            users=users,
            decoy_dir=DECOY_DIRS.get("naive", Path(fake_site_dir)),
            log_dir=layout.log_dir,
            cert_file=cert_file,
            key_file=key_file,
            accept_proxy_protocol=accept_proxy_protocol,
        )
