"""Stable TrustTunnel plugin facade."""
from __future__ import annotations

import json
import shutil
import time
import urllib.parse

from hydra.core.host import HOST
from hydra.core.state_models import User
from hydra.plugins.base import (
    BasePlugin,
    ConfigFragment,
    PluginCategory,
    PluginMeta,
    PluginStatus,
)
from hydra.plugins.decoy_support import DecoyThemeSupport
from hydra.plugins.context import PluginStateAccess
from hydra.utils.crypto import derive_hex_key
from hydra.utils.tls import resolve_tls_material

from . import configuration, observation, policy, profiles, runtime
from .constants import DEFAULT_TRANSPORT, VALID_TRANSPORTS


# Historical module-level seams kept for callers and focused monkeypatches.
_VALID_TRANSPORTS = VALID_TRANSPORTS
_DEFAULT_TRANSPORT = DEFAULT_TRANSPORT


class TrustTunnelPlugin(DecoyThemeSupport, BasePlugin):

    decoy_default_theme = "docs"
    meta = PluginMeta(
        name="trusttunnel",
        description=(
            "TrustTunnel: HTTP/2 and QUIC obfuscated tunnel "
            "(sing-box inbound)"
        ),
        category=PluginCategory.TRANSPORT,
        version="2.1.0",
        needs_domain=True,
        commands=("set_transport", "set_decoy_theme"),
        tls_domain_source="protocol",
        config_defaults=(
            ("transport", "tcp"),
            ("decoy_theme", "docs"),
        ),
        connection_source="tracked",
    )

    def install(self) -> bool:
        from hydra.core.singbox import is_installed

        return is_installed()

    def uninstall(self) -> bool:
        return True

    def configure(self, state: PluginStateAccess) -> ConfigFragment:
        return configuration.configure(
            state,
            derive_username=self._derive_username,
            derive_password=self._derive_password,
            resolve_certs=self._resolve_certs,
            transport_of=self._transport,
            build_tcp_inbound=self._build_tcp_inbound,
            build_quic_inbound=self._build_quic_inbound,
        )

    @staticmethod
    def _build_tcp_inbound(
        domain: str,
        cert_file: str,
        key_file: str,
        users: list[dict],
        listen_port: int,
        behind_mux: bool,
    ) -> dict:
        return configuration.build_tcp_inbound(
            domain,
            cert_file,
            key_file,
            users,
            listen_port,
            behind_mux,
        )

    @staticmethod
    def _build_quic_inbound(
        domain: str,
        cert_file: str,
        key_file: str,
        users: list[dict],
        listen_port: int,
        behind_mux: bool,
    ) -> dict:
        return configuration.build_quic_inbound(
            domain,
            cert_file,
            key_file,
            users,
            listen_port,
            behind_mux,
        )

    def apply(self, state: PluginStateAccess) -> bool:
        return True

    def on_user_add(
        self,
        user: User,
        state: PluginStateAccess,
    ) -> None:
        user.credentials.setdefault("trusttunnel", {})
        user.credentials["trusttunnel"]["username"] = (
            self._derive_username(user)
        )
        user.credentials["trusttunnel"]["password"] = (
            self._derive_password(user.uuid)
        )

    def on_user_remove(
        self,
        user: User,
        state: PluginStateAccess,
    ) -> None:
        pass

    def on_user_block(
        self,
        user: User,
        state: PluginStateAccess,
    ) -> None:
        pass

    def generate_client_config(
        self,
        user: User,
        state: PluginStateAccess,
    ) -> str:
        return profiles.generate_client_config(
            user,
            state,
            derive_username=self._derive_username,
            derive_password=self._derive_password,
            transport_of=self._transport,
            build_outbound=self._build_client_outbound,
            json_dumps=json.dumps,
        )

    @staticmethod
    def _build_client_outbound(
        server: str,
        domain: str,
        username: str,
        password: str,
        quic: bool,
    ) -> dict:
        return profiles.build_client_outbound(
            server,
            domain,
            username,
            password,
            quic,
        )

    def client_link(
        self,
        user: User,
        state: PluginStateAccess,
    ) -> str:
        return profiles.client_link(
            user,
            state,
            derive_username=self._derive_username,
            derive_password=self._derive_password,
            transport_of=self._transport,
            quote=urllib.parse.quote,
        )

    def client_links(
        self,
        user: User,
        state: PluginStateAccess,
    ) -> list[str]:
        return profiles.client_links(
            user,
            state,
            derive_username=self._derive_username,
            derive_password=self._derive_password,
            transport_of=self._transport,
            quote=urllib.parse.quote,
        )

    def on_enable(self, state: PluginStateAccess) -> None:
        runtime.on_enable(
            state,
            transport_of=self._transport,
            validate=self.validate_config,
            resolve_certs=self._resolve_certs,
            remove_iptables_rules=self._remove_iptables_rules,
        )

    def on_disable(self, state: PluginStateAccess) -> None:
        self._remove_iptables_rules()

    def status(
        self,
        state: PluginStateAccess | None = None,
    ) -> PluginStatus:
        return observation.status(
            state,
            health=self.health,
            get_total_traffic=self._get_total_traffic,
        )

    def traffic(self, state: PluginStateAccess) -> dict[str, int]:
        return observation.traffic(state)

    def connected_clients(
        self,
        state: PluginStateAccess | None = None,
    ) -> list[dict]:
        return observation.connected_clients(
            state,
            which=shutil.which,
            transport_of=self._transport,
            collect=self._collect_ss_clients,
            now=time.time,
        )

    @staticmethod
    def _transport(ps) -> str:
        return policy.transport(ps)

    def validate_config(
        self,
        state: PluginStateAccess,
        require_cert: bool = True,
        prospective_enable: bool = False,
    ) -> list[str]:
        return policy.validate_config(
            state,
            require_cert=require_cert,
            prospective_enable=prospective_enable,
            resolve_certs=self._resolve_certs,
            transport_of=self._transport,
        )

    def health(
        self,
        state: PluginStateAccess,
    ) -> dict[str, object]:
        return observation.health(
            state,
            validate=self.validate_config,
            transport_of=self._transport,
            host=HOST,
        )

    def set_transport(
        self,
        state: PluginStateAccess,
        transport: str,
    ) -> bool:
        return policy.set_transport(
            state,
            transport,
            validate=self.validate_config,
        )

    @staticmethod
    def _split_endpoint(endpoint: str) -> tuple[str, int | None]:
        return observation.split_endpoint(endpoint)

    def _collect_ss_clients(
        self,
        cmd: list[str],
        port: int,
        kind: str,
        counts: dict[tuple[str, str], int],
    ) -> None:
        observation.collect_ss_clients(
            cmd,
            port,
            kind,
            counts,
            host=HOST,
            split=self._split_endpoint,
        )

    @staticmethod
    def _derive_username(user: User) -> str:
        return user.email

    @staticmethod
    def _derive_password(uuid: str) -> str:
        return derive_hex_key("trusttunnel-pass", uuid)

    def _resolve_certs(
        self,
        domain: str,
        ps,
    ) -> tuple[str, str]:
        config = (
            ps.config
            if ps and ps.config
            else {}
        )
        return resolve_tls_material(domain, config)

    def _remove_iptables_rules(self) -> None:
        runtime.remove_iptables_rules(HOST)

    @staticmethod
    def _get_total_traffic(state: PluginStateAccess) -> int:
        return observation.total_traffic(state)
