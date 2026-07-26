"""Stable ShadowTLS v3 + Trojan plugin facade."""
from __future__ import annotations

import ipaddress
import json
import shutil
import socket
import ssl
import subprocess  # noqa: F401  # Historical module monkeypatch seam.
import time
import urllib.parse
from pathlib import Path  # noqa: F401  # Historical module monkeypatch seam.

from hydra.core.host import HOST
from hydra.core.state_models import User
from hydra.plugins.base import (
    BasePlugin,
    ConfigFragment,
    PluginCategory,
    PluginMeta,
    PluginStatus,
)
from hydra.plugins.context import PluginStateAccess
from hydra.utils.crypto import derive_hex_key
from hydra.utils.net import public_ip

from . import configuration, observation, policy, profiles, runtime
from .constants import SHADOWTLS_SNI_PRESETS  # noqa: F401  # Re-export.


class ShadowTLSPlugin(BasePlugin):
    meta = PluginMeta(
        name="shadowtls",
        description=(
            "ShadowTLS v3 + Trojan: TLS-camouflaged tunnel "
            "(sing-box inbound)"
        ),
        category=PluginCategory.TRANSPORT,
        version="1.0.0",
        needs_domain=False,
        commands=("set_handshake_sni",),
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
            validate_sni=self._validate_handshake_sni,
            derive_username=self._derive_username,
            derive_stls_password=self._derive_stls_password,
            derive_trojan_password=self._derive_trojan_password,
        )

    def apply(self, state: PluginStateAccess) -> bool:
        return True

    def on_user_add(
        self,
        user: User,
        state: PluginStateAccess,
    ) -> None:
        user.credentials.setdefault("shadowtls", {})
        credentials = user.credentials["shadowtls"]
        credentials["username"] = self._derive_username(user)
        credentials["stls_password"] = (
            self._derive_stls_password(user.uuid)
        )
        credentials["trojan_password"] = (
            self._derive_trojan_password(user.uuid)
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
            derive_stls_password=self._derive_stls_password,
            derive_trojan_password=self._derive_trojan_password,
            server_ip=self._server_ip,
            json_dumps=json.dumps,
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
            derive_stls_password=self._derive_stls_password,
            derive_trojan_password=self._derive_trojan_password,
            server_ip=self._server_ip,
            url_host=self._url_host,
            quote=urllib.parse.quote,
        )

    def on_enable(self, state: PluginStateAccess) -> None:
        runtime.on_enable(
            state,
            validate_sni=self._validate_handshake_sni,
            remove_iptables_rules=self._remove_iptables_rules,
            add_iptables_rules=self._add_iptables_rules,
        )

    def set_handshake_sni(
        self,
        state: PluginStateAccess,
        value: str,
    ) -> bool:
        return policy.set_handshake_sni(
            state,
            value,
            validate=self._validate_handshake_sni,
            probe=self._probe_handshake_sni,
        )

    def on_disable(self, state: PluginStateAccess) -> None:
        self._remove_iptables_rules()

    def status(
        self,
        state: PluginStateAccess | None = None,
    ) -> PluginStatus:
        return observation.status(
            state,
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
            host=HOST,
            now=time.time,
        )

    @staticmethod
    def _derive_username(user: User) -> str:
        return user.email

    @staticmethod
    def _derive_stls_password(uuid: str) -> str:
        return derive_hex_key("shadowtls-pass", uuid)

    @staticmethod
    def _derive_trojan_password(uuid: str) -> str:
        return derive_hex_key("shadowtls-pass", uuid)

    @staticmethod
    def _normalized_host(value: str) -> str:
        return policy.normalized_host(value)

    def _validate_handshake_sni(
        self,
        value: str,
        state: PluginStateAccess,
    ) -> str:
        return policy.validate_handshake_sni(
            value,
            state,
            normalize=self._normalized_host,
        )

    @staticmethod
    def _probe_handshake_sni(
        handshake_sni: str,
        timeout: float = 6.0,
    ) -> None:
        policy.probe_handshake_sni(
            handshake_sni,
            timeout,
            socket_module=socket,
            ssl_module=ssl,
        )

    @staticmethod
    def _server_ip(state: PluginStateAccess) -> str:
        return policy.server_ip(
            state,
            public_ip_provider=public_ip,
            parse_ip=ipaddress.ip_address,
        )

    @staticmethod
    def _url_host(value: str) -> str:
        return policy.url_host(
            value,
            parse_ip=ipaddress.ip_address,
        )

    def _remove_iptables_rules(self) -> None:
        runtime.remove_iptables_rules(HOST)

    def _add_iptables_rules(self) -> None:
        runtime.add_iptables_rules(HOST)

    def _get_total_traffic(self) -> int:
        return runtime.total_traffic(HOST)
