"""NaiveProxy credentials and client-profile serialization."""
from __future__ import annotations

import json
import urllib.parse

from hydra.core.state_models import User
from hydra.plugins.context import PluginStateAccess
from hydra.utils.crypto import derive_hex_key


def derive_username(user: User) -> str:
    """Derive the stable Caddy username used by server and client profiles."""
    local_part = user.email.split("@")[0]
    sanitized = "".join(
        character
        for character in local_part
        if character.isalnum() or character in ("_", "-")
    )
    return sanitized or user.email


def derive_password(uuid: str) -> str:
    """Derive a stable, protocol-scoped password without persisting a secret."""
    return derive_hex_key("naive-pass", uuid)[:24]


def transport_mode(state: PluginStateAccess) -> str:
    protocol = state.protocols.get("naive")
    if protocol is None or not protocol.config:
        return "tcp"
    return str(protocol.config.get("network", "tcp"))


def _outbound(
    *,
    domain: str,
    port: int,
    username: str,
    password: str,
    quic: bool,
) -> dict:
    transport = "quic" if quic else "tcp"
    return {
        "type": "naive",
        "tag": f"naive-{transport}-{username}",
        "server": domain,
        "server_port": port,
        "username": username,
        "password": password,
        "quic": quic,
        "tls": {
            "enabled": True,
            "server_name": domain,
        },
    }


def serialize_client_config(
    *,
    domain: str,
    port: int,
    username: str,
    password: str,
    network: str,
) -> str:
    """Serialize the standalone sing-box client profile."""
    outbounds: list[dict] = []
    if network in ("tcp", "both"):
        outbounds.append(
            _outbound(
                domain=domain,
                port=port,
                username=username,
                password=password,
                quic=False,
            ),
        )
    if network in ("quic", "both"):
        outbounds.append(
            _outbound(
                domain=domain,
                port=port,
                username=username,
                password=password,
                quic=True,
            ),
        )

    document = {
        "log": {"level": "info"},
        "dns": {
            "servers": [
                {"tag": "google", "address": "8.8.8.8"},
                {
                    "tag": "local",
                    "address": "1.1.1.1",
                    "detour": "direct",
                },
            ],
        },
        "outbounds": outbounds + [{"type": "direct", "tag": "direct"}],
        "route": {"final": outbounds[0]["tag"] if outbounds else "direct"},
    }
    return json.dumps(document, indent=2)


def serialize_client_link(
    *,
    domain: str,
    port: int,
    username: str,
    password: str,
    quic: bool,
) -> str:
    """Serialize one URI while escaping every user-controlled component."""
    user_q = urllib.parse.quote(username, safe="")
    password_q = urllib.parse.quote(password, safe="")
    sni_q = urllib.parse.quote(domain, safe="")
    suffix = " QUIC" if quic else ""
    tag_q = urllib.parse.quote(
        f"{username} NaiveProxy{suffix}",
        safe="",
    )
    scheme = "naive+quic" if quic else "naive+https"
    return (
        f"{scheme}://{user_q}:{password_q}@{domain}:{port}"
        f"?security=tls&sni={sni_q}#{tag_q}"
    )


class NaiveProfilesMixin:
    """Plugin contract methods concerned only with users and client output."""

    def on_user_add(
        self,
        user: User,
        state: PluginStateAccess,
    ) -> None:
        del state
        credentials = user.credentials.setdefault("naive", {})
        credentials["username"] = self._derive_username(user)
        credentials["password"] = self._derive_password(user.uuid)

    def on_user_remove(
        self,
        user: User,
        state: PluginStateAccess,
    ) -> None:
        del user, state

    def on_user_block(
        self,
        user: User,
        state: PluginStateAccess,
    ) -> None:
        del user, state

    @staticmethod
    def _derive_username(user: User) -> str:
        return derive_username(user)

    @staticmethod
    def _derive_password(uuid: str) -> str:
        return derive_password(uuid)

    def generate_client_config(
        self,
        user: User,
        state: PluginStateAccess,
    ) -> str:
        domain = state.network.domain
        if not domain:
            return ""
        layout = self._runtime_layout()
        return serialize_client_config(
            domain=domain,
            port=layout.default_port,
            username=self._derive_username(user),
            password=self._derive_password(user.uuid),
            network=transport_mode(state),
        )

    def client_link(
        self,
        user: User,
        state: PluginStateAccess,
    ) -> str:
        domain = state.network.domain
        if not domain:
            return ""
        layout = self._runtime_layout()
        return serialize_client_link(
            domain=domain,
            port=layout.default_port,
            username=self._derive_username(user),
            password=self._derive_password(user.uuid),
            quic=transport_mode(state) == "quic",
        )

    def client_links(
        self,
        user: User,
        state: PluginStateAccess,
    ) -> list[str]:
        domain = state.network.domain
        if not domain:
            return []

        layout = self._runtime_layout()
        username = self._derive_username(user)
        password = self._derive_password(user.uuid)
        mode = transport_mode(state)
        links: list[str] = []
        if mode in ("tcp", "both"):
            links.append(
                serialize_client_link(
                    domain=domain,
                    port=layout.default_port,
                    username=username,
                    password=password,
                    quic=False,
                ),
            )
        if mode in ("quic", "both"):
            links.append(
                serialize_client_link(
                    domain=domain,
                    port=layout.default_port,
                    username=username,
                    password=password,
                    quic=True,
                ),
            )
        return links
