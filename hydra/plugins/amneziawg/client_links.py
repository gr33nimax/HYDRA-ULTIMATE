"""Read-only AmneziaWG client configuration and link serialization."""
from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from pathlib import Path

from hydra.core.state_models import User
from hydra.plugins.context import PluginStateAccess

from .constants import (
    DEFAULT_NETWORK,
    DEFAULT_PORT_1,
    OBFUSCATION_KEYS_EXTENDED,
)


@dataclass(frozen=True)
class _ClientProfile:
    name: str
    conf_path: Path
    keys: dict
    address_base: str
    address_octet: str
    server_public_key: str
    endpoint: str
    port: int
    mtu: str
    obfuscation: dict[str, str]


class AwgClientLinksMixin:
    """Serialize already-provisioned state without creating credentials."""

    def _client_profile(
        self,
        user: User,
        state: PluginStateAccess,
        profile_name: str,
    ) -> _ClientProfile | None:
        conf_path = self._conf_path(profile_name)
        if not conf_path.exists():
            return None
        keys = self._existing_keys(user, profile_name)
        if keys is None:
            return None
        address_octet = self._existing_peer_ips_for_conf(conf_path).get(
            keys["public_key"]
        )
        if not address_octet:
            return None
        default_network = (
            "10.68.68.0/24"
            if profile_name == "mobile"
            else DEFAULT_NETWORK
        )
        address_base, _, _ = self._network_for_profile(
            state,
            conf_path,
            profile_name,
            default_network,
        )
        server_public_key = self._server_pubkey_for_conf(conf_path)
        port = self._profile_port(state, profile_name)
        params = self._params()
        endpoint = (
            state.network.server_ip
            or params.get("SERVER_PUB_IP")
            or self._public_ip()
        )
        mtu_match = re.search(
            r"^MTU\s*=\s*(\d+)",
            self._interface_block_for_conf(conf_path, address_base, "1"),
            re.M,
        )
        mtu = (
            mtu_match.group(1)
            if mtu_match and mtu_match.group(1) != "1420"
            else "1376"
        )
        return _ClientProfile(
            name=profile_name,
            conf_path=conf_path,
            keys=keys,
            address_base=address_base,
            address_octet=address_octet,
            server_public_key=server_public_key,
            endpoint=endpoint,
            port=port,
            mtu=mtu,
            obfuscation=self._obfuscation_for_conf(conf_path),
        )

    def _profile_port(
        self,
        state: PluginStateAccess,
        profile_name: str,
    ) -> int:
        if profile_name != "mobile":
            return self._current_port()
        profile = self._profile_config(state, "mobile")
        if profile is None:
            return DEFAULT_PORT_1
        return profile.get("port", DEFAULT_PORT_1)

    def _render_client_config(
        self,
        profile: _ClientProfile,
        state: PluginStateAccess,
    ) -> str:
        params = self._params()
        primary_dns = params.get("CLIENT_DNS_1", "1.1.1.1")
        secondary_dns = params.get("CLIENT_DNS_2", "")
        dns = (
            f"{primary_dns}, {secondary_dns}"
            if secondary_dns
            else primary_dns
        )
        dnscrypt = state.protocols.get("dnscrypt")
        if dnscrypt and dnscrypt.enabled:
            dns = profile.endpoint
        lines = [
            "[Interface]",
            f"PrivateKey = {profile.keys['private_key']}",
            (
                f"Address = {profile.address_base}."
                f"{profile.address_octet}/32"
            ),
            f"DNS = {dns}",
            f"MTU = {profile.mtu}",
            "",
        ]
        for key in OBFUSCATION_KEYS_EXTENDED:
            if profile.obfuscation.get(key) not in (None, ""):
                lines.append(f"{key} = {profile.obfuscation[key]}")
        lines.extend(
            (
                "",
                "[Peer]",
                f"PublicKey = {profile.server_public_key}",
                f"PresharedKey = {profile.keys['preshared_key']}",
                f"Endpoint = {profile.endpoint}:{profile.port}",
                "AllowedIPs = 0.0.0.0/0",
                "PersistentKeepalive = 25",
            )
        )
        return "\n".join(lines)

    def generate_client_config(
        self,
        user: User,
        state: PluginStateAccess,
        profile: str = None,
    ) -> str:
        """Render a client config from existing desired/runtime material."""
        data = self._client_profile(user, state, profile or "desktop")
        return self._render_client_config(data, state) if data else ""

    def client_link(
        self,
        user: User,
        state: PluginStateAccess,
        profile: str = None,
    ) -> str:
        """Return a ``wg://`` link understood by AmneziaWG clients."""
        profile_name = profile or "desktop"
        config = self.generate_client_config(user, state, profile=profile_name)
        if not config:
            return ""

        def field(key: str) -> str | None:
            match = re.search(rf"^{key}\s*=\s*(.+)$", config, re.M)
            return match.group(1).strip() if match else None

        endpoint = field("Endpoint")
        if not endpoint or ":" not in endpoint:
            return ""
        host, port = endpoint.rsplit(":", 1)
        params = []
        if field("PrivateKey"):
            params.append(f"private_key={field('PrivateKey')}")
        if field("Address"):
            params.append(f"local_address={field('Address')}")
        params.append("enable_amnezia=true")
        for key in OBFUSCATION_KEYS_EXTENDED:
            value = field(key)
            if value:
                params.append(f"{key.lower()}={value}")
        if field("PublicKey"):
            params.append(f"public_key={field('PublicKey')}")
        if field("PresharedKey"):
            params.append(f"pre_shared_key={field('PresharedKey')}")
        params.append("persistent_keepalive_interval=25")
        label = "AWG Mobile" if profile_name == "mobile" else "AWG Desktop"
        return (
            f"wg://{host}:{port}?{'&'.join(params)}"
            f"#{user.email}%20{label}"
        )

    def amnezia_link(
        self,
        user: User,
        state: PluginStateAccess,
        profile: str = None,
    ) -> str:
        """Return a one-tap ``vpn://`` link for the official Amnezia client."""
        profile_name = profile or "desktop"
        config = self.generate_client_config(
            user,
            state,
            profile=profile_name,
        )
        if not config:
            return ""
        data = self._client_profile(user, state, profile_name)
        if data is None:
            return ""
        inner = self._amnezia_payload(data, config)
        inner_json = json.dumps(inner, ensure_ascii=False)
        inner_b64 = base64.b64encode(inner_json.encode("utf-8")).decode("ascii")
        outer = {
            "containers": [
                {
                    "awg": {
                        "isThirdPartyConfig": True,
                        "last_config": inner_json,
                        "port": str(data.port),
                        "protocol_version": "2",
                        "transport_proto": "udp",
                    },
                    "container": "amnezia-awg",
                }
            ],
            "defaultContainer": "amnezia-awg",
        }
        outer_json = json.dumps(outer, ensure_ascii=False)
        outer_b64 = base64.b64encode(outer_json.encode("utf-8")).decode("ascii")
        return f"vpn://free/{outer_b64}/{inner_b64}"

    def client_links(
        self,
        user: User,
        state: PluginStateAccess,
        profile: str = None,
    ) -> list[str]:
        """Expose every supported client import format through the contract."""
        values = (
            self.client_link(user, state, profile=profile),
            self.amnezia_link(user, state, profile=profile),
        )
        return list(dict.fromkeys(value for value in values if value))

    @staticmethod
    def _amnezia_payload(
        data: _ClientProfile,
        config: str,
    ) -> dict:
        obfuscation = data.obfuscation
        payload = {
            "H1": str(obfuscation.get("H1", "1")),
            "H2": str(obfuscation.get("H2", "2")),
            "H3": str(obfuscation.get("H3", "3")),
            "H4": str(obfuscation.get("H4", "4")),
            "Jc": str(obfuscation.get("Jc", "4")),
            "Jmin": str(obfuscation.get("Jmin", "40")),
            "Jmax": str(obfuscation.get("Jmax", "70")),
            "S1": str(obfuscation.get("S1", "0")),
            "S2": str(obfuscation.get("S2", "0")),
            "S3": str(obfuscation.get("S3", "0")),
            "S4": str(obfuscation.get("S4", "0")),
        }
        for key in ("I1", "I2", "I3", "I4", "I5"):
            value = obfuscation.get(key, "")
            if value:
                payload[key] = str(value)
        payload.update(
            {
                "allowed_ips": ["0.0.0.0/0"],
                "client_ip": (
                    f"{data.address_base}.{data.address_octet}"
                ),
                "client_ipv6": "",
                "client_priv_key": data.keys["private_key"],
                "config": config,
                "hostName": data.endpoint,
                "mtu": str(data.mtu),
                "persistent_keep_alive": "25",
                "port": data.port,
                "server_pub_key": data.server_public_key,
            }
        )
        if data.keys.get("preshared_key"):
            payload["psk_key"] = data.keys["preshared_key"]
        return payload
