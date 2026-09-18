"""Read-only AmneziaWG client configuration and link serialization."""

from __future__ import annotations

import base64
import json
import re
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TYPE_CHECKING

from hydra.core.host import HOST
from hydra.core.state_models import User
from hydra.plugins.context import PluginStateAccess

from .constants import (
    DEFAULT_MTU,
    OBFUSCATION_KEYS_EXTENDED,
    PROFILE_NETWORKS,
)
from .directives import GENERATION_DIRECTIVE_KEYS, canonical_mode
from .endpoints import canonical_generation
from .keys import public_key

# The first HydraCore release that carries the two AWG 3.1 configuration fields.
# An older core refuses such a profile at parse time, so the HydraBox export stays
# closed until that release is installed.
MIN_AWG31_CORE = "v1.14.0-extended-2.7.1-hydracore.12"


def _boolean(value: object) -> bool:
    return str(value).strip().lower() in {"1", "true", "on", "yes"}


def kernel_supports_awg31() -> bool:
    """Report whether the installed core understands the AWG 3.1 field set."""
    try:
        from hydra.core.singbox import get_version
        from hydra.core.singbox_upgrade import parse_version

        version = get_version()
    except Exception:
        return False
    return bool(version) and parse_version(version) >= parse_version(MIN_AWG31_CORE)


@dataclass(frozen=True)
class _ClientProfile:
    name: str
    keys: dict
    address_base: str
    address_octet: str
    server_public_key: str
    endpoint: str
    port: int
    mtu: str
    obfuscation: dict[str, str]
    generation: dict[str, str]
    protocol_mode: str


class AwgClientLinksMixin:
    """Serialize already-provisioned state without creating credentials."""

    if TYPE_CHECKING:

        def __getattr__(self, name: str) -> Any:
            """Static dependency seam for client serialization."""
            ...

    def _client_profile(
        self,
        user: User,
        state: PluginStateAccess,
        profile_name: str,
    ) -> _ClientProfile | None:
        """Serialize one user's profile from desired state alone."""
        profile = self._profile_config(state, profile_name) or {}
        keys = self._existing_keys(user, profile_name)
        if keys is None:
            return None
        address_octet = str(keys.get("address_octet") or "").strip()
        if not address_octet:
            return None
        # The public half is derived from the server key HYDRA holds: the key is the only source, so a
        # client can never be handed a value the endpoint does not serve.
        server_private_key = str(profile.get("server_private_key") or "").strip()
        server_public_key = str(profile.get("server_public_key") or "").strip() or (
            public_key(server_private_key) if server_private_key else ""
        )
        if not server_public_key:
            return None
        address_base, _, _ = self._network_for_profile(
            state,
            profile_name,
            PROFILE_NETWORKS.get(profile_name, PROFILE_NETWORKS["desktop"]),
        )
        stored_generation = profile.get("generation")
        generation = stored_generation if isinstance(stored_generation, dict) else {}
        # Every client artifact reads the material the mode actually serves, not the stored copy: a
        # profile written by an earlier release can carry the opposite 3.1 pair.
        mode = self.desired_protocol_mode(state)
        generation = canonical_generation(generation, mode)
        return _ClientProfile(
            name=profile_name,
            keys=keys,
            address_base=address_base,
            address_octet=address_octet,
            server_public_key=server_public_key,
            endpoint=state.network.server_ip or self._public_ip(),
            port=self._profile_port(state, profile_name),
            mtu=str(profile.get("mtu") or "").strip() or DEFAULT_MTU,
            obfuscation=self._obfuscation(state, profile_name),
            generation={str(key): value for key, value in generation.items() if value not in (None, "")},
            protocol_mode=mode,
        )

    @staticmethod
    def _public_ip() -> str:
        """The address clients dial when desired state recorded none."""
        result = HOST.run(["hostname", "-I"], capture_output=True, text=True)
        addresses = (result.stdout or "").split()
        return addresses[0] if addresses else "127.0.0.1"

    def _render_client_config(
        self,
        profile: _ClientProfile,
        state: PluginStateAccess,
    ) -> str:
        dns = "1.1.1.1"
        dnscrypt = state.protocols.get("dnscrypt")
        if dnscrypt and dnscrypt.enabled:
            dns = profile.endpoint
        lines = [
            "[Interface]",
            f"PrivateKey = {profile.keys['private_key']}",
            (f"Address = {profile.address_base}.{profile.address_octet}/32"),
            f"DNS = {dns}",
            f"MTU = {profile.mtu}",
            "",
        ]
        for key in OBFUSCATION_KEYS_EXTENDED:
            if profile.obfuscation.get(key) not in (None, ""):
                lines.append(f"{key} = {profile.obfuscation[key]}")
        for key in GENERATION_DIRECTIVE_KEYS:
            value = canonical_generation(
                profile.generation,
                profile.protocol_mode,
            ).get(key)
            if value in (None, ""):
                continue
            # The two 3.1 flags are booleans in the stored material; a client configuration carries tokens.
            lines.append(f"{key} = {str(value).lower() if isinstance(value, bool) else value}")
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
        profile: str | None = None,
    ) -> str:
        """Render a client config from existing desired/runtime material."""
        data = self._client_profile(user, state, profile or "desktop")
        return self._render_client_config(data, state) if data else ""

    @staticmethod
    def _singbox_amnezia_options(profile: _ClientProfile) -> dict:
        options = {}
        for key in OBFUSCATION_KEYS_EXTENDED:
            value = profile.obfuscation.get(key)
            if value in (None, ""):
                continue
            normalized = key.lower()
            if key.startswith("I"):
                options[normalized] = str(value)
                continue
            try:
                options[normalized] = int(value)
            except (TypeError, ValueError):
                options[normalized] = str(value)
        for key, value in AwgClientLinksMixin._generation_fields(profile).items():
            normalized = re.sub(r"(?<!^)(?=[A-Z])", "_", key).lower()
            if key in {"RandomTrailers", "DisableCookies"}:
                # The core expects JSON booleans here; stringified ones are refused by its strict
                # configuration parser.
                options[normalized] = _boolean(value)
                continue
            options[normalized] = str(value)
        return options

    def _singbox_endpoint(
        self,
        profile: _ClientProfile,
        user: User,
    ) -> dict:
        peer = {
            "address": profile.endpoint,
            "port": profile.port,
            "public_key": profile.server_public_key,
            "allowed_ips": ["0.0.0.0/0"],
            "persistent_keepalive_interval": 25,
        }
        preshared_key = profile.keys.get("preshared_key")
        if preshared_key:
            peer["pre_shared_key"] = preshared_key
        return {
            "type": "wireguard",
            "tag": f"amneziawg-{profile.name}-{user.email}",
            "mtu": self._safe_mtu(profile.mtu),
            "address": [
                f"{profile.address_base}.{profile.address_octet}/32",
            ],
            "private_key": profile.keys["private_key"],
            "peers": [peer],
            "amnezia": self._singbox_amnezia_options(profile),
        }

    @staticmethod
    def _safe_mtu(value: str) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return 1376

    @staticmethod
    def export_capabilities(state: PluginStateAccess) -> dict[str, str]:
        """State the compatibility outcome without exposing configuration secrets."""
        protocol = state.protocols.get("amneziawg")
        mode = protocol.config.get("protocol_mode", "2.0") if protocol else "2.0"
        if mode == "2.0":
            return {
                name: "ready"
                for name in ("native_conf", "wg_uri", "vpn_uri", "sn_awg", "singbox", "hydrabox_subscription")
            }
        unsupported = f"unsupported: AWG {mode} importer compatibility is unverified"
        capabilities = {
            "native_conf": "ready",
            "wg_uri": "ready",
            "vpn_uri": "ready",
            "sn_awg": unsupported,
            "singbox": unsupported,
            "hydrabox_subscription": unsupported,
        }
        if mode == "3.0":
            capabilities["singbox"] = "ready"
            capabilities["hydrabox_subscription"] = "ready"
        elif mode == "3.1":
            if kernel_supports_awg31():
                capabilities["singbox"] = "ready"
                capabilities["hydrabox_subscription"] = "ready"
            else:
                reason = f"unsupported: AWG 3.1 requires a HydraCore with the 3.1 fields ({MIN_AWG31_CORE} or newer)"
                capabilities["singbox"] = reason
                capabilities["hydrabox_subscription"] = reason
        return capabilities

    @staticmethod
    def _export_allowed(state: PluginStateAccess, name: str) -> bool:
        return AwgClientLinksMixin.export_capabilities(state)[name] == "ready"

    def generate_singbox_client_config(
        self,
        user: User,
        state: PluginStateAccess,
    ) -> str:
        """Render every active profile as a sing-box-extended endpoint."""
        if not self._export_allowed(state, "singbox"):
            return ""
        protocol = state.protocols.get("amneziawg")
        configured = protocol.config.get("profiles") if protocol else None
        active_names = (
            {name for name, value in configured.items() if name in {"desktop", "mobile"} and isinstance(value, dict)}
            if isinstance(configured, dict) and configured
            else {"desktop"}
        )
        endpoints = []
        for profile_name in ("desktop", "mobile"):
            if profile_name not in active_names:
                continue
            profile = self._client_profile(user, state, profile_name)
            if profile is not None:
                endpoints.append(self._singbox_endpoint(profile, user))
        if not endpoints:
            return ""
        return json.dumps(
            {
                "endpoints": endpoints,
                "route": {"final": endpoints[0]["tag"]},
            },
            ensure_ascii=False,
        )

    def client_link(
        self,
        user: User,
        state: PluginStateAccess,
        profile: str | None = None,
    ) -> str:
        """Return a ``wg://`` link understood by AmneziaWG clients."""
        if not self._export_allowed(state, "wg_uri"):
            return ""
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
        data = self._client_profile(user, state, profile_name)
        if data is not None:
            for key, value in self._generation_fields(data).items():
                name = re.sub(r"(?<!^)(?=[A-Z])", "_", key).lower()
                if key in {"RandomTrailers", "DisableCookies"}:
                    # The material is a boolean once HYDRA owns it and a token when it comes from an
                    # interface file; one normalizer handles both.
                    value = "true" if _boolean(value) else "false"
                params.append(f"{name}={value}")
        if field("PublicKey"):
            params.append(f"public_key={field('PublicKey')}")
        if field("PresharedKey"):
            params.append(f"pre_shared_key={field('PresharedKey')}")
        params.append("persistent_keepalive_interval=25")
        label = "AWG Mobile" if profile_name == "mobile" else "AWG Desktop"
        return f"wg://{host}:{port}?{'&'.join(params)}#{user.email}%20{label}"

    def amnezia_link(
        self,
        user: User,
        state: PluginStateAccess,
        profile: str | None = None,
    ) -> str:
        """Return a one-tap ``vpn://`` link for the official Amnezia client."""
        if not self._export_allowed(state, "vpn_uri"):
            return ""
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
        inner_json = json.dumps(inner, ensure_ascii=False, separators=(",", ":"))
        outer = {
            "containers": [
                {
                    "awg": {
                        "isThirdPartyConfig": True,
                        "last_config": inner_json,
                        "port": str(data.port),
                        # No `protocol_version`: the client derives the generation from `last_config`,
                        # and a constant "2" on a 3.x profile is exactly what made the import fail.
                        "transport_proto": "udp",
                    },
                    "container": "amnezia-awg",
                }
            ],
            "defaultContainer": "amnezia-awg",
            "description": f"{user.email} AWG",
            "hostName": data.endpoint,
        }
        payload = json.dumps(outer, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        compressed = struct.pack(">I", len(payload)) + zlib.compress(payload, level=8)
        encoded = base64.urlsafe_b64encode(compressed).rstrip(b"=").decode("ascii")
        return f"vpn://{encoded}"

    def client_links(
        self,
        user: User,
        state: PluginStateAccess,
        profile: str | None = None,
    ) -> list[str]:
        """Expose every supported client import format through the contract."""
        values = (
            self.client_link(user, state, profile=profile),
            self.amnezia_link(user, state, profile=profile),
        )
        return list(dict.fromkeys(value for value in values if value))

    @staticmethod
    def _generation_fields(data: _ClientProfile) -> dict[str, str]:
        """Return the generation fields exactly as the server interface carries them.

        The server is the source of truth: a client handed a value its server does not have is a
        client that cannot complete a handshake. Both 3.1 fields are written into the server
        configuration where the mode is switched, and reflected here — never invented here.
        """
        material = canonical_generation(data.generation, data.protocol_mode)
        return {
            key: value
            for key, value in material.items()
            if key in GENERATION_DIRECTIVE_KEYS and value not in (None, "")
        }

    def _amnezia_payload(
        self,
        data: _ClientProfile,
        config: str,
    ) -> dict:
        obfuscation = data.obfuscation
        payload: dict[str, object] = {
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
        generation = self._generation_fields(data)
        # The Amnezia client reads every AWG parameter as a string, so a JSON boolean reaches it as
        # an empty value and the two 3.1 toggles disappear: they travel as the tokens that client
        # writes itself.
        for key in ("RandomTrailers", "DisableCookies"):
            if key in generation:
                generation[key] = "on" if _boolean(generation[key]) else "off"
        payload.update(generation)
        payload.update(
            {
                "allowed_ips": ["0.0.0.0/0"],
                "client_ip": f"{data.address_base}.{data.address_octet}/32",
                "client_ipv6": "",
                "client_priv_key": data.keys["private_key"],
                "client_pub_key": data.keys["public_key"],
                "clientId": data.keys["public_key"],
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
