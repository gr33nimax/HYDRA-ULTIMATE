"""Per-user Snell 5/6 inbounds via sing-box-extended."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import urllib.parse

from hydra.core.state_models import User
from hydra.plugins.context import PluginStateAccess
from hydra.plugins.base import BasePlugin, ConfigFragment, PluginCategory, PluginMeta, PluginStatus
from hydra.utils.crypto import derive_hex_key
from hydra.utils.net import public_ip
from hydra.utils.plugin_identity import snell_user_tag


PORT_START = 32000
PORT_END = 32999
SNELL_GENERATIONS = (5, 6)
SNELL_VERSION = 5
# Obfuscation is not free-form. Surge's own protocol gives `tls` only to generations 1-3;
# generations 4 and 5 carry `http` or nothing, and generation 6 replaced obfuscation with its own
# traffic `mode`. A generation-5 server left with `tls` offers a combination no conforming client
# can answer, and every connection then dies on its first record with "cipher: message
# authentication failed" — which is exactly what a host configured that way showed for every
# client, every time.
OBFS_MODES = ("none", "http")
OBFS_MODE = "none"
OBFS_HOST = "www.bing.com"
V6_MODES = ("default", "unshaped", "unsafe-raw")
V6_MODE = "default"

# The first HydraCore release that carries the upstream Snell implementation: its server
# accepts version 5 or 6 and expects the flat `obfs_mode` / `mode` fields. The core this
# plugin was written for owned its own Snell and took a server `version: 4`.
MIN_SNELL_CORE = "v1.14.0-extended-2.7.1-hydracore.12"


def kernel_supports_snell() -> bool:
    """Report whether the installed core speaks the upstream Snell generations."""
    try:
        from hydra.core.singbox import get_version
        from hydra.core.singbox_upgrade import parse_version

        version = get_version()
    except Exception:
        return False
    return bool(version) and parse_version(version) >= parse_version(MIN_SNELL_CORE)


class SnellPlugin(BasePlugin):
    meta = PluginMeta(
        name="snell",
        description="Snell 5/6: отдельный PSK и порт для каждого пользователя",
        category=PluginCategory.TRANSPORT,
        version="1.1.0",
        needs_domain=False,
        commands=("set_settings",),
        connection_source="tracked",
    )

    def install(self) -> bool:
        from hydra.core.singbox import is_installed

        return is_installed()

    def uninstall(self) -> bool:
        return True

    def configure(self, state: PluginStateAccess) -> ConfigFragment:
        self._require_generation_support()
        ports = self._port_map(state)
        generation = self._version(state)
        inbounds = []
        for user in state.users:
            if user.blocked:
                continue
            inbound = {
                "type": "snell",
                "tag": self._tag(user),
                "listen": "::",
                "listen_port": ports[user.uuid],
                "psk": self._psk(user.uuid),
                "version": generation,
                # No `network` here: the core dropped that field from the Snell inbound schema and
                # refuses a configuration carrying it, and Snell tunnels UDP inside its own session
                # anyway. This field is what stopped Snell from being installed at all.
            }
            if generation == 5:
                obfs_mode = self._obfs_mode(state)
                if obfs_mode != "none":
                    inbound["obfs_mode"] = obfs_mode
            else:
                inbound["mode"] = self._v6_mode(state)
            inbounds.append(inbound)
        return ConfigFragment(inbounds=inbounds)

    def apply(self, state: PluginStateAccess) -> bool:
        return True

    def on_user_add(self, user: User, state: PluginStateAccess) -> None:
        creds = user.credentials.setdefault("snell", {})
        creds.update({"psk": self._psk(user.uuid), "port": self._port_for(user, state)})

    def on_user_remove(self, user: User, state: PluginStateAccess) -> None:
        pass

    def on_user_block(self, user: User, state: PluginStateAccess) -> None:
        pass

    def generate_client_config(self, user: User, state: PluginStateAccess) -> str:
        server = self._server_ip(state)
        generation = self._version(state)
        outbound = {
            "type": "snell",
            "tag": self._tag(user).replace("-in", "-out"),
            "server": server,
            "server_port": self._port_for(user, state),
            "psk": self._psk(user.uuid),
            # The classic generation is negotiated as 4 on the client side even
            # though the server that answers it is version 5; the core has no
            # outbound 5 at all.
            "version": 4 if generation == 5 else 6,
        }
        if generation == 5:
            obfs_mode = self._obfs_mode(state)
            if obfs_mode != "none":
                outbound["obfs_mode"] = obfs_mode
                outbound["obfs_host"] = self._obfs_host(state)
        else:
            outbound["mode"] = self._v6_mode(state)
        return json.dumps(
            {
                "log": {"level": "info"},
                "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
                "route": {"final": outbound["tag"]},
            },
            indent=2,
        )

    def client_link(self, user: User, state: PluginStateAccess) -> str:
        server = self._url_host(self._server_ip(state))
        psk = urllib.parse.quote(self._psk(user.uuid), safe="")
        generation = self._version(state)
        query_params = {
            # What a client sends, not what the server is configured as.
            "version": 4 if generation == 5 else 6,
            "udp-relay": "true",
        }
        if generation == 5:
            obfs_mode = self._obfs_mode(state)
            if obfs_mode != "none":
                query_params.update({"obfs-mode": obfs_mode, "obfs-host": self._obfs_host(state)})
        else:
            query_params["mode"] = self._v6_mode(state)
        query = urllib.parse.urlencode(query_params)
        tag = urllib.parse.quote(f"{user.email} Snell", safe="")
        return f"snell://{psk}@{server}:{self._port_for(user, state)}?{query}#{tag}"

    def on_enable(self, state: PluginStateAccess) -> None:
        if state.protocols.get("snell") is None:
            raise ValueError("Snell configuration is missing")
        self._require_generation_support()
        generation = self._version(state)
        if generation == 5 and self._obfs_mode(state) != "none":
            self._obfs_host(state)
        self._v6_mode(state)
        from hydra.utils.firewall import open_range

        open_range("tcp", PORT_START, PORT_END, "snell")

    def on_disable(self, state: PluginStateAccess) -> None:
        from hydra.utils.firewall import close_range

        close_range("tcp", PORT_START, PORT_END, "snell")

    def status(
        self,
        state: PluginStateAccess | None = None,
    ) -> PluginStatus:
        from hydra.core.singbox import is_installed, is_running

        installed = is_installed()
        enabled = False
        info = {"Диапазон": f"{PORT_START}-{PORT_END}"}
        if state is not None:
            try:
                ps = state.protocols.get("snell")
                enabled = bool(ps and ps.enabled)
                generation = self._version(state)
                info["Версия"] = f"v{generation}"
                if generation == 5:
                    mode = self._obfs_mode(state)
                    info["Obfs"] = f"{mode.upper()} · {self._obfs_host(state)}" if mode != "none" else "выключен"
                else:
                    info["Режим"] = self._v6_mode(state)
                    info["Obfs"] = "не применимо"
                    info["Клиенты"] = "только v6"
            except Exception:
                pass
        return PluginStatus(installed, enabled, installed and enabled and is_running(), PORT_START, info)

    @staticmethod
    def _psk(seed: str) -> str:
        # Keep the original derivation label so existing installations retain
        # their issued PSKs while migrating the wire protocol to v4.
        return derive_hex_key("snell-v5-psk", seed)

    @staticmethod
    def _tag(user: User) -> str:
        """Compatibility wrapper for the former plugin-private helper."""
        return snell_user_tag(user)

    @staticmethod
    def _port_map(state: PluginStateAccess) -> dict[str, int]:
        used: set[int] = set()
        result: dict[str, int] = {}
        size = PORT_END - PORT_START + 1
        if len(state.users) > size:
            raise ValueError("Snell user count exceeds the dedicated port range")
        ordered_users = sorted(state.users, key=lambda item: item.uuid)

        # Preserve previously issued ports. This prevents a rare hash
        # collision with a newly added user from changing an existing link.
        for user in ordered_users:
            stored = user.credentials.get("snell", {}).get("port")
            try:
                port = int(str(stored).strip())
            except (TypeError, ValueError):
                continue
            if PORT_START <= port <= PORT_END and port not in used:
                used.add(port)
                result[user.uuid] = port

        for user in ordered_users:
            if user.uuid in result:
                continue
            port = PORT_START + int(hashlib.sha256(user.uuid.encode()).hexdigest()[:8], 16) % size
            while port in used:
                port = PORT_START + ((port - PORT_START + 1) % size)
            used.add(port)
            result[user.uuid] = port
        return result

    def _port_for(self, user: User, state: PluginStateAccess) -> int:
        port = self._port_map(state).get(user.uuid)
        if port is not None:
            return port
        size = PORT_END - PORT_START + 1
        return PORT_START + int(hashlib.sha256(user.uuid.encode()).hexdigest()[:8], 16) % size

    @staticmethod
    def _server_ip(state: PluginStateAccess) -> str:
        """Return the server IP without borrowing a domain from another plugin."""
        value = (state.network.server_ip or public_ip()).strip().strip("[]")
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise ValueError("Не удалось определить публичный IP сервера для Snell") from exc

    @staticmethod
    def _url_host(value: str) -> str:
        address = ipaddress.ip_address(value)
        return f"[{address}]" if address.version == 6 else str(address)

    @staticmethod
    def _version(state: PluginStateAccess) -> int:
        ps = state.protocols.get("snell")
        raw = ps.config.get("version", SNELL_VERSION) if ps else SNELL_VERSION
        try:
            version = int(str(raw).strip())
        except (TypeError, ValueError) as exc:
            raise ValueError("Некорректная версия Snell") from exc
        # A server-side version 4 no longer exists in the core: the classic
        # generation is 5, and its pair is server 5 with client 4.
        if version == 4:
            return 5
        if version not in SNELL_GENERATIONS:
            raise ValueError("Hydra Snell supports generations 5 and 6")
        return version

    @staticmethod
    def _obfs_mode(state: PluginStateAccess) -> str:
        ps = state.protocols.get("snell")
        raw = ps.config.get("obfs_mode", OBFS_MODE) if ps else OBFS_MODE
        mode = str(raw).strip().lower() or "none"
        if mode not in OBFS_MODES:
            raise ValueError(
                "Snell obfs mode must be none or http: `tls` belongs to generations 1-3, and "
                "generation 6 replaces obfuscation with its own mode",
            )
        return mode

    @staticmethod
    def _v6_mode(state: PluginStateAccess) -> str:
        ps = state.protocols.get("snell")
        raw = ps.config.get("mode", V6_MODE) if ps else V6_MODE
        mode = str(raw).strip().lower() or V6_MODE
        if mode not in V6_MODES:
            raise ValueError("Snell v6 mode must be default, unshaped or unsafe-raw")
        return mode

    @staticmethod
    def _require_generation_support() -> None:
        if not kernel_supports_snell():
            raise ValueError(
                f"Snell 5/6 requires a HydraCore with the upstream Snell implementation ({MIN_SNELL_CORE} or newer)"
            )

    @staticmethod
    def _obfs_host(state: PluginStateAccess) -> str:
        ps = state.protocols.get("snell")
        host = str(ps.config.get("obfs_host", OBFS_HOST)).strip() if ps else OBFS_HOST
        if not host or "://" in host or any(ch.isspace() for ch in host):
            raise ValueError("Некорректный Snell obfs host")
        return host

    def set_settings(
        self,
        state: PluginStateAccess,
        version: int,
        obfs_mode: str = OBFS_MODE,
        obfs_host: str = OBFS_HOST,
        mode: str = V6_MODE,
    ) -> bool:
        """Validate and update desired Snell settings without I/O."""
        try:
            raw_version = int(str(version).strip())
        except (TypeError, ValueError) as exc:
            raise ValueError("Некорректная версия Snell") from exc
        # 4 was the server-side version of the previous core; it maps onto the
        # classic generation, which the current core serves as 5.
        normalized_version = 5 if raw_version == 4 else raw_version
        if normalized_version not in SNELL_GENERATIONS:
            raise ValueError("Hydra Snell supports generations 5 and 6")
        normalized_mode = str(obfs_mode).strip().lower() or "none"
        if normalized_mode not in OBFS_MODES:
            raise ValueError(
                "Snell obfs mode must be none or http: `tls` belongs to generations 1-3, and "
                "generation 6 replaces obfuscation with its own mode",
            )
        normalized_v6_mode = str(mode).strip().lower() or V6_MODE
        if normalized_v6_mode not in V6_MODES:
            raise ValueError("Snell v6 mode must be default, unshaped or unsafe-raw")
        if normalized_version == 6 and normalized_mode != "none":
            raise ValueError("Snell generation 6 replaces obfuscation with its own mode")
        if normalized_version == 5 and normalized_v6_mode != V6_MODE:
            raise ValueError("Snell v6 mode applies to generation 6 only")
        normalized_host = str(obfs_host).strip()
        if normalized_mode == "http" and (
            not normalized_host or "://" in normalized_host or any(character.isspace() for character in normalized_host)
        ):
            raise ValueError("Invalid Snell obfs host")
        ps = state.protocols.get("snell")
        if ps is None:
            return False
        ps.config.update(
            {
                "version": normalized_version,
                "obfs_mode": normalized_mode,
                "obfs_host": normalized_host,
                "mode": normalized_v6_mode,
            },
        )
        return True
