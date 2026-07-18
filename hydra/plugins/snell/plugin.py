"""Per-user Snell v4 inbounds via sing-box-extended."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import copy
import urllib.parse

from hydra.core.state import AppState, User, get_protocol
from hydra.plugins.base import BasePlugin, ConfigFragment, PluginCategory, PluginMeta, PluginStatus
from hydra.utils.crypto import derive_hex_key
from hydra.utils.net import public_ip


PORT_START = 32000
PORT_END = 32999
SNELL_VERSION = 4
OBFS_MODE = ""
OBFS_HOST = "www.bing.com"


class SnellPlugin(BasePlugin):
    meta = PluginMeta(
        name="snell",
        description="Snell v4: отдельный PSK и порт для каждого пользователя",
        category=PluginCategory.TRANSPORT,
        version="1.0.2",
        needs_domain=False,
    )

    def install(self) -> bool:
        from hydra.core.singbox import is_installed
        return is_installed()

    def uninstall(self) -> bool:
        return True

    def configure(self, state: AppState) -> ConfigFragment:
        ports = self._port_map(state)
        inbounds = []
        for user in state.users:
            if user.blocked:
                continue
            inbounds.append({
                "type": "snell",
                "tag": self._tag(user),
                "listen": "::",
                "listen_port": ports[user.uuid],
                "psk": self._psk(user.uuid),
                "version": self._version(state),
                "network": ["tcp", "udp"],
            })
            mode = self._obfs_mode(state)
            if mode:
                inbounds[-1]["obfs"] = {"mode": mode}
        return ConfigFragment(inbounds=inbounds)

    def apply(self, state: AppState) -> bool:
        return True

    def on_user_add(self, user: User, state: AppState) -> None:
        creds = user.credentials.setdefault("snell", {})
        creds.update({"psk": self._psk(user.uuid), "port": self._port_for(user, state)})

    def on_user_remove(self, user: User, state: AppState) -> None:
        pass

    def on_user_block(self, user: User, state: AppState) -> None:
        pass

    def generate_client_config(self, user: User, state: AppState) -> str:
        server = self._server_ip(state)
        outbound = {
            "type": "snell",
            "tag": self._tag(user).replace("-in", "-out"),
            "server": server,
            "server_port": self._port_for(user, state),
            "psk": self._psk(user.uuid),
            "version": self._version(state),
            "network": ["tcp", "udp"],
        }
        mode = self._obfs_mode(state)
        if mode:
            outbound["obfs"] = {"mode": mode, "host": self._obfs_host(state)}
        return json.dumps({
            "log": {"level": "info"},
            "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
            "route": {"final": outbound["tag"]},
        }, indent=2)

    def client_link(self, user: User, state: AppState) -> str:
        server = self._url_host(self._server_ip(state))
        psk = urllib.parse.quote(self._psk(user.uuid), safe="")
        query_params = {"version": self._version(state)}
        mode = self._obfs_mode(state)
        if mode:
            query_params.update({"obfs": mode, "obfs-host": self._obfs_host(state)})
        query = urllib.parse.urlencode(query_params)
        tag = urllib.parse.quote(f"{user.email} Snell", safe="")
        return f"snell://{psk}@{server}:{self._port_for(user, state)}?{query}#{tag}"

    def on_enable(self, state: AppState) -> None:
        ps = get_protocol(state, "snell")
        # sing-box-extended accepts v5 on the inbound, but its outbound maps
        # v5 to v4.  Keeping both ends on v4 avoids an incompatible handshake.
        ps.config["version"] = self._version(state)
        ps.config.setdefault("obfs_mode", OBFS_MODE)
        ps.config.setdefault("obfs_host", OBFS_HOST)
        from hydra.utils.firewall import open_range
        open_range("tcp", PORT_START, PORT_END, "snell")

    def on_disable(self, state: AppState) -> None:
        from hydra.utils.firewall import close_range
        close_range("tcp", PORT_START, PORT_END, "snell")

    def status(self) -> PluginStatus:
        from hydra.core.singbox import is_installed, is_running
        from hydra.core.state import load_state
        installed = is_installed()
        enabled = False
        info = {"Диапазон": f"{PORT_START}-{PORT_END}"}
        try:
            state = load_state()
            ps = state.protocols.get("snell")
            enabled = bool(ps and ps.enabled)
            info["Версия"] = f"v{self._version(state)}"
            mode = self._obfs_mode(state)
            info["Obfs"] = f"{mode.upper()} · {self._obfs_host(state)}" if mode else "выключен"
        except Exception:
            pass
        return PluginStatus(installed, enabled, installed and enabled and is_running(), PORT_START,
                            info)

    @staticmethod
    def _psk(seed: str) -> str:
        # Keep the original derivation label so existing installations retain
        # their issued PSKs while migrating the wire protocol to v4.
        return derive_hex_key("snell-v5-psk", seed)

    @staticmethod
    def _tag(user: User) -> str:
        return f"snell-{hashlib.sha256(user.uuid.encode()).hexdigest()[:12]}-in"

    @staticmethod
    def _port_map(state: AppState) -> dict[str, int]:
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
                port = int(stored)
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

    def _port_for(self, user: User, state: AppState) -> int:
        port = self._port_map(state).get(user.uuid)
        if port is not None:
            return port
        size = PORT_END - PORT_START + 1
        return PORT_START + int(hashlib.sha256(user.uuid.encode()).hexdigest()[:8], 16) % size

    @staticmethod
    def _server_ip(state: AppState) -> str:
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
    def _version(state: AppState) -> int:
        ps = state.protocols.get("snell")
        version = int(ps.config.get("version", SNELL_VERSION)) if ps else SNELL_VERSION
        if version == 5:
            # Compatibility migration for installations created before the
            # sing-box-extended outbound v5->v4 behaviour was accounted for.
            return 4
        if version != 4:
            raise ValueError("Hydra Snell supports version 4")
        return SNELL_VERSION

    @staticmethod
    def _obfs_mode(state: AppState) -> str:
        ps = state.protocols.get("snell")
        mode = str(ps.config.get("obfs_mode", OBFS_MODE)) if ps else OBFS_MODE
        if mode not in {"", "http", "tls"}:
            raise ValueError("Snell obfs mode must be empty, http or tls")
        return mode

    @staticmethod
    def _obfs_host(state: AppState) -> str:
        ps = state.protocols.get("snell")
        host = str(ps.config.get("obfs_host", OBFS_HOST)).strip() if ps else OBFS_HOST
        if not host or "://" in host or any(ch.isspace() for ch in host):
            raise ValueError("Некорректный Snell obfs host")
        return host

    def set_settings(self, state: AppState, version: int, obfs_mode: str,
                     obfs_host: str = OBFS_HOST) -> bool:
        from hydra.core.state import save_state
        from hydra.core import orchestrator

        ps = get_protocol(state, "snell")
        previous = copy.deepcopy(ps.config)
        ps.config.update({
            "version": 4 if int(version) == 5 else int(version),
            "obfs_mode": obfs_mode,
            "obfs_host": obfs_host.strip(),
        })
        try:
            self._version(state)
            mode = self._obfs_mode(state)
            if mode:
                self._obfs_host(state)
        except Exception:
            ps.config = previous
            raise
        save_state(state)
        try:
            applied = not ps.enabled or orchestrator.apply_config(state)
        except Exception:
            applied = False
        if applied:
            return True
        ps.config = previous
        save_state(state)
        try:
            orchestrator.apply_config(state)
        except Exception:
            pass
        return False
