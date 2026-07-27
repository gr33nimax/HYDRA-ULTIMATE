"""Hysteria2 multi-user QUIC transport via sing-box-extended."""
from __future__ import annotations

import json
import urllib.parse

from hydra.core.state_models import User
from hydra.plugins.context import PluginStateAccess
from hydra.plugins.decoy_support import DecoyThemeSupport
from hydra.plugins.base import BasePlugin, ConfigFragment, PluginCategory, PluginMeta, PluginStatus
from hydra.utils.crypto import derive_hex_key
from hydra.utils.net import public_ip
from hydra.utils.tls import resolve_tls_material


DEFAULT_PORT = 8443
DECOY_DIR = "/var/www/decoy-hysteria2"


class Hysteria2Plugin(DecoyThemeSupport, BasePlugin):

    decoy_default_theme = "status"
    meta = PluginMeta(
        name="hysteria2",
        description="Hysteria2: QUIC-транспорт с Salamander obfuscation",
        category=PluginCategory.TRANSPORT,
        version="1.0.0",
        needs_domain=True,
        commands=(
            "set_domain",
            "set_port",
            "set_congestion",
            "set_obfs_password",
            "set_decoy_theme",
        ),
        tls_domain_source="protocol",
        config_defaults=(("decoy_theme", "status"),),
        connection_source="tracked",
    )

    def install(self) -> bool:
        from hydra.core.singbox import is_installed
        return is_installed()

    def uninstall(self) -> bool:
        return True

    def configure(self, state: PluginStateAccess) -> ConfigFragment:
        ps = state.protocols.get("hysteria2")
        if not ps:
            return ConfigFragment()
        domain = str(ps.config.get("domain", "")).strip()
        cert, key = resolve_tls_material(domain, ps.config)
        users = [
            {"name": user.email, "password": self._password(user.uuid)}
            for user in state.users if not user.blocked
        ]
        if not domain or not cert or not key or not users:
            return ConfigFragment()

        port = self._port(state)
        obfs_password = self._obfs_password(state)
        inbound = {
            "type": "hysteria2",
            "tag": "hysteria2-in",
            "listen": "::",
            "listen_port": port,
            "users": users,
            "obfs": {"type": "salamander", "password": obfs_password},
            "tls": {
                "enabled": True,
                "server_name": domain,
                "alpn": ["h3"],
                "certificate_path": cert,
                "key_path": key,
            },
            "masquerade": {
                "type": "file",
                "directory": DECOY_DIR,
            },
        }
        mode = self._congestion_mode(state)
        if mode == "brutal":
            inbound["up_mbps"] = self._bandwidth(state, "up_mbps")
            inbound["down_mbps"] = self._bandwidth(state, "down_mbps")
        else:
            inbound["ignore_client_bandwidth"] = True
        return ConfigFragment(inbounds=[inbound])

    def apply(self, state: PluginStateAccess) -> bool:
        from hydra.core.decoy import ensure_decoy_site
        from hydra.utils.firewall import open_tcp
        protocol = state.protocols.get("hysteria2")
        ensure_decoy_site(
            "hysteria2",
            self.decoy_theme(state),
            domain=str(protocol.config.get("domain", "")) if protocol else "",
        )
        open_tcp(80, "hysteria2-decoy-http")
        open_tcp(443, "hysteria2-decoy")
        return True

    def on_user_add(self, user: User, state: PluginStateAccess) -> None:
        user.credentials.setdefault("hysteria2", {})["password"] = self._password(user.uuid)

    def on_user_remove(self, user: User, state: PluginStateAccess) -> None:
        pass

    def on_user_block(self, user: User, state: PluginStateAccess) -> None:
        pass

    def generate_client_config(self, user: User, state: PluginStateAccess) -> str:
        ps = state.protocols.get("hysteria2")
        if not ps or not ps.config.get("domain"):
            return ""
        domain = ps.config["domain"]
        server = state.network.server_ip or domain or public_ip()
        outbound = {
            "type": "hysteria2",
            "tag": f"hysteria2-{user.email}",
            "server": server,
            "server_port": self._port(state),
            "password": self._password(user.uuid),
            "obfs": {"type": "salamander", "password": self._obfs_password(state)},
            "tls": {"enabled": True, "server_name": domain, "alpn": ["h3"]},
        }
        if self._congestion_mode(state) == "brutal":
            outbound["up_mbps"] = self._bandwidth(state, "up_mbps")
            outbound["down_mbps"] = self._bandwidth(state, "down_mbps")
        return json.dumps({
            "log": {"level": "info"},
            "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
            "route": {"final": outbound["tag"]},
        }, indent=2)

    def client_link(self, user: User, state: PluginStateAccess) -> str:
        ps = state.protocols.get("hysteria2")
        if not ps or not ps.config.get("domain"):
            return ""
        domain = ps.config["domain"]
        server = state.network.server_ip or domain or public_ip()
        query = urllib.parse.urlencode({
            "sni": domain,
            "obfs": "salamander",
            "obfs-password": self._obfs_password(state),
            "alpn": "h3",
        })
        password = urllib.parse.quote(self._password(user.uuid), safe="")
        tag = urllib.parse.quote(f"{user.email} Hysteria2", safe="")
        return f"hysteria2://{password}@{server}:{self._port(state)}/?{query}#{tag}"

    def on_enable(self, state: PluginStateAccess) -> None:
        ps = state.protocols.get("hysteria2")
        if ps is None or not str(ps.config.get("domain", "")).strip():
            raise ValueError("Hysteria2 domain is not configured")
        port = self._port(state)
        from hydra.utils.firewall import open_udp
        open_udp(port, "hysteria2")

    def on_disable(self, state: PluginStateAccess) -> None:
        from hydra.utils.firewall import close_tcp, close_udp
        close_udp(self._port(state), "hysteria2")
        close_tcp(80, "hysteria2-decoy-http")
        close_tcp(443, "hysteria2-decoy")

    def status(
        self,
        state: PluginStateAccess | None = None,
    ) -> PluginStatus:
        from hydra.core.singbox import is_installed, is_running
        installed = is_installed()
        enabled = False
        port = DEFAULT_PORT
        ps = None
        if state is not None:
            ps = state.protocols.get("hysteria2")
            enabled = bool(ps and ps.enabled)
            port = self._port(state)
        info = {}
        try:
            if ps and state:
                mode = self._congestion_mode(state)
                info["Домен"] = ps.config.get("domain", "")
                info["Congestion"] = (
                    f"Brutal {self._bandwidth(state, 'up_mbps')}/{self._bandwidth(state, 'down_mbps')} Mbps"
                    if mode == "brutal" else "BBR"
                )
        except Exception:
            pass
        return PluginStatus(installed, enabled, installed and enabled and is_running(), port, info)

    def traffic(self, state: PluginStateAccess) -> dict[str, int]:
        return {
            user.email: int(user.credentials.get("hysteria2", {}).get("traffic_used_bytes", 0))
            for user in state.users
            if int(user.credentials.get("hysteria2", {}).get("traffic_used_bytes", 0)) > 0
        }

    @staticmethod
    def _password(seed: str) -> str:
        return derive_hex_key("hysteria2-pass", seed)

    @staticmethod
    def _port(state: PluginStateAccess) -> int:
        ps = state.protocols.get("hysteria2")
        port = int(ps.config.get("port", DEFAULT_PORT)) if ps else DEFAULT_PORT
        if not 1 <= port <= 65535:
            raise ValueError("Hysteria2 port must be between 1 and 65535")
        return port

    @staticmethod
    def _obfs_password(state: PluginStateAccess) -> str:
        ps = state.protocols.get("hysteria2")
        if ps and ps.config.get("obfs_password"):
            return str(ps.config["obfs_password"])
        domain = str(ps.config.get("domain", "hydra")) if ps else "hydra"
        return derive_hex_key("hysteria2-obfs", domain)

    @staticmethod
    def _congestion_mode(state: PluginStateAccess) -> str:
        ps = state.protocols.get("hysteria2")
        mode = str(ps.config.get("congestion_mode", "bbr")) if ps else "bbr"
        if mode not in {"bbr", "brutal"}:
            raise ValueError("Hysteria2 congestion mode must be bbr or brutal")
        return mode

    @staticmethod
    def _bandwidth(state: PluginStateAccess, key: str) -> int:
        ps = state.protocols.get("hysteria2")
        value = int(ps.config.get(key, 100)) if ps else 100
        if not 1 <= value <= 100000:
            raise ValueError("Hysteria2 bandwidth must be between 1 and 100000 Mbps")
        return value

    def set_domain(
        self,
        state: PluginStateAccess,
        domain: str,
    ) -> bool:
        ps = state.protocols.get("hysteria2")
        if ps is None:
            return False
        normalized = domain.strip().lower().rstrip(".")
        if not normalized or "://" in normalized or any(ch.isspace() for ch in normalized):
            raise ValueError("Некорректный домен Hysteria2")
        if normalized == ps.config.get("domain"):
            return True
        ps.config["domain"] = normalized
        ps.config.pop("cert_file", None)
        ps.config.pop("key_file", None)
        return True

    def set_port(
        self,
        state: PluginStateAccess,
        port: int,
    ) -> bool:
        ps = state.protocols.get("hysteria2")
        if ps is None:
            return False
        new_port = int(port)
        if not 1 <= new_port <= 65535:
            raise ValueError("Hysteria2 port must be between 1 and 65535")
        ps.config["port"] = new_port
        ps.port = new_port
        return True

    def set_congestion(
        self,
        state: PluginStateAccess,
        mode: str,
        up_mbps: int = 100,
        down_mbps: int = 100,
    ) -> bool:
        if mode not in {"bbr", "brutal"}:
            raise ValueError("Hysteria2 congestion mode must be bbr or brutal")
        normalized_up = int(up_mbps)
        normalized_down = int(down_mbps)
        if mode == "brutal":
            if not 1 <= normalized_up <= 100000 or not 1 <= normalized_down <= 100000:
                raise ValueError("Hysteria2 bandwidth must be between 1 and 100000 Mbps")
        ps = state.protocols.get("hysteria2")
        if ps is None:
            return False
        ps.config["congestion_mode"] = mode
        if mode == "brutal":
            ps.config["up_mbps"] = normalized_up
            ps.config["down_mbps"] = normalized_down
        return True

    def set_obfs_password(
        self,
        state: PluginStateAccess,
        password: str,
    ) -> bool:
        value = password.strip()
        if len(value) < 16:
            raise ValueError("Salamander-пароль должен содержать минимум 16 символов")
        ps = state.protocols.get("hysteria2")
        if ps is None:
            return False
        ps.config["obfs_password"] = value
        return True
