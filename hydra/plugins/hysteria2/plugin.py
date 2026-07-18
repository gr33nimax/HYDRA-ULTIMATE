"""Hysteria2 multi-user QUIC transport via sing-box-extended."""
from __future__ import annotations

import json
import copy
import urllib.parse

from hydra.core.state import AppState, User, get_protocol
from hydra.plugins.base import BasePlugin, ConfigFragment, PluginCategory, PluginMeta, PluginStatus
from hydra.plugins.tls_support import ensure_tls_material, resolve_tls_material
from hydra.utils.crypto import derive_hex_key
from hydra.utils.net import public_ip


DEFAULT_PORT = 8443
DECOY_DIR = "/var/www/decoy-hysteria2"


class Hysteria2Plugin(BasePlugin):
    meta = PluginMeta(
        name="hysteria2",
        description="Hysteria2: QUIC-транспорт с Salamander obfuscation",
        category=PluginCategory.TRANSPORT,
        version="1.0.0",
        needs_domain=True,
    )

    def install(self) -> bool:
        from hydra.core.singbox import is_installed
        return is_installed()

    def uninstall(self) -> bool:
        return True

    def configure(self, state: AppState) -> ConfigFragment:
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

    def apply(self, state: AppState) -> bool:
        from hydra.core.decoy import ensure_decoy_site
        from hydra.utils.firewall import open_tcp
        ensure_decoy_site("hysteria2")
        open_tcp(443, "hysteria2-decoy")
        return True

    def on_user_add(self, user: User, state: AppState) -> None:
        user.credentials.setdefault("hysteria2", {})["password"] = self._password(user.uuid)

    def on_user_remove(self, user: User, state: AppState) -> None:
        pass

    def on_user_block(self, user: User, state: AppState) -> None:
        pass

    def generate_client_config(self, user: User, state: AppState) -> str:
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

    def client_link(self, user: User, state: AppState) -> str:
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

    def on_enable(self, state: AppState) -> None:
        ensure_tls_material(state, "hysteria2")
        ps = get_protocol(state, "hysteria2")
        ps.port = self._port(state)
        ps.config.setdefault("port", ps.port)
        ps.config.setdefault("obfs_password", derive_hex_key("hysteria2-obfs", ps.config["domain"]))
        ps.config.setdefault("congestion_mode", "bbr")
        from hydra.utils.firewall import open_udp
        open_udp(ps.port, "hysteria2")

    def on_disable(self, state: AppState) -> None:
        from hydra.utils.firewall import close_tcp, close_udp
        close_udp(self._port(state), "hysteria2")
        close_tcp(443, "hysteria2-decoy")

    def status(self) -> PluginStatus:
        from hydra.core.singbox import is_installed, is_running
        from hydra.core.state import load_state
        installed = is_installed()
        enabled = False
        port = DEFAULT_PORT
        state = None
        ps = None
        try:
            state = load_state()
            ps = state.protocols.get("hysteria2")
            enabled = bool(ps and ps.enabled)
            port = self._port(state)
        except Exception:
            pass
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

    def traffic(self, state: AppState) -> dict[str, int]:
        return {
            user.email: int(user.credentials.get("hysteria2", {}).get("traffic_used_bytes", 0))
            for user in state.users
            if int(user.credentials.get("hysteria2", {}).get("traffic_used_bytes", 0)) > 0
        }

    @staticmethod
    def _password(seed: str) -> str:
        return derive_hex_key("hysteria2-pass", seed)

    @staticmethod
    def _port(state: AppState) -> int:
        ps = state.protocols.get("hysteria2")
        port = int(ps.config.get("port", DEFAULT_PORT)) if ps else DEFAULT_PORT
        if not 1 <= port <= 65535:
            raise ValueError("Hysteria2 port must be between 1 and 65535")
        return port

    @staticmethod
    def _obfs_password(state: AppState) -> str:
        ps = state.protocols.get("hysteria2")
        if ps and ps.config.get("obfs_password"):
            return str(ps.config["obfs_password"])
        domain = str(ps.config.get("domain", "hydra")) if ps else "hydra"
        return derive_hex_key("hysteria2-obfs", domain)

    @staticmethod
    def _congestion_mode(state: AppState) -> str:
        ps = state.protocols.get("hysteria2")
        mode = str(ps.config.get("congestion_mode", "bbr")) if ps else "bbr"
        if mode not in {"bbr", "brutal"}:
            raise ValueError("Hysteria2 congestion mode must be bbr or brutal")
        return mode

    @staticmethod
    def _bandwidth(state: AppState, key: str) -> int:
        ps = state.protocols.get("hysteria2")
        value = int(ps.config.get(key, 100)) if ps else 100
        if not 1 <= value <= 100000:
            raise ValueError("Hysteria2 bandwidth must be between 1 and 100000 Mbps")
        return value

    def _commit_config(self, state: AppState, previous: dict) -> bool:
        from hydra.core.state import save_state
        from hydra.core import orchestrator

        ps = get_protocol(state, "hysteria2")
        save_state(state)
        try:
            applied = not ps.enabled or orchestrator.apply_config(state)
        except Exception:
            applied = False
        if applied:
            return True
        ps.config = previous
        ps.port = self._port(state)
        save_state(state)
        try:
            orchestrator.apply_config(state)
        except Exception:
            pass
        return False

    def set_domain(self, state: AppState, domain: str) -> bool:
        ps = get_protocol(state, "hysteria2")
        previous = copy.deepcopy(ps.config)
        normalized = domain.strip().lower().rstrip(".")
        if not normalized or "://" in normalized or any(ch.isspace() for ch in normalized):
            raise ValueError("Некорректный домен Hysteria2")
        if normalized == ps.config.get("domain"):
            return True
        ps.config["domain"] = normalized
        ps.config.pop("cert_file", None)
        ps.config.pop("key_file", None)
        try:
            ensure_tls_material(state, "hysteria2")
        except Exception:
            ps.config = previous
            raise
        return self._commit_config(state, previous)

    def set_port(self, state: AppState, port: int) -> bool:
        ps = get_protocol(state, "hysteria2")
        previous = copy.deepcopy(ps.config)
        old_port = self._port(state)
        try:
            ps.config["port"] = int(port)
            new_port = self._port(state)
        except (TypeError, ValueError):
            ps.config = previous
            raise
        if new_port == old_port:
            return True
        ps.port = new_port
        if ps.enabled:
            from hydra.utils.firewall import open_udp, close_udp
            open_udp(new_port, "hysteria2")
        if self._commit_config(state, previous):
            ps.port = new_port
            if ps.enabled:
                close_udp(old_port, "hysteria2")
            return True
        if ps.enabled:
            close_udp(new_port, "hysteria2")
        return False

    def set_congestion(self, state: AppState, mode: str, up_mbps: int = 100,
                       down_mbps: int = 100) -> bool:
        ps = get_protocol(state, "hysteria2")
        previous = copy.deepcopy(ps.config)
        ps.config["congestion_mode"] = mode
        if mode == "brutal":
            ps.config["up_mbps"] = int(up_mbps)
            ps.config["down_mbps"] = int(down_mbps)
        try:
            self._congestion_mode(state)
            if mode == "brutal":
                self._bandwidth(state, "up_mbps")
                self._bandwidth(state, "down_mbps")
        except Exception:
            ps.config = previous
            raise
        return self._commit_config(state, previous)

    def set_obfs_password(self, state: AppState, password: str) -> bool:
        value = password.strip()
        if len(value) < 16:
            raise ValueError("Salamander-пароль должен содержать минимум 16 символов")
        ps = get_protocol(state, "hysteria2")
        previous = copy.deepcopy(ps.config)
        ps.config["obfs_password"] = value
        return self._commit_config(state, previous)
