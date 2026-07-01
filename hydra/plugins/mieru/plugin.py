"""
hydra/plugins/mieru/plugin.py — Mieru: mTLS-туннель через sing-box-extended inbound.

Архитектура:
  • configure() — генерит mieru inbound dict для sing-box config.json
  • install/uninstall — no-op (sing-box-extended ставится ядром)
  • per-user: детерминированные креды через derive_key
  • Весь трафик проходит через sing-box → WARP/DNS/GeoIP автоматически
"""
from __future__ import annotations

import json

from hydra.plugins.base import (
    BasePlugin, PluginMeta, PluginStatus, PluginCategory, ConfigFragment,
)
from hydra.core.state import AppState, User
from hydra.utils.crypto import derive_key
from hydra.utils.net import public_ip

DEFAULT_PORT_START = 2012
DEFAULT_PORT_END = 2022
DEFAULT_PROTOCOL = "TCP"
DEFAULT_TRAFFIC_PATTERN = "GgQIARAK"


class MieruPlugin(BasePlugin):
    meta = PluginMeta(
        name="mieru",
        description="Mieru: mTLS-туннель с random padding (sing-box inbound)",
        category=PluginCategory.TRANSPORT,
        version="2.0.0",
        needs_domain=False,
    )

    # ═══════════════════════════════════════════════════════════════════
    #  Установка / удаление — no-op
    # ═══════════════════════════════════════════════════════════════════

    def install(self) -> bool:
        """Mieru работает через sing-box-extended. Отдельная установка не нужна."""
        from hydra.core.singbox import is_installed
        return is_installed()

    def uninstall(self) -> bool:
        """Удаление = отключение inbound. Sing-box не удаляется."""
        return True

    # ═══════════════════════════════════════════════════════════════════
    #  configure — генерит mieru inbound для sing-box config.json
    # ═══════════════════════════════════════════════════════════════════

    def configure(self, state: AppState) -> ConfigFragment:
        users = []
        for user in state.users:
            if user.blocked:
                continue
            users.append({
                "name": self._derive_username(user.uuid),
                "password": self._derive_password(user.uuid),
            })

        if not users:
            return ConfigFragment()

        inbound = {
            "type": "mieru",
            "tag": "mieru-in",
            "listen_port": DEFAULT_PORT_START,
            "transport": DEFAULT_PROTOCOL,
            "users": users,
            "traffic_pattern": DEFAULT_TRAFFIC_PATTERN,
        }

        # Диапазон портов
        if DEFAULT_PORT_START != DEFAULT_PORT_END:
            inbound["listen_ports"] = [
                f"{DEFAULT_PORT_START}-{DEFAULT_PORT_END}"
            ]

        return ConfigFragment(inbounds=[inbound])

    def apply(self, state: AppState) -> bool:
        """No-op: конфиг применяется через orchestrator.apply_config()."""
        return True

    # ═══════════════════════════════════════════════════════════════════
    #  Per-user
    # ═══════════════════════════════════════════════════════════════════

    def on_user_add(self, user: User, state: AppState) -> None:
        user.credentials.setdefault("mieru", {})
        user.credentials["mieru"]["username"] = self._derive_username(user.uuid)
        user.credentials["mieru"]["password"] = self._derive_password(user.uuid)

    def on_user_remove(self, user: User, state: AppState) -> None:
        pass  # Оркестратор пересоберёт конфиг без этого юзера

    def on_user_block(self, user: User, state: AppState) -> None:
        pass  # Оркестратор пересоберёт конфиг без blocked юзера

    # ═══════════════════════════════════════════════════════════════════
    #  Клиентский конфиг
    # ═══════════════════════════════════════════════════════════════════

    def generate_client_config(self, user: User, state: AppState) -> str:
        """Sing-box клиентский конфиг JSON."""
        username = self._derive_username(user.uuid)
        password = self._derive_password(user.uuid)
        server_ip = state.network.server_ip or public_ip()

        outbound = {
            "type": "mieru",
            "tag": f"mieru-{username}",
            "server": server_ip,
            "server_port": DEFAULT_PORT_START,
            "transport": DEFAULT_PROTOCOL,
            "username": username,
            "password": password,
            "multiplexing": "MULTIPLEXING_HIGH",
            "traffic_pattern": DEFAULT_TRAFFIC_PATTERN,
        }

        full = {
            "log": {"level": "info"},
            "dns": {
                "servers": [
                    {"tag": "google", "address": "8.8.8.8"},
                    {"tag": "local", "address": "1.1.1.1", "detour": "direct"},
                ],
            },
            "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
            "route": {"final": outbound["tag"]},
        }
        return json.dumps(full, indent=2)

    def client_link(self, user: User, state: AppState) -> str:
        """mierus:// ссылка для Karing."""
        import urllib.parse
        username = urllib.parse.quote(self._derive_username(user.uuid))
        password = urllib.parse.quote(self._derive_password(user.uuid))
        server_ip = state.network.server_ip or public_ip()

        return (
            f"mierus://{username}:{password}@{server_ip}"
            f"?port={DEFAULT_PORT_START}&protocol={DEFAULT_PROTOCOL}"
            f"&profile=default&mtu=1400&multiplexing=MULTIPLEXING_HIGH"
        )

    # ═══════════════════════════════════════════════════════════════════
    #  Статус
    # ═══════════════════════════════════════════════════════════════════

    def status(self) -> PluginStatus:
        from hydra.core.singbox import is_installed, is_running
        from hydra.core.state import load_state
        installed = is_installed()
        enabled = False
        try:
            state = load_state()
            ps = state.protocols.get("mieru")
            if ps:
                enabled = ps.enabled
        except Exception:
            pass
        return PluginStatus(
            installed=installed,
            enabled=enabled,
            running=installed and is_running() and enabled,
            port=DEFAULT_PORT_START,
        )

    def traffic(self, state: AppState) -> dict[str, int]:
        """TODO: получить трафик из sing-box API/логов."""
        return {}

    def connected_clients(self, state: AppState | None = None) -> list[dict]:
        """Получает список подключённых клиентов через утилиту ss."""
        import shutil
        import subprocess
        import time
        if not shutil.which("ss"):
            return []

        r = subprocess.run(
            ["ss", "-t", "-H", "-n", "state", "established"],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            return []

        clients = []
        now_ts = int(time.time())

        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue

            local_addr = parts[3]
            remote_addr = parts[4]

            local_port_str = local_addr.split(":")[-1]
            if not local_port_str.isdigit():
                continue
            local_port = int(local_port_str)

            if DEFAULT_PORT_START <= local_port <= DEFAULT_PORT_END:
                remote_parts = remote_addr.split(":")
                remote_ip = ":".join(remote_parts[:-1]).strip("[]")

                clients.append({
                    "online": True,
                    "email": remote_ip,
                    "rx": 0,
                    "tx": 0,
                    "last_handshake": now_ts,
                })
        return clients

    # ═══════════════════════════════════════════════════════════════════
    #  Управление
    # ═══════════════════════════════════════════════════════════════════

    def on_enable(self, state: AppState) -> None:
        from hydra.utils.firewall import open_range
        open_range("tcp", DEFAULT_PORT_START, DEFAULT_PORT_END, "mieru")

    def on_disable(self, state: AppState) -> None:
        from hydra.utils.firewall import close_range
        close_range("tcp", DEFAULT_PORT_START, DEFAULT_PORT_END)

    # ═══════════════════════════════════════════════════════════════════
    #  Внутренние помощники
    # ═══════════════════════════════════════════════════════════════════

    @staticmethod
    def _derive_username(uuid: str) -> str:
        return "u" + derive_key("mieru-user", uuid)[:8]

    @staticmethod
    def _derive_password(uuid: str) -> str:
        return derive_key("mieru-pass", uuid)
