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
                "name": self._derive_username(user),
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
            "traffic_pattern": self._get_traffic_pattern(state),
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
        user.credentials["mieru"]["username"] = self._derive_username(user)
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
        username = self._derive_username(user)
        password = self._derive_password(user.uuid)
        server_ip = state.network.server_ip or public_ip()
        pattern = self._get_traffic_pattern(state)

        outbound = {
            "type": "mieru",
            "tag": f"mieru-{username}",
            "server": server_ip,
            "server_port": DEFAULT_PORT_START,
            "transport": DEFAULT_PROTOCOL,
            "username": username,
            "password": password,
            "multiplexing": "MULTIPLEXING_HIGH",
            "traffic_pattern": pattern,
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
        """mierus:// ссылка для Karing и Throne."""
        import urllib.parse
        username = urllib.parse.quote(self._derive_username(user), safe="")
        password = urllib.parse.quote(self._derive_password(user.uuid), safe="")
        server_ip = state.network.server_ip or public_ip()
        pattern = self._get_traffic_pattern(state)

        return (
            f"mierus://{username}:{password}@{server_ip}"
            f"?profile=default&port={DEFAULT_PORT_START}&protocol={DEFAULT_PROTOCOL}"
            f"&port={DEFAULT_PORT_START}-{DEFAULT_PORT_END}&protocol={DEFAULT_PROTOCOL}"
            f"&multiplexing=MULTIPLEXING_HIGH"
            f"&traffic-pattern={urllib.parse.quote(pattern, safe='')}"
        )

    # ═══════════════════════════════════════════════════════════════════
    #  Статус
    # ═══════════════════════════════════════════════════════════════════

    def _get_total_traffic(self) -> int:
        """Считает суммарный трафик на портах Mieru через iptables accounting."""
        import subprocess
        total_bytes = 0
        for chain in ("INPUT", "OUTPUT"):
            r = subprocess.run(
                ["iptables", "-t", "filter", "-L", chain, "-n", "-v", "-x"],
                capture_output=True, text=True,
            )
            if r.returncode != 0:
                continue
            for line in r.stdout.splitlines():
                if "mieru-" in line:
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        total_bytes += int(parts[1])
        return total_bytes

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

        info = {}
        if installed and enabled:
            try:
                total = self._get_total_traffic()
                size = float(total)
                for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
                    if size < 1024.0:
                        formatted = f"{size:.2f} {unit}" if unit != 'B' else f"{int(size)} B"
                        break
                    size /= 1024.0
                else:
                    formatted = f"{size:.2f} PB"
                info["Общий трафик"] = formatted
            except Exception:
                pass

        return PluginStatus(
            installed=installed,
            enabled=enabled,
            running=installed and is_running() and enabled,
            port=DEFAULT_PORT_START,
            info=info,
        )

    def traffic(self, state: AppState) -> dict[str, int]:
        res = {}
        for u in state.users:
            t = u.credentials.get("mieru", {}).get("traffic_used_bytes", 0)
            if t > 0:
                res[u.email] = t
        return res

    def connected_clients(self, state: AppState | None = None) -> list[dict]:
        """Получает список подключённых клиентов через утилиту ss с группировкой по IP."""
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

        ip_counts = {}
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue

            local_addr = parts[2]
            remote_addr = parts[3]

            local_port_str = local_addr.split(":")[-1]
            if not local_port_str.isdigit():
                continue
            local_port = int(local_port_str)

            if DEFAULT_PORT_START <= local_port <= DEFAULT_PORT_END:
                remote_parts = remote_addr.split(":")
                remote_ip = ":".join(remote_parts[:-1]).strip("[]")
                ip_counts[remote_ip] = ip_counts.get(remote_ip, 0) + 1

        # Считаем rx/tx из iptables для вывода в сводке
        rx_bytes = 0
        tx_bytes = 0
        r_rx = subprocess.run(["iptables", "-t", "filter", "-L", "INPUT", "-n", "-v", "-x"], capture_output=True, text=True)
        if r_rx.returncode == 0:
            for line in r_rx.stdout.splitlines():
                if "mieru-rx-" in line:
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        rx_bytes += int(parts[1])
        r_tx = subprocess.run(["iptables", "-t", "filter", "-L", "OUTPUT", "-n", "-v", "-x"], capture_output=True, text=True)
        if r_tx.returncode == 0:
            for line in r_tx.stdout.splitlines():
                if "mieru-tx-" in line:
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        tx_bytes += int(parts[1])

        clients = []
        now_ts = int(time.time())
        n_clients = len(ip_counts)

        for remote_ip, count in ip_counts.items():
            clients.append({
                "online": True,
                "email": f"{remote_ip} ({count} TCP)",
                "rx": rx_bytes // n_clients if n_clients > 0 else 0,
                "tx": tx_bytes // n_clients if n_clients > 0 else 0,
                "last_handshake": now_ts,
            })
        return clients

    # ═══════════════════════════════════════════════════════════════════
    #  Управление
    # ═══════════════════════════════════════════════════════════════════

    def on_enable(self, state: AppState) -> None:
        from hydra.utils.firewall import open_range
        open_range("tcp", DEFAULT_PORT_START, DEFAULT_PORT_END, "mieru")
        
        # Добавляем iptables правила для подсчёта трафика
        import subprocess
        self._remove_iptables_rules()
        for p in range(DEFAULT_PORT_START, DEFAULT_PORT_END + 1):
            subprocess.run([
                "iptables", "-I", "INPUT", "1", "-p", "tcp", "--dport", str(p),
                "-m", "comment", "--comment", f"mieru-rx-{p}"
            ], capture_output=True)
            subprocess.run([
                "iptables", "-I", "OUTPUT", "1", "-p", "tcp", "--sport", str(p),
                "-m", "comment", "--comment", f"mieru-tx-{p}"
            ], capture_output=True)

    def on_disable(self, state: AppState) -> None:
        from hydra.utils.firewall import close_range
        close_range("tcp", DEFAULT_PORT_START, DEFAULT_PORT_END)
        self._remove_iptables_rules()

    # ═══════════════════════════════════════════════════════════════════
    #  Внутренние помощники
    # ═══════════════════════════════════════════════════════════════════

    def _remove_iptables_rules(self) -> None:
        import subprocess
        for chain in ("INPUT", "OUTPUT"):
            r = subprocess.run(["iptables", "-S", chain], capture_output=True, text=True)
            if r.returncode != 0:
                continue
            for line in r.stdout.splitlines():
                if "mieru-" in line:
                    parts = line.split()
                    if parts[0] == "-A":
                        parts[0] = "-D"
                        subprocess.run(["iptables"] + parts, capture_output=True)

    @staticmethod
    def _derive_username(user: User) -> str:
        return user.email

    @staticmethod
    def _derive_password(uuid: str) -> str:
        return derive_key("mieru-pass", uuid)

    def _get_traffic_pattern(self, state: AppState) -> str:
        """Возвращает base64 traffic_pattern для текущего пресета."""
        from hydra.plugins.mieru.presets import get_preset_base64
        ps = state.protocols.get("mieru")
        preset_name = "basic"
        if ps and ps.config and "traffic_preset" in ps.config:
            preset_name = ps.config["traffic_preset"]
        return get_preset_base64(preset_name)

    def get_current_preset(self, state: AppState) -> str:
        """Возвращает имя текущего пресета обфускации."""
        ps = state.protocols.get("mieru")
        if ps and ps.config and "traffic_preset" in ps.config:
            return ps.config["traffic_preset"]
        return "basic"


    def set_preset(self, state: AppState, preset_name: str) -> bool:
        """Устанавливает пресет обфускации и применяет конфиг."""
        from hydra.plugins.mieru.presets import PRESETS
        if preset_name not in PRESETS:
            return False
        
        from hydra.core.state import get_protocol, save_state
        ps = get_protocol(state, "mieru")
        ps.config["traffic_preset"] = preset_name
        save_state(state)
        
        from hydra.core import orchestrator
        return orchestrator.apply_config(state)
