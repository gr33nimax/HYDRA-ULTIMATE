"""hydra/plugins/vkturn/plugin.py — VK Turn Proxy (FreeTurn): UDP-туннель через TURN-серверы ВК.

Контракт v2 — TRANSPORT-плагин, single-инстанс, не per-user:
  • configure() — читает listen/target порты из state.
  • apply() — пишет systemd-сервис, перезапускает.
  • client_link — возвращает инструкцию для FreeTurn Android.
  • nft_tproxy_ports=[56000] — порт для nftables TPROXY.
"""
from __future__ import annotations

import json
import platform
import shutil
import subprocess
import time
import urllib.request
from pathlib import Path

from hydra.plugins.base import BasePlugin, PluginMeta, PluginStatus, PluginCategory, ConfigFragment
from hydra.core.state import AppState, User
from hydra.utils.net import public_ip

BIN_DIR = Path("/opt/vk-turn-proxy")
BIN_PATH = BIN_DIR / "server"
SERVICE_FILE = Path("/etc/systemd/system/vk-turn-proxy.service")
SERVICE_NAME = "vk-turn-proxy"

DEFAULT_LISTEN_PORT = 56000
DEFAULT_TARGET_PORT = 51820

GITHUB_RELEASES_URL = (
    "https://github.com/cacggghp/vk-turn-proxy/releases/latest/download/"
    "server-linux-amd64"
)


class VkTurnPlugin(BasePlugin):
    meta = PluginMeta(
        name="vkturn",
        description="VK Turn Proxy (FreeTurn): UDP-туннель через TURN-серверы ВК",
        category=PluginCategory.TRANSPORT,
        version="2.0.0",
        needs_domain=False,
    )

    def __init__(self):
        self._pending_cfg: dict | None = None

    # ═════════════════════════════════════════════════════════════════════
    #  Установка / удаление
    # ═════════════════════════════════════════════════════════════════════

    def install(self) -> bool:
        if self._installed():
            return True

        print("  Скачиваю vk-turn-proxy...")
        if not self._download_binary():
            print("  Не удалось установить vk-turn-proxy.")
            return False

        return self._installed()

    def uninstall(self) -> bool:
        subprocess.run(["systemctl", "stop", SERVICE_NAME], capture_output=True)
        subprocess.run(["systemctl", "disable", SERVICE_NAME], capture_output=True)
        if SERVICE_FILE.exists():
            SERVICE_FILE.unlink()
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
        subprocess.run(["systemctl", "reset-failed"], capture_output=True)

        if BIN_DIR.exists():
            shutil.rmtree(BIN_DIR, ignore_errors=True)
        return True

    # ═════════════════════════════════════════════════════════════════════
    #  configure — чистая: собирает параметры сервиса в памяти
    # ═════════════════════════════════════════════════════════════════════

    def configure(self, state: AppState) -> ConfigFragment:
        ps = state.protocols.get("vkturn")
        cfg = ps.config if ps and ps.config else {}

        listen_port = cfg.get("listen_port", DEFAULT_LISTEN_PORT)
        target_port = cfg.get("target_port", DEFAULT_TARGET_PORT)
        target_type = cfg.get("target_type", "wireguard")

        self._pending_cfg = {
            "listen_port": listen_port,
            "target_port": target_port,
            "target_type": target_type,
        }

        return ConfigFragment(
            nft_tproxy_ports=[listen_port],
        )

    def apply(self, state: AppState) -> bool:
        if not self._pending_cfg:
            return False

        listen_port = self._pending_cfg["listen_port"]
        target_port = self._pending_cfg["target_port"]

        BIN_DIR.mkdir(parents=True, exist_ok=True)
        self._write_service(listen_port, target_port)

        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
        subprocess.run(["systemctl", "reload-or-restart", SERVICE_NAME], capture_output=True)
        time.sleep(2)
        return True

    # ═════════════════════════════════════════════════════════════════════
    #  Per-user (no-op — single instance, не per-user)
    # ═════════════════════════════════════════════════════════════════════

    def on_user_add(self, user: User, state: AppState) -> None:
        pass

    def on_user_remove(self, user: User, state: AppState) -> None:
        pass

    def on_user_block(self, user: User, state: AppState) -> None:
        pass

    # ═════════════════════════════════════════════════════════════════════
    #  Клиентский конфиг
    # ═════════════════════════════════════════════════════════════════════

    def generate_client_config(self, user: User, state: AppState) -> str:
        ps = state.protocols.get("vkturn")
        cfg = ps.config if ps and ps.config else {}
        listen_port = cfg.get("listen_port", DEFAULT_LISTEN_PORT)
        target_type = cfg.get("target_type", "wireguard")
        server_ip = state.network.server_ip or public_ip()

        config = {
            "protocol": "vkturn",
            "server": server_ip,
            "port": listen_port,
            "target_type": target_type,
            "client": "FreeTurn (Android) — github.com/samosvalishe/turn-proxy-android",
            "instructions": (
                f"1. Установите FreeTurn на Android\n"
                f"2. Сервер: {server_ip}\n"
                f"3. Порт: {listen_port}\n"
                f"4. Тип: {target_type}\n"
            ),
        }
        return json.dumps(config, indent=2)

    def client_link(self, user: User, state: AppState) -> str:
        cfg = {}
        ps = state.protocols.get("vkturn")
        if ps and ps.config:
            cfg = ps.config
        listen_port = cfg.get("listen_port", DEFAULT_LISTEN_PORT)
        server_ip = state.network.server_ip or public_ip()
        return f"freeturn://{server_ip}:{listen_port}"

    # ═════════════════════════════════════════════════════════════════════
    #  Статус / трафик
    # ═════════════════════════════════════════════════════════════════════

    def status(self) -> PluginStatus:
        installed = self._installed()
        running = False
        listen_port = DEFAULT_LISTEN_PORT
        if installed:
            r = subprocess.run(
                ["systemctl", "is-active", SERVICE_NAME],
                capture_output=True, text=True,
            )
            running = r.stdout.strip() == "active"

        return PluginStatus(
            installed=installed,
            enabled=SERVICE_FILE.exists(),
            running=running,
            port=listen_port,
        )

    def traffic(self, state: AppState) -> dict[str, int]:
        return {}

    def connected_clients(self) -> list[dict]:
        return []

    # ═════════════════════════════════════════════════════════════════════
    #  Управление сервисом
    # ═════════════════════════════════════════════════════════════════════

    def on_enable(self, state: AppState) -> None:
        self.configure(state)
        self.apply(state)
        r = subprocess.run(
            ["systemctl", "is-active", SERVICE_NAME],
            capture_output=True, text=True,
        )
        if r.stdout.strip() != "active":
            subprocess.run(["systemctl", "enable", "--now", SERVICE_NAME], capture_output=True)

    def on_disable(self, state: AppState) -> None:
        subprocess.run(["systemctl", "stop", SERVICE_NAME], capture_output=True)

    # ═════════════════════════════════════════════════════════════════════
    #  Внутренние помощники
    # ═════════════════════════════════════════════════════════════════════

    @staticmethod
    def _installed() -> bool:
        return BIN_PATH.exists()

    def _download_binary(self) -> bool:
        import tempfile
        tmp = Path(tempfile.mkdtemp())
        tmp_bin = tmp / "server-linux-amd64"
        try:
            urllib.request.urlretrieve(GITHUB_RELEASES_URL, str(tmp_bin))
            BIN_DIR.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(tmp_bin), str(BIN_PATH))
            BIN_PATH.chmod(0o755)
            return True
        except Exception as e:
            print(f"  Ошибка загрузки: {e}")
            return False
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    @staticmethod
    def _write_service(listen_port: int, target_port: int) -> None:
        SERVICE_FILE.write_text(
            "[Unit]\n"
            "Description=VK Turn Proxy — TURN tunnel to WireGuard/Hysteria2\n"
            "After=network-online.target\n"
            "Wants=network-online.target\n"
            "\n"
            "[Service]\n"
            "Type=simple\n"
            f"WorkingDirectory={BIN_DIR}\n"
            f"ExecStart={BIN_PATH} "
            f"-listen 0.0.0.0:{listen_port} "
            f"-connect 127.0.0.1:{target_port}\n"
            "Restart=always\n"
            "RestartSec=5\n"
            "NoNewPrivileges=true\n"
            "\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n"
        )

    @staticmethod
    def _open_port(port: int) -> None:
        subprocess.run(
            ["iptables", "-t", "filter", "-I", "INPUT", "1",
             "-p", "udp", "--dport", str(port), "-j", "ACCEPT"],
            capture_output=True,
        )

    @staticmethod
    def _close_port(port: int) -> None:
        for _ in range(5):
            subprocess.run(
                ["iptables", "-t", "filter", "-D", "INPUT",
                 "-p", "udp", "--dport", str(port), "-j", "ACCEPT"],
                capture_output=True,
            )
