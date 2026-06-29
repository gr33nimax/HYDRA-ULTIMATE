"""hydra/plugins/slipgate/plugin.py — SlipGate: DNS-туннели (DNSTT/NoizDNS/Slipstream/VayDNS).

Контракт v2 — TRANSPORT-плагин, single-инстанс, не per-user:
  • configure() — возвращает nft_tproxy_ports=[53] для заворота DNS-трафика.
  • apply() — no-op (slipgate управляет туннелями сам).
  • install — официальный install.sh от anonvector/slipgate.
  • client_link — slipnet:// URI для клиента SlipNet.
  • needs_domain — True (NS-делегирование для DNS-туннелей).
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from hydra.plugins.base import BasePlugin, PluginMeta, PluginStatus, PluginCategory, ConfigFragment
from hydra.core.state import AppState, User
from hydra.utils.net import public_ip

SLIPGATE_BIN = Path("/usr/local/bin/slipgate")
SLIPGATE_CFG_DIR = Path("/etc/slipgate")
INSTALL_SCRIPT_URL = "https://raw.githubusercontent.com/anonvector/slipgate/main/install.sh"
GITHUB_REPO = "anonvector/slipgate"

DNS_PORT = 53


class SlipGatePlugin(BasePlugin):
    meta = PluginMeta(
        name="slipgate",
        description="SlipGate: DNS-туннели (DNSTT/NoizDNS/Slipstream/VayDNS) — обход полных блокировок",
        category=PluginCategory.TRANSPORT,
        version="2.0.0",
        needs_domain=True,
    )

    # ═════════════════════════════════════════════════════════════════════
    #  Установка / удаление
    # ═════════════════════════════════════════════════════════════════════

    def install(self) -> bool:
        if self._installed():
            return True

        if not shutil.which("curl"):
            print("  curl не найден. Установите: apt install curl")
            return False

        print("  Запускаю официальный установщик SlipGate...")
        r = subprocess.run(
            ["bash", "-c", f"curl -fsSL {INSTALL_SCRIPT_URL} | sudo bash"],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            print(f"  Ошибка установки: {(r.stderr or r.stdout or '')[:300]}")
            return False

        return self._installed()

    def uninstall(self) -> bool:
        if not self._installed():
            return True

        r = subprocess.run(
            [str(SLIPGATE_BIN), "uninstall"],
            capture_output=True, text=True, timeout=60,
        )
        if r.returncode != 0:
            print(f"  Ошибка удаления: {(r.stderr or r.stdout or '')[:300]}")
            return False

        if SLIPGATE_CFG_DIR.exists():
            shutil.rmtree(SLIPGATE_CFG_DIR, ignore_errors=True)
        return True

    # ═════════════════════════════════════════════════════════════════════
    #  configure — чистая: возвращает nft_tproxy_ports для DNS (53/udp)
    # ═════════════════════════════════════════════════════════════════════

    def configure(self, state: AppState) -> ConfigFragment:
        if not state.network.domain:
            return ConfigFragment()

        return ConfigFragment(
            nft_tproxy_ports=[DNS_PORT],
        )

    def apply(self, state: AppState) -> bool:
        return True

    # ═════════════════════════════════════════════════════════════════════
    #  Per-user (no-op — single instance, tunnels managed via slipgate TUI)
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
        if not state.network.domain:
            return ""
        link = self.client_link(user, state)
        if not link:
            return ""
        return json.dumps({
            "protocol": "slipgate",
            "link": link,
            "client": "SlipNet (Android) — github.com/anonvector/SlipNet",
            "instructions": (
                "1. Установите SlipNet на Android\n"
                "2. Импортируйте ссылку ниже\n"
                "3. Подключитесь\n"
            ),
        }, indent=2)

    def client_link(self, user: User, state: AppState) -> str:
        if not state.network.domain:
            return ""
        server_ip = state.network.server_ip or public_ip()
        return f"slipnet://{server_ip}?domain={state.network.domain}"

    # ═════════════════════════════════════════════════════════════════════
    #  Статус / трафик
    # ═════════════════════════════════════════════════════════════════════

    def status(self) -> PluginStatus:
        installed = self._installed()
        running = False
        if installed:
            r = subprocess.run(
                [str(SLIPGATE_BIN), "tunnel", "status"],
                capture_output=True, text=True, timeout=15,
            )
            running = r.returncode == 0

        return PluginStatus(
            installed=installed,
            enabled=SLIPGATE_CFG_DIR.exists(),
            running=running,
            port=DNS_PORT,
        )

    def traffic(self, state: AppState) -> dict[str, int]:
        return {}

    def connected_clients(self) -> list[dict]:
        if not self._installed():
            return []
        r = subprocess.run(
            [str(SLIPGATE_BIN), "tunnel", "status"],
            capture_output=True, text=True, timeout=15,
        )
        if r.returncode != 0:
            return []
        tunnels = [line.strip() for line in r.stdout.splitlines()
                   if line.strip() and not line.startswith("#") and not line.startswith("─")]
        return [{"tunnel": t} for t in tunnels]

    # ═════════════════════════════════════════════════════════════════════
    #  Управление сервисом
    # ═════════════════════════════════════════════════════════════════════

    def on_enable(self, state: AppState) -> None:
        pass

    def on_disable(self, state: AppState) -> None:
        pass

    # ═════════════════════════════════════════════════════════════════════
    #  Внутренние помощники
    # ═════════════════════════════════════════════════════════════════════

    @staticmethod
    def _installed() -> bool:
        return SLIPGATE_BIN.exists() or shutil.which("slipgate") is not None
