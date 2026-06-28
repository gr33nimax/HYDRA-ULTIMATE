"""
hydra/plugins/mieru/plugin.py — Mieru (mTLS + random padding).

Mieru — mTLS-прокси с шумовым заполнением пакетов.
Работает как внешний процесс (mita), в Sing-Box не интегрируется напрямую.
Вместо этого генерируем Sing-Box конфиг для клиентов с mieru outbound.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from hydra.plugins.base import BasePlugin, PluginMeta, PluginStatus, ConfigFragment
from hydra.core.state import AppState

MIERU_BIN = Path("/usr/local/bin/mita")
MIERU_CONFIG = Path("/etc/mita/server.conf")
MIERU_PORT = 8444


class MieruPlugin(BasePlugin):
    meta = PluginMeta(
        name="mieru",
        description="Mieru: mTLS + random padding — обход статистического анализа",
        version="1.0.0",
    )

    def install(self) -> bool:
        if MIERU_BIN.exists():
            return True

        r = subprocess.run(
            [
                "bash", "-c",
                "curl -fsSL https://github.com/enfein/mieru/releases/latest/download/"
                "mita_amd64.deb -o /tmp/mita.deb && "
                "dpkg -i /tmp/mita.deb && rm /tmp/mita.deb",
            ],
            capture_output=True, text=True, timeout=120,
        )
        return r.returncode == 0

    def uninstall(self) -> bool:
        subprocess.run(["systemctl", "stop", "mita"], capture_output=True)
        MIERU_CONFIG.unlink(missing_ok=True)
        return True

    def configure(self, state: AppState) -> ConfigFragment:
        """Генерирует конфиг Mieru и фрагмент для Sing-Box клиентского экспорта."""
        users = [u for u in state.users if not u.blocked]

        # Конфиг mita (серверная часть)
        mita_cfg = {
            "port": MIERU_PORT,
            "protocol": "TCP",
            "users": [
                {"name": u.email, "password": u.uuid[:16]}
                for u in users
            ],
            "mtls": True,
            "padding": {"maxLength": 1500},
        }
        MIERU_CONFIG.parent.mkdir(parents=True, exist_ok=True)
        MIERU_CONFIG.write_text(json.dumps(mita_cfg, indent=2))

        # Sing-Box inbound для Mieru (проксирует локально)
        inbound = {
            "type": "http",
            "tag": "mieru-internal",
            "listen": "127.0.0.1",
            "listen_port": MIERU_PORT + 1000,
        }

        return ConfigFragment(
            inbounds=[inbound],
        )

    def status(self) -> PluginStatus:
        installed = MIERU_BIN.exists()
        running = False
        if installed:
            r = subprocess.run(
                ["systemctl", "is-active", "--quiet", "mita"],
            )
            running = r.returncode == 0

        return PluginStatus(
            installed=installed,
            enabled=bool(MIERU_CONFIG.exists()),
            running=running,
            port=MIERU_PORT,
        )

    def traffic(self) -> dict[str, int]:
        return {}

    def on_enable(self, state: AppState) -> None:
        self.configure(state)
        subprocess.run(["systemctl", "start", "mita"], capture_output=True)

    def on_disable(self, state: AppState) -> None:
        subprocess.run(["systemctl", "stop", "mita"], capture_output=True)
