"""
hydra/plugins/amneziawg/plugin.py — AmneziaWG 2.0 через wiresock.

Архитектура:
  Клиент ──→ AWG (kernel, порт X) ──→ сетевая маршрутизация ──→ интернет
                                          │
                                    Sing-Box host-level роутинг
                                    (WARP, DNS, GeoIP через iptables)

Установка: wiresock/amneziawg-install (https://github.com/wiresock/amneziawg-install)
— ставит kernel-модуль amneziawg, НЕ использует Docker.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
from pathlib import Path
from typing import Optional

from hydra.plugins.base import BasePlugin, PluginMeta, PluginStatus, ConfigFragment
from hydra.core.state import AppState

AWG_INSTALL_SCRIPT = "https://raw.githubusercontent.com/wiresock/amneziawg-install/main/install.sh"
AWG_BIN = Path("/usr/bin/awg")
AWG_QUICK = Path("/usr/bin/awg-quick")
AWG_CONF = Path("/etc/amnezia/awg0.conf")
AWG_PORT = 51820
AWG_INTERFACE = "awg0"
AWG_NETWORK = "10.8.20.0/24"
AWG_SERVER_IP = "10.8.20.1"

STATE_FILE = Path("/var/lib/hydra/awg_state.json")


class AmneziaWGPlugin(BasePlugin):
    meta = PluginMeta(
        name="amneziawg",
        description="AmneziaWG 2.0: WireGuard с обфускацией пакетов (kernel-модуль)",
        version="1.0.0",
    )

    # ═════════════════════════════════════════════════════════════════════
    #  Установка
    # ═════════════════════════════════════════════════════════════════════

    def install(self) -> bool:
        """Устанавливает AmneziaWG kernel-модуль через wiresock/amneziawg-install."""
        if AWG_BIN.exists():
            return True

        r = subprocess.run(
            ["bash", "-c", f"curl -fsSL {AWG_INSTALL_SCRIPT} | bash"],
            capture_output=True, text=True, timeout=180,
        )
        if r.returncode != 0:
            return False

        # Проверяем, что модуль загружен
        lsmod = subprocess.run(
            ["lsmod"], capture_output=True, text=True,
        )
        if "amneziawg" not in lsmod.stdout:
            subprocess.run(["modprobe", "amneziawg"], capture_output=True)

        return AWG_BIN.exists()

    def uninstall(self) -> bool:
        """Останавливает AWG, удаляет интерфейс и конфиг."""
        subprocess.run(
            ["awg-quick", "down", str(AWG_CONF)],
            capture_output=True,
        )
        AWG_CONF.unlink(missing_ok=True)
        return True

    # ═════════════════════════════════════════════════════════════════════
    #  Конфигурация
    # ═════════════════════════════════════════════════════════════════════

    def configure(self, state: AppState) -> ConfigFragment:
        """Генерирует конфиг AWG и создаёт пиры для каждого пользователя."""
        server_key = self._load_or_generate_keys()
        users = [u for u in state.users if not u.blocked]

        conf = self._generate_awg_conf(server_key, users, state)
        AWG_CONF.parent.mkdir(parents=True, exist_ok=True)
        AWG_CONF.write_text(conf)

        # Sing-Box фрагмент: маршрутизация трафика с AWG-интерфейса
        return ConfigFragment(
            route_rules=[
                {
                    "inbound": [f"awg-{u.email}" for u in users],
                    "outbound": "direct",
                }
            ] if users else [],
        )

    def _load_or_generate_keys(self) -> dict:
        """Загружает или генерирует ключевую пару сервера."""
        if STATE_FILE.exists():
            try:
                return json.loads(STATE_FILE.read_text())
            except Exception:
                pass

        private = subprocess.run(
            ["awg", "genkey"], capture_output=True, text=True,
        ).stdout.strip()
        public = subprocess.run(
            ["awg", "pubkey"],
            input=private, capture_output=True, text=True,
        ).stdout.strip()

        keys = {"private": private, "public": public}
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps(keys, indent=2))
        return keys

    def _generate_awg_conf(self, server_key: dict, users: list, state: AppState) -> str:
        """Генерирует конфигурационный файл AWG."""
        lines = [
            "[Interface]",
            f"PrivateKey = {server_key['private']}",
            f"Address = {AWG_SERVER_IP}/24",
            f"ListenPort = {AWG_PORT}",
            "",
            "# Обфускация (AmneziaWG)",
            "Jc = 4",
            "Jmin = 40",
            "Jmax = 70",
            "S1 = 8",
            "S2 = 72",
            "H1 = 1748384502",
            "H2 = 410655843",
            "H3 = 3426724947",
            "H4 = 4202318234",
            "",
        ]

        # Добавляем пиров (клиентов)
        for idx, user in enumerate(users):
            peer_ip = f"10.8.20.{idx + 2}"
            # Генерируем ключи клиента на основе UUID для детерминизма
            client_private = self._derive_key(user.uuid)
            client_public = subprocess.run(
                ["awg", "pubkey"],
                input=client_private, capture_output=True, text=True,
            ).stdout.strip()

            lines += [
                f"# Peer: {user.email}",
                "[Peer]",
                f"PublicKey = {client_public}",
                f"AllowedIPs = {peer_ip}/32",
                "",
            ]

        return "\n".join(lines)

    def _derive_key(self, seed: str) -> str:
        """Детерминированно выводит WireGuard-ключ из UUID пользователя."""
        import hashlib
        import base64
        h = hashlib.sha256(seed.encode()).digest()
        return base64.b64encode(h[:32]).decode()

    # ═════════════════════════════════════════════════════════════════════
    #  Статус / трафик
    # ═════════════════════════════════════════════════════════════════════

    def status(self) -> PluginStatus:
        installed = AWG_BIN.exists()
        running = False
        if installed:
            r = subprocess.run(
                ["ip", "link", "show", AWG_INTERFACE],
                capture_output=True,
            )
            running = r.returncode == 0

        return PluginStatus(
            installed=installed,
            enabled=bool(AWG_CONF.exists()),
            running=running,
            port=AWG_PORT,
        )

    def traffic(self) -> dict[str, int]:
        """Считывает трафик с AWG-интерфейса (awg show)."""
        if not AWG_CONF.exists():
            return {}

        r = subprocess.run(
            ["awg", "show", AWG_INTERFACE, "transfer"],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            return {}

        traffic: dict[str, int] = {}
        # awg show transfer выводит: public_key \t rx_bytes \t tx_bytes
        for line in r.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) >= 3:
                traffic[parts[0]] = int(parts[1]) + int(parts[2])
        return traffic

    # ═════════════════════════════════════════════════════════════════════
    #  Управление
    # ═════════════════════════════════════════════════════════════════════

    def on_enable(self, state: AppState) -> None:
        self.configure(state)
        subprocess.run(
            ["awg-quick", "up", str(AWG_CONF)],
            capture_output=True,
        )

    def on_disable(self, state: AppState) -> None:
        subprocess.run(
            ["awg-quick", "down", str(AWG_CONF)],
            capture_output=True,
        )
