"""
hydra/plugins/warp/plugin.py — Cloudflare WARP.

WARP обеспечивает исходящий трафик через сеть Cloudflare.
Реализован как WireGuard-интерфейс (wgcf) + Sing-Box outbound с route-правилами.

Архитектура:
  Любой inbound → Sing-Box routing → WARP outbound (wgcf) → Cloudflare → интернет

Маршрутизация:
  - WARP-домены (openai.com, claude.ai и др.) → через WARP
  - Всё остальное → direct
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from hydra.plugins.base import BasePlugin, PluginMeta, PluginStatus, ConfigFragment
from hydra.core.state import AppState

WGCF_BIN = Path("/usr/local/bin/wgcf")
WGCF_PROFILE = Path("/etc/wireguard/wgcf-profile.conf")
WARP_INTERFACE = "wgcf"
WARP_DOMAINS = [
    "openai.com",
    "claude.ai",
    "anthropic.com",
    "chatgpt.com",
    "sora.com",
    "gemini.google.com",
    "bard.google.com",
]


class WarpPlugin(BasePlugin):
    meta = PluginMeta(
        name="warp",
        description="Cloudflare WARP: туннелирование через сеть Cloudflare",
        version="1.0.0",
    )

    def install(self) -> bool:
        if WGCF_BIN.exists():
            return True

        r = subprocess.run(
            [
                "bash", "-c",
                "curl -fsSL https://raw.githubusercontent.com/ViRb3/wgcf/master/wgcf_install.sh | bash",
            ],
            capture_output=True, text=True, timeout=60,
        )
        if r.returncode != 0:
            return False

        # Регистрация и генерация профиля
        subprocess.run(
            [str(WGCF_BIN), "register"],
            capture_output=True, timeout=30,
        )
        subprocess.run(
            [str(WGCF_BIN), "generate"],
            capture_output=True, timeout=30,
        )

        # Перемещаем профиль
        profile = Path("wgcf-profile.conf")
        if profile.exists():
            WGCF_PROFILE.parent.mkdir(parents=True, exist_ok=True)
            profile.rename(WGCF_PROFILE)

        return WGCF_PROFILE.exists()

    def uninstall(self) -> bool:
        subprocess.run(
            ["wg-quick", "down", str(WGCF_PROFILE)],
            capture_output=True,
        )
        return True

    def _load_warp_config(self) -> dict | None:
        """Извлекает ключи из wgcf-профиля."""
        if not WGCF_PROFILE.exists():
            return None

        text = WGCF_PROFILE.read_text()
        private = re.search(r"PrivateKey\s*=\s*(\S+)", text)
        address = re.search(r"Address\s*=\s*(\S+)", text)

        if not private:
            return None

        return {
            "private_key": private.group(1),
            "address": address.group(1) if address else "172.16.0.2/32",
        }

    def configure(self, state: AppState) -> ConfigFragment:
        """Генерирует Sing-Box outbound для WARP и route-правила."""
        warp_cfg = self._load_warp_config()
        if not warp_cfg:
            return ConfigFragment()

        # WARP outbound
        outbound = {
            "type": "wireguard",
            "tag": "warp",
            "server": "162.159.193.1",
            "server_port": 2408,
            "local_address": [warp_cfg["address"]],
            "private_key": warp_cfg["private_key"],
            "peer_public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
            "mtu": 1280,
        }

        # Route rules: WARP-домены → WARP outbound
        rules = [
            {
                "domain": WARP_DOMAINS,
                "outbound": "warp",
            }
        ]

        return ConfigFragment(
            outbounds=[outbound],
            route_rules=rules,
        )

    def status(self) -> PluginStatus:
        installed = WGCF_PROFILE.exists()
        running = False
        if installed:
            r = subprocess.run(
                ["ip", "link", "show", WARP_INTERFACE],
                capture_output=True,
            )
            running = r.returncode == 0

        return PluginStatus(
            installed=installed,
            enabled=bool(WGCF_PROFILE.exists()),
            running=running,
        )

    def traffic(self) -> dict[str, int]:
        return {}

    def on_enable(self, state: AppState) -> None:
        state.network.warp_enabled = True
        if WGCF_PROFILE.exists():
            subprocess.run(
                ["wg-quick", "up", str(WGCF_PROFILE)],
                capture_output=True,
            )

    def on_disable(self, state: AppState) -> None:
        state.network.warp_enabled = False
        subprocess.run(
            ["wg-quick", "down", str(WGCF_PROFILE)],
            capture_output=True,
        )
