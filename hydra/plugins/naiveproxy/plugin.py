"""
hydra/plugins/naiveproxy/plugin.py — NaiveProxy через Caddy + Sing-Box.

Архитектура:
  Клиент ──→ Caddy (TLS + naive) ──→ Sing-Box (внутренний inbound) ──→ outbound

Caddy обеспечивает:
  - Автоматический ACME (Let's Encrypt)
  - Naive-транспорт (HTTP/2 CONNECT, Chromium fingerprint)
  - Терминирование TLS

Sing-Box обеспечивает:
  - Единый роутинг (WARP, GeoIP, DNS)
  - Учёт трафика для конкретного пользователя

Пользователи аутентифицируются через Caddy (basicauth),
их трафик виден Sing-Box по уникальному пользовательскому пути.
"""
from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Optional

from hydra.plugins.base import BasePlugin, PluginMeta, PluginStatus, ConfigFragment
from hydra.core.state import AppState, ProtocolState, load_state

CADDY_BIN = Path("/usr/bin/caddy")
CADDYFILE = Path("/etc/caddy/Caddyfile")
CADDY_DATA = Path("/var/lib/caddy")
NAIVE_INTERNAL_PORT = 8443


class NaiveProxyPlugin(BasePlugin):
    meta = PluginMeta(
        name="naiveproxy",
        description="NaiveProxy: HTTPS/HTTP2 + Chromium fingerprint через Caddy",
        version="1.0.0",
    )

    # ═════════════════════════════════════════════════════════════════════
    #  Установка / удаление
    # ═════════════════════════════════════════════════════════════════════

    def install(self) -> bool:
        """Устанавливает Caddy."""
        if CADDY_BIN.exists():
            return True

        # Способ 1: официальный apt-репозиторий Caddy
        r = subprocess.run(
            [
                "bash", "-c",
                "apt-get update -qq && "
                "apt-get install -y -qq debian-keyring debian-archive-keyring && "
                "mkdir -p /usr/share/keyrings && "
                "curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key "
                "| gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg && "
                "echo 'deb [signed-by=/usr/share/keyrings/caddy-stable-archive-keyring.gpg] "
                "https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main' "
                "> /etc/apt/sources.list.d/caddy-stable.list && "
                "apt-get update -qq && "
                "apt-get install -y -qq caddy",
            ],
            capture_output=True, text=True, timeout=120,
        )

        if r.returncode == 0 and CADDY_BIN.exists():
            subprocess.run(["systemctl", "stop", "caddy"], capture_output=True)
            subprocess.run(["systemctl", "disable", "caddy"], capture_output=True)
            return True

        # Способ 2: официальный установочный скрипт Caddy
        r = subprocess.run(
            ["bash", "-c", "curl -fsSL https://getcaddy.com | bash -s personal"],
            capture_output=True, text=True, timeout=120,
        )

        if r.returncode == 0 and CADDY_BIN.exists():
            subprocess.run(["systemctl", "stop", "caddy"], capture_output=True)
            subprocess.run(["systemctl", "disable", "caddy"], capture_output=True)
            return True

        return False

    def uninstall(self) -> bool:
        """Останавливает Caddy и удаляет конфиг."""
        subprocess.run(["systemctl", "stop", "caddy"], capture_output=True)
        CADDYFILE.unlink(missing_ok=True)
        return True

    # ═════════════════════════════════════════════════════════════════════
    #  Конфигурация
    # ═════════════════════════════════════════════════════════════════════

    def configure(self, state: AppState) -> ConfigFragment:
        """Генерирует Caddyfile и фрагмент Sing-Box конфига."""
        domain = state.network.domain
        if not domain:
            return ConfigFragment()

        users = [u for u in state.users if not u.blocked]

        # Генерируем Caddyfile
        self._write_caddyfile(domain, users)

        # Генерируем фрагмент для Sing-Box (внутренний HTTP inbound)
        inbound = {
            "type": "http",
            "tag": "naive-internal",
            "listen": "127.0.0.1",
            "listen_port": NAIVE_INTERNAL_PORT,
            "users": [
                {"username": u.email, "password": u.uuid}
                for u in users
            ],
        }

        return ConfigFragment(
            inbounds=[inbound],
        )

    def _write_caddyfile(self, domain: str, users: list) -> None:
        """Генерирует Caddyfile: TLS + forwardproxy → Sing-Box."""
        lines = [
            f"{domain}:443 {{",
            f"    tls {{",
            f"        protocols tls1.2 tls1.3",
            f"    }}",
            f"    forwardproxy {{",
            f"        basicauth {' '.join(f'{u.email} {u.uuid}' for u in users)}",
            f"        probe_resistance",
            f"    }}",
            f"    reverse_proxy 127.0.0.1:{NAIVE_INTERNAL_PORT}",
            f"}}",
        ]

        CADDYFILE.parent.mkdir(parents=True, exist_ok=True)
        CADDYFILE.write_text("\n".join(lines))

    # ═════════════════════════════════════════════════════════════════════
    #  Статус / трафик
    # ═════════════════════════════════════════════════════════════════════

    def status(self) -> PluginStatus:
        installed = CADDY_BIN.exists()
        running = False
        if installed:
            r = subprocess.run(
                ["systemctl", "is-active", "--quiet", "caddy"],
            )
            running = r.returncode == 0

        return PluginStatus(
            installed=installed,
            enabled=bool(CADDYFILE.exists()),
            running=running,
            port=443,
        )

    def traffic(self) -> dict[str, int]:
        """Парсит access-лог Caddy для учёта трафика по пользователям."""
        log_path = Path("/var/log/caddy/access.log")
        if not log_path.exists():
            return {}

        traffic: dict[str, int] = {}
        try:
            import json as _json
            with log_path.open("r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        entry = _json.loads(line)
                        user = (
                            entry.get("request", {}).get("user_id")
                            or entry.get("user_id", "")
                        )
                        if user:
                            size = int(entry.get("size", 0))
                            traffic[user] = traffic.get(user, 0) + size
                    except Exception:
                        continue
        except Exception:
            pass
        return traffic

    # ═════════════════════════════════════════════════════════════════════
    #  Управление
    # ═════════════════════════════════════════════════════════════════════

    def on_enable(self, state: AppState) -> None:
        self.configure(state)
        subprocess.run(["systemctl", "start", "caddy"], capture_output=True)

    def on_disable(self, state: AppState) -> None:
        subprocess.run(["systemctl", "stop", "caddy"], capture_output=True)
