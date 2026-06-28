"""
hydra/services/subscriptions/generator.py — Генератор подписок.

Форматы:
  • Base64 (для v2rayNG, Shadowrocket, Hiddify)
  • Sing-Box JSON (для NekoBox, Karing)
  • Mieru-ссылки
  • AmneziaWG-конфиги

Поддерживает персональные подписки (один пользователь) и
общие (все пользователи, только admin).
"""
from __future__ import annotations

import base64
import json
import uuid as _uuid
from typing import Optional

from hydra.core.state import AppState, User


def generate_singbox_config(user: User, state: AppState) -> dict:
    """Генерирует персональный Sing-Box JSON-конфиг для клиента."""
    domain = state.network.domain
    server_ip = state.network.server_ip or domain

    config: dict = {
        "log": {"level": "info"},
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": 2080,
            }
        ],
        "outbounds": [],
        "route": {"rules": [], "auto_detect_interface": True},
    }

    # NaiveProxy outbound
    if state.protocols.get("naiveproxy") and state.protocols["naiveproxy"].enabled:
        config["outbounds"].append({
            "type": "naive",
            "tag": "naive-out",
            "server": domain,
            "server_port": 443,
            "username": user.email,
            "password": user.uuid,
            "tls": {
                "enabled": True,
                "server_name": domain,
            },
        })

    # Mieru outbound
    if state.protocols.get("mieru") and state.protocols["mieru"].enabled:
        config["outbounds"].append({
            "type": "mieru",
            "tag": "mieru-out",
            "server": server_ip,
            "server_port": 8444,
            "username": user.email,
            "password": user.uuid[:16],
            "mtls": True,
        })

    # AmneziaWG outbound (как WireGuard)
    if state.protocols.get("amneziawg") and state.protocols["amneziawg"].enabled:
        config["outbounds"].append({
            "type": "wireguard",
            "tag": "awg-out",
            "server": server_ip,
            "server_port": 51820,
            "local_address": ["10.8.20.100/32"],
            "private_key": "{{AWG_CLIENT_PRIVATE_KEY}}",
            "peer_public_key": "{{AWG_SERVER_PUBLIC_KEY}}",
            "mtu": 1420,
        })

    # Direct (fallback)
    config["outbounds"].append({"type": "direct", "tag": "direct"})

    # Route: наивный трафик → Naive
    if state.protocols.get("naiveproxy") and state.protocols["naiveproxy"].enabled:
        config["route"]["rules"].append({
            "outbound": "naive-out",
            "domain": ["geosite:category-ads", "geosite:gfw"],
        })

    return config


def generate_base64_sub(user: User, state: AppState) -> str:
    """Генерирует Base64-подписку (v2rayNG-совместимую)."""
    links: list[str] = []

    domain = state.network.domain
    server_ip = state.network.server_ip or domain

    # NaiveProxy ссылка
    if state.protocols.get("naiveproxy") and state.protocols["naiveproxy"].enabled:
        naive_link = (
            f"naive+https://{user.email}:{user.uuid}@{domain}:443"
            f"?padding=false#HYDRA-Naive"
        )
        links.append(naive_link)

    # Mieru ссылка
    if state.protocols.get("mieru") and state.protocols["mieru"].enabled:
        mieru_link = (
            f"mieru://{user.email}:{user.uuid[:16]}@{server_ip}:8444"
            f"?mtls=true#HYDRA-Mieru"
        )
        links.append(mieru_link)

    # AmneziaWG не имеет стандартной ссылки — пропускаем

    payload = "\n".join(links)
    return base64.b64encode(payload.encode()).decode()


def generate_awg_client_config(user: User, state: AppState) -> str:
    """Генерирует клиентский конфиг AmneziaWG (единый источник — плагин)."""
    from hydra.plugins.registry import get
    plugin = get("amneziawg")
    if not plugin:
        return ""
    return plugin.generate_client_config(user, state)


# ═════════════════════════════════════════════════════════════════════════════
#  HTTP-сервер подписок (минимальный)
# ═════════════════════════════════════════════════════════════════════════════

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import threading

SUBSCRIPTION_PORT = 8443


class SubscriptionHandler(BaseHTTPRequestHandler):
    state: AppState = None  # type: ignore[assignment]

    def log_message(self, format, *args):
        pass  # Безшумный режим

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        token = params.get("token", [None])[0]

        if not self.state:
            self.send_error(500, "Server not configured")
            return

        # Проверяем токен (UUID пользователя)
        user = None
        for u in self.state.users:
            if u.uuid == token and not u.blocked:
                user = u
                break

        if not user:
            self.send_error(403, "Invalid or expired token")
            return

        # Определяем формат: /sub?token=X&format=base64|singbox|awg
        fmt = params.get("format", ["singbox"])[0]

        if fmt == "base64":
            content = generate_base64_sub(user, self.state)
            content_type = "text/plain; charset=utf-8"
        elif fmt == "awg":
            content = generate_awg_client_config(user, self.state)
            content_type = "text/plain; charset=utf-8"
        else:
            config = generate_singbox_config(user, self.state)
            content = json.dumps(config, indent=2, ensure_ascii=False)
            content_type = "application/json; charset=utf-8"

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Disposition", f"attachment; filename=hydra-{user.email}.json")
        self.send_header("Subscription-Userinfo", f"upload=0; download={user.traffic_used_bytes}; total={int(user.traffic_limit_gb * 1073741824)}")
        self.end_headers()
        self.wfile.write(content.encode("utf-8"))


def start_sub_server(state: AppState) -> HTTPServer:
    """Запускает HTTP-сервер подписок в фоновом потоке."""
    SubscriptionHandler.state = state
    server = HTTPServer(("0.0.0.0", SUBSCRIPTION_PORT), SubscriptionHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server
