"""
hydra/services/subscriptions/generator.py — Генератор подписок v2.

Форматы:
  • Base64 (для v2rayNG, Shadowrocket, Hiddify)
  • Sing-Box JSON (для NekoBox, Karing)
  • Протокол-специфичные конфиги (AWG .conf)

Динамически собирает ссылки/конфиги со всех включённых TRANSPORT-плагинов
через их v2-методы client_link() и generate_client_config().
"""
from __future__ import annotations

import base64
import json
from typing import Optional

from hydra.core.state import AppState, User
from hydra.plugins.base import PluginCategory
from hydra.plugins.registry import enabled, get


def generate_links(user: User, state: AppState) -> list[str]:
    """Собирает ссылки со всех включённых TRANSPORT-плагинов."""
    links: list[str] = []
    for p in enabled(state, PluginCategory.TRANSPORT):
        try:
            link = p.client_link(user, state)
            if link:
                links.append(link)
        except Exception:
            pass
    return links


def generate_base64_sub(user: User, state: AppState) -> str:
    """Base64-кодированные ссылки (v2rayNG-совместимые)."""
    links = generate_links(user, state)
    payload = "\n".join(links)
    return base64.b64encode(payload.encode()).decode()


def generate_singbox_config(user: User, state: AppState) -> dict:
    """Собирает sing-box конфиг из outbound'ов, возвращаемых плагинами."""
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

    for p in enabled(state, PluginCategory.TRANSPORT):
        conf_str = p.generate_client_config(user, state)
        if not conf_str:
            continue
        try:
            parsed = json.loads(conf_str)
            for ob in parsed.get("outbounds", []):
                config["outbounds"].append(ob)
        except json.JSONDecodeError:
            pass

    config["outbounds"].append({"type": "direct", "tag": "direct"})
    return config


def generate_client_config(user: User, state: AppState, protocol: str) -> str:
    """Генерирует конфиг для конкретного протокола (например, AWG .conf)."""
    p = get(protocol)
    if not p:
        return ""
    return p.generate_client_config(user, state)


# ═════════════════════════════════════════════════════════════════════════════
#  HTTP-сервер подписок
# ═════════════════════════════════════════════════════════════════════════════

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import threading

SUBSCRIPTION_PORT = 8443


class SubscriptionHandler(BaseHTTPRequestHandler):
    state: AppState = None

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        token = params.get("token", [None])[0]

        if not self.state:
            self.send_error(500, "Server not configured")
            return

        user = None
        for u in self.state.users:
            if u.uuid == token and not u.blocked:
                user = u
                break

        if not user:
            self.send_error(403, "Invalid or expired token")
            return

        fmt = params.get("format", ["singbox"])[0]
        protocol = params.get("protocol", [None])[0]

        if fmt == "base64":
            content = generate_base64_sub(user, self.state)
            content_type = "text/plain; charset=utf-8"
        elif fmt == "conf" and protocol:
            content = generate_client_config(user, self.state, protocol)
            content_type = "text/plain; charset=utf-8"
        else:
            config = generate_singbox_config(user, self.state)
            content = json.dumps(config, indent=2, ensure_ascii=False)
            content_type = "application/json; charset=utf-8"

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header(
            "Content-Disposition",
            f"attachment; filename=hydra-{user.email}.json",
        )
        self.send_header(
            "Subscription-Userinfo",
            f"upload=0; download={user.traffic_used_bytes}; "
            f"total={int(user.traffic_limit_gb * 1073741824)}",
        )
        self.end_headers()
        self.wfile.write(content.encode("utf-8"))


def start_sub_server(state: AppState) -> HTTPServer:
    SubscriptionHandler.state = state
    server = HTTPServer(("0.0.0.0", SUBSCRIPTION_PORT), SubscriptionHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server
