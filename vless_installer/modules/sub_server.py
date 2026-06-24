"""
vless_installer/modules/sub_server.py
───────────────────────────────────────────────────────────────────────────────
HTTP-сервер подписок на stdlib Python (zero pip dependencies).

Слушает 127.0.0.1:8443, nginx проксирует снаружи.

Эндпоинты:
  GET /sub/<token>          → Base64 (v2rayNG, Shadowrocket, Hiddify)
  GET /sub/<token>/clash    → Clash Meta YAML
  GET /sub/<token>/singbox  → Sing-box JSON

Точка входа:
    from vless_installer.modules.sub_server import (
        install_sub_service, uninstall_sub_service, start_sub_server
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import textwrap
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional

# ── Константы ─────────────────────────────────────────────────────────────────

STATE_FILE = Path("/var/lib/xray-installer/state.json")
XRAY_CONFIG = Path("/var/lib/xray-installer/config.json")
LOG_FILE = Path("/var/log/vless-install.log")
SERVICE_NAME = "vless-sub"
SERVICE_FILE = Path(f"/etc/systemd/system/{SERVICE_NAME}.service")
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 9443

# ── Цвета ─────────────────────────────────────────────────────────────────────

if sys.stdout.isatty():
    GREEN = '\033[0;32m'; RED = '\033[0;31m'; YELLOW = '\033[1;33m'
    CYAN = '\033[0;36m'; BOLD = '\033[1m'; DIM = '\033[2m'; NC = '\033[0m'
else:
    GREEN = RED = YELLOW = CYAN = BOLD = DIM = NC = ''


def _log(level: str, msg: str) -> None:
    try:
        from datetime import datetime
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with LOG_FILE.open("a") as f:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            clean = re.sub(r'\x1b\[[0-9;]*m', '', msg)
            f.write(f"[{ts}] [SUB-{level}] {clean}\n")
    except Exception:
        pass


def info(msg: str)    -> None: print(f"{CYAN}[INFO]{NC}  {msg}"); _log("INFO", msg)
def success(msg: str) -> None: print(f"{GREEN}[OK]{NC}    {msg}"); _log("OK", msg)
def warn(msg: str)    -> None: print(f"{YELLOW}[WARN]{NC}  {msg}"); _log("WARN", msg)
def error(msg: str)   -> None: print(f"{RED}[ERR]{NC}   {msg}"); _log("ERR", msg)


# ── Поиск пользователя по токену ─────────────────────────────────────────────

def _load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def _load_xray_config() -> dict:
    for p in (Path("/etc/xray/config.json"), Path("/usr/local/etc/xray/config.json"), Path("/var/lib/xray-installer/config.json")):
        if p.exists():
            try:
                return json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                pass
    return {}


def find_user_by_token(token: str) -> Optional[tuple[str, str]]:
    """Найти пользователя по подписочному токену with rich debug logs.
    Returns (uuid, email) or None.
    """
    state = _load_state()
    if not state:
        _log("WARN", "find_user_by_token: state.json is empty or failed to load")
    sub_tokens = state.get("sub_tokens", {})
    _log("INFO", f"Comparing requested token: '{token}' against {len(sub_tokens)} stored tokens")

    email = None
    token_lower = token.lower().strip()
    for e, t in sub_tokens.items():
        _log("INFO", f"Checking stored user '{e}' with token: '{t}'")
        if str(t).lower().strip() == token_lower:
            email = e
            break

    if not email:
        _log("WARN", f"find_user_by_token: No email matched for token '{token}'")
        return None

    # Ищем UUID в xray config
    cfg = _load_xray_config()
    for inb in cfg.get("inbounds", []):
        for cl in inb.get("settings", {}).get("clients", []):
            if cl.get("email", "") == email:
                return (cl.get("id", ""), email)

    # Если не нашли в xray config, используем основной UUID
    main_uuid = state.get("uuid", "")
    if main_uuid:
        return (main_uuid, email)

    # Если UUID нет, возвращаем пустую строку как UUID, но разрешаем авторизацию!
    _log("INFO", f"User '{email}' authenticated successfully via token, but no UUID found in xray config or state.json. Returning empty UUID.")
    return ("", email)


# ── HTTP Handler ──────────────────────────────────────────────────────────────

class SubRequestHandler(BaseHTTPRequestHandler):
    """Обработчик HTTP-запросов подписок."""

    server_version = "VLESS-Sub/1.0"

    def log_message(self, format, *args):
        """Перенаправляем логи в файл."""
        _log("HTTP", f"{self.client_address[0]} - {format % args}")

    def _send_error(self, code: int, message: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(message.encode("utf-8"))

    def do_GET(self) -> None:
        _log("INFO", f"do_GET: raw path = {self.path}")
        # Разбираем путь: /sub/<token>[/format]
        path = self.path
        if "?" in path:
            path = path.split("?")[0]
        path = path.rstrip("/")
        parts = path.split("/")
        _log("INFO", f"do_GET: split parts = {parts}")

        #  /sub/TOKEN → ["", "sub", "TOKEN"]
        if len(parts) < 3 or parts[1] != "sub":
            self._send_error(404, "Not found")
            return

        token = parts[2]
        fmt = parts[3] if len(parts) > 3 else "base64"

        # Авторизация
        user_info = find_user_by_token(token)
        if not user_info:
            self._send_error(403, "Invalid token")
            return

        uuid_str, email = user_info
        state = _load_state()

        # Импортируем генератор
        try:
            from vless_installer.modules.sub_generator import (
                generate_base64_sub,
                generate_clash_yaml,
                generate_singbox_json,
                generate_userinfo_header,
            )
        except ImportError:
            # Fallback для автономного запуска
            sys.path.insert(0, str(Path(__file__).parent.parent.parent))
            from vless_installer.modules.sub_generator import (
                generate_base64_sub,
                generate_clash_yaml,
                generate_singbox_json,
                generate_userinfo_header,
            )

        userinfo = generate_userinfo_header(state, email)

        if fmt == "base64" or fmt == token:
            # GET /sub/TOKEN → Base64
            body = generate_base64_sub(state, uuid_str, email)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Disposition",
                             f'attachment; filename="{email}_sub.txt"')
            self.send_header("Subscription-Userinfo", userinfo)
            self.send_header("Profile-Update-Interval", "6")  # обновлять каждые 6 часов
            self.end_headers()
            self.wfile.write(body.encode("utf-8"))

        elif fmt == "clash":
            body = generate_clash_yaml(state, uuid_str, email)
            self.send_response(200)
            self.send_header("Content-Type", "text/yaml; charset=utf-8")
            self.send_header("Content-Disposition",
                             f'attachment; filename="{email}_clash.yaml"')
            self.send_header("Subscription-Userinfo", userinfo)
            self.send_header("Profile-Update-Interval", "6")
            self.end_headers()
            self.wfile.write(body.encode("utf-8"))

        elif fmt == "singbox":
            body = generate_singbox_json(state, uuid_str, email)
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Disposition",
                             f'attachment; filename="{email}_singbox.json"')
            self.send_header("Subscription-Userinfo", userinfo)
            self.send_header("Profile-Update-Interval", "6")
            self.end_headers()
            self.wfile.write(body.encode("utf-8"))

        else:
            self._send_error(404, f"Unknown format: {fmt}")


# ── Запуск сервера ────────────────────────────────────────────────────────────

def start_sub_server(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
                     daemon: bool = True) -> Optional[ThreadingHTTPServer]:
    """Запустить HTTP-сервер подписок с поддержкой SSL/HTTPS."""
    try:
        server = ThreadingHTTPServer((host, port), SubRequestHandler)
        
        # Подключаем SSL если домен настроен и сертификаты найдены
        state = _load_state()
        sub_domain = state.get("sub_domain")
        if sub_domain:
            cert_file = Path(f"/etc/letsencrypt/live/{sub_domain}/fullchain.pem")
            key_file = Path(f"/etc/letsencrypt/live/{sub_domain}/privkey.pem")
            if cert_file.exists() and key_file.exists():
                try:
                    import ssl
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    context.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
                    server.socket = context.wrap_socket(server.socket, server_side=True)
                    _log("INFO", f"SSL/HTTPS enabled for sub server domain: {sub_domain}")
                except Exception as ssl_err:
                    _log("ERR", f"Failed to wrap socket with SSL: {ssl_err}")
            else:
                _log("WARN", f"SSL certificate files not found for {sub_domain} at /etc/letsencrypt/live/")
        
        thread = threading.Thread(target=server.serve_forever, daemon=daemon)
        thread.start()
        _log("INFO", f"Sub server started on {host}:{port}")
        return server
    except OSError as e:
        _log("ERR", f"Failed to start sub server: {e}")
        return None


# ── Systemd-сервис ────────────────────────────────────────────────────────────

def generate_systemd_unit(host: str = DEFAULT_HOST,
                           port: int = DEFAULT_PORT) -> str:
    """Генерация содержимого systemd unit-файла."""
    install_dir = "/opt/vless-ultimate"
    # Ищем реальную директорию установки
    for candidate in ("/opt/vless-ultimate",
                      "/root/VLESS-Ultimate-Installer",
                      "/opt/VLESS-Ultimate-Installer"):
        if Path(candidate).exists():
            install_dir = candidate
            break

    return textwrap.dedent(f"""\
        [Unit]
        Description=VLESS Subscription Server
        After=network.target xray.service
        Wants=network.target

        [Service]
        Type=simple
        WorkingDirectory={install_dir}
        Environment=PYTHONPATH={install_dir}
        ExecStart=/usr/bin/python3 {install_dir}/vless_installer/modules/sub_server.py --host {host} --port {port}
        Restart=always
        RestartSec=5
        StandardOutput=journal
        StandardError=journal

        [Install]
        WantedBy=multi-user.target
    """)


def install_sub_service(host: str = DEFAULT_HOST,
                        port: int = DEFAULT_PORT) -> bool:
    """Установить и запустить systemd-сервис подписок."""
    try:
        unit_content = generate_systemd_unit(host, port)
        SERVICE_FILE.write_text(unit_content)
        success(f"Создан {SERVICE_FILE}")

        subprocess.run(["systemctl", "daemon-reload"], check=True,
                       capture_output=True)
        subprocess.run(["systemctl", "enable", SERVICE_NAME], check=True,
                       capture_output=True)
        subprocess.run(["systemctl", "restart", SERVICE_NAME], check=True,
                       capture_output=True)
        success(f"Сервис {SERVICE_NAME} запущен на {host}:{port}")
        return True
    except Exception as e:
        error(f"Ошибка установки сервиса: {e}")
        return False


def uninstall_sub_service() -> bool:
    """Остановить и удалить systemd-сервис подписок."""
    try:
        subprocess.run(["systemctl", "stop", SERVICE_NAME],
                       capture_output=True)
        subprocess.run(["systemctl", "disable", SERVICE_NAME],
                       capture_output=True)
        if SERVICE_FILE.exists():
            SERVICE_FILE.unlink()
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
        success(f"Сервис {SERVICE_NAME} удалён")
        return True
    except Exception as e:
        error(f"Ошибка удаления сервиса: {e}")
        return False


def is_sub_service_running() -> bool:
    """Проверить, запущен ли сервис подписок."""
    try:
        r = subprocess.run(["systemctl", "is-active", SERVICE_NAME],
                           capture_output=True, text=True)
        return r.stdout.strip() == "active"
    except Exception:
        return False


# ── Точка входа для standalone-режима ─────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="VLESS Subscription Server")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()

    print(f"Starting subscription server on {args.host}:{args.port}")
    server = start_sub_server(args.host, args.port, daemon=True)
    if server:
        import signal, threading
        evt = threading.Event()
        signal.signal(signal.SIGTERM, lambda *a: (server.shutdown(), evt.set()))
        signal.signal(signal.SIGINT,  lambda *a: (server.shutdown(), evt.set()))
        try:
            evt.wait()
        except KeyboardInterrupt:
            server.shutdown()
        print("\nServer stopped.")
