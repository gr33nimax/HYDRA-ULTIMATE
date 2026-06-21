"""
vless_installer/modules/subscription.py
───────────────────────────────────────────────────────────────────────────────
Подписка (Subscription) — единая система пользователей и раздача конфигов.

Объединяет конфигурации VLESS, NaiveProxy и Mieru в одну subscription-ссылку.
Пользователь вводит префикс поддомена (например «sub»), после настройки DNS
все конфиги доступны по адресу:

    https://sub.example.com:8443/<tag>          → URI-подписка (base64)
    https://sub.example.com:8443/<tag>/singbox  → sing-box JSON (Karing/NekoBox)

где <tag> — уникальный идентификатор пользователя (латиница, цифры, _ -).

Форматы ответа:
  • URI (по умолчанию): base64(vless://...\\nnaive+https://...\\nmierus://...)
    — v2rayNG, Happ, Shadowrocket
  • Sing-box JSON (/singbox или ?format=singbox): полный конфиг с outbounds
    — Karing, NekoBox, sing-box CLI

Схема:
  Клиент (v2rayNG / NekoBox / Happ / Karing)
    │  HTTPS GET https://sub.domain.com:8443/ivan
    ▼
  Nginx :8443 (TLS, Let's Encrypt)
    │  proxy_pass
    ▼
  xray-subscription.service :8765 (localhost)
    │  читает subscription.json + state.json
    ▼
  base64(vless://...\\nnaive+https://...\\nmierus://...)

Единая система пользователей:
  • Один tag на пользователя — ключ в URL подписки
  • При добавлении создаётся/синхронизируется запись в:
      - /etc/xray/users.json + config.json (VLESS)
      - /var/lib/xray-installer/naiveproxy.json (NaiveProxy)
      - /var/lib/xray-installer/mieru.json (Mieru)
  • Пароль Naive/Mieru общий; VLESS использует UUID

Хранение:
  /var/lib/xray-installer/subscription.json  — конфиг и пользователи
  /usr/local/bin/xray-subscription-server.py   — HTTP-сервер (systemd)
  /etc/systemd/system/xray-subscription.service

Публичное API:
    do_subscription_menu()  → главное меню [14]
    build_subscription_body(tag) → bytes (URI base64)
    build_singbox_body(tag)        → bytes (sing-box JSON)
    subscription_singbox_url(tag)  → str
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import base64
import json
import os
import platform
import re
import secrets
import shutil
import socket
import subprocess
import sys
import textwrap
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Optional

# ══════════════════════════════════════════════════════════════════════════════
#  ЦВЕТА
# ══════════════════════════════════════════════════════════════════════════════
def _detect_colors() -> dict:
    _light = os.environ.get("VLESS_THEME", "").lower() == "light"
    if sys.stdout.isatty():
        if _light:
            return dict(
                RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[0;33m',
                CYAN='\033[0;34m', BOLD='\033[1m', DIM='\033[2m',
                WHITE='\033[0;30m', NC='\033[0m',
            )
        return dict(
            RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
            CYAN='\033[0;36m', BOLD='\033[1m', DIM='\033[2m',
            WHITE='\033[1;37m', NC='\033[0m',
        )
    return {k: '' for k in ('RED', 'GREEN', 'YELLOW', 'CYAN', 'BOLD', 'DIM', 'WHITE', 'NC')}

_C = _detect_colors()
RED, GREEN, YELLOW, CYAN, BOLD, DIM, WHITE, NC = (
    _C['RED'], _C['GREEN'], _C['YELLOW'], _C['CYAN'],
    _C['BOLD'], _C['DIM'], _C['WHITE'], _C['NC'],
)

# ══════════════════════════════════════════════════════════════════════════════
#  КОНСТАНТЫ
# ══════════════════════════════════════════════════════════════════════════════
_MODULE_STATE   = Path("/var/lib/xray-installer/subscription.json")
_INSTALLER_STATE = Path("/var/lib/xray-installer/state.json")
_NAIVE_STATE    = Path("/var/lib/xray-installer/naiveproxy.json")
_MIERU_STATE    = Path("/var/lib/xray-installer/mieru.json")
_USERS_FILE     = Path("/etc/xray/users.json")

_SVC_NAME       = "xray-subscription"
_SVC_FILE       = Path(f"/etc/systemd/system/{_SVC_NAME}.service")
_SERVER_SCRIPT  = Path("/usr/local/bin/xray-subscription-server.py")
_NGINX_CONF_DIR = Path("/etc/nginx/sites-available")
_NGINX_ENABLED  = Path("/etc/nginx/sites-enabled")
_WEB_ROOT_BASE  = Path("/var/www")

_DEFAULT_PORT   = 8765          # внутренний HTTP
_DEFAULT_HTTPS  = 8443          # внешний HTTPS (443 обычно занят Xray)
_RE_TAG         = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_-]{0,31}$')
_LOG_FILE       = Path("/var/log/vless-install.log")

from vless_installer.modules.box_renderer import (
    _box_top, _box_sep, _box_bottom, _box_row, _box_item, _box_back,
    _box_info, _box_warn, _box_desc, _get_box_width,
)

# ══════════════════════════════════════════════════════════════════════════════
#  УТИЛИТЫ
# ══════════════════════════════════════════════════════════════════════════════
class _Cancelled(Exception):
    pass

def _log(level: str, msg: str) -> None:
    try:
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        clean = re.sub(r'\x1b\[[0-9;]*m', '', msg)
        with _LOG_FILE.open("a") as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [SUB] [{level}] {clean}\n")
    except Exception:
        pass

def _info(msg: str):  print(f"{CYAN}[INFO]{NC}  {msg}");  _log("INFO", msg)
def _ok(msg: str):    print(f"{GREEN}[OK]{NC}    {msg}");  _log("SUCCESS", msg)
def _warn(msg: str):  print(f"{YELLOW}[WARN]{NC}  {msg}"); _log("WARN", msg)
def _err(msg: str):   print(f"{RED}[ERR]{NC}   {msg}");   _log("ERROR", msg)

def _pause() -> None:
    try:
        input(f"\n{CYAN}Нажмите Enter...{NC}")
    except (KeyboardInterrupt, EOFError):
        raise _Cancelled()

def _ask(prompt: str, default: str = "", c: bool = False) -> str:
    suffix = f" [{default}]" if default else ""
    try:
        raw = input(f"{prompt}{suffix}: ").strip()
    except (KeyboardInterrupt, EOFError):
        raise _Cancelled()
    return raw or default

def _run(cmd: list, capture: bool = False, quiet: bool = False) -> subprocess.CompletedProcess:
    kw: dict = {}
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    elif quiet:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(cmd, **kw)

def _gen_password(length: int = 16) -> str:
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"
    return ''.join(secrets.choice(chars) for _ in range(length))

def _gen_uuid() -> str:
    import uuid
    return str(uuid.uuid4())

def _get_server_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        pass
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=5) as r:
            return r.read().decode().strip()
    except Exception:
        return ""

def _port_in_use(port: int) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            return s.connect_ex(("127.0.0.1", port)) == 0
    except Exception:
        return False

# ══════════════════════════════════════════════════════════════════════════════
#  СОСТОЯНИЕ МОДУЛЯ
# ══════════════════════════════════════════════════════════════════════════════
def _default_state() -> dict:
    return {
        "enabled": False,
        "subdomain_prefix": "sub",
        "base_domain": "",
        "full_domain": "",
        "https_port": _DEFAULT_HTTPS,
        "listen_port": _DEFAULT_PORT,
        "protocols": ["vless", "naive", "mieru"],
        "users": [],
        "installed_at": "",
    }

def _load_state() -> dict:
    if not _MODULE_STATE.exists():
        return _default_state()
    try:
        data = json.loads(_MODULE_STATE.read_text())
        base = _default_state()
        base.update(data)
        return base
    except Exception:
        return _default_state()

def _save_state(data: dict) -> None:
    _MODULE_STATE.parent.mkdir(parents=True, exist_ok=True)
    _MODULE_STATE.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    _MODULE_STATE.chmod(0o600)

def _is_configured() -> bool:
    st = _load_state()
    return bool(st.get("enabled") and st.get("full_domain"))

def _svc_active() -> bool:
    r = _run(["systemctl", "is-active", _SVC_NAME], capture=True)
    return r.stdout.strip() == "active"

# ══════════════════════════════════════════════════════════════════════════════
#  ГЕНЕРАЦИЯ ССЫЛОК (самодостаточно — используется HTTP-сервером)
# ══════════════════════════════════════════════════════════════════════════════
def _load_installer_state() -> dict:
    if not _INSTALLER_STATE.exists():
        return {}
    try:
        return json.loads(_INSTALLER_STATE.read_text())
    except Exception:
        return {}

def _load_naive_state() -> dict:
    if not _NAIVE_STATE.exists():
        return {}
    try:
        return json.loads(_NAIVE_STATE.read_text())
    except Exception:
        return {}

def _load_mieru_state() -> dict:
    if not _MIERU_STATE.exists():
        return {}
    try:
        return json.loads(_MIERU_STATE.read_text())
    except Exception:
        return {}

def _gen_vless_link(uuid_val: str, label: str, st: dict) -> str:
    domain     = st.get("domain", "")
    port       = int(st.get("server_port", 443))
    proto      = st.get("protocol_mode", "reality")
    pub_key    = st.get("public_key", "")
    short_id   = st.get("short_id", "")
    fp         = st.get("fingerprint", "chrome") or "chrome"
    xhttp_path = st.get("xhttp_path", "/")
    xhttp_mode = st.get("xhttp_mode", "streamup")
    install_mode = st.get("install_mode", "A")
    awg_exit   = st.get("awg_exit_enabled", False) and install_mode == "B"
    reality_dest = st.get("reality_dest", "")
    if proto == "reality" and awg_exit and reality_dest:
        sni = reality_dest.split(":")[0]
    else:
        sni = domain
    if not domain or not uuid_val:
        return ""
    tag_enc = urllib.parse.quote(label)
    if proto == "xhttp":
        path_enc = urllib.parse.quote(xhttp_path, safe="/")
        return (
            f"vless://{uuid_val}@{domain}:{port}"
            f"?type=xhttp&security=tls&sni={sni}"
            f"&path={path_enc}&mode={xhttp_mode}"
            f"&fp={fp}#{tag_enc}"
        )
    flow = st.get("xtls_flow", "xtls-rprx-vision") or ""
    flow_part = f"&flow={flow}" if flow else ""
    return (
        f"vless://{uuid_val}@{domain}:{port}"
        f"?type=tcp&security=reality&pbk={pub_key}"
        f"&fp={fp}&sni={sni}&sid={short_id}"
        f"{flow_part}#{tag_enc}"
    )

def _gen_naive_link(username: str, password: str, label: str, naive_st: dict) -> str:
    domain = naive_st.get("domain", "")
    port   = int(naive_st.get("port", 443))
    if not domain or not username or not password:
        return ""
    user_q = urllib.parse.quote(username, safe="")
    pass_q = urllib.parse.quote(password, safe="")
    link = f"naive+https://{user_q}:{pass_q}@{domain}:{port}/"
    if label:
        link += f"#{urllib.parse.quote(label, safe='')}"
    return link

def _gen_mieru_link(username: str, password: str, label: str, mieru_st: dict) -> str:
    server_ip  = _get_server_ip()
    port_start = int(mieru_st.get("port_start", 2012))
    protocol   = mieru_st.get("protocol", "TCP").upper()
    if not username or not password or not server_ip:
        return ""
    link = (
        f"mierus://{username}:{password}@{server_ip}"
        f"?port={port_start}&protocol={protocol}&profile=default"
        f"&mtu=1400&multiplexing=MULTIPLEXING_HIGH"
    )
    if label:
        link += f"#{urllib.parse.quote(label, safe='')}"
    return link

def _find_user_by_tag(tag: str, sub_st: Optional[dict] = None) -> Optional[dict]:
    sub_st = sub_st or _load_state()
    tag_l = tag.strip().lower()
    for u in sub_st.get("users", []):
        if u.get("tag", "").lower() == tag_l:
            return u
    return None

def build_subscription_lines(user: dict, sub_st: Optional[dict] = None) -> list[str]:
    """Собирает список proxy-ссылок для пользователя подписки."""
    sub_st = sub_st or _load_state()
    if user.get("blocked"):
        return []
    protocols = user.get("protocols") or sub_st.get("protocols", ["vless", "naive", "mieru"])
    label = user.get("name") or user.get("tag", "user")
    lines: list[str] = []

    if "vless" in protocols and user.get("vless_uuid"):
        inst = _load_installer_state()
        link = _gen_vless_link(user["vless_uuid"], label, inst)
        if link:
            lines.append(link)

    if "naive" in protocols and user.get("naive_username") and user.get("naive_password"):
        naive_st = _load_naive_state()
        link = _gen_naive_link(
            user["naive_username"], user["naive_password"], label, naive_st,
        )
        if link:
            lines.append(link)

    if "mieru" in protocols and user.get("mieru_username") and user.get("mieru_password"):
        mieru_st = _load_mieru_state()
        link = _gen_mieru_link(
            user["mieru_username"], user["mieru_password"], label, mieru_st,
        )
        if link:
            lines.append(link)

    return lines

def _gen_vless_singbox_outbound(uuid_val: str, tag: str, label: str, st: dict) -> dict:
    """Sing-box outbound для VLESS (REALITY или xHTTP)."""
    domain     = st.get("domain", "")
    port       = int(st.get("server_port", 443))
    proto      = st.get("protocol_mode", "reality")
    pub_key    = st.get("public_key", "")
    short_id   = st.get("short_id", "")
    fp         = st.get("fingerprint", "chrome") or "chrome"
    xhttp_path = st.get("xhttp_path", "/")
    install_mode = st.get("install_mode", "A")
    awg_exit   = st.get("awg_exit_enabled", False) and install_mode == "B"
    reality_dest = st.get("reality_dest", "")
    if proto == "reality" and awg_exit and reality_dest:
        sni = reality_dest.split(":")[0]
    else:
        sni = domain
    if not domain or not uuid_val:
        return {}
    outbound_tag = f"vless-{tag}"
    flow = st.get("xtls_flow", "xtls-rprx-vision") or ""
    if proto == "xhttp":
        return {
            "type": "vless",
            "tag": outbound_tag,
            "server": domain,
            "server_port": port,
            "uuid": uuid_val,
            "transport": {"type": "http", "path": xhttp_path},
            "tls": {
                "enabled": True,
                "server_name": domain,
                "utls": {"enabled": True, "fingerprint": fp},
            },
        }
    ob: dict = {
        "type": "vless",
        "tag": outbound_tag,
        "server": domain,
        "server_port": port,
        "uuid": uuid_val,
        "tls": {
            "enabled": True,
            "server_name": sni,
            "utls": {"enabled": True, "fingerprint": fp},
            "reality": {
                "enabled": True,
                "public_key": pub_key,
                "short_id": short_id,
            },
        },
    }
    if flow:
        ob["flow"] = flow
    return ob

def _gen_naive_singbox_outbound(username: str, password: str, tag: str, naive_st: dict) -> dict:
    domain = naive_st.get("domain", "")
    port   = int(naive_st.get("port", 443))
    if not domain or not username or not password:
        return {}
    return {
        "type": "naive",
        "tag": f"naive-{tag}",
        "server": domain,
        "server_port": port,
        "username": username,
        "password": password,
        "tls": {
            "enabled": True,
            "server_name": domain,
        },
    }

def _gen_mieru_singbox_outbound(username: str, password: str, tag: str, mieru_st: dict) -> dict:
    server_ip  = _get_server_ip()
    port_start = int(mieru_st.get("port_start", 2012))
    protocol   = mieru_st.get("protocol", "TCP").upper()
    if not username or not password or not server_ip:
        return {}
    return {
        "type": "mieru",
        "tag": f"mieru-{tag}",
        "server": server_ip,
        "server_port": port_start,
        "transport": protocol,
        "username": username,
        "password": password,
        "multiplexing": "MULTIPLEXING_HIGH",
    }

def build_singbox_config(user: dict, sub_st: Optional[dict] = None) -> dict:
    """Собирает sing-box JSON с outbounds для всех протоколов пользователя."""
    sub_st = sub_st or _load_state()
    if user.get("blocked"):
        return {}
    protocols = user.get("protocols") or sub_st.get("protocols", ["vless", "naive", "mieru"])
    tag = user.get("tag", "user")
    proxy_tags: list[str] = []
    outbounds: list[dict] = []

    if "vless" in protocols and user.get("vless_uuid"):
        ob = _gen_vless_singbox_outbound(
            user["vless_uuid"], tag, user.get("name", tag), _load_installer_state(),
        )
        if ob:
            outbounds.append(ob)
            proxy_tags.append(ob["tag"])

    if "naive" in protocols and user.get("naive_username") and user.get("naive_password"):
        ob = _gen_naive_singbox_outbound(
            user["naive_username"], user["naive_password"], tag, _load_naive_state(),
        )
        if ob:
            outbounds.append(ob)
            proxy_tags.append(ob["tag"])

    if "mieru" in protocols and user.get("mieru_username") and user.get("mieru_password"):
        ob = _gen_mieru_singbox_outbound(
            user["mieru_username"], user["mieru_password"], tag, _load_mieru_state(),
        )
        if ob:
            outbounds.append(ob)
            proxy_tags.append(ob["tag"])

    if not outbounds:
        return {}

    if len(proxy_tags) > 1:
        outbounds.append({
            "type": "selector",
            "tag": "proxy",
            "outbounds": proxy_tags,
            "default": proxy_tags[0],
        })
        final_tag = "proxy"
    else:
        final_tag = proxy_tags[0]

    outbounds.extend([
        {"type": "direct", "tag": "direct"},
        {"type": "block", "tag": "block"},
    ])

    return {
        "log": {"level": "info"},
        "outbounds": outbounds,
        "route": {
            "rules": [],
            "auto_detect_interface": True,
            "final": final_tag,
        },
    }

def build_singbox_body(tag: str) -> bytes:
    """Возвращает sing-box JSON для tag (bytes, UTF-8)."""
    user = _find_user_by_tag(tag)
    if not user:
        return b""
    cfg = build_singbox_config(user)
    if not cfg:
        return b""
    return json.dumps(cfg, indent=2, ensure_ascii=False).encode("utf-8")

def build_subscription_body(tag: str) -> bytes:
    """
    Возвращает тело HTTP-ответа подписки (base64) для tag.
    Пустая строка — пользователь не найден или заблокирован.
    """
    user = _find_user_by_tag(tag)
    if not user:
        return b""
    lines = build_subscription_lines(user)
    if not lines:
        return b""
    raw = "\n".join(lines)
    return base64.b64encode(raw.encode("utf-8"))

def subscription_url(tag: str, sub_st: Optional[dict] = None) -> str:
    sub_st = sub_st or _load_state()
    domain = sub_st.get("full_domain", "")
    port   = int(sub_st.get("https_port", _DEFAULT_HTTPS))
    if not domain:
        return ""
    if port == 443:
        return f"https://{domain}/{tag}"
    return f"https://{domain}:{port}/{tag}"

def subscription_singbox_url(tag: str, sub_st: Optional[dict] = None) -> str:
    """URL для импорта sing-box JSON (Karing / NekoBox / sing-box CLI)."""
    base = subscription_url(tag, sub_st)
    if not base:
        return ""
    return f"{base}/singbox"

def _parse_request_path(raw_path: str) -> tuple[str, str]:
    """
    Разбирает путь запроса.
    Возвращает (tag, format): format = 'uri' | 'singbox'.
    """
    path, _, query = raw_path.partition("?")
    path = path.strip("/")
    if not path or path == "favicon.ico":
        return "", ""

    parts = [p for p in path.split("/") if p]
    tag = parts[0]
    suffix = parts[1].lower() if len(parts) > 1 else ""

    if tag.lower().endswith(".json"):
        tag = tag[:-5]
        suffix = suffix or "json"

    if suffix in ("singbox", "sing-box", "json"):
        return tag, "singbox"
    if suffix:
        return "", ""

    qs = urllib.parse.parse_qs(query)
    fmt = (qs.get("format") or [""])[0].strip().lower()
    if fmt in ("singbox", "sing-box", "json"):
        return tag, "singbox"
    return tag, "uri"

# ══════════════════════════════════════════════════════════════════════════════
#  СИНХРОНИЗАЦИЯ ПОЛЬЗОВАТЕЛЕЙ С VLESS / NAIVE / MIERU
# ══════════════════════════════════════════════════════════════════════════════
def _sync_vless_user(uuid_val: str, name: str, email: str) -> tuple[bool, str]:
    try:
        import importlib
        core = importlib.import_module("vless_installer._core")
        users = core._unified_load_users()
        if any(u.get("uuid") == uuid_val for u in users):
            return True, ""
        install_mode = "A"
        if _INSTALLER_STATE.exists():
            try:
                install_mode = json.loads(_INSTALLER_STATE.read_text()).get("install_mode", "A")
            except Exception:
                pass
        users.append({
            "uuid": uuid_val,
            "email": email,
            "name": name,
            "device_label": f"sub-{name}",
            "created": datetime.now(timezone.utc).isoformat(),
            "source": install_mode,
        })
        core._unified_save_users(users)
        return True, ""
    except Exception as e:
        return False, str(e)

def _sync_naive_user(username: str, password: str) -> tuple[bool, str]:
    try:
        from vless_installer.modules.naiveproxy import (
            _apply_config, _hash_password, _load_state as _naive_load,
            _save_state as _naive_save, _is_installed,
        )
        if not _is_installed():
            return False, "NaiveProxy не установлен"
        state = _naive_load()
        users = state.get("users", [])
        if not any(u["username"] == username for u in users):
            users.append({
                "username": username,
                "password": password,
                "password_hash": _hash_password(password),
            })
            state["users"] = users
            _naive_save(state)
        err = _apply_config(
            state["domain"], state["port"], users,
            state.get("fake_url", "https://www.bing.com"),
            state.get("probe_secret", ""),
            state.get("upstream", ""),
        )
        return (False, err) if err else (True, "")
    except Exception as e:
        return False, str(e)

def _sync_mieru_user(username: str, password: str) -> tuple[bool, str]:
    try:
        from vless_installer.modules.mieru import (
            _apply_server_config, _build_server_config,
            _load_state as _mieru_load, _save_state as _mieru_save,
            _is_installed, _DEFAULT_PORT_START, _DEFAULT_PORT_END, _DEFAULT_PROTOCOL,
        )
        if not _is_installed():
            return False, "Mieru не установлен"
        state = _mieru_load()
        users = state.get("users", [])
        if not any(u["username"] == username for u in users):
            users.append({"username": username, "password": password})
            state["users"] = users
            _mieru_save(state)
        cfg = _build_server_config(
            users,
            state.get("port_start", _DEFAULT_PORT_START),
            state.get("port_end", _DEFAULT_PORT_END),
            state.get("protocol", _DEFAULT_PROTOCOL),
        )
        err = _apply_server_config(cfg)
        if err:
            _run(["systemctl", "restart", "mita"], quiet=True)
        return (False, err) if err else (True, "")
    except Exception as e:
        return False, str(e)

def _remove_vless_user(uuid_val: str) -> None:
    try:
        import importlib
        core = importlib.import_module("vless_installer._core")
        users = [u for u in core._unified_load_users() if u.get("uuid") != uuid_val]
        core._unified_save_users(users)
    except Exception:
        pass

def _remove_naive_user(username: str) -> None:
    try:
        from vless_installer.modules.naiveproxy import (
            _apply_config, _load_state as _naive_load,
            _save_state as _naive_save, _is_installed, _DEFAULT_FAKE,
        )
        if not _is_installed():
            return
        state = _naive_load()
        users = [u for u in state.get("users", []) if u.get("username") != username]
        if len(users) == len(state.get("users", [])):
            return
        state["users"] = users
        _naive_save(state)
        _apply_config(
            state["domain"], state["port"], users,
            state.get("fake_url", _DEFAULT_FAKE),
            state.get("probe_secret", ""),
            state.get("upstream", ""),
        )
    except Exception:
        pass

def _remove_mieru_user(username: str) -> None:
    try:
        from vless_installer.modules.mieru import (
            _apply_server_config, _build_server_config,
            _load_state as _mieru_load, _save_state as _mieru_save,
            _is_installed, _DEFAULT_PORT_START, _DEFAULT_PORT_END, _DEFAULT_PROTOCOL,
        )
        if not _is_installed():
            return
        state = _mieru_load()
        users = [u for u in state.get("users", []) if u.get("username") != username]
        if len(users) == len(state.get("users", [])):
            return
        state["users"] = users
        _mieru_save(state)
        cfg = _build_server_config(
            users,
            state.get("port_start", _DEFAULT_PORT_START),
            state.get("port_end", _DEFAULT_PORT_END),
            state.get("protocol", _DEFAULT_PROTOCOL),
        )
        _apply_server_config(cfg)
        _run(["systemctl", "restart", "mita"], quiet=True)
    except Exception:
        pass

# ══════════════════════════════════════════════════════════════════════════════
#  HTTP-СЕРВЕР ПОДПИСКИ
# ══════════════════════════════════════════════════════════════════════════════
def _generate_server_script() -> str:
    repo = "/opt/vless-ultimate"
    if not Path(repo).exists():
        repo = str(Path(__file__).resolve().parents[2])
    return textwrap.dedent(f'''\
        #!/usr/bin/env python3
        """xray-subscription-server — автогенерируемый HTTP-сервер подписок."""
        import sys
        sys.path.insert(0, "{repo}")
        from vless_installer.modules.subscription import _run_subscription_server
        if __name__ == "__main__":
            _run_subscription_server()
    ''')

class _SubscriptionHandler(BaseHTTPRequestHandler):
    """GET /{tag} — URI base64; GET /{tag}/singbox — sing-box JSON."""

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        tag, fmt = _parse_request_path(self.path)
        if not tag:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not found")
            return

        if fmt == "singbox":
            body = build_singbox_body(tag)
            if not body:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"Not found")
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Disposition", f'inline; filename="sing-box-{tag}.json"')
            self.end_headers()
            self.wfile.write(body)
            return

        body = build_subscription_body(tag)
        if not body:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not found")
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Subscription-Userinfo", "upload=0; download=0; total=0; expire=0")
        self.end_headers()
        self.wfile.write(body)

def _run_subscription_server() -> None:
    st = _load_state()
    port = int(st.get("listen_port", _DEFAULT_PORT))
    httpd = HTTPServer(("127.0.0.1", port), _SubscriptionHandler)
    httpd.serve_forever()

def _install_systemd_service() -> bool:
    _SERVER_SCRIPT.write_text(_generate_server_script())
    _SERVER_SCRIPT.chmod(0o700)
    st = _load_state()
    port = int(st.get("listen_port", _DEFAULT_PORT))
    svc = (
        "[Unit]\n"
        "Description=VLESS Subscription HTTP Server\n"
        "After=network.target\n\n"
        "[Service]\n"
        "Type=simple\n"
        f"ExecStart=/usr/bin/python3 {_SERVER_SCRIPT}\n"
        "Restart=always\n"
        "RestartSec=5\n"
        "StandardOutput=journal\n"
        "StandardError=journal\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )
    _SVC_FILE.write_text(svc)
    _run(["systemctl", "daemon-reload"], quiet=True)
    _run(["systemctl", "enable", _SVC_NAME], quiet=True)
    _run(["systemctl", "restart", _SVC_NAME], quiet=True)
    time.sleep(1)
    return _svc_active()

def _stop_systemd_service() -> None:
    _run(["systemctl", "stop", _SVC_NAME], quiet=True)
    _run(["systemctl", "disable", _SVC_NAME], quiet=True)
    _SVC_FILE.unlink(missing_ok=True)
    _SERVER_SCRIPT.unlink(missing_ok=True)
    _run(["systemctl", "daemon-reload"], quiet=True)

# ══════════════════════════════════════════════════════════════════════════════
#  NGINX + TLS
# ══════════════════════════════════════════════════════════════════════════════
def _nginx_site_name(full_domain: str) -> str:
    return f"subscription-{full_domain.replace('.', '-')}"

def _write_nginx_config(full_domain: str, https_port: int, listen_port: int) -> Path:
    _NGINX_CONF_DIR.mkdir(parents=True, exist_ok=True)
    _NGINX_ENABLED.mkdir(parents=True, exist_ok=True)
    web_root = _WEB_ROOT_BASE / full_domain.replace(".", "-")
    web_root.mkdir(parents=True, exist_ok=True)

    cert = Path(f"/etc/letsencrypt/live/{full_domain}/fullchain.pem")
    key  = Path(f"/etc/letsencrypt/live/{full_domain}/privkey.pem")
    ssl_block = ""
    listen_https = ""
    if cert.exists() and key.exists():
        ssl_block = textwrap.dedent(f"""\
            ssl_certificate     {cert};
            ssl_certificate_key {key};
            ssl_protocols       TLSv1.2 TLSv1.3;
        """)
        listen_https = textwrap.dedent(f"""\
            listen {https_port} ssl;
            listen [::]:{https_port} ssl;
        """)

    cfg_path = _NGINX_CONF_DIR / _nginx_site_name(full_domain)
    cfg_path.write_text(textwrap.dedent(f"""\
        # Subscription — {full_domain} (auto-generated)
        server {{
            {listen_https}
            server_name {full_domain};
            {ssl_block}
            location / {{
                proxy_pass http://127.0.0.1:{listen_port};
                proxy_set_header Host $host;
                proxy_set_header X-Real-IP $remote_addr;
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                proxy_set_header X-Forwarded-Proto $scheme;
            }}
        }}

        server {{
            listen 80;
            listen [::]:80;
            server_name {full_domain};
            root {web_root};
            location /.well-known/acme-challenge/ {{ try_files $uri =404; }}
            location / {{
                return 301 https://$host{f":{https_port}" if https_port != 443 else ""}$request_uri;
            }}
        }}
    """))
    link = _NGINX_ENABLED / cfg_path.name
    link.unlink(missing_ok=True)
    link.symlink_to(cfg_path)
    return cfg_path

def _remove_nginx_config(full_domain: str) -> None:
    name = _nginx_site_name(full_domain)
    (_NGINX_ENABLED / name).unlink(missing_ok=True)
    (_NGINX_CONF_DIR / name).unlink(missing_ok=True)

def _reload_nginx() -> bool:
    for bin_path in ("/usr/sbin/nginx", "/sbin/nginx"):
        if Path(bin_path).exists():
            r = _run([bin_path, "-t"], capture=True)
            if r.returncode != 0:
                return False
            _run([bin_path, "-s", "reload"], quiet=True)
            return True
    r = _run(["systemctl", "reload", "nginx"], quiet=True)
    return r.returncode == 0

def _obtain_cert(full_domain: str) -> tuple[bool, str]:
    web_root = _WEB_ROOT_BASE / full_domain.replace(".", "-")
    web_root.mkdir(parents=True, exist_ok=True)
    certbot = shutil.which("certbot") or "/usr/bin/certbot"
    if not Path(certbot).exists():
        return False, "certbot не найден — установите certbot python3-certbot-nginx"
    r = _run([
        certbot, "certonly", "--webroot",
        "-w", str(web_root),
        "-d", full_domain,
        "--non-interactive", "--agree-tos",
        "-m", f"admin@{full_domain.split('.', 1)[-1]}",
        "--no-eff-email",
    ], capture=True)
    if r.returncode != 0:
        err = (r.stderr or r.stdout or "certbot failed")[:400]
        return False, err
    return True, ""

def _open_firewall_port(port: int) -> None:
    r = _run(["ufw", "status"], capture=True)
    if "active" in (r.stdout or "").lower():
        _run(["ufw", "allow", f"{port}/tcp"], quiet=True)
        return
    chk = _run(
        ["iptables", "-C", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"],
        capture=True,
    )
    if chk.returncode != 0:
        _run(["iptables", "-I", "INPUT", "1", "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"])

# ══════════════════════════════════════════════════════════════════════════════
#  УСТАНОВКА / НАСТРОЙКА
# ══════════════════════════════════════════════════════════════════════════════
def _resolve_base_domain() -> str:
    inst = _load_installer_state()
    if inst.get("domain"):
        return inst["domain"]
    naive = _load_naive_state()
    if naive.get("domain"):
        return naive["domain"]
    return ""

def _setup_wizard() -> None:
    os.system("clear")
    _box_top("📡  НАСТРОЙКА  •  ПОДПИСКА")
    _box_row()
    _box_info("Подписка объединяет VLESS + NaiveProxy + Mieru в одну ссылку.")
    _box_info("Клиенты: v2rayNG, NekoBox, Happ, Karing, Shadowrocket.")
    _box_row()
    _box_warn("Порт 443 обычно занят Xray — подписка использует 8443 по умолчанию.")
    _box_bottom()
    print()

    state = _load_state()
    suggested_base = _resolve_base_domain()

    try:
        prefix = _ask(
            f"  {CYAN}Префикс поддомена (например sub){NC}",
            default=state.get("subdomain_prefix", "sub"),
        ).strip().lower()
        if not prefix or not re.match(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$', prefix):
            _warn("Некорректный префикс поддомена.")
            _pause()
            return

        base = _ask(
            f"  {CYAN}Базовый домен (example.com){NC}",
            default=state.get("base_domain") or suggested_base,
        ).strip().lower()
        if not base or "." not in base:
            _warn("Укажите корректный домен.")
            _pause()
            return

        full_domain = f"{prefix}.{base}"
        https_port = int(state.get("https_port", _DEFAULT_HTTPS))

        raw_port = _ask(
            f"  {CYAN}HTTPS-порт для подписки [{https_port}]{NC}",
            default=str(https_port),
        ).strip()
        if raw_port.isdigit():
            https_port = int(raw_port)

        print()
        _box_info(f"Полный адрес: {BOLD}https://{full_domain}:{https_port}/<tag>{NC}")
        _box_info(f"DNS: создайте A-запись  {prefix}  →  {_get_server_ip() or 'IP_VPS'}")
        print()
        confirm = _ask(f"  {CYAN}Продолжить? [y/N]{NC}", default="n").strip().lower()
        if confirm not in ("y", "yes", "д", "да"):
            return
    except _Cancelled:
        return

    state["subdomain_prefix"] = prefix
    state["base_domain"] = base
    state["full_domain"] = full_domain
    state["https_port"] = https_port
    state["listen_port"] = _DEFAULT_PORT
    _save_state(state)

    _info("Настраиваю nginx...")
    _write_nginx_config(full_domain, https_port, _DEFAULT_PORT)
    if not _reload_nginx():
        _warn("nginx -t не прошёл — проверьте конфиг вручную")

    _info("Получаю TLS-сертификат (certbot)...")
    ok, err = _obtain_cert(full_domain)
    if ok:
        _ok("Сертификат получен")
        _write_nginx_config(full_domain, https_port, _DEFAULT_PORT)
        _reload_nginx()
    else:
        _warn(f"Сертификат не получен: {err}")
        _warn("Подписка будет работать по HTTP (порт 80) до получения сертификата.")

    _info("Запускаю HTTP-сервер подписки...")
    if _install_systemd_service():
        _ok("Сервис xray-subscription запущен")
    else:
        _warn("Сервис не запустился — проверьте: journalctl -u xray-subscription")

    _open_firewall_port(https_port)
    _open_firewall_port(80)

    state["enabled"] = True
    state["installed_at"] = datetime.now(timezone.utc).isoformat()
    _save_state(state)

    os.system("clear")
    _box_top("✅  ПОДПИСКА НАСТРОЕНА")
    _box_row()
    _box_info(f"Домен: {BOLD}{full_domain}{NC}")
    _box_info(f"Порт:  {BOLD}{https_port}{NC}")
    _box_info(f"Формат URI: {BOLD}https://{full_domain}:{https_port}/<tag>{NC}")
    _box_info(f"Формат JSON: {BOLD}https://{full_domain}:{https_port}/<tag>/singbox{NC}")
    _box_row()
    _box_warn("Добавьте пользователей в меню [2] и выдайте им ссылку подписки.")
    _box_bottom()
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  УПРАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯМИ
# ══════════════════════════════════════════════════════════════════════════════
def _validate_tag(tag: str) -> Optional[str]:
    if not tag:
        return "Тег не может быть пустым"
    if not _RE_TAG.match(tag):
        return "Тег: латиница, цифры, _ - (2–32 символа, начинается с буквы/цифры)"
    return None

def _add_user(state: dict) -> None:
    os.system("clear")
    _box_top("➕  ДОБАВИТЬ ПОЛЬЗОВАТЕЛЯ  •  ПОДПИСКА")
    _box_row()
    _box_info("Создаёт единого пользователя во всех протоколах (VLESS/Naive/Mieru).")
    _box_bottom()
    print()

    try:
        tag = _ask(f"  {CYAN}Тег (URL: .../{{tag}}){NC}", c=True).strip()
        err = _validate_tag(tag)
        if err:
            _warn(err)
            _pause()
            return
        if _find_user_by_tag(tag, state):
            _warn(f"Пользователь с тегом '{tag}' уже существует.")
            _pause()
            return

        name = _ask(f"  {CYAN}Имя (отображается в клиенте){NC}", default=tag, c=True).strip() or tag
        protocols_raw = _ask(
            f"  {CYAN}Протоколы [vless,naive,mieru]{NC}",
            default=",".join(state.get("protocols", ["vless", "naive", "mieru"])),
            c=True,
        ).strip()
        protocols = [p.strip().lower() for p in protocols_raw.split(",") if p.strip()]
        valid = {"vless", "naive", "mieru"}
        protocols = [p for p in protocols if p in valid]
        if not protocols:
            _warn("Выберите хотя бы один протокол: vless, naive, mieru")
            _pause()
            return
    except _Cancelled:
        return

    vless_uuid = _gen_uuid()
    naive_user = tag if "naive" in protocols else ""
    naive_pass = _gen_password() if "naive" in protocols else ""
    mieru_user = tag if "mieru" in protocols else ""
    mieru_pass = _gen_password() if "mieru" in protocols else ""
    email = f"{tag}@subscription"

    sync_errors: list[str] = []

    if "vless" in protocols:
        ok, err = _sync_vless_user(vless_uuid, name, email)
        if not ok:
            sync_errors.append(f"VLESS: {err}")

    if "naive" in protocols:
        ok, err = _sync_naive_user(naive_user, naive_pass)
        if not ok:
            sync_errors.append(f"Naive: {err}")

    if "mieru" in protocols:
        ok, err = _sync_mieru_user(mieru_user, mieru_pass)
        if not ok:
            sync_errors.append(f"Mieru: {err}")

    user_rec = {
        "tag": tag,
        "name": name,
        "protocols": protocols,
        "vless_uuid": vless_uuid if "vless" in protocols else "",
        "naive_username": naive_user,
        "naive_password": naive_pass,
        "mieru_username": mieru_user,
        "mieru_password": mieru_pass,
        "blocked": False,
        "created": datetime.now(timezone.utc).isoformat(),
    }
    users = state.get("users", [])
    users.append(user_rec)
    state["users"] = users
    _save_state(state)

    os.system("clear")
    _box_top("✅  ПОЛЬЗОВАТЕЛЬ ДОБАВЛЕН")
    _box_row()
    _box_info(f"Тег:  {BOLD}{tag}{NC}")
    _box_info(f"Имя:  {name}")
    _box_info(f"Протоколы: {', '.join(protocols)}")
    if sync_errors:
        _box_row()
        for e in sync_errors:
            _box_warn(e)
    sub_url = subscription_url(tag, state)
    sb_url = subscription_singbox_url(tag, state)
    if sub_url:
        _box_row()
        _box_info("URI-подписка (v2rayNG / Happ):")
        print(f"  {GREEN}{sub_url}{NC}")
    if sb_url:
        _box_info("Sing-box JSON (Karing / NekoBox):")
        print(f"  {GREEN}{sb_url}{NC}")
    _box_bottom()
    _pause()

def _import_existing_user(state: dict) -> None:
    """Импорт: связать существующих пользователей VLESS/Naive/Mieru по имени."""
    os.system("clear")
    _box_top("📥  ИМПОРТ  •  СУЩЕСТВУЮЩИХ ПОЛЬЗОВАТЕЛЕЙ")
    _box_row()

    vless_users: list[dict] = []
    try:
        import importlib
        core = importlib.import_module("vless_installer._core")
        vless_users = core._unified_load_users()
    except Exception:
        pass
    naive_users = _load_naive_state().get("users", [])
    mieru_users = _load_mieru_state().get("users", [])

    if not vless_users and not naive_users and not mieru_users:
        _box_warn("Нет пользователей в VLESS/Naive/Mieru для импорта.")
        _box_bottom()
        _pause()
        return

    if vless_users:
        _box_row(f"  {BOLD}VLESS ({len(vless_users)}):{NC}")
        for i, u in enumerate(vless_users[:10], 1):
            _box_row(f"    {i}. {u.get('name','?')}  {DIM}{u.get('uuid','')[:8]}...{NC}")
    if naive_users:
        _box_row(f"  {BOLD}Naive ({len(naive_users)}):{NC}")
        for i, u in enumerate(naive_users[:10], 1):
            _box_row(f"    {i}. {u.get('username','?')}")
    if mieru_users:
        _box_row(f"  {BOLD}Mieru ({len(mieru_users)}):{NC}")
        for i, u in enumerate(mieru_users[:10], 1):
            _box_row(f"    {i}. {u.get('username','?')}")
    _box_bottom()
    print()

    try:
        tag = _ask(f"  {CYAN}Тег для новой подписки{NC}", c=True).strip()
        err = _validate_tag(tag)
        if err:
            _warn(err)
            _pause()
            return
        if _find_user_by_tag(tag, state):
            _warn("Тег уже занят.")
            _pause()
            return

        name = _ask(f"  {CYAN}Имя{NC}", default=tag, c=True).strip() or tag
        protocols: list[str] = []

        if vless_users:
            raw = _ask(f"  {CYAN}№ VLESS пользователя (Enter=пропустить){NC}", c=True).strip()
            if raw.isdigit() and 1 <= int(raw) <= len(vless_users):
                vu = vless_users[int(raw) - 1]
                vless_uuid = vu["uuid"]
                protocols.append("vless")
            else:
                vless_uuid = ""
        else:
            vless_uuid = ""

        naive_user, naive_pass = "", ""
        if naive_users:
            raw = _ask(f"  {CYAN}№ Naive пользователя (Enter=пропустить){NC}", c=True).strip()
            if raw.isdigit() and 1 <= int(raw) <= len(naive_users):
                nu = naive_users[int(raw) - 1]
                naive_user = nu["username"]
                naive_pass = nu.get("password", "")
                protocols.append("naive")

        mieru_user, mieru_pass = "", ""
        if mieru_users:
            raw = _ask(f"  {CYAN}№ Mieru пользователя (Enter=пропустить){NC}", c=True).strip()
            if raw.isdigit() and 1 <= int(raw) <= len(mieru_users):
                mu = mieru_users[int(raw) - 1]
                mieru_user = mu["username"]
                mieru_pass = mu.get("password", "")
                protocols.append("mieru")

        if not protocols:
            _warn("Не выбран ни один протокол.")
            _pause()
            return

        user_rec = {
            "tag": tag,
            "name": name,
            "protocols": protocols,
            "vless_uuid": vless_uuid,
            "naive_username": naive_user,
            "naive_password": naive_pass,
            "mieru_username": mieru_user,
            "mieru_password": mieru_pass,
            "blocked": False,
            "created": datetime.now(timezone.utc).isoformat(),
        }
        users = state.get("users", [])
        users.append(user_rec)
        state["users"] = users
        _save_state(state)
        _ok(f"Импортирован: {tag} ({', '.join(protocols)})")
        sub_url = subscription_url(tag, state)
        if sub_url:
            print(f"  {GREEN}{sub_url}{NC}")
        _pause()
    except _Cancelled:
        return

def _users_menu() -> None:
    while True:
        os.system("clear")
        state = _load_state()
        users = state.get("users", [])
        full_domain = state.get("full_domain", "—")

        _box_top("👥  ПОЛЬЗОВАТЕЛИ  •  ПОДПИСКА")
        _box_row()
        _box_info(f"Домен: {full_domain}")
        _box_info(f"Пользователей: {len(users)}")
        _box_row()
        _box_sep()

        if users:
            _box_row(f"  {BOLD}{'№':<4}{'Тег':<16}{'Имя':<16}{'Протоколы'}{NC}")
            _box_sep()
            for i, u in enumerate(users, 1):
                protos = ",".join(u.get("protocols", []))
                blocked = f" {RED}[блок]{NC}" if u.get("blocked") else ""
                _box_row(
                    f"  {i:<4}{CYAN}{u.get('tag','?'):<16}{NC}"
                    f"{u.get('name','?'):<16}{DIM}{protos}{NC}{blocked}"
                )
        else:
            _box_warn("Пользователей нет.")

        _box_row()
        _box_sep()
        _box_item("1", "➕  Добавить пользователя (синхронизация во все протоколы)")
        _box_item("2", "📥  Импорт существующих из VLESS/Naive/Mieru")
        _box_item("3", "🔗  Показать ссылки подписки (URI + sing-box)")
        _box_item("4", "📋  Содержимое URI-подписки (декодированные ссылки)")
        _box_item("5", "📋  Предпросмотр sing-box JSON")
        _box_item("6", "🚫  Блокировать / разблокировать")
        _box_item("7", f"{RED}🗑️   Удалить пользователя{NC}")
        _box_sep()
        _box_item("Q", "← Назад")
        _box_bottom()
        print()

        try:
            ch = _ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled:
            break

        if ch == "1":
            try:
                _add_user(state)
            except _Cancelled:
                pass
            state = _load_state()
        elif ch == "2":
            try:
                _import_existing_user(state)
            except _Cancelled:
                pass
            state = _load_state()
        elif ch == "3":
            if not users:
                _warn("Нет пользователей")
                _pause()
                continue
            try:
                raw = _ask("  Номер пользователя: ", c=True).strip()
                if raw.isdigit() and 1 <= int(raw) <= len(users):
                    u = users[int(raw) - 1]
                    url = subscription_url(u["tag"], state)
                    sb_url = subscription_singbox_url(u["tag"], state)
                    os.system("clear")
                    _box_top(f"🔗  ПОДПИСКА  •  {u.get('name', u['tag'])}")
                    _box_row()
                    _box_info("URI (v2rayNG / Happ / Shadowrocket):")
                    print(f"  {GREEN}{url}{NC}")
                    _box_row()
                    _box_info("Sing-box JSON (Karing / NekoBox / sing-box CLI):")
                    print(f"  {GREEN}{sb_url}{NC}")
                    _box_row()
                    _box_info("Альтернатива: добавьте ?format=singbox к URI-ссылке")
                    _box_bottom()
                    _pause()
            except _Cancelled:
                pass
        elif ch == "4":
            if not users:
                _warn("Нет пользователей")
                _pause()
                continue
            try:
                raw = _ask("  Номер пользователя: ", c=True).strip()
                if raw.isdigit() and 1 <= int(raw) <= len(users):
                    u = users[int(raw) - 1]
                    lines = build_subscription_lines(u, state)
                    os.system("clear")
                    _box_top(f"📋  СОДЕРЖИМОЕ  •  {u.get('tag')}")
                    _box_row()
                    if lines:
                        for ln in lines:
                            print(f"  {ln}")
                    else:
                        _box_warn("Нет ссылок — проверьте установку протоколов.")
                    _box_bottom()
                    _pause()
            except _Cancelled:
                pass
        elif ch == "5":
            if not users:
                _warn("Нет пользователей")
                _pause()
                continue
            try:
                raw = _ask("  Номер пользователя: ", c=True).strip()
                if raw.isdigit() and 1 <= int(raw) <= len(users):
                    u = users[int(raw) - 1]
                    cfg = build_singbox_config(u, state)
                    os.system("clear")
                    _box_top(f"📋  SING-BOX JSON  •  {u.get('tag')}")
                    _box_row()
                    if cfg:
                        print(json.dumps(cfg, indent=2, ensure_ascii=False))
                    else:
                        _box_warn("Нет outbounds — проверьте установку протоколов.")
                    _box_bottom()
                    _pause()
            except _Cancelled:
                pass
        elif ch == "6":
            if not users:
                _warn("Нет пользователей")
                _pause()
                continue
            try:
                raw = _ask("  Номер пользователя: ", c=True).strip()
                if raw.isdigit() and 1 <= int(raw) <= len(users):
                    u = users[int(raw) - 1]
                    u["blocked"] = not u.get("blocked", False)
                    state["users"] = users
                    _save_state(state)
                    status = "заблокирован" if u["blocked"] else "разблокирован"
                    _ok(f"{u['tag']} {status}")
                    _pause()
            except _Cancelled:
                pass
        elif ch == "7":
            if not users:
                _warn("Нет пользователей")
                _pause()
                continue
            try:
                raw = _ask("  Номер для удаления: ", c=True).strip()
                if raw.isdigit() and 1 <= int(raw) <= len(users):
                    u = users.pop(int(raw) - 1)
                    state["users"] = users
                    _save_state(state)
                    if u.get("vless_uuid"):
                        _remove_vless_user(u["vless_uuid"])
                    if u.get("naive_username"):
                        _remove_naive_user(u["naive_username"])
                    if u.get("mieru_username"):
                        _remove_mieru_user(u["mieru_username"])
                    _ok(f"Удалён: {u.get('tag')}")
                    _pause()
            except _Cancelled:
                pass
        elif ch in ("q", ""):
            break

def _show_status() -> None:
    state = _load_state()
    os.system("clear")
    svc = f"{GREEN}● активен{NC}" if _svc_active() else f"{RED}● остановлен{NC}"
    _box_top("📊  СТАТУС  •  ПОДПИСКА")
    _box_row()
    _box_info(f"Сервис: {svc}")
    _box_info(f"Домен:  {state.get('full_domain', '—')}")
    _box_info(f"Порт:   {state.get('https_port', _DEFAULT_HTTPS)}")
    _box_info(f"Внутр.: 127.0.0.1:{state.get('listen_port', _DEFAULT_PORT)}")
    _box_info(f"Пользователей: {len(state.get('users', []))}")
    _box_row()
    if state.get("full_domain"):
        _box_info(f"URI:      {subscription_url('TAG', state).replace('TAG', '<tag>')}")
        _box_info(f"Sing-box: {subscription_singbox_url('TAG', state).replace('TAG', '<tag>')}")
    _box_bottom()
    _pause()

def _uninstall() -> None:
    try:
        ans = _ask(f"  {RED}Удалить подписку (сервис, nginx, пользователи)? [y/N]{NC}", c=True)
    except _Cancelled:
        return
    if ans.strip().lower() not in ("y", "yes", "д", "да"):
        return
    state = _load_state()
    full = state.get("full_domain", "")
    _stop_systemd_service()
    if full:
        _remove_nginx_config(full)
        _reload_nginx()
    _MODULE_STATE.unlink(missing_ok=True)
    _ok("Модуль подписки удалён.")

def subscription_status() -> dict:
    st = _load_state()
    return {
        "enabled": st.get("enabled", False),
        "domain": st.get("full_domain", ""),
        "https_port": st.get("https_port", _DEFAULT_HTTPS),
        "users": len(st.get("users", [])),
        "service_active": _svc_active(),
    }

# ══════════════════════════════════════════════════════════════════════════════
#  ГЛАВНОЕ МЕНЮ
# ══════════════════════════════════════════════════════════════════════════════
def do_subscription_menu() -> None:
    """Точка входа из _core.py — главное меню [14]."""
    while True:
        os.system("clear")
        configured = _is_configured()
        state = _load_state()
        svc_ok = _svc_active()

        svc_str = (
            f"{GREEN}● активен{NC}" if svc_ok else
            f"{RED}● остановлен{NC}" if configured else
            f"{YELLOW}● не настроен{NC}"
        )

        _box_top("📡  ПОДПИСКА  •  Единая раздача конфигов")
        _box_row()
        _box_info(f"Статус: {svc_str}")

        if configured:
            _box_info(f"Адрес: {BOLD}{state.get('full_domain')}:{state.get('https_port')}{NC}")
            _box_info(f"Пользователей: {len(state.get('users', []))}")
            _box_desc("URI: .../<tag>  |  Sing-box: .../<tag>/singbox")
        else:
            _box_desc("Объединяет VLESS + NaiveProxy + Mieru в одну subscription-ссылку.")

        _box_row()
        _box_sep()

        if not configured:
            _box_item("1", "🚀  Настроить подписку (поддомен + TLS)")
        else:
            _box_item("1", "⚙️   Перенастроить поддомен / порт")
            _box_item("2", "👥  Управление пользователями")
            _box_item("3", "🔄  Перезапустить сервис")
            _box_item("4", "🔒  Обновить TLS-сертификат")
            _box_item("5", "📊  Статус")
            _box_sep()
            _box_item("9", f"{RED}🗑️   Удалить модуль подписки{NC}")

        _box_sep()
        _box_item("G", "📖  Гайд: как работает подписка")
        _box_sep()
        _box_item("Q", "← Назад в главное меню VLESS")
        _box_bottom()
        print()

        try:
            ch = _ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled:
            break

        if ch == "1":
            _setup_wizard()
        elif ch == "2" and configured:
            try:
                _users_menu()
            except _Cancelled:
                pass
        elif ch == "3" and configured:
            _install_systemd_service()
            _ok("Сервис перезапущен") if _svc_active() else _warn("Сервис не запустился")
            _pause()
        elif ch == "4" and configured:
            full = state.get("full_domain", "")
            if full:
                ok, err = _obtain_cert(full)
                if ok:
                    _write_nginx_config(full, state.get("https_port", _DEFAULT_HTTPS),
                                        state.get("listen_port", _DEFAULT_PORT))
                    _reload_nginx()
                    _ok("Сертификат обновлён")
                else:
                    _warn(err)
            _pause()
        elif ch == "5" and configured:
            _show_status()
        elif ch == "9" and configured:
            _uninstall()
            _pause()
        elif ch == "g":
            os.system("clear")
            _box_top("📖  ГАЙД  •  ПОДПИСКА")
            _box_row()
            _box_info("1. Настройте DNS: A-запись sub → IP VPS")
            _box_info("2. Запустите настройку [1] — certbot + nginx + сервис")
            _box_info("3. Добавьте пользователя [2] — создастся в VLESS/Naive/Mieru")
            _box_info("4. Выдайте ссылку клиенту:")
            _box_info("   URI:      https://sub.domain.com:8443/ivan")
            _box_info("   Sing-box: https://sub.domain.com:8443/ivan/singbox")
            _box_row()
            _box_info("Клиенты URI: v2rayNG, Happ, Shadowrocket")
            _box_info("Клиенты JSON: Karing, NekoBox, sing-box CLI")
            _box_info("Формат URI: base64(vless://...\\nnaive+https://...\\nmierus://...)")
            _box_info("Формат JSON: outbounds vless + naive + mieru + selector")
            _box_row()
            _box_warn("Тег в URL — секретный ключ. Не публикуйте ссылку открыто.")
            _box_bottom()
            _pause()
        elif ch in ("q", ""):
            break


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Требуются права root: sudo python3 -m vless_installer.modules.subscription")
        sys.exit(1)
    do_subscription_menu()
