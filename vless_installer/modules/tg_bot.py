"""
vless_installer/modules/tg_bot.py
───────────────────────────────────────────────────────────────────────────────
Telegram Bot — единая точка для всего, что связано с Telegram в проекте.

Объединяет и заменяет разрозненные TG_CONFIG_FILE / _tg_load / _tg_save /
tg_send / _tg_notify_event / _tg_install_monitor_cron из _core.py.
В _core.py оставляем тонкие обёртки-делегаты (2 строки), которые
импортируют функции отсюда — обратная совместимость полная.

════════════════════════════════════════════════════════════════════════════════
ЧАСТЬ 1: Уведомления (admin-only, одностороннее)
  Текущая функциональность: xray_down/up, cert_expire, traffic_limit,
  health_report, node_down — всё сохранено без изменений.

ЧАСТЬ 2: Пользовательский бот (раздача конфигов)
  Пользователь пишет боту → получает свою ссылку/QR/конфиг.
  Поддерживает все режимы: A, B, B-Multi, REALITY, xHTTP.
  Работает как systemd-сервис (long-polling), никаких внешних зависимостей
  кроме python3 и curl (уже есть на сервере).

Команды бота:
  /start       — приветствие, список команд
  /config      — VLESS-ссылка и подписки для этого пользователя (если авторизован)
  /qr          — QR-код подписки для этого пользователя
  /status      — статус сервера (только для admin chat_id)
  /users       — список пользователей (только admin)
  /invite <email> — сгенерировать invite-ссылку для конкретного пользователя Xray (только admin)
  /broadcast <текст> — рассылка всем пользователям (только admin)
  /help        — справка

Авторизация пользователей:
  Белый список Telegram user_id в tg_bot.json → "allowed_users": [123, 456]
  Или открытый режим: admin выдаёт одноразовый invite-токен через меню или бот.
  Пользователь вводит /start <token> → добавляется в allowed_users и привязывается к Xray email.

Хранение:
  /var/lib/xray-installer/tg_bot.json   — конфиг бота
  /var/lib/xray-installer/telegram.json — конфиг уведомлений (совместимость)

Публичное API (обратная совместимость с _core.py):
  tg_load()                    → dict  (= _tg_load)
  tg_save(cfg)                          (= _tg_save)
  tg_send(msg, token, chat_id) → bool  (= tg_send)
  tg_notify_event(event, detail)        (= _tg_notify_event)
  do_manage_telegram()                  — меню уведомлений (как раньше)
  do_tg_bot_menu()                      — меню бота (новое)
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

# ── Цвета ─────────────────────────────────────────────────────────────────────
def _detect_colors() -> dict:
    if sys.stdout.isatty():
        light = os.environ.get("VLESS_THEME", "").lower() == "light"
        if light:
            return dict(RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[0;33m',
                        CYAN='\033[0;34m', BLUE='\033[0;35m', BOLD='\033[1m',
                        DIM='\033[2m', WHITE='\033[0;30m', NC='\033[0m')
        return dict(RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
                    CYAN='\033[0;36m', BLUE='\033[0;34m', BOLD='\033[1m',
                    DIM='\033[2m', WHITE='\033[1;37m', NC='\033[0m')
    return {k: '' for k in ('RED','GREEN','YELLOW','CYAN','BLUE','BOLD','DIM','WHITE','NC')}

_C = _detect_colors()
RED=_C['RED']; GREEN=_C['GREEN']; YELLOW=_C['YELLOW']; CYAN=_C['CYAN']
BLUE=_C['BLUE']; BOLD=_C['BOLD']; DIM=_C['DIM']; WHITE=_C['WHITE']; NC=_C['NC']

# ── Константы ─────────────────────────────────────────────────────────────────
_NOTIF_FILE  = Path("/var/lib/xray-installer/telegram.json")   # уведомления (совместимость)
_BOT_FILE    = Path("/var/lib/xray-installer/tg_bot.json")     # бот
_STATE_FILE  = Path("/var/lib/xray-installer/state.json")
_LOG_FILE    = Path("/var/log/vless-install.log")
_BOT_SVC     = Path("/etc/systemd/system/xray-tg-bot.service")
_BOT_SCRIPT  = Path("/usr/local/bin/xray-tg-bot.py")
_ADMIN_SVC   = Path("/etc/systemd/system/xray-tg-admin.service")
_ADMIN_SCRIPT = Path("/usr/local/bin/xray-tg-admin.py")
_MONITOR_SVC = Path("/etc/cron.d/xray-tg-monitor")


# ── box_renderer ───────────────────────────────────────────────────────────────
from vless_installer.modules.box_renderer import (
    _box_top, _box_sep, _box_bottom, _box_row, _box_item,
    _box_back, _box_info, _box_warn, _box_desc,
)

# ── Логирование ────────────────────────────────────────────────────────────────
def _log(level: str, msg: str) -> None:
    try:
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        clean = re.sub(r'\x1b\[[0-9;]*m', '', msg)
        with _LOG_FILE.open("a") as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [TG] [{level}] {clean}\n")
    except Exception:
        pass

def _info(msg: str):  print(f"{CYAN}[INFO]{NC}  {msg}");   _log("INFO",    msg)
def _ok(msg: str):    print(f"{GREEN}[OK]{NC}    {msg}");  _log("SUCCESS", msg)
def _warn(msg: str):  print(f"{YELLOW}[WARN]{NC}  {msg}"); _log("WARN",    msg)
def _err(msg: str):   print(f"{RED}[ERR]{NC}   {msg}");    _log("ERROR",   msg)

def _run(cmd: list, capture: bool = False, quiet: bool = False) -> subprocess.CompletedProcess:
    kw: dict = {}
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    elif quiet:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(cmd, **kw)

# ══════════════════════════════════════════════════════════════════════════════
#  ЧАСТЬ 1: Уведомления — публичное API (обратная совместимость с _core.py)
# ══════════════════════════════════════════════════════════════════════════════

def tg_load() -> dict:
    """Загружает конфиг уведомлений. Совместим с _tg_load() из _core.py."""
    try:
        if _NOTIF_FILE.exists():
            return json.loads(_NOTIF_FILE.read_text())
    except Exception:
        pass
    return {}


def tg_save(cfg: dict) -> None:
    """Сохраняет конфиг уведомлений. Совместим с _tg_save() из _core.py."""
    _NOTIF_FILE.parent.mkdir(parents=True, exist_ok=True)
    _NOTIF_FILE.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
    _NOTIF_FILE.chmod(0o600)


def tg_send(msg: str, token: str = "", chat_id: str = "") -> bool:
    """
    Отправляет сообщение в Telegram через curl.
    Если token/chat_id не переданы — берёт из _NOTIF_FILE.
    Совместим с tg_send() из _core.py.
    """
    if not token or not chat_id:
        cfg = tg_load()
        token   = cfg.get("token", "")
        chat_id = cfg.get("chat_id", "")
    if not token or not chat_id:
        return False
    try:
        r = _run([
            "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
            "-m", "10",
            f"https://api.telegram.org/bot{token}/sendMessage",
            "-d", f"chat_id={chat_id}",
            "-d", f"text={msg}",
            "-d", "parse_mode=HTML",
        ], capture=True)
        return r.stdout.strip() == "200"
    except Exception:
        return False


def tg_notify_event(event: str, detail: str = "") -> None:
    """
    Отправляет уведомление если соответствующее событие включено.
    Совместим с _tg_notify_event() из _core.py.
    """
    cfg = tg_load()
    if not cfg.get("token") or not cfg.get("chat_id"):
        return
    events = cfg.get("events", {})
    if not events.get(event, True):
        return
    hostname = ""
    try:
        hostname = _run(["hostname", "-s"], capture=True).stdout.strip()
    except Exception:
        pass
    ts = datetime.now().strftime("%d.%m.%Y %H:%M")
    icons = {
        "xray_down":     "🔴",
        "xray_up":       "🟢",
        "cert_expire":   "🔒",
        "traffic_limit": "⚠️",
        "user_connect":  "👤",
        "health_report": "📋",
        "node_down":     "📡",
        "port_blocked":  "🚫",
        "autoban":       "🛡️",
        "port_hopping":  "⚡",
    }
    icon = icons.get(event, "ℹ️")
    text = f"{icon} <b>[{hostname}]</b> {detail}\n<i>{ts}</i>"
    tg_send(text)
    _log("INFO", f"TG notify: {event} — {detail}")


def _install_monitor_cron() -> None:
    """Устанавливает cron-скрипт мониторинга Xray (xray_down/up, cert)."""
    cfg = tg_load()
    token   = cfg.get("token", "")
    chat_id = cfg.get("chat_id", "")
    if not token or not chat_id:
        _warn("Сначала настройте токен и Chat ID")
        return

    script = Path("/usr/local/bin/xray-tg-monitor.sh")
    script.write_text(
        "#!/bin/bash\n"
        f"TOKEN=\"{token}\"\n"
        f"CHAT=\"{chat_id}\"\n"
        "send() { curl -s -o /dev/null -m 10 "
        "\"https://api.telegram.org/bot$TOKEN/sendMessage\" "
        "-d \"chat_id=$CHAT\" -d \"text=$1\" -d \"parse_mode=HTML\" || true; }\n"
        "HOST=$(hostname -s)\n"
        "TS=$(date '+%d.%m.%Y %H:%M')\n"
        "if ! systemctl is-active --quiet xray 2>/dev/null; then\n"
        "  STAMP=/tmp/xray-tg-down.stamp\n"
        "  if [ ! -f \"$STAMP\" ]; then touch \"$STAMP\";\n"
        "    send \"🔴 <b>[$HOST]</b> Xray не запущен!\\n<i>$TS</i>\"; fi\n"
        "else\n"
        "  if [ -f /tmp/xray-tg-down.stamp ]; then rm -f /tmp/xray-tg-down.stamp;\n"
        "    send \"🟢 <b>[$HOST]</b> Xray восстановился.\\n<i>$TS</i>\"; fi\n"
        "fi\n"
        "# Проверка срока сертификата (< 30 дней)\n"
        "CERT=$(find /etc/letsencrypt/live -name 'cert.pem' 2>/dev/null | head -1)\n"
        "if [ -n \"$CERT\" ]; then\n"
        "  EXP=$(openssl x509 -enddate -noout -in \"$CERT\" 2>/dev/null | cut -d= -f2)\n"
        "  if [ -n \"$EXP\" ]; then\n"
        "    DAYS=$(( ( $(date -d \"$EXP\" +%s) - $(date +%s) ) / 86400 ))\n"
        "    if [ \"$DAYS\" -lt 30 ]; then\n"
        "      send \"🔒 <b>[$HOST]</b> Сертификат истекает через $DAYS дн.\\n<i>$TS</i>\"; fi\n"
        "  fi\n"
        "fi\n"
    )
    script.chmod(0o755)

    _MONITOR_SVC.parent.mkdir(parents=True, exist_ok=True)
    _MONITOR_SVC.write_text(
        "# xray-tg-monitor — installed by vless-installer\n"
        f"*/5 * * * * root {script} 2>/dev/null\n"
    )
    _ok(f"Cron-мониторинг установлен: {script}")
    _log("INFO", "TG monitor cron installed")


# ══════════════════════════════════════════════════════════════════════════════
#  ЧАСТЬ 2: Пользовательский бот — раздача конфигов
# ══════════════════════════════════════════════════════════════════════════════

def _bot_load() -> dict:
    try:
        if _BOT_FILE.exists():
            return json.loads(_BOT_FILE.read_text())
    except Exception:
        pass
    return {}


def _bot_save(cfg: dict) -> None:
    _BOT_FILE.parent.mkdir(parents=True, exist_ok=True)
    _BOT_FILE.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
    _BOT_FILE.chmod(0o600)


def _bot_running() -> bool:
    """Проверяет, запущен ли systemd-сервис бота."""
    r = _run(["systemctl", "is-active", "--quiet", "xray-tg-bot"], quiet=False)
    return r.returncode == 0


def _load_state() -> dict:
    try:
        if _STATE_FILE.exists():
            return json.loads(_STATE_FILE.read_text())
    except Exception:
        pass
    return {}


def _get_xray_emails() -> list[str]:
    cfg_paths = [
        Path("/usr/local/etc/xray/config.json"),
        Path("/etc/xray/config.json"),
    ]
    emails = []
    for p in cfg_paths:
        if p.exists():
            try:
                cfg = json.loads(p.read_text())
                for ib in cfg.get("inbounds", []):
                    for client in ib.get("settings", {}).get("clients", []):
                        email = client.get("email")
                        if email and email not in emails:
                            emails.append(email)
            except Exception:
                pass
    st = _load_state()
    main_email = st.get("email") or "admin"
    if main_email not in emails:
        emails.append(main_email)
    return sorted(emails)


def _generate_user_bot_script(bot_cfg: dict, notif_cfg: dict) -> str:
    """
    Генерирует Python-скрипт пользовательского бота (long-polling, без внешних зависимостей).
    Скрипт запускается как systemd-сервис xray-tg-bot.
    """
    token        = bot_cfg.get("user_token") or bot_cfg.get("token") or notif_cfg.get("token", "")
    admin_id     = str(bot_cfg.get("admin_id") or notif_cfg.get("chat_id", ""))
    state_file   = str(_STATE_FILE)
    bot_file     = str(_BOT_FILE)

    script = f'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# xray-tg-bot — auto-generated by vless-installer
# НЕ РЕДАКТИРОВАТЬ ВРУЧНУЮ — перегенерируется из меню установщика

import json, os, sys, time, re, subprocess, urllib.request, urllib.parse, urllib.error
from pathlib import Path
from datetime import datetime

TOKEN    = "{token}"
ADMIN_ID = "{admin_id}"
BOT_FILE = Path("{bot_file}")
STATE_F  = Path("{state_file}")
LOG_F    = Path("/var/log/vless-install.log")
LIMITS_F = Path("/var/lib/xray-installer/traffic_limits.json")
TTL_F    = Path("/var/lib/xray-installer/ttl_users.json")
XRAY_BIN = Path("/usr/local/bin/xray")
if not XRAY_BIN.exists():
    XRAY_BIN = Path("/usr/bin/xray")
STATS_PORT = 10085
OFFSET   = 0

def _log(msg):
    try:
        with LOG_F.open("a") as f:
            f.write(f"[{{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}}] [BOT] {{msg}}\\n")
    except Exception:
        pass

def _bot_load():
    try:
        return json.loads(BOT_FILE.read_text()) if BOT_FILE.exists() else {{}}
    except Exception:
        return {{}}

def _bot_save(cfg):
    BOT_FILE.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
    BOT_FILE.chmod(0o600)

def _state():
    try:
        return json.loads(STATE_F.read_text()) if STATE_F.exists() else {{}}
    except Exception:
        return {{}}

def _bytes_human(n):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if n < 1024:
            return f"{{n:.2f}} {{unit}}" if unit != 'B' else f"{{n}} B"
        n /= 1024
    return f"{{n:.2f}} PB"

def api(method, **params):
    url = f"https://api.telegram.org/bot{{TOKEN}}/{{method}}"
    data = urllib.parse.urlencode(params).encode()
    try:
        req = urllib.request.Request(url, data=data)
        resp = urllib.request.urlopen(req, timeout=30)
        return json.loads(resp.read())
    except Exception as e:
        _log(f"API error {{method}}: {{e}}")
        return {{}}

def send(chat_id, text, parse_mode="HTML"):
    api("sendMessage", chat_id=chat_id, text=text, parse_mode=parse_mode)

def is_admin(uid):
    return str(uid) == ADMIN_ID

def is_allowed(uid):
    cfg = _bot_load()
    allowed = cfg.get("allowed_users", [])
    return str(uid) in [str(x) for x in allowed] or is_admin(uid)

def get_user_uuid(email):
    st = _state()
    if st.get("email") == email or email == "admin":
        return st.get("uuid", "")
    cfg_paths = [
        Path("/usr/local/etc/xray/config.json"),
        Path("/etc/xray/config.json"),
    ]
    for p in cfg_paths:
        if p.exists():
            try:
                cfg = json.loads(p.read_text())
                for ib in cfg.get("inbounds", []):
                    for client in ib.get("settings", {{}}).get("clients", []):
                        if client.get("email") == email:
                            return client.get("id", "")
            except Exception:
                pass
    return ""

def get_subscription_url(email):
    st = _state()
    sub_tokens = st.setdefault("sub_tokens", {{}})
    token = sub_tokens.get(email)
    if not token:
        import uuid as _uuid
        token = str(_uuid.uuid4())
        sub_tokens[email] = token
        st["sub_tokens"] = sub_tokens
        try:
            STATE_F.write_text(json.dumps(st, indent=2, ensure_ascii=False))
        except Exception:
            pass
            
    sub_domain = st.get("sub_domain", "")
    sub_port = st.get("sub_port", 9443)
    
    domain_to_use = sub_domain or st.get("domain", "")
    if not domain_to_use:
        try:
            domain_to_use = subprocess.check_output(["curl", "-s", "-4", "https://api.ipify.org"], text=True).strip()
        except Exception:
            domain_to_use = "IP_СЕРВЕРА"
            
    port_suffix = f":{{sub_port}}" if sub_port != 443 else ""
    return f"https://{{domain_to_use}}{{port_suffix}}/sub/{{token}}"

def handle_start(msg, args):
    uid  = msg["from"]["id"]
    uname = msg["from"].get("username", str(uid))
    cfg = _bot_load()

    if args:
        token_val = args[0]
        invites = cfg.get("invite_tokens", {{}})
        if token_val in invites:
            email = invites[token_val].get("email", "admin")
            allowed = cfg.get("allowed_users", [])
            if uid not in allowed:
                allowed.append(uid)
                cfg["allowed_users"] = allowed
            
            user_map = cfg.setdefault("user_map", {{}})
            user_map[str(uid)] = email
            cfg["user_map"] = user_map
            
            del invites[token_val]
            cfg["invite_tokens"] = invites
            _bot_save(cfg)
            send(uid, f"✅ Вы успешно авторизованы как пользователь <b>{{email}}</b>! Используйте /config для получения подписки.")
            _log(f"User @{{uname}} ({{uid}}) authorized as {{email}} via invite token")
            return

    if is_allowed(uid):
        send(uid, "👋 Привет! Используйте /config для получения вашей подписки или /qr для получения QR-кода.")
    else:
        send(uid, f"👋 Для доступа запросите у администратора invite-ссылку.\\nВаш ID: <code>{{uid}}</code>")

def handle_config(msg):
    uid = msg["from"]["id"]
    if not is_allowed(uid):
        send(uid, "⛔ Нет доступа. Запросите invite-ссылку у администратора.")
        return
        
    cfg = _bot_load()
    user_map = cfg.get("user_map", {{}})
    email = user_map.get(str(uid))
    
    if not email and is_admin(uid):
        st = _state()
        email = st.get("email") or "admin"
        
    if not email:
        send(uid, "⚠️ Ваша учетная запись не привязана к пользователю Xray. Обратитесь к администратору.")
        return
        
    sub_url = get_subscription_url(email)
    
    send(uid, (
        f"👤 <b>Пользователь:</b> {{email}}\\n\\n"
        f"📋 <b>Ваша подписка:</b>\\n"
        f"<code>{{sub_url}}</code>\\n\\n"
        f"📲 <b>Как подключиться:</b>\\n"
        f"1. Скопируйте ссылку выше\\n"
        f"2. Откройте ваш VPN-клиент (v2rayNG, Hiddify, Streisand, NekoBox)\\n"
        f"3. Добавьте подписку → Вставьте ссылку\\n\\n"
        f"🔄 Подписка обновляется автоматически."
    ))
    _log(f"Config sent to user {{email}} ({{uid}})")

def handle_traffic(msg):
    uid = msg["from"]["id"]
    if not is_allowed(uid):
        send(uid, "⛔ Нет доступа.")
        return
    
    cfg = _bot_load()
    email = cfg.get("user_map", {{}}).get(str(uid))
    if not email and is_admin(uid):
        st = _state()
        email = st.get("email") or "admin"
        
    if not email:
        send(uid, "⚠️ Нет привязанного аккаунта.")
        return
    
    total = 0
    for direction in ("uplink", "downlink"):
        try:
            r = subprocess.run([
                str(XRAY_BIN), "api", "statsquery",
                f"--server=127.0.0.1:{{STATS_PORT}}",
                f"--pattern=user>>>{{email}}>>>{{direction}}",
            ], capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                m = re.search(r'"value"\s*:\s*"?(\d+)"?', line)
                if m:
                    total += int(m.group(1))
        except Exception:
            pass
    
    limits = {{}}
    try:
        limits = json.loads(LIMITS_F.read_text()).get(email, {{}})
    except:
        pass
    limit_gb = limits.get("limit_gb", 0)
    
    ttl_info = ""
    try:
        ttl_data = json.loads(TTL_F.read_text()).get(email, {{}})
        expires = ttl_data.get("expires_at", "")
        if expires:
            ttl_info = f"\\n⏳ Действует до: {{expires[:10]}}"
    except:
        pass
    
    text = f"📊 <b>Ваш трафик ({{email}}):</b>\\n\\n"
    text += f"Использовано: <b>{{_bytes_human(total)}}</b>\\n"
    if limit_gb:
        limit_bytes = int(limit_gb * 1024**3)
        pct = min(100, int(total / limit_bytes * 100)) if limit_bytes else 0
        filled = pct // 10
        bar = "■" * filled + "□" * (10 - filled)
        text += f"Лимит: {{limit_gb}} GB\\n[{{bar}}] {{pct}}%\\n"
    else:
        text += "Лимит: безлимитный\\n"
    text += ttl_info
    
    send(uid, text)

def handle_qr(msg):
    uid = msg["from"]["id"]
    if not is_allowed(uid):
        send(uid, "⛔ Нет доступа.")
        return
        
    cfg = _bot_load()
    user_map = cfg.get("user_map", {{}})
    email = user_map.get(str(uid))
    if not email and is_admin(uid):
        st = _state()
        email = st.get("email") or "admin"
        
    if not email:
        send(uid, "⚠️ Нет привязанного пользователя.")
        return
        
    sub_url = get_subscription_url(email)
    qr_file = f"/tmp/user_qr_{{uid}}.png"
    
    try:
        subprocess.run(["qrencode", "-o", qr_file, "-s", "8", sub_url], check=True)
        subprocess.run([
            "curl", "-s", "-X", "POST",
            f"https://api.telegram.org/bot{{TOKEN}}/sendPhoto",
            "-F", f"chat_id={{uid}}",
            "-F", f"photo=@{{qr_file}}",
            "-F", f"caption=QR-код вашей подписки ({{email}})"
        ], stdout=subprocess.DEVNULL)
        Path(qr_file).unlink(missing_ok=True)
    except Exception as e:
        send(uid, f"❌ Ошибка генерации QR-кода: {{e}}")

def handle_help(msg):
    uid = msg["from"]["id"]
    text = (
        "📖 <b>Справка</b>\\n\\n"
        "/start  — начало работы\\n"
        "/config — получить ссылку подписки\\n"
        "/traffic — проверить использование трафика\\n"
        "/qr     — получить QR-код подписки\\n"
        "/help   — эта справка\\n"
    )
    send(uid, text)

def process_update(update):
    msg = update.get("message") or update.get("edited_message")
    if not msg or "text" not in msg:
        return
    text  = msg["text"].strip()
    parts = text.split()
    cmd   = parts[0].split("@")[0].lower() if parts else ""
    args  = parts[1:]
    if cmd == "/start":   handle_start(msg, args)
    elif cmd == "/config": handle_config(msg)
    elif cmd == "/traffic": handle_traffic(msg)
    elif cmd == "/qr":     handle_qr(msg)
    elif cmd == "/help":   handle_help(msg)

def main():
    global OFFSET
    _log("Bot started")
    while True:
        try:
            r = api("getUpdates", offset=OFFSET, timeout=25, limit=10)
            for upd in r.get("result", []):
                OFFSET = upd["update_id"] + 1
                try:
                    process_update(upd)
                except Exception as e:
                    _log(f"Update error: {{e}}")
        except Exception as e:
            _log(f"Poll error: {{e}}")
            time.sleep(5)

if __name__ == "__main__":
    main()
'''
    try:
        from vless_installer.modules.user_fp_manager import patch_tg_bot_script
        return patch_tg_bot_script(script)
    except Exception:
        return script


def _generate_admin_bot_script(bot_cfg: dict) -> str:
    """
    Генерирует Python-скрипт панели администратора (long-polling, без внешних зависимостей).
    Скрипт запускается как systemd-сервис xray-tg-admin.
    """
    token        = bot_cfg.get("admin_token", "")
    state_file   = str(_STATE_FILE)
    bot_file     = str(_BOT_FILE)

    script = f'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# xray-tg-admin — auto-generated by vless-installer
# НЕ РЕДАКТИРОВАТЬ ВРУЧНУЮ — перегенерируется из меню установщика

import json, os, sys, time, re, subprocess, urllib.request, urllib.parse, urllib.error
from pathlib import Path
from datetime import datetime

TOKEN    = "{token}"
BOT_FILE = Path("{bot_file}")
STATE_F  = Path("{state_file}")
USERS_F  = Path("/etc/xray/users.json")
CONFIG_F = Path("/etc/xray/config.json")
LIMITS_F = Path("/var/lib/xray-installer/traffic_limits.json")
TTL_F    = Path("/var/lib/xray-installer/ttl_users.json")
LOG_F    = Path("/var/log/vless-install.log")
XRAY_BIN = Path("/usr/local/bin/xray")
if not XRAY_BIN.exists():
    XRAY_BIN = Path("/usr/bin/xray")
STATS_PORT = 10085
OFFSET   = 0

def _log(msg):
    try:
        with LOG_F.open("a") as f:
            f.write(f"[{{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}}] [ADMIN_BOT] {{msg}}\\n")
    except Exception:
        pass

def _bot_load():
    try:
        return json.loads(BOT_FILE.read_text()) if BOT_FILE.exists() else {{}}
    except Exception:
        return {{}}

def _bot_save(cfg):
    BOT_FILE.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
    BOT_FILE.chmod(0o600)

def _state():
    try:
        return json.loads(STATE_F.read_text()) if STATE_F.exists() else {{}}
    except Exception:
        return {{}}

def _bytes_human(n):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if n < 1024:
            return f"{{n:.2f}} {{unit}}" if unit != 'B' else f"{{n}} B"
        n /= 1024
    return f"{{n:.2f}} PB"

def api(method, **params):
    url = f"https://api.telegram.org/bot{{TOKEN}}/{{method}}"
    data = urllib.parse.urlencode(params).encode()
    try:
        req = urllib.request.Request(url, data=data)
        resp = urllib.request.urlopen(req, timeout=30)
        return json.loads(resp.read())
    except Exception as e:
        _log(f"API error {{method}}: {{e}}")
        return {{}}

def send(chat_id, text, parse_mode="HTML"):
    api("sendMessage", chat_id=chat_id, text=text, parse_mode=parse_mode)

def is_authed(chat_id):
    cfg = _bot_load()
    return str(chat_id) in [str(x) for x in cfg.get("admin_sessions", [])]

def auth_admin(chat_id, password):
    cfg = _bot_load()
    if password and password == cfg.get("admin_password"):
        sessions = cfg.setdefault("admin_sessions", [])
        if str(chat_id) not in [str(x) for x in sessions]:
            sessions.append(str(chat_id))
            cfg["admin_sessions"] = sessions
            _bot_save(cfg)
        return True
    return False

def handle_server(chat_id):
    cpu = "❓ неизвестно"
    try:
        with open("/proc/stat") as f:
            fields = [float(column) for column in f.readline().strip().split()[1:]]
        idle, total = fields[3], sum(fields)
        time.sleep(0.5)
        with open("/proc/stat") as f:
            fields2 = [float(column) for column in f.readline().strip().split()[1:]]
        idle2, total2 = fields2[3], sum(fields2)
        idle_diff = idle2 - idle
        total_diff = total2 - total
        if total_diff > 0:
            cpu = f"{{100 * (1 - idle_diff / total_diff):.1f}}%"
    except Exception as e:
        _log(f"CPU error: {{e}}")
        
    ram = "❓ неизвестно"
    try:
        meminfo = {{}}
        with open("/proc/meminfo") as f:
            for line in f:
                parts = line.split(":")
                if len(parts) == 2:
                    meminfo[parts[0].strip()] = int(parts[1].split()[0])
        total_kb = meminfo.get("MemTotal", 0)
        avail_kb = meminfo.get("MemAvailable", 0)
        if total_kb > 0:
            used_kb = total_kb - avail_kb
            ram = f"{{used_kb/1024/1024:.2f}}/{{total_kb/1024/1024:.2f}} GB ({{100*used_kb/total_kb:.1f}}%)"
    except Exception as e:
        _log(f"RAM error: {{e}}")
        
    disk = "❓ неизвестно"
    try:
        r = subprocess.run(["df", "-h", "/"], capture_output=True, text=True, timeout=5)
        lines = r.stdout.strip().split("\\n")
        if len(lines) >= 2:
            parts = lines[1].split()
            if len(parts) >= 5:
                disk = f"{{parts[2]}}/{{parts[1]}} ({{parts[4]}} исп.)"
    except Exception as e:
        _log(f"Disk error: {{e}}")
        
    load = "❓ неизвестно"
    try:
        with open("/proc/loadavg") as f:
            load = " ".join(f.read().split()[:3])
    except Exception as e:
        _log(f"LoadAvg error: {{e}}")
        
    uptime = "❓ неизвестно"
    try:
        uptime = subprocess.check_output(["uptime", "-p"], text=True, timeout=5).strip()
    except Exception as e:
        _log(f"Uptime error: {{e}}")
        
    xray = "🔴 не активен"
    try:
        r = subprocess.run(["systemctl", "is-active", "xray"], capture_output=True, text=True, timeout=5)
        if r.stdout.strip() == "active":
            xray = "🟢 активен"
    except Exception as e:
        _log(f"Xray status error: {{e}}")
        
    text = (f"📊 <b>Информация о сервере</b>\\n\\n"
            f"💻 CPU: {{cpu}}\\n"
            f"💾 RAM: {{ram}}\\n"
            f"💽 Диск: {{disk}}\\n"
            f"⏱️ Load average: {{load}}\\n"
            f"⏰ Uptime: {{uptime}}\\n"
            f"⚙️ Xray: {{xray}}")
    send(chat_id, text)

def handle_traffic(chat_id):
    xray_lines = []
    xray_total = 0
    emails = []
    if USERS_F.exists():
        try:
            users_list = json.loads(USERS_F.read_text())
            emails = [u.get("email") for u in users_list if u.get("email")]
        except Exception as e:
            _log(f"Error reading users: {{e}}")
    if not emails:
        st = _state()
        if st.get("email"):
            emails = [st["email"]]
            
    for email in emails:
        user_total = 0
        for direction in ("uplink", "downlink"):
            try:
                r = subprocess.run([
                    str(XRAY_BIN), "api", "statsquery",
                    f"--server=127.0.0.1:{{STATS_PORT}}",
                    f"--pattern=user>>>{{email}}>>>{{direction}}",
                ], capture_output=True, text=True, timeout=5)
                for line in r.stdout.splitlines():
                    m = re.search(r'"value"\s*:\s*"?(\d+)"?', line)
                    if m:
                        user_total += int(m.group(1))
            except Exception:
                pass
        xray_total += user_total
        xray_lines.append(f"  • {{email}}: {{_bytes_human(user_total)}}")
        
    naive_total = 0
    naive_port = None
    naive_cfg_f = Path("/var/lib/xray-installer/naiveproxy.json")
    if naive_cfg_f.exists():
        try: naive_port = json.loads(naive_cfg_f.read_text()).get("port")
        except: pass
    if not naive_port:
        naive_port = _state().get("naiveproxy", {{}}).get("port")
    if naive_port:
        try:
            r = subprocess.run(["iptables", "-L", "INPUT", "-n", "-v", "-x"], capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                if f"tcp dpt:{{naive_port}}" in line or f"dpt:{{naive_port}}" in line:
                    tokens = line.split()
                    if len(tokens) >= 2:
                        naive_total += int(tokens[1])
        except Exception as e:
            _log(f"Naive traffic error: {{e}}")
            
    h2_total = 0
    h2_port = _state().get("hysteria2", {{}}).get("port")
    if h2_port:
        try:
            r = subprocess.run(["iptables", "-L", "INPUT", "-n", "-v", "-x"], capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                if f"udp dpt:{{h2_port}}" in line or f"dpt:{{h2_port}}" in line:
                    tokens = line.split()
                    if len(tokens) >= 2:
                        h2_total += int(tokens[1])
        except Exception as e:
            _log(f"H2 traffic error: {{e}}")
            
    mieru_total = 0
    mieru_port = None
    mieru_cfg_f = Path("/var/lib/xray-installer/mieru.json")
    if mieru_cfg_f.exists():
        try: mieru_port = json.loads(mieru_cfg_f.read_text()).get("port_start")
        except: pass
    if not mieru_port:
        mieru_port = _state().get("mieru", {{}}).get("port")
    if mieru_port:
        try:
            r = subprocess.run(["iptables", "-L", "INPUT", "-n", "-v", "-x"], capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                if f"dpt:{{mieru_port}}" in line:
                    tokens = line.split()
                    if len(tokens) >= 2:
                        mieru_total += int(tokens[1])
        except Exception as e:
            _log(f"Mieru traffic error: {{e}}")
            
    awg_total = 0
    awg_lines = []
    try:
        r = subprocess.run(["docker", "ps", "--filter", "name=amnezia-awg", "--filter", "status=running", "--format", "{{{{.Names}}}}"], capture_output=True, text=True, timeout=5)
        if "amnezia-awg" in r.stdout:
            r2 = subprocess.run(["docker", "exec", "amnezia-awg", "awg", "show", "awg0"], capture_output=True, text=True, timeout=5)
            cur_peer = None
            for line in r2.stdout.splitlines():
                if "peer:" in line:
                    cur_peer = line.split()[-1][:8] + "..."
                elif "transfer:" in line and cur_peer:
                    m = re.findall(r'([\d\.]+)\s+([a-zA-Z]+)', line)
                    peer_bytes = 0
                    for val_str, unit in m:
                        val = float(val_str)
                        unit_l = unit.lower()
                        if 'g' in unit_l: val *= 1024**3
                        elif 'm' in unit_l: val *= 1024**2
                        elif 'k' in unit_l: val *= 1024
                        peer_bytes += int(val)
                    awg_total += peer_bytes
                    awg_lines.append(f"  • peer {{cur_peer}}: {{_bytes_human(peer_bytes)}}")
    except Exception as e:
        _log(f"AWG traffic error: {{e}}")

    text = "📊 <b>Потребление трафика</b>\\n\\n"
    if xray_lines:
        text += "<b>Xray (по пользователям):</b>\\n" + "\\n".join(xray_lines) + f"\\nИтого Xray: {{_bytes_human(xray_total)}}\\n\\n"
    if naive_port:
        text += f"<b>NaiveProxy (порт {{naive_port}}):</b> {{_bytes_human(naive_total)}}\\n\\n"
    if h2_port:
        text += f"<b>Hysteria2 (порт {{h2_port}}):</b> {{_bytes_human(h2_total)}}\\n\\n"
    if mieru_port:
        text += f"<b>Mieru (порт {{mieru_port}}):</b> {{_bytes_human(mieru_total)}}\\n\\n"
    if awg_lines:
        text += "<b>AmneziaVPN (по пирам):</b>\\n" + "\\n".join(awg_lines) + f"\\nИтого AmneziaVPN: {{_bytes_human(awg_total)}}\\n\\n"
        
    grand_total = xray_total + naive_total + h2_total + mieru_total + awg_total
    text += f"<b>💳 ВСЕГО ПО СЕРВЕРУ:</b> {{_bytes_human(grand_total)}}"
    send(chat_id, text)

def handle_users(chat_id):
    if not USERS_F.exists():
        send(chat_id, "⚠️ Список пользователей пуст.")
        return
    try:
        users_list = json.loads(USERS_F.read_text())
    except Exception as e:
        send(chat_id, f"❌ Ошибка чтения: {{e}}")
        return
    if not users_list:
        send(chat_id, "⚠️ Нет зарегистрированных пользователей.")
        return
        
    limits = {{}}
    try:
        if LIMITS_F.exists(): limits = json.loads(LIMITS_F.read_text())
    except: pass
    ttl = {{}}
    try:
        if TTL_F.exists(): ttl = json.loads(TTL_F.read_text())
    except: pass
    
    lines = []
    for u in users_list:
        email = u.get("email", "unknown")
        uuid_short = u.get("uuid", "")[:8] + "..."
        created = u.get("created", "")
        if created: created = created[:10]
        else: created = "—"
            
        user_traffic = 0
        for direction in ("uplink", "downlink"):
            try:
                r = subprocess.run([
                    str(XRAY_BIN), "api", "statsquery",
                    f"--server=127.0.0.1:{{STATS_PORT}}",
                    f"--pattern=user>>>{{email}}>>>{{direction}}",
                ], capture_output=True, text=True, timeout=5)
                for line in r.stdout.splitlines():
                    m = re.search(r'"value"\s*:\s*"?(\d+)"?', line)
                    if m: user_traffic += int(m.group(1))
            except Exception: pass
                
        limit_gb = limits.get(email, {{}}).get("limit_gb", 0)
        limit_str = f"{{limit_gb}} GB" if limit_gb else "безлимит"
        exp = ttl.get(email, {{}}).get("expires_at", "")
        exp_str = f"до {{exp[:10]}}" if exp else "бессрочно"
        
        lines.append(
            f"👤 <b>{{email}}</b>\\n"
            f"  UUID: <code>{{uuid_short}}</code>\\n"
            f"  Создан: {{created}}\\n"
            f"  Трафик: {{_bytes_human(user_traffic)}} / {{limit_str}}\\n"
            f"  TTL: {{exp_str}}"
        )
    send(chat_id, "\\n\\n".join(lines))

def handle_adduser(chat_id, args):
    if not args:
        send(chat_id, "⚠️ Укажите email: /adduser email@domain")
        return
    email = args[0].strip()
    if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
        send(chat_id, "❌ Некорректный email.")
        return
    users = []
    if USERS_F.exists():
        try: users = json.loads(USERS_F.read_text())
        except: pass
    if any(u.get("email") == email for u in users):
        send(chat_id, f"❌ Пользователь с email {{email}} уже существует.")
        return
    import uuid
    new_uuid = str(uuid.uuid4())
    users.append({{"uuid": new_uuid, "email": email, "name": email.split("@")[0], "created": datetime.now().isoformat()}})
    try:
        USERS_F.write_text(json.dumps(users, indent=2, ensure_ascii=False))
        USERS_F.chmod(0o640)
    except Exception as e:
        send(chat_id, f"❌ Ошибка сохранения: {{e}}")
        return
        
    success = False
    written = set()
    for cfg_path in (CONFIG_F, Path("/usr/local/etc/xray/config.json")):
        if not cfg_path.exists(): continue
        try: real = str(cfg_path.resolve())
        except: real = str(cfg_path)
        if real in written: continue
        written.add(real)
        try:
            cfg = json.loads(cfg_path.read_text())
            changed = False
            for inb in cfg.get("inbounds", []):
                settings = inb.get("settings", {{}})
                if "clients" not in settings: continue
                proto = inb.get("protocol", "")
                st    = inb.get("streamSettings", {{}})
                use_flow = (proto == "vless" and "realitySettings" in st)
                
                clients = []
                for u in users:
                    client = {{"id": u["uuid"], "email": u["email"]}}
                    if use_flow:
                        st_dict = _state()
                        xtls_flow = st_dict.get("xtls_flow", "xtls-rprx-vision")
                        if xtls_flow: client["flow"] = xtls_flow
                    clients.append(client)
                settings["clients"] = clients
                changed = True
            if changed:
                cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
                success = True
        except Exception as e:
            send(chat_id, f"⚠️ Ошибка патча {{cfg_path}}: {{e}}")
            
    if success:
        r = subprocess.run(["systemctl", "restart", "xray"])
        if r.returncode == 0:
            send(chat_id, f"✅ Пользователь <b>{{email}}</b> создан.\\nUUID: <code>{{new_uuid}}</code>")
        else:
            send(chat_id, f"⚠️ Пользователь создан, но Xray не перезапустился.")
    else:
        send(chat_id, "❌ Не удалось обновить конфигурацию Xray.")

def handle_deluser(chat_id, args):
    if not args:
        send(chat_id, "⚠️ Укажите email: /deluser email@domain")
        return
    email = args[0].strip()
    users = []
    if USERS_F.exists():
        try: users = json.loads(USERS_F.read_text())
        except: pass
    found_user = None
    for u in users:
        if u.get("email") == email:
            found_user = u
            break
    if not found_user:
        send(chat_id, f"❌ Пользователь {{email}} не найден.")
        return
    users.remove(found_user)
    try:
        USERS_F.write_text(json.dumps(users, indent=2, ensure_ascii=False))
        USERS_F.chmod(0o640)
    except Exception as e:
        send(chat_id, f"❌ Ошибка сохранения: {{e}}")
        return
        
    success = False
    written = set()
    effective_users = users if users else [{{"uuid": "00000000-0000-0000-0000-000000000000", "email": "disabled@placeholder"}}]
    for cfg_path in (CONFIG_F, Path("/usr/local/etc/xray/config.json")):
        if not cfg_path.exists(): continue
        try: real = str(cfg_path.resolve())
        except: real = str(cfg_path)
        if real in written: continue
        written.add(real)
        try:
            cfg = json.loads(cfg_path.read_text())
            changed = False
            for inb in cfg.get("inbounds", []):
                settings = inb.get("settings", {{}})
                if "clients" not in settings: continue
                proto = inb.get("protocol", "")
                st    = inb.get("streamSettings", {{}})
                use_flow = (proto == "vless" and "realitySettings" in st)
                
                clients = []
                for u in effective_users:
                    client = {{"id": u["uuid"], "email": u["email"]}}
                    if use_flow:
                        st_dict = _state()
                        xtls_flow = st_dict.get("xtls_flow", "xtls-rprx-vision")
                        if xtls_flow: client["flow"] = xtls_flow
                    clients.append(client)
                settings["clients"] = clients
                changed = True
            if changed:
                cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
                success = True
        except Exception as e:
            send(chat_id, f"⚠️ Ошибка патча {{cfg_path}}: {{e}}")
            
    st = _state()
    if "sub_tokens" in st and email in st["sub_tokens"]:
        del st["sub_tokens"][email]
        try: STATE_F.write_text(json.dumps(st, indent=2, ensure_ascii=False))
        except: pass
        
    try:
        cfg = _bot_load()
        user_map = cfg.get("user_map", {{}})
        to_del = [uid for uid, em in user_map.items() if em == email]
        for uid in to_del: del user_map[uid]
        cfg["user_map"] = user_map
        _bot_save(cfg)
    except: pass

    if success:
        r = subprocess.run(["systemctl", "restart", "xray"])
        if r.returncode == 0:
            send(chat_id, f"✅ Пользователь <b>{{email}}</b> успешно удалён.")
        else:
            send(chat_id, f"⚠️ Xray не перезапустился.")
    else:
        send(chat_id, "❌ Не удалось обновить конфигурацию Xray.")

def handle_sub(chat_id, args):
    if not args:
        send(chat_id, "⚠️ Укажите email: /sub email@domain")
        return
    email = args[0].strip()
    users = []
    if USERS_F.exists():
        try: users = json.loads(USERS_F.read_text())
        except: pass
    if not any(u.get("email") == email for u in users):
        send(chat_id, f"❌ Пользователь {{email}} не найден.")
        return
    st = _state()
    sub_tokens = st.setdefault("sub_tokens", {{}})
    token = sub_tokens.get(email)
    if not token:
        import uuid
        token = str(uuid.uuid4())
        sub_tokens[email] = token
        st["sub_tokens"] = sub_tokens
        try: STATE_F.write_text(json.dumps(st, indent=2, ensure_ascii=False))
        except Exception as e:
            send(chat_id, f"❌ Ошибка сохранения: {{e}}")
            return
            
    sub_domain = st.get("sub_domain", "")
    sub_port = st.get("sub_port", 9443)
    domain_to_use = sub_domain or st.get("domain", "")
    if not domain_to_use:
        try: domain_to_use = subprocess.check_output(["curl", "-s", "-4", "https://api.ipify.org"], text=True).strip()
        except: domain_to_use = "IP_СЕРВЕРА"
            
    port_suffix = f":{{sub_port}}" if sub_port != 443 else ""
    sub_url = f"https://{{domain_to_use}}{{port_suffix}}/sub/{{token}}"
    
    text = (f"📋 <b>Подписка для {{email}}:</b>\\n\\n"
            f"Base64: <code>{{sub_url}}</code>\\n"
            f"Clash Meta: <code>{{sub_url}}/clash</code>\\n"
            f"Sing-box: <code>{{sub_url}}/singbox</code>")
    send(chat_id, text)

def handle_delsub(chat_id, args):
    if not args:
        send(chat_id, "⚠️ Укажите email: /delsub email@domain")
        return
    email = args[0].strip()
    st = _state()
    sub_tokens = st.get("sub_tokens", {{}})
    if email in sub_tokens:
        del sub_tokens[email]
        st["sub_tokens"] = sub_tokens
        try:
            STATE_F.write_text(json.dumps(st, indent=2, ensure_ascii=False))
            send(chat_id, f"✅ Подписочный токен для {{email}} удалён.")
        except Exception as e:
            send(chat_id, f"❌ Ошибка сохранения: {{e}}")
    else:
        send(chat_id, f"❌ Подписка для {{email}} не найдена.")

def handle_fail2ban(chat_id):
    status = "🔴 не активен"
    try:
        r = subprocess.run(["systemctl", "is-active", "fail2ban"], capture_output=True, text=True, timeout=5)
        if r.stdout.strip() == "active":
            status = "🟢 активен"
    except Exception as e:
        _log(f"F2B error: {{e}}")
        
    jails_lines = []
    if "активен" in status:
        try:
            r = subprocess.run(["fail2ban-client", "status"], capture_output=True, text=True, timeout=5)
            jail_list = []
            for line in r.stdout.splitlines():
                if "Jail list:" in line:
                    jails_str = line.split("Jail list:")[-1].strip()
                    jail_list = [j.strip() for j in jails_str.split(",") if j.strip()]
            for jail in jail_list:
                r_jail = subprocess.run(["fail2ban-client", "status", jail], capture_output=True, text=True, timeout=5)
                currently_banned = 0
                total_banned = 0
                for jl in r_jail.stdout.splitlines():
                    if "Currently banned:" in jl:
                        currently_banned = int(jl.split(":")[-1].strip())
                    elif "Total banned:" in jl:
                        total_banned = int(jl.split(":")[-1].strip())
                jails_lines.append(f"  • <b>{{jail}}</b>: {{currently_banned}} забанено (всего {{total_banned}})")
        except Exception as e:
            _log(f"F2B jails error: {{e}}")
            jails_lines = ["❌ Ошибка получения списка джейлов"]

    text = f"🛡️ <b>Статус Fail2ban</b>\\n\\nСтатус: {{status}}\\n\\n"
    if jails_lines: text += "<b>Джейлы:</b>\\n" + "\\n".join(jails_lines)
    else: text += "Нет активных джейлов или Fail2ban не запущен."
    send(chat_id, text)

def handle_honeypot(chat_id):
    hp_file = Path("/var/lib/xray-installer/honeypot.json")
    enabled = False
    port = "unknown"
    caught_ips = []
    if hp_file.exists():
        try:
            hp_data = json.loads(hp_file.read_text())
            enabled = hp_data.get("enabled", False)
            port = hp_data.get("port", "unknown")
            caught_ips = hp_data.get("caught_ips", [])
        except Exception as e: _log(f"Honeypot json read error: {{e}}")
            
    hp_status = "🔴 не активен"
    try:
        r = subprocess.run(["systemctl", "is-active", "xray-honeypot"], capture_output=True, text=True, timeout=5)
        if r.stdout.strip() == "active": hp_status = "🟢 активен"
    except Exception as e: _log(f"Honeypot status check error: {{e}}")
        
    caught_24h = 0
    now_ts = time.time()
    for item in caught_ips:
        ts = None
        if isinstance(item, dict):
            for k in ("time", "timestamp", "date"):
                v = item.get(k)
                if isinstance(v, (int, float)):
                    ts = v
                    break
                elif isinstance(v, str):
                    try:
                        ts = datetime.fromisoformat(v).timestamp()
                        break
                    except: pass
        if ts and (now_ts - ts) <= 24 * 3600: caught_24h += 1
            
    last_10 = []
    for item in caught_ips[-10:]:
        ip = item.get("ip") if isinstance(item, dict) else str(item)
        ts_str = ""
        v = item.get("timestamp") or item.get("time") if isinstance(item, dict) else None
        if isinstance(v, str): ts_str = f" ({{v[:16]}})"
        last_10.append(f"  • <code>{{ip}}</code>{{ts_str}}")
        
    text = (f"🍯 <b>Honeypot-порт</b>\\n\\n"
            f"Статус: {{hp_status}}\\n"
            f"Порт ловушки: {{port}}\\n"
            f"Поймано за 24ч: {{caught_24h}} IP\\n"
            f"Всего поймано: {{len(caught_ips)}} IP\\n\\n")
    if last_10: text += "<b>Последние 10 IP:</b>\\n" + "\\n".join(last_10)
    else: text += "Пока никто не попался."
    send(chat_id, text)

def handle_logs(chat_id, args):
    modules = {{
        "xray": ("journalctl -u xray -n 20 --no-pager", "Log Xray"),
        "fail2ban": ("journalctl -u fail2ban -n 20 --no-pager", "Log Fail2ban"),
        "honeypot": ("journalctl -u xray-honeypot -n 20 --no-pager", "Log Honeypot"),
        "naive": ("tail -20 /var/log/caddy-naive/access.log", "Log NaiveProxy"),
        "hysteria2": ("journalctl -u hysteria2 -n 20 --no-pager", "Log Hysteria2"),
        "mieru": ("journalctl -u mita -n 20 --no-pager", "Log Mieru"),
        "installer": ("tail -20 /var/log/vless-install.log", "Log Установщика")
    }}
    if not args:
        lines = [f"  • <code>/logs {{m}}</code> — {{desc}}" for m, (_, desc) in modules.items()]
        send(chat_id, "📋 <b>Доступные журналы логов:</b>\\n\\n" + "\\n".join(lines))
        return
    mod = args[0].strip().lower()
    if mod not in modules:
        send(chat_id, f"❌ Модуль '{{mod}}' не найден. Используйте: /logs для списка.")
        return
    cmd, desc = modules[mod]
    try:
        r = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=5)
        out = r.stdout.strip()
        if not out: out = r.stderr.strip() or "(пусто)"
        if len(out) > 3900: out = out[-3900:]
        out_escaped = out.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        send(chat_id, f"📋 <b>{{desc}} (последние строки):</b>\\n<pre>{{out_escaped}}</pre>")
    except Exception as e:
        send(chat_id, f"❌ Ошибка чтения логов: {{e}}")

def handle_notify(chat_id, args):
    if not args or args[0].strip().lower() not in ("on", "off"):
        send(chat_id, "⚠️ Использование: <code>/notify on</code> или <code>/notify off</code>")
        return
    val = args[0].strip().lower() == "on"
    cfg = {{}}
    t_file = Path("/var/lib/xray-installer/telegram.json")
    if t_file.exists():
        try: cfg = json.loads(t_file.read_text())
        except: pass
    events = cfg.get("events", {{}})
    ev_keys = ["xray_down", "xray_up", "cert_expire", "traffic_limit", "health_report", "node_down", "port_blocked", "autoban"]
    for k in ev_keys: events[k] = val
    cfg["events"] = events
    try:
        t_file.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
        state = "включены" if val else "выключены"
        send(chat_id, f"🔔 Все пуш-уведомления успешно {{state}}.")
    except Exception as e:
        send(chat_id, f"❌ Ошибка сохранения настроек: {{e}}")

def handle_logout(chat_id):
    cfg = _bot_load()
    sessions = cfg.get("admin_sessions", [])
    if str(chat_id) in [str(x) for x in sessions]:
        sessions = [x for x in sessions if str(x) != str(chat_id)]
        cfg["admin_sessions"] = sessions
        _bot_save(cfg)
        send(chat_id, "🔐 Вы вышли из сессии администратора.")
    else:
        send(chat_id, "⛔ Вы не авторизованы.")

def handle_help(chat_id):
    text = (
        "📖 <b>Панель администратора VLESS-ULTIMATE X</b>\\n\\n"
        "/server - Статус и метрики сервера\\n"
        "/traffic - Потребление трафика по протоколам\\n"
        "/users - Список пользователей Xray, трафик и TTL\\n"
        "/adduser &lt;email&gt; - Добавить нового пользователя Xray\\n"
        "/deluser &lt;email&gt; - Удалить пользователя Xray\\n"
        "/sub &lt;email&gt; - Получить ссылки подписок\\n"
        "/delsub &lt;email&gt; - Удалить токен подписки\\n"
        "/fail2ban - Статус джейлов Fail2ban\\n"
        "/honeypot - Логи ловушки Honeypot\\n"
        "/logs [модуль] - Журнал логов выбранного модуля\\n"
        "/notify on|off - Вкл/выкл уведомления в TG\\n"
        "/logout - Завершить сессию админа\\n"
    )
    send(chat_id, text)

def process_update(update):
    msg = update.get("message") or update.get("edited_message")
    if not msg or "text" not in msg:
        return
    chat_id = msg["from"]["id"]
    text = msg["text"].strip()
    parts = text.split()
    cmd = parts[0].split("@")[0].lower() if parts else ""
    args = parts[1:]
    
    if cmd == "/start":
        if args:
            if auth_admin(chat_id, args[0]):
                send(chat_id, "✅ Авторизация успешна! Введите /help для просмотра команд.")
                _log(f"Admin auth success for chat_id {{chat_id}}")
            else:
                send(chat_id, "❌ Неверный пароль панели.")
        else:
            if is_authed(chat_id):
                handle_help(chat_id)
            else:
                send(chat_id, "🔐 Введите: /start &lt;пароль&gt;")
        return
        
    if not is_authed(chat_id):
        send(chat_id, "⛔ Вы не авторизованы. Введите /start &lt;пароль&gt;")
        return
        
    if cmd == "/server": handle_server(chat_id)
    elif cmd == "/traffic": handle_traffic(chat_id)
    elif cmd == "/users": handle_users(chat_id)
    elif cmd == "/adduser": handle_adduser(chat_id, args)
    elif cmd == "/deluser": handle_deluser(chat_id, args)
    elif cmd == "/sub": handle_sub(chat_id, args)
    elif cmd == "/delsub": handle_delsub(chat_id, args)
    elif cmd == "/fail2ban": handle_fail2ban(chat_id)
    elif cmd == "/honeypot": handle_honeypot(chat_id)
    elif cmd == "/logs": handle_logs(chat_id, args)
    elif cmd == "/notify": handle_notify(chat_id, args)
    elif cmd == "/logout": handle_logout(chat_id)
    elif cmd == "/help": handle_help(chat_id)

def main():
    global OFFSET
    _log("Admin Bot started")
    while True:
        try:
            r = api("getUpdates", offset=OFFSET, timeout=25, limit=10)
            for upd in r.get("result", []):
                OFFSET = upd["update_id"] + 1
                try:
                    process_update(upd)
                except Exception as e:
                    _log(f"Update error: {{e}}")
        except Exception as e:
            _log(f"Poll error: {{e}}")
            time.sleep(5)

if __name__ == "__main__":
    main()
'''
    return script


def _install_bot_service(bot_cfg: dict) -> bool:
    """Устанавливает systemd-сервис для пользовательского бота."""
    notif_cfg = tg_load()
    script_content = _generate_user_bot_script(bot_cfg, notif_cfg)

    _BOT_SCRIPT.write_text(script_content)
    _BOT_SCRIPT.chmod(0o700)

    svc = (
        "[Unit]\n"
        "Description=VLESS Telegram Config Bot\n"
        "After=network.target\n"
        "Wants=network-online.target\n\n"
        "[Service]\n"
        "Type=simple\n"
        "ExecStart=/usr/bin/python3 /usr/local/bin/xray-tg-bot.py\n"
        "Restart=always\n"
        "RestartSec=10\n"
        "StandardOutput=journal\n"
        "StandardError=journal\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )
    _BOT_SVC.write_text(svc)
    _run(["systemctl", "daemon-reload"], quiet=True)
    _run(["systemctl", "enable", "xray-tg-bot"], quiet=True)
    r = _run(["systemctl", "restart", "xray-tg-bot"])
    time.sleep(2)
    return _bot_running()


def _stop_bot_service() -> None:
    _run(["systemctl", "stop", "xray-tg-bot"], quiet=True)
    _run(["systemctl", "disable", "xray-tg-bot"], quiet=True)
    _BOT_SCRIPT.unlink(missing_ok=True)
    _BOT_SVC.unlink(missing_ok=True)
    _run(["systemctl", "daemon-reload"], quiet=True)


def _regenerate_bot() -> bool:
    """Перегенерирует скрипт пользовательского бота."""
    bot_cfg  = _bot_load()
    notif_cfg = tg_load()
    if not (bot_cfg.get("user_token") or bot_cfg.get("token") or notif_cfg.get("token")):
        return False
    script_content = _generate_user_bot_script(bot_cfg, notif_cfg)
    _BOT_SCRIPT.write_text(script_content)
    _BOT_SCRIPT.chmod(0o700)
    if _bot_running():
        _run(["systemctl", "restart", "xray-tg-bot"], quiet=True)
        time.sleep(1)
    return True


def _admin_bot_running() -> bool:
    """Проверяет, запущен ли systemd-сервис админ-панели."""
    r = _run(["systemctl", "is-active", "--quiet", "xray-tg-admin"], quiet=False)
    return r.returncode == 0


def _install_admin_bot_service(bot_cfg: dict) -> bool:
    """Устанавливает systemd-сервис для админ-панели."""
    script_content = _generate_admin_bot_script(bot_cfg)

    _ADMIN_SCRIPT.write_text(script_content)
    _ADMIN_SCRIPT.chmod(0o700)

    svc = (
        "[Unit]\n"
        "Description=VLESS Telegram Admin Panel Bot\n"
        "After=network.target\n"
        "Wants=network-online.target\n\n"
        "[Service]\n"
        "Type=simple\n"
        "ExecStart=/usr/bin/python3 /usr/local/bin/xray-tg-admin.py\n"
        "Restart=always\n"
        "RestartSec=10\n"
        "StandardOutput=journal\n"
        "StandardError=journal\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )
    _ADMIN_SVC.write_text(svc)
    _run(["systemctl", "daemon-reload"], quiet=True)
    _run(["systemctl", "enable", "xray-tg-admin"], quiet=True)
    r = _run(["systemctl", "restart", "xray-tg-admin"])
    time.sleep(2)
    return _admin_bot_running()


def _stop_admin_bot_service() -> None:
    _run(["systemctl", "stop", "xray-tg-admin"], quiet=True)
    _run(["systemctl", "disable", "xray-tg-admin"], quiet=True)
    _ADMIN_SCRIPT.unlink(missing_ok=True)
    _ADMIN_SVC.unlink(missing_ok=True)
    _run(["systemctl", "daemon-reload"], quiet=True)


def _regenerate_admin_bot() -> bool:
    """Перегенерирует скрипт админ-панели."""
    bot_cfg = _bot_load()
    if not bot_cfg.get("admin_token"):
        return False
    script_content = _generate_admin_bot_script(bot_cfg)
    _ADMIN_SCRIPT.write_text(script_content)
    _ADMIN_SCRIPT.chmod(0o700)
    if _admin_bot_running():
        _run(["systemctl", "restart", "xray-tg-admin"], quiet=True)
        time.sleep(1)
    return True


# ══════════════════════════════════════════════════════════════════════════════
#  МЕНЮ: Уведомления (оригинальная функциональность, без изменений интерфейса)
# ══════════════════════════════════════════════════════════════════════════════

def do_manage_telegram() -> None:
    """Меню настройки Telegram Admin Panel."""
    while True:
        os.system("clear")
        bot_cfg = _bot_load()
        notif_cfg = tg_load()
        running = _admin_bot_running()
        
        token = bot_cfg.get("admin_token", "")
        password = bot_cfg.get("admin_password", "")
        configured = bool(token)
        
        print()
        _box_top("📬  TELEGRAM ADMIN PANEL")
        _box_row(f"  Статус:      {''+GREEN+'🟢 ЗАПУЩЕН'+NC if running else ''+DIM+'🔴 ОСТАНОВЛЕН'+NC}")
        _box_row(f"  Токен:       {''+DIM+token[:10]+'...'+NC if token else ''+YELLOW+'не настроен'+NC}")
        _box_row(f"  Пароль:      {''+CYAN+'●●●●●●●●●●●● (скрыт)'+NC if password else ''+YELLOW+'не сгенерирован'+NC}")
        _box_sep()
        _box_item("1", "Настроить / Изменить токен Admin Bot")
        if configured:
            _box_item("2", "Показать пароль")
            _box_item("3", "Сбросить пароль (сгенерировать новый)")
            if running:
                _box_item("4", "Перезапустить бота")
                _box_item("5", f"{RED}Остановить бота{NC}")
            else:
                _box_item("4", f"{GREEN}Запустить бота{NC}")
            _box_item("6", "Статус сервиса")
            _box_item("7", "Настройки уведомлений (вкл/выкл событий)")
            _box_item("8", "Тест — отправить тестовое сообщение")
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            return

        if ch == "1":
            print()
            new_token = input(f"  Admin Bot Token (Enter = оставить): ").strip()
            if new_token:
                bot_cfg["admin_token"] = new_token
                if "admin_password" not in bot_cfg or not bot_cfg["admin_password"]:
                    bot_cfg["admin_password"] = secrets.token_urlsafe(12)
                _bot_save(bot_cfg)
                _info("Устанавливаю systemd-сервис для Admin Panel...")
                if _install_admin_bot_service(bot_cfg):
                    _ok("Admin Bot успешно запущен!")
                    print(f"  🔑 Пароль для доступа: {GREEN}{bot_cfg['admin_password']}{NC}")
                    print(f"  ⚠️ Запишите его! Он нужен для авторизации в боте.")
                    print(f"  Напишите боту: /start {bot_cfg['admin_password']}")
                else:
                    _err("Не удалось запустить xray-tg-admin service")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "2" and configured:
            print()
            if password:
                print(f"  🔑 Текущий пароль доступа: {GREEN}{password}{NC}")
                print(f"  Для авторизации отправьте боту команду: /start {password}")
            else:
                _warn("Пароль еще не сгенерирован")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "3" and configured:
            print()
            try:
                ans = input(f"  Сгенерировать новый пароль? Сессии будут сброшены. [y/N]: ").strip().lower()
            except KeyboardInterrupt:
                continue
            if ans == "y":
                bot_cfg["admin_password"] = secrets.token_urlsafe(12)
                bot_cfg["admin_sessions"] = []
                _bot_save(bot_cfg)
                _regenerate_admin_bot()
                _ok("Новый пароль сгенерирован, все активные сессии сброшены!")
                print(f"  🔑 Новый пароль доступа: {GREEN}{bot_cfg['admin_password']}{NC}")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "4" and configured:
            if running:
                _info("Перезапускаю сервис panel bot...")
                _run(["systemctl", "restart", "xray-tg-admin"], quiet=True)
                time.sleep(2)
                _ok("Перезапущен") if _admin_bot_running() else _warn("Не запустился — см. journalctl -u xray-tg-admin")
            else:
                _info("Запускаю сервис panel bot...")
                _run(["systemctl", "start", "xray-tg-admin"], quiet=True)
                time.sleep(2)
                _ok("Запущен") if _admin_bot_running() else _warn("Не запустился")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "5" and configured and running:
            try:
                ans = input(f"  Остановить Admin Bot? [y/N]: ").strip().lower()
            except KeyboardInterrupt:
                continue
            if ans == "y":
                _stop_admin_bot_service()
                _ok("Бот остановлен")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "6" and configured:
            os.system("clear")
            print()
            _box_top("🔍  Статус сервиса xray-tg-admin")
            _box_bottom()
            print()
            _run(["systemctl", "status", "xray-tg-admin", "--no-pager", "-l"])
            print()
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "7" and configured:
            ev_keys = ["xray_down","xray_up","cert_expire","traffic_limit",
                       "health_report","node_down","port_blocked","autoban"]
            ev_labels = [
                "Xray упал","Xray восстановился","Сертификат истекает",
                "Лимит трафика","Daily health-отчёт","Exit-нода недоступна",
                "Порт заблокирован ТСПУ","AutoBan — IP забанен",
            ]
            events = notif_cfg.get("events", {k: True for k in ev_keys})
            print()
            _box_top("Уведомления — вкл/выкл событий")
            for i, (k, lbl) in enumerate(zip(ev_keys, ev_labels), 1):
                en = events.get(k, True)
                _box_item(f"{i}", f"{''+GREEN+'[ВКЛ]'+NC if en else ''+DIM+'[ВЫКЛ]'+NC} {lbl}")
            _box_back()
            _box_bottom()
            raw = input("  Номер для переключения (Enter = выход): ").strip()
            if raw.isdigit() and 1 <= int(raw) <= len(ev_keys):
                k = ev_keys[int(raw)-1]
                events[k] = not events.get(k, True)
                notif_cfg["events"] = events
                tg_save(notif_cfg)
                _ok(f"{'Включено' if events[k] else 'Выключено'}: {ev_labels[int(raw)-1]}")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "8" and configured:
            if not notif_cfg.get("token") or not notif_cfg.get("chat_id"):
                tok = token
                chat = bot_cfg.get("admin_id", "")
            else:
                tok = notif_cfg.get("token")
                chat = notif_cfg.get("chat_id")
            
            if not tok or not chat:
                _warn("Для отправки теста настройте Chat ID в уведомлениях или боте.")
            else:
                _info("Отправка тестового сообщения...")
                ok = tg_send(
                    "✅ <b>VLESS-ULTIMATE X</b>: тестовое сообщение Admin Panel. Уведомления работают!",
                    tok, chat
                )
                _ok("Сообщение отправлено!") if ok else _warn("Ошибка — проверьте настройки бота/уведомлений")
            input(f"{BLUE}Нажмите Enter...{NC}")

# ══════════════════════════════════════════════════════════════════════════════
#  МЕНЮ: Пользовательский бот
# ══════════════════════════════════════════════════════════════════════════════

def do_tg_bot_menu() -> None:
    """Меню управления Telegram Config Bot."""

    while True:
        os.system("clear")
        bot_cfg   = _bot_load()
        notif_cfg = tg_load()
        running   = _bot_running()

        token     = bot_cfg.get("token") or notif_cfg.get("token", "")
        admin_id  = bot_cfg.get("admin_id") or notif_cfg.get("chat_id", "")
        allowed   = bot_cfg.get("allowed_users", [])
        invites   = bot_cfg.get("invite_tokens", {})

        configured = bool(token and admin_id)

        print()
        _box_top("🤖  TELEGRAM CONFIG BOT — раздача конфигов пользователям")
        _box_desc(
            "Пользователь пишет боту /config → получает свою VLESS-ссылку и подписки. "
            "Администратор управляет доступом через invite-ссылки, привязанные к пользователям Xray."
        )
        _box_sep()
        _box_row(f"  Статус бота:      {''+GREEN+'ЗАПУЩЕН'+NC if running else ''+DIM+'ОСТАНОВЛЕН'+NC}")
        _box_row(f"  Конфиг:           {''+GREEN+'НАСТРОЕН'+NC if configured else ''+YELLOW+'НЕ НАСТРОЕН'+NC}")
        if configured:
            _box_row(f"  Токен:            {DIM}{token[:10]}...{NC}")
            _box_row(f"  Admin Chat ID:    {CYAN}{admin_id}{NC}")
            _box_row(f"  Авторизовано:     {CYAN}{len(allowed)}{NC} пользователей")
            if invites:
                _box_row(f"  Активных invite:  {YELLOW}{len(invites)}{NC}")
        _box_sep()
        if not configured:
            _box_item("1", f"Настроить бота (токен + admin ID)")
        else:
            _box_item("1", f"Изменить настройки")
            if running:
                _box_item("2", f"Перезапустить бота")
                _box_item("3", f"{RED}Остановить бота{NC}")
            else:
                _box_item("2", f"{GREEN}Запустить бота{NC}")
            _box_item("4", f"Создать invite-ссылку для пользователя Xray")
            _box_item("5", f"Список авторизованных пользователей")
            _box_item("6", f"Удалить пользователя из списка")
            _box_item("7", f"Проверить статус сервиса")
        _box_sep()
        _box_info("Бот работает как systemd-сервис xray-tg-bot")
        _box_info("Токен: @BotFather → /newbot")
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            return

        if ch == "1":
            _menu_bot_configure(bot_cfg, notif_cfg)
        elif ch == "2" and configured:
            if running:
                _info("Перезапускаю...")
                _run(["systemctl", "restart", "xray-tg-bot"], quiet=True)
                time.sleep(2)
                _ok("Перезапущен") if _bot_running() else _warn("Не запустился — см. journalctl -u xray-tg-bot")
            else:
                _menu_bot_start(bot_cfg)
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "3" and configured and running:
            _menu_bot_stop()
        elif ch == "4" and configured:
            _menu_bot_invite(bot_cfg, token, admin_id)
        elif ch == "5" and configured:
            _menu_bot_list_users(bot_cfg)
        elif ch == "6" and configured:
            _menu_bot_remove_user(bot_cfg)
        elif ch == "7" and configured:
            _menu_bot_svc_status()
        elif ch in ("q", "Q", "0", ""):
            return
        else:
            _warn("Неверный выбор")
            time.sleep(1)


def _menu_bot_configure(bot_cfg: dict, notif_cfg: dict) -> None:
    """Настройка токена и admin ID."""
    os.system("clear")
    print()
    _box_top("🤖  Настройка Telegram Bot")
    _box_desc(
        "Создайте бота через @BotFather (/newbot). "
        "Если токен тот же что для уведомлений — можно использовать один бот. "
        "Admin Chat ID — ваш личный Telegram ID (узнать: @userinfobot)."
    )
    _box_sep()
    cur_token    = bot_cfg.get("token") or notif_cfg.get("token", "")
    cur_admin_id = bot_cfg.get("admin_id") or notif_cfg.get("chat_id", "")
    if cur_token:
        _box_row(f"  Текущий токен:    {DIM}{cur_token[:10]}...{NC}")
    if cur_admin_id:
        _box_row(f"  Текущий admin ID: {CYAN}{cur_admin_id}{NC}")
    _box_bottom()
    print()

    try:
        new_token = input(f"  Bot Token [{DIM}Enter = оставить{NC}]: ").strip()
        new_admin = input(f"  Admin Chat ID [{DIM}Enter = оставить{NC}]: ").strip()
    except KeyboardInterrupt:
        return

    if new_token:
        bot_cfg["token"] = new_token
    elif cur_token and not bot_cfg.get("token"):
        bot_cfg["token"] = cur_token

    if new_admin:
        bot_cfg["admin_id"] = new_admin
    elif cur_admin_id and not bot_cfg.get("admin_id"):
        bot_cfg["admin_id"] = cur_admin_id

    if not bot_cfg.get("token") or not bot_cfg.get("admin_id"):
        _warn("Токен и Admin ID обязательны")
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    _bot_save(bot_cfg)

    # Синхронизируем токен в уведомлениях если это тот же токен
    if bot_cfg["token"] == notif_cfg.get("token") or not notif_cfg.get("token"):
        notif_cfg["token"]   = bot_cfg["token"]
        notif_cfg["chat_id"] = bot_cfg["admin_id"]
        tg_save(notif_cfg)

    print()
    _info("Устанавливаю systemd-сервис бота...")
    if _install_bot_service(bot_cfg):
        _ok("Бот запущен!")
        print()
        # Проверяем токен через getMe
        r = _run([
            "curl", "-s", "-m", "10",
            f"https://api.telegram.org/bot{bot_cfg['token']}/getMe"
        ], capture=True)
        try:
            data = json.loads(r.stdout)
            if data.get("ok"):
                uname = data["result"].get("username", "")
                _ok(f"Бот: @{uname}")
                _box_top("📋  Готово!")
                _box_row(f"  Ссылка на бота: {CYAN}https://t.me/{uname}{NC}")
                _box_info(f"Напишите боту /start для проверки")
                _box_info(f"Admin Chat ID {bot_cfg['admin_id']} имеет полный доступ")
                _box_bottom()
            else:
                _warn("Бот запущен, но токен может быть неверным")
        except Exception:
            _ok("Бот запущен (не удалось проверить токен)")
    else:
        _err("Бот не запустился — проверьте journalctl -u xray-tg-bot")

    input(f"\n{BLUE}Нажмите Enter...{NC}")


def _menu_bot_start(bot_cfg: dict) -> None:
    _info("Запускаю бота...")
    if _install_bot_service(bot_cfg):
        _ok("Бот запущен")
    else:
        _err("Не удалось запустить — проверьте journalctl -u xray-tg-bot")


def _menu_bot_stop() -> None:
    try:
        ans = input(f"  {YELLOW}Остановить бота? [y/N]:{NC} ").strip().lower()
    except KeyboardInterrupt:
        return
    if ans == "y":
        _stop_bot_service()
        _ok("Бот остановлен и удалён из автозапуска")
    input(f"{BLUE}Нажмите Enter...{NC}")


def _menu_bot_invite(bot_cfg: dict, token: str, admin_id: str) -> None:
    """Создаёт одноразовый invite-токен и показывает ссылку."""
    emails = _get_xray_emails()
    if not emails:
        _warn("Сначала добавьте пользователей в xray")
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    os.system("clear")
    print()
    _box_top("Создать invite-ссылку")
    _box_row("Выберите пользователя Xray, для которого создается ссылка:")
    _box_sep()
    for i, e in enumerate(emails, 1):
        _box_row(f"  {i}. {CYAN}{e}{NC}")
    _box_back()
    _box_bottom()
    
    try:
        raw = input(f"  Выбор (Enter = отмена): ").strip()
    except KeyboardInterrupt:
        return
        
    if not raw:
        return
        
    if not raw.isdigit() or not (1 <= int(raw) <= len(emails)):
        _warn("Неверный выбор")
        time.sleep(1.5)
        return
        
    email = emails[int(raw)-1]

    # Получаем username бота
    bot_username = ""
    try:
        r = _run([
            "curl", "-s", "-m", "10",
            f"https://api.telegram.org/bot{token}/getMe"
        ], capture=True)
        data = json.loads(r.stdout)
        if data.get("ok"):
            bot_username = data["result"].get("username", "")
    except Exception:
        pass

    tok = secrets.token_urlsafe(12)
    invites = bot_cfg.get("invite_tokens", {})
    invites[tok] = {
        "created": datetime.now().isoformat(),
        "by": "admin_menu",
        "email": email
    }
    bot_cfg["invite_tokens"] = invites
    _bot_save(bot_cfg)
    _regenerate_bot()

    print()
    _ok(f"Invite-токен для {email} создан")
    print()
    if bot_username:
        invite_link = f"https://t.me/{bot_username}?start={tok}"
        _box_top(f"📋  Invite-ссылка ({email})")
        _box_row(f"  {CYAN}{invite_link}{NC}")
        _box_info("Одноразовая — после использования удаляется")
        _box_info("Отправьте пользователю — он нажмёт и получит доступ к /config")
        _box_bottom()
    else:
        _box_top(f"📋  Invite-токен ({email})")
        _box_row(f"  Токен: {CYAN}{tok}{NC}")
        _box_info("Пользователь должен написать боту: /start <токен>")
        _box_bottom()

    # Уведомляем себя в TG
    if bot_username:
        tg_send(
            f"🔑 <b>Новая invite-ссылка для {email} создана:</b>\n\nhttps://t.me/{bot_username}?start={tok}",
            token, admin_id
        )

    input(f"\n{BLUE}Нажмите Enter...{NC}")


def _menu_bot_list_users(bot_cfg: dict) -> None:
    os.system("clear")
    print()
    allowed = bot_cfg.get("allowed_users", [])
    user_map = bot_cfg.get("user_map", {})
    _box_top("👥  Авторизованные пользователи")
    if not allowed:
        _box_row(f"  {DIM}(пусто){NC}")
    else:
        for i, uid in enumerate(allowed, 1):
            email = user_map.get(str(uid)) or "admin / не привязан"
            _box_row(f"  {i}. {CYAN}{uid}{NC} ➔ {GREEN}{email}{NC}")
    _box_bottom()
    print()
    input(f"{BLUE}Нажмите Enter...{NC}")


def _menu_bot_remove_user(bot_cfg: dict) -> None:
    allowed = bot_cfg.get("allowed_users", [])
    user_map = bot_cfg.get("user_map", {})
    if not allowed:
        _warn("Список пользователей пуст")
        time.sleep(1)
        return
    print()
    _box_top("Удалить пользователя")
    for i, uid in enumerate(allowed, 1):
        email = user_map.get(str(uid)) or "admin / не привязан"
        _box_row(f"  {i}. {uid} ({email})")
    _box_back()
    _box_bottom()
    try:
        raw = input(f"  Номер (Enter = отмена): ").strip()
    except KeyboardInterrupt:
        return
    if raw.isdigit() and 1 <= int(raw) <= len(allowed):
        removed = allowed.pop(int(raw)-1)
        bot_cfg["allowed_users"] = allowed
        if str(removed) in user_map:
            del user_map[str(removed)]
        bot_cfg["user_map"] = user_map
        _bot_save(bot_cfg)
        _regenerate_bot()
        _ok(f"Удалён: {removed}")
    time.sleep(1)


def _menu_bot_svc_status() -> None:
    os.system("clear")
    print()
    _box_top("🔍  Статус сервиса xray-tg-bot")
    _box_bottom()
    print()
    _run(["systemctl", "status", "xray-tg-bot", "--no-pager", "-l"])
    print()
    input(f"{BLUE}Нажмите Enter...{NC}")


# ── Алиасы для обратной совместимости с _core.py ──────────────────────────────
TG_CONFIG_FILE = _NOTIF_FILE  # совместимость
_tg_load       = tg_load
_tg_save       = tg_save
_tg_notify_event = tg_notify_event
