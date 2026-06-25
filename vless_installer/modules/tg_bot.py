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
    """Устанавливает cron-скрипт мониторинга (cert)."""
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
        "# tg-monitor — installed by installer\n"
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
    st = _load_state()
    sub_tokens = st.get("sub_tokens", {})
    emails = list(sub_tokens.keys())
    main_email = st.get("email") or "admin"
    if main_email not in emails:
        emails.append(main_email)
    return sorted(emails)


def _generate_user_bot_script(bot_cfg: dict, notif_cfg: dict) -> str:
    """
    Генерирует легковесный скрипт-обертку для пользовательского бота.
    """
    return """#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
sys.path.insert(0, "/opt/vless-ultimate")
from vless_installer.modules.tg_bot import run_user_bot
if __name__ == "__main__":
    run_user_bot()
"""


def _generate_admin_bot_script(bot_cfg: dict) -> str:
    """
    Генерирует легковесный скрипт-обертку для админ-бота.
    """
    return """#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
sys.path.insert(0, "/opt/vless-ultimate")
from vless_installer.modules.tg_bot import run_admin_bot
if __name__ == "__main__":
    run_admin_bot()
"""


def run_admin_bot():
    import json, os, sys, time, re, subprocess, urllib.request, urllib.parse, socket
    from pathlib import Path
    from datetime import datetime, timezone, timedelta

    socket.setdefaulttimeout(35)
    
    bot_file = Path("/var/lib/xray-installer/tg_bot.json")
    state_file = Path("/var/lib/xray-installer/state.json")
    log_file = Path("/var/log/vless-install.log")
    
    if not bot_file.exists():
        print("Error: tg_bot.json not found")
        sys.exit(1)
        
    bot_cfg = json.loads(bot_file.read_text(encoding="utf-8"))
    token = bot_cfg.get("admin_token", "")
    if not token:
        print("Error: admin_token not found in tg_bot.json")
        sys.exit(1)
        
    USER_STATES = {}

    def _log(msg):
        try:
            with log_file.open("a", encoding="utf-8") as f:
                f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ADMIN_BOT] {msg}\n")
        except Exception:
            pass

    def _state():
        try:
            state = json.loads(state_file.read_text(encoding="utf-8")) if state_file.exists() else {}
            users_db = state.setdefault("users", {})
            sub_tokens = state.setdefault("sub_tokens", {})
            changed = False
            for email, token in sub_tokens.items():
                if email not in users_db:
                    users_db[email] = {
                        "token": token,
                        "created_at": datetime.now().isoformat(),
                        "expires_at": "",
                        "limit_gb": 0,
                        "is_blocked": False,
                        "block_reason": "",
                        "traffic_baseline": 0,
                        "traffic_accumulated": 0,
                        "previous_live": 0
                    }
                    changed = True
            if changed:
                _save_state(state)
            return state
        except Exception:
            return {}

    def _save_state(state):
        try:
            state_file.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception as e:
            _log(f"Error saving state: {e}")

    def _bytes_human(n):
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if n < 1024:
                return f"{n:.2f} {unit}" if unit != 'B' else f"{n} B"
            n /= 1024
        return f"{n:.2f} PB"

    def api(method, **params):
        url = f"https://api.telegram.org/bot{token}/{method}"
        if "reply_markup" in params and isinstance(params["reply_markup"], dict):
            params["reply_markup"] = json.dumps(params["reply_markup"])
        data = urllib.parse.urlencode(params).encode()
        try:
            req = urllib.request.Request(url, data=data)
            resp = urllib.request.urlopen(req, timeout=30)
            return json.loads(resp.read())
        except Exception as e:
            _log(f"API error {method}: {e}")
            return {}

    def send(chat_id, text, reply_markup=None):
        params = {"chat_id": chat_id, "text": text, "parse_mode": "HTML"}
        if reply_markup:
            params["reply_markup"] = reply_markup
        return api("sendMessage", **params)

    def edit(chat_id, message_id, text, reply_markup=None):
        params = {"chat_id": chat_id, "message_id": message_id, "text": text, "parse_mode": "HTML"}
        if reply_markup:
            params["reply_markup"] = reply_markup
        return api("editMessageText", **params)

    def is_authed(chat_id):
        cfg = json.loads(bot_file.read_text(encoding="utf-8")) if bot_file.exists() else {}
        return str(chat_id) in [str(x) for x in cfg.get("admin_sessions", [])]

    def auth_admin(chat_id, password):
        cfg = json.loads(bot_file.read_text(encoding="utf-8")) if bot_file.exists() else {}
        if password and password == cfg.get("admin_password"):
            sessions = cfg.setdefault("admin_sessions", [])
            if str(chat_id) not in [str(x) for x in sessions]:
                sessions.append(str(chat_id))
                cfg["admin_sessions"] = sessions
                bot_file.write_text(json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")
                bot_file.chmod(0o600)
            return True
        return False

    def show_users_page(chat_id, page=1, message_id=None):
        state = _state()
        users_db = state.get("users", {})
        if not users_db:
            users_db = {email: {"token": tok} for email, tok in state.get("sub_tokens", {}).items()}
            
        emails = sorted(list(users_db.keys()))
        if not emails:
            text = "⚠️ Список пользователей пуст."
            if message_id:
                edit(chat_id, message_id, text)
            else:
                send(chat_id, text)
            return

        per_page = 5
        total_pages = (len(emails) + per_page - 1) // per_page
        if page < 1: page = 1
        if page > total_pages: page = total_pages

        start = (page - 1) * per_page
        end = start + per_page
        page_emails = emails[start:end]

        text = f"👤 <b>Список пользователей</b> (Страница {page}/{total_pages}):\nВыберите пользователя для управления:"
        
        inline_keyboard = []
        for email in page_emails:
            udata = users_db[email]
            status_emoji = "🔴" if udata.get("is_blocked") else "🟢"
            inline_keyboard.append([{"text": f"{status_emoji} {email}", "callback_data": f"admin:user:view:{email}:{page}"}])

        nav_buttons = []
        if page > 1:
            nav_buttons.append({"text": "« Пред.", "callback_data": f"admin:users:page:{page-1}"})
        nav_buttons.append({"text": f"{page}/{total_pages}", "callback_data": "admin:users:noop"})
        if page < total_pages:
            nav_buttons.append({"text": "След. »", "callback_data": f"admin:users:page:{page+1}"})

        inline_keyboard.append(nav_buttons)
        inline_keyboard.append([{"text": "❌ Закрыть", "callback_data": "admin:users:close"}])

        reply_markup = {"inline_keyboard": inline_keyboard}
        if message_id:
            edit(chat_id, message_id, text, reply_markup)
        else:
            send(chat_id, text, reply_markup)

    def show_user_details(chat_id, email, message_id, page=1):
        state = _state()
        users_db = state.get("users", {})
        if email not in users_db:
            text = f"❌ Пользователь <b>{email}</b> не найден."
            reply_markup = {"inline_keyboard": [[{"text": "🔙 Назад к списку", "callback_data": f"admin:users:page:{page}"}]]}
            edit(chat_id, message_id, text, reply_markup)
            return

        udata = users_db[email]
        token = udata.get("token", "")
        
        sys.path.insert(0, "/opt/vless-ultimate")
        try:
            from vless_installer.modules.user_lifecycle import get_user_cumulative_traffic
            used_bytes = get_user_cumulative_traffic(email, state)
        except Exception:
            used_bytes = udata.get("used_bytes", 0)

        limit_gb = udata.get("limit_gb", 0)
        limit_str = f"{limit_gb} GB" if limit_gb else "безлимит"
        expires_at_str = udata.get("expires_at", "")
        
        def get_expires_desc(iso):
            if not iso:
                return "бессрочно"
            try:
                exp = datetime.fromisoformat(iso)
                now = datetime.now(timezone.utc)
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=timezone.utc)
                delta = exp - now
                total = int(delta.total_seconds())
                if total <= 0:
                    return f"ИСТЁК ({exp.strftime('%Y-%m-%d %H:%M')})"
                days = total // 86400
                hours = (total % 86400) // 3600
                if days > 0:
                    return f"{days}д {hours}ч ({exp.strftime('%Y-%m-%d %H:%M')})"
                return f"{hours}ч (истекает сегодня)"
            except Exception:
                return iso

        exp_str = get_expires_desc(expires_at_str)
        is_blocked = udata.get("is_blocked", False)
        
        status_str = f"🟢 Активен"
        if is_blocked:
            reason = udata.get("block_reason", "Причина неизвестна")
            status_str = f"🔴 Заблокирован ({reason})"

        sub_domain = state.get("sub_domain", "")
        domain_to_use = sub_domain or state.get("domain", "")
        if not domain_to_use:
            try:
                domain_to_use = subprocess.check_output(["curl", "-s", "-4", "https://api.ipify.org"], text=True, timeout=5).strip()
            except Exception:
                domain_to_use = "IP_СЕРВЕРА"
        
        sub_url = f"https://{domain_to_use}/sub/{token}"
        sub_url_pc = f"{sub_url}/pc"

        text = (
            f"👤 <b>Пользователь:</b> <code>{email}</code>\n"
            f"──────────────────\n"
            f"🔑 <b>Токен:</b> <code>{token}</code>\n"
            f"📱 <b>Mobile подписка:</b>\n<code>{sub_url}</code>\n"
            f"💻 <b>PC подписка:</b>\n<code>{sub_url_pc}</code>\n\n"
            f"📊 <b>Трафик:</b> { _bytes_human(used_bytes) } / {limit_str}\n"
            f"⏳ <b>Срок действия (TTL):</b> {exp_str}\n"
            f"⚠️ <b>Статус:</b> {status_str}"
        )

        inline_keyboard = []
        if is_blocked:
            inline_keyboard.append([{"text": "🔓 Разблокировать", "callback_data": f"admin:user:unblock:{email}:{page}"}])
        else:
            inline_keyboard.append([{"text": "🔒 Заблокировать", "callback_data": f"admin:user:block:{email}:{page}"}])

        inline_keyboard.append([
            {"text": "⏳ Изменить TTL", "callback_data": f"admin:user:ttlmenu:{email}:{page}"},
            {"text": "💳 Изменить лимит", "callback_data": f"admin:user:limitmenu:{email}:{page}"}
        ])

        inline_keyboard.append([{"text": "❌ Удалить пользователя", "callback_data": f"admin:user:delete:{email}:{page}"}])
        inline_keyboard.append([{"text": "🔙 Назад к списку", "callback_data": f"admin:users:page:{page}"}])

        reply_markup = {"inline_keyboard": inline_keyboard}
        edit(chat_id, message_id, text, reply_markup)

    def show_user_details_new(chat_id, email, page=1):
        res = send(chat_id, "Загрузка...")
        msg_id = res.get("result", {}).get("message_id")
        if msg_id:
            show_user_details(chat_id, email, msg_id, page)

    def show_ttl_menu(chat_id, email, message_id, page):
        text = f"⏳ <b>Изменение TTL для {email}</b>\nВыберите срок действия:"
        inline_keyboard = [
            [
                {"text": "1 день", "callback_data": f"admin:user:ttlset:{email}:1:{page}"},
                {"text": "7 дней", "callback_data": f"admin:user:ttlset:{email}:7:{page}"}
            ],
            [
                {"text": "30 дней", "callback_data": f"admin:user:ttlset:{email}:30:{page}"},
                {"text": "90 дней", "callback_data": f"admin:user:ttlset:{email}:90:{page}"}
            ],
            [{"text": "♾️ Сделать бессрочным (снять TTL)", "callback_data": f"admin:user:ttlset:{email}:0:{page}"}],
            [{"text": "✍️ Свой вариант (ввести в чат)", "callback_data": f"admin:user:ttlcustom:{email}:{page}"}],
            [{"text": "🔙 Отмена", "callback_data": f"admin:user:view:{email}:{page}"}]
        ]
        edit(chat_id, message_id, text, {"inline_keyboard": inline_keyboard})

    def show_limit_menu(chat_id, email, message_id, page):
        text = f"💳 <b>Изменение лимита трафика для {email}</b>\nВыберите лимит:"
        inline_keyboard = [
            [
                {"text": "5 ГБ", "callback_data": f"admin:user:limitset:{email}:5:{page}"},
                {"text": "10 ГБ", "callback_data": f"admin:user:limitset:{email}:10:{page}"}
            ],
            [
                {"text": "50 ГБ", "callback_data": f"admin:user:limitset:{email}:50:{page}"},
                {"text": "100 ГБ", "callback_data": f"admin:user:limitset:{email}:100:{page}"}
            ],
            [{"text": "♾️ Снять лимит (безлимит)", "callback_data": f"admin:user:limitset:{email}:0:{page}"}],
            [{"text": "✍️ Свой вариант (ввести в чат)", "callback_data": f"admin:user:limitcustom:{email}:{page}"}],
            [{"text": "🔙 Отмена", "callback_data": f"admin:user:view:{email}:{page}"}]
        ]
        edit(chat_id, message_id, text, {"inline_keyboard": inline_keyboard})

    def show_security_panel(chat_id, message_id=None):
        f2b_status = "🔴 не активен"
        try:
            r = subprocess.run(["systemctl", "is-active", "fail2ban"], capture_output=True, text=True, timeout=5)
            if r.stdout.strip() == "active":
                f2b_status = "🟢 активен"
        except Exception: pass
            
        jails_lines = []
        if "активен" in f2b_status:
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
                    jails_lines.append(f"  • <b>{jail}</b>: {currently_banned} забанено (всего {total_banned})")
            except Exception: pass

        hp_file = Path("/var/lib/xray-installer/honeypot.json")
        hp_port = "unknown"
        banned = {}
        if hp_file.exists():
            try:
                hp_data = json.loads(hp_file.read_text())
                hp_port = hp_data.get("port", "unknown")
                banned = hp_data.get("banned", {})
            except Exception: pass
                
        hp_status = "🔴 не активен"
        try:
            r = subprocess.run(["systemctl", "is-active", "xray-honeypot"], capture_output=True, text=True, timeout=5)
            if r.stdout.strip() == "active": hp_status = "🟢 активен"
        except Exception: pass
            
        caught_24h = 0
        now_ts = time.time()
        for ip, meta in banned.items():
            ts_str = meta.get("banned_at")
            if ts_str:
                try:
                    ts = datetime.fromisoformat(ts_str).timestamp()
                    if (now_ts - ts) <= 24 * 3600: caught_24h += 1
                except: pass

        text = (
            f"🛡️ <b>Панель безопасности</b>\n\n"
            f"🔒 <b>Fail2ban:</b> {f2b_status}\n"
        )
        if jails_lines:
            text += "\n".join(jails_lines) + "\n"
        else:
            text += "  Нет активных джейлов.\n"
            
        text += (
            f"\n🍯 <b>Honeypot (ловушка):</b> {hp_status}\n"
            f"  Порт ловушки: {hp_port}\n"
            f"  Поймано за 24ч: {caught_24h} IP\n"
            f"  Всего поймано: {len(banned)} IP\n"
        )
        
        inline_keyboard = [
            [
                {"text": "🛡️ Fail2ban Logs", "callback_data": "admin:security:log:fail2ban"},
                {"text": "🍯 Honeypot Logs", "callback_data": "admin:security:log:honeypot"}
            ],
            [{"text": "📄 Installer Logs", "callback_data": "admin:security:log:installer"}],
            [{"text": "❌ Close", "callback_data": "admin:users:close"}]
        ]
        
        if message_id:
            edit(chat_id, message_id, text, {"inline_keyboard": inline_keyboard})
        else:
            send(chat_id, text, {"inline_keyboard": inline_keyboard})

    def handle_traffic(chat_id):
        sys.path.insert(0, "/opt/vless-ultimate")
        try:
            from vless_installer.modules.user_lifecycle import get_naive_traffic_by_user
            naive_users = get_naive_traffic_by_user()
            naive_total = sum(naive_users.values())
        except Exception: naive_total = 0

        try:
            from vless_installer.modules.user_lifecycle import get_mieru_traffic_by_user
            mieru_users = get_mieru_traffic_by_user()
            mieru_total = sum(mieru_users.values())
        except Exception: Mieru_total = 0
        mieru_total = locals().get("mieru_total") or 0

        try:
            from vless_installer.modules.user_lifecycle import get_awg_traffic_all_users
            awg_users = get_awg_traffic_all_users()
            awg_total = sum(awg_users.values())
        except Exception: awg_total = 0

        grand_total = naive_total + mieru_total + awg_total

        text = (
            f"📊 <b>Потребление трафика по протоколам</b>\n\n"
            f"🌐 <b>NaiveProxy (Caddy):</b> { _bytes_human(naive_total) }\n"
            f"👁️ <b>Mieru:</b> { _bytes_human(mieru_total) }\n"
            f"🛡️ <b>AmneziaWG:</b> { _bytes_human(awg_total) }\n\n"
            f"💳 <b>ВСЕГО ПО СЕРВЕРУ:</b> { _bytes_human(grand_total) }"
        )
        send(chat_id, text)

    def handle_addsub(chat_id, args):
        if not args:
            send(chat_id, "⚠️ Укажите имя: /addsub username")
            return
        username = args[0].strip()
        if not re.match(r'^[a-zA-Z0-9._-]+$', username):
            send(chat_id, "❌ Некорректное имя (разрешены буквы, цифры, точки, дефисы, подчёркивания).")
            return
            
        sys.path.insert(0, "/opt/vless-ultimate")
        try:
            from vless_installer.modules.user_lifecycle import sync_user_lifecycle
            sync_user_lifecycle(username, "add")
            
            st = _state()
            token = st.get("users", {}).get(username, {}).get("token", "")
            
            sub_domain = st.get("sub_domain", "")
            domain_to_use = sub_domain or st.get("domain", "")
            if not domain_to_use:
                try: domain_to_use = subprocess.check_output(["curl", "-s", "-4", "https://api.ipify.org"], text=True, timeout=5).strip()
                except: domain_to_use = "IP_СЕРВЕРА"
            
            sub_url = f"https://{domain_to_use}/sub/{token}"
            sub_url_pc = f"{sub_url}/pc"
            
            text = (
                f"✅ Пользователь <b>{username}</b> успешно создан.\n\n"
                f"🔑 <b>Токен подписки:</b> <code>{token}</code>\n"
                f"📱 <b>Mobile:</b> <code>{sub_url}</code>\n"
                f"💻 <b>PC (Throne):</b> <code>{sub_url_pc}</code>"
            )
            send(chat_id, text)
        except Exception as e:
            send(chat_id, f"❌ Ошибка создания: {e}")

    def handle_delsub(chat_id, args):
        if not args:
            send(chat_id, "⚠️ Укажите имя: /delsub username")
            return
        username = args[0].strip()
        sys.path.insert(0, "/opt/vless-ultimate")
        try:
            from vless_installer.modules.user_lifecycle import sync_user_lifecycle
            sync_user_lifecycle(username, "delete")
            send(chat_id, f"✅ Пользователь <b>{username}</b> успешно удалён.")
        except Exception as e:
            send(chat_id, f"❌ Ошибка удаления: {e}")

    def handle_callback_query(cb):
        cb_id = cb["id"]
        chat_id = cb["message"]["chat"]["id"]
        message_id = cb["message"]["message_id"]
        data = cb.get("data", "")
        
        api("answerCallbackQuery", callback_query_id=cb_id)
        
        if not data.startswith("admin:"):
            return
            
        parts = data.split(":")
        action = parts[1]
        
        if action == "users":
            sub_act = parts[2]
            if sub_act == "page":
                page = int(parts[3])
                show_users_page(chat_id, page, message_id)
            elif sub_act == "close":
                api("deleteMessage", chat_id=chat_id, message_id=message_id)
            elif sub_act == "back":
                show_users_page(chat_id, 1, message_id)
                
        elif action == "user":
            sub_act = parts[2]
            email = parts[3]
            page = int(parts[4]) if len(parts) > 4 else 1
            
            if sub_act == "view":
                show_user_details(chat_id, email, message_id, page)
            elif sub_act == "block":
                sys.path.insert(0, "/opt/vless-ultimate")
                from vless_installer.modules.user_lifecycle import sync_user_lifecycle
                sync_user_lifecycle(email, "block")
                show_user_details(chat_id, email, message_id, page)
            elif sub_act == "unblock":
                sys.path.insert(0, "/opt/vless-ultimate")
                from vless_installer.modules.user_lifecycle import sync_user_lifecycle
                sync_user_lifecycle(email, "unblock")
                show_user_details(chat_id, email, message_id, page)
            elif sub_act == "ttlmenu":
                show_ttl_menu(chat_id, email, message_id, page)
            elif sub_act == "limitmenu":
                show_limit_menu(chat_id, email, message_id, page)
            elif sub_act == "delete":
                text = f"❓ Вы действительно хотите удалить пользователя <b>{email}</b>?"
                inline_keyboard = [
                    [
                        {"text": "👍 Да, удалить", "callback_data": f"admin:user:delconfirm:{email}:{page}"},
                        {"text": "👎 Отмена", "callback_data": f"admin:user:view:{email}:{page}"}
                    ]
                ]
                edit(chat_id, message_id, text, {"inline_keyboard": inline_keyboard})
            elif sub_act == "delconfirm":
                sys.path.insert(0, "/opt/vless-ultimate")
                from vless_installer.modules.user_lifecycle import sync_user_lifecycle
                sync_user_lifecycle(email, "delete")
                text = f"✅ Пользователь <b>{email}</b> успешно удален."
                inline_keyboard = [[{"text": "🔙 Назад к списку", "callback_data": f"admin:users:page:{page}"}]]
                edit(chat_id, message_id, text, {"inline_keyboard": inline_keyboard})
            elif sub_act == "ttlset":
                days = int(parts[4])
                page = int(parts[5]) if len(parts) > 5 else 1
                st = _state()
                users_db = st.setdefault("users", {})
                udata = users_db.setdefault(email, {})
                if days == 0:
                    udata["expires_at"] = ""
                else:
                    udata["expires_at"] = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()
                _save_state(st)
                
                sys.path.insert(0, "/opt/vless-ultimate")
                from vless_installer.modules.user_lifecycle import sync_user_lifecycle
                sync_user_lifecycle(email, "unblock" if udata.get("is_blocked") else "add")
                show_user_details(chat_id, email, message_id, page)
            elif sub_act == "ttlcustom":
                USER_STATES[str(chat_id)] = {"action": "wait_ttl", "target": email, "page": page}
                text = f"✍️ Введите новое значение TTL в днях для <b>{email}</b> (от 1 до 3650):\nИли отправьте 0 для бессрочного."
                edit(chat_id, message_id, text)
            elif sub_act == "limitset":
                gb = int(parts[4])
                page = int(parts[5]) if len(parts) > 5 else 1
                st = _state()
                users_db = st.setdefault("users", {})
                udata = users_db.setdefault(email, {})
                udata["limit_gb"] = gb
                _save_state(st)
                
                sys.path.insert(0, "/opt/vless-ultimate")
                from vless_installer.modules.user_lifecycle import sync_user_lifecycle
                if udata.get("is_blocked"):
                    sync_user_lifecycle(email, "unblock")
                else:
                    sync_user_lifecycle(email, "add")
                show_user_details(chat_id, email, message_id, page)
            elif sub_act == "limitcustom":
                USER_STATES[str(chat_id)] = {"action": "wait_limit", "target": email, "page": page}
                text = f"✍️ Введите лимит трафика в ГБ для <b>{email}</b> (целое число):\nИли отправьте 0 для безлимита."
                edit(chat_id, message_id, text)
                
        elif action == "security":
            sub_act = parts[2]
            if sub_act == "log":
                log_type = parts[3]
                modules = {
                    "fail2ban": ("journalctl -u fail2ban -n 20 --no-pager", "Log Fail2ban"),
                    "honeypot": ("journalctl -u xray-honeypot -n 20 --no-pager", "Log Honeypot"),
                    "installer": ("tail -20 /var/log/vless-install.log", "Log Установщика")
                }
                if log_type in modules:
                    cmd, desc = modules[log_type]
                    try:
                        r = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=5)
                        out = r.stdout.strip()
                        if not out: out = r.stderr.strip() or "(пусто)"
                        if len(out) > 3900: out = out[-3900:]
                        out_escaped = out.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                        text = f"📋 <b>{desc} (последние строки):</b>\n<pre>{out_escaped}</pre>"
                    except Exception as e:
                        text = f"❌ Ошибка чтения логов: {e}"
                    
                    inline_keyboard = [
                        [{"text": "🔙 Назад к безопасности", "callback_data": "admin:security:back"}]
                    ]
                    edit(chat_id, message_id, text, {"inline_keyboard": inline_keyboard})
            elif sub_act == "back":
                show_security_panel(chat_id, message_id)

    def process_update(update):
        if "callback_query" in update:
            handle_callback_query(update["callback_query"])
            return

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
                    _log(f"Admin auth success for chat_id {chat_id}")
                else:
                    send(chat_id, "❌ Неверный пароль панели.")
            else:
                if is_authed(chat_id):
                    send(chat_id, "📖 Введите /help для просмотра команд.")
                else:
                    send(chat_id, "🔐 Введите: /start <пароль>")
            return
            
        if not is_authed(chat_id):
            send(chat_id, "⛔ Вы не авторизованы. Введите /start <пароль>")
            return

        state_key = str(chat_id)
        if state_key in USER_STATES:
            state_info = USER_STATES[state_key]
            action = state_info["action"]
            email = state_info["target"]
            page = state_info.get("page", 1)
            
            if action == "wait_ttl":
                del USER_STATES[state_key]
                try:
                    days = int(text)
                    if days < 0 or days > 3650: raise ValueError
                    st = _state()
                    users_db = st.setdefault("users", {})
                    udata = users_db.setdefault(email, {})
                    if days == 0:
                        udata["expires_at"] = ""
                    else:
                        udata["expires_at"] = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()
                    _save_state(st)
                    
                    sys.path.insert(0, "/opt/vless-ultimate")
                    from vless_installer.modules.user_lifecycle import sync_user_lifecycle
                    sync_user_lifecycle(email, "unblock" if udata.get("is_blocked") else "add")
                    
                    send(chat_id, f"✅ TTL для {email} изменен на {days} дней.")
                    show_user_details_new(chat_id, email, page)
                except ValueError:
                    send(chat_id, "❌ Неверное значение. Введите целое число дней от 1 до 3650 (или 0 для снятия лимита).")
                return
                
            elif action == "wait_limit":
                del USER_STATES[state_key]
                try:
                    gb = int(text)
                    if gb < 0: raise ValueError
                    st = _state()
                    users_db = st.setdefault("users", {})
                    udata = users_db.setdefault(email, {})
                    udata["limit_gb"] = gb
                    _save_state(st)
                    
                    sys.path.insert(0, "/opt/vless-ultimate")
                    from vless_installer.modules.user_lifecycle import sync_user_lifecycle
                    if udata.get("is_blocked"):
                        sync_user_lifecycle(email, "unblock")
                    else:
                        sync_user_lifecycle(email, "add")
                        
                    send(chat_id, f"✅ Лимит для {email} изменен на {gb} ГБ.")
                    show_user_details_new(chat_id, email, page)
                except ValueError:
                    send(chat_id, "❌ Неверное значение. Введите положительное целое число ГБ.")
                return

        if cmd == "/server":
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
                    cpu = f"{100 * (1 - idle_diff / total_diff):.1f}%"
            except Exception: pass
            
            ram = "❓ неизвестно"
            try:
                meminfo = {}
                with open("/proc/meminfo") as f:
                    for line in f:
                        parts = line.split(":")
                        if len(parts) == 2:
                            meminfo[parts[0].strip()] = int(parts[1].split()[0])
                total_kb = meminfo.get("MemTotal", 0)
                avail_kb = meminfo.get("MemAvailable", 0)
                if total_kb > 0:
                    used_kb = total_kb - avail_kb
                    ram = f"{used_kb/1024/1024:.2f}/{total_kb/1024/1024:.2f} GB ({100*used_kb/total_kb:.1f}%)"
            except Exception: pass
            
            disk = "❓ неизвестно"
            try:
                r = subprocess.run(["df", "-h", "/"], capture_output=True, text=True, timeout=5)
                lines = r.stdout.strip().splitlines()
                if len(lines) >= 2:
                    parts = lines[1].split()
                    if len(parts) >= 5:
                        disk = f"{parts[2]}/{parts[1]} ({parts[4]} исп.)"
            except Exception: pass
            
            load = "❓ неизвестно"
            try:
                with open("/proc/loadavg") as f:
                    load = " ".join(f.read().split()[:3])
            except Exception: pass
            
            uptime = "❓ неизвестно"
            try:
                uptime = subprocess.check_output(["uptime", "-p"], text=True, timeout=5).strip()
            except Exception: pass
            
            text = (f"📊 <b>Информация о сервере</b>\n\n"
                    f"💻 CPU: {cpu}\n"
                    f"💾 RAM: {ram}\n"
                    f"💽 Диск: {disk}\n"
                    f"⏱️ Load average: {load}\n"
                    f"⏰ Uptime: {uptime}")
            send(chat_id, text)

        elif cmd == "/traffic":
            handle_traffic(chat_id)
        elif cmd == "/users":
            show_users_page(chat_id, 1)
        elif cmd == "/addsub":
            handle_addsub(chat_id, args)
        elif cmd == "/delsub":
            handle_delsub(chat_id, args)
        elif cmd == "/security":
            show_security_panel(chat_id)
        elif cmd == "/logs":
            if args:
                mod = args[0].strip().lower()
                modules = {
                    "fail2ban": ("journalctl -u fail2ban -n 20 --no-pager", "Log Fail2ban"),
                    "honeypot": ("journalctl -u xray-honeypot -n 20 --no-pager", "Log Honeypot"),
                    "naive": ("tail -20 /var/log/caddy-naive/access.log", "Log NaiveProxy"),
                    "installer": ("tail -20 /var/log/vless-install.log", "Log Установщика")
                }
                if mod in modules:
                    cmd_run, desc = modules[mod]
                    try:
                        r = subprocess.run(cmd_run.split(), capture_output=True, text=True, timeout=5)
                        out = r.stdout.strip()
                        if not out: out = r.stderr.strip() or "(пусто)"
                        if len(out) > 3900: out = out[-3900:]
                        out_escaped = out.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                        send(chat_id, f"📋 <b>{desc} (последние строки):</b>\n<pre>{out_escaped}</pre>")
                    except Exception as e:
                        send(chat_id, f"❌ Ошибка чтения логов: {e}")
                else:
                    send(chat_id, f"❌ Модуль '{mod}' не найден.")
            else:
                lines = [
                    "  • <code>/logs fail2ban</code> — Log Fail2ban",
                    "  • <code>/logs honeypot</code> — Log Honeypot",
                    "  • <code>/logs naive</code> — Log NaiveProxy",
                    "  • <code>/logs installer</code> — Log Установщика"
                ]
                send(chat_id, "📋 <b>Доступные журналы логов:</b>\n\n" + "\n".join(lines))
        elif cmd == "/notify":
            if not args or args[0].strip().lower() not in ("on", "off"):
                send(chat_id, "⚠️ Использование: <code>/notify on</code> or <code>/notify off</code>")
                return
            val = args[0].strip().lower() == "on"
            cfg = {}
            t_file = Path("/var/lib/xray-installer/telegram.json")
            if t_file.exists():
                try: cfg = json.loads(t_file.read_text())
                except: pass
            events = cfg.get("events", {})
            ev_keys = ["cert_expire", "traffic_limit", "health_report", "node_down", "port_blocked", "autoban"]
            for k in ev_keys: events[k] = val
            cfg["events"] = events
            try:
                t_file.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
                state_str = "включены" if val else "выключены"
                send(chat_id, f"🔔 Все пуш-уведомления успешно {state_str}.")
            except Exception as e:
                send(chat_id, f"❌ Ошибка сохранения настроек: {e}")
        elif cmd == "/logout":
            cfg = json.loads(bot_file.read_text(encoding="utf-8")) if bot_file.exists() else {}
            sessions = cfg.get("admin_sessions", [])
            if str(chat_id) in [str(x) for x in sessions]:
                sessions = [x for x in sessions if str(x) != str(chat_id)]
                cfg["admin_sessions"] = sessions
                bot_file.write_text(json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")
                bot_file.chmod(0o600)
                send(chat_id, "🔐 Вы вышли из сессии администратора.")
            else:
                send(chat_id, "⛔ Вы не авторизованы.")
        elif cmd == "/help":
            text = (
                "📖 <b>Панель администратора Multi-Proxy Manager</b>\n\n"
                "/server - Статус и метрики сервера\n"
                "/traffic - Потребление трафика по протоколам\n"
                "/users - Интерактивное управление пользователями\n"
                "/addsub &lt;tag&gt; - Добавить подписку\n"
                "/delsub &lt;tag&gt; - Удалить подписку\n"
                "/security - Панель безопасности\n"
                "/logs [модуль] - Просмотр логов выбранного модуля\n"
                "/notify on|off - Вкл/выкл уведомления\n"
                "/logout - Завершить сессию\n"
            )
            send(chat_id, text)

    offset = 0
    _log("Admin Bot started")
    while True:
        try:
            r = api("getUpdates", offset=offset, timeout=25, limit=10)
            for upd in r.get("result", []):
                offset = upd["update_id"] + 1
                try:
                    process_update(upd)
                except Exception as e:
                    _log(f"Update error: {e}")
        except Exception as e:
            _log(f"Poll error: {e}")
            time.sleep(5)


def run_user_bot():
    import json, os, sys, time, re, subprocess, urllib.request, urllib.parse, socket
    from pathlib import Path
    from datetime import datetime, timezone, timedelta

    socket.setdefaulttimeout(35)
    
    bot_file = Path("/var/lib/xray-installer/tg_bot.json")
    state_file = Path("/var/lib/xray-installer/state.json")
    log_file = Path("/var/log/vless-install.log")
    
    if not bot_file.exists():
        print("Error: tg_bot.json not found")
        sys.exit(1)
        
    bot_cfg = json.loads(bot_file.read_text(encoding="utf-8"))
    token = bot_cfg.get("token") or bot_cfg.get("user_token")
    if not token:
        token = bot_cfg.get("admin_token", "")
    if not token:
        print("Error: bot token not found in tg_bot.json")
        sys.exit(1)

    def _log(msg):
        try:
            with log_file.open("a", encoding="utf-8") as f:
                f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [USER_BOT] {msg}\n")
        except Exception:
            pass

    def _state():
        try:
            state = json.loads(state_file.read_text(encoding="utf-8")) if state_file.exists() else {}
            users_db = state.setdefault("users", {})
            sub_tokens = state.setdefault("sub_tokens", {})
            changed = False
            for email, token in sub_tokens.items():
                if email not in users_db:
                    users_db[email] = {
                        "token": token,
                        "created_at": datetime.now().isoformat(),
                        "expires_at": "",
                        "limit_gb": 0,
                        "is_blocked": False,
                        "block_reason": "",
                        "traffic_baseline": 0,
                        "traffic_accumulated": 0,
                        "previous_live": 0
                    }
                    changed = True
            if changed:
                try:
                    state_file.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
                except Exception as e:
                    _log(f"Error saving state: {e}")
            return state
        except Exception:
            return {}

    def _bytes_human(n):
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if n < 1024:
                return f"{n:.2f} {unit}" if unit != 'B' else f"{n} B"
            n /= 1024
        return f"{n:.2f} PB"

    def api(method, **params):
        url = f"https://api.telegram.org/bot{token}/{method}"
        data = urllib.parse.urlencode(params).encode()
        try:
            req = urllib.request.Request(url, data=data)
            resp = urllib.request.urlopen(req, timeout=30)
            return json.loads(resp.read())
        except Exception as e:
            _log(f"API error {method}: {e}")
            return {}

    def send(chat_id, text):
        return api("sendMessage", chat_id=chat_id, text=text, parse_mode="HTML")

    def is_allowed(uid):
        cfg = json.loads(bot_file.read_text(encoding="utf-8")) if bot_file.exists() else {}
        allowed = cfg.get("allowed_users", [])
        user_map = cfg.get("user_map", {})
        admin_id = str(cfg.get("admin_id", ""))
        return (str(uid) in [str(x) for x in allowed] and str(uid) in user_map) or str(uid) == admin_id

    def handle_config(chat_id):
        cfg = json.loads(bot_file.read_text(encoding="utf-8")) if bot_file.exists() else {}
        email = cfg.get("user_map", {}).get(str(chat_id))
        if not email:
            admin_id = str(cfg.get("admin_id", ""))
            if str(chat_id) == admin_id:
                st = _state()
                email = st.get("email") or "admin"
                
        if not email:
            send(chat_id, "⚠️ Ошибка: нет привязанного пользователя подписки. Пожалуйста, пройдите авторизацию заново.")
            return

        st = _state()
        users_db = st.get("users", {})
        udata = users_db.get(email, {})
        
        if udata.get("is_blocked"):
            send(chat_id, "❌ <b>Ваша подписка заблокирована или истекла.</b>\nДля продления обратитесь к администратору.")
            return

        token_str = udata.get("token", "")
        if not token_str:
            token_str = st.get("sub_tokens", {}).get(email, "")
            
        sub_domain = st.get("sub_domain", "")
        domain_to_use = sub_domain or st.get("domain", "")
        if not domain_to_use:
            try: domain_to_use = subprocess.check_output(["curl", "-s", "-4", "https://api.ipify.org"], text=True).strip()
            except: domain_to_use = "IP_СЕРВЕРА"

        sub_url = f"https://{domain_to_use}/sub/{token_str}"
        sub_url_pc = f"{sub_url}/pc"

        sys.path.insert(0, "/opt/vless-ultimate")
        try:
            from vless_installer.modules.user_lifecycle import get_user_cumulative_traffic
            used_bytes = get_user_cumulative_traffic(email, st)
        except Exception:
            used_bytes = udata.get("used_bytes", 0)

        limit_gb = udata.get("limit_gb", 0)
        expires_at = udata.get("expires_at", "")

        def get_expires_desc(iso):
            if not iso:
                return "бессрочно"
            try:
                exp = datetime.fromisoformat(iso)
                now = datetime.now(timezone.utc)
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=timezone.utc)
                delta = exp - now
                total = int(delta.total_seconds())
                if total <= 0:
                    return f"ИСТЁК ({exp.strftime('%Y-%m-%d %H:%M')})"
                days = total // 86400
                hours = (total % 86400) // 3600
                if days > 0:
                    return f"{days}д {hours}ч ({exp.strftime('%Y-%m-%d %H:%M')})"
                return f"{hours}ч (истекает сегодня)"
            except Exception:
                return iso

        pct_str = ""
        bar_str = ""
        if limit_gb:
            limit_bytes = int(limit_gb * 1024**3)
            pct = min(100, int(used_bytes / limit_bytes * 100)) if limit_bytes else 0
            filled = pct // 10
            bar_str = "\n[" + "■" * filled + "□" * (10 - filled) + f"] {pct}%"
            pct_str = f" / {limit_gb} GB"

        traffic_info = f"📊 <b>Трафик:</b> <code>{_bytes_human(used_bytes)}{pct_str}</code>{bar_str}"
        expires_info = f"⏳ <b>Действует до:</b> <code>{get_expires_desc(expires_at)}</code>"
        instruction_url = cfg.get("instruction_url", "https://telegra.ph/Instrukciya-k-podklyucheniyu-06-24")

        send(chat_id, (
            f"👤 <b>Пользователь:</b> {email}\n"
            f"{traffic_info}\n"
            f"{expires_info}\n\n"
            f"📋 <b>Ваша подписка (Mobile):</b>\n"
            f"<code>{sub_url}</code>\n\n"
            f"📋 <b>Ваша подписка (PC - NekoBox/Throne):</b>\n"
            f"<code>{sub_url_pc}</code>\n\n"
            f"📖 <b>Инструкция по подключению:</b>\n"
            f"{instruction_url}\n\n"
            f"📲 <b>Как подключиться:</b>\n"
            f"1. Скопируйте нужную ссылку выше\n"
            f"2. Откройте ваш VPN-клиент\n"
            f"3. Добавьте подписку → Вставьте ссылку"
        ))

    def handle_traffic(chat_id):
        cfg = json.loads(bot_file.read_text(encoding="utf-8")) if bot_file.exists() else {}
        email = cfg.get("user_map", {}).get(str(chat_id))
        if not email:
            admin_id = str(cfg.get("admin_id", ""))
            if str(chat_id) == admin_id:
                st = _state()
                email = st.get("email") or "admin"
                
        if not email:
            send(chat_id, "⚠️ Нет привязанного аккаунта.")
            return

        st = _state()
        users_db = st.get("users", {})
        udata = users_db.get(email, {})
        
        if udata.get("is_blocked"):
            send(chat_id, "❌ <b>Ваша подписка заблокирована или истекла.</b>\nДля продления обратитесь к администратору.")
            return

        sys.path.insert(0, "/opt/vless-ultimate")
        try:
            from vless_installer.modules.user_lifecycle import get_user_cumulative_traffic
            used_bytes = get_user_cumulative_traffic(email, st)
        except Exception:
            used_bytes = udata.get("used_bytes", 0)

        limit_gb = udata.get("limit_gb", 0)
        expires_at = udata.get("expires_at", "")

        def get_expires_desc(iso):
            if not iso:
                return "бессрочно"
            try:
                exp = datetime.fromisoformat(iso)
                now = datetime.now(timezone.utc)
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=timezone.utc)
                delta = exp - now
                total = int(delta.total_seconds())
                if total <= 0:
                    return f"ИСТЁК ({exp.strftime('%Y-%m-%d %H:%M')})"
                days = total // 86400
                hours = (total % 86400) // 3600
                if days > 0:
                    return f"{days}д {hours}ч ({exp.strftime('%Y-%m-%d %H:%M')})"
                return f"{hours}ч (истекает сегодня)"
            except Exception:
                return iso

        ttl_info = f"\n⏳ Действует до: {get_expires_desc(expires_at)}" if expires_at else "\n⏳ Действует до: бессрочно"

        text = f"📊 <b>Ваш трафик ({email}):</b>\n\n"
        text += f"Использовано: <b>{_bytes_human(used_bytes)}</b>\n"
        if limit_gb:
            limit_bytes = int(limit_gb * 1024**3)
            pct = min(100, int(used_bytes / limit_bytes * 100)) if limit_bytes else 0
            filled = pct // 10
            bar = "■" * filled + "□" * (10 - filled)
            text += f"Лимит: {limit_gb} GB\n[{bar}] {pct}%\n"
        else:
            text += "Лимит: безлимитный\n"
        text += ttl_info
        
        send(chat_id, text)

    def handle_qr(chat_id):
        cfg = json.loads(bot_file.read_text(encoding="utf-8")) if bot_file.exists() else {}
        email = cfg.get("user_map", {}).get(str(chat_id))
        if not email:
            admin_id = str(cfg.get("admin_id", ""))
            if str(chat_id) == admin_id:
                st = _state()
                email = st.get("email") or "admin"
                
        if not email:
            send(chat_id, "⚠️ Нет привязанного пользователя.")
            return

        st = _state()
        users_db = st.get("users", {})
        udata = users_db.get(email, {})
        if udata.get("is_blocked"):
            send(chat_id, "❌ <b>Ваша подписка заблокирована или истекла.</b>\nДля продления обратитесь к администратору.")
            return

        token_str = udata.get("token", "")
        if not token_str:
            token_str = st.get("sub_tokens", {}).get(email, "")
            
        sub_domain = st.get("sub_domain", "")
        domain_to_use = sub_domain or st.get("domain", "")
        if not domain_to_use:
            try: domain_to_use = subprocess.check_output(["curl", "-s", "-4", "https://api.ipify.org"], text=True).strip()
            except: domain_to_use = "IP_СЕРВЕРА"

        sub_url = f"https://{domain_to_use}/sub/{token_str}"
        qr_file = f"/tmp/user_qr_{chat_id}.png"
        
        try:
            subprocess.run(["qrencode", "-o", qr_file, "-s", "8", sub_url], check=True)
            subprocess.run([
                "curl", "-s", "-X", "POST",
                f"https://api.telegram.org/bot{token}/sendPhoto",
                "-F", f"chat_id={chat_id}",
                "-F", f"photo=@{qr_file}",
                "-F", f"caption=QR-код вашей подписки ({email})"
            ], stdout=subprocess.DEVNULL)
            Path(qr_file).unlink(missing_ok=True)
        except Exception as e:
            send(chat_id, f"❌ Ошибка генерации QR-кода: {e}")

    def process_update(update):
        msg = update.get("message") or update.get("edited_message")
        if not msg or "text" not in msg:
            return
        text  = msg["text"].strip()
        uid   = msg["from"]["id"]
        uname = msg["from"].get("username", str(uid))
        
        parts = text.split()
        cmd = parts[0].split("@")[0].lower() if parts else ""
        args = parts[1:]
        
        authorized = is_allowed(uid)
        
        if not authorized:
            cfg = json.loads(bot_file.read_text(encoding="utf-8")) if bot_file.exists() else {}
            bot_password = cfg.get("bot_password", "")
            
            if bot_password and text == bot_password:
                uname_raw = msg["from"].get("username", "")
                if uname_raw:
                    clean_uname = re.sub(r'[^a-zA-Z0-9._-]', '', uname_raw)
                    tag = f"tg_{clean_uname}" if clean_uname else f"tg_{uid}"
                else:
                    tag = f"tg_{uid}"
                    
                st = _state()
                sub_tokens = st.setdefault("sub_tokens", {})
                if tag in sub_tokens and tag != f"tg_{uid}":
                    tag = f"{tag}_{uid}"
                    
                sys.path.insert(0, "/opt/vless-ultimate")
                from vless_installer.modules.user_lifecycle import sync_user_lifecycle
                try:
                    sync_user_lifecycle(tag, "add")
                    
                    allowed = cfg.setdefault("allowed_users", [])
                    if uid not in allowed:
                        allowed.append(uid)
                    cfg["allowed_users"] = allowed
                    
                    user_map = cfg.setdefault("user_map", {})
                    user_map[str(uid)] = tag
                    cfg["user_map"] = user_map
                    
                    bot_file.write_text(json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")
                    bot_file.chmod(0o600)
                    
                    send(uid, f"✅ Авторизация успешна! Создан пользователь подписки: <b>{tag}</b>.\nИспользуйте /config для получения подписки.")
                    _log(f"User @{uname} ({uid}) authorized and created user {tag}")
                except Exception as e:
                    send(uid, f"❌ Ошибка при создании пользователя подписки: {e}")
                    _log(f"Failed to create user for @{uname}: {e}")
            else:
                send(uid, "🔐 Для получения подписки, пожалуйста, введите пароль для авторизации:")
            return
            
        if cmd == "/start":
            send(uid, "👋 Привет! Используйте /config для получения вашей подписки или /qr для получения QR-кода.")
        elif cmd == "/config":
            handle_config(uid)
        elif cmd == "/traffic":
            handle_traffic(uid)
        elif cmd == "/qr":
            handle_qr(uid)
        elif cmd == "/help":
            send(uid, (
                "📖 <b>Справка</b>\n\n"
                "/start  — начало работы\n"
                "/config — получить ссылку подписки\n"
                "/traffic — проверить использование трафика\n"
                "/qr     — получить QR-код подписки\n"
                "/help   — эта справка\n"
            ))

    offset = 0
    _log("User Bot started")
    while True:
        try:
            r = api("getUpdates", offset=offset, timeout=25, limit=10)
            for upd in r.get("result", []):
                offset = upd["update_id"] + 1
                try:
                    process_update(upd)
                except Exception as e:
                    _log(f"Update error: {e}")
        except Exception as e:
            _log(f"Poll error: {e}")
            time.sleep(5)
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
            ev_keys = ["cert_expire","traffic_limit",
                       "health_report","node_down","port_blocked","autoban"]
            ev_labels = [
                "Сертификат истекает",
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
                    "✅ <b>Multi-Proxy Manager</b>: тестовое сообщение Admin Panel. Уведомления работают!",
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

        token        = bot_cfg.get("token") or notif_cfg.get("token", "")
        admin_id     = bot_cfg.get("admin_id") or notif_cfg.get("chat_id", "")
        bot_password = bot_cfg.get("bot_password", "")
        allowed      = bot_cfg.get("allowed_users", [])
        instruction_url = bot_cfg.get("instruction_url", "https://telegra.ph/Instrukciya-k-podklyucheniyu-06-24")

        configured = bool(token and admin_id and bot_password)

        print()
        _box_top("🤖  TELEGRAM CONFIG BOT — раздача конфигов пользователям")
        _box_desc(
            "Пользователь пишет боту /config → бот запрашивает пароль авторизации. "
            "После ввода пароля автоматически создаётся новый пользователь подписки."
        )
        _box_sep()
        _box_row(f"  Статус бота:      {''+GREEN+'ЗАПУЩЕН'+NC if running else ''+DIM+'ОСТАНОВЛЕН'+NC}")
        _box_row(f"  Конфиг:           {''+GREEN+'НАСТРОЕН'+NC if configured else ''+YELLOW+'НЕ НАСТРОЕН'+NC}")
        if configured:
            _box_row(f"  Токен:            {DIM}{token[:10]}...{NC}")
            _box_row(f"  Admin Chat ID:    {CYAN}{admin_id}{NC}")
            _box_row(f"  Пароль юзеров:    {GREEN}{bot_password}{NC}")
            _box_row(f"  Авторизовано:     {CYAN}{len(allowed)}{NC} пользователей")
            _box_row(f"  Инструкция URL:   {CYAN}{instruction_url}{NC}")
        _box_sep()
        if not configured:
            _box_item("1", f"Настроить бота (токен + admin ID + пароль)")
        else:
            _box_item("1", f"Изменить настройки")
            if running:
                _box_item("2", f"Перезапустить бота")
                _box_item("3", f"{RED}Остановить бота{NC}")
            else:
                _box_item("2", f"{GREEN}Запустить бота{NC}")
            _box_item("4", f"Список авторизованных пользователей")
            _box_item("5", f"Удалить пользователя из списка")
            _box_item("6", f"Проверить статус сервиса")
            _box_item("7", f"Изменить ссылку на инструкцию")
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
            _menu_bot_list_users(bot_cfg)
        elif ch == "5" and configured:
            _menu_bot_remove_user(bot_cfg)
        elif ch == "6" and configured:
            _menu_bot_svc_status()
        elif ch == "7" and configured:
            _menu_bot_change_instruction(bot_cfg)
        elif ch in ("q", "Q", "0", ""):
            return
        else:
            _warn("Неверный выбор")
            time.sleep(1)


def _menu_bot_change_instruction(bot_cfg: dict) -> None:
    os.system("clear")
    print()
    _box_top("📖 Изменение ссылки на инструкцию")
    cur_url = bot_cfg.get("instruction_url", "https://telegra.ph/Instrukciya-k-podklyucheniyu-06-24")
    _box_row(f"  Текущая ссылка: {CYAN}{cur_url}{NC}")
    _box_bottom()
    print()
    try:
        new_url = input(f"  Новая ссылка [{DIM}Enter = оставить{NC}]: ").strip()
    except KeyboardInterrupt:
        return
    if new_url:
        bot_cfg["instruction_url"] = new_url
        _bot_save(bot_cfg)
        _info("Ссылка на инструкцию обновлена!")
        time.sleep(1.5)


def _menu_bot_configure(bot_cfg: dict, notif_cfg: dict) -> None:
    """Настройка токена, admin ID и общего пароля."""
    os.system("clear")
    print()
    _box_top("🤖  Настройка Telegram Bot")
    _box_desc(
        "Создайте бота через @BotFather (/newbot). "
        "Если токен тот же что для уведомлений — можно использовать один бот. "
        "Admin Chat ID — ваш личный Telegram ID (узнать: @userinfobot). "
        "Пароль для пользователей — общий пароль, который вводится для авторизации."
    )
    _box_sep()
    cur_token    = bot_cfg.get("token") or notif_cfg.get("token", "")
    cur_admin_id = bot_cfg.get("admin_id") or notif_cfg.get("chat_id", "")
    cur_password = bot_cfg.get("bot_password", "")
    if cur_token:
        _box_row(f"  Текущий токен:    {DIM}{cur_token[:10]}...{NC}")
    if cur_admin_id:
        _box_row(f"  Текущий admin ID: {CYAN}{cur_admin_id}{NC}")
    if cur_password:
        _box_row(f"  Текущий пароль:   {CYAN}{cur_password}{NC}")
    _box_bottom()
    print()

    try:
        new_token = input(f"  Bot Token [{DIM}Enter = оставить{NC}]: ").strip()
        new_admin = input(f"  Admin Chat ID [{DIM}Enter = оставить{NC}]: ").strip()
        new_pass  = input(f"  Пароль для пользователей [{DIM}Enter = оставить{NC}]: ").strip()
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

    if new_pass:
        bot_cfg["bot_password"] = new_pass
    elif cur_password and not bot_cfg.get("bot_password"):
        bot_cfg["bot_password"] = cur_password

    if not bot_cfg.get("token") or not bot_cfg.get("admin_id") or not bot_cfg.get("bot_password"):
        _warn("Токен, Admin ID и Пароль обязательны")
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
        _warn("Сначала добавьте пользователей в подписки")
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    os.system("clear")
    print()
    _box_top("Создать invite-ссылку")
    _box_row("Выберите пользователя подписки, для которого создается ссылка:")
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
