"""
hydra/services/telegram/bot.py — Telegram Admin Bot (System Info + Fail2ban & AntiDPI Notifications).

Архитектура:
  - Admin Bot: получение информации о системе, мониторинг Fail2ban и AntiDPI, разблокировка IP.
  - Реагирование на события безопасности AntiDPI и Fail2ban в режиме реального времени.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import threading
import time
import urllib.request
from pathlib import Path
from typing import Optional

from hydra.core.host import HOST
from hydra.core.state import AppState, load_state
from hydra.plugins.registry import status_all

try:
    from telegram import Update
    from telegram.ext import (
        Application, CommandHandler, ContextTypes,
    )
    TELEGRAM_AVAILABLE = True
except ImportError:
    TELEGRAM_AVAILABLE = False


# ═════════════════════════════════════════════════════════════════════════════
#  Уведомления Админа (Direct HTTP Dispatch)
# ═════════════════════════════════════════════════════════════════════════════

def send_admin_notification(text: str, state: Optional[AppState] = None) -> bool:
    """Отправка уведомления в Telegram админ-чат в реальном времени.

    Безопасный вызов напрямую из AntiDPI, Fail2ban, CLI или сервисов.
    """
    try:
        if state is None:
            state = load_state()
        token = getattr(state.telegram, "admin_token", "")
        chat_id = getattr(state.telegram, "admin_chat_id", "")
        if not token or not chat_id:
            return False

        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = json.dumps({
            "chat_id": str(chat_id),
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }).encode("utf-8")

        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except Exception:
        return False


# ═════════════════════════════════════════════════════════════════════════════
#  Утилиты сбора данных и статусов
# ═════════════════════════════════════════════════════════════════════════════

def get_system_info_text() -> str:
    """Сбор информации о ресурсах системы и Hydra-сервисах."""
    hostname = socket.gethostname()
    try:
        state = load_state()
        server_ip = state.network.server_ip or "N/A"
    except Exception:
        server_ip = "N/A"

    # CPU load
    try:
        load1, load5, load15 = os.getloadavg()
        load_str = f"{load1:.2f}, {load5:.2f}, {load15:.2f}"
    except Exception:
        load_str = "N/A"

    # RAM
    ram_str = "N/A"
    try:
        if Path("/proc/meminfo").exists():
            mem = {}
            with open("/proc/meminfo", "r", encoding="utf-8") as f:
                for line in f:
                    parts = line.split(":")
                    if len(parts) == 2:
                        key = parts[0].strip()
                        val = parts[1].strip().split()[0]
                        mem[key] = int(val)
            total_kb = mem.get("MemTotal", 0)
            avail_kb = mem.get("MemAvailable", mem.get("MemFree", 0))
            used_kb = total_kb - avail_kb
            if total_kb > 0:
                ram_str = f"{used_kb / 1048576:.2f} GB / {total_kb / 1048576:.2f} GB ({(used_kb / total_kb) * 100:.0f}%)"
    except Exception:
        pass

    # Disk
    disk_str = "N/A"
    try:
        usage = shutil.disk_usage("/")
        used_gb = usage.used / (1024**3)
        total_gb = usage.total / (1024**3)
        disk_str = f"{used_gb:.1f} GB / {total_gb:.1f} GB ({(usage.used / usage.total) * 100:.0f}%)"
    except Exception:
        pass

    # Uptime
    uptime_str = "N/A"
    try:
        if Path("/proc/uptime").exists():
            secs = float(Path("/proc/uptime").read_text().split()[0])
            days = int(secs // 86400)
            hours = int((secs % 86400) // 3600)
            mins = int((secs % 3600) // 60)
            uptime_str = f"{days}d {hours}h {mins}m"
    except Exception:
        pass

    # Status of Hydra plugins
    services_lines = []
    try:
        plugins = status_all()
        for name, s in plugins.items():
            icon = "🟢" if s.get("running") else ("⚠️" if s.get("installed") else "🔴")
            port = f" (port {s['port']})" if s.get("port") else ""
            services_lines.append(f"• {icon} <b>{name}</b>{port}")
    except Exception as e:
        services_lines.append(f"Ошибка получения статуса: {e}")

    services_block = "\n".join(services_lines) if services_lines else "Нет активных плагинов"

    return (
        "<b>🖥️ HYDRA System Information</b>\n\n"
        f"<b>Сервер:</b> <code>{hostname}</code> ({server_ip})\n"
        f"<b>Аптайм:</b> <code>{uptime_str}</code>\n"
        f"<b>Load Average:</b> <code>{load_str}</code>\n"
        f"<b>RAM:</b> <code>{ram_str}</code>\n"
        f"<b>Диск:</b> <code>{disk_str}</code>\n\n"
        f"<b>⚡ Статус сервисов:</b>\n{services_block}"
    )


def get_antidpi_status_text() -> str:
    """Получить статус модуля AntiDPI и список заблокированных IP."""
    from hydra.plugins.antidpi.plugin import AntiDPIPlugin, STATE_FILE
    plugin = AntiDPIPlugin()
    status = plugin.status()
    running_icon = "🟢 Активен" if status.running else ("⚠️ Установлен" if status.installed else "🔴 Отключен")

    banned_ips = []
    events_count = 0
    if STATE_FILE.exists():
        try:
            data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            banned = data.get("banned", {})
            events_count = data.get("events", 0)
            for ip, meta in banned.items():
                score = meta.get("score", 0)
                signals = ", ".join(meta.get("signals", []))
                banned_ips.append(f"• <code>{ip}</code> (score: {score:.1f}, {signals})")
        except Exception:
            pass

    banned_block = "\n".join(banned_ips[:25]) if banned_ips else "<i>Нет заблокированных IP</i>"
    if len(banned_ips) > 25:
        banned_block += f"\n<i>...и ещё {len(banned_ips) - 25} IP</i>"

    return (
        "<b>🛡️ AntiDPI Status</b>\n\n"
        f"<b>Статус:</b> {running_icon}\n"
        f"<b>Всего событий:</b> {events_count}\n"
        f"<b>Заблокировано IP:</b> {len(banned_ips)}\n\n"
        f"<b>Заблокированные IP:</b>\n{banned_block}"
    )


def get_fail2ban_status_text() -> str:
    """Получить статус Fail2ban и список актиных джейлов."""
    from hydra.plugins.fail2ban.plugin import Fail2banPlugin
    plugin = Fail2banPlugin()
    status = plugin.status()
    running_icon = "🟢 Активен" if status.running else ("⚠️ Установлен" if status.installed else "🔴 Отключен")

    jails_info = []
    total_banned = status.info.get("banned_ips", 0)
    if status.running:
        try:
            overall = HOST.run(["fail2ban-client", "status"], timeout=10, text=True)
            match = re.search(r"Jail list:\s*(.*)", overall.stdout)
            if match:
                for jail in (item.strip() for item in match.group(1).split(",")):
                    if not jail:
                        continue
                    detail = HOST.run(["fail2ban-client", "status", jail], timeout=10, text=True)
                    curr = re.search(r"Currently banned:\s*(\d+)", detail.stdout)
                    count = curr.group(1) if curr else "0"
                    jails_info.append(f"• <b>{jail}</b>: <code>{count} banned</code>")
        except Exception:
            pass

    jails_block = "\n".join(jails_info) if jails_info else "<i>Нет активных джейлов</i>"

    return (
        "<b>🚫 Fail2ban Status</b>\n\n"
        f"<b>Статус:</b> {running_icon}\n"
        f"<b>Всего заблокировано IP:</b> {total_banned}\n\n"
        f"<b>Джейлы:</b>\n{jails_block}"
    )


def unban_ip_everywhere(ip: str) -> str:
    """Разблокировать IP адрес в AntiDPI и Fail2ban."""
    from hydra.plugins.antidpi.plugin import AntiDPIPlugin
    results = []

    # AntiDPI unban
    try:
        adpi_ok = AntiDPIPlugin().unban(ip)
        results.append(f"• AntiDPI: {'✅ Разблокирован' if adpi_ok else 'ℹ️ Не найден в бане'}")
    except Exception as e:
        results.append(f"• AntiDPI: ❌ Ошибка ({e})")

    # Fail2ban unban
    try:
        f2b_res = HOST.run(["fail2ban-client", "unban", ip], timeout=10, text=True)
        if f2b_res.returncode == 0:
            results.append(f"• Fail2ban: ✅ Разблокирован ({f2b_res.stdout.strip()})")
        else:
            results.append("• Fail2ban: ℹ️ Не найден в джейлах")
    except Exception as e:
        results.append(f"• Fail2ban: ❌ Ошибка ({e})")

    return f"<b>🔓 Результат разблокировки IP <code>{ip}</code>:</b>\n\n" + "\n".join(results)


# ═════════════════════════════════════════════════════════════════════════════
#  Fail2ban Monitor Thread
# ═════════════════════════════════════════════════════════════════════════════

def _process_fail2ban_log_line(line: str) -> None:
    match = re.search(r"NOTICE\s+\[(?P<jail>[^\]]+)\]\s+(?P<action>Ban|Unban)\s+(?P<ip>\S+)", line)
    if match:
        jail = match.group("jail")
        action = match.group("action")
        ip = match.group("ip")

        if action == "Ban":
            msg = (
                f"🚨 <b>Fail2ban BAN</b>\n"
                f"<b>Jail:</b> <code>{jail}</code>\n"
                f"<b>IP:</b> <code>{ip}</code>"
            )
        else:
            msg = (
                f"✅ <b>Fail2ban UNBAN</b>\n"
                f"<b>Jail:</b> <code>{jail}</code>\n"
                f"<b>IP:</b> <code>{ip}</code>"
            )
        send_admin_notification(msg)


def _fail2ban_monitor_worker(stop_event: threading.Event) -> None:
    f2b_log = Path("/var/log/fail2ban.log")
    if f2b_log.exists():
        try:
            with f2b_log.open("r", encoding="utf-8", errors="replace") as f:
                f.seek(0, 2)
                while not stop_event.is_set():
                    line = f.readline()
                    if not line:
                        time.sleep(0.5)
                        continue
                    _process_fail2ban_log_line(line)
        except Exception:
            pass
    else:
        cmd = ["journalctl", "-u", "fail2ban", "-f", "-n", "0", "-o", "cat"]
        try:
            process = HOST.popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
            assert process.stdout is not None
            for line in process.stdout:
                if stop_event.is_set():
                    break
                _process_fail2ban_log_line(line)
            process.terminate()
        except Exception:
            pass


# ═════════════════════════════════════════════════════════════════════════════
#  Admin Bot implementation
# ═════════════════════════════════════════════════════════════════════════════

class AdminBot:
    def __init__(self, token: str, admin_chat_id: str):
        if not TELEGRAM_AVAILABLE:
            raise RuntimeError("python-telegram-bot не установлен")
        self.token = token
        self.admin_chat_id = int(admin_chat_id)
        self.app: Optional[Application] = None
        self.stop_event = threading.Event()
        self.monitor_thread: Optional[threading.Thread] = None

    async def _check_admin(self, update: Update) -> bool:
        if update.effective_user and update.effective_user.id == self.admin_chat_id:
            return True
        if update.message:
            await update.message.reply_text("Доступ запрещён.")
        return False

    async def cmd_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not await self._check_admin(update):
            return
        await update.message.reply_text(
            "<b>🛡️ HYDRA Admin Bot</b>\n\n"
            "Доступные команды:\n"
            "/system — Информация о системе и ресурсах\n"
            "/antidpi — Статус AntiDPI и заблокированные IP\n"
            "/fail2ban — Статус Fail2ban и джейлы\n"
            "/unban &lt;ip&gt; — Разблокировать IP в AntiDPI и Fail2ban\n"
            "/help — Справка по командам",
            parse_mode="HTML",
        )

    async def cmd_system(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not await self._check_admin(update):
            return
        msg = get_system_info_text()
        await update.message.reply_text(msg, parse_mode="HTML")

    async def cmd_antidpi(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not await self._check_admin(update):
            return
        msg = get_antidpi_status_text()
        await update.message.reply_text(msg, parse_mode="HTML")

    async def cmd_fail2ban(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not await self._check_admin(update):
            return
        msg = get_fail2ban_status_text()
        await update.message.reply_text(msg, parse_mode="HTML")

    async def cmd_unban(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not await self._check_admin(update):
            return
        if not context.args:
            await update.message.reply_text("Использование: /unban <ip>")
            return
        target_ip = context.args[0].strip()
        msg = unban_ip_everywhere(target_ip)
        await update.message.reply_text(msg, parse_mode="HTML")

    def run(self):
        self.stop_event.clear()
        self.monitor_thread = threading.Thread(
            target=_fail2ban_monitor_worker,
            args=(self.stop_event,),
            daemon=True,
        )
        self.monitor_thread.start()

        self.app = Application.builder().token(self.token).build()
        self.app.add_handler(CommandHandler(["start", "help"], self.cmd_start))
        self.app.add_handler(CommandHandler(["system", "status"], self.cmd_system))
        self.app.add_handler(CommandHandler("antidpi", self.cmd_antidpi))
        self.app.add_handler(CommandHandler("fail2ban", self.cmd_fail2ban))
        self.app.add_handler(CommandHandler("unban", self.cmd_unban))
        try:
            self.app.run_polling()
        finally:
            self.stop_event.set()


def run_admin_bot(token: str, admin_chat_id: str):
    bot = AdminBot(token, admin_chat_id)
    bot.run()


def run_client_bot(token: str, admin_chat_id: str):
    """Совместимость со старым вызовом. Логика клиентского бота удалена."""
    print("ClientBot устарел и отключен. Используйте AdminBot для мониторинга и уведомлений.")
