"""
hydra/services/telegram/bot.py — Telegram Admin Bot (System Info + Fail2ban & AntiDPI Notifications).

Архитектура:
  - Admin Bot: получение информации о системе, мониторинг Fail2ban и AntiDPI, разблокировка IP.
  - Реагирование на события безопасности AntiDPI и Fail2ban в режиме реального времени.
"""
from __future__ import annotations

import asyncio
import html
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path
from typing import Optional

from hydra.core.host import HOST
from hydra.core.state import AppState, load_state, update_state
from hydra.plugins.registry import status_all

try:
    from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
    from telegram.ext import (
        Application, CallbackQueryHandler, CommandHandler, ContextTypes,
        MessageHandler, filters,
    )
    TELEGRAM_AVAILABLE = True
except ImportError:
    TELEGRAM_AVAILABLE = False


# ═════════════════════════════════════════════════════════════════════════════
#  Уведомления Админа (Direct HTTP Dispatch)
# ═════════════════════════════════════════════════════════════════════════════

_NOTIFICATION_FIELDS = {
    "antidpi": "notify_antidpi",
    "fail2ban": "notify_fail2ban",
    "fail2ban_unban": "notify_unbans",
    "system": "notify_system",
}


def notification_allowed(state: AppState, category: str) -> bool:
    telegram = state.telegram
    if not getattr(telegram, "notifications_enabled", True):
        return False
    field = _NOTIFICATION_FIELDS.get(category, "notify_system")
    return bool(getattr(telegram, field, True))


def send_admin_notification(
    text: str,
    state: Optional[AppState] = None,
    *,
    category: str = "system",
    force: bool = False,
) -> bool:
    """Send a categorized notification to the configured administrator."""
    try:
        if state is None:
            state = load_state()
        token = getattr(state.telegram, "admin_token", "").strip()
        chat_id = getattr(state.telegram, "admin_chat_id", "").strip()
        if not token or not chat_id or (not force and not notification_allowed(state, category)):
            return False

        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = json.dumps({
            "chat_id": chat_id,
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
    except Exception as e:
        # HTTP exceptions may include the full Bot API URL, including the token.
        status = getattr(e, "code", None)
        suffix = f" status={status}" if status is not None else ""
        sys.stderr.write(f"[AdminBot Notification Error] {type(e).__name__}{suffix}\n")
        return False


# ═════════════════════════════════════════════════════════════════════════════
#  Утилиты сбора данных и статусов
# ═════════════════════════════════════════════════════════════════════════════

def get_system_info_text() -> str:
    """Сбор информации о ресурсах системы и Hydra-сервисах."""
    hostname = html.escape(socket.gethostname())
    try:
        state = load_state()
        server_ip = html.escape(state.network.server_ip or "N/A")
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
            services_lines.append(f"• {icon} <b>{html.escape(str(name))}</b>{html.escape(port)}")
    except Exception as e:
        services_lines.append(f"Ошибка получения статуса: {html.escape(str(e))}")

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
    from hydra.plugins.antidpi.plugin import AntiDPIPlugin, STATE_FILE, active_bans
    plugin = AntiDPIPlugin()
    status = plugin.status()
    running_icon = "🟢 Активен" if status.running else ("⚠️ Установлен" if status.installed else "🔴 Отключен")

    banned_ips = []
    events_count = 0
    if STATE_FILE.exists():
        try:
            data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            banned = active_bans(data)
            events_count = data.get("events", 0)
            source_counts = data.get("source_counts", {}) if isinstance(data.get("source_counts"), dict) else {}
            signal_counts = data.get("signal_counts", {}) if isinstance(data.get("signal_counts"), dict) else {}
            notification_stats = data.get("notification_stats", {}) if isinstance(data.get("notification_stats"), dict) else {}
            suppressed_notices = int(data.get("suppressed_ban_notifications", 0) or 0)
            ordered_bans = sorted(
                banned.items(),
                key=lambda item: float(item[1].get("at", 0) or 0),
                reverse=True,
            )
            for ip, meta in ordered_bans:
                try:
                    score = float(meta.get("score", 0))
                except (TypeError, ValueError):
                    score = 0.0
                raw_signals = meta.get("signals", [])
                signals = ", ".join(str(value) for value in raw_signals) if isinstance(raw_signals, list) else str(raw_signals or "")
                banned_ips.append(f"• <code>{html.escape(str(ip))}</code> (score: {score:.1f}, {html.escape(signals)})")
        except Exception:
            pass

    source_counts = locals().get("source_counts", {})
    signal_counts = locals().get("signal_counts", {})
    notification_stats = locals().get("notification_stats", {})
    suppressed_notices = locals().get("suppressed_notices", 0)

    def summarize(counter: dict) -> str:
        safe = []
        for name, value in counter.items():
            try:
                safe.append((str(name), int(value)))
            except (TypeError, ValueError):
                continue
        safe.sort(key=lambda item: item[1], reverse=True)
        return ", ".join(f"{html.escape(name)}: {value}" for name, value in safe[:5]) or "нет данных"

    sources_block = summarize(source_counts)
    signals_block = summarize(signal_counts)
    delivered = int(notification_stats.get("delivered", 0) or 0)
    failed = int(notification_stats.get("failed", 0) or 0)
    banned_block = "\n".join(banned_ips[:10]) if banned_ips else "<i>Нет заблокированных IP</i>"
    if len(banned_ips) > 10:
        banned_block += f"\n<i>...и ещё {len(banned_ips) - 10} IP</i>"

    return (
        "<b>🛡️ AntiDPI Status</b>\n\n"
        f"<b>Статус:</b> {running_icon}\n"
        f"<b>Всего событий:</b> {events_count}\n"
        f"<b>Заблокировано IP:</b> {len(banned_ips)}\n"
        f"<b>Источники:</b> {sources_block}\n"
        f"<b>Сигналы:</b> {signals_block}\n"
        f"<b>Уведомления:</b> доставлено {delivered}, ошибок {failed}, "
        f"сгруппировано {suppressed_notices}\n\n"
        f"<b>Заблокированные IP:</b>\n{banned_block}"
    )


def get_fail2ban_status_text() -> str:
    """Получить статус Fail2ban и список активных джейлов."""
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
                    jails_info.append(f"• <b>{html.escape(jail)}</b>: <code>{count} banned</code>")
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
    try:
        target_ip = ipaddress.ip_address(str(ip).strip().strip("[]")).compressed
    except ValueError:
        return "<b>❌ Некорректный IP-адрес.</b>"
    safe_ip = html.escape(target_ip)

    # AntiDPI unban
    try:
        adpi_ok = AntiDPIPlugin().unban(target_ip)
        results.append(f"• AntiDPI: {'✅ Разблокирован' if adpi_ok else 'ℹ️ Не найден в бане'}")
    except Exception as e:
        results.append(f"• AntiDPI: ❌ Ошибка ({html.escape(str(e))})")

    # Honeypot unban
    try:
        from hydra.plugins.honeypot.plugin import HoneypotPlugin
        honeypot_ok = HoneypotPlugin().unban(target_ip)
        results.append(f"• Honeypot: {'✅ Разблокирован' if honeypot_ok else 'ℹ️ Не найден в бане'}")
    except Exception as e:
        results.append(f"• Honeypot: ❌ Ошибка ({html.escape(str(e))})")

    # Fail2ban unban
    try:
        f2b_res = HOST.run(["fail2ban-client", "unban", target_ip], timeout=10, text=True)
        if f2b_res.returncode == 0:
            results.append(f"• Fail2ban: ✅ Разблокирован ({html.escape(f2b_res.stdout.strip())})")
        else:
            results.append("• Fail2ban: ℹ️ Не найден в джейлах")
    except Exception as e:
        results.append(f"• Fail2ban: ❌ Ошибка ({html.escape(str(e))})")

    return f"<b>🔓 Результат разблокировки IP <code>{safe_ip}</code>:</b>\n\n" + "\n".join(results)


# ═════════════════════════════════════════════════════════════════════════════
#  Fail2ban Monitor Thread
# ═════════════════════════════════════════════════════════════════════════════

def _process_fail2ban_log_line(line: str) -> None:
    match = re.search(r"NOTICE\s+\[(?P<jail>[^\]]+)\]\s+(?P<action>Ban|Unban)\s+(?P<ip>\S+)", line)
    if match:
        jail = html.escape(match.group("jail"))
        action = match.group("action")
        ip = html.escape(match.group("ip"))

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
        category = "fail2ban" if action == "Ban" else "fail2ban_unban"
        send_admin_notification(msg, category=category)


def _fail2ban_monitor_worker(stop_event: threading.Event) -> None:
    f2b_log = Path("/var/log/fail2ban.log")
    if f2b_log.exists():
        handle = None
        inode = None
        try:
            while not stop_event.is_set():
                if handle is None:
                    try:
                        handle = f2b_log.open("r", encoding="utf-8", errors="replace")
                        handle.seek(0, 2)
                        inode = f2b_log.stat().st_ino
                    except OSError:
                        if handle is not None:
                            handle.close()
                        handle = None
                        stop_event.wait(0.5)
                        continue
                try:
                    stat = f2b_log.stat()
                    if stat.st_ino != inode or stat.st_size < handle.tell():
                        handle.close()
                        handle = None
                        continue
                    line = handle.readline()
                except OSError:
                    handle.close()
                    handle = None
                    continue
                if line:
                    _process_fail2ban_log_line(line)
                else:
                    stop_event.wait(0.5)
        except Exception:
            pass
        finally:
            if handle is not None:
                handle.close()
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

def _notification_settings_text() -> str:
    tg = load_state().telegram
    mark = lambda value: "✅" if value else "❌"
    return (
        "<b>🔔 Настройки уведомлений</b>\n\n"
        f"Все уведомления: {mark(getattr(tg, 'notifications_enabled', True))}\n"
        f"AntiDPI: {mark(getattr(tg, 'notify_antidpi', True))}\n"
        f"Fail2ban BAN: {mark(getattr(tg, 'notify_fail2ban', True))}\n"
        f"События UNBAN: {mark(getattr(tg, 'notify_unbans', False))}\n"
        f"Системные: {mark(getattr(tg, 'notify_system', True))}"
    )


def _toggle_notification(field: str) -> bool:
    allowed = {
        "notifications_enabled", "notify_antidpi", "notify_fail2ban",
        "notify_unbans", "notify_system",
    }
    if field not in allowed:
        raise ValueError("unknown notification setting")

    def mutate(state: AppState) -> bool:
        value = not bool(getattr(state.telegram, field, True))
        setattr(state.telegram, field, value)
        return value

    _, value = update_state(mutate)
    return value


def _main_keyboard():
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🖥 Система", callback_data="view:system"),
            InlineKeyboardButton("🛡 AntiDPI", callback_data="view:antidpi"),
        ],
        [
            InlineKeyboardButton("🚫 Fail2ban", callback_data="view:fail2ban"),
            InlineKeyboardButton("🔔 Уведомления", callback_data="view:notifications"),
        ],
        [InlineKeyboardButton("🔄 Обновить", callback_data="view:home")],
    ])


def _back_keyboard(*, refresh: str = "home", extra: list | None = None):
    rows = list(extra or [])
    rows.append([
        InlineKeyboardButton("🔄 Обновить", callback_data=f"view:{refresh}"),
        InlineKeyboardButton("⬅️ Меню", callback_data="view:home"),
    ])
    return InlineKeyboardMarkup(rows)


def _notification_keyboard():
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("Все", callback_data="notify:notifications_enabled"),
            InlineKeyboardButton("AntiDPI", callback_data="notify:notify_antidpi"),
        ],
        [
            InlineKeyboardButton("Fail2ban", callback_data="notify:notify_fail2ban"),
            InlineKeyboardButton("UNBAN", callback_data="notify:notify_unbans"),
        ],
        [
            InlineKeyboardButton("Системные", callback_data="notify:notify_system"),
            InlineKeyboardButton("⬅️ Меню", callback_data="view:home"),
        ],
    ])


def _antidpi_keyboard():
    from hydra.plugins.antidpi.plugin import AntiDPIPlugin, STATE_FILE, active_bans

    status = AntiDPIPlugin().status()
    action = "⏸ Остановить" if status.running else "▶️ Запустить"
    rows = [[InlineKeyboardButton(action, callback_data="ask:antidpi_toggle")]]
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        banned = active_bans(data)
        addresses = [
            address for address, _metadata in sorted(
                banned.items(),
                key=lambda item: float(item[1].get("at", 0) or 0),
                reverse=True,
            )[:5]
        ]
    except (OSError, ValueError, TypeError):
        addresses = []
    for address in addresses:
        rows.append([InlineKeyboardButton(f"🔓 {address}", callback_data=f"ask-unban:{address}")])
    return _back_keyboard(refresh="antidpi", extra=rows)


def _toggle_antidpi() -> tuple[bool, str]:
    import hydra.core.orchestrator as orchestrator
    from hydra.plugins.antidpi.plugin import AntiDPIPlugin

    state = load_state()
    running = AntiDPIPlugin().status().running
    ok = orchestrator.disable(state, "antidpi") if running else orchestrator.enable(state, "antidpi")
    return ok, "остановлен" if running else "запущен"


class AdminBot:
    def __init__(self, token: str, admin_chat_id: str):
        if not TELEGRAM_AVAILABLE:
            raise RuntimeError("python-telegram-bot не установлен")
        self.token = str(token or "").strip()
        self.admin_chat_id = str(admin_chat_id or "").strip()
        if not self.token:
            raise ValueError("Admin Bot token пуст")
        if not self.admin_chat_id:
            raise ValueError("Admin Chat ID пуст")
        self.app: Optional[Application] = None
        self.stop_event = threading.Event()
        self.monitor_thread: Optional[threading.Thread] = None

    async def _check_admin(self, update: Update) -> bool:
        if update.effective_user and str(update.effective_user.id).strip() == self.admin_chat_id:
            return True
        if update.callback_query:
            await update.callback_query.answer("Доступ запрещён", show_alert=True)
        elif update.effective_message:
            await update.effective_message.reply_text("Доступ запрещён.")
        return False

    async def _show(self, update: Update, text: str, keyboard=None) -> None:
        if update.callback_query:
            await update.callback_query.answer()
            try:
                await update.callback_query.edit_message_text(
                    text, parse_mode="HTML", reply_markup=keyboard,
                    disable_web_page_preview=True,
                )
                return
            except Exception as exc:
                if "message is not modified" in str(exc).lower():
                    return
        if update.effective_message:
            await update.effective_message.reply_text(
                text, parse_mode="HTML", reply_markup=keyboard,
                disable_web_page_preview=True,
            )

    async def cmd_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not await self._check_admin(update):
            return
        await self._show(
            update,
            "<b>🛡️ HYDRA Control Center</b>\n\n"
            "Управление защитой и мониторингом VPS. Выберите раздел:",
            _main_keyboard(),
        )

    async def cmd_system(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not await self._check_admin(update):
            return
        msg = await asyncio.to_thread(get_system_info_text)
        await self._show(update, msg, _back_keyboard(refresh="system"))

    async def cmd_antidpi(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not await self._check_admin(update):
            return
        msg = await asyncio.to_thread(get_antidpi_status_text)
        keyboard = await asyncio.to_thread(_antidpi_keyboard)
        await self._show(update, msg, keyboard)

    async def cmd_fail2ban(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not await self._check_admin(update):
            return
        msg = await asyncio.to_thread(get_fail2ban_status_text)
        await self._show(update, msg, _back_keyboard(refresh="fail2ban"))

    async def cmd_notifications(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not await self._check_admin(update):
            return
        msg = await asyncio.to_thread(_notification_settings_text)
        await self._show(update, msg, _notification_keyboard())

    async def cmd_unban(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not await self._check_admin(update):
            return
        if not context.args:
            await self._show(update, "Использование: <code>/unban &lt;ip&gt;</code>", _back_keyboard())
            return
        msg = await asyncio.to_thread(unban_ip_everywhere, context.args[0].strip())
        await self._show(update, msg, _back_keyboard(refresh="antidpi"))

    async def handle_message(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Keep the bot responsive to text and unsupported commands."""
        if not await self._check_admin(update):
            return
        await self._show(
            update,
            "<b>🛡️ HYDRA Control Center</b>\n\n"
            "Используйте кнопки меню или команды /system, /antidpi, "
            "/fail2ban, /notifications и /unban &lt;ip&gt;.",
            _main_keyboard(),
        )

    async def handle_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not await self._check_admin(update):
            return
        data = str(update.callback_query.data or "")
        if data == "view:home":
            await self.cmd_start(update, context)
        elif data == "view:system":
            await self.cmd_system(update, context)
        elif data == "view:antidpi":
            await self.cmd_antidpi(update, context)
        elif data == "view:fail2ban":
            await self.cmd_fail2ban(update, context)
        elif data == "view:notifications":
            await self.cmd_notifications(update, context)
        elif data.startswith("notify:"):
            field = data.split(":", 1)[1]
            try:
                await asyncio.to_thread(_toggle_notification, field)
                msg = await asyncio.to_thread(_notification_settings_text)
                await self._show(update, msg, _notification_keyboard())
            except ValueError:
                await update.callback_query.answer("Неизвестная настройка", show_alert=True)
        elif data == "ask:antidpi_toggle":
            keyboard = InlineKeyboardMarkup([[
                InlineKeyboardButton("✅ Подтвердить", callback_data="antidpi:toggle"),
                InlineKeyboardButton("Отмена", callback_data="view:antidpi"),
            ]])
            await self._show(update, "Изменить состояние AntiDPI?", keyboard)
        elif data.startswith("ask-unban:"):
            address = data.split(":", 1)[1]
            keyboard = InlineKeyboardMarkup([[
                InlineKeyboardButton("✅ Разбанить", callback_data=f"unban:{address}"),
                InlineKeyboardButton("Отмена", callback_data="view:antidpi"),
            ]])
            await self._show(
                update,
                f"Снять блокировку с <code>{html.escape(address)}</code> во всех системах?",
                keyboard,
            )
        elif data == "antidpi:toggle":
            try:
                ok, action = await asyncio.to_thread(_toggle_antidpi)
                prefix = "✅" if ok else "❌"
                status_text = await asyncio.to_thread(get_antidpi_status_text)
                msg = f"{prefix} AntiDPI {action}.\n\n{status_text}"
            except Exception as exc:
                msg = f"❌ Не удалось изменить состояние AntiDPI: {html.escape(str(exc))}"
            keyboard = await asyncio.to_thread(_antidpi_keyboard)
            await self._show(update, msg, keyboard)
        elif data.startswith("unban:"):
            msg = await asyncio.to_thread(unban_ip_everywhere, data.split(":", 1)[1])
            keyboard = await asyncio.to_thread(_antidpi_keyboard)
            await self._show(update, msg, keyboard)
        else:
            await update.callback_query.answer("Неизвестное действие", show_alert=True)

    def run(self):
        self.stop_event.clear()
        self.monitor_thread = threading.Thread(
            target=_fail2ban_monitor_worker,
            args=(self.stop_event,),
            daemon=True,
        )
        try:
            self.monitor_thread.start()
            self.app = Application.builder().token(self.token).build()
            self.app.add_handler(CommandHandler(["start", "help", "menu"], self.cmd_start))
            self.app.add_handler(CommandHandler(["system", "status"], self.cmd_system))
            self.app.add_handler(CommandHandler("antidpi", self.cmd_antidpi))
            self.app.add_handler(CommandHandler("fail2ban", self.cmd_fail2ban))
            self.app.add_handler(CommandHandler(["notifications", "notify"], self.cmd_notifications))
            self.app.add_handler(CommandHandler("unban", self.cmd_unban))
            self.app.add_handler(CallbackQueryHandler(self.handle_callback))
            self.app.add_handler(MessageHandler(filters.COMMAND | filters.TEXT, self.handle_message))
            self.app.run_polling()
        finally:
            self.stop_event.set()
            if self.monitor_thread.is_alive():
                self.monitor_thread.join(timeout=2)


def run_admin_bot(token: str, admin_chat_id: str):
    bot = AdminBot(token, admin_chat_id)
    bot.run()


def run_client_bot(token: str, admin_chat_id: str):
    """Совместимость со старым вызовом. Логика клиентского бота удалена."""
    print("ClientBot устарел и отключен. Используйте AdminBot для мониторинга и уведомлений.")
