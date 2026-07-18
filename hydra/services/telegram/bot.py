"""
hydra/services/telegram/bot.py — Telegram-боты (Admin + Client) v2.

Архитектура:
  - Admin Bot: управление пользователями, трафик, безопасность
  - Client Bot: выдача подписок, конфигов, QR-кодов

Оба бота работают как отдельные systemd-сервисы.
Используют новый динамический генератор подписок v2.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from hydra.core.state import (
    AppState, User, load_state, save_state, find_user, add_user,
)
from hydra.services.subscriptions.generator import (
    generate_singbox_config, generate_base64_sub, generate_client_config,
    generate_links,
)
from hydra.core import orchestrator
from hydra.services.traffic import collect_traffic, refresh_traffic_state
from hydra.plugins.registry import status_all

try:
    from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
    from telegram.ext import (
        Application, CommandHandler, CallbackQueryHandler,
        MessageHandler, filters, ContextTypes, ConversationHandler,
    )
    TELEGRAM_AVAILABLE = True
except ImportError:
    TELEGRAM_AVAILABLE = False

BOT_DIR = Path("/var/lib/hydra/bots")
ADMIN_STATE_FILE = BOT_DIR / "admin_state.json"


# ═════════════════════════════════════════════════════════════════════════════
#  Admin Bot
# ═════════════════════════════════════════════════════════════════════════════

class AdminBot:
    def __init__(self, token: str, admin_chat_id: str):
        if not TELEGRAM_AVAILABLE:
            raise RuntimeError("python-telegram-bot не установлен")
        self.token = token
        self.admin_chat_id = int(admin_chat_id)
        self.app: Optional[Application] = None

    async def _check_admin(self, update: Update) -> bool:
        if update.effective_user and update.effective_user.id == self.admin_chat_id:
            return True
        await update.message.reply_text("Доступ запрещён.")
        return False

    async def cmd_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not await self._check_admin(update):
            return
        await update.message.reply_text(
            "HYDRA Admin Panel\n\n"
            "/users — управление пользователями\n"
            "/traffic — статистика трафика\n"
            "/status — статус протоколов\n"
            "/adduser <email> — добавить пользователя\n"
            "/deluser <email> — удалить пользователя\n"
            "/help — справка",
            parse_mode="Markdown",
        )

    async def cmd_users(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not await self._check_admin(update):
            return
        state = load_state()
        if not state.users:
            await update.message.reply_text("Нет пользователей.")
            return

        lines = ["Пользователи:\n"]
        for u in state.users:
            status_icon = "🔴" if u.blocked else "🟢"
            limit = f"{u.traffic_limit_gb} GiB" if u.traffic_limit_gb else "∞"
            expiry = u.expiry_date[:10] if u.expiry_date else "∞"
            lines.append(
                f"{status_icon} `{u.email}`\n"
                f"   Лимит: {limit} | TTL: {expiry}"
            )

        await update.message.reply_text("\n".join(lines), parse_mode="Markdown")

    async def cmd_traffic(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not await self._check_admin(update):
            return
        state = refresh_traffic_state()
        traffic = collect_traffic(state)

        lines = ["Трафик:\n"]
        for u in state.users:
            used = traffic.get(u.email, u.traffic_used_bytes)
            used_gb = used / 1073741824
            limit = f"/ {u.traffic_limit_gb} GiB" if u.traffic_limit_gb else ""
            bar = _progress_bar(used, int(u.traffic_limit_gb * 1073741824) if u.traffic_limit_gb else 0)
            lines.append(f"`{u.email}`: {used_gb:.2f} GB {limit}\n{bar}")

        await update.message.reply_text("\n".join(lines), parse_mode="Markdown")

    async def cmd_status(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not await self._check_admin(update):
            return
        plugins = status_all()
        lines = ["Статус протоколов:\n"]
        for name, s in plugins.items():
            icon = "✅" if s["running"] else ("⚠️" if s["installed"] else "❌")
            lines.append(f"{icon} *{name}*: порт {s['port']}")
        await update.message.reply_text("\n".join(lines), parse_mode="Markdown")

    async def cmd_adduser(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not await self._check_admin(update):
            return
        if not context.args:
            await update.message.reply_text("Использование: /adduser <email>")
            return

        import uuid as _uuid
        import secrets as _secrets
        email = context.args[0]
        state = load_state()

        if find_user(state, email):
            await update.message.reply_text(f"Пользователь `{email}` уже существует.")
            return

        user = User(
            email=email,
            uuid=str(_uuid.uuid4()),
            traffic_limit_gb=0,
            created_at=datetime.now().isoformat(),
        )
        orchestrator.add_user(state, user)

        await update.message.reply_text(
            f"Пользователь `{email}` создан.\n"
            f"UUID: `{user.uuid}`",
            parse_mode="Markdown",
        )

    async def cmd_deluser(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not await self._check_admin(update):
            return
        if not context.args:
            await update.message.reply_text("Использование: /deluser <email>")
            return

        email = context.args[0]
        state = load_state()
        user = find_user(state, email)
        if not user:
            await update.message.reply_text(f"Пользователь `{email}` не найден.")
            return

        orchestrator.remove_user(state, email)
        await update.message.reply_text(f"Пользователь `{email}` удалён.", parse_mode="Markdown")

    def run(self):
        self.app = Application.builder().token(self.token).build()
        self.app.add_handler(CommandHandler("start", self.cmd_start))
        self.app.add_handler(CommandHandler("users", self.cmd_users))
        self.app.add_handler(CommandHandler("traffic", self.cmd_traffic))
        self.app.add_handler(CommandHandler("status", self.cmd_status))
        self.app.add_handler(CommandHandler("adduser", self.cmd_adduser))
        self.app.add_handler(CommandHandler("deluser", self.cmd_deluser))
        self.app.run_polling()


# ═════════════════════════════════════════════════════════════════════════════
#  Client Bot
# ═════════════════════════════════════════════════════════════════════════════

class ClientBot:
    def __init__(self, token: str, admin_chat_id: str):
        if not TELEGRAM_AVAILABLE:
            raise RuntimeError("python-telegram-bot не установлен")
        self.token = token
        self.admin_chat_id = int(admin_chat_id)
        self.app: Optional[Application] = None

    def _find_user_by_telegram(self, state: AppState, telegram_id: int) -> Optional[User]:
        for u in state.users:
            if u.telegram_id == telegram_id:
                return u
        return None

    async def cmd_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not update.effective_user:
            return
        tid = update.effective_user.id
        state = load_state()
        user = self._find_user_by_telegram(state, tid)

        if not user:
            token = context.args[0] if context.args else None
            if token:
                for u in state.users:
                    if u.uuid == token:
                        u.telegram_id = tid
                        save_state(state)
                        user = u
                        break

        if not user:
            await update.message.reply_text(
                "У вас нет доступа. Обратитесь к администратору за invite-ссылкой."
            )
            return

        if user.blocked:
            await update.message.reply_text("Ваша подписка заблокирована.")
            return

        limit_text = f"{user.traffic_limit_gb} GiB" if user.traffic_limit_gb else "∞"
        await update.message.reply_text(
            f"HYDRA Subscription\n\n"
            f"Пользователь: `{user.email}`\n"
            f"Лимит: {limit_text}\n\n"
            "/config — получить конфиг (Sing-Box)\n"
            "/link — ссылка для импорта\n"
            "/awg — конфиг AmneziaWG\n"
            "/status — статус подписки",
            parse_mode="Markdown",
        )

    async def cmd_config(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not update.effective_user:
            return
        state = load_state()
        user = self._find_user_by_telegram(state, update.effective_user.id)
        if not user or user.blocked:
            await update.message.reply_text("Нет доступа.")
            return

        config = generate_singbox_config(user, state)
        config_str = json.dumps(config, indent=2, ensure_ascii=False)

        if len(config_str) > 4000:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False, encoding="utf-8",
            ) as f:
                f.write(config_str)
                f.flush()
                await update.message.reply_document(
                    document=open(f.name, "rb"),
                    filename=f"hydra-{user.email}.json",
                    caption="Sing-Box конфиг",
                )
            os.unlink(f.name)
        else:
            await update.message.reply_text(
                f"```json\n{config_str}\n```",
                parse_mode="Markdown",
            )

    async def cmd_link(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not update.effective_user:
            return
        state = load_state()
        user = self._find_user_by_telegram(state, update.effective_user.id)
        if not user or user.blocked:
            await update.message.reply_text("Нет доступа.")
            return

        links = generate_links(user, state)
        if not links:
            await update.message.reply_text("Нет доступных ссылок для импорта.")
            return

        sub_link = generate_base64_sub(user, state)
        lines = [f"`{link}`" for link in links]
        lines.append(
            f"\nBase64-подписка:\n"
            f"`https://{state.network.domain}:9443/sub"
            f"?token={user.uuid}&format=base64`"
        )
        lines.append(
            f"\nSing-Box JSON (ShadowTLS):\n"
            f"`https://{state.network.domain}:9443/sub"
            f"?token={user.uuid}&format=singbox`"
        )
        lines.append(
            f"\nThrone (ShadowTLS chain):\n"
            f"`https://{state.network.domain}:9443/sub"
            f"?token={user.uuid}&format=throne`"
        )
        await update.message.reply_text(
            "\n".join(lines),
            parse_mode="Markdown",
        )

    async def cmd_awg(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not update.effective_user:
            return
        state = load_state()
        user = self._find_user_by_telegram(state, update.effective_user.id)
        if not user or user.blocked:
            await update.message.reply_text("Нет доступа.")
            return

        config = generate_client_config(user, state, "amneziawg")
        if not config:
            await update.message.reply_text("AmneziaWG не доступен.")
            return

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".conf", delete=False, encoding="utf-8",
        ) as f:
            f.write(config)
            f.flush()
            await update.message.reply_document(
                document=open(f.name, "rb"),
                filename=f"awg-{user.email}.conf",
                caption="AmneziaWG конфиг",
            )
        os.unlink(f.name)

    async def cmd_status(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not update.effective_user:
            return
        state = load_state()
        user = self._find_user_by_telegram(state, update.effective_user.id)
        if not user or user.blocked:
            await update.message.reply_text("Нет доступа.")
            return

        used_gb = user.traffic_used_bytes / 1073741824
        limit_str = f"{user.traffic_limit_gb} GiB" if user.traffic_limit_gb else "∞"
        bar = _progress_bar(user.traffic_used_bytes, int(user.traffic_limit_gb * 1073741824) if user.traffic_limit_gb else 0)

        await update.message.reply_text(
            f"Статус подписки\n\n"
            f"Трафик: {used_gb:.2f} GB / {limit_str}\n{bar}\n"
            f"Действует до: {user.expiry_date[:10] if user.expiry_date else '∞'}",
            parse_mode="Markdown",
        )

    def run(self):
        self.app = Application.builder().token(self.token).build()
        self.app.add_handler(CommandHandler("start", self.cmd_start))
        self.app.add_handler(CommandHandler("config", self.cmd_config))
        self.app.add_handler(CommandHandler("link", self.cmd_link))
        self.app.add_handler(CommandHandler("awg", self.cmd_awg))
        self.app.add_handler(CommandHandler("status", self.cmd_status))
        self.app.run_polling()


# ═════════════════════════════════════════════════════════════════════════════
#  Утилиты
# ═════════════════════════════════════════════════════════════════════════════

def _progress_bar(used: int, limit: int, width: int = 15) -> str:
    if limit <= 0:
        return "`[███████████████]` ∞"
    pct = min(used / limit, 1.0)
    filled = int(pct * width)
    bar = "█" * filled + "░" * (width - filled)
    return f"`[{bar}]` {pct:.0%}"


def run_admin_bot(token: str, admin_chat_id: str):
    bot = AdminBot(token, admin_chat_id)
    bot.run()


def run_client_bot(token: str, admin_chat_id: str):
    bot = ClientBot(token, admin_chat_id)
    bot.run()
