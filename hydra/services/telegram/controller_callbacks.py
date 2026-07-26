"""Callback routing and action handlers for AdminBot."""
from __future__ import annotations

import asyncio
import html

from hydra.services.telegram import dashboards, security_actions
from hydra.services.telegram.sdk import (
    ContextTypes,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Update,
)


class AdminBotCallbackMixin:
    async def handle_callback(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE,
    ) -> None:
        if not await self._check_admin(update):
            return
        data = str(update.callback_query.data or "")
        if data == "view:home":
            await self.cmd_start(update, context)
        elif data == "view:system":
            await self.cmd_system(update, context)
        elif data == "view:antidpi":
            await self.cmd_antidpi(update, context)
        elif data == "view:honeypot":
            await self.cmd_honeypot(update, context)
        elif data == "view:fail2ban":
            await self.cmd_fail2ban(update, context)
        elif data == "view:notifications":
            await self.cmd_notifications(update, context)
        elif data.startswith("notify:"):
            await self._toggle_notification(update, data)
        elif data == "ask:antidpi_toggle":
            await self._confirm_toggle(
                update,
                "AntiDPI",
                "antidpi:toggle",
                "view:antidpi",
            )
        elif data == "ask:honeypot_toggle":
            await self._confirm_toggle(
                update,
                "Honeypot",
                "honeypot:toggle",
                "view:honeypot",
            )
        elif data == "ask:fail2ban_toggle":
            await self._confirm_toggle(
                update,
                "Fail2ban",
                "fail2ban:toggle",
                "view:fail2ban",
            )
        elif data.startswith("ask-unban:"):
            await self._confirm_unban(update, data, honeypot_only=False)
        elif data.startswith("ask-hp-unban:"):
            await self._confirm_unban(update, data, honeypot_only=True)
        elif data == "antidpi:toggle":
            await self._toggle_security_component(update, "antidpi")
        elif data == "honeypot:toggle":
            await self._toggle_security_component(update, "honeypot")
        elif data == "fail2ban:toggle":
            await self._toggle_security_component(update, "fail2ban")
        elif data.startswith("hp-unban:"):
            await self._unban_honeypot(update, data)
        elif data.startswith("unban:"):
            await self._unban_everywhere(update, data)
        elif data.startswith("antidpi-ban:"):
            await self._ban_antidpi(update, data)
        else:
            await update.callback_query.answer(
                "Неизвестное действие",
                show_alert=True,
            )

    async def _toggle_notification(self, update: Update, data: str) -> None:
        field = data.split(":", 1)[1]
        try:
            await asyncio.to_thread(
                security_actions._toggle_notification,
                field,
            )
            message = await asyncio.to_thread(
                security_actions._notification_settings_text,
            )
            await self._show(
                update,
                message,
                security_actions._notification_keyboard(),
            )
        except ValueError:
            await update.callback_query.answer(
                "Неизвестная настройка",
                show_alert=True,
            )

    async def _confirm_toggle(
        self,
        update: Update,
        name: str,
        callback_data: str,
        cancel_data: str,
    ) -> None:
        keyboard = InlineKeyboardMarkup(
            [
                [
                    InlineKeyboardButton(
                        "✅ Подтвердить",
                        callback_data=callback_data,
                    ),
                    InlineKeyboardButton(
                        "Отмена",
                        callback_data=cancel_data,
                    ),
                ],
            ],
        )
        await self._show(
            update,
            f"Изменить состояние {name}?",
            keyboard,
        )

    async def _confirm_unban(
        self,
        update: Update,
        data: str,
        *,
        honeypot_only: bool,
    ) -> None:
        address = data.split(":", 1)[1]
        callback_data = (
            f"hp-unban:{address}"
            if honeypot_only
            else f"unban:{address}"
        )
        cancel_data = "view:honeypot" if honeypot_only else "view:antidpi"
        keyboard = InlineKeyboardMarkup(
            [
                [
                    InlineKeyboardButton(
                        "✅ Разбанить",
                        callback_data=callback_data,
                    ),
                    InlineKeyboardButton(
                        "Отмена",
                        callback_data=cancel_data,
                    ),
                ],
            ],
        )
        scope = "Honeypot-блокировку" if honeypot_only else "блокировку"
        suffix = "" if honeypot_only else " во всех системах"
        await self._show(
            update,
            f"Снять {scope} с <code>{html.escape(address)}</code>"
            f"{suffix}?",
            keyboard,
        )

    async def _toggle_security_component(
        self,
        update: Update,
        name: str,
    ) -> None:
        toggle = {
            "antidpi": security_actions._toggle_antidpi,
            "honeypot": security_actions._toggle_honeypot,
            "fail2ban": security_actions._toggle_fail2ban,
        }[name]
        dashboard = {
            "antidpi": dashboards.get_antidpi_dashboard_text,
            "honeypot": dashboards.get_honeypot_status_text,
            "fail2ban": dashboards.get_fail2ban_dashboard_text,
        }[name]
        keyboard = {
            "antidpi": security_actions._antidpi_keyboard,
            "honeypot": security_actions._honeypot_keyboard,
            "fail2ban": security_actions._fail2ban_keyboard,
        }[name]
        label = {
            "antidpi": "AntiDPI",
            "honeypot": "Honeypot",
            "fail2ban": "Fail2ban",
        }[name]
        try:
            ok, action = await asyncio.to_thread(toggle, self.application)
            prefix = "✅" if ok else "❌"
            status_text = await asyncio.to_thread(
                dashboard,
                self.application,
            )
            message = f"{prefix} {label} {action}.\n\n{status_text}"
        except Exception as exc:
            message = (
                f"❌ Ошибка управления {label}: "
                f"{html.escape(str(exc))}"
            )
        markup = await asyncio.to_thread(keyboard, self.application)
        await self._show(update, message, markup)

    async def _unban_honeypot(self, update: Update, data: str) -> None:
        address = data.split(":", 1)[1]
        ok = await asyncio.to_thread(
            self.application.plugin_action,
            "honeypot",
            "unban",
            raw=address,
        )
        message = (
            f"{'✅' if ok else 'ℹ️'} Honeypot: "
            f"<code>{html.escape(address)}</code> "
            + ("разблокирован" if ok else "не найден")
        )
        keyboard = await asyncio.to_thread(
            security_actions._honeypot_keyboard,
            self.application,
        )
        await self._show(update, message, keyboard)

    async def _unban_everywhere(self, update: Update, data: str) -> None:
        message = await asyncio.to_thread(
            security_actions.unban_ip_everywhere,
            data.split(":", 1)[1],
            self.application,
        )
        keyboard = await asyncio.to_thread(
            security_actions._antidpi_keyboard,
            self.application,
        )
        await self._show(update, message, keyboard)

    async def _ban_antidpi(self, update: Update, data: str) -> None:
        address = data.split(":", 1)[1]
        result = await asyncio.to_thread(
            security_actions.ban_ip_antidpi,
            address,
            self.application,
        )
        if not result.get("ok"):
            errors = {
                "invalid_ip": "Некорректный IP-адрес",
                "whitelisted": "IP находится в whitelist",
                "firewall_error": "Не удалось применить firewall ban",
            }
            await update.callback_query.answer(
                errors.get(
                    str(result.get("error")),
                    "Не удалось заблокировать IP",
                ),
                show_alert=True,
            )
            return
        duration = max(
            0,
            int(
                result.get(
                    "remaining",
                    result.get("duration", 0),
                )
                or 0,
            ),
        )
        ttl = (
            "бессрочно"
            if result.get("permanent") is True
            else dashboards._format_period(duration)
        )
        status = (
            "already_banned"
            if result.get("already_active")
            else "manual_ban"
        )
        message = update.callback_query.message
        original = getattr(message, "text_html", None)
        if not isinstance(original, str) or not original:
            original = html.escape(
                str(
                    getattr(
                        message,
                        "text",
                        "AntiDPI · ALERT",
                    )
                    or "AntiDPI · ALERT",
                ),
            )
        updated = (
            f"{original}\n"
            f"<b>Action:</b> <code>{status}</code>\n"
            f"<b>TTL:</b> <code>{ttl}</code>\n"
            f"<b>Offense:</b> "
            f"<code>{int(result.get('offense_count', 1) or 1)}</code>"
        )
        try:
            await update.callback_query.edit_message_text(
                updated,
                parse_mode="HTML",
                reply_markup=None,
                disable_web_page_preview=True,
            )
        except Exception:
            await update.callback_query.answer(
                "IP заблокирован, но сообщение не удалось обновить",
                show_alert=True,
            )
            return
        await update.callback_query.answer(
            "IP уже заблокирован"
            if result.get("already_active")
            else "IP заблокирован",
        )
