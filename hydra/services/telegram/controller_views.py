"""Authorization, rendering and command handlers for AdminBot."""
from __future__ import annotations

import asyncio

from hydra.services.telegram import dashboards, security_actions
from hydra.services.telegram.sdk import ContextTypes, Update


class AdminBotViewMixin:
    async def _check_admin(self, update: Update) -> bool:
        user = getattr(update, "effective_user", None)
        if user and str(user.id).strip() == self.admin_chat_id:
            return True

        chat = getattr(update, "effective_chat", None)
        if user and chat and str(chat.id).strip() == self.admin_chat_id:
            try:
                member = await update.get_bot().get_chat_member(
                    chat_id=chat.id,
                    user_id=user.id,
                )
                status = getattr(member, "status", "")
                status = str(getattr(status, "value", status)).lower()
                if status in {"administrator", "creator", "owner"}:
                    return True
            except Exception:
                pass
        if update.callback_query:
            await update.callback_query.answer(
                "Доступ запрещён",
                show_alert=True,
            )
        elif update.effective_message:
            await update.effective_message.reply_text("Доступ запрещён.")
        return False

    async def _show(self, update: Update, text: str, keyboard=None) -> None:
        if update.callback_query:
            await update.callback_query.answer()
            try:
                await update.callback_query.edit_message_text(
                    text,
                    parse_mode="HTML",
                    reply_markup=keyboard,
                    disable_web_page_preview=True,
                )
                return
            except Exception as exc:
                if "message is not modified" in str(exc).lower():
                    return
        if update.effective_message:
            await update.effective_message.reply_text(
                text,
                parse_mode="HTML",
                reply_markup=keyboard,
                disable_web_page_preview=True,
            )

    async def cmd_start(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE,
    ) -> None:
        if not await self._check_admin(update):
            return
        await self._show(
            update,
            "<b>🛡️ HYDRA Control Center</b>\n\n"
            "Управление защитой и мониторингом VPS. Выберите раздел:",
            security_actions._main_keyboard(),
        )

    async def cmd_system(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE,
    ) -> None:
        if not await self._check_admin(update):
            return
        message = await asyncio.to_thread(
            dashboards.get_system_info_text,
            self.application,
        )
        await self._show(
            update,
            message,
            security_actions._back_keyboard(refresh="system"),
        )

    async def cmd_antidpi(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE,
    ) -> None:
        if not await self._check_admin(update):
            return
        message = await asyncio.to_thread(
            dashboards.get_antidpi_dashboard_text,
            self.application,
        )
        keyboard = await asyncio.to_thread(
            security_actions._antidpi_keyboard,
            self.application,
        )
        await self._show(update, message, keyboard)

    async def cmd_honeypot(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE,
    ) -> None:
        if not await self._check_admin(update):
            return
        message = await asyncio.to_thread(
            dashboards.get_honeypot_status_text,
            self.application,
        )
        keyboard = await asyncio.to_thread(
            security_actions._honeypot_keyboard,
            self.application,
        )
        await self._show(update, message, keyboard)

    async def cmd_fail2ban(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE,
    ) -> None:
        if not await self._check_admin(update):
            return
        message = await asyncio.to_thread(
            dashboards.get_fail2ban_dashboard_text,
            self.application,
        )
        keyboard = await asyncio.to_thread(
            security_actions._fail2ban_keyboard,
            self.application,
        )
        await self._show(update, message, keyboard)

    async def cmd_notifications(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE,
    ) -> None:
        if not await self._check_admin(update):
            return
        message = await asyncio.to_thread(
            security_actions._notification_settings_text,
        )
        await self._show(
            update,
            message,
            security_actions._notification_keyboard(),
        )

    async def cmd_unban(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE,
    ) -> None:
        if not await self._check_admin(update):
            return
        if not context.args:
            await self._show(
                update,
                "Использование: <code>/unban &lt;ip&gt;</code>",
                security_actions._back_keyboard(),
            )
            return
        message = await asyncio.to_thread(
            security_actions.unban_ip_everywhere,
            context.args[0].strip(),
            self.application,
        )
        await self._show(
            update,
            message,
            security_actions._back_keyboard(refresh="antidpi"),
        )

    async def handle_message(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE,
    ) -> None:
        if not await self._check_admin(update):
            return
        await self._show(
            update,
            "<b>🛡️ HYDRA Control Center</b>\n\n"
            "Используйте кнопки меню или команды /system, /antidpi, "
            "/honeypot, /fail2ban, /notifications и /unban &lt;ip&gt;.",
            security_actions._main_keyboard(),
        )
