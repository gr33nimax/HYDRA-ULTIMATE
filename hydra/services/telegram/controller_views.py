"""Authorization, rendering and command handlers for AdminBot."""
from __future__ import annotations

import asyncio
import html
import ipaddress

from hydra.services.telegram import security_actions
from hydra.services.telegram.controller_screens import (
    SCREEN_RENDERERS,
    render_address_card,
)
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

    async def _render(self, update: Update, render, *arguments) -> None:
        """Render one screen, reporting failures instead of swallowing them."""
        try:
            text, keyboard = await asyncio.to_thread(render, *arguments)
        except Exception as exc:
            await self._report_failure(update, exc)
            return
        await self._show(update, text, keyboard)

    async def _report_failure(self, update: Update, exc: Exception) -> None:
        detail = html.escape(str(exc) or exc.__class__.__name__)[:300]
        message = (
            "<b>⚠️ Не удалось построить экран</b>\n\n"
            f"<code>{detail}</code>\n\n"
            "Панель продолжает работать — попробуйте обновить."
        )
        keyboard = security_actions._back_keyboard()
        if update.callback_query:
            try:
                await update.callback_query.answer(
                    "Ошибка при обновлении экрана",
                    show_alert=True,
                )
            except Exception:
                pass
        await self._show(update, message, keyboard)

    async def cmd_screen(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE,
        *,
        name: str,
        page: int = 1,
    ) -> None:
        """Render any registered screen by name."""
        del context
        if not await self._check_admin(update):
            return
        render = SCREEN_RENDERERS.get(name)
        if render is None:
            await self._show(
                update,
                "<b>Неизвестный экран</b>\n\nВернитесь в меню.",
                security_actions._back_keyboard(),
            )
            return
        await self._render(update, render, self.application, name, page)

    async def cmd_address(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE,
        *,
        address: str,
        origin: str = "antidpi",
    ) -> None:
        """Render the card of one address."""
        del context
        if not await self._check_admin(update):
            return
        await self._render(
            update,
            render_address_card,
            self.application,
            address,
            origin,
        )

    async def cmd_start(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE,
    ) -> None:
        await self.cmd_screen(update, context, name="home")

    async def cmd_system(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE,
    ) -> None:
        await self.cmd_screen(update, context, name="system")

    async def cmd_antidpi(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE,
    ) -> None:
        await self.cmd_screen(update, context, name="antidpi")

    async def cmd_antidpi_details(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE,
    ) -> None:
        await self.cmd_screen(update, context, name="antidpi_details")

    async def cmd_honeypot(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE,
    ) -> None:
        await self.cmd_screen(update, context, name="honeypot")

    async def cmd_fail2ban(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE,
    ) -> None:
        await self.cmd_screen(update, context, name="fail2ban")

    async def cmd_notifications(
        self,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE,
    ) -> None:
        await self.cmd_screen(update, context, name="notifications")

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
        text = str(
            getattr(update.effective_message, "text", "") or "",
        ).strip()
        address = _parse_address(text)
        if address:
            await self.cmd_address(update, context, address=address)
            return
        if text.startswith("/"):
            command = html.escape(text.split()[0][:32])
            await self._show(
                update,
                f"<b>Неизвестная команда</b> <code>{command}</code>\n\n"
                + _COMMAND_HINT,
                security_actions._main_keyboard(),
            )
            return
        await self._show(
            update,
            "<b>🛡️ HYDRA Control Center</b>\n\n" + _COMMAND_HINT,
            security_actions._main_keyboard(),
        )


_COMMAND_HINT = (
    "Команды: /system, /antidpi, /honeypot, /fail2ban, /notifications, "
    "/unban &lt;ip&gt;.\n"
    "Пришлите IPv4 или IPv6 адрес сообщением — открою карточку с тем, "
    "что о нём известно."
)


def _parse_address(text: str) -> str:
    """Return the canonical address if the whole message is one IP."""
    candidate = text.split()[-1].strip("[]") if text.split() else ""
    try:
        return ipaddress.ip_address(candidate).compressed
    except ValueError:
        return ""
