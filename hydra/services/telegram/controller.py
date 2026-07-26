"""Telegram transport controller with explicit application dependencies."""
from __future__ import annotations

import threading
from typing import Any

from hydra.services.application import ApplicationService
from hydra.services.security_notifications import send_admin_notification
from hydra.services.telegram import dashboards, security_actions
from hydra.services.telegram.controller_callbacks import (
    AdminBotCallbackMixin,
)
from hydra.services.telegram.controller_runtime import (
    run_admin_bot_transport,
)
from hydra.services.telegram.controller_views import AdminBotViewMixin
from hydra.services.telegram.sdk import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    MessageHandler,
    TELEGRAM_AVAILABLE,
    filters,
)


class AdminBot(AdminBotViewMixin, AdminBotCallbackMixin):
    """Telegram command/callback adapter over an injected application service."""

    def __init__(
        self,
        token: str,
        admin_chat_id: str,
        application: ApplicationService,
        *,
        notifier=send_admin_notification,
    ) -> None:
        if not TELEGRAM_AVAILABLE:
            raise RuntimeError("python-telegram-bot не установлен")
        self.token = str(token or "").strip()
        self.admin_chat_id = str(admin_chat_id or "").strip()
        if not self.token:
            raise ValueError("Admin Bot token пуст")
        if not self.admin_chat_id:
            raise ValueError("Admin Chat ID пуст")
        self.application = application
        self.notifier = notifier
        self.telegram_app: Any | None = None
        self.stop_event = threading.Event()
        self.monitor_threads: list[threading.Thread] = []

    def run(self) -> None:
        run_admin_bot_transport(
            self,
            application_type=Application,
            callback_handler=CallbackQueryHandler,
            command_handler=CommandHandler,
            message_handler=MessageHandler,
            filters_object=filters,
        )


__all__ = ["AdminBot"]
