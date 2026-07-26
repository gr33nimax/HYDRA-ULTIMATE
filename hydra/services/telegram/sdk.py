"""Optional python-telegram-bot imports used by the Telegram adapter."""
from __future__ import annotations

try:
    from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
    from telegram.ext import (
        Application,
        CallbackQueryHandler,
        CommandHandler,
        ContextTypes,
        MessageHandler,
        filters,
    )

    TELEGRAM_AVAILABLE = True
except ImportError:
    TELEGRAM_AVAILABLE = False

    class InlineKeyboardButton:
        """Minimal value object for rendering and tests without the SDK."""

        def __init__(self, text: str, *, callback_data: str | None = None):
            self.text = text
            self.callback_data = callback_data

    class InlineKeyboardMarkup:
        """Minimal keyboard container used when the SDK is unavailable."""

        def __init__(self, inline_keyboard: list[list[InlineKeyboardButton]]):
            self.inline_keyboard = inline_keyboard

    class Update:
        """Typing placeholder for environments without the optional SDK."""

    Application = None
    CallbackQueryHandler = None
    CommandHandler = None
    ContextTypes = None
    MessageHandler = None
    filters = None


__all__ = [
    "Application",
    "CallbackQueryHandler",
    "CommandHandler",
    "ContextTypes",
    "InlineKeyboardButton",
    "InlineKeyboardMarkup",
    "MessageHandler",
    "TELEGRAM_AVAILABLE",
    "Update",
    "filters",
]
