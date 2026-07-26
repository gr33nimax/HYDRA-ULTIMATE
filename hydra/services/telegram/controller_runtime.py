"""Telegram polling runtime for the AdminBot adapter."""
from __future__ import annotations

import threading

from hydra.services.telegram import security_actions


def run_admin_bot_transport(
    bot,
    *,
    application_type,
    callback_handler,
    command_handler,
    message_handler,
    filters_object,
) -> None:
    bot.stop_event.clear()
    bot.monitor_threads = [
        threading.Thread(
            target=security_actions._fail2ban_monitor_worker,
            args=(bot.stop_event, bot.application),
            kwargs={"notify": bot.notifier},
            daemon=True,
        ),
        threading.Thread(
            target=security_actions._honeypot_monitor_worker,
            args=(bot.stop_event, bot.application),
            kwargs={"notify": bot.notifier},
            daemon=True,
        ),
    ]
    try:
        for monitor in bot.monitor_threads:
            monitor.start()
        if application_type is None:
            raise RuntimeError("python-telegram-bot не установлен")
        bot.telegram_app = application_type.builder().token(bot.token).build()
        bot.telegram_app.add_handler(
            command_handler(
                ["start", "help", "menu"],
                bot.cmd_start,
            ),
        )
        bot.telegram_app.add_handler(
            command_handler(["system", "status"], bot.cmd_system),
        )
        bot.telegram_app.add_handler(
            command_handler("antidpi", bot.cmd_antidpi),
        )
        bot.telegram_app.add_handler(
            command_handler("honeypot", bot.cmd_honeypot),
        )
        bot.telegram_app.add_handler(
            command_handler("fail2ban", bot.cmd_fail2ban),
        )
        bot.telegram_app.add_handler(
            command_handler(
                ["notifications", "notify"],
                bot.cmd_notifications,
            ),
        )
        bot.telegram_app.add_handler(
            command_handler("unban", bot.cmd_unban),
        )
        bot.telegram_app.add_handler(
            callback_handler(bot.handle_callback),
        )
        bot.telegram_app.add_handler(
            message_handler(
                filters_object.COMMAND | filters_object.TEXT,
                bot.handle_message,
            ),
        )
        bot.telegram_app.run_polling()
    finally:
        bot.stop_event.set()
        for monitor in bot.monitor_threads:
            if monitor.is_alive():
                monitor.join(timeout=2)
