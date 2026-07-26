"""Telegram administration menu controller."""
from __future__ import annotations

from hydra.core.state_models import AppState
from hydra.services.application import ApplicationService
from hydra.ui.tui import (
    clear,
    error,
    info,
    kv,
    menu,
    panel,
    prompt,
    success,
    _ok,
)


def menu_telegram(state: AppState, app: ApplicationService):
    while True:
        clear()
        tg = state.telegram
        panel("Telegram Admin Bot", [
            kv("Admin токен:", _ok(bool(tg.admin_token))),
            kv("Admin Chat ID:", tg.admin_chat_id or "—"),
            kv("Admin бот:", f"{_ok(tg.admin_enabled)} {'запущен' if tg.admin_enabled else 'остановлен'}"),
        ])
        choice = menu(
            [("1", "🔑 Admin-токен", "@BotFather"),
             ("2", "💬 Admin Chat ID", "@userinfobot"),
             ("3", "▶️  Запустить Admin-бота", "systemd-сервис hydra-tg-admin"),
             ("4", "⏸️  Остановить Admin-бота", ""),
             ("0", "↩ Назад", "")],
            "TELEGRAM",
        )
        if choice == "0":
            return
        elif choice == "1":
            t = prompt("Токен admin-бота")
            if t:
                state.telegram.admin_token = t.strip()
                app.admin.save_state(state)
                success("Сохранён")
            prompt("Нажмите Enter")
        elif choice == "2":
            c = prompt("Admin Chat ID")
            if c:
                state.telegram.admin_chat_id = c.strip()
                app.admin.save_state(state)
                success("Сохранён")
            prompt("Нажмите Enter")
        elif choice == "3":
            _install_admin_bot(state, app)
        elif choice == "4":
            app.admin.stop_admin_bot(state)
            success("Admin-бот остановлен")
            prompt("Нажмите Enter")


def _install_admin_bot(state: AppState, app: ApplicationService):
    if not state.telegram.admin_token:
        error("Сначала укажите admin-токен (пункт 1)")
        prompt("Нажмите Enter")
        return
    if not state.telegram.admin_chat_id:
        error("Сначала укажите Admin Chat ID (пункт 2)")
        prompt("Нажмите Enter")
        return

    info("Установка и запуск Admin-бота...")
    result = app.admin.install_admin_bot(state)
    if result.ok:
        success("Admin-бот запущен (hydra-tg-admin)")
    elif result.code == "dependency_install_failed":
        error("Не удалось установить python-telegram-bot 22.8")
    else:
        error(
            "Admin-бот не запустился. "
            "Проверьте: journalctl -u hydra-tg-admin -n 100"
        )
    prompt("Нажмите Enter")
