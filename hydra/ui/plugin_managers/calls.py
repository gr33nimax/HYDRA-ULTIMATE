"""TUI controller for the native Sing-Box Calls transport."""
from __future__ import annotations

from hydra.core.state_models import AppState
from hydra.services.application import ApplicationService
from hydra.ui.tui import clear, confirm, error, menu, panel, prompt, success, warn


def _pause() -> None:
    prompt("Нажмите Enter")


def _show_result(result, success_message: str) -> None:
    if result:
        success(success_message)
    else:
        message = result.error.message if result.error else "операция не выполнена"
        error(message)
    _pause()


def _status_panel(state: AppState, app: ApplicationService) -> None:
    status = app.calls.status(state)
    ready = status.feature_supported and status.creator_installed and status.cookies_ready
    panel(
        "Calls · VK (экспериментально)",
        [
            f"Транспорт: {'работает' if status.native_running else 'выключен'}",
            f"Sing-Box Call: {'поддерживается' if status.feature_supported else 'не поддерживается'}",
            f"Headless Creator: {'установлен' if status.creator_installed else 'не установлен'}",
            f"VK cookies: {'готовы' if status.cookies_ready else 'не настроены'}",
            f"Join-link: {'сохранён' if status.native_link_ready else 'отсутствует'}",
            (
                "Готовность: можно включать Calls"
                if ready
                else "Готовность: сначала откройте главное меню → Headless Creator"
            ),
        ],
    )


def _show_profile(state: AppState, app: ApplicationService) -> None:
    if not confirm("Показать admin-профиль? Join-link является общим секретом"):
        return
    try:
        profile = app.calls.native_client_profile(state)
    except Exception as exc:
        error(str(exc))
    else:
        warn("Не публикуйте профиль: владелец ссылки может войти в VK-комнату.")
        print(f"\n{profile.config}\n")
    _pause()


def _dispatch(choice: str, state: AppState, app: ApplicationService) -> bool:
    if choice == "0":
        return False
    if choice == "1":
        _show_result(app.calls.enable_native_vk(state), "Native VK Calls включён")
    elif choice == "2" and confirm("Создать новую VK-комнату и переключить сервер?"):
        _show_result(app.calls.rotate_native_vk(state), "VK-комната успешно заменена")
    elif choice == "3":
        _show_profile(state, app)
    elif choice == "4" and confirm("Отключить native VK Calls?"):
        purge = confirm("Удалить сохранённый join-link после отключения?")
        _show_result(
            app.calls.disable_native_vk(state, purge_link=purge),
            "Native VK Calls отключён",
        )
    return True


def menu_calls(state: AppState, app: ApplicationService) -> None:
    while True:
        clear()
        state = app.admin.load_state()
        _status_panel(state, app)
        choice = menu(
            [
                ("1", "Включить", "Создать комнату через общий Headless Creator"),
                ("2", "Ротация комнаты", "Сохранить старую ссылку до успешного handoff"),
                ("3", "Клиентский профиль", "Явно показать секретный admin JSON"),
                ("4", "Отключить", "Отключить native call inbound"),
                ("0", "Назад", ""),
            ],
            "CALLS · VK",
        )
        if not _dispatch(choice, state, app):
            return


__all__ = ["menu_calls"]
