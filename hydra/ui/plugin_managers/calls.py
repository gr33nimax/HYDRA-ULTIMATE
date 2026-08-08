"""Compact TUI controller for native Sing-Box Calls."""
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


def _native_enabled(state: AppState) -> bool:
    desired = state.protocols.get("calls")
    return bool(desired and desired.enabled)


def _status_panel(state: AppState, app: ApplicationService) -> None:
    status = app.calls.status(state)
    ready = status.feature_supported and status.creator_installed and status.cookies_ready
    if status.native_running:
        transport = "работает"
    elif status.native_enabled:
        transport = "не запущен"
    else:
        transport = "выключен"
    panel(
        "Calls · VK",
        [
            f"Native Calls: {transport}",
            f"Sing-Box Call: {'доступен' if status.feature_supported else 'не поддерживается'}",
            f"Creator и cookies: {'готовы' if status.creator_installed and status.cookies_ready else 'не готовы'}",
        ],
    )
    if not ready:
        warn("Подготовьте Creator и VK cookies в меню Headless Creator.")


def _show_profile(state: AppState, app: ApplicationService) -> None:
    if not confirm("Показать секретный admin-профиль?"):
        return
    try:
        profile = app.calls.native_client_profile(state)
    except Exception as exc:
        error(str(exc))
    else:
        warn("Не публикуйте профиль: join-link даёт доступ к VK-комнате.")
        print(f"\n{profile.config}\n")
    _pause()


def _menu_options(*, enabled: bool) -> list[tuple[str, str, str]]:
    if not enabled:
        return [
            ("1", "Включить", "Создать VK-комнату"),
            ("0", "Назад", ""),
        ]
    return [
        ("1", "Обновить комнату", "Переключиться без потери старой ссылки"),
        ("2", "Показать профиль", "Секретный admin JSON"),
        ("3", "Отключить", "Остановить native Calls"),
        ("0", "Назад", ""),
    ]


def _dispatch(choice: str, state: AppState, app: ApplicationService) -> bool:
    if choice == "0":
        return False
    if not _native_enabled(state):
        if choice == "1":
            _show_result(app.calls.enable_native_vk(state), "Native VK Calls включён")
        return True
    if choice == "1" and confirm("Создать новую VK-комнату?"):
        _show_result(app.calls.rotate_native_vk(state), "VK-комната обновлена")
    elif choice == "2":
        _show_profile(state, app)
    elif choice == "3" and confirm("Отключить native VK Calls?"):
        purge = confirm("Удалить сохранённый join-link?")
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
            _menu_options(enabled=_native_enabled(state)),
            "CALLS · VK",
        )
        if not _dispatch(choice, state, app):
            return


__all__ = ["menu_calls"]
