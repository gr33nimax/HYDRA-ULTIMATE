"""Protocol-style TUI controller for native Sing-Box Calls."""
from __future__ import annotations

from hydra.core.state_models import AppState, PluginState
from hydra.services.application import ApplicationService
from hydra.ui.protocol_ui import protocol_menu_title, protocol_status_panel
from hydra.ui.tui import clear, confirm, error, menu, prompt, success, warn


def _pause() -> None:
    prompt("Нажмите Enter")


def _show_result(result, success_message: str) -> bool:
    if result:
        success(success_message)
    else:
        message = result.error.message if result.error else "операция не выполнена"
        error(message)
    _pause()
    return bool(result)


def _desired(state: AppState) -> PluginState:
    return state.protocols.get("calls", PluginState())


def _status_panel(state: AppState, app: ApplicationService) -> None:
    desired = _desired(state)
    status = app.calls.status(state)
    protocol_status_panel(
        "calls",
        installed=desired.installed,
        enabled=desired.enabled,
        running=status.native_running,
        details=[
            ("Платформа", "VK"),
            ("Комната", "создана" if status.native_link_ready else "отсутствует"),
        ],
    )


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


def _menu_options(*, installed: bool) -> list[tuple[str, str, str]]:
    if not installed:
        return [
            ("1", "🔧 Установить", "Создать VK-комнату и запустить Calls"),
            ("0", "↩ Назад", ""),
        ]
    return [
        ("1", "🔄 Переустановить", "Пересоздать VK-комнату с rollback"),
        ("2", "📄 Показать admin-профиль", "Секретный клиентский JSON"),
        ("9", "❌ Удалить", "Удалить Calls и сохранённый join-link"),
        ("0", "↩ Назад", ""),
    ]


def _dispatch(choice: str, state: AppState, app: ApplicationService) -> bool:
    desired = _desired(state)
    if choice == "0":
        return False
    if choice == "1" and not desired.installed:
        _show_result(app.calls.enable_native_vk(state), "Calls · VK установлен")
    elif choice == "1" and confirm("Переустановить Calls и пересоздать VK-комнату?"):
        _show_result(app.calls.reinstall_native_vk(state), "Calls · VK переустановлен")
    elif choice == "2" and desired.installed:
        _show_profile(state, app)
    elif choice == "9" and desired.installed:
        if confirm("Удалить Calls и сохранённый join-link?"):
            removed = _show_result(
                app.calls.uninstall_native_vk(state),
                "Calls · VK удалён",
            )
            if removed:
                return False
    return True


def menu_calls(state: AppState, app: ApplicationService) -> None:
    while True:
        clear()
        state = app.admin.load_state()
        desired = _desired(state)
        _status_panel(state, app)
        choice = menu(
            _menu_options(installed=desired.installed),
            protocol_menu_title("calls"),
        )
        if not _dispatch(choice, state, app):
            return


__all__ = ["menu_calls"]
