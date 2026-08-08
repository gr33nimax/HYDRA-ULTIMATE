"""Minimal TUI for the shared provider-neutral headless creator."""
from __future__ import annotations

from hydra.core.state_models import AppState
from hydra.services.application import ApplicationService
from hydra.services.headless_creator import QWDTT_AUTO_FLAG
from hydra.ui.tui import clear, confirm, error, menu, panel, prompt, success, warn


def _pause() -> None:
    prompt("Нажмите Enter")


def _show_result(result, success_message: str) -> None:
    if result:
        success(success_message)
    else:
        error(result.error.message if result.error else "операция не выполнена")
    _pause()


def _status(state: AppState, app: ApplicationService):
    return app.headless_creator.status(state)


def _root_status_panel(status) -> None:
    installed = "✓ Установлен" if status.installed else "❌ Не установлен"
    vk = "✓ VK" if status.cookies_ready else "❌ VK"
    panel(
        "🎬 Headless Creator",
        [
            f"Состояние: {installed}",
            f"Cookies: {vk}  ❌ WB",
            f"Путь cookies: {status.cookies_path}",
            f"qWDTT rooms: {status.vk_qwdtt_call_count}/{status.vk_qwdtt_room_count}",
        ],
    )
    if status.legacy_reinstall_required:
        warn("Команда «Создать комнаты» перенесёт старую установку qWDTT.")


def _root_options(*, installed: bool) -> list[tuple[str, str, str]]:
    options: list[tuple[str, str, str]] = []
    if not installed:
        options.append(("1", "🔧 Установить", "Установить headless-vk-creator"))
    options.append(("2", "🎥 qWDTT", "Управление пулом VK-комнат"))
    if installed:
        options.append(("9", "❌ Удалить", "Удалить creator и qWDTT runtime"))
    options.append(("0", "↩ Назад", ""))
    return options


def _set_interval(state: AppState, app: ApplicationService) -> None:
    raw = prompt("Интервал обновления, часов (1–24)").strip()
    try:
        hours = int(raw)
    except ValueError:
        error("Введите целое число от 1 до 24")
        _pause()
        return
    _show_result(
        app.headless_creator.set_qwdtt_refresh_interval(state, hours * 3600),
        "Интервал обновлён",
    )


def _toggle_auto(state: AppState, app: ApplicationService) -> None:
    enabled = bool(state.install.get(QWDTT_AUTO_FLAG, True))
    _show_result(
        app.headless_creator.set_qwdtt_auto_refresh(state, not enabled),
        f"Автообновление {'выключено' if enabled else 'включено'}",
    )


def _set_room_count(state: AppState, app: ApplicationService) -> None:
    raw = prompt("Количество qWDTT-комнат (1–16)").strip()
    try:
        count = int(raw)
    except ValueError:
        error("Введите целое число от 1 до 16")
        _pause()
        return
    _show_result(
        app.headless_creator.set_qwdtt_room_count(state, count),
        "Количество комнат обновлено; оно применится при следующем создании пула",
    )


def _create_rooms(state: AppState, app: ApplicationService, status) -> None:
    count = status.vk_qwdtt_room_count
    if not confirm(f"Создать {count} новых VK-комнат для qWDTT?"):
        return
    if status.vk_qwdtt_pool_enabled and not status.legacy_reinstall_required:
        result = app.headless_creator.refresh_qwdtt_pool(state, forced=True)
    else:
        result = app.headless_creator.setup_qwdtt_pool(state)
    _show_result(result, f"Создано qWDTT-комнат: {count}")


def _dispatch_qwdtt(
    choice: str,
    state: AppState,
    app: ApplicationService,
    status,
) -> bool:
    if choice == "0":
        return False
    if choice == "1":
        _create_rooms(state, app, status)
    elif choice == "2" and confirm("Остановить qWDTT-комнаты?"):
        _show_result(
            app.headless_creator.stop_qwdtt_pool(state),
            "qWDTT-комнаты остановлены",
        )
    elif choice == "3":
        _set_room_count(state, app)
    elif choice == "4":
        _toggle_auto(state, app)
    elif choice == "5":
        _set_interval(state, app)
    return True


def _qwdtt_options() -> list[tuple[str, str, str]]:
    return [
        ("1", "🎬 Создать комнаты", "Создать новый пул заданного размера"),
        ("2", "⏹ Остановить комнаты", "Creator и cookies сохранятся"),
        ("3", "🔢 Изменить число комнат", "От 1 до 16"),
        ("4", "🔄 Включить / выключить автообновление", ""),
        ("5", "⏱ Изменить интервал", "От 1 до 24 часов"),
        ("0", "↩ Назад", ""),
    ]


def _menu_qwdtt(state: AppState, app: ApplicationService) -> None:
    while True:
        clear()
        state = app.admin.load_state()
        status = _status(state, app)
        auto = bool(state.install.get(QWDTT_AUTO_FLAG, True))
        panel(
            "🎥 qWDTT · VK-комнаты",
            [
                f"Комнаты: {status.vk_qwdtt_call_count}/{status.vk_qwdtt_room_count}",
                f"Автообновление: {'✓ Включено' if auto else '❌ Выключено'}",
                f"Интервал: {status.vk_qwdtt_refresh_interval_seconds // 3600} ч",
            ],
        )
        choice = menu(
            _qwdtt_options(),
            "QWDTT · VK-КОМНАТЫ",
        )
        if not _dispatch_qwdtt(choice, state, app, status):
            return


def _dispatch_root(choice: str, state: AppState, app: ApplicationService) -> bool:
    if choice == "0":
        return False
    if choice == "1":
        _show_result(app.headless_creator.install(state), "Headless Creator установлен")
    elif choice == "2":
        _menu_qwdtt(state, app)
    elif choice == "9" and confirm("Удалить Headless Creator и qWDTT runtime?"):
        _show_result(app.headless_creator.uninstall(state), "Headless Creator удалён")
    return True


def menu_headless_creator(state: AppState, app: ApplicationService) -> None:
    """Manage creator installation and its qWDTT consumer."""
    while True:
        clear()
        state = app.admin.load_state()
        status = _status(state, app)
        _root_status_panel(status)
        choice = menu(
            _root_options(installed=status.installed),
            "HEADLESS CREATOR",
        )
        if not _dispatch_root(choice, state, app):
            return


__all__ = ["menu_headless_creator"]
