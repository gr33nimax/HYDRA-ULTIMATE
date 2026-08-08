"""Compact TUI for the provider-neutral headless creator."""
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


def _root_status_panel(state: AppState, app: ApplicationService) -> None:
    status = _status(state, app)
    auto = bool(state.install.get(QWDTT_AUTO_FLAG, True))
    panel(
        "Headless Creator",
        [
            f"Creator: {'установлен' if status.installed else 'не установлен'}",
            f"VK cookies: {'готовы' if status.cookies_ready else 'не настроены'}",
            (
                f"qWDTT: {'включён' if status.vk_qwdtt_pool_enabled else 'выключен'}"
                f" · {status.vk_qwdtt_call_count}/4 · auto {'on' if auto else 'off'}"
            ),
        ],
    )
    if status.legacy_reinstall_required:
        warn("Для старого qWDTT creator требуется Fresh setup.")


def _root_options() -> list[tuple[str, str, str]]:
    return [
        ("1", "Creator", "Установка и удаление"),
        ("2", "VK cookies", "Проверка credentials"),
        ("3", "qWDTT-комнаты", "Пул из четырёх комнат"),
        ("0", "Назад", ""),
    ]


def _dispatch_core(choice: str, state: AppState, app: ApplicationService) -> bool:
    creator = app.headless_creator
    if choice == "0":
        return False
    if choice == "1":
        _show_result(creator.install(state), "Headless Creator установлен")
    elif choice == "2" and confirm("Удалить Headless Creator?"):
        _show_result(creator.uninstall(state), "Headless Creator удалён")
    return True


def _menu_core(state: AppState, app: ApplicationService) -> None:
    while True:
        clear()
        state = app.admin.load_state()
        status = _status(state, app)
        panel("Creator", [f"Состояние: {'установлен' if status.installed else 'не установлен'}"])
        choice = menu(
            [
                ("1", "Установить / проверить", ""),
                ("2", "Удалить", "Calls и qWDTT должны быть отключены"),
                ("0", "Назад", ""),
            ],
            "CREATOR",
        )
        if not _dispatch_core(choice, state, app):
            return


def _dispatch_vk(choice: str, state: AppState, app: ApplicationService) -> bool:
    creator = app.headless_creator
    if choice == "0":
        return False
    if choice == "1":
        _show_result(creator.validate_vk_credentials(state), "VK cookies корректны")
    elif choice == "2" and confirm("Удалить общие VK cookies?"):
        _show_result(creator.forget_vk_credentials(state), "VK cookies удалены")
    return True


def _menu_vk(state: AppState, app: ApplicationService) -> None:
    while True:
        clear()
        state = app.admin.load_state()
        status = _status(state, app)
        panel(
            "VK cookies",
            [
                f"Состояние: {'готовы' if status.cookies_ready else 'не настроены'}",
                status.cookies_path,
            ],
        )
        choice = menu(
            [
                ("1", "Проверить", ""),
                ("2", "Удалить", "Calls и qWDTT должны быть отключены"),
                ("0", "Назад", ""),
            ],
            "VK COOKIES",
        )
        if not _dispatch_vk(choice, state, app):
            return


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
    app.admin.set_install_flag(QWDTT_AUTO_FLAG, not enabled)
    success(f"Автообновление {'выключено' if enabled else 'включено'}")
    _pause()


def _menu_auto(state: AppState, app: ApplicationService) -> None:
    while True:
        clear()
        state = app.admin.load_state()
        status = _status(state, app)
        enabled = bool(state.install.get(QWDTT_AUTO_FLAG, True))
        panel(
            "Автообновление qWDTT",
            [
                f"Режим: {'включён' if enabled else 'выключен'}",
                f"Интервал: {status.vk_qwdtt_refresh_interval_seconds // 3600} ч",
            ],
        )
        choice = menu(
            [
                ("1", "Включить / выключить", ""),
                ("2", "Изменить интервал", ""),
                ("0", "Назад", ""),
            ],
            "АВТООБНОВЛЕНИЕ",
        )
        if choice == "0":
            return
        if choice == "1":
            _toggle_auto(state, app)
        elif choice == "2":
            _set_interval(state, app)


def _dispatch_qwdtt(choice: str, state: AppState, app: ApplicationService) -> bool:
    creator = app.headless_creator
    if choice == "0":
        return False
    if choice == "1" and confirm("Создать заново четыре VK-комнаты для qWDTT?"):
        _show_result(creator.setup_qwdtt_pool(state), "qWDTT-пул настроен")
    elif choice == "2":
        _show_result(creator.refresh_qwdtt_pool(state, forced=True), "qWDTT-пул обновлён")
    elif choice == "3":
        _menu_auto(state, app)
    elif choice == "4" and confirm("Остановить qWDTT-комнаты?"):
        _show_result(creator.stop_qwdtt_pool(state), "qWDTT-пул остановлен")
    elif choice == "5" and confirm("Удалить qWDTT units и runtime?"):
        _show_result(creator.uninstall_qwdtt_pool(state), "qWDTT-пул удалён")
    return True


def _menu_qwdtt(state: AppState, app: ApplicationService) -> None:
    while True:
        clear()
        state = app.admin.load_state()
        status = _status(state, app)
        auto = bool(state.install.get(QWDTT_AUTO_FLAG, True))
        panel(
            "qWDTT-комнаты",
            [
                f"Пул: {'включён' if status.vk_qwdtt_pool_enabled else 'выключен'}",
                f"Комнаты: {status.vk_qwdtt_call_count}/4",
                (
                    f"Автообновление: {'on' if auto else 'off'}"
                    f" · {status.vk_qwdtt_refresh_interval_seconds // 3600} ч"
                ),
            ],
        )
        if status.legacy_reinstall_required:
            warn("Старая установка будет заменена только через Fresh setup.")
        choice = menu(
            [
                ("1", "Fresh setup", "Создать четыре комнаты"),
                ("2", "Обновить комнаты", "Без потери старой ссылки при ошибке"),
                ("3", "Автообновление", "Режим и интервал"),
                ("4", "Остановить", "Сохранить creator и cookies"),
                ("5", "Удалить пул", "Удалить только qWDTT runtime"),
                ("0", "Назад", ""),
            ],
            "QWDTT-КОМНАТЫ",
        )
        if not _dispatch_qwdtt(choice, state, app):
            return


def _dispatch_root(choice: str, state: AppState, app: ApplicationService) -> bool:
    if choice == "0":
        return False
    if choice == "1":
        _menu_core(state, app)
    elif choice == "2":
        _menu_vk(state, app)
    elif choice == "3":
        _menu_qwdtt(state, app)
    return True


def menu_headless_creator(state: AppState, app: ApplicationService) -> None:
    """Manage creator core, provider credentials and consumers separately."""
    while True:
        clear()
        state = app.admin.load_state()
        _root_status_panel(state, app)
        choice = menu(_root_options(), "HEADLESS CREATOR")
        if not _dispatch_root(choice, state, app):
            return


__all__ = ["menu_headless_creator"]
