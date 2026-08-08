"""TUI controller for native VK Calls and the qWDTT call pool."""
from __future__ import annotations

from hydra.core.state_models import AppState
from hydra.services.application import ApplicationService
from hydra.services.calls import QWDTT_AUTO_FLAG
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
    panel(
        "Calls · VK (экспериментально)",
        [
            f"Sing-Box Call: {'поддерживается' if status.feature_supported else 'не поддерживается'}",
            f"VK cookies: {'готовы' if status.cookies_ready else 'не найдены'}",
            f"Native Calls: {'работает' if status.native_running else 'выключен'}",
            f"qWDTT-пул: {'включён' if status.qwdtt_pool_enabled else 'выключен'}",
            f"Комнат qWDTT: {status.qwdtt_call_count}/4",
            f"Интервал: {status.qwdtt_refresh_interval_seconds // 3600} ч",
            (
                "Миграция: требуется явная переустановка старого creator"
                if status.legacy_creator_reinstall_required
                else "Миграция: не требуется"
            ),
        ],
    )


def _show_profile(state: AppState, app: ApplicationService) -> None:
    if not confirm(
        "Показать административный профиль? Join-link является общим секретом",
    ):
        return
    try:
        profile = app.calls.native_client_profile(state)
    except Exception as exc:
        error(str(exc))
    else:
        warn("Не публикуйте этот профиль: любой владелец ссылки может войти в комнату.")
        print(f"\n{profile.config}\n")
    _pause()


def _set_interval(state: AppState, app: ApplicationService) -> None:
    raw = prompt("Интервал обновления qWDTT-пула, часов (1–24)").strip()
    try:
        hours = int(raw)
    except ValueError:
        error("Введите целое число от 1 до 24")
        _pause()
        return
    _show_result(
        app.calls.set_qwdtt_refresh_interval(state, hours * 3600),
        "Интервал обновлён",
    )


def _toggle_auto(state: AppState, app: ApplicationService) -> None:
    enabled = bool(state.install.get(QWDTT_AUTO_FLAG, True))
    app.admin.set_install_flag(QWDTT_AUTO_FLAG, not enabled)
    success(f"Автообновление {'выключено' if enabled else 'включено'}")
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
        result = app.calls.disable_native_vk(state, purge_link=purge)
        _show_result(result, "Native VK Calls отключён")
    elif choice == "5" and confirm("Создать заново четыре VK-комнаты для qWDTT?"):
        _show_result(app.calls.setup_qwdtt_pool(state), "qWDTT-пул настроен")
    elif choice == "6":
        result = app.calls.refresh_qwdtt_pool(state, forced=True)
        _show_result(result, "qWDTT-пул обновлён")
    elif choice == "7":
        _show_result(app.calls.stop_qwdtt_pool(state), "qWDTT-пул остановлен")
    elif choice == "8" and confirm("Удалить creator и qWDTT-пул?"):
        _show_result(app.calls.uninstall_qwdtt_pool(state), "qWDTT-пул удалён")
    elif choice == "9":
        _set_interval(state, app)
    elif choice.upper() == "A":
        _toggle_auto(state, app)
    elif choice.upper() == "F" and confirm("Удалить общие VK cookies?"):
        result = app.calls.forget_vk_credentials(state)
        _show_result(result, "VK cookies удалены")
    return True


def menu_calls(state: AppState, app: ApplicationService) -> None:
    while True:
        clear()
        state = app.admin.load_state()
        _status_panel(state, app)
        choice = menu(
            [
                ("-", "Native Sing-Box Calls", ""),
                ("1", "Включить", "Создать VK-комнату и применить call inbound"),
                ("2", "Ротация комнаты", "Сохранить старую ссылку до переключения"),
                ("3", "Показать клиентский профиль", "Явный запрос; содержит секрет"),
                ("4", "Отключить", "Отключить native call inbound"),
                ("-", "VK-комнаты для qWDTT", ""),
                ("5", "Fresh setup", "Создать 4 комнаты; удалить legacy creator"),
                ("6", "Обновить сейчас", "Ротировать комнаты и master-ссылку"),
                ("7", "Остановить", "Остановить creator, сохранив cookies"),
                ("8", "Удалить creator", "Удалить units, binary и qWDTT pool"),
                ("9", "Интервал обновления", "От 1 до 24 часов"),
                ("A", "Автоматический режим", "Переключить задачу Sync Agent"),
                ("F", "Забыть VK cookies", "После отключения обоих потребителей"),
                ("0", "Назад", ""),
            ],
            "CALLS · VK",
        )
        if not _dispatch(choice, state, app):
            return


__all__ = ["menu_calls"]
