"""Top-level TUI for creator providers and their consumers."""
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


def _status_panel(state: AppState, app: ApplicationService) -> None:
    status = app.headless_creator.status(state)
    auto = bool(state.install.get(QWDTT_AUTO_FLAG, True))
    panel(
        "Headless Creator",
        [
            f"Core: {'установлен' if status.installed else 'не установлен'}",
            f"Провайдеры: {', '.join(name.upper() for name in status.providers)}",
            f"VK cookies: {'готовы' if status.cookies_ready else 'не настроены'}",
            f"Каталог cookies: {status.cookies_path}",
            f"qWDTT-комнаты: {status.vk_qwdtt_call_count}/4",
            f"qWDTT-пул: {'включён' if status.vk_qwdtt_pool_enabled else 'выключен'}",
            f"Обновление: каждые {status.vk_qwdtt_refresh_interval_seconds // 3600} ч; auto {'on' if auto else 'off'}",
            (
                "Миграция: требуется Fresh setup старого creator"
                if status.legacy_reinstall_required
                else "Миграция: не требуется"
            ),
        ],
    )


def _set_interval(state: AppState, app: ApplicationService) -> None:
    raw = prompt("Интервал обновления qWDTT-пула, часов (1–24)").strip()
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


def _dispatch(choice: str, state: AppState, app: ApplicationService) -> bool:
    creator = app.headless_creator
    if choice == "0":
        return False
    if choice == "1":
        _show_result(creator.install(state), "Headless Creator установлен")
    elif choice == "2" and confirm("Удалить общий Headless Creator?"):
        _show_result(creator.uninstall(state), "Headless Creator удалён")
    elif choice == "3":
        _show_result(creator.validate_vk_credentials(state), "VK cookies корректны")
    elif choice == "4" and confirm("Удалить общие VK cookies?"):
        _show_result(creator.forget_vk_credentials(state), "VK cookies удалены")
    elif choice == "5" and confirm("Создать заново четыре VK-комнаты для qWDTT?"):
        _show_result(creator.setup_qwdtt_pool(state), "qWDTT-пул настроен")
    elif choice == "6":
        _show_result(creator.refresh_qwdtt_pool(state, forced=True), "qWDTT-пул обновлён")
    elif choice == "7":
        _show_result(creator.stop_qwdtt_pool(state), "qWDTT-пул остановлен")
    elif choice == "8" and confirm("Удалить units и файлы qWDTT-пула?"):
        _show_result(creator.uninstall_qwdtt_pool(state), "qWDTT-пул удалён")
    elif choice == "9":
        _set_interval(state, app)
    elif choice.upper() == "A":
        _toggle_auto(state, app)
    return True


def menu_headless_creator(state: AppState, app: ApplicationService) -> None:
    """Manage creator core separately from all protocol menus."""
    while True:
        clear()
        state = app.admin.load_state()
        _status_panel(state, app)
        warn("Новые провайдеры (например WB Stream) будут добавляться в этот раздел.")
        choice = menu(
            [
                ("-", "Creator core", ""),
                ("1", "Установить / проверить", "Один creator для всех потребителей"),
                ("2", "Удалить", "После отключения Calls и qWDTT-пула"),
                ("-", "Провайдер VK", ""),
                ("3", "Проверить cookies", "Не выводит содержимое cookies"),
                ("4", "Забыть cookies", "После отключения обоих потребителей"),
                ("-", "VK-комнаты для qWDTT", ""),
                ("5", "Fresh setup", "Создать 4 комнаты и удалить legacy runtime"),
                ("6", "Обновить сейчас", "Blue/green ротация комнат и master-ссылки"),
                ("7", "Остановить", "Сохранить общий creator и cookies"),
                ("8", "Удалить пул", "Удалить только qWDTT units и runtime"),
                ("9", "Интервал", "От 1 до 24 часов"),
                ("A", "Автоматический режим", "Задача owner-neutral Sync Agent"),
                ("0", "Назад", ""),
            ],
            "HEADLESS CREATOR",
        )
        if not _dispatch(choice, state, app):
            return


__all__ = ["menu_headless_creator"]
