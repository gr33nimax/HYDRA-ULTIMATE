"""Interactive setup for the four-call VK headless creator."""
from __future__ import annotations

from hydra.ui.plugin_managers._facade_bridge import facade


def _result(value: object) -> tuple[bool, str]:
    if isinstance(value, tuple) and len(value) == 2:
        return bool(value[0]), str(value[1] or "")
    return bool(value), ""


def _master_link(app: facade.ApplicationService) -> str:
    try:
        return str(app.plugin_query("wdtt", "headless_creator_link") or "")
    except Exception:
        return ""


def _show_master_link(
    link: str,
    app: facade.ApplicationService,
    *,
    save: bool,
) -> None:
    if not link:
        return
    facade.panel(
        "ЕДИНАЯ МАСТЕР-ССЫЛКА",
        ["Используйте эту ссылку для qWDTT-конфигурации:", link],
        wrap=True,
    )
    if save:
        facade._save_link_to_file(link, "qwdtt_link.txt", app)


def _run_setup(
    state: facade.AppState,
    app: facade.ApplicationService,
) -> None:
    facade.clear()
    facade.title("Настройка VK headless creator")
    facade.panel(
        "HEADLESS CREATOR",
        [
            "HYDRA скачает подходящий verified release и установит headless-vk-creator.",
            "Будут запущены четыре независимых VK-звонка.",
            "Файл VK cookies: /etc/hydra/cookiesvk/cookies-vk.json",
            "Поддерживается экспортированный Creator JSON, в том числе многострочный.",
            "Файл защищается правами 0600 и не попадает в state.",
        ],
    )
    protocol = facade.get_protocol(state, "wdtt")
    was_enabled = bool(protocol.config.get("headless_enabled", False))
    if not was_enabled:
        protocol.config["headless_enabled"] = True
        app.admin.save_state(state)
    facade.info(
        "Устанавливаю headless creator и запускаю четыре инстанса; "
        "ожидание ссылок может занять до минуты...",
    )
    try:
        result = app.plugin_action(
            "wdtt",
            "setup_headless_creator",
            state=state,
        )
        ok, message = _result(result)
    except Exception as exc:
        ok, message = False, str(exc)
    if not ok:
        if not was_enabled:
            protocol.config["headless_enabled"] = False
            app.admin.save_state(state)
        facade.error(message or "Не удалось запустить headless creator")
        facade.prompt("Нажмите Enter...")
        return
    link = _master_link(app)
    facade.success("Четыре звонка созданы, мастер-ссылка qWDTT обновлена.")
    _show_master_link(link, app, save=True)
    facade.prompt("Нажмите Enter...")


def _refresh_calls(
    state: facade.AppState,
    app: facade.ApplicationService,
) -> None:
    facade.clear()
    facade.title("Обновление VK-звонков qWDTT")
    facade.info("Пересоздаю четыре звонка без переустановки creator...")
    try:
        ok, message = _result(
            app.plugin_action(
                "wdtt",
                "refresh_headless_creator",
                state=state,
            ),
        )
    except Exception as exc:
        ok, message = False, str(exc)
    if not ok:
        facade.error(message or "Не удалось обновить VK-звонки")
        facade.prompt("Нажмите Enter...")
        return
    facade.success("Четыре звонка пересозданы, master-ссылка обновлена.")
    _show_master_link(_master_link(app), app, save=True)
    facade.prompt("Нажмите Enter...")


def _stop_calls(
    state: facade.AppState,
    app: facade.ApplicationService,
) -> None:
    if not facade.confirm(
        "Завершить все четыре звонка и удалить текущую master-ссылку?",
    ):
        return
    facade.clear()
    facade.title("Завершение VK-звонков qWDTT")
    facade.info("Останавливаю четыре creator-инстанса...")
    try:
        ok, message = _result(
            app.plugin_action("wdtt", "stop_headless_creator"),
        )
    except Exception as exc:
        ok, message = False, str(exc)
    if ok:
        if _automatic_management_enabled(state):
            facade.success(
                "Все звонки завершены. Режим АВТО включён: "
                "Sync Agent пересоздаст их по таймеру.",
            )
        else:
            facade.success(
                "Все звонки завершены. Режим РУЧНОЙ: "
                "Sync Agent не будет создавать новые.",
            )
    else:
        facade.error(message or "Не удалось завершить все VK-звонки")
    facade.prompt("Нажмите Enter...")


def _automatic_management_enabled(state: facade.AppState) -> bool:
    return bool(
        state.install.get(facade.HEADLESS_AUTO_MANAGEMENT_FLAG, True),
    )


def _toggle_management_mode(
    state: facade.AppState,
    app: facade.ApplicationService,
    enabled: bool,
) -> None:
    target = not enabled
    flag = facade.HEADLESS_AUTO_MANAGEMENT_FLAG
    had_value = flag in state.install
    previous = state.install.get(flag)
    state.install[flag] = target
    try:
        app.admin.save_state(state)
    except Exception as exc:
        if had_value:
            state.install[flag] = previous
        else:
            state.install.pop(flag, None)
        facade.error(str(exc) or "Не удалось сохранить режим управления звонками")
        facade.prompt("Нажмите Enter...")
        return
    if target:
        facade.success(
            "Включён режим АВТО: Sync Agent будет проверять таймер "
            "и при необходимости пересоздавать VK-звонки.",
        )
    else:
        facade.success(
            "Включён режим РУЧНОЙ: Sync Agent больше не управляет VK-звонками; "
            "текущие звонки продолжат работать.",
        )
    facade.prompt("Нажмите Enter...")


def _configure_refresh_timer(
    state: facade.AppState,
    app: facade.ApplicationService,
    current_seconds: int,
) -> None:
    facade.clear()
    facade.title("Интервал пересоздания VK-звонков")
    current_hours = max(1, current_seconds // 3600)
    choice = facade.menu(
        [
            ("1", "Каждые 6 часов", "Частое обновление всех четырёх звонков"),
            ("2", "Каждые 12 часов", "Дважды в сутки"),
            ("3", "Каждые 24 часа", "Стандартный интервал"),
            ("4", "Свой интервал", "От 1 до 24 часов"),
            ("0", "↩ Назад", ""),
        ],
        f"ТЕКУЩИЙ ИНТЕРВАЛ · {current_hours} Ч.",
    )
    if choice == "0":
        return
    presets = {"1": 6, "2": 12, "3": 24}
    if choice in presets:
        hours = presets[choice]
    elif choice == "4":
        raw = facade.prompt("Интервал в часах (1–24)")
        try:
            hours = int(raw)
        except ValueError:
            hours = 0
    else:
        return
    if not 1 <= hours <= 24:
        facade.error("Интервал должен быть целым числом от 1 до 24 часов")
        facade.prompt("Нажмите Enter...")
        return
    try:
        changed = app.plugin_command(
            state,
            "wdtt",
            "set_headless_refresh_interval",
            seconds=hours * 3600,
        )
    except Exception as exc:
        facade.error(str(exc) or "Не удалось сохранить интервал")
        facade.prompt("Нажмите Enter...")
        return
    if changed:
        facade.success(f"Звонки будут пересоздаваться каждые {hours} ч.")
    else:
        facade.info("Этот интервал уже установлен.")
    facade.prompt("Нажмите Enter...")


def _configured_menu(
    state: facade.AppState,
    app: facade.ApplicationService,
) -> None:
    facade.clear()
    facade.title("VK headless creator")
    try:
        value = app.plugin_query(
            "wdtt",
            "headless_creator_status",
            state=state,
        )
        status = value if isinstance(value, dict) else {}
    except Exception:
        status = {}
    call_count = int(status.get("call_count", 0) or 0)
    refreshed_at = str(status.get("refreshed_at", "") or "неизвестно")
    interval_seconds = int(
        status.get("refresh_interval_seconds", 86_400) or 86_400,
    )
    interval_hours = max(1, interval_seconds // 3600)
    automatic_management = _automatic_management_enabled(state)
    if automatic_management:
        mode_line = "Режим: АВТОМАТИЧЕСКИЙ — Sync Agent управляет звонками"
        ownership_line = (
            f"Каждые {interval_hours} ч. Sync Agent проверяет таймер и при "
            "необходимости пересоздаёт 4 звонка."
        )
    else:
        mode_line = "Режим: РУЧНОЙ — Sync Agent не управляет звонками"
        ownership_line = (
            "Звонки меняются только командами этого меню; "
            "текущие продолжают работать."
        )
    link = _master_link(app)
    facade.panel(
        "HEADLESS CREATOR · НАСТРОЕН",
        [
            f"Активные звонки: {call_count}/4",
            f"Последнее обновление: {refreshed_at}",
            mode_line,
            ownership_line,
            "Открытие этого экрана не перезапускает creator.",
        ],
    )
    _show_master_link(link, app, save=False)
    choice = facade.menu(
        [
            (
                "1",
                "🔄 Пересоздать звонки сейчас",
                "Обновить четыре хеша без переустановки creator",
            ),
            (
                "2",
                "⏹ Завершить все звонки",
                "Остановить четыре звонка и удалить текущую master-ссылку",
            ),
            (
                "3",
                "⏱ Интервал пересоздания",
                "Настроить общий таймер для четырёх звонков",
            ),
            (
                "4",
                (
                    "⏸ Перейти в ручной режим"
                    if automatic_management
                    else "▶ Включить автоматический режим"
                ),
                (
                    "Sync Agent перестанет управлять qWDTT; текущие звонки останутся активны"
                    if automatic_management
                    else "Передать Sync Agent управление созданием и обновлением звонков"
                ),
            ),
            (
                "5",
                "🛠 Проверить / восстановить установку",
                "Проверить cookies и binary, затем пересоздать звонки",
            ),
            ("0", "↩ Назад", ""),
        ],
        "УПРАВЛЕНИЕ HEADLESS CREATOR",
    )
    if choice == "1":
        _refresh_calls(state, app)
    elif choice == "2":
        _stop_calls(state, app)
    elif choice == "3":
        _configure_refresh_timer(state, app, interval_seconds)
    elif choice == "4":
        _toggle_management_mode(state, app, automatic_management)
    elif choice == "5" and facade.confirm(
        "Проверить установку и пересоздать четыре звонка?",
    ):
        _run_setup(state, app)


def setup_headless_creator(
    state: facade.AppState,
    app: facade.ApplicationService,
) -> None:
    protocol = facade.get_protocol(state, "wdtt")
    if bool(protocol.config.get("headless_enabled", False)):
        _configured_menu(state, app)
        return
    _run_setup(state, app)


__all__ = ["setup_headless_creator"]
