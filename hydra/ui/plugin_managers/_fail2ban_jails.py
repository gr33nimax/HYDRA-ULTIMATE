"""Jail configuration interactions for the Fail2ban TUI controller."""
from __future__ import annotations

from hydra.core.state_models import AppState
from hydra.services.application import ApplicationService
from hydra.ui.plugin_managers._facade_bridge import facade
from hydra.ui.tui import (
    CYAN,
    DIM,
    GREEN,
    NC,
    YELLOW,
    clear,
    confirm,
    error,
    info,
    menu,
    panel,
    prompt,
    success,
    warn,
)


def _configuration(
    state: AppState,
    app: ApplicationService,
) -> dict[str, dict[str, object]]:
    return app.plugin_query(
        "fail2ban",
        "jail_options",
        state=state,
    )


def _options(
    configuration: dict[str, dict[str, object]],
    *,
    show_state: bool,
) -> tuple[list[tuple[str, str, str]], list[str]]:
    all_jails = facade._PROTOCOL_JAILS + facade._SYSTEM_JAILS
    options: list[tuple[str, str, str]] = []
    index = 1
    groups = (
        (facade._PROTOCOL_JAILS, CYAN, "Протокол"),
        (facade._SYSTEM_JAILS, YELLOW, "Система"),
    )
    for group_index, (group, color, label) in enumerate(groups):
        for jail in group:
            suffix = ""
            if show_state:
                enabled = (
                    str(
                        configuration.get(jail, {}).get(
                            "enabled",
                            "false",
                        ),
                    ).lower()
                    == "true"
                )
                state_text = f"{GREEN}вкл{NC}" if enabled else f"{DIM}выкл{NC}"
                suffix = f" [{state_text}]"
            options.append(
                (
                    str(index),
                    f"{color}[{label}]{NC} {jail}{suffix}",
                    "",
                ),
            )
            index += 1
        if group_index == 0:
            options.append(("-", "", ""))
    options.append(("0", "Отмена", ""))
    return options, all_jails


def _select(
    state: AppState,
    app: ApplicationService,
    *,
    show_state: bool,
    title_text: str,
) -> tuple[str | None, dict[str, dict[str, object]]]:
    configuration = _configuration(state, app)
    options, all_jails = _options(
        configuration,
        show_state=show_state,
    )
    choice = menu(options, title_text)
    if not choice.isdigit():
        return None, configuration
    index = int(choice) - 1
    if not 0 <= index < len(all_jails):
        return None, configuration
    return all_jails[index], configuration


def configure(
    state: AppState,
    app: ApplicationService,
) -> None:
    clear()
    jail, configuration = _select(
        state,
        app,
        show_state=False,
        title_text="ВЫБЕРИТЕ ДЖЕЙЛ ДЛЯ НАСТРОЙКИ",
    )
    if jail is None:
        return
    current = configuration.get(jail, {})
    current_bantime = str(current.get("bantime", "3600"))
    current_findtime = str(current.get("findtime", "600"))
    current_maxretry = str(current.get("maxretry", "5"))

    clear()
    panel(f"⚙️ НАСТРОЙКА ДЖЕЙЛА {jail}", [
        "  Текущие параметры:",
        f"    bantime (время бана):     {current_bantime} сек",
        f"    findtime (окно поиска):   {current_findtime} сек",
        f"    maxretry (кол-во попыток): {current_maxretry}",
    ])
    bantime = prompt("bantime, сек", default=current_bantime).strip()
    findtime = prompt("findtime, сек", default=current_findtime).strip()
    maxretry = prompt("maxretry", default=current_maxretry).strip()
    values = (bantime, findtime, maxretry)
    if not all(value.isdigit() for value in values) or min(
        map(int, values),
    ) < 1:
        error("Параметры должны быть положительными целыми числами!")
        prompt("Нажмите Enter...")
        return

    changed = app.plugin_command(
        state,
        "fail2ban",
        "set_jail_options",
        jail=jail,
        bantime=bantime,
        findtime=findtime,
        maxretry=maxretry,
    )
    info("Сохраняю настройки...")
    if changed:
        success(
            f"Настройки применены: bantime={bantime}, "
            f"findtime={findtime}, maxretry={maxretry}",
        )
    else:
        error(
            "Настройки не применены: "
            "конфигурация Fail2ban не прошла проверку",
        )
    prompt("Нажмите Enter для продолжения")


def toggle(
    state: AppState,
    app: ApplicationService,
) -> None:
    clear()
    jail, configuration = _select(
        state,
        app,
        show_state=True,
        title_text="ВКЛЮЧИТЬ / ВЫКЛЮЧИТЬ ДЖЕЙЛ",
    )
    if jail is None:
        return
    enabled = (
        str(configuration.get(jail, {}).get("enabled", "false")).lower()
        == "true"
    )
    changed = app.plugin_command(
        state,
        "fail2ban",
        "set_jail_enabled",
        jail=jail,
        enabled=not enabled,
    )
    info(f"Переключаю статус {jail}...")
    if changed:
        success(
            f"Джейл {jail} успешно "
            f"{'выключен' if enabled else 'включен'}!",
        )
    else:
        error(
            "Статус не изменён: "
            "конфигурация Fail2ban не прошла проверку",
        )
    prompt("Нажмите Enter для продолжения")


def reset(
    state: AppState,
    app: ApplicationService,
) -> None:
    warn("СБРОС КОНФИГУРАЦИИ ДЖЕЙЛОВ!")
    warn(
        "Локальные изменения лимитов и параметров джейлов будут удалены.",
    )
    if not confirm("Продолжить?", default=False):
        info("Отменено.")
        prompt("Нажмите Enter для продолжения")
        return
    info("Восстанавливаю конфигурации...")
    was_active = facade._f2b_active(app)
    if app.plugin_command(state, "fail2ban", "reset_jails"):
        if was_active:
            success("Базовая конфигурация восстановлена и применена!")
        else:
            success(
                "Базовая конфигурация восстановлена. "
                "Служба оставлена остановленной.",
            )
    else:
        detail = app.apply_error()
        error(
            "Не удалось восстановить конфигурацию; "
            "предыдущие настройки сохранены.",
        )
        if detail:
            error(f"Причина: {detail}")
    prompt("Нажмите Enter для продолжения")


__all__ = ["configure", "reset", "toggle"]
