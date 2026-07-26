"""Small controller loop and views for the Fail2ban manager facade."""
from __future__ import annotations

from hydra.core.state_models import AppState, get_protocol
from hydra.services.application import ApplicationService
from hydra.ui.plugin_managers._facade_bridge import facade
from hydra.ui.plugin_managers._fail2ban_bans import (
    manage_banned_ips,
    manual_ban,
    show_history,
)
from hydra.ui.plugin_managers._fail2ban_jails import (
    configure as configure_jail,
)
from hydra.ui.plugin_managers._fail2ban_jails import (
    reset as reset_jails,
)
from hydra.ui.plugin_managers._fail2ban_jails import toggle as toggle_jail
from hydra.ui.plugin_managers._fail2ban_whitelist import (
    manage as manage_whitelist,
)
from hydra.ui.tui import (
    BOLD,
    CYAN,
    DIM,
    GREEN,
    NC,
    RED,
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


def _runtime(
    app: ApplicationService,
) -> tuple[bool, bool, list[str], int]:
    status = app.protocols.status("fail2ban")
    live_jails = facade._f2b_list_jails(app) if status.running else []
    configured = facade._PROTOCOL_JAILS + facade._SYSTEM_JAILS
    jail_names = live_jails if live_jails else configured
    total_banned = sum(
        facade._f2b_jail_info(app, jail)["currently_banned"]
        for jail in live_jails
    )
    return status.installed, status.running, jail_names, total_banned


def _status_lines(
    installed: bool,
    active: bool,
    jail_names: list[str],
    total_banned: int,
) -> list[str]:
    if not installed:
        return [f"  Статус:      {RED}не установлен{NC}"]
    lines = [
        f"  Статус:      "
        f"{(GREEN + '● активен') if active else (DIM + '○ остановлен')}{NC}",
    ]
    protocols = [
        jail.replace("hydra-", "")
        for jail in jail_names
        if jail in facade._PROTOCOL_JAILS
    ]
    systems = [
        jail.replace("hydra-", "")
        for jail in jail_names
        if jail not in facade._PROTOCOL_JAILS
    ]
    if protocols:
        lines.append(
            f"  Протоколы:   {CYAN}{len(protocols)}{NC} "
            f"({', '.join(protocols)})",
        )
    if systems:
        lines.append(
            f"  Система:     {YELLOW}{len(systems)}{NC} "
            f"({', '.join(systems)})",
        )
    lines.append(
        f"  Забанено:    {(RED if total_banned else DIM)}"
        f"{total_banned}{NC} IP (сейчас)",
    )
    return lines


def _options(
    state: AppState,
    installed: bool,
    active: bool,
    total_banned: int,
) -> list[tuple[str, str, str]]:
    if not installed:
        options = [
            (
                "1",
                "📥 Установить и настроить Fail2ban",
                "Установить пакет и создать базовые джейлы",
            ),
        ]
    else:
        whitelist = get_protocol(
            state,
            "fail2ban",
        ).config.get("whitelist", [])
        options = [
            (
                "1",
                f"{'⏸️  Остановить' if active else '▶️  Запустить'} Fail2ban",
                "Переключить статус службы",
            ),
            (
                "2",
                "🔁 Перезапустить / применить конфигурацию",
                "Выполнить reload / restart",
            ),
            (
                "3",
                f"🚫 Забаненные IP ({total_banned} шт.)",
                "Просмотр заблокированных IP по джейлам и разбан",
            ),
            (
                "4",
                "➕ Забанить вручную (IP/диапазон/ASN)",
                "Добавить адреса в черный список",
            ),
            (
                "5",
                "⚙️  Настройка джейла (bantime/findtime/maxretry)",
                "Изменить тайминги и попытки",
            ),
            (
                "6",
                "🔌 Включить/выключить джейл",
                "Активация отдельных джейлов",
            ),
            (
                "7",
                "📋 Лог Fail2ban (последние 30 строк)",
                "Просмотр лог-файла в реальном времени",
            ),
            (
                "8",
                "🛠️  Восстановить базовую конфигурацию",
                "Сбросить локальные изменения джейлов",
            ),
            (
                "9",
                "📊 История банов за сутки",
                "Просмотр накопленной статистики",
            ),
            (
                "W",
                f"⚪ Управление whitelist {DIM}({len(whitelist)} IP){NC}",
                "Список IP-адресов/подсетей-исключений",
            ),
            ("-", "", ""),
            ("X", "🧹 Очистить лог Fail2ban", ""),
        ]
    options.append(("0", "↩ Назад", ""))
    return options


def _install(state: AppState, app: ApplicationService) -> None:
    info("Устанавливаю и настраиваю Fail2ban...")
    if (
        app.protocols.install(state, "fail2ban")
        and app.protocols.enable(state, "fail2ban")
    ):
        success("Fail2ban успешно установлен и запущен!")
    else:
        error("Не удалось выполнить установку Fail2ban.")
    prompt("Нажмите Enter для продолжения")


def _toggle(
    state: AppState,
    app: ApplicationService,
    active: bool,
) -> None:
    info("Останавливаю Fail2ban..." if active else "Запускаю Fail2ban...")
    try:
        if active:
            app.protocols.disable(state, "fail2ban")
        else:
            app.protocols.enable(state, "fail2ban")
    except RuntimeError:
        pass
    app.monitoring.sleep(1 if active else 2)
    running = facade._f2b_active(app)
    if active and not running:
        success("Служба остановлена.")
    elif not active and running:
        success("Служба запущена.")
    else:
        error(
            "Не удалось остановить службу."
            if active
            else "Служба не запустилась.",
        )
    prompt("Нажмите Enter для продолжения")


def _apply(state: AppState, app: ApplicationService) -> None:
    info("Пересобираю и применяю конфигурацию...")
    if app.protocols.apply_runtime(state, "fail2ban"):
        success("Конфигурация успешно применена!")
    else:
        error(
            "Не удалось применить конфигурацию Fail2ban. "
            "Проверьте: journalctl -u fail2ban",
        )
    prompt("Нажмите Enter для продолжения")


def _show_log(app: ApplicationService) -> None:
    clear()
    lines = facade._f2b_log_lines(app)[-30:]
    print()
    print(f"  {BOLD}{CYAN}📋 ЛОГ FAIL2BAN (последние 30 строк){NC}")
    print(f"  {CYAN}" + "═" * 70 + f"{NC}")
    if not lines:
        print(f"  {DIM}Лог пуст{NC}")
    else:
        for line in lines:
            color = (
                RED
                if " Ban " in line
                else YELLOW if " Unban " in line else DIM
            )
            print(f"  {color}{line}{NC}")
    print(f"  {CYAN}" + "═" * 70 + f"{NC}")
    print()
    prompt("Нажмите Enter для продолжения")


def _clear_log(app: ApplicationService) -> None:
    warn("ОЧИСТКА ЛОГА FAIL2BAN")
    warn(f"Будут очищены файлы {facade._F2B_LOG} и .1.")
    warn("Текущие баны и работа Fail2ban не пострадают.")
    if confirm("Продолжить?", default=False):
        ok, message = facade._f2b_clear_log(app)
        if ok:
            success(message)
        else:
            error(f"Не удалось очистить: {message}")
    else:
        info("Отменено.")
    prompt("Нажмите Enter для продолжения")


def _dispatch(
    choice: str,
    state: AppState,
    app: ApplicationService,
    active: bool,
    jail_names: list[str],
) -> None:
    actions = {
        "1": lambda: _toggle(state, app, active),
        "2": lambda: _apply(state, app),
        "3": lambda: manage_banned_ips(jail_names, app),
        "4": lambda: manual_ban(jail_names, app),
        "5": lambda: configure_jail(state, app),
        "6": lambda: toggle_jail(state, app),
        "7": lambda: _show_log(app),
        "8": lambda: reset_jails(state, app),
        "9": lambda: show_history(app),
        "W": lambda: manage_whitelist(state, app),
        "X": lambda: _clear_log(app),
    }
    action = actions.get(choice.upper())
    if action is not None:
        action()


def run(state: AppState, app: ApplicationService) -> None:
    while True:
        clear()
        installed, active, jail_names, total_banned = _runtime(app)
        panel(
            "🛡️ FAIL2BAN — ЗАЩИТА ОТ ПЕРЕБОРА",
            _status_lines(installed, active, jail_names, total_banned),
        )
        choice = menu(
            _options(state, installed, active, total_banned),
            "УПРАВЛЕНИЕ FAIL2BAN",
        )
        if choice == "0":
            return
        if not installed:
            if choice == "1":
                _install(state, app)
            continue
        _dispatch(choice, state, app, active, jail_names)


__all__ = ["run"]
