"""
Application UI for managing Honeypot.
"""
from __future__ import annotations

import ipaddress

from hydra.core.state_models import AppState
from hydra.services.application import ApplicationService
from hydra.ui.tui import (
    clear, menu, prompt, panel, info, success, warn, error,
    RED, GREEN, YELLOW, CYAN, BOLD, DIM, NC
)

def _honeypot_status_lines(
    active: bool,
    port: int,
    banned: dict,
) -> list[str]:
    return [
        f"  Сервис:      "
        f"{(GREEN + '● активен') if active else (DIM + '○ остановлен')}{NC}",
        f"  Порт:        {CYAN}{port}{NC}",
        f"  Забанено:    {(RED if banned else DIM)}"
        f"{len(banned)}{NC} IP (всего)",
    ]


def _honeypot_options(
    active: bool,
    port: int,
    whitelist: list[str],
    banned: dict,
) -> list[tuple[str, str, str]]:
    return [
        (
            "1",
            f"{'⏸️  Остановить' if active else '▶️  Запустить'} Honeypot",
            "Переключить статус сервиса",
        ),
        (
            "2",
            f"Изменить порт {DIM}(текущий: {port}){NC}",
            "Сменить прослушиваемый TCP-порт",
        ),
        (
            "3",
            f"Управление whitelist {DIM}({len(whitelist)} IP){NC}",
            "Список доверенных IP",
        ),
        (
            "4",
            f"Список пойманных IP {DIM}({len(banned)} шт.){NC}",
            "Просмотр всех забаненных адресов",
        ),
        ("5", "🔓 Разбанить IP", "Удалить адрес из UFW и базы"),
        (
            "6",
            "📋 Последние 30 строк лога",
            "Просмотреть лог-файл ловушки",
        ),
        ("0", "↩ Назад", ""),
    ]


def _toggle_honeypot(
    state: AppState,
    app: ApplicationService,
    *,
    installed: bool,
    active: bool,
    port: int,
) -> None:
    if active:
        info("Останавливаю Honeypot...")
        try:
            app.protocols.disable(state, "honeypot")
        except RuntimeError as exc:
            error(str(exc))
        else:
            if app.protocols.status("honeypot").running:
                error("Honeypot всё ещё активен после команды остановки.")
            else:
                success("Honeypot остановлен.")
    else:
        info("Запускаю Honeypot...")
        if (
            not installed
            and not app.protocols.install(state, "honeypot")
        ):
            error("Не найдены обязательные зависимости: python3/systemd")
            prompt("Нажмите Enter для продолжения")
            return
        try:
            app.protocols.enable(state, "honeypot")
        except RuntimeError as exc:
            error(str(exc))
        else:
            if not app.protocols.status("honeypot").running:
                error(
                    "Honeypot завершился сразу после запуска. "
                    "Проверьте journalctl -u hydra-honeypot.",
                )
            else:
                success(f"Honeypot запущен на порту {port}.")
    prompt("Нажмите Enter для продолжения")


def _change_honeypot_port(
    state: AppState,
    app: ApplicationService,
    *,
    port: int,
    active: bool,
) -> None:
    clear()
    raw = prompt("Новый порт", default=str(port)).strip()
    if not raw.isdigit() or not 1 <= int(raw) <= 65535:
        error("Некорректный номер порта!")
        prompt("Нажмите Enter для продолжения")
        return
    new_port = int(raw)
    conflicting = [
        name
        for name, protocol in state.protocols.items()
        if protocol and protocol.enabled and protocol.port == new_port
    ]
    if conflicting:
        error(
            f"Порт {new_port} уже занят протоколом: "
            f"{', '.join(conflicting)}!",
        )
        prompt("Нажмите Enter для продолжения")
        return

    changed = app.plugin_command(
        state,
        "honeypot",
        "set_port",
        port=new_port,
    )
    if active:
        info("Перезапускаю Honeypot с новым портом...")
        if not changed:
            error("Новый порт не удалось активировать; восстановлен прежний")
            prompt("Нажмите Enter для продолжения")
            return
    success(f"Порт изменен на {new_port}")
    prompt("Нажмите Enter для продолжения")


def _add_honeypot_whitelist(
    state: AppState,
    app: ApplicationService,
) -> None:
    raw = prompt("Введите IP или подсеть CIDR").strip()
    try:
        network = str(ipaddress.ip_network(raw, strict=False))
    except ValueError:
        error("Некорректный IP или CIDR.")
        prompt("Нажмите Enter для продолжения")
        return
    if app.plugin_command(
        state,
        "honeypot",
        "add_whitelist",
        network=network,
    ):
        success(f"Добавлен в whitelist: {network}")
    else:
        warn("IP пуст или уже в списке.")
    prompt("Нажмите Enter для продолжения")


def _remove_honeypot_whitelist(
    state: AppState,
    app: ApplicationService,
    whitelist: list[str],
) -> None:
    if not whitelist:
        warn("Список пуст.")
        prompt("Нажмите Enter...")
        return
    raw = prompt("Номер для удаления").strip()
    if not raw.isdigit() or not 1 <= int(raw) <= len(whitelist):
        error("Неверный номер.")
        prompt("Нажмите Enter для продолжения")
        return
    network = whitelist[int(raw) - 1]
    app.plugin_command(
        state,
        "honeypot",
        "remove_whitelist",
        network=network,
    )
    success(f"Удален из whitelist: {network}")
    prompt("Нажмите Enter для продолжения")


def _manage_honeypot_whitelist(
    state: AppState,
    app: ApplicationService,
) -> None:
    while True:
        clear()
        snapshot = app.plugin_query("honeypot", "management_snapshot")
        whitelist = snapshot.get("whitelist", [])
        lines = [
            f"  {CYAN}{index:>2}.{NC} {network}"
            for index, network in enumerate(whitelist, 1)
        ]
        panel("Доверенные IP (Whitelist)", lines)
        choice = menu([
            ("1", "➕ Добавить IP", "Внести адрес в whitelist"),
            ("2", "➖ Удалить IP", "Исключить адрес из whitelist"),
            ("0", "↩ Назад", ""),
        ], "WHITELIST HONEYPOT")
        if choice == "0":
            return
        if choice == "1":
            _add_honeypot_whitelist(state, app)
        elif choice == "2":
            _remove_honeypot_whitelist(state, app, whitelist)


def _show_honeypot_bans(banned: dict) -> None:
    clear()
    if not banned:
        lines = [f"  {DIM}Список пойманных IP пуст{NC}"]
    else:
        lines = [
            f"  {BOLD}{'IP':<24} {'Время бана':<20} Источник{NC}",
            "  " + "─" * 58,
        ]
        for address, metadata in list(banned.items())[-30:]:
            timestamp = metadata.get("banned_at", "?")[:16].replace(
                "T",
                " ",
            )
            source = metadata.get("source", "honeypot")
            lines.append(
                f"  {RED}{address:<24}{NC} "
                f"{DIM}{timestamp:<20}{NC} {source}",
            )
        if len(banned) > 30:
            lines.append(f"  {DIM}... и еще {len(banned) - 30} IP{NC}")
    panel(f"ПОЙМАННЫЕ IP ({len(banned)} шт.)", lines)
    prompt("Нажмите Enter для продолжения")


def _unban_honeypot_address(
    state: AppState,
    app: ApplicationService,
    banned: dict,
) -> None:
    clear()
    if not banned:
        warn("Список пойманных IP пуст.")
        prompt("Нажмите Enter для продолжения")
        return
    addresses = list(banned.keys())[-20:]
    panel(
        "Выберите IP для разбана",
        [
            f"  {CYAN}{index:>2}.{NC} {RED}{address}{NC}"
            for index, address in enumerate(addresses, 1)
        ],
    )
    raw = prompt("Номер или IP").strip()
    target = ""
    if raw.isdigit() and 1 <= int(raw) <= len(addresses):
        target = addresses[int(raw) - 1]
    elif raw in banned:
        target = raw
    if not target:
        error("IP не найден.")
    else:
        info(f"Разбаниваю {target}...")
        if app.plugin_command(
            state,
            "honeypot",
            "unban_address",
            address=target,
        ):
            success(f"Разбанен: {target}")
        else:
            error("Firewall не подтвердил удаление правила; запись сохранена")
    prompt("Нажмите Enter для продолжения")


def _show_honeypot_logs(app: ApplicationService) -> None:
    clear()
    lines = app.plugin_query("honeypot", "recent_logs", limit=30)
    if not lines:
        warn("Лог пуст или еще не создан.")
    else:
        log_lines = [
            f"  "
            f"{RED if 'BAN' in line else YELLOW if 'CONNECT' in line else DIM}"
            f"{line[:100]}{NC}"
            for line in lines
        ]
        panel("📋 ЛОГ HONEYPOT (последние 30 строк)", log_lines)
    prompt("Нажмите Enter для продолжения")


def _dispatch_honeypot_choice(
    choice: str,
    state: AppState,
    app: ApplicationService,
    *,
    installed: bool,
    active: bool,
    port: int,
    banned: dict,
) -> None:
    if choice == "1":
        _toggle_honeypot(
            state,
            app,
            installed=installed,
            active=active,
            port=port,
        )
    elif choice == "2":
        _change_honeypot_port(state, app, port=port, active=active)
    elif choice == "3":
        _manage_honeypot_whitelist(state, app)
    elif choice == "4":
        _show_honeypot_bans(banned)
    elif choice == "5":
        _unban_honeypot_address(state, app, banned)
    elif choice == "6":
        _show_honeypot_logs(app)


def menu_honeypot(state: AppState, app: ApplicationService) -> None:
    while True:
        clear()
        snapshot = app.plugin_query("honeypot", "management_snapshot")
        port = snapshot.get("port", 9999)
        whitelist = snapshot.get("whitelist", ["127.0.0.1", "::1"])
        banned = snapshot.get("banned", {})
        status = app.protocols.status("honeypot")
        panel(
            "🍯 HONEYPOT-ПОРТ (ловушка сканеров)",
            _honeypot_status_lines(status.running, port, banned),
        )
        choice = menu(
            _honeypot_options(
                status.running,
                port,
                whitelist,
                banned,
            ),
            "УПРАВЛЕНИЕ HONEYPOT",
        )
        if choice == "0":
            return
        _dispatch_honeypot_choice(
            choice,
            state,
            app,
            installed=status.installed,
            active=status.running,
            port=port,
            banned=banned,
        )
