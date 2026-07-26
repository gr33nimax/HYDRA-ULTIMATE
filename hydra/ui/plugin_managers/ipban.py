"""
Application UI for managing IP bans.
"""
from __future__ import annotations

from hydra.core.state_models import AppState
from hydra.services.application import ApplicationService
from hydra.ui.tui import (
    clear, menu, prompt, confirm, panel, info, success, warn, error,
    GREEN, CYAN, BOLD, DIM, NC
)

def _ipban_status_lines(
    installed: bool,
    running: bool,
    entries: list[dict],
    cidrs_v4: int,
    cidrs_v6: int,
) -> list[str]:
    return [
        f"  Статус iptables:    "
        f"{f'{GREEN}активны{NC}' if running else f'{DIM}не установлены{NC}'}",
        f"  Записей в базе:     "
        f"{f'{GREEN}{len(entries)}{NC}' if entries else f'{DIM}нет{NC}'}",
        f"  Активных CIDR:      "
        f"{f'{GREEN}{cidrs_v4} IPv4 / {cidrs_v6} IPv6{NC}' if installed else f'{DIM}ipset не создан{NC}'}",
    ]


def _ipban_options(
    installed: bool,
) -> list[tuple[str, str, str]]:
    if not installed:
        options = [
            (
                "1",
                "🔧 Установить ipset и правила",
                "Необходим пакет ipset и iptables правила",
            ),
        ]
    else:
        options = [
            (
                "1",
                "➕ Добавить бан",
                "IP / подсеть / диапазон / ASN (RIPE Stat)",
            ),
            ("2", "➖ Снять бан", "Выбрать и разбанить запись"),
            (
                "3",
                "📋 Список активных банов",
                "Просмотр всех блокировок",
            ),
            (
                "4",
                "🔄 Восстановить из базы",
                "Пересоздать правила и восстановить баны",
            ),
            ("-", "", ""),
            (
                "X",
                "🗑️ Снять ВСЕ баны",
                "Очистить базу, сбросить сеты и правила",
            ),
        ]
    options.append(("0", "↩ Назад", ""))
    return options


def _install_ipban(
    state: AppState,
    app: ApplicationService,
) -> None:
    info("Установка ipset и настройка правил...")
    if (
        app.protocols.install(state, "ipban")
        and app.protocols.enable(state, "ipban")
    ):
        success("Успешно установлено!")
    else:
        error(
            "Не удалось настроить ipset. Подробнее в логе: "
            "/var/log/hydra/install.log",
        )
    prompt("Нажмите Enter для продолжения")


def _add_ipban(
    state: AppState,
    app: ApplicationService,
) -> None:
    clear()
    panel("➕ ДОБАВИТЬ БАН", [
        "  Форматы ввода (можно несколько через пробел или запятую):",
        "",
        f"    {CYAN}1.2.3.4{NC}              — одиночный IP",
        f"    {CYAN}10.0.0.0/24{NC}          — подсеть (CIDR)",
        f"    {CYAN}10.0.0.1-10.0.0.255{NC}  — диапазон IPv4",
        f"    {CYAN}AS12345{NC}              — автономная система (ASN)",
        f"    {CYAN}2001:db8::/32{NC}         — IPv6 подсеть",
        "",
        f"  {DIM}Пример: 1.2.3.4, 10.0.0.0/8, AS1234{NC}",
    ])
    raw = prompt("Ввод").strip()
    if not raw:
        return
    comment = prompt("Комментарий (Enter — пропустить)").strip()
    tokens = [
        token
        for token in raw.replace(",", " ").split()
        if token
    ]
    print()
    info("Применяю блокировку...")
    for token in tokens:
        try:
            changed = app.plugin_command(
                state,
                "ipban",
                "add_ban",
                raw=token,
                comment=comment,
            )
        except Exception as exc:
            error(f"Не удалось разобрать '{token}': {exc}")
            continue
        info("Разрешено в 1 CIDR...")
        if changed:
            success(f"Заблокировано: {token} (desired) — 1 CIDR")
        else:
            error(f"Не удалось заблокировать: {token}")
    prompt("Нажмите Enter для продолжения")


def _ipban_entry_icon(entry: dict) -> str:
    return {
        "ip": "🔹",
        "cidr": "🔸",
        "range": "🔷",
        "asn": "🏢",
    }.get(entry.get("kind", ""), "•")


def _ipban_remove_lines(entries: list[dict]) -> list[str]:
    lines: list[str] = []
    for index, entry in enumerate(entries, 1):
        count = len(entry.get("cidrs", []))
        added = entry.get("added_at", "")[:10]
        comment = (
            f" | {DIM}{entry['comment']}{NC}"
            if entry.get("comment")
            else ""
        )
        lines.append(
            f"  {CYAN}{index:>2}.{NC} {_ipban_entry_icon(entry)} "
            f"{BOLD}{entry['display']}{NC} "
            f"[{count} CIDR, {added}]{comment}",
        )
    return lines


def _find_ipban_target(
    raw: str,
    entries: list[dict],
) -> str | None:
    if raw.isdigit():
        index = int(raw) - 1
        if 0 <= index < len(entries):
            return str(entries[index]["display"])
        return None
    return next(
        (
            str(entry["display"])
            for entry in entries
            if raw.upper() == str(entry["display"]).upper()
        ),
        None,
    )


def _remove_ipban(
    state: AppState,
    app: ApplicationService,
    entries: list[dict],
) -> None:
    clear()
    if not entries:
        warn("Список блокировок пуст.")
        prompt("Нажмите Enter для продолжения")
        return
    panel(
        "СНЯТЬ БАН — выберите запись",
        _ipban_remove_lines(entries),
    )
    raw = prompt("Номер или имя для разбана").strip()
    if not raw:
        return
    target = _find_ipban_target(raw, entries)
    if target is None:
        error(f"Запись '{raw}' не найдена.")
        app.monitoring.sleep(1.5)
        return
    info(f"Снимаю бан с {target}...")
    if app.plugin_command(
        state,
        "ipban",
        "remove_ban",
        display=target,
    ):
        success(f"Разбанено: {target}")
    else:
        error(f"Не удалось разбанить {target}")
    prompt("Нажмите Enter для продолжения")


def _ipban_list_lines(entries: list[dict]) -> list[str]:
    if not entries:
        return [f"  {DIM}Список блокировок пуст{NC}"]
    labels = {
        "ip": "IP",
        "cidr": "CIDR",
        "range": "Range",
        "asn": "ASN",
    }
    lines = [
        f"  {BOLD}{'#':>3}  {'Тип':<6}  {'Запись':<28}  "
        f"{'CIDR':>5}  {'Добавлен':<10}  Комментарий{NC}",
        "  " + "─" * 68,
    ]
    for index, entry in enumerate(entries, 1):
        kind = labels.get(entry.get("kind", ""), "?")
        count = len(entry.get("cidrs", []))
        added = entry.get("added_at", "")[:10]
        comment = entry.get("comment", "")[:20]
        display = entry.get("display", "")[:28]
        lines.append(
            f"  {CYAN}{index:>3}.{NC}  {kind:<6}  "
            f"{BOLD}{display:<28}{NC}  {count:>5}  "
            f"{DIM}{added:<10}{NC}  {DIM}{comment}{NC}",
        )
    return lines


def _show_ipban_entries(entries: list[dict]) -> None:
    clear()
    panel("📋 АКТИВНЫЕ IP-БАНЫ", _ipban_list_lines(entries))
    prompt("Нажмите Enter для продолжения")


def _restore_ipban(
    state: AppState,
    app: ApplicationService,
) -> None:
    info("Восстановление правил и сетов из базы...")
    if app.plugin_command(state, "ipban", "restore_bans"):
        success("Готово!")
    else:
        error("Ошибка при восстановлении правил.")
    prompt("Нажмите Enter для продолжения")


def _reset_ipban(
    state: AppState,
    app: ApplicationService,
) -> None:
    warn("СБРОС ВСЕХ БАНОВ!")
    warn(
        "Будут удалены все правила iptables, "
        "ipset-сеты и очищена база данных.",
    )
    if not confirm("Вы уверены?", default=False):
        info("Отменено.")
        prompt("Нажмите Enter для продолжения")
        return
    info("Очищаю...")
    if app.plugin_command(state, "ipban", "reset_bans"):
        if app.protocols.status("ipban").running:
            success("Все блокировки успешно сброшены!")
        else:
            error("Баны сняты, но защитные правила не удалось восстановить")
    else:
        error(
            "Не удалось удалить все правила firewall; "
            "база оставлена без изменений",
        )
    prompt("Нажмите Enter для продолжения")


def _dispatch_ipban_choice(
    choice: str,
    state: AppState,
    app: ApplicationService,
    entries: list[dict],
) -> None:
    if choice == "1":
        _add_ipban(state, app)
    elif choice == "2":
        _remove_ipban(state, app, entries)
    elif choice == "3":
        _show_ipban_entries(entries)
    elif choice == "4":
        _restore_ipban(state, app)
    elif choice.upper() == "X":
        _reset_ipban(state, app)


def menu_ipban(state: AppState, app: ApplicationService) -> None:
    while True:
        clear()
        status = app.protocols.status("ipban")
        entries = app.plugin_query("ipban", "list_banned")
        cidrs_v4 = int(status.info.get("cidrs_v4", 0))
        cidrs_v6 = int(status.info.get("cidrs_v6", 0))
        panel(
            "🚫 IP-БАН (iptables / ipset)",
            _ipban_status_lines(
                status.installed,
                status.running,
                entries,
                cidrs_v4,
                cidrs_v6,
            ),
        )
        choice = menu(
            _ipban_options(status.installed),
            "УПРАВЛЕНИЕ IP-БАНАМИ",
        )
        if choice == "0":
            return
        if not status.installed:
            if choice == "1":
                _install_ipban(state, app)
            continue
        _dispatch_ipban_choice(choice, state, app, entries)
