"""Ban-list interactions for the Fail2ban TUI controller."""
from __future__ import annotations

from hydra.services.application import ApplicationService
from hydra.ui.plugin_managers._facade_bridge import facade
from hydra.ui.tui import (
    BOLD,
    CYAN,
    DIM,
    NC,
    RED,
    clear,
    error,
    info,
    menu,
    panel,
    prompt,
    success,
    warn,
)


def manage_banned_ips(
    jail_names: list[str],
    app: ApplicationService,
) -> None:
    clear()
    rows = [
        (address, jail)
        for jail in jail_names
        for address in facade._f2b_jail_info(app, jail)["banned_ips"]
    ]
    if rows:
        lines = [
            f"  {BOLD}{'#':<4}{'IP':<24}Джейл{NC}",
            "  " + "─" * 40,
        ]
        lines.extend(
            f"  {CYAN}{index:<4}{NC}{RED}{address:<24}{NC}"
            f"{DIM}{jail}{NC}"
            for index, (address, jail) in enumerate(rows, 1)
        )
        lines.extend([
            "",
            f"  {DIM}Введите номер(а), IP, CIDR или ASN для разбана{NC}",
        ])
    else:
        lines = [f"  {DIM}Забаненных IP нет{NC}"]
    panel(f"🚫 ЗАБАНЕННЫЕ IP ({len(rows)} шт.)", lines)

    raw = prompt(
        "Разбанить (Enter — отмена)"
        if rows
        else "Нажмите Enter для продолжения",
    ).strip()
    if not rows or not raw:
        return
    targets: list[str] = []
    for token in raw.replace(",", " ").split():
        if token.isdigit() and 1 <= int(token) <= len(rows):
            targets.append(rows[int(token) - 1][0])
            continue
        for _display, _kind, cidrs in facade._resolve_ban_targets(
            token,
            app,
        ):
            targets.extend(cidrs)
    if not targets:
        error("Не удалось распознать цели для разбана.")
    else:
        unbanned, missing = facade._f2b_unban_many(app, targets)
        if unbanned:
            success(f"Разбанено адресов: {unbanned}")
        if missing:
            warn(f"Не забанено / не найдено: {missing}")
    prompt("Нажмите Enter для продолжения")


def _choose_jail(
    jail_names: list[str],
    title_text: str,
) -> str | None:
    options = [
        (str(index), jail, "")
        for index, jail in enumerate(jail_names, 1)
    ]
    options.append(("0", "Отмена", ""))
    choice = menu(options, title_text)
    if not choice.isdigit():
        return None
    index = int(choice) - 1
    return jail_names[index] if 0 <= index < len(jail_names) else None


def manual_ban(
    jail_names: list[str],
    app: ApplicationService,
) -> None:
    clear()
    if not jail_names:
        error("Нет доступных активных джейлов.")
        prompt("Нажмите Enter...")
        return
    jail = _choose_jail(jail_names, "ВЫБЕРИТЕ ДЖЕЙЛ ДЛЯ БАНА")
    if jail is None:
        return

    clear()
    panel(f"БАН В ДЖЕЙЛЕ {jail}", [
        "  Можно ввести несколько целей через пробел или запятую:",
        "",
        f"    {CYAN}1.2.3.4{NC}              — одиночный IP",
        f"    {CYAN}10.0.0.0/24{NC}          — подсеть (CIDR)",
        f"    {CYAN}10.0.0.1-10.0.0.255{NC}  — диапазон IPv4",
        f"    {CYAN}AS12345{NC}              — автономная система (ASN)",
        "",
        f"  {DIM}Пример: 1.2.3.4, AS1234{NC}",
    ])
    raw = prompt("Цели для бана").strip()
    if not raw:
        return
    targets = facade._resolve_ban_targets(raw, app)
    if not targets:
        error("Не удалось разобрать ни одной цели.")
        prompt("Нажмите Enter...")
        return

    cidrs: list[str] = []
    for display, kind, resolved in targets:
        cidrs.extend(resolved)
        info(f"Разрешено {display} ({kind}): {len(resolved)} CIDR")
    info(f"Применяю бан в джейле {jail} ({len(cidrs)} CIDR)...")
    newly_banned = facade._f2b_ban_many(app, jail, cidrs)
    if newly_banned:
        success(
            f"Успешно забанено новых записей: {newly_banned} в {jail}",
        )
    else:
        warn(
            "Новых записей не добавлено "
            "(возможно, они уже в бане или служба остановлена)",
        )
    prompt("Нажмите Enter для продолжения")


def show_history(app: ApplicationService) -> None:
    clear()
    history = facade._f2b_today_ban_history(app)
    lines = [
        f"  {DIM}Накопительный список за текущие сутки "
        f"(сбрасывается в полночь).{NC}",
        f"  {DIM}Показывает факт бана, даже если bantime уже истек "
        f"и IP разбанен.{NC}",
        "  " + "─" * 68,
        f"  {BOLD}{'#':<4}{'IP':<22}{'Джейл':<15}"
        f"{'Раз':<5}{'Впервые':<10}Последний{NC}",
        "  " + "─" * 68,
    ]
    if not history:
        lines.append(
            f"  {DIM}За сегодня событий бана не зафиксировано.{NC}",
        )
    else:
        lines.extend(
            f"  {CYAN}{index:<4}{NC}{RED}{entry['ip']:<22}{NC}"
            f"{DIM}{entry['jail']:<15}{NC}{entry['count']:<5}"
            f"{DIM}{entry['first_seen']:<10}{NC}{entry['last_seen']}"
            for index, entry in enumerate(history, 1)
        )
    panel(
        f"📊 ИСТОРИЯ БАНОВ ЗА СЕГОДНЯ ({len(history)} шт.)",
        lines,
    )
    prompt("Нажмите Enter для продолжения")


__all__ = ["manage_banned_ips", "manual_ban", "show_history"]
