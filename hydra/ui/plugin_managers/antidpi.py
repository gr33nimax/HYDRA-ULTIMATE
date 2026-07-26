"""TUI manager for the Anti-DPI detector."""
from __future__ import annotations

import ipaddress

from hydra.core.state_models import AppState
from hydra.services.application import ApplicationService
from hydra.ui.plugin_managers._antidpi_views import (
    ban_table,
    coordinated_table,
    counter_lines,
    history_table,
    rows as views_rows,
    status_lines,
    watchlist_table,
)
from hydra.ui.tui import (
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

BAN_ERRORS = {
    "invalid_ip": "Некорректный IP-адрес",
    "whitelisted": "Адрес находится в whitelist",
    "firewall_error": "Firewall не принял правило блокировки",
}


def _snapshot(app: ApplicationService) -> dict:
    data = app.plugin_query("antidpi", "management_snapshot")
    return data if isinstance(data, dict) else {}


def _signals(metadata: object) -> str:
    """Legacy raw signal renderer kept for the compatibility module alias."""
    if not isinstance(metadata, dict):
        return "—"
    value = metadata.get("signals", [])
    if isinstance(value, str):
        return value or "—"
    if isinstance(value, list):
        return ", ".join(str(item) for item in value) or "—"
    return "—"


def _resolve_targets(raw: str, addresses: list[str]) -> list[str]:
    """Accept row numbers, bare addresses, or a mix of both."""
    targets: list[str] = []
    for token in raw.replace(",", " ").split():
        if token.isdigit() and 1 <= int(token) <= len(addresses):
            targets.append(addresses[int(token) - 1])
            continue
        try:
            targets.append(ipaddress.ip_address(token.strip("[]")).compressed)
        except ValueError:
            warn(f"Не распознано: {token}")
    return list(dict.fromkeys(targets))


def _bans(state: AppState, app: ApplicationService) -> None:
    while True:
        data = _snapshot(app)
        ordered = [
            str(row.get("ip"))
            for row in views_rows(data, "ban_rows")
            if row.get("ip")
        ]
        clear()
        panel(
            f"🚫 АКТИВНЫЕ БЛОКИРОВКИ ({len(ordered)})",
            ban_table(data),
        )
        panel("📜 ЗАВЕРШЁННЫЕ ЗАПИСИ", history_table(data))
        if not ordered:
            prompt("Enter для возврата")
            return
        raw = prompt("Номера или IP для разбана (Enter — назад)").strip()
        if not raw:
            return
        _unban_targets(state, app, _resolve_targets(raw, ordered))
        prompt("Enter для продолжения")


def _unban_targets(
    state: AppState,
    app: ApplicationService,
    targets: list[str],
) -> None:
    if not targets:
        error("Не указано ни одного корректного адреса.")
        return
    for address in targets:
        if app.plugin_command(
            state,
            "antidpi",
            "unban_address",
            address=address,
        ):
            success(f"Блокировка снята: {address}")
        else:
            warn(f"Не удалось снять блокировку: {address}")


def _watchlist(app: ApplicationService) -> None:
    data = _snapshot(app)
    clear()
    panel(
        f"👁 ПОД НАБЛЮДЕНИЕМ ({len(views_rows(data, 'watchlist'))})",
        watchlist_table(data),
    )
    coordinated = views_rows(data, "coordinated")
    panel(
        f"🌐 СКООРДИНИРОВАННАЯ АКТИВНОСТЬ ({len(coordinated)})",
        coordinated_table(data),
    )
    panel("📊 НАКОПЛЕННАЯ СТАТИСТИКА", counter_lines(data))
    prompt("Enter для возврата")


def _manual_ban(app: ApplicationService) -> None:
    clear()
    panel("🔒 РУЧНАЯ БЛОКИРОВКА", [
        f"  {DIM}Адрес блокируется бессрочно, до снятия вручную.{NC}",
        f"  {DIM}Whitelist имеет приоритет: доверенный адрес заблокирован "
        f"не будет.{NC}",
        "",
        f"  {CYAN}Пример:{NC} 198.51.100.7",
    ])
    raw = prompt("IP для блокировки (Enter — отмена)").strip()
    if not raw:
        return
    result = app.plugin_action("antidpi", "manual_ban", raw=raw, source="tui")
    result = result if isinstance(result, dict) else {}
    if not result.get("ok"):
        error(
            BAN_ERRORS.get(
                str(result.get("error")),
                "Не удалось заблокировать адрес",
            ),
        )
    elif result.get("already_active"):
        info(f"{raw} уже заблокирован бессрочно")
    else:
        success(f"{raw} заблокирован бессрочно (нарушение "
                f"#{int(result.get('offense_count', 1) or 1)})")
    prompt("Enter для продолжения")


def _whitelist(state: AppState, app: ApplicationService) -> None:
    while True:
        data = _snapshot(app)
        values = data.get("whitelist", [])
        values = values if isinstance(values, list) else []
        clear()
        panel("⚪ WHITELIST — ДОВЕРЕННЫЕ АДРЕСА", [
            *(
                f"  {CYAN}{index:>3}.{NC} {value}"
                for index, value in enumerate(values, 1)
            ),
            *([] if values else [f"  {DIM}Список пуст{NC}"]),
            "",
            f"  {DIM}Адреса самой VPS и приватные сети доверены всегда.{NC}",
        ])
        choice = menu([
            ("1", "➕ Добавить IP/CIDR", "Исключить адрес или подсеть из анализа и снять её блокировки"),
            ("2", "➖ Удалить IP/CIDR", "Вернуть адрес под контроль Anti-DPI"),
            ("0", "↩ Назад", ""),
        ], "УПРАВЛЕНИЕ WHITELIST")
        if choice == "0":
            return
        raw = prompt("IP/CIDR").strip()
        if not raw:
            continue
        try:
            network = str(ipaddress.ip_network(raw, strict=False))
        except ValueError:
            error("Некорректный IP или CIDR")
            prompt("Enter для продолжения")
            continue
        _apply_whitelist_change(state, app, choice, network)
        prompt("Enter для продолжения")


def _apply_whitelist_change(
    state: AppState,
    app: ApplicationService,
    choice: str,
    network: str,
) -> None:
    if choice == "1":
        if app.plugin_command(
            state,
            "antidpi",
            "add_whitelist",
            network=network,
        ):
            success(f"{network} добавлен в whitelist")
        else:
            info(f"{network} уже был в whitelist")
        return
    if choice == "2":
        if app.plugin_command(
            state,
            "antidpi",
            "remove_whitelist",
            network=network,
        ):
            success(f"{network} удалён из whitelist")
        else:
            warn("Запись не найдена")


def _show_log(app: ApplicationService) -> None:
    clear()
    lines = app.plugin_query("antidpi", "recent_logs", limit=50)
    lines = lines if isinstance(lines, list) else []
    rendered = [
        f"  {_log_color(line)}{str(line)[:104]}{NC}"
        for line in lines
    ] or [f"  {DIM}Журнал пуст или служба ещё не запускалась{NC}"]
    panel("📋 ЖУРНАЛ ANTI-DPI — ПОСЛЕДНИЕ 50 СТРОК", rendered)
    prompt("Enter для возврата")


def _log_color(line: object) -> str:
    text = str(line).lower()
    if any(token in text for token in ("error", "traceback", "failed")):
        return RED
    if any(token in text for token in ("ban", "alert", "warn")):
        return YELLOW
    return DIM


def _selftest(state: AppState, app: ApplicationService) -> None:
    clear()
    panel("🧪 ЛОКАЛЬНАЯ ДИАГНОСТИКА", [
        f"  {DIM}Отправляет некорректные пакеты на включённые "
        f"транспорты с самой VPS{NC}",
        f"  {DIM}и собирает redacted-архив с журналами протоколов.{NC}",
        "",
        f"  {YELLOW}Не проверяет{NC} {DIM}атрибуцию внешнего IP, "
        f"применение банов и доставку в Telegram:{NC}",
        f"  {DIM}петлевые адреса всегда доверены.{NC}",
    ])
    if not confirm("Запустить локальную диагностику?", default=False):
        return
    info("Выполняю зондирование, это займёт несколько секунд...")
    try:
        result = app.plugin_action(
            "antidpi",
            "run_selftest",
            state=state,
            wait_seconds=2.0,
            protocols=app.protocols,
        )
    except Exception as exc:
        error(f"Диагностика не выполнена: {exc}")
        prompt("Enter для продолжения")
        return
    _report_selftest(result if isinstance(result, dict) else {})
    prompt("Enter для продолжения")


def _report_selftest(result: dict) -> None:
    coverage = result.get("report", {})
    coverage = (
        coverage.get("coverage", {})
        if isinstance(coverage, dict)
        else {}
    )
    coverage = coverage if isinstance(coverage, dict) else {}
    clear()
    panel("🧪 РЕЗУЛЬТАТ ДИАГНОСТИКИ", [
        f"  Архив:              {GREEN}{result.get('archive', '—')}{NC}",
        f"  Протоколов с логом: "
        f"{result.get('captured_protocols', 0)}",
        f"  Включено протоколов: "
        f"{coverage.get('enabled_protocols', 0)}",
        f"  Совпало с фильтрами: "
        f"{coverage.get('filter_matches', 0)}",
        "",
        f"  {DIM}Проверьте архив перед отправкой: он вычищен "
        f"автоматически.{NC}",
    ])


def _toggle(state: AppState, app: ApplicationService, *, running: bool) -> None:
    try:
        ok = (
            app.protocols.disable(state, "antidpi")
            if running
            else app.protocols.enable(state, "antidpi")
        )
    except Exception as exc:
        error(str(exc))
        prompt("Enter для продолжения")
        return
    if not ok:
        warn("Не удалось изменить состояние службы")
    elif running:
        success("Служба Anti-DPI остановлена, правила firewall удалены")
    else:
        success("Служба Anti-DPI запущена")
    prompt("Enter для продолжения")


def _options(*, running: bool, banned: int, watching: int, whitelist: int):
    return [
        (
            "1",
            "⏸️  Остановить Anti-DPI" if running else "▶️  Запустить Anti-DPI",
            "Переключить состояние службы и правил firewall",
        ),
        (
            "2",
            f"🚫 Блокировки и история ({banned})",
            "Score, сигналы, остаток срока и разбан адресов",
        ),
        (
            "3",
            f"👁 Под наблюдением ({watching})",
            "Адреса с уликами ниже порога бана и статистика сигналов",
        ),
        (
            "4",
            f"⚪ Whitelist ({whitelist})",
            "Доверенные адреса и подсети",
        ),
        ("5", "🔒 Заблокировать адрес", "Бессрочная блокировка вручную"),
        ("6", "📋 Журнал Anti-DPI", "Последние 50 строк журнала службы"),
        ("7", "🧪 Локальная диагностика", "Проверка логов протоколов и фильтров"),
        ("0", "↩ Назад", ""),
    ]


def menu_antidpi(state: AppState, app: ApplicationService) -> None:
    while True:
        status = app.protocols.status("antidpi")
        data = _snapshot(app)
        whitelist = data.get("whitelist", [])
        whitelist = whitelist if isinstance(whitelist, list) else []
        health = app.protocols.health(state, "antidpi")
        payload = dict(data)
        payload["last_error"] = status.info.get("last_error", "")
        clear()
        panel(
            "🛡 ANTI-DPI — ЗАЩИТА ОТ АКТИВНЫХ ЗОНДОВ",
            status_lines(
                running=status.running,
                health=health,
                data=payload,
            ),
        )
        choice = menu(
            _options(
                running=status.running,
                banned=len(views_rows(data, "ban_rows")),
                watching=len(views_rows(data, "watchlist")),
                whitelist=len(whitelist),
            ),
            "УПРАВЛЕНИЕ ANTI-DPI",
        )
        if choice == "0":
            return
        _dispatch(choice, state, app, running=status.running)


def _dispatch(
    choice: str,
    state: AppState,
    app: ApplicationService,
    *,
    running: bool,
) -> None:
    if choice == "1":
        _toggle(state, app, running=running)
    elif choice == "2":
        _bans(state, app)
    elif choice == "3":
        _watchlist(app)
    elif choice == "4":
        _whitelist(state, app)
    elif choice == "5":
        _manual_ban(app)
    elif choice == "6":
        _show_log(app)
    elif choice == "7":
        _selftest(state, app)


__all__ = ["_signals", "menu_antidpi"]
