"""Operator-only MASQUE endpoint picker, using the DNSCrypt numbered-panel pattern."""

from __future__ import annotations

from hydra.core.state_models import AppState
from hydra.services.application import ApplicationService
from hydra.ui.tui import clear, confirm, error, info, menu, panel, prompt, success, warn


def _label(selected: object) -> str:
    if isinstance(selected, dict) and selected.get("address") and selected.get("port"):
        return f"{selected['address']}:{selected['port']}"
    return "автоматический выбор"


def _result_lines(rows: list[dict], selected: object, *, page: int) -> list[str]:
    start = page * 20
    shown = rows[start : start + 20]
    pages = (len(rows) + 19) // 20
    lines = [
        f"  Рабочих адресов: {len(rows)} · страница {page + 1} из {pages}",
        f"  Сейчас: {_label(selected)}",
        "  " + "─" * 50,
        "   №  АДРЕС                    ЗАДЕРЖКА  ПОТЕРИ  УЗЕЛ",
    ]
    for index, row in enumerate(shown, start + 1):
        address = _label(row)
        current = (
            " ← выбран сейчас"
            if isinstance(selected, dict)
            and row["address"] == selected.get("address")
            and row["port"] == selected.get("port")
            else ""
        )
        lines.append(
            f"  {index:>2}. {address:<24} {row['ping_ms']:>5g} мс  {row['loss_percent']:>3}%  {row['node']}{current}"
        )
    lines.extend(
        [
            "  " + "─" * 50,
            "  Смена адреса не гарантирует смену страны выхода.",
            "  Номер — выбрать · [n]/[p] — страницы",
            "  [r] — повторить поиск · [0] — назад",
        ]
    )
    return lines


def _switch(
    state: AppState, app: ApplicationService, *, address: str, port: int, measurement: dict | None = None
) -> bool:
    selected = state.protocols["warp"].config.get("masque_endpoint")
    if selected == ({"address": address, "port": port} if address else None):
        info("Этот адрес уже выбран.")
        prompt("Нажмите Enter для продолжения")
        return False
    clear()
    lines = [
        f"  Сейчас: {_label(selected)}",
        f"  Новый адрес: {address}:{port}" if address else "  Новый режим: автоматический выбор",
    ]
    if measurement is not None:
        lines.append(f"  Поиск: {measurement['ping_ms']:g} мс · {measurement['loss_percent']}% потерь")
    lines.extend(["  " + "─" * 50, "  Если адрес не заработает, прежний выбор вернётся."])
    panel("ПЕРЕКЛЮЧИТЬ WARP?", lines)
    if not confirm("Переключить?", default=False):
        return False
    try:
        changed = app.plugin_command(state, "warp", "set_masque_endpoint", address=address, port=port)
    except Exception:
        error("Прежний выбор не удалось подтвердить — WARP может быть недоступен.")
        prompt("Нажмите Enter для продолжения")
        return False
    if changed:
        if not state.protocols["warp"].enabled:
            success("Адрес сохранён; WARP выключен.")
        elif address:
            success(f"WARP подключён к {address}:{port}.")
        else:
            success("Автоматический выбор восстановлен.")
    else:
        error("Новый адрес не заработал. Прежний выбор восстановлен.")
    prompt("Нажмите Enter для продолжения")
    return changed


def _results(state: AppState, app: ApplicationService, rows: list[dict]) -> bool:
    page = 0
    while True:
        clear()
        panel(
            "РЕЗУЛЬТАТЫ ПОИСКА WARP",
            _result_lines(rows, state.protocols["warp"].config.get("masque_endpoint"), page=page),
        )
        choice = prompt("Номер адреса", "0").strip().lower()
        if choice == "0":
            return False
        if choice == "r":
            return True
        if choice == "n":
            page = min(page + 1, (len(rows) - 1) // 20)
        elif choice == "p":
            page = max(page - 1, 0)
        else:
            try:
                index = int(choice)
            except ValueError:
                index = 0
            if 1 <= index <= len(rows):
                row = rows[index - 1]
                if _switch(state, app, address=row["address"], port=row["port"], measurement=row):
                    return False
                continue
            warn("Такого номера нет.")
            prompt("Нажмите Enter для продолжения")


def _scan(state: AppState, app: ApplicationService) -> None:
    status = app.plugin_query("warp", "masque_scanner_status")
    if not status["installed"]:
        error("warpscout не установлен на VPS.")
        info("Установи проверенный релиз: github.com/vernette/warpscout/releases")
        prompt("Нажмите Enter для продолжения")
        return
    if not status["account_ready"]:
        panel(
            "ПОДГОТОВКА ПОИСКА WARP",
            [
                "  Для поиска нужен отдельный аккаунт warpscout.",
                "  Рабочее устройство WARP в Hydra не меняется.",
            ],
        )
        if not confirm("Создать аккаунт для поиска?", default=False):
            return
        try:
            app.plugin_action("warp", "register_masque_scanner")
        except Exception:
            error("Не удалось подготовить поиск WARP.")
            prompt("Нажмите Enter для продолжения")
            return
    if not confirm("Проверить адреса с этой VPS? Текущий WARP не изменится.", default=False):
        return
    while True:
        clear()
        panel(
            "ПОИСК АДРЕСОВ WARP",
            ["  Проверяю MASQUE и передачу данных...", "  Текущий WARP не меняется. Ctrl+C — остановить поиск."],
        )
        try:
            rows = app.plugin_action("warp", "scan_masque_endpoints")
        except KeyboardInterrupt:
            warn("Поиск остановлен. Текущий адрес не изменён.")
            prompt("Нажмите Enter для продолжения")
            return
        except Exception:
            error("Поиск не удался. Текущий адрес не изменён.")
            prompt("Нажмите Enter для продолжения")
            return
        if not rows:
            warn("Рабочих адресов не найдено. Текущий адрес не изменён.")
            prompt("Нажмите Enter для продолжения")
            return
        if not _results(state, app, rows):
            return


def _menu_masque(state: AppState, app: ApplicationService) -> None:
    while True:
        clear()
        selected = state.protocols["warp"].config.get("masque_endpoint")
        panel(
            "СЕРВЕР ПОДКЛЮЧЕНИЯ WARP",
            [
                f"  Режим: {'выбран вручную' if selected else 'автоматический'}",
                f"  Адрес: {_label(selected)}",
                f"  WARP: {'включён' if state.protocols['warp'].enabled else 'выключен'}",
            ],
        )
        choice = menu(
            [
                ("1", "Найти рабочие адреса", "Проверить MASQUE с этой VPS, не меняя WARP"),
                (
                    "2",
                    "Вернуть автоматический выбор",
                    "Ядро снова само выберет адрес" if selected else "Уже используется",
                ),
                ("0", "Назад", ""),
            ],
            "СЕРВЕР ПОДКЛЮЧЕНИЯ WARP",
        )
        if choice == "0":
            return
        if choice == "1":
            _scan(state, app)
        elif choice == "2" and selected:
            _switch(state, app, address="", port=0)
