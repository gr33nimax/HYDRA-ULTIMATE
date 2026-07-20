"""TUI manager for the Anti-DPI detector."""
from __future__ import annotations

import ipaddress
from datetime import datetime

import hydra.core.orchestrator as orchestrator
from hydra.core.host import HOST
from hydra.core.state import AppState
from hydra.ui.tui import CYAN, DIM, GREEN, RED, clear, menu, panel, prompt, success, warn


def _signals(metadata: object) -> str:
    if not isinstance(metadata, dict):
        return "—"
    value = metadata.get("signals", [])
    if isinstance(value, str):
        return value or "—"
    if isinstance(value, list):
        return ", ".join(str(item) for item in value) or "—"
    return "—"


def _time(value: object) -> str:
    try:
        return datetime.fromtimestamp(float(value)).strftime("%d.%m %H:%M:%S")
    except (TypeError, ValueError, OSError):
        return "—"


def _ban_history(plugin) -> None:
    data = plugin._load_state()
    banned = data.get("banned", {}) if isinstance(data.get("banned"), dict) else {}
    history = data.get("history", []) if isinstance(data.get("history"), list) else []
    clear()
    lines = []
    for item in reversed(history[-100:]):
        if not isinstance(item, dict):
            continue
        status = "активен" if item.get("status", "active") == "active" else "снят"
        lines.append(
            f"  {CYAN}{item.get('ip', '?'):<39}{DIM} {_time(item.get('at'))}  "
            f"score={item.get('score', 0)}  {status}  {_signals(item)}"
        )
    if not lines:
        for ip, metadata in reversed(list(banned.items())):
            meta = metadata if isinstance(metadata, dict) else {}
            lines.append(f"  {CYAN}{ip:<39}{DIM} {_time(meta.get('at'))}  score={meta.get('score', 0)}  {_signals(meta)}")
    panel(f"ИСТОРИЯ БАНОВ — АКТИВНЫХ: {len(banned)}", lines or ["  История пока пуста"])
    if banned:
        raw = prompt("IP для разбана или Enter для возврата").strip()
        if raw:
            success("Бан снят") if plugin.unban(raw) else warn("Не удалось снять бан")
            prompt("Enter")
    else:
        prompt("Enter")


def _whitelist(plugin) -> None:
    while True:
        data = plugin._load_state()
        values = data.get("whitelist", []) if isinstance(data.get("whitelist"), list) else []
        clear()
        panel("WHITELIST", [f"  {index}. {value}" for index, value in enumerate(values, 1)] or ["  Список пуст"])
        choice = menu([
            ("1", "➕ Добавить IP/CIDR", "Исключить адрес или подсеть из анализа"),
            ("2", "➖ Удалить IP/CIDR", "Вернуть адрес под контроль Anti-DPI"),
            ("0", "Назад", ""),
        ], "УПРАВЛЕНИЕ WHITELIST")
        if choice == "0":
            return
        raw = prompt("IP/CIDR").strip()
        try:
            network = str(ipaddress.ip_network(raw, strict=False))
        except ValueError:
            warn("Некорректный IP/CIDR")
            prompt("Enter")
            continue
        if choice == "1":
            if network not in values:
                values.append(network)
                data["whitelist"] = values
                plugin._save_state(data)
            success("Добавлено в whitelist")
        elif choice == "2":
            if network in values:
                values.remove(network)
                data["whitelist"] = values
                plugin._save_state(data)
                success("Удалено из whitelist")
            else:
                warn("Запись не найдена")
        prompt("Enter")


def _show_log() -> None:
    result = HOST.run(
        ["journalctl", "-u", "hydra-antidpi", "-n", "50", "--no-pager", "-o", "short-iso"],
        text=True, timeout=20,
    )
    output = str(result.stdout or result.stderr or "").strip()
    panel("ЛОГ ANTI-DPI — ПОСЛЕДНИЕ 50 СТРОК", [f"  {line[:110]}" for line in output.splitlines()] or ["  Лог пуст"])
    prompt("Enter")


def menu_antidpi(state: AppState, plugin) -> None:
    while True:
        status = plugin.status()
        data = plugin._load_state()
        banned = data.get("banned", {}) if isinstance(data.get("banned"), dict) else {}
        whitelist = data.get("whitelist", []) if isinstance(data.get("whitelist"), list) else []
        health = plugin.health_result()
        clear()
        service_text = "активна" if status.running else "остановлена"
        health_text = "исправна" if health.healthy else "требует внимания"
        panel("ANTI-DPI — ЗАЩИТА ОТ АКТИВНЫХ ЗОНДОВ", [
            f"  Служба:     {GREEN if status.running else RED}{service_text}{DIM}",
            f"  Состояние:  {GREEN if health.healthy else RED}{health_text}{DIM}",
            f"  Событий:    {data.get('events', 0)}",
            f"  Активных банов: {len(banned)}",
            f"  Whitelist:  {len(whitelist)} IP/CIDR",
            f"  Ошибка:     {status.info.get('last_error') or 'нет'}",
        ])
        choice = menu([
            ("1", "⏸️  Остановить Anti-DPI" if status.running else "▶️  Запустить Anti-DPI", "Переключить статус службы"),
            ("2", f"🚫 История банов ({len(banned)} активных)", "Просмотр score/signals и разбан IP"),
            ("3", f"⚪ Управление whitelist ({len(whitelist)} записей)", "Добавление и удаление IP/подсетей-исключений"),
            ("4", "📋 Лог Anti-DPI", "Последние 50 строк журнала службы"),
            ("0", "Назад", ""),
        ], "УПРАВЛЕНИЕ ANTI-DPI")
        if choice == "0":
            return
        if choice == "1":
            try:
                ok = orchestrator.disable(state, "antidpi") if status.running else orchestrator.enable(state, "antidpi")
                success("Служба остановлена" if status.running and ok else "Служба запущена") if ok else warn("Не удалось изменить состояние службы")
            except Exception as exc:
                warn(str(exc))
            prompt("Enter")
        elif choice == "2":
            _ban_history(plugin)
        elif choice == "3":
            _whitelist(plugin)
        elif choice == "4":
            _show_log()
