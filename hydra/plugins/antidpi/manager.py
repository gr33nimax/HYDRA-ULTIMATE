"""TUI manager for the Anti-DPI detector."""
from __future__ import annotations

import ipaddress
from datetime import datetime

import hydra.core.orchestrator as orchestrator
from hydra.core.host import HOST
from hydra.core.state import AppState
from hydra.plugins.antidpi.plugin import _lock_state_file, active_bans, ban_duration, expire_bans
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


def _get_signals_list(metadata: object) -> list[str]:
    if not isinstance(metadata, dict):
        return []
    val = metadata.get("signals", [])
    if isinstance(val, list):
        return [str(x) for x in val if x]
    if isinstance(val, str) and val:
        return [x.strip() for x in val.split(",") if x.strip()]
    return []


def _format_dur(sec: float | int) -> str:
    s = int(sec)
    if s < 60:
        return f"{s}с"
    if s < 3600:
        return f"{s // 60}м"
    if s < 86400:
        return f"{s // 3600}ч"
    return f"{s // 86400}д"


def _format_signal_lines(signals: list[str], max_len: int = 45) -> list[str]:
    if not signals:
        return ["Сигналы: —"]
    lines = []
    curr = "Сигналы: "
    for i, s in enumerate(signals):
        item = s + (", " if i < len(signals) - 1 else "")
        if len(curr) + len(item) > max_len:
            lines.append(curr)
            curr = "         " + item
        else:
            curr += item
    if curr.strip():
        lines.append(curr)
    return lines


def _ban_history(plugin) -> None:
    import time
    with _lock_state_file():
        data = plugin._load_state()
        if expire_bans(data):
            plugin._save_state(data)
    banned = active_bans(data)
    history = data.get("history", []) if isinstance(data.get("history"), list) else []
    now = time.time()
    clear()
    lines = []

    if banned:
        lines.append(f"{RED}─── АКТИВНЫЕ БАНЫ ({len(banned)}) ───{DIM}")
        for ip, meta in reversed(list(banned.items())):
            if not isinstance(meta, dict):
                meta = {}
            score = meta.get("score", 0.0)
            at = meta.get("at", 0)
            duration = ban_duration(meta)
            offense = meta.get("offense_count", 1)
            sig_list = _get_signals_list(meta)
            rem = duration - (now - at)
            if rem > 0:
                rem_str = f"осталось {_format_dur(rem)}"
                icon = "🔴"
            else:
                rem_str = "истёк"
                icon = "🟡"
            dur_str = _format_dur(duration)

            lines.append(
                f"  {icon} {CYAN}{ip:<15}{DIM} | Score: {RED}{score:.1f}{DIM} | "
                f"Срок: {GREEN}{dur_str}{DIM} ({rem_str}) | #{offense}"
            )
            lines.append(f"     {DIM}Время бана: {_time(at)}")
            for sig_line in _format_signal_lines(sig_list):
                lines.append(f"     {DIM}{sig_line.strip()}")
            lines.append("")

    if history:
        lines.append(f"{CYAN}─── ИСТОРИЯ ПОСЛЕДНИХ СОБЫТИЙ ───{DIM}")
        shown = 0
        for item in reversed(history[-30:]):
            if not isinstance(item, dict):
                continue
            ip = item.get("ip", "?")
            if ip in banned:
                continue
            status_raw = item.get("status", "active")
            if status_raw == "active":
                st_color, st_text = RED, "АКТИВЕН"
            elif status_raw == "expired":
                st_color, st_text = DIM, "ИСТЁК"
            else:
                st_color, st_text = GREEN, "СНЯТ"
            score = item.get("score", 0.0)
            at = item.get("at", 0)
            sig_list = _get_signals_list(item)

            lines.append(
                f"  ⚪ {CYAN}{ip:<15}{DIM} | Score: {score:.1f} | Статус: {st_color}{st_text}{DIM} | Время: {_time(at)}"
            )
            for sig_line in _format_signal_lines(sig_list):
                lines.append(f"     {DIM}{sig_line.strip()}")
            lines.append("")
            shown += 1
            if shown >= 10:
                break

    if not lines:
        lines = ["  История банов пока пуста."]

    panel(f"ИСТОРИЯ И СТАТУС БАНОВ — АКТИВНЫХ: {len(banned)}", lines)
    if banned:
        raw = prompt("IP для разбана (или Enter для возврата)").strip()
        if raw:
            if plugin.unban(raw):
                success(f"Бан с IP {raw} успешно снят")
            else:
                warn(f"Не удалось снять бан с {raw} (не найден в бане)")
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
            with _lock_state_file():
                data = plugin._load_state()
                values = data.get("whitelist", []) if isinstance(data.get("whitelist"), list) else []
                if network not in values:
                    values.append(network)
                    data["whitelist"] = values
                    plugin._save_state(data)
            success("Добавлено в whitelist")
        elif choice == "2":
            with _lock_state_file():
                data = plugin._load_state()
                values = data.get("whitelist", []) if isinstance(data.get("whitelist"), list) else []
                found = network in values
                if found:
                    values.remove(network)
                    data["whitelist"] = values
                    plugin._save_state(data)
            if found:
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
        banned = active_bans(data)
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
