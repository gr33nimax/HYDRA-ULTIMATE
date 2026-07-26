"""Reusable log and journal viewing primitives for TUI menus."""
from __future__ import annotations

from datetime import datetime
from typing import Callable

from hydra.services.logs import LogOperations
from hydra.services.system_monitoring_compatibility import (
    legacy_system_monitoring,
)
from hydra.ui.tui import DIM, NC, PANEL_W, clear, error, menu, prompt, title, warn


def read_source(
    logs: LogOperations,
    source_type: str,
    source: str,
    num_lines: int,
) -> tuple[list[str], str]:
    result = logs.read(source_type, source, num_lines)
    return list(result.lines), result.message


def source_status(
    logs: LogOperations,
    source_type: str,
    source: str,
    *,
    bytes_auto: Callable[[int], str],
) -> str:
    info = logs.source_info(source_type, source)
    if source_type == "file":
        if not info.available:
            return "ещё не создан"
        if info.size_bytes is None:
            return "недоступен"
        return bytes_auto(info.size_bytes)
    if info.active:
        return "активно"
    return "остановлено" if info.loaded else "не установлено"


def sync_snapshot(
    logs: LogOperations,
    log_path: str,
    now_timestamp: float | None = None,
) -> tuple[str, str, bool]:
    lines, message = read_source(logs, "file", log_path, 5)
    last_line = next((line for line in reversed(lines) if line.strip()), "")
    if not last_line:
        return message or "нет логов", "нет данных", True

    source_info = logs.source_info("file", log_path)
    if source_info.modified_at is None:
        return last_line, "время неизвестно", True
    current = datetime.now().timestamp() if now_timestamp is None else now_timestamp
    age_seconds = max(0, int(current - source_info.modified_at))

    if age_seconds < 60:
        freshness = "только что"
    elif age_seconds < 3600:
        freshness = f"{age_seconds // 60} мин назад"
    elif age_seconds < 86400:
        freshness = f"{age_seconds // 3600} ч назад"
    else:
        freshness = f"{age_seconds // 86400} дн назад"
    return last_line, freshness, age_seconds > 600


def show_source(
    title_text: str,
    source_type: str,
    source: str,
    num_lines: int,
    *,
    logs: LogOperations,
    enter_pressed: Callable[[], bool],
    sleep: Callable[[float], None] | None = None,
) -> None:
    source_label = source if source_type == "file" else f"journalctl -u {source}"
    while True:
        clear()
        title(f"{title_text} ({num_lines} строк)")
        print(f"  {DIM}Источник: {source_label}{NC}\n")

        lines, message = read_source(logs, source_type, source, num_lines)
        for line in lines:
            print(f"  {DIM}{line}{NC}")
        if message:
            warn(message)
        print()

        choice = menu(
            [
                ("R", "🔄 Обновить", ""),
                ("W", "👀 Следить в реальном времени", ""),
                ("0", "↩ Назад", ""),
            ],
            "ПРОСМОТР ЛОГА",
        )
        if choice == "0":
            return
        if choice.upper() == "W":
            if source_type == "file":
                watch_file(title_text, source, logs, enter_pressed)
            else:
                watch_journal(
                    title_text,
                    source,
                    logs,
                    enter_pressed,
                    sleep=sleep,
                )


def show_file(
    title_text: str,
    path_str: str,
    num_lines: int,
    *,
    logs: LogOperations,
    enter_pressed: Callable[[], bool],
    sleep: Callable[[float], None] | None = None,
) -> None:
    show_source(
        title_text,
        "file",
        path_str,
        num_lines,
        logs=logs,
        enter_pressed=enter_pressed,
        sleep=sleep,
    )


def watch_file(
    title_text: str,
    path_str: str,
    logs: LogOperations,
    enter_pressed: Callable[[], bool],
) -> None:
    clear()
    title(f"👀 Слежение: {title_text}")
    print(f"  {DIM}Файл: {path_str}{NC}")
    print(f"  {DIM}Нажмите [Enter] для выхода из режима слежения.{NC}")
    print(f"  {DIM}{'─' * PANEL_W}{NC}\n")

    if not logs.source_info("file", path_str).available:
        error("Файл лога не найден.")
        prompt("Нажмите Enter")
        return

    try:
        stream = logs.open_stream("file", path_str)
    except OSError as exc:
        error(f"Не удалось следить за файлом: {exc}")
        prompt("Нажмите Enter")
        return

    try:
        while stream.running():
            if enter_pressed():
                return
            if line := stream.read_line():
                print(f"  {DIM}{line}{NC}")
    except KeyboardInterrupt:
        return
    finally:
        stream.close()


def watch_journal(
    title_text: str,
    unit: str,
    logs: LogOperations,
    enter_pressed: Callable[[], bool],
    *,
    sleep: Callable[[float], None] | None = None,
) -> None:
    clear()
    title(f"👀 Слежение: {title_text}")
    print(f"  {DIM}Источник: journalctl -u {unit}{NC}")
    print(f"  {DIM}Нажмите [Enter] для выхода из режима слежения.{NC}")
    print(f"  {DIM}{'─' * PANEL_W}{NC}\n")

    try:
        stream = logs.open_stream("journal", unit)
    except OSError as exc:
        error(f"Не удалось запустить journalctl: {exc}")
        prompt("Нажмите Enter")
        return

    try:
        while stream.running():
            if enter_pressed():
                break
            if line := stream.read_line():
                print(f"  {DIM}{line}{NC}")
        if not stream.running():
            warn("journalctl завершил работу.")
            (sleep or legacy_system_monitoring().sleep)(1)
    except KeyboardInterrupt:
        pass
    finally:
        stream.close()
