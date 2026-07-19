"""Reusable log and journal viewing primitives for TUI menus."""
from __future__ import annotations

import select
import subprocess
import time
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Callable

from hydra.ui.tui import DIM, NC, PANEL_W, clear, error, menu, prompt, title, warn


def unit_known(unit: str) -> bool:
    try:
        result = subprocess.run(
            ["systemctl", "show", "--property=LoadState", "--value", unit],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.returncode == 0 and result.stdout.strip() == "loaded"
    except (OSError, subprocess.TimeoutExpired):
        return False


def read_source(source_type: str, source: str, num_lines: int) -> tuple[list[str], str]:
    if source_type == "file":
        path = Path(source)
        if not path.exists():
            return [], "Файл ещё не создан."
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                return [line.rstrip("\n") for line in deque(handle, maxlen=num_lines)], ""
        except OSError as exc:
            return [], f"Ошибка чтения файла: {exc}"

    try:
        result = subprocess.run(
            [
                "journalctl",
                "-u",
                source,
                "-n",
                str(num_lines),
                "--no-pager",
                "-o",
                "short-iso",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [], f"Не удалось прочитать journalctl: {exc}"

    output = (result.stdout or "").strip()
    if result.returncode != 0:
        return [], (result.stderr or output or "journalctl завершился с ошибкой").strip()
    lines = [
        line
        for line in output.splitlines()
        if line.strip() and line.strip() != "-- No entries --"
    ]
    return lines, "" if lines else "В журнале пока нет записей."


def source_status(
    source_type: str,
    source: str,
    *,
    unit_active: Callable[[str], bool],
    bytes_auto: Callable[[int], str],
) -> str:
    if source_type == "file":
        path = Path(source)
        if not path.exists():
            return "ещё не создан"
        try:
            return bytes_auto(path.stat().st_size)
        except OSError:
            return "недоступен"
    if unit_active(source):
        return "активно"
    return "остановлено" if unit_known(source) else "не установлено"


def sync_snapshot(
    log_path: Path,
    now_timestamp: float | None = None,
) -> tuple[str, str, bool]:
    lines, message = read_source("file", str(log_path), 5)
    last_line = next((line for line in reversed(lines) if line.strip()), "")
    if not last_line:
        return message or "нет логов", "нет данных", True

    try:
        current = datetime.now().timestamp() if now_timestamp is None else now_timestamp
        age_seconds = max(0, int(current - log_path.stat().st_mtime))
    except OSError:
        return last_line, "время неизвестно", True

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
    enter_pressed: Callable[[], bool],
) -> None:
    source_label = source if source_type == "file" else f"journalctl -u {source}"
    while True:
        clear()
        title(f"{title_text} ({num_lines} строк)")
        print(f"  {DIM}Источник: {source_label}{NC}\n")

        lines, message = read_source(source_type, source, num_lines)
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
                watch_file(title_text, source, enter_pressed)
            else:
                watch_journal(title_text, source, enter_pressed)


def show_file(
    title_text: str,
    path_str: str,
    num_lines: int,
    *,
    enter_pressed: Callable[[], bool],
) -> None:
    show_source(
        title_text,
        "file",
        path_str,
        num_lines,
        enter_pressed=enter_pressed,
    )


def watch_file(
    title_text: str,
    path_str: str,
    enter_pressed: Callable[[], bool],
) -> None:
    path = Path(path_str)
    clear()
    title(f"👀 Слежение: {title_text}")
    print(f"  {DIM}Файл: {path_str}{NC}")
    print(f"  {DIM}Нажмите [Enter] для выхода из режима слежения.{NC}")
    print(f"  {DIM}{'─' * PANEL_W}{NC}\n")

    if not path.exists():
        error("Файл лога не найден.")
        prompt("Нажмите Enter")
        return

    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            handle.seek(0, 2)
            while True:
                if enter_pressed():
                    return
                line = handle.readline()
                if line:
                    print(f"  {DIM}{line.strip()}{NC}")
                else:
                    time.sleep(0.5)
    except KeyboardInterrupt:
        return


def watch_journal(
    title_text: str,
    unit: str,
    enter_pressed: Callable[[], bool],
) -> None:
    clear()
    title(f"👀 Слежение: {title_text}")
    print(f"  {DIM}Источник: journalctl -u {unit}{NC}")
    print(f"  {DIM}Нажмите [Enter] для выхода из режима слежения.{NC}")
    print(f"  {DIM}{'─' * PANEL_W}{NC}\n")

    try:
        process = subprocess.Popen(
            [
                "journalctl",
                "-u",
                unit,
                "-f",
                "-n",
                "0",
                "--no-pager",
                "-o",
                "short-iso",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except OSError as exc:
        error(f"Не удалось запустить journalctl: {exc}")
        prompt("Нажмите Enter")
        return

    try:
        while True:
            if enter_pressed():
                break
            if process.stdout is not None:
                ready, _, _ = select.select([process.stdout], [], [], 0.25)
                if ready:
                    line = process.stdout.readline()
                    if line:
                        print(f"  {DIM}{line.rstrip()}{NC}")
                        continue
            if process.poll() is not None:
                warn("journalctl завершил работу.")
                time.sleep(1)
                break
    except KeyboardInterrupt:
        pass
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
