"""
hydra/ui/tui.py — Текстовый UI-фреймворк.

Минимальный набор для отрисовки меню: цвета, рамки, заголовки.
"""
from __future__ import annotations

import os
import sys
import shutil
from typing import Optional

# ═════════════════════════════════════════════════════════════════════════════
#  Цвета
# ═════════════════════════════════════════════════════════════════════════════

def _detect_colors() -> dict:
    if not sys.stdout.isatty():
        return {k: "" for k in ("RED", "GREEN", "YELLOW", "CYAN", "BLUE", "BOLD", "DIM", "WHITE", "NC")}

    light = os.environ.get("HYDRA_THEME", "").lower() == "light"
    if light:
        return {
            "RED": "\033[0;31m", "GREEN": "\033[0;32m", "YELLOW": "\033[0;33m",
            "CYAN": "\033[0;34m", "BLUE": "\033[0;35m", "BOLD": "\033[1m",
            "DIM": "\033[2m", "WHITE": "\033[0;30m", "NC": "\033[0m",
        }
    return {
        "RED": "\033[0;31m", "GREEN": "\033[0;32m", "YELLOW": "\033[1;33m",
        "CYAN": "\033[0;36m", "BLUE": "\033[0;34m", "BOLD": "\033[1m",
        "DIM": "\033[2m", "WHITE": "\033[1;37m", "NC": "\033[0m",
    }

C = _detect_colors()
RED = C["RED"]; GREEN = C["GREEN"]; YELLOW = C["YELLOW"]; CYAN = C["CYAN"]
BLUE = C["BLUE"]; BOLD = C["BOLD"]; DIM = C["DIM"]; WHITE = C["WHITE"]; NC = C["NC"]

TERM_WIDTH = shutil.get_terminal_size().columns


# ═════════════════════════════════════════════════════════════════════════════
#  Баннер
# ═════════════════════════════════════════════════════════════════════════════

BANNER = rf"""
{GREEN}        ██╗  ██╗██╗   ██╗██████╗ ██████╗  █████╗
        ██║  ██║╚██╗ ██╔╝██╔══██╗██╔══██╗██╔══██╗
        ███████║ ╚████╔╝ ██║  ██║██████╔╝███████║
        ██╔══██║  ╚██╔╝  ██║  ██║██╔══██╗██╔══██║
        ██║  ██║   ██║   ██████╔╝██║  ██║██║  ██║
        ╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝{NC}
{GREEN}              🐉 Multi-Protocol Proxy Manager v1.0{NC}
"""


# ═════════════════════════════════════════════════════════════════════════════
#  Функции отрисовки
# ═════════════════════════════════════════════════════════════════════════════

def clear():
    os.system("clear" if os.name != "nt" else "cls")


def title(text: str):
    print(f"{BOLD}{CYAN}{text}{NC}")


def info(msg: str):
    print(f"{CYAN}[INFO]{NC}  {msg}")


def success(msg: str):
    print(f"{GREEN}[OK]{NC}    {msg}")


def warn(msg: str):
    print(f"{YELLOW}[WARN]{NC}  {msg}")


def error(msg: str):
    print(f"{RED}[ERR]{NC}   {msg}")


def box(content: str, header: str = ""):
    """Рисует рамку вокруг текста."""
    width = min(TERM_WIDTH - 4, 72)
    top = f"╭{'─' * (width - 2)}╮"
    bot = f"╰{'─' * (width - 2)}╯"

    print(f"{CYAN}{top}{NC}")
    if header:
        print(f"{CYAN}│{NC} {BOLD}{header}{NC}")
        print(f"{CYAN}│{NC} {'─' * (width - 4)}")
    for line in content.split("\n"):
        print(f"{CYAN}│{NC} {line}")
    print(f"{CYAN}{bot}{NC}")


def menu(options: list[tuple[str, str, str]], header: str = "") -> str:
    """
    Отображает меню и возвращает выбор пользователя.

    options: список (ключ, метка, описание)
    header: заголовок меню
    """
    print()
    if header:
        title(f"  {header}")
        print()

    for key, label, desc in options:
        if key == "0":
            print(f"  {DIM}[{NC}{BOLD}0{NC}{DIM}]{NC}  {label}")
        elif key == "-":
            print(f"  {DIM}────────────────────────────────{NC}")
        else:
            print(f"  {CYAN}{key}{NC}  {label}")
            if desc:
                print(f"     {DIM}{desc}{NC}")

    print()
    try:
        choice = input(f"{CYAN}Выбор (0–{len(options)-1}):{NC} ").strip()
    except (KeyboardInterrupt, EOFError):
        return "0"
    return choice


def prompt(text: str, default: str = "") -> str:
    """Запрашивает ввод у пользователя."""
    d = f" [{default}]" if default else ""
    try:
        result = input(f"{CYAN}{text}{d}:{NC} ").strip()
        return result or default
    except (KeyboardInterrupt, EOFError):
        return default
