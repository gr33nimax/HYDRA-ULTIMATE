"""
hydra/ui/tui.py — Текстовый UI-фреймворк.

Минимальный набор для отрисовки меню: цвета, рамки, заголовки, панели.
"""
from __future__ import annotations

import os
import re
import sys
import shutil
from typing import Optional

# ═════════════════════════════════════════════════════════════════════════════
#  Цвета
# ═════════════════════════════════════════════════════════════════════════════

def _detect_colors() -> dict:
    keys = ("RED", "GREEN", "YELLOW", "CYAN", "BLUE", "MAGENTA",
            "BOLD", "DIM", "WHITE", "NC")
    if not sys.stdout.isatty():
        return {k: "" for k in keys}

    light = os.environ.get("HYDRA_THEME", "").lower() == "light"
    if light:
        return {
            "RED": "\033[0;31m", "GREEN": "\033[0;32m", "YELLOW": "\033[0;33m",
            "CYAN": "\033[0;34m", "BLUE": "\033[0;35m", "MAGENTA": "\033[0;35m",
            "BOLD": "\033[1m", "DIM": "\033[2m", "WHITE": "\033[0;30m", "NC": "\033[0m",
        }
    return {
        "RED": "\033[0;31m", "GREEN": "\033[0;32m", "YELLOW": "\033[1;33m",
        "CYAN": "\033[0;36m", "BLUE": "\033[0;34m", "MAGENTA": "\033[0;35m",
        "BOLD": "\033[1m", "DIM": "\033[2m", "WHITE": "\033[1;37m", "NC": "\033[0m",
    }

C = _detect_colors()
RED = C["RED"]; GREEN = C["GREEN"]; YELLOW = C["YELLOW"]; CYAN = C["CYAN"]
BLUE = C["BLUE"]; MAGENTA = C["MAGENTA"]; BOLD = C["BOLD"]; DIM = C["DIM"]
WHITE = C["WHITE"]; NC = C["NC"]

TERM_WIDTH = shutil.get_terminal_size().columns
PANEL_W = min(TERM_WIDTH - 4, 62)
INDENT = "  "


def _strip(s: str) -> str:
    return re.sub(r"\033\[[0-9;]*m", "", s)


# ═════════════════════════════════════════════════════════════════════════════
#  Баннер
# ═════════════════════════════════════════════════════════════════════════════

BANNER = rf"""
{CYAN}        ██╗  ██╗{GREEN}██╗   ██╗{CYAN}██████╗ {GREEN}██████╗ {CYAN} █████╗
        ██║  ██║{GREEN}╚██╗ ██╔╝{CYAN}██╔══██╗{GREEN}██╔══██╗{CYAN}██╔══██╗
        ███████║{GREEN} ╚████╔╝ {CYAN}██║  ██║{GREEN}██████╔╝{CYAN}███████║
        ██╔══██║{GREEN}  ╚██╔╝  {CYAN}██║  ██║{GREEN}██╔══██╗{CYAN}██╔══██║
        ██║  ██║{GREEN}   ██║   {CYAN}██████╔╝{GREEN}██║  ██║{CYAN}██║  ██║
        ╚═╝  ╚═╝{GREEN}   ╚═╝   {CYAN}╚═════╝ {GREEN}╚═╝  ╚═╝{CYAN}╚═╝  ╚═╝{NC}
{DIM}        ─────────────────────────────────────────────────{NC}
{MAGENTA}              🐉  Multi-Protocol Proxy Manager{NC}
{DIM}                         v1.0{NC}
"""


# ═════════════════════════════════════════════════════════════════════════════
#  Базовые функции
# ═════════════════════════════════════════════════════════════════════════════

def clear():
    os.system("clear" if os.name != "nt" else "cls")


def divider(char: str = "─", width: Optional[int] = None):
    w = width or PANEL_W
    print(f"{INDENT}{DIM}{char * w}{NC}")


def title(text: str):
    print(f"\n{INDENT}{BOLD}{CYAN}▸ {text}{NC}")


def kv(label: str, value: str, label_w: int = 16) -> str:
    """Строка «ключ — значение» для панелей."""
    return f"  {DIM}{label:<{label_w}}{NC} {value}"


def panel(title_text: str, lines: list[str]):
    """Панель состояния с заголовком и списком строк."""
    plain_title = _strip(title_text)
    tail = max(PANEL_W - len(plain_title) - 5, 8)
    print()
    print(f"{INDENT}{CYAN}┌─ {BOLD}{WHITE}{title_text}{NC}{CYAN} {'─' * tail}{NC}")
    for line in lines:
        print(f"{INDENT}{CYAN}│{NC}{line}")
    print(f"{INDENT}{CYAN}└{'─' * PANEL_W}{NC}")


def box(content: str, header: str = ""):
    """Рисует рамку вокруг текста."""
    width = min(TERM_WIDTH - 4, 72)
    inner = width - 2
    print(f"{INDENT}{CYAN}╭{'─' * inner}╮{NC}")
    if header:
        h_pad = inner - len(_strip(header)) - 2
        print(f"{INDENT}{CYAN}│{NC} {BOLD}{header}{NC}{' ' * max(h_pad, 0)}{CYAN}│{NC}")
        print(f"{INDENT}{CYAN}├{'─' * inner}┤{NC}")
    for line in content.split("\n"):
        pad = inner - len(_strip(line)) - 2
        print(f"{INDENT}{CYAN}│{NC} {line}{' ' * max(pad, 0)}{CYAN}│{NC}")
    print(f"{INDENT}{CYAN}╰{'─' * inner}╯{NC}")


# ═════════════════════════════════════════════════════════════════════════════
#  Сообщения
# ═════════════════════════════════════════════════════════════════════════════

def info(msg: str):
    print(f"{INDENT}{CYAN}●{NC} {DIM}INFO{NC}  {msg}")


def success(msg: str):
    print(f"{INDENT}{GREEN}✓{NC} {GREEN}{BOLD}OK{NC}    {msg}")


def warn(msg: str):
    print(f"{INDENT}{YELLOW}⚠{NC} {YELLOW}WARN{NC}  {msg}")


def error(msg: str):
    print(f"{INDENT}{RED}✗{NC} {RED}{BOLD}ERR{NC}   {msg}")


# ═════════════════════════════════════════════════════════════════════════════
#  Меню и ввод
# ═════════════════════════════════════════════════════════════════════════════

def _menu_key(key: str) -> str:
    if key in ("0", "Q", "q"):
        return f"{DIM}[{NC}{RED}{BOLD}{key}{NC}{DIM}]{NC}"
    if key == "-":
        return ""
    return f"{DIM}[{NC}{CYAN}{BOLD}{key}{NC}{DIM}]{NC}"


def menu(options: list[tuple[str, str, str]], header: str = "") -> str:
    """
    Отображает меню и возвращает выбор пользователя.

    options: список (ключ, метка, описание)
    header: заголовок меню
    """
    print()
    print(f"{INDENT}{CYAN}╭{'─' * PANEL_W}╮{NC}")

    if header:
        h = f" {header} "
        h_pad = PANEL_W - len(_strip(h))
        print(f"{INDENT}{CYAN}│{NC}{BOLD}{WHITE}{h}{NC}{' ' * max(h_pad, 0)}{CYAN}│{NC}")
        print(f"{INDENT}{CYAN}├{'─' * PANEL_W}┤{NC}")

    for key, label, desc in options:
        if key == "-":
            print(f"{INDENT}{CYAN}│{NC}{DIM}{'─' * PANEL_W}{NC}{CYAN}│{NC}")
            continue
        key_col = _menu_key(key)
        line = f"  {key_col}  {label}"
        pad = PANEL_W - len(_strip(line))
        print(f"{INDENT}{CYAN}│{NC}{line}{' ' * max(pad, 0)}{CYAN}│{NC}")
        if desc:
            dline = f"       {DIM}{desc}{NC}"
            dpad = PANEL_W - len(_strip(desc)) - 7
            print(f"{INDENT}{CYAN}│{NC}{dline}{' ' * max(dpad, 0)}{CYAN}│{NC}")

    print(f"{INDENT}{CYAN}╰{'─' * PANEL_W}╯{NC}")
    print()

    keys = [k for k, _, _ in options if k not in ("-", "")]
    hint = "0" if "0" in keys else keys[-1] if keys else "0"
    try:
        choice = input(f"{INDENT}{CYAN}▸{NC} {BOLD}Выбор{NC}{DIM} ({hint}):{NC} ").strip()
    except (KeyboardInterrupt, EOFError):
        return "0"
    return choice


def prompt(text: str, default: str = "") -> str:
    """Запрашивает ввод у пользователя."""
    d = f" {DIM}[{default}]{NC}" if default else ""
    try:
        result = input(f"{INDENT}{CYAN}▸{NC} {BOLD}{text}{NC}{d}{CYAN} ›{NC} ").strip()
        return result or default
    except (KeyboardInterrupt, EOFError):
        return default
