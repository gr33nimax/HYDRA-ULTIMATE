"""
hydra/ui/tui.py — Текстовый UI-фреймворк.

Цвета, рамки, заголовки, панели, утилиты ввода.
"""

from __future__ import annotations

import math
import os
import re
import sys
import shutil
from typing import Optional
from hydra import __version__
from hydra.build_info import get_build_info

try:
    import readline
except ImportError:
    pass

# ═════════════════════════════════════════════════════════════════════════════
#  Цвета
# ═════════════════════════════════════════════════════════════════════════════


def _detect_colors() -> dict:
    keys = ("RED", "GREEN", "YELLOW", "CYAN", "BLUE", "MAGENTA", "BOLD", "DIM", "WHITE", "NC")
    if not sys.stdout.isatty():
        return {k: "" for k in keys}

    light = os.environ.get("HYDRA_THEME", "").lower() == "light"
    if light:
        return {
            "RED": "\033[0;31m",
            "GREEN": "\033[0;32m",
            "YELLOW": "\033[0;33m",
            "CYAN": "\033[0;34m",
            "BLUE": "\033[0;35m",
            "MAGENTA": "\033[0;35m",
            "BOLD": "\033[1m",
            "DIM": "\033[2m",
            "WHITE": "\033[0;30m",
            "NC": "\033[0m",
        }
    return {
        "RED": "\033[0;31m",
        "GREEN": "\033[0;32m",
        "YELLOW": "\033[1;33m",
        "CYAN": "\033[0;36m",
        "BLUE": "\033[0;34m",
        "MAGENTA": "\033[0;35m",
        "BOLD": "\033[1m",
        "DIM": "\033[2m",
        "WHITE": "\033[1;37m",
        "NC": "\033[0m",
    }


C = _detect_colors()
RED = C["RED"]
GREEN = C["GREEN"]
YELLOW = C["YELLOW"]
CYAN = C["CYAN"]
BLUE = C["BLUE"]
MAGENTA = C["MAGENTA"]
BOLD = C["BOLD"]
DIM = C["DIM"]
WHITE = C["WHITE"]
NC = C["NC"]

TERM_WIDTH = shutil.get_terminal_size().columns
PANEL_W = min(TERM_WIDTH - 4, 78)
INDENT = "  "


def enter_pressed() -> bool:
    """Poll Enter without blocking; terminal access is owned by this adapter."""

    if os.name == "nt":
        import msvcrt

        if not msvcrt.kbhit():
            return False
        return msvcrt.getch() in (b"\r", b"\n")

    import select

    readable, _, _ = select.select([sys.stdin], [], [], 0.0)
    if sys.stdin not in readable:
        return False
    sys.stdin.readline()
    return True


def _strip(s: str) -> str:
    return re.sub(r"\033\[[0-9;]*m", "", s)


def _char_width(char: str) -> int:
    code = ord(char)
    if code == 0xFE0F:
        return 0
    # Common 2-cell emojis in standard BMP
    if code in {
        0x274C,  # ❌
        0x2705,  # ✅
        0x26A1,  # ⚡
        0x1F4CA,  # 📊
        0x1F310,  # 🌐
    }:
        return 2
    # Special cases: emojis that are rendered as 1 cell wide in standard monospace fonts/terminals
    if code in (0x1F6E1, 0x1F6E0, 0x1F576):  # 🛡, 🛠 and 🕶
        return 1
    # Emojis > 0xffff are always 2 cells wide
    if code > 0xFFFF:
        return 2
    # CJK characters
    if 0x4E00 <= code <= 0x9FFF or 0x3000 <= code <= 0x303F or 0xFF00 <= code <= 0xFFEF:
        return 2
    return 1


def _width(s: str) -> int:
    """Возвращает визуальную ширину строки в терминале с учетом эмодзи."""
    plain = _strip(s)
    w = 0
    flags_count = 0
    for char in plain:
        code = ord(char)
        if 0x1F1E6 <= code <= 0x1F1FF:
            flags_count += 1
        w += _char_width(char)

    # Каждая пара региональных индикаторов представляет собой один флаг (2 ячейки).
    # Без корректировки 2 символа давали бы 2 + 2 = 4 ячейки. Вычитаем разницу.
    w -= (flags_count // 2) * 2
    return w


def visible_width(text: str) -> int:
    """Return the terminal width of a string, ignoring colour escapes."""
    return _width(text)


def _fit_line(line: str, max_w: int) -> tuple[str, int]:
    """Ограничивает визуальную ширину строки до max_w, обрезая её при необходимости."""
    line_w = _width(line)
    if line_w <= max_w:
        return line, line_w

    parts = re.split(r"(\033\[[0-9;]*m)", line)
    new_parts = []
    accum_w = 0
    target_w = max_w - 3

    for part in parts:
        if not part:
            continue
        if part.startswith("\033["):
            new_parts.append(part)
        else:
            for char in part:
                if ord(char) == 0xFE0F:
                    new_parts.append(char)
                    continue
                char_w = _char_width(char)
                if accum_w + char_w > target_w:
                    new_parts.append("...")
                    accum_w += 3
                    break
                new_parts.append(char)
                accum_w += char_w
            if accum_w >= target_w:
                break
    new_parts.append("\033[0m")
    return "".join(new_parts), accum_w


def _wrap_line(line: str, max_w: int) -> list[tuple[str, int]]:
    """Split an ANSI-coloured line without dropping visible characters."""
    if max_w < 1:
        raise ValueError("max_w must be positive")
    line_w = _width(line)
    if line_w <= max_w:
        return [(line, line_w)]

    wrapped: list[tuple[str, int]] = []
    current: list[str] = []
    current_w = 0
    active_sgr: list[str] = []
    for part in re.split(r"(\033\[[0-9;]*m)", line):
        if not part:
            continue
        if part.startswith("\033["):
            current.append(part)
            codes = part[2:-1].split(";")
            if not codes or "0" in codes or "" in codes:
                active_sgr.clear()
            if any(code not in {"", "0"} for code in codes):
                active_sgr.append(part)
            continue
        for char in part:
            char_w = _char_width(char)
            if current_w and current_w + char_w > max_w:
                if active_sgr:
                    current.append("\033[0m")
                wrapped.append(("".join(current), current_w))
                current = list(active_sgr)
                current_w = 0
            current.append(char)
            current_w += char_w
    if current or not wrapped:
        wrapped.append(("".join(current), current_w))
    return wrapped


def _frame_top(title_text: str = "") -> str:
    if not title_text:
        return f"{INDENT}{CYAN}╭{'─' * PANEL_W}╮{NC}"
    title_fit, title_w = _fit_line(title_text, PANEL_W - 3)
    return f"{INDENT}{CYAN}╭─ {BOLD}{WHITE}{title_fit}{NC}{CYAN} {'─' * (PANEL_W - title_w - 3)}╮{NC}"


def _frame_row(line: str, *, wrap: bool = False) -> list[str]:
    width = PANEL_W - 2
    fitted = _wrap_line(line, width) if wrap else [_fit_line(line, width)]
    return [f"{INDENT}{CYAN}│{NC} {value}{' ' * (width - line_w)} {CYAN}│{NC}" for value, line_w in fitted]


def _frame_rule() -> str:
    return f"{INDENT}{CYAN}├{'─' * PANEL_W}┤{NC}"


def _frame_bottom() -> str:
    return f"{INDENT}{CYAN}╰{'─' * PANEL_W}╯{NC}"


# ═════════════════════════════════════════════════════════════════════════════
#  Баннер
# ═════════════════════════════════════════════════════════════════════════════

_build_info = get_build_info()
_build_identity = _build_info.channel
if _build_info.revision:
    _build_identity += f" · {_build_info.revision[:7]}"
_banner_left = f"{BOLD}{CYAN}HYDRA{NC} {DIM}v{__version__} · {_build_identity}{NC}"
_banner_right = f"{MAGENTA}{BOLD}ULTIMATE{NC}"
_banner_gap = max(1, PANEL_W - _width(_banner_left) - _width(_banner_right) - 2)
BANNER = "\n".join(
    (
        "",
        _frame_top(),
        f"{INDENT}{CYAN}│{NC} {_banner_left}{' ' * _banner_gap}{_banner_right} {CYAN}│{NC}",
        _frame_row(f"{DIM}Multi-Protocol Proxy Manager{NC}")[0],
        _frame_bottom(),
    ),
)


# ═════════════════════════════════════════════════════════════════════════════
#  Базовые функции
# ═════════════════════════════════════════════════════════════════════════════


def clear():
    print("\033[2J\033[H", end="", flush=True)


def divider(char: str = "═", width: Optional[int] = None):
    w = width or PANEL_W
    print(f"{INDENT}{DIM}{char * w}{NC}")


def title(text: str):
    print(f"\n{INDENT}{BOLD}{CYAN}▸ {text}{NC}")


def kv(label: str, value: str, label_w: int = 16) -> str:
    """Строка «ключ — значение» для панелей."""
    return f"  {DIM}{label:<{label_w}}{NC} {value}"


def panel(title_text: str, lines: list[str], *, wrap: bool = False):
    """Компактная панель состояния в тонкой рамке."""
    print()
    print(_frame_top(title_text))
    for line in lines:
        plain_line = _strip(line).strip()
        if plain_line and all(c in "─-" for c in plain_line):
            print(_frame_rule())
            continue
        print(*_frame_row(line, wrap=wrap), sep="\n")
    print(_frame_bottom())


def box(content: str, header: str = ""):
    """Рисует компактную рамку вокруг текста."""
    print(_frame_top(header))
    for line in content.split("\n"):
        plain_line = _strip(line).strip()
        if plain_line and all(c in "─-" for c in plain_line):
            print(_frame_rule())
        else:
            print(*_frame_row(line), sep="\n")
    print(_frame_bottom())


# ═════════════════════════════════════════════════════════════════════════════
#  Сообщения
# ═════════════════════════════════════════════════════════════════════════════


def info(msg: str):
    print(f"{INDENT}{CYAN}●{NC} {msg}")


def success(msg: str):
    print(f"{INDENT}{GREEN}✓{NC} {msg}")


def warn(msg: str):
    print(f"{INDENT}{YELLOW}⚠{NC} {msg}")


def error(msg: str):
    print(f"{INDENT}{RED}✗{NC} {msg}")


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
    """Отображает компактное меню в тонкой рамке.

    Третий элемент кортежа — краткое описание; если оно есть, показываем его тусклой
    строкой под пунктом — оператору не надо угадывать, что делает пункт.
    """
    print()
    print(_frame_top(header))

    for key, label, desc in options:
        if key == "-":
            print(_frame_rule())
            continue
        key_col = _menu_key(key)
        print(*_frame_row(f"{key_col}  {label}"), sep="\n")
        text = str(desc or "").strip()
        if text:
            # Выравниваем под label: ключ «[X]» = 3 символа + 2 пробела.
            print(*_frame_row(f"     {DIM}{text}{NC}"), sep="\n")
    print(_frame_bottom())
    print()

    keys = [k for k, _, _ in options if k not in ("-", "")]
    hint = "0" if "0" in keys else keys[-1] if keys else "0"
    try:
        choice = input(f"{INDENT}{CYAN}▸{NC} {BOLD}Выбор{NC}{DIM} ({hint}):{NC} ").strip()
    except (KeyboardInterrupt, EOFError):
        return "0"

    if not choice:
        return hint

    choice = choice.upper()
    # Маппинг кириллических homoglyphs (похожих букв) и раскладки в латиницу
    cyrillic_map = {
        "А": "A",
        "В": "B",
        "Б": "B",
        "С": "C",
        "Е": "E",
        "Н": "H",
        "К": "K",
        "М": "M",
        "О": "O",
        "Р": "P",
        "Т": "T",
        "Х": "X",
        "У": "Y",
    }
    return cyrillic_map.get(choice, choice)


def prompt(text: str, default: str = "") -> str:
    """Запрашивает ввод у пользователя."""
    d = f" {DIM}[{default}]{NC}" if default else ""
    try:
        print(f"{INDENT}{CYAN}▸{NC} {BOLD}{text}{NC}{d}")
        result = input(f"{INDENT}  {CYAN}›{NC} ").strip()
        return result or default
    except (KeyboardInterrupt, EOFError):
        return default


def confirm(text: str, default: bool = True) -> bool:
    """Запрашивает да/нет."""
    hint = f"{GREEN}Y{NC}/{RED}n{NC}" if default else f"{RED}y{NC}/{GREEN}N{NC}"
    try:
        r = input(f"{INDENT}{CYAN}▸{NC} {BOLD}{text}{NC} ({hint}) › ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        return default
    if not r:
        return default
    return r[0] == "y"


# ═════════════════════════════════════════════════════════════════════════════
#  Утилиты
# ═════════════════════════════════════════════════════════════════════════════


def _bytes_auto(v: int) -> str:
    """Форматирует байты в IEC-единицах."""
    if v < 1024:
        return f"{v} B"
    if v < 1048576:
        return f"{v / 1024:.1f} KiB"
    if v < 1073741824:
        return f"{v / 1048576:.1f} MiB"
    if v < 1099511627776:
        return f"{v / 1073741824:.2f} GiB"
    return f"{v / 1099511627776:.2f} TiB"


def _bytes(v: int) -> str:
    """Форматирует байты в GB (совместимость)."""
    return f"{v / 1073741824:.2f} GiB"


def _bar(value: float, maximum: float, width: int = 18) -> str:
    if maximum <= 0:
        return f"{GREEN}[{'█' * width}{NC}] ∞"
    pct = value / maximum
    if not math.isfinite(pct):
        pct = 0.0
    pct = min(max(pct, 0.0), 1.0)
    try:
        filled = int(pct * width)
    except (OverflowError, ValueError):
        filled = 0
    return f"{GREEN}[{'█' * filled}{DIM}{'░' * (width - filled)}{NC}] {pct:.0%}"


def _ok(ok: bool) -> str:
    return f"{GREEN}✓{NC}" if ok else f"{RED}✗{NC}"
