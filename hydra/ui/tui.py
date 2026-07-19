"""
hydra/ui/tui.py — Текстовый UI-фреймворк.

Цвета, рамки, заголовки, панели, утилиты ввода.
"""
from __future__ import annotations

import os
import re
import sys
import shutil
from typing import Optional

try:
    import readline
except ImportError:
    pass

# ═════════════════════════════════════════════════════════════════════════════
#  Цвета
# ═════════════════════════════════════════════════════════════════════════════

def _detect_colors() -> dict:
    keys = ("RED", "GREEN", "YELLOW", "CYAN", "BLUE", "MAGENTA",
            "BOLD", "DIM", "WHITE", "TEXT", "NC")
    if not sys.stdout.isatty():
        return {k: "" for k in keys}

    light = os.environ.get("HYDRA_THEME", "").lower() == "light"
    if light:
        return {
            "RED": "\033[0;31m", "GREEN": "\033[0;32m", "YELLOW": "\033[0;33m",
            "CYAN": "\033[0;34m", "BLUE": "\033[0;35m", "MAGENTA": "\033[0;35m",
            "BOLD": "\033[1m", "DIM": "\033[2m", "WHITE": "\033[0;30m",
            "TEXT": "\033[0;30m", "NC": "\033[0m",
        }
    return {
        "RED": "\033[0;31m", "GREEN": "\033[0;32m", "YELLOW": "\033[1;33m",
        "CYAN": "\033[0;36m", "BLUE": "\033[0;34m", "MAGENTA": "\033[0;35m",
        "BOLD": "\033[1m", "DIM": "\033[2m", "WHITE": "\033[1;37m",
        "TEXT": "\033[0;37m", "NC": "\033[0m",
    }

C = _detect_colors()
RED = C["RED"]; GREEN = C["GREEN"]; YELLOW = C["YELLOW"]; CYAN = C["CYAN"]
BLUE = C["BLUE"]; MAGENTA = C["MAGENTA"]; BOLD = C["BOLD"]; DIM = C["DIM"]
WHITE = C["WHITE"]; NC = C["NC"]
TEXT = C["TEXT"]

TERM_WIDTH = shutil.get_terminal_size().columns
PANEL_W = min(TERM_WIDTH - 4, 78)
INDENT = " " * max(2, (TERM_WIDTH - PANEL_W - 2) // 2)


def _strip(s: str) -> str:
    return re.sub(r"\033\[[0-9;]*m", "", s)


def _char_width(char: str) -> int:
    code = ord(char)
    if code == 0xfe0f:
        return 0
    # Problematic characters that render as 1-cell in typical terminal fonts
    if code in {
        0x1f7e2, # 🟢
        0x1f534, # 🔴
        0x1f310, # 🌐
        0x1f512, # 🔒
        0x1f6e1, # 🛡
        0x2699,  # ⚙
    }:
        return 1
    # Common 2-cell emojis in standard BMP
    if code in {
        0x274c,  # ❌
        0x2705,  # ✅
        0x26a1,  # ⚡
        0x23f1,  # ⏱
        0x1f4ca, # 📊
    }:
        return 2
    # Emojis > 0xffff are always 2 cells wide
    if code > 0xffff:
        return 2
    # CJK characters
    if (0x4e00 <= code <= 0x9fff or 
        0x3000 <= code <= 0x303f or 
        0xff00 <= code <= 0xffef):
        return 2
    return 1


def _width(s: str) -> int:
    """Возвращает визуальную ширину строки в терминале с учетом эмодзи."""
    plain = _strip(s)
    w = 0
    flags_count = 0
    for char in plain:
        code = ord(char)
        if 0x1f1e6 <= code <= 0x1f1ff:
            flags_count += 1
        w += _char_width(char)
    
    # Каждая пара региональных индикаторов представляет собой один флаг (2 ячейки).
    # Без корректировки 2 символа давали бы 2 + 2 = 4 ячейки. Вычитаем разницу.
    w -= (flags_count // 2) * 2
    return w


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
                if ord(char) == 0xfe0f:
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


# ═════════════════════════════════════════════════════════════════════════════
#  Баннер
# ═════════════════════════════════════════════════════════════════════════════

BANNER = rf"""
{CYAN}██╗  ██╗{GREEN}██╗   ██╗{CYAN}██████╗ {GREEN}██████╗ {CYAN} █████╗
 ██║  ██║{GREEN}╚██╗ ██╔╝{CYAN}██╔══██╗{GREEN}██╔══██╗{CYAN}██╔══██╗
 ███████║{GREEN} ╚████╔╝ {CYAN}██║  ██║{GREEN}██████╔╝{CYAN}███████║
 ██╔══██║{GREEN}  ╚██╔╝  {CYAN}██║  ██║{GREEN}██╔══██╗{CYAN}██╔══██║
 ██║  ██║{GREEN}   ██║   {CYAN}██████╔╝{GREEN}██║  ██║{CYAN}██║  ██║
 ╚═╝  ╚═╝{GREEN}   ╚═╝   {CYAN}╚═════╝ {GREEN}╚═╝  ╚═╝{CYAN}╚═╝  ╚═╝{NC}
{DIM}─────────────────────────────────────────────────{NC}
{MAGENTA}🐍  Multi-Protocol Proxy & Routing Orchestrator  🐍{NC}
{DIM}v2.4.0{NC}
"""



# ═════════════════════════════════════════════════════════════════════════════
#  Базовые функции
# ═════════════════════════════════════════════════════════════════════════════

def clear():
    os.system("clear" if os.name != "nt" else "cls")


def divider(char: str = "═", width: Optional[int] = None):
    w = width or PANEL_W
    print(f"{INDENT}{DIM}{char * w}{NC}")


def title(text: str):
    print(f"\n{INDENT}{BOLD}{CYAN}▸ {text}{NC}")


def kv(label: str, value: str, label_w: int = 16) -> str:
    """Строка «ключ — значение» для панелей."""
    return f"  {TEXT}{label:<{label_w}}{NC} {value}"


def panel(title_text: str, lines: list[str]):
    """Панель состояния с двойными рамками."""
    inner = PANEL_W
    
    # Центрируем заголовок
    title_fit, title_w = _fit_line(title_text, inner - 2)
    pad_left = (inner - title_w) // 2
    pad_right = inner - title_w - pad_left
    
    print()
    print(f"{INDENT}{CYAN}╔{'═' * inner}╗{NC}")
    print(f"{INDENT}{CYAN}║{NC}{' ' * pad_left}{BOLD}{WHITE}{title_fit}{NC}{' ' * pad_right}{CYAN}║{NC}")
    print(f"{INDENT}{CYAN}╠{'═' * inner}╣{NC}")
    for line in lines:
        plain_line = _strip(line).strip()
        if plain_line and all(c in "─-" for c in plain_line):
            line_fit = f"{DIM}{'─' * (inner - 2)}{NC}"
            line_w = inner - 2
            pad = 0
        else:
            line_fit, line_w = _fit_line(line, inner - 2)
            pad = inner - 2 - line_w
        print(f"{INDENT}{CYAN}║{NC} {line_fit}{' ' * pad} {CYAN}║{NC}")
    print(f"{INDENT}{CYAN}╚{'═' * inner}╝{NC}")


def box(content: str, header: str = ""):
    """Рисует рамку вокруг текста с двойными границами."""
    inner = PANEL_W
    print(f"{INDENT}{CYAN}╔{'═' * inner}╗{NC}")
    if header:
        h_fit, h_w = _fit_line(header, inner - 2)
        pad_left = (inner - h_w) // 2
        pad_right = inner - h_w - pad_left
        print(f"{INDENT}{CYAN}║{NC}{' ' * pad_left}{BOLD}{h_fit}{NC}{' ' * pad_right}{CYAN}║{NC}")
        print(f"{INDENT}{CYAN}╠{'═' * inner}╣{NC}")
    for line in content.split("\n"):
        plain_line = _strip(line).strip()
        if plain_line and all(c in "─-" for c in plain_line):
            line_fit = f"{DIM}{'─' * (inner - 2)}{NC}"
            line_w = inner - 2
            pad = 0
        else:
            line_fit, line_w = _fit_line(line, inner - 2)
            pad = inner - 2 - line_w
        print(f"{INDENT}{CYAN}║{NC} {line_fit}{' ' * pad} {CYAN}║{NC}")
    print(f"{INDENT}{CYAN}╚{'═' * inner}╝{NC}")


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
    """Отображает меню с двойными рамками."""
    inner = PANEL_W
    print()
    print(f"{INDENT}{CYAN}╔{'═' * inner}╗{NC}")

    if header:
        h_fit, h_w = _fit_line(header, inner - 2)
        pad_left = (inner - h_w) // 2
        pad_right = inner - h_w - pad_left
        print(f"{INDENT}{CYAN}║{NC}{' ' * pad_left}{BOLD}{WHITE}{h_fit}{NC}{' ' * pad_right}{CYAN}║{NC}")
        print(f"{INDENT}{CYAN}╠{'═' * inner}╣{NC}")

    for key, label, desc in options:
        if key == "-":
            print(f"{INDENT}{CYAN}╠{'═' * inner}╣{NC}")
            continue
        key_col = _menu_key(key)
        line = f"  {key_col}  {label}"
        
        plain_line = _strip(line).strip()
        if plain_line and all(c in "─-" for c in plain_line):
            line_fit = f"{DIM}{'─' * (inner - 2)}{NC}"
            line_w = inner - 2
            pad = 0
        else:
            line_fit, line_w = _fit_line(line, inner - 2)
            pad = inner - 2 - line_w
            
        print(f"{INDENT}{CYAN}║{NC} {line_fit}{' ' * pad} {CYAN}║{NC}")
        if desc:
            import textwrap
            desc_width = max(20, inner - 9)
            for paragraph in desc.split("\n"):
                wrapped_lines = textwrap.wrap(paragraph, width=desc_width) if paragraph.strip() else [""]
                for w_line in wrapped_lines:
                    dline = f"       {DIM}{w_line}{NC}"
                    
                    plain_dline = _strip(dline).strip()
                    if plain_dline and all(c in "─-" for c in plain_dline):
                        dline_fit = f"{DIM}{'─' * (inner - 2)}{NC}"
                        dline_w = inner - 2
                        dpad = 0
                    else:
                        dline_fit, dline_w = _fit_line(dline, inner - 2)
                        dpad = inner - 2 - dline_w
                        
                    print(f"{INDENT}{CYAN}║{NC} {dline_fit}{' ' * dpad} {CYAN}║{NC}")

    print(f"{INDENT}{CYAN}╚{'═' * inner}╝{NC}")
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


def dashboard_menu(
    sections: list[tuple[str, list[str]]],
    options: list[tuple[str, str, str]],
    header: str = "",
    banner: str = "",
    options_header: str = "",
) -> str:
    """Рисует составной главный экран с единой рамкой и секциями."""
    inner = PANEL_W
    print()
    print(f"{INDENT}{CYAN}╔{'═' * inner}╗{NC}")

    def section_divider() -> None:
        print(f"{INDENT}{CYAN}║{NC}{DIM}{'─' * inner}{NC}{CYAN}║{NC}")

    if banner:
        import textwrap
        banner = textwrap.dedent(banner)
        print(f"{INDENT}{CYAN}║{NC}{' ' * inner}{CYAN}║{NC}")
        for raw_line in banner.splitlines():
            if not raw_line.strip():
                print(f"{INDENT}{CYAN}║{NC}{' ' * inner}{CYAN}║{NC}")
                continue
            line_fit, line_w = _fit_line(raw_line, inner - 2)
            left = max(0, (inner - line_w) // 2)
            right = max(0, inner - line_w - left)
            print(f"{INDENT}{CYAN}║{NC}{' ' * left}{line_fit}{' ' * right}{CYAN}║{NC}")
        print(f"{INDENT}{CYAN}║{NC}{' ' * inner}{CYAN}║{NC}")
        section_divider()

    if header:
        h_fit, h_w = _fit_line(header, inner - 2)
        pad_left = (inner - h_w) // 2
        pad_right = inner - h_w - pad_left
        print(f"{INDENT}{CYAN}║{NC}{' ' * pad_left}{BOLD}{WHITE}{h_fit}{NC}{' ' * pad_right}{CYAN}║{NC}")
        section_divider()

    for section_title, lines in sections:
        title_fit, title_w = _fit_line(section_title, inner - 4)
        print(f"{INDENT}{CYAN}║{NC} {BOLD}{CYAN}{title_fit}{NC}{' ' * (inner - 2 - title_w)} {CYAN}║{NC}")
        print(f"{INDENT}{CYAN}║{NC}{' ' * inner}{CYAN}║{NC}")
        for line in lines:
            line_fit, line_w = _fit_line(line, inner - 2)
            print(f"{INDENT}{CYAN}║{NC} {line_fit}{' ' * (inner - 2 - line_w)} {CYAN}║{NC}")
        print(f"{INDENT}{CYAN}║{NC}{' ' * inner}{CYAN}║{NC}")
        section_divider()

    if options_header:
        title_fit, title_w = _fit_line(options_header, inner - 4)
        print(f"{INDENT}{CYAN}║{NC} {BOLD}{CYAN}{title_fit}{NC}{' ' * (inner - 2 - title_w)} {CYAN}║{NC}")
        print(f"{INDENT}{CYAN}║{NC}{' ' * inner}{CYAN}║{NC}")

    for key, label, desc in options:
        if key == "-":
            section_divider()
            continue
        line = f"  {_menu_key(key)}  {TEXT}{label}{NC}"
        line_fit, line_w = _fit_line(line, inner - 2)
        print(f"{INDENT}{CYAN}║{NC} {line_fit}{' ' * (inner - 2 - line_w)} {CYAN}║{NC}")
        if desc:
            import textwrap
            for paragraph in desc.split("\n"):
                for wrapped in textwrap.wrap(paragraph, width=max(20, inner - 9)) or [""]:
                    dline = f"       {TEXT}{DIM}{wrapped}{NC}"
                    dline_fit, dline_w = _fit_line(dline, inner - 2)
                    print(f"{INDENT}{CYAN}║{NC} {dline_fit}{' ' * (inner - 2 - dline_w)} {CYAN}║{NC}")

    print(f"{INDENT}{CYAN}╚{'═' * inner}╝{NC}")
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
    cyrillic_map = {
        "А": "A", "В": "B", "Б": "B", "С": "C", "Е": "E", "Н": "H",
        "К": "K", "М": "M", "О": "O", "Р": "P", "Т": "T", "Х": "X", "У": "Y",
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
    pct = min(value / maximum, 1.0)
    filled = int(pct * width)
    return f"{GREEN}[{'█' * filled}{DIM}{'░' * (width - filled)}{NC}] {pct:.0%}"


def _ok(ok: bool) -> str:
    return f"{GREEN}✓{NC}" if ok else f"{RED}✗{NC}"
