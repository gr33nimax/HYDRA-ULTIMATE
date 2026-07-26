"""Console rendering for Telemt fallback configuration."""

from __future__ import annotations

import os
import re
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from hydra.plugins.telemt.telemt_fallback_model import FallbackConfig
from hydra.plugins.telemt.telemt_fallback_probe import MiddleProxyProbe


@dataclass(frozen=True)
class ConsolePalette:
    red: str
    green: str
    yellow: str
    cyan: str
    bold: str
    dim: str
    white: str
    reset: str


@dataclass(frozen=True)
class ConsoleDependencies:
    read_config: Callable[[Path], FallbackConfig]
    fetch_endpoints: Callable[[], list[tuple[str, int]]]
    probe_factory: Callable[[list[tuple[str, int]]], MiddleProxyProbe]
    endpoints: list[tuple[str, int]]
    quorum: Callable[[], float]


def _display_width(text: str) -> int:
    plain = re.sub(r"\033\[[0-9;]*m", "", text)
    return sum(
        2 if unicodedata.east_asian_width(char) in {"W", "F"} else 1
        for char in plain
    )


class _Box:
    def __init__(self, palette: ConsolePalette, width: int = 66) -> None:
        self.palette = palette
        self.width = width

    def row(self, text: str = "") -> None:
        padding = max(0, self.width - _display_width(text))
        print(
            f"{self.palette.cyan}║{self.palette.reset}"
            f"{text}{' ' * padding}"
            f"{self.palette.cyan}║{self.palette.reset}"
        )

    def kv(self, key: str, value: str, key_width: int = 28) -> None:
        colored_key = f"{self.palette.cyan}{key}{self.palette.reset}"
        padding = key_width - _display_width(colored_key)
        self.row(f"  {colored_key}{' ' * max(0, padding)}  {value}")

    def separator(self) -> None:
        print(
            f"{self.palette.cyan}╠{'═' * self.width}╣"
            f"{self.palette.reset}"
        )

    def item(self, key: str, label: str) -> None:
        color = (
            self.palette.red + self.palette.bold
            if key.strip().upper() in {"Q", "0"}
            else self.palette.white + self.palette.bold
        )
        self.row(
            f"  {self.palette.dim}[{self.palette.reset}"
            f"{color}{key}{self.palette.reset}"
            f"{self.palette.dim}]{self.palette.reset}  {label}"
        )


def fallback_status_line(
    fallback: FallbackConfig,
    current_mode: bool | None,
    palette: ConsolePalette,
) -> str:
    """Render fallback state without reading config or global state."""

    if not fallback.fallback_to_direct:
        return f"{palette.yellow}отключён{palette.reset}"
    mode = "Middle Proxy" if current_mode else "Direct (fallback)"
    color = palette.green if current_mode else palette.yellow
    parts = [
        f"{color}{mode}{palette.reset}",
        (
            f"{palette.dim}(попыток: {fallback.fallback_after_attempts}, "
            f"timeout: {fallback.fallback_after_seconds}s){palette.reset}"
        ),
    ]
    if fallback.auto_revert_to_middle:
        parts.append(f"{palette.cyan}auto-revert{palette.reset}")
    return "  ".join(parts)


def me_probe_menu(
    config_file: Path,
    *,
    dependencies: ConsoleDependencies,
    palette: ConsolePalette,
) -> FallbackConfig:
    """Interactively edit a fallback policy and optionally run a live probe."""

    current = dependencies.read_config(config_file)
    box = _Box(palette)
    os.system("clear")
    print(f"{palette.cyan}╔{'═' * box.width}╗{palette.reset}")
    title = "НАСТРОЙКА FALLBACK: MIDDLE PROXY → DIRECT"
    padding = box.width - _display_width(title)
    print(
        f"{palette.cyan}║{palette.reset}"
        f"{' ' * (padding // 2)}{palette.bold}{palette.white}{title}"
        f"{palette.reset}{' ' * (padding - padding // 2)}"
        f"{palette.cyan}║{palette.reset}"
    )
    box.separator()
    box.row()
    box.row(
        f"  {palette.dim}При недоступности Telegram ME-серверов Telemt "
        f"автоматически{palette.reset}"
    )
    box.row(
        f"  {palette.dim}переходит в Direct Mode без перезапуска.{palette.reset}"
    )
    box.row()
    box.row(f"  {palette.bold}Текущие настройки:{palette.reset}")
    box.row()
    box.kv(
        "fallback_to_direct",
        f"{palette.green if current.fallback_to_direct else palette.red}"
        f"{current.fallback_to_direct}{palette.reset}",
    )
    box.kv("fallback_after_attempts", str(current.fallback_after_attempts))
    box.kv("fallback_after_seconds", str(current.fallback_after_seconds))
    box.kv(
        "auto_revert_to_middle",
        f"{palette.green if current.auto_revert_to_middle else palette.dim}"
        f"{current.auto_revert_to_middle}{palette.reset}",
    )
    box.row()
    box.separator()
    box.item("1", f"Включить fallback {palette.green}(рекомендуется){palette.reset}")
    box.item(
        "2",
        f"Отключить fallback {palette.dim}(жёсткий Middle Proxy){palette.reset}",
    )
    box.item("3", "Настроить параметры вручную")
    box.item("T", "Проверить доступность ME-серверов прямо сейчас")
    box.separator()
    box.item("Enter", "Оставить текущие настройки и продолжить")
    box.item("Q", "← Назад (без изменений)")
    print(f"{palette.cyan}╚{'═' * box.width}╝{palette.reset}")
    print()

    try:
        print(f"{palette.cyan}Выбор: {palette.reset}", end="", flush=True)
        choice = input().strip().lower()
    except (KeyboardInterrupt, EOFError):
        print()
        return current

    if choice in {"q", ""}:
        return current
    if choice == "1":
        current.fallback_to_direct = True
        print(f"  {palette.green}✓{palette.reset}  Fallback включён.")
    elif choice == "2":
        current.fallback_to_direct = False
        print(
            f"  {palette.yellow}⚠{palette.reset}  "
            "Fallback отключён — Middle Proxy обязателен."
        )
    elif choice == "3":
        _read_manual_policy(current, palette)
    elif choice == "t":
        _run_live_probe(dependencies, palette)
        try:
            print(
                f"  {palette.dim}Нажмите Enter...{palette.reset}",
                end="",
                flush=True,
            )
            input()
        except (KeyboardInterrupt, EOFError):
            pass
        return me_probe_menu(
            config_file,
            dependencies=dependencies,
            palette=palette,
        )
    return current


def _read_manual_policy(
    current: FallbackConfig,
    palette: ConsolePalette,
) -> None:
    print()
    try:
        value = input(
            "  Попыток перед fallback "
            f"[{current.fallback_after_attempts}]: "
        ).strip()
        if value:
            current.fallback_after_attempts = int(value)
    except (ValueError, KeyboardInterrupt, EOFError):
        pass
    try:
        value = input(
            "  Timeout warmup (секунд) "
            f"[{current.fallback_after_seconds}]: "
        ).strip()
        if value:
            current.fallback_after_seconds = int(value)
    except (ValueError, KeyboardInterrupt, EOFError):
        pass
    try:
        current.auto_revert_to_middle = (
            input("  Auto-revert в Middle при восстановлении? [y/N]: ")
            .strip()
            .lower()
            == "y"
        )
    except (KeyboardInterrupt, EOFError):
        pass
    current.__post_init__()
    print(f"  {palette.green}✓{palette.reset}  Настройки обновлены.")


def _run_live_probe(
    dependencies: ConsoleDependencies,
    palette: ConsolePalette,
) -> None:
    print()
    print(
        f"  {palette.cyan}→{palette.reset}  "
        "Проверяю доступность ME-серверов Telegram..."
    )
    live = dependencies.fetch_endpoints()
    source = (
        f"живой пул getProxyConfig ({len(live)} адресов)"
        if live
        else "статический fallback-список (getProxyConfig недоступен)"
    )
    print(f"  {palette.dim}источник: {source}{palette.reset}")
    endpoints = live or dependencies.endpoints
    ok, total = dependencies.probe_factory(endpoints).probe_all()
    ratio = ok / total if total else 0
    quorum = dependencies.quorum()
    if ratio >= quorum:
        print(
            f"  {palette.green}✓{palette.reset}  "
            f"ME-серверы доступны: {ok}/{total} endpoint'ов ({ratio:.0%})"
        )
        return
    print(
        f"  {palette.yellow}⚠{palette.reset}  "
        f"ME-серверы НЕДОСТУПНЫ: {ok}/{total} "
        f"({ratio:.0%} < кворум {quorum:.0%})"
    )
