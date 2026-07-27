"""Shared presentation helpers for protocol TUI screens.

Keep protocol managers free to expose their own advanced actions, while making
their identity, status block and menu titles look the same everywhere.
"""
from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from hydra.ui.tui import (
    BOLD,
    CYAN,
    DIM,
    GREEN,
    NC,
    PANEL_W,
    RED,
    YELLOW,
    panel,
    visible_width,
)


PROTOCOL_LABELS = {
    "amneziawg": "AmneziaWG",
    "anytls": "AnyTLS",
    "trusttunnel": "TrustTunnel",
    "shadowtls": "ShadowTLS",
    "hysteria2": "Hysteria2",
    "snell": "Snell",
    "mieru": "Mieru",
    "naive": "NaiveProxy",
    "vless": "VLESS",
    "telemt": "Telemt",
    "wdtt": "qWDTT",
}


def protocol_label(name: str, display_name: str = "") -> str:
    """Return the product-facing protocol name instead of an internal key."""
    label = display_name if isinstance(display_name, str) else ""
    return label or PROTOCOL_LABELS.get(name, name)


def protocol_menu_title(name: str, display_name: str = "") -> str:
    return f"{protocol_label(name, display_name).upper()} · УПРАВЛЕНИЕ"


def protocol_state(installed: bool, enabled: bool, running: bool) -> str:
    if running:
        return f"{GREEN}● Работает{NC}"
    if not installed:
        return f"{DIM}● Не установлен{NC}"
    if not enabled:
        return f"{YELLOW}● Отключён{NC}"
    return f"{RED}● Не работает{NC}"


def _yes_no(value: bool) -> str:
    return f"{GREEN}Да{NC}" if value else f"{DIM}Нет{NC}"


_LABEL_WIDTH = 16
# Panel border, one space of padding on both sides, the label column and the
# gap after it. What is left is what a value may occupy on one line.
_VALUE_WIDTH = PANEL_W - 2 - 2 - _LABEL_WIDTH - 1


def _detail_lines(label: str, value: str) -> list[str]:
    """Lay out one status row, wrapping a long value under its own column."""
    head = f"  {DIM}{label:<{_LABEL_WIDTH}}{NC} "
    if "" in value or visible_width(value) <= _VALUE_WIDTH:
        return [f"{head}{value}"]

    lines: list[str] = []
    current = ""
    for word in value.split(" "):
        candidate = f"{current} {word}".strip()
        if current and visible_width(candidate) > _VALUE_WIDTH:
            lines.append(current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(current)
    continuation = f"  {' ' * _LABEL_WIDTH} "
    return [
        f"{head if index == 0 else continuation}{line}"
        for index, line in enumerate(lines)
    ]


def protocol_status_panel(
    name: str,
    *,
    installed: bool,
    enabled: bool,
    running: bool,
    port: int | str | None = None,
    details: Iterable[tuple[str, Any]] = (),
    error: str = "",
    display_name: str = "",
) -> None:
    """Render the canonical status card used by every transport protocol."""
    lines = [
        f"  {DIM}{'Состояние':<16}{NC} {protocol_state(installed, enabled, running)}",
        f"  {DIM}{'Установлен':<16}{NC} {_yes_no(installed)}",
        f"  {DIM}{'Включён':<16}{NC} {_yes_no(enabled)}",
    ]
    if port not in (None, "", 0, "0"):
        lines.append(f"  {DIM}{'Порт':<16}{NC} {BOLD}{port}{NC}")
    for label, value in details:
        if value not in (None, ""):
            lines.extend(_detail_lines(str(label), str(value)))
    if error:
        lines.extend(("", f"  {RED}Ошибка статуса:{NC} {error}"))
    panel(
        f"{CYAN}◈{NC} {protocol_label(name, display_name)}",
        lines,
    )


def status_badge(status: dict[str, Any]) -> str:
    """Return an explicit status marker that remains clear without colours."""
    drift = status.get("drift")
    if drift == "unexpectedly_running":
        return f"{YELLOW}{BOLD}{'! ЛИШНИЙ ПРОЦЕСС':<16}{NC}"
    if drift == "unknown":
        return f"{RED}{BOLD}{'! НЕИЗВЕСТНО':<16}{NC}"
    if status.get("running"):
        return f"{GREEN}{BOLD}{'✓ РАБОТАЕТ':<16}{NC}"
    if status.get("error"):
        return f"{RED}{BOLD}{'! ОШИБКА СТАТУСА':<16}{NC}"
    if status.get("installed") and status.get("desired_enabled", status.get("enabled")):
        return f"{RED}{BOLD}{'✕ СБОЙ':<16}{NC}"
    if status.get("installed"):
        return f"{YELLOW}{'○ ОТКЛЮЧЁН':<16}{NC}"
    return f"{DIM}{'— НЕ УСТАНОВЛЕН':<16}{NC}"
