"""Shared presentation helpers for protocol TUI screens.

Keep protocol managers free to expose their own advanced actions, while making
their identity, status block and menu titles look the same everywhere.
"""
from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from hydra.ui.tui import BOLD, CYAN, DIM, GREEN, RED, YELLOW, NC, panel


PROTOCOL_LABELS = {
    "amneziawg": "AmneziaWG",
    "anytls": "AnyTLS",
    "trusttunnel": "TrustTunnel",
    "shadowtls": "ShadowTLS",
    "hysteria2": "Hysteria2",
    "snell": "Snell",
    "mieru": "Mieru",
    "naive": "NaiveProxy",
    "telemt": "Telemt",
    "wdtt": "qWDTT",
}


def protocol_label(name: str) -> str:
    """Return the product-facing protocol name instead of an internal key."""
    return PROTOCOL_LABELS.get(name, name)


def protocol_menu_title(name: str) -> str:
    return f"{protocol_label(name).upper()} · УПРАВЛЕНИЕ"


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


def protocol_status_panel(
    name: str,
    *,
    installed: bool,
    enabled: bool,
    running: bool,
    port: int | str | None = None,
    details: Iterable[tuple[str, Any]] = (),
    error: str = "",
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
            lines.append(f"  {DIM}{str(label):<16}{NC} {value}")
    if error:
        lines.extend(("", f"  {RED}Ошибка статуса:{NC} {error}"))
    panel(f"{CYAN}◈{NC} {protocol_label(name)}", lines)


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
