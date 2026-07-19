"""Presentation helpers for protocol and network-service menus.

The interactive loops remain in :mod:`hydra.ui.menus`, while this module owns
the deterministic transformation from plugin metadata/statuses to menu rows.
Keeping that boundary small makes the UI testable without running the TUI and
prevents status formatting from being duplicated by future frontends.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from hydra.ui.protocol_ui import protocol_label, protocol_status_panel, status_badge
from hydra.ui.tui import BOLD, DIM, GREEN, NC, RED, YELLOW


def transport_summary_lines(plugins: Iterable[Any], statuses: Mapping[str, Mapping[str, Any]]) -> list[str]:
    """Build compact transport rows for the protocol overview panel."""
    lines = []
    for plugin in plugins:
        status = statuses.get(plugin.meta.name, {})
        port = str(status["port"]) if status.get("port") else "—"
        lines.append(
            f"  {status_badge(status)}  {protocol_label(plugin.meta.name):<16} "
            f"{DIM}порт {port}{NC}"
        )
    return lines


def transport_options(plugins: Iterable[Any], statuses: Mapping[str, Mapping[str, Any]]) -> list[tuple[str, str, str]]:
    """Build selectable transport rows, preserving registry order."""
    options = []
    for index, plugin in enumerate(plugins, 1):
        status = statuses.get(plugin.meta.name, {})
        options.append((
            str(index),
            f"{status_badge(status)}  {protocol_label(plugin.meta.name)}",
            status.get("error") or plugin.meta.description,
        ))
    return options


def enhancement_summary_lines(plugins: Iterable[Any], statuses: Mapping[str, Mapping[str, Any]]) -> list[str]:
    """Build compact rows for DNS/routing enhancement services."""
    lines = []
    for plugin in plugins:
        status = statuses.get(plugin.meta.name, {})
        icon = (
            f"{GREEN}●{NC}" if status.get("running")
            else f"{YELLOW}●{NC}" if status.get("installed")
            else f"{DIM}●{NC}"
        )
        port = f":{status['port']}" if status.get("port") else ""
        enabled = "вкл" if status.get("enabled") else "выкл"
        lines.append(f"  {icon} {plugin.meta.name:<14} {DIM}{enabled:>4}{NC}  порт{port}")
    return lines


def enhancement_options(plugins: Iterable[Any], statuses: Mapping[str, Mapping[str, Any]]) -> list[tuple[str, str, str]]:
    """Build selectable enhancement rows, preserving registry order."""
    options = []
    for index, plugin in enumerate(plugins, 1):
        status = statuses.get(plugin.meta.name, {})
        icon = (
            f"{GREEN}✓{NC}" if status.get("running")
            else f"{YELLOW}⚠{NC}" if status.get("installed")
            else f"{RED}✗{NC}"
        )
        options.append((str(index), f"{icon} {plugin.meta.name}", plugin.meta.description))
    return options


def menu_footer() -> list[tuple[str, str, str]]:
    """Return the common separator/back entries for protocol menus."""
    return [("-", "", ""), ("0", "↩ Назад", "")]


def render_protocol_status(plugin: Any, persisted: Any) -> None:
    """Render a plugin status with a safe runtime-to-persisted fallback.

    A broken probe must not take down the menu: the persisted state remains
    useful context while the error is shown in the same status card.
    """
    try:
        status = plugin.status()
        protocol_status_panel(
            plugin.meta.name,
            installed=status.installed,
            enabled=status.enabled,
            running=status.running,
            port=status.port,
            details=(status.info or {}).items(),
        )
    except Exception as exc:
        protocol_status_panel(
            plugin.meta.name,
            installed=persisted.installed,
            enabled=persisted.enabled,
            running=False,
            port=persisted.port,
            error=str(exc) or exc.__class__.__name__,
        )
