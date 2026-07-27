"""Per-protocol traffic projection for protocol screens."""
from __future__ import annotations

from hydra.core.state_models import AppState
from hydra.services.application import ApplicationService
from hydra.ui.tui import (
    BOLD,
    CYAN,
    DIM,
    NC,
    PANEL_W,
    WHITE,
    YELLOW,
    _bytes_auto,
    clear,
    error,
    panel,
    prompt,
)


def show_plugin_traffic(
    state: AppState,
    plugin,
    app: ApplicationService,
) -> None:
    """Show what each user has moved through this protocol."""
    clear()
    name = plugin.meta.name
    try:
        traffic = app.protocols.traffic(state, name)
        lines: list[str] = []
        if not traffic:
            lines.append(f"{YELLOW}Трафик по протоколу ещё не учтён{NC}")
        else:
            lines.append(f"{BOLD}{WHITE}Трафик по пользователям:{NC}")
            lines.extend(
                f"  {BOLD}{email:<24}{NC}  {_bytes_auto(total)}"
                for email, total in sorted(
                    traffic.items(),
                    key=lambda item: int(item[1]),
                    reverse=True,
                )
            )
            lines.extend(
                [
                    f"{DIM}{'─' * (PANEL_W - 4)}{NC}",
                    f"  Пользователей:  {len(traffic)}",
                    "  Всего:          "
                    f"{CYAN}{_bytes_auto(sum(int(value) for value in traffic.values()))}{NC}",
                ],
            )
        panel(f"📊  ТРАФИК: {name.upper()}", lines)
    except Exception as exc:
        error(f"Ошибка получения трафика: {exc}")
    print()
    prompt("Нажмите Enter")


# Historical name kept for adapters that still import it.
show_plugin_clients = show_plugin_traffic


__all__ = ["show_plugin_clients", "show_plugin_traffic"]
