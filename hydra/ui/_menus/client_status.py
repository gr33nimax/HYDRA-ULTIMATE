"""Protocol client and traffic status projection."""
from __future__ import annotations

from datetime import datetime

from hydra.core.state_models import AppState
from hydra.services.application import ApplicationService
from hydra.ui.tui import (
    BOLD,
    CYAN,
    DIM,
    GREEN,
    NC,
    PANEL_W,
    RED,
    WHITE,
    YELLOW,
    _bytes_auto,
    clear,
    error,
    panel,
    prompt,
)


def show_plugin_clients(
    state: AppState,
    plugin,
    app: ApplicationService,
) -> None:
    clear()
    name = plugin.meta.name
    try:
        clients = app.protocols.connected_clients(state, name)
        traffic = app.protocols.traffic(state, name)
        lines: list[str] = []
        if not clients and not traffic:
            lines.append(f"{YELLOW}Нет активных клиентов или трафика{NC}")
        elif clients:
            lines.append(f"{BOLD}{WHITE}Активные сессии:{NC}")
            now = int(datetime.now().timestamp())
            for client in clients:
                marker = (
                    f"{GREEN}🟢{NC}" if client.get("online") else f"{RED}🔴{NC}"
                )
                handshake = int(client.get("last_handshake", 0))
                age = max(0, now - handshake) if handshake else None
                if age is None:
                    activity = f"{DIM}не активен{NC}"
                elif age < 60:
                    activity = f"{GREEN}только что{NC}"
                elif age < 3600:
                    activity = f"{GREEN}{age // 60} мин. назад{NC}"
                elif age < 86400:
                    activity = f"{DIM}{age // 3600} ч. назад{NC}"
                else:
                    activity = f"{DIM}{age // 86400} дн. назад{NC}"
                lines.append(
                    f"  {marker} {BOLD}{client.get('email', '?'):<18}{NC}  "
                    f"↓{_bytes_auto(client.get('rx', 0)):<9} "
                    f"↑{_bytes_auto(client.get('tx', 0)):<9}  {activity}",
                )
        else:
            lines.append(f"{BOLD}{WHITE}Статистика трафика:{NC}")
            lines.extend(
                f"  {BOLD}{email:<20}{NC}  {_bytes_auto(total)}"
                for email, total in traffic.items()
            )

        lines.extend(
            [
                f"{DIM}{'─' * (PANEL_W - 4)}{NC}",
                f"{BOLD}{WHITE}СВОДНАЯ СТАТИСТИКА ПОТОКА:{NC}",
                f"  Всего клиентов:  {len(clients) if clients else len(traffic)}",
            ],
        )
        if clients:
            online = sum(1 for client in clients if client.get("online"))
            received = sum(int(client.get("rx", 0)) for client in clients)
            sent = sum(int(client.get("tx", 0)) for client in clients)
            lines.extend(
                [
                    f"  В сети (online): {GREEN}{online}{NC}",
                    f"  Получено (RX):   {GREEN}{_bytes_auto(received)}{NC}",
                    f"  Отправлено (TX): {GREEN}{_bytes_auto(sent)}{NC}",
                    f"  Общий трафик:    {CYAN}{_bytes_auto(received + sent)}{NC}",
                ],
            )
        panel(f"👥  КЛИЕНТЫ: {name.upper()}", lines)
    except Exception as exc:
        error(f"Ошибка получения клиентов: {exc}")
    print()
    prompt("Нажмите Enter")


__all__ = ["show_plugin_clients"]
