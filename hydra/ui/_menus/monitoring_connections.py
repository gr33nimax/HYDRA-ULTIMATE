"""Active and recent connection controller."""
from __future__ import annotations

from hydra.core.state_models import AppState
from hydra.plugins.base import PluginCategory
from hydra.services.active_connections import (
    tracked_active_connections,
    traffic_daemon_fresh,
)
from hydra.services.application import ApplicationService
from hydra.services.system_monitoring_compatibility import (
    monitoring_from_application,
)
from hydra.ui.tui import (
    BOLD,
    DIM,
    GREEN,
    NC,
    PANEL_W,
    YELLOW,
    _bytes_auto,
    clear,
    menu,
    title,
)


def _collect_connections(
    state: AppState,
    app: ApplicationService,
) -> list[dict]:
    clients = list(tracked_active_connections(state))
    for plugin_name in sorted(
        app.protocols.enabled_names(state, PluginCategory.TRANSPORT),
    ):
        try:
            for client in app.protocols.connection_activity(
                state,
                plugin_name,
            ):
                row = dict(client)
                row["plugin"] = plugin_name
                clients.append(row)
        except Exception:
            pass
    clients.sort(key=lambda item: (
        str(item.get("plugin", "")),
        str(item.get("email", "")).lower(),
    ))
    return clients


def _activity_text(client: dict, now_timestamp: int) -> str:
    handshake = client.get("last_handshake", 0)
    if handshake > 0:
        elapsed = now_timestamp - handshake
        if elapsed < 0:
            return "сейчас"
        if elapsed < 60:
            return f"{elapsed} сек"
        if elapsed < 3600:
            return f"{elapsed // 60} мин"
        return f"{elapsed // 3600} ч"
    return "активен" if client.get("online", True) else "—"


def _render_connections(clients: list[dict], now_timestamp: int) -> None:
    if not clients:
        print(
            f"  {YELLOW}Нет активных подключений "
            f"в данный момент.{NC}",
        )
        print()
        return
    print(
        f"  {BOLD}{'Протокол':<12} {'Пользователь':<30} "
        f"{'Rx / Tx':<20} {'Активность':<15}{NC}",
    )
    print(f"  {DIM}{'─' * PANEL_W}{NC}")
    for client in clients:
        plugin_name = client.get("plugin", "unknown")
        email = client.get("email", "?")
        profiles = client.get("profiles", [])
        if profiles:
            email = f"{email} [{'/'.join(profiles)}]"
        elif client.get("connections", 0) > 1:
            email = f"{email} ({client['connections']} сесс.)"
        rx = client.get("rx", 0)
        tx = client.get("tx", 0)
        online = client.get("online", True)
        recent = client.get("activity_kind") == "recent"
        status = (
            f"{GREEN}●{NC}" if online
            else f"{YELLOW}◐{NC}" if recent
            else f"{DIM}●{NC}"
        )
        traffic = (
            f"{_bytes_auto(rx)} / {_bytes_auto(tx)}"
            if rx or tx else "—"
        )
        display_email = email if len(email) <= 30 else email[:27] + "..."
        print(
            f"  {plugin_name:<12} {status} "
            f"{BOLD}{display_email:<28}{NC} {traffic:<20} "
            f"{_activity_text(client, now_timestamp):<15}",
        )
    print()
    print(f"  {DIM}● Активно ◐ Активно (5 мин){NC}")


def _render_connection_warning(state: AppState) -> None:
    if not state.network.clash_api_enabled:
        print(
            f"  {YELLOW}Атрибуция Sing-Box соединений недоступна: "
            f"Clash API и демон статистики выключены.{NC}",
        )
    elif not traffic_daemon_fresh(state):
        print(
            f"  {YELLOW}Данные Clash API устарели: проверьте службу "
            f"hydra-traffic-daemon.{NC}",
        )


def _show_connections(state: AppState, app: ApplicationService):
    monitoring = monitoring_from_application(app)
    while True:
        clear()
        title("🔌 Подключения и активность")
        print()
        state = app.admin.load_state()
        clients = _collect_connections(state, app)
        _render_connections(clients, int(monitoring.now()))
        _render_connection_warning(state)
        choice = menu([
            ("R", "🔄 Обновить список", ""),
            ("0", "↩ Назад", ""),
        ], "ПОДКЛЮЧЕНИЯ И АКТИВНОСТЬ")
        if choice == "0":
            break
