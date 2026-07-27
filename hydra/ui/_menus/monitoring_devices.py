"""Fleet-wide view of the devices users are connected from."""
from __future__ import annotations

from dataclasses import dataclass

from hydra.core.state_models import AppState
from hydra.services.application import ApplicationService
from hydra.services.device_sessions import user_sessions
from hydra.ui._menus.device_formatting import address_label
from hydra.ui._menus.monitoring_support import _application
from hydra.ui.tui import (
    BOLD,
    CYAN,
    DIM,
    GREEN,
    NC,
    RED,
    WHITE,
    YELLOW,
    _bytes_auto,
    clear,
    panel,
    prompt,
)


@dataclass(frozen=True)
class DeviceSummary:
    """Aggregated device counters across every user."""

    online_devices: int = 0
    online_users: int = 0
    over_limit_users: int = 0
    registered_devices: int = 0

    @property
    def headline(self) -> str:
        """Return the one-line summary shown on the monitoring overview."""
        if not self.online_devices:
            return f"{DIM}никто не подключён{NC}"
        text = (
            f"{CYAN}{self.online_devices}{NC} у "
            f"{self.online_users} польз."
        )
        if self.over_limit_users:
            text += f"  │  {RED}{self.over_limit_users} сверх лимита{NC}"
        return text


def summarize(state: AppState) -> DeviceSummary:
    """Count online devices, users behind them and limit violations."""
    online = 0
    users_online = 0
    over_limit = 0
    for user in state.users:
        sessions = [
            session
            for session in user_sessions(state, user.email)
            if session.connections
        ]
        if not sessions:
            continue
        users_online += 1
        online += len(sessions)
        if any(not session.allowed for session in sessions):
            over_limit += 1
    return DeviceSummary(
        online_devices=online,
        online_users=users_online,
        over_limit_users=over_limit,
        registered_devices=sum(len(user.devices) for user in state.users),
    )


def _user_lines(state: AppState, user) -> list[str]:
    sessions = user_sessions(state, user.email)
    active = [session for session in sessions if session.connections]
    if not active and not user.devices:
        return []
    limit = (
        f"{user.device_limit} одновр."
        if user.device_limit
        else "без лимита"
    )
    marker = f"{GREEN}●{NC}" if active else f"{DIM}○{NC}"
    lines = [
        f"  {marker} {BOLD}{user.email[:28]:<28}{NC} "
        f"{len(active)} онлайн · {len(user.devices)} известно · {limit}",
    ]
    for session in active[:4]:
        flag = "" if session.allowed else f"  {RED}сверх лимита{NC}"
        lines.append(
            f"      {address_label(session.address):<30} "
            f"{session.connections} соед.  "
            f"{_bytes_auto(session.bytes_total)}{flag}",
        )
    if len(active) > 4:
        lines.append(f"      {DIM}… ещё {len(active) - 4}{NC}")
    return lines


def _show_devices(
    state: AppState,
    app: ApplicationService | None = None,
) -> None:
    """Show which devices are connected right now, user by user."""
    app = _application(app)
    clear()
    state = app.admin.load_state()
    summary = summarize(state)
    lines = [
        f"  📱 {BOLD}Онлайн-устройств:{NC} {summary.headline}",
        f"  🗂  {BOLD}Известно устройств:{NC} {summary.registered_devices} "
        f"{DIM}(по запросам подписки){NC}",
        "",
        f"{BOLD}{WHITE}Пользователи:{NC}",
    ]
    reported = [
        line
        for user in sorted(state.users, key=lambda item: item.email)
        for line in _user_lines(state, user)
    ]
    lines.extend(reported or [f"  {DIM}нет данных об устройствах{NC}"])
    if summary.over_limit_users:
        lines.extend(
            [
                "",
                f"  {YELLOW}Устройство сверх лимита отключается автоматически;{NC}",
                f"  {YELLOW}приоритет у тех, кто подключился раньше.{NC}",
            ],
        )
    lines.extend(
        [
            "",
            f"  {DIM}Устройство на канале данных — это адрес источника."
            f" HWID известен{NC}",
            f"  {DIM}только по запросам подписки и виден в карточке"
            f" пользователя.{NC}",
        ],
    )
    panel("📱  УСТРОЙСТВА И СЕССИИ", lines)
    print()
    prompt("Нажмите Enter")


__all__ = ["DeviceSummary", "_show_devices", "summarize"]
