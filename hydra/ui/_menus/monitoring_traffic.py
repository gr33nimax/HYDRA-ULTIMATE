"""Traffic accounting controller for the monitoring UI."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from hydra.core.state_models import AppState
from hydra.plugins.base import PluginCategory
from hydra.services.application import ApplicationService
from hydra.ui._menus.monitoring_support import _application
from hydra.ui._menus.users import _select_user, _show_user_detail
from hydra.ui.protocol_ui import protocol_label
from hydra.ui.tui import (
    BOLD,
    CYAN,
    DIM,
    GREEN,
    NC,
    RED,
    YELLOW,
    _bytes_auto,
    clear,
    kv,
    menu,
    panel,
    title,
)


@dataclass(frozen=True)
class _TrafficView:
    state: AppState
    by_protocol: dict[str, int]
    enabled_names: set[str]
    names: list[str]
    labels: dict[str, str]
    aggregate_totals: dict[str, int]
    legacy_unattributed: int
    total_traffic: int


def _share_bar(value: int, total: int, width: int = 11) -> str:
    ratio = min(1.0, value / total) if total > 0 else 0.0
    filled = int(round(ratio * width))
    return (
        f"{CYAN}{'█' * filled}{DIM}{'░' * (width - filled)}{NC} "
        f"{ratio * 100:5.1f}%"
    )


def _load_traffic_view(app: ApplicationService) -> _TrafficView:
    state = app.traffic.refresh_state()
    by_protocol = app.traffic.protocol_totals(state)
    enabled_names = set(app.protocols.enabled_names(
        state,
        PluginCategory.TRANSPORT,
    ))
    order = [
        plugin.meta.name
        for plugin in app.protocols.list(PluginCategory.TRANSPORT)
    ]
    names = [
        name for name in order
        if name in enabled_names or by_protocol.get(name, 0)
    ]
    names.extend(
        sorted((enabled_names | set(by_protocol)) - set(names)),
    )
    labels = {
        name: app.protocols.display_name(name)
        for name in names
    }
    aggregate_totals = {
        name: int(stats.get("traffic_used_bytes", 0))
        for name, stats in state.install.get(
            "protocol_traffic_totals",
            {},
        ).items()
        if isinstance(stats, dict)
    }
    user_total = sum(
        max(0, int(user.traffic_used_bytes))
        for user in state.users
    )
    attributed_user_total = sum(
        max(0, int(stats.get("traffic_used_bytes", 0)))
        for user in state.users
        for stats in user.credentials.values()
        if isinstance(stats, dict)
    )
    legacy_unattributed = max(0, user_total - attributed_user_total)
    return _TrafficView(
        state=state,
        by_protocol=by_protocol,
        enabled_names=enabled_names,
        names=names,
        labels=labels,
        aggregate_totals=aggregate_totals,
        legacy_unattributed=legacy_unattributed,
        total_traffic=sum(by_protocol.values()) + legacy_unattributed,
    )


def _render_traffic_summary(view: _TrafficView) -> None:
    active_users = sum(not user.blocked for user in view.state.users)
    limited_users = sum(
        user.traffic_limit_gb > 0 for user in view.state.users
    )
    panel("📊 Сводка трафика", [
        kv(
            "Всего учтено:",
            f"{BOLD}{CYAN}{_bytes_auto(view.total_traffic)}{NC}",
        ),
        kv(
            "Пользователи:",
            f"{active_users} активны / {len(view.state.users)} всего",
        ),
        kv("С лимитом:", str(limited_users)),
    ])


def _render_protocol_traffic(view: _TrafficView) -> None:
    print()
    print(f"  {BOLD}По протоколам{NC}")
    print(
        f"  {BOLD}{'Протокол':<15} {'Трафик':>12}  {'Доля':<18} "
        f"{'Учёт':<13} {'Статус':<8}{NC}",
    )
    print(f"  {DIM}{'─' * 77}{NC}")
    for name in view.names:
        status = (
            f"{GREEN}включён{NC}"
            if name in view.enabled_names
            else f"{DIM}история{NC}"
        )
        accounting_text = (
            "общий" if name in view.aggregate_totals else "по пользов."
        )
        accounting_color = (
            YELLOW if name in view.aggregate_totals else DIM
        )
        value = view.by_protocol.get(name, 0)
        print(
            f"  {protocol_label(name, view.labels.get(name, '')):<15} "
            f"{GREEN}{_bytes_auto(value):>12}{NC}  "
            f"{_share_bar(value, view.total_traffic):<18} "
            f"{accounting_color}{accounting_text:<13}{NC} {status}",
        )
    if view.legacy_unattributed:
        print(
            f"  {'Старая статист.':<15} "
            f"{YELLOW}{_bytes_auto(view.legacy_unattributed):>12}{NC}  "
            f"{_share_bar(view.legacy_unattributed, view.total_traffic):<18} "
            f"{DIM}без разбивки{NC}",
        )
    print()


def _sorted_users(
    state: AppState,
    sort_by: str,
    show_zero_users: bool,
) -> list:
    users = list(state.users)
    if not show_zero_users:
        users = [user for user in users if user.traffic_used_bytes > 0]
    if sort_by == "traffic":
        users.sort(key=lambda user: user.traffic_used_bytes, reverse=True)
    elif sort_by == "name":
        users.sort(key=lambda user: user.email.lower())
    elif sort_by == "limit":
        users.sort(key=lambda user: user.traffic_limit_gb, reverse=True)
    elif sort_by == "expiry":
        users.sort(key=lambda user: user.expiry_date or "9999-12-31")
    return users


def _expiry_text(user) -> str:
    if not user.expiry_date:
        return "бессрочно"
    try:
        expiry = datetime.fromisoformat(user.expiry_date)
        delta = expiry - datetime.now(expiry.tzinfo)
        return f"{RED}истёк{NC}" if delta.days < 0 else f"{delta.days}дн"
    except Exception:
        return user.expiry_date[:10]


def _render_user_traffic(
    state: AppState,
    sort_by: str,
    show_zero_users: bool,
) -> None:
    users = _sorted_users(state, sort_by, show_zero_users)
    print(f"  {BOLD}По пользователям{NC}")
    print(
        f"  {BOLD}{'#':<3} {'Пользователь':<20} {'Трафик':>12} "
        f"{'Лимит':>10} {'Исп.':>7} {'Статус':<9} {'Срок':<10}{NC}",
    )
    print(f"  {DIM}{'─' * 77}{NC}")
    for index, user in enumerate(users, 1):
        used = user.traffic_used_bytes
        status_text = "блок" if user.blocked else "активен"
        status_color = RED if user.blocked else GREEN
        limit_bytes = int(user.traffic_limit_gb * 1073741824)
        limit = f"{user.traffic_limit_gb:.1f} GiB" if limit_bytes else "∞"
        usage = (
            f"{min(999, used / limit_bytes * 100):.0f}%"
            if limit_bytes else "—"
        )
        email = (
            user.email if len(user.email) <= 20
            else user.email[:17] + "..."
        )
        print(
            f"  {index:<3d} {BOLD}{email:<20}{NC} "
            f"{_bytes_auto(used):>12} {limit:>10} {usage:>7} "
            f"{status_color}{status_text:<9}{NC} "
            f"{_expiry_text(user):<10}",
        )
    if not users:
        print(f"  {DIM}Нет пользователей с ненулевым трафиком.{NC}")
    print(f"  {DIM}{'─' * 77}{NC}")
    print(f"  {DIM}Показано: {len(users)}/{len(state.users)}{NC}")
    print()


def _traffic_choice(
    state: AppState,
    sort_by: str,
    show_zero_users: bool,
    app: ApplicationService,
) -> tuple[str, bool, bool]:
    sort_labels = {
        "traffic": "по трафику", "name": "по имени",
        "limit": "по лимиту", "expiry": "по сроку",
    }
    choice = menu([
        ("1", f"{'✓ ' if sort_by == 'traffic' else ''}Сортировать по трафику", ""),
        ("2", f"{'✓ ' if sort_by == 'name' else ''}Сортировать по имени", ""),
        ("3", f"{'✓ ' if sort_by == 'limit' else ''}Сортировать по лимиту", ""),
        ("4", f"{'✓ ' if sort_by == 'expiry' else ''}Сортировать по сроку", ""),
        ("Z", "Показать всех пользователей" if not show_zero_users else "Скрыть пользователей без трафика", ""),
        ("D", "🔍 Статистика пользователя", ""),
        ("0", "↩ Назад", ""),
    ], f"УПРАВЛЕНИЕ · {sort_labels[sort_by].upper()}")
    if choice in {"1", "2", "3", "4"}:
        sort_by = {
            "1": "traffic", "2": "name", "3": "limit", "4": "expiry",
        }[choice]
    elif choice.upper() == "Z":
        show_zero_users = not show_zero_users
    elif choice.upper() == "D":
        user = _select_user(
            state,
            "Выберите пользователя для просмотра деталей",
            app,
        )
        if user:
            _show_user_detail(state, user, app)
    return sort_by, show_zero_users, choice == "0"


def _show_traffic_combined(
    state: AppState,
    app: ApplicationService | None = None,
):
    app = _application(app)
    sort_by = "traffic"
    show_zero_users = True
    while True:
        clear()
        title("📊 Потребление трафика")
        print()
        view = _load_traffic_view(app)
        state = view.state
        _render_traffic_summary(view)
        _render_protocol_traffic(view)
        _render_user_traffic(state, sort_by, show_zero_users)
        sort_by, show_zero_users, should_exit = _traffic_choice(
            state,
            sort_by,
            show_zero_users,
            app,
        )
        if should_exit:
            break
