"""Traffic accounting controller for the monitoring UI."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from hydra.core.state_models import AppState
from hydra.plugins.base import PluginCategory
from hydra.services.application import ApplicationService
from hydra.ui._menus.monitoring_support import (
    ACCOUNTING_WIDTH,
    PROTOCOL_WIDTH,
    SHARE_WIDTH,
    STATUS_WIDTH,
    TABLE_WIDTH,
    TRAFFIC_WIDTH,
    _application,
    _as_int,
    _cell,
    _share_bar,
    _status_text,
)
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
    confirm,
    kv,
    menu,
    panel,
    prompt,
    success,
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
    runtime: dict[str, tuple[bool, bool]]
    source_reasons: dict[str, str]


def _runtime_states(
    app: ApplicationService,
    state: AppState,
    names: list[str],
) -> dict[str, tuple[bool, bool]]:
    """Read installed/running per row through the protocol boundary."""
    runtime: dict[str, tuple[bool, bool]] = {}
    for name in names:
        try:
            status = app.protocols.status(name, state)
            runtime[name] = (bool(status.installed), bool(status.running))
        except Exception:
            runtime[name] = (False, False)
    return runtime


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
        name: _as_int(stats.get("traffic_used_bytes", 0))
        for name, stats in state.install.get(
            "protocol_traffic_totals",
            {},
        ).items()
        if isinstance(stats, dict)
    }
    user_total = sum(
        _as_int(user.traffic_used_bytes)
        for user in state.users
    )
    attributed_user_total = sum(
        _as_int(stats.get("traffic_used_bytes", 0))
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
        runtime=_runtime_states(app, state, names),
        source_reasons=app.traffic.source_availability(state),
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


def _protocol_row(view: _TrafficView, name: str) -> str:
    """Render one 77-cell protocol row from the shared column widths."""
    enabled = name in view.enabled_names
    installed, running = view.runtime.get(name, (False, False))
    status = _cell(_status_text(installed, enabled, running), STATUS_WIDTH)
    value = view.by_protocol.get(name, 0)
    if enabled and view.source_reasons.get(name, ""):
        traffic = _cell("—", TRAFFIC_WIDTH, ">")
        share = _cell(f"{YELLOW}источник недоступен{NC}", SHARE_WIDTH)
    else:
        traffic = _cell(f"{GREEN}{_bytes_auto(value)}{NC}", TRAFFIC_WIDTH, ">")
        share = _cell(_share_bar(value, view.total_traffic), SHARE_WIDTH)
    aggregate = name in view.aggregate_totals
    accounting = _cell(
        f"{YELLOW if aggregate else DIM}"
        f"{'общий' if aggregate else 'по пользов.'}{NC}",
        ACCOUNTING_WIDTH,
    )
    return (
        f"  {_cell(protocol_label(name, view.labels.get(name, '')), PROTOCOL_WIDTH)} "
        f"{traffic}  {share} {accounting} {status}"
    )


def _legacy_row(view: _TrafficView) -> str:
    value = view.legacy_unattributed
    return (
        f"  {_cell('Старая статист.', PROTOCOL_WIDTH)} "
        f"{_cell(f'{YELLOW}{_bytes_auto(value)}{NC}', TRAFFIC_WIDTH, '>')}  "
        f"{_cell(_share_bar(value, view.total_traffic), SHARE_WIDTH)} "
        f"{_cell(f'{DIM}без разбивки{NC}', ACCOUNTING_WIDTH)} "
        f"{_cell('', STATUS_WIDTH)}"
    )


def _render_protocol_traffic(view: _TrafficView) -> None:
    print()
    print(f"  {BOLD}По протоколам{NC}")
    print(
        f"  {BOLD}{_cell('Протокол', PROTOCOL_WIDTH)} "
        f"{_cell('Трафик', TRAFFIC_WIDTH, '>')}  "
        f"{_cell('Доля', SHARE_WIDTH)} "
        f"{_cell('Учёт', ACCOUNTING_WIDTH)} "
        f"{_cell('Статус', STATUS_WIDTH)}{NC}",
    )
    print(f"  {DIM}{'─' * TABLE_WIDTH}{NC}")
    for name in view.names:
        print(_protocol_row(view, name))
    if view.legacy_unattributed:
        print(_legacy_row(view))
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
        limit_bytes = _as_int(user.traffic_limit_gb * 1073741824)
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
        ("R", "♻️ Сбросить общую статистику", "Не меняет квоты пользователей"),
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
    elif choice.upper() == "R":
        if confirm(
            "Сбросить общую статистику трафика? Квоты пользователей сохранятся.",
            default=False,
        ):
            app.traffic.reset_global_report_state()
            success("Общая статистика трафика обнулена.")
            prompt("Нажмите Enter")
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
