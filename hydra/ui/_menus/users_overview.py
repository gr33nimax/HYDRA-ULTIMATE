"""User selection, overview, and creation controllers."""
from __future__ import annotations

import re
import uuid as _uuid
from datetime import datetime

from hydra.core.state_models import AppState, User
from hydra.plugins.base import PluginCategory
from hydra.services.application import ApplicationService
from hydra.services.user_access import access_status as get_user_access_status
from hydra.ui._menus.users_common import _application
from hydra.ui.protocol_ui import protocol_label
from hydra.ui.tui import (
    BOLD,
    CYAN,
    DIM,
    GREEN,
    NC,
    RED,
    _bar,
    _bytes_auto,
    clear,
    error,
    info,
    kv,
    panel,
    prompt,
    success,
    title,
    warn,
)


def _select_user(
    state: AppState,
    prompt_text: str = "",
    app: ApplicationService | None = None,
) -> User | None:
    """Показывает нумерованный список пользователей и возвращает выбранного."""
    app = _application(app)
    if not state.users:
        warn("Нет пользователей.")
        return None

    app.traffic.refresh(state)
    print(f"\n  {CYAN}Пользователи:{NC}\n")
    for i, user in enumerate(state.users, 1):
        available, reason = get_user_access_status(user)
        icon = f"{GREEN}🟢{NC}" if available else f"{RED}🔴{NC}"
        used = _bytes_auto(user.traffic_used_bytes)
        limit = f"{user.traffic_limit_gb:g} GiB" if user.traffic_limit_gb else "∞"
        expiry = user.expiry_date[:10] if user.expiry_date else "∞"
        state_text = "" if available else f"  {RED}{reason}{NC}"
        print(
            f"  {i}. {icon} {BOLD}{user.email:<24}{NC}  "
            f"{used} / {limit}  до {expiry}{state_text}"
        )
    print()

    try:
        index = int(prompt(prompt_text or "Номер пользователя", "1")) - 1
    except ValueError:
        warn("Введите число.")
        return None
    if not 0 <= index < len(state.users):
        warn("Неверный номер.")
        return None
    return state.users[index]


def _show_user_detail(
    state: AppState,
    user: User,
    app: ApplicationService | None = None,
):
    """Monitoring-only user statistics without secrets or client links."""
    app = _application(app)
    clear()
    app.traffic.refresh(state)
    used = user.traffic_used_bytes
    limit = int(user.traffic_limit_gb * 1073741824) if user.traffic_limit_gb else 0
    status = (
        f"{RED}заблокирован 🔴{NC}"
        if user.blocked
        else f"{GREEN}активен 🟢{NC}"
    )
    expiry = user.expiry_date[:10] if user.expiry_date else "бессрочно"
    if user.expiry_date:
        try:
            expiry_dt = datetime.fromisoformat(user.expiry_date)
            remaining = (expiry_dt - datetime.now(expiry_dt.tzinfo)).days
            expiry = f"{expiry} · {'истёк' if remaining < 0 else f'{remaining} дн.'}"
        except (TypeError, ValueError):
            pass

    panel(
        f"👤 {user.email}",
        [
            kv("Статус:", status),
            kv("Трафик:", f"{BOLD}{_bytes_auto(used)}{NC}"),
            kv(
                "Лимит:",
                f"{user.traffic_limit_gb:g} GiB"
                if user.traffic_limit_gb
                else "без ограничений",
            ),
            *([kv("Прогресс:", _bar(used, limit))] if user.traffic_limit_gb else []),
            kv("Подписка:", expiry),
            kv("Создан:", user.created_at[:10] if user.created_at else "—"),
        ],
    )

    enabled_names = app.protocols.enabled_subscription_names(
        state,
        PluginCategory.TRANSPORT,
    )
    transport_plugins = app.protocols.list(PluginCategory.TRANSPORT)
    order = [
        plugin.meta.name
        for plugin in transport_plugins
        if plugin.meta.capabilities.subscription_enabled
    ]
    excluded_known = {
        plugin.meta.name
        for plugin in transport_plugins
        if not plugin.meta.capabilities.subscription_enabled
    }
    protocol_values = {
        name: max(0, int(stats.get("traffic_used_bytes", 0)))
        for name, stats in user.credentials.items()
        if isinstance(stats, dict)
    }
    names = [
        name
        for name in order
        if name in enabled_names or protocol_values.get(name, 0)
    ]
    names.extend(
        sorted(set(protocol_values) - set(names) - excluded_known),
    )
    attributed = sum(protocol_values.get(name, 0) for name in names)

    print()
    print(f"  {BOLD}Трафик по протоколам{NC}")
    print(f"  {BOLD}{'Протокол':<18} {'Накоплено':>14} {'Доля':>9}{NC}")
    print(f"  {DIM}{'─' * 45}{NC}")
    for name in names:
        value = protocol_values.get(name, 0)
        share = value / used * 100 if used else 0
        print(
            f"  {protocol_label(name, app.protocols.display_name(name)):<18} "
            f"{_bytes_auto(value):>14} {share:>8.1f}%"
        )
    legacy = max(0, used - attributed)
    if legacy:
        share = legacy / used * 100 if used else 0
        print(f"  {'Без разбивки':<18} {_bytes_auto(legacy):>14} {share:>8.1f}%")
    if not names and not legacy:
        print(f"  {DIM}Пользователь пока не расходовал трафик.{NC}")
    print(f"  {DIM}{'─' * 45}{NC}")
    print()
    prompt("Нажмите Enter")


def _show_users(
    state: AppState,
    app: ApplicationService | None = None,
):
    app = _application(app)
    clear()
    if not state.users:
        warn("Нет пользователей.")
        prompt("Нажмите Enter")
        return
    title("Список пользователей")
    print()
    app.traffic.refresh(state)
    print(
        f"  {BOLD}{'Пользователь':<30} {'Статус':<17} "
        f"{'Трафик':>20} {'Действует до':>12}{NC}"
    )
    print(f"  {DIM}{'─' * 83}{NC}")
    for user in sorted(state.users, key=lambda item: item.email.casefold()):
        available, reason = get_user_access_status(user)
        color = GREEN if available else RED
        limit = f"{user.traffic_limit_gb:g} GiB" if user.traffic_limit_gb else "∞"
        traffic = f"{_bytes_auto(user.traffic_used_bytes)} / {limit}"
        expiry = user.expiry_date[:10] if user.expiry_date else "∞"
        print(
            f"  {color}●{NC} {BOLD}{user.email:<28}{NC} "
            f"{color}{reason:<17}{NC} {traffic:>20} {expiry:>12}"
        )
    print()
    prompt("Нажмите Enter")


def _add_user(state: AppState, app: ApplicationService | None = None):
    """Добавляет пользователя и делегирует генерацию конфигов приложению."""
    app = _application(app)
    clear()
    title("Добавить пользователя")

    enabled_transports = app.protocols.enabled_subscription_names(
        state,
        PluginCategory.TRANSPORT,
    )
    if enabled_transports:
        protocol_names = ", ".join(sorted(enabled_transports))
        info(f"Конфиги будут созданы для: {protocol_names}")
    else:
        warn("Нет включённых протоколов — конфиги не будут созданы")
    print()

    email = prompt("Email пользователя").strip().lower()
    if not email:
        return
    if not re.fullmatch(r"\S+", email):
        error("Введите имя пользователя или email без пробелов.")
        prompt("Нажмите Enter")
        return
    if any(existing.email.casefold() == email.casefold() for existing in state.users):
        error(f"Пользователь {email} уже существует")
        prompt("Нажмите Enter")
        return

    user = User(
        email=email,
        uuid=str(_uuid.uuid4()),
        created_at=datetime.now().isoformat(),
    )
    app.add_user(state, user)
    success(f"Пользователь {email} создан")
    if enabled_transports:
        success(
            f"Конфиги сгенерированы для {len(enabled_transports)} протокол(ов)"
        )
    prompt("Нажмите Enter")
