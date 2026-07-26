"""User lifecycle and access-management menu controllers."""
from __future__ import annotations

import math
from datetime import datetime

from hydra.core.state_models import AppState, User
from hydra.plugins.base import PluginCategory
from hydra.services.application import ApplicationService
from hydra.services.user_access import (
    access_status as get_user_access_status,
    entitlement_status as get_user_entitlement_status,
)
from hydra.ui._menus.users_common import _application
from hydra.ui._menus.users_links import _show_subscription_links, _user_configs
from hydra.ui._menus.users_overview import _add_user, _select_user, _show_users
from hydra.ui._menus.users_subscription import menu_subscription_server
from hydra.ui.tui import (
    GREEN,
    NC,
    RED,
    _bytes_auto,
    clear,
    confirm,
    error,
    info,
    kv,
    menu,
    panel,
    prompt,
    success,
    title,
    warn,
)


def menu_users(state: AppState, app: ApplicationService | None = None):
    """Управление пользователями."""
    app = _application(app)
    while True:
        clear()
        title("Пользователи")

        total = len(state.users)
        active = sum(1 for user in state.users if get_user_access_status(user)[0])
        restricted = total - active
        info(
            f"Всего: {total}  |  Активных: {active}  |  "
            f"Ограничено: {restricted}"
        )
        print()

        choice = menu(
            [
                (
                    "1",
                    "📋 Список пользователей",
                    "Просмотр всех пользователей",
                ),
                (
                    "2",
                    "👤 Добавить пользователя",
                    "Создать нового пользователя",
                ),
                (
                    "3",
                    "🔧  Управление пользователем",
                    "Конфиги, блокировка, удаление",
                ),
                (
                    "4",
                    "🔗 Сервер подписок",
                    "Управление фоновым сервисом подписок",
                ),
                ("0", "↩ Назад", ""),
            ],
            "ПОЛЬЗОВАТЕЛИ",
        )

        if choice == "1":
            _show_users(state, app)
        elif choice == "2":
            _add_user(state, app)
        elif choice == "3":
            user = _select_user(state, app=app)
            if user:
                _user_detail_menu(state, user, app)
        elif choice == "4":
            menu_subscription_server(state, app)
        elif choice == "0":
            return


def _change_traffic_limit(
    state: AppState,
    user: User,
    app: ApplicationService,
) -> None:
    new_limit = prompt(
        "Введите лимит трафика в GiB "
        "(0 или пусто для безлимита)",
        default=str(user.traffic_limit_gb or ""),
    )
    try:
        value = float(new_limit) if new_limit.strip() else 0.0
        if not math.isfinite(value) or value < 0:
            raise ValueError
        user.traffic_limit_gb = value
        app.admin.save_state(state)
        label = f"{value:g} GiB" if value else "без ограничений"
        success(f"Лимит трафика: {label}")
        _reconcile_user_access(state, user, app)
    except ValueError:
        error("Лимит должен быть неотрицательным конечным числом.")
    prompt("Нажмите Enter")


def _change_expiry(
    state: AppState,
    user: User,
    app: ApplicationService,
) -> None:
    current = user.expiry_date[:10] if user.expiry_date else ""
    new_expiry = prompt(
        "Введите срок действия подписки "
        "(ГГГГ-ММ-ДД, или пусто для безлимита)",
        default=current,
    )
    if not new_expiry.strip():
        user.expiry_date = ""
        app.admin.save_state(state)
        success(f"Подписка для {user.email} сделана бессрочной")
    else:
        try:
            datetime.strptime(new_expiry.strip(), "%Y-%m-%d")
        except ValueError:
            error("Неверный формат даты! Используйте ГГГГ-ММ-ДД.")
            prompt("Нажмите Enter")
            return
        user.expiry_date = f"{new_expiry.strip()}T23:59:59Z"
        app.admin.save_state(state)
        success(
            f"Срок действия подписки для {user.email} "
            f"установлен до {new_expiry.strip()}"
        )
    _reconcile_user_access(state, user, app)
    prompt("Нажмите Enter")


def _user_detail_menu(
    state: AppState,
    user: User,
    app: ApplicationService | None = None,
):
    """Детальное меню пользователя с конфигами и управлением."""
    app = _application(app)
    while True:
        clear()
        app.traffic.refresh(state)

        available, access_reason = get_user_access_status(user)
        status_icon = f"{GREEN}🟢{NC}" if available else f"{RED}🔴{NC}"
        limit = f"{user.traffic_limit_gb:g} GiB" if user.traffic_limit_gb else "∞"
        expiry = user.expiry_date[:10] if user.expiry_date else "∞"
        panel(
            f"Пользователь: {user.email}",
            [
                kv("Статус:", f"{status_icon} {access_reason}"),
                kv(
                    "Трафик:",
                    f"{_bytes_auto(user.traffic_used_bytes)} / {limit}",
                ),
                kv("Действует до:", expiry),
                kv("Создан:", user.created_at[:10] if user.created_at else "—"),
                kv(
                    "Устройства:",
                    f"{len(user.devices)} / {user.device_limit}"
                    if user.device_limit
                    else f"{len(user.devices)} / ∞",
                ),
            ],
        )
        print()

        enabled_transports = app.protocols.enabled_subscription_names(
            state,
            PluginCategory.TRANSPORT,
        )
        if enabled_transports:
            info(
                "Включённые протоколы: "
                + ", ".join(sorted(enabled_transports))
            )
        else:
            warn("Нет включённых транспортных протоколов")
        print()

        block_label = "Разблокировать" if user.blocked else "Заблокировать"
        choice = menu(
            [
                (
                    "1",
                    "🔗 Ссылки подписки",
                    "Автоопределение клиента и специальные форматы",
                ),
                (
                    "2",
                    "📄 Ручные конфиги",
                    "Ссылки и конфиги отдельных протоколов",
                ),
                (
                    "3",
                    f"🔒🔓 {block_label}",
                    "Переключить статус блокировки",
                ),
                (
                    "4",
                    "📝 Изменить лимит трафика",
                    "Задать квоту трафика в GiB",
                ),
                (
                    "5",
                    "⏳ Изменить срок действия",
                    "Задать дату окончания подписки",
                ),
                ("6", "❌ Удалить", "Удалить пользователя"),
                (
                    "7",
                    "✏️ Переименовать",
                    "Изменить имя без смены UUID и ссылок",
                ),
                (
                    "8",
                    "📱 Лимит устройств",
                    "Настроить HWID-ограничение и сбросить привязки",
                ),
                ("0", "↩ Назад", ""),
            ],
            f"ПОЛЬЗОВАТЕЛЬ {user.email}",
        )

        if choice == "1":
            _show_subscription_links(state, user, app)
        elif choice == "2":
            _user_configs(state, user, app)
        elif choice == "3":
            _toggle_block(state, user, app)
        elif choice == "4":
            _change_traffic_limit(state, user, app)
        elif choice == "5":
            _change_expiry(state, user, app)
        elif choice == "6":
            if confirm(f"Удалить {user.email}?", default=False):
                app.remove_user(state, user.email)
                success(f"Пользователь {user.email} удалён")
                prompt("Нажмите Enter")
                return
        elif choice == "7":
            old_email = user.email
            new_email = prompt(
                "Новое имя пользователя",
                default=old_email,
            ).strip().lower()
            try:
                app.rename_user(state, old_email, new_email)
                success(
                    f"Пользователь {old_email} переименован в {new_email}",
                )
            except ValueError as exc:
                error(str(exc))
            prompt("Нажмите Enter")
        elif choice == "8":
            raw_limit = prompt(
                "Максимум устройств (0 = без ограничений)",
                default=str(user.device_limit),
            )
            try:
                device_limit = int(raw_limit)
                if device_limit < 0:
                    raise ValueError
                reset = confirm(
                    "Сбросить текущие HWID-привязки?",
                    default=False,
                )
                app.set_user_device_limit(
                    state,
                    user.email,
                    device_limit,
                    reset=reset,
                )
                success(
                    "Лимит устройств: "
                    f"{device_limit if device_limit else 'без ограничений'}"
                    + ("; привязки сброшены" if reset else ""),
                )
            except ValueError:
                error("Лимит должен быть целым неотрицательным числом.")
            prompt("Нажмите Enter")
        elif choice == "0":
            return


def _reconcile_user_access(
    state: AppState,
    user: User,
    app: ApplicationService | None = None,
) -> None:
    """Немедленно применяет новые TTL/квоту к серверным конфигурациям."""
    app = _application(app)
    entitled, reason = get_user_entitlement_status(user)
    if not entitled and not user.blocked:
        app.block_user(state, user.email)
        warn(f"Доступ отключён: {reason}.")
    elif entitled and user.blocked:
        if confirm(
            "Ограничения больше не превышены. "
            "Разблокировать пользователя?",
            default=True,
        ):
            app.unblock_user(state, user.email)
            success("Пользователь разблокирован")


def _toggle_block(
    state: AppState,
    user: User,
    app: ApplicationService | None = None,
):
    """Переключает блокировку пользователя."""
    app = _application(app)
    if user.blocked:
        entitled, reason = get_user_entitlement_status(user)
        if not entitled:
            error(
                f"Нельзя разблокировать: {reason}. "
                "Сначала измените лимит или срок действия."
            )
            prompt("Нажмите Enter")
            return
        app.unblock_user(state, user.email)
        success(f"{user.email} разблокирован")
    else:
        app.block_user(state, user.email)
        success(f"{user.email} заблокирован")
    prompt("Нажмите Enter")
