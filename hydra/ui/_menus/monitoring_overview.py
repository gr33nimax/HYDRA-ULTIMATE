"""Monitoring overview and background-service navigation."""
from __future__ import annotations

from hydra.core.state_models import AppState
from hydra.plugins.base import PluginCategory
from hydra.services.application import ApplicationService
from hydra.services.system_monitoring_compatibility import (
    monitoring_from_application,
)
from hydra.ui._menus.monitoring_connections import _show_connections
from hydra.ui._menus.monitoring_devices import (
    _show_devices,
    summarize as _device_summary,
)
from hydra.ui._menus.monitoring_logs import _menu_logs
from hydra.ui._menus.monitoring_realtime import _show_realtime_sys_monitor
from hydra.ui._menus.monitoring_services import (
    _menu_clash_api,
    _menu_sync_agent,
)
from hydra.ui._menus.monitoring_support import _application, _unit_active
from hydra.ui._menus.monitoring_traffic import _show_traffic_combined
from hydra.ui.tui import (
    BOLD,
    CYAN,
    DIM,
    GREEN,
    NC,
    YELLOW,
    clear,
    kv,
    menu,
    panel,
)


def menu_monitoring(
    state: AppState,
    app: ApplicationService | None = None,
):
    app = _application(app)
    monitoring = monitoring_from_application(app)
    while True:
        state = app.admin.load_state()
        clear()

        load_str = "—"
        ram_str = "—"
        averages = monitoring.load_averages()
        if averages is not None:
            load_str = f"{averages[0]:.2f}, {averages[1]:.2f}"
        try:
            _, _, ram_percent = monitoring.memory_usage()
            ram_str = f"{ram_percent:.0f}%"
        except Exception:
            pass

        enabled_names = app.protocols.enabled_names(
            state,
            PluginCategory.TRANSPORT,
        )
        statuses = app.protocols.statuses(state)
        running_count = sum(
            int(bool(statuses.get(name, {}).get("running")))
            for name in enabled_names
        )
        users_count = len(state.users)
        active_users = sum(not user.blocked for user in state.users)
        sync_active = _unit_active("hydra-sync-agent.timer", app)
        traffic_active = _unit_active("hydra-traffic-daemon.service", app)

        lines = [
            f"  🔌 {BOLD}Протоколы:{NC} {GREEN}{running_count} работают{NC} / {len(enabled_names)} включено",
            f"  👥 {BOLD}Пользователи:{NC} {CYAN}{active_users} активны{NC} / {users_count} всего",
            f"  🖥️  {BOLD}Система:{NC} Load Avg {YELLOW}{load_str}{NC}  │  RAM {YELLOW}{ram_str}{NC}",
            f"  📱 {BOLD}Устройства:{NC} {_device_summary(state).headline}",
            f"  ⚙️  {BOLD}Фоновые службы:{NC} Sync Agent "
            f"{f'{GREEN}●{NC}' if sync_active else f'{DIM}○{NC}'}  Clash API "
            f"{f'{GREEN}●{NC}' if traffic_active else f'{DIM}○{NC}'}",
        ]
        panel("💻  Состояние системы", lines)

        choice = menu(
            [
                ("1", "📊 Потребление трафика", "Сводная статистика по протоколам и пользователям"),
                ("2", "🔌 Подключения и активность", "Активные сессии и недавние запросы пользователей"),
                ("3", "📈 Живой монитор CPU/RAM", "Нагрузка системы, скорость сети и метрики"),
                ("4", "📱 Устройства и сессии", "Кто подключён, с каких адресов и кто вне лимита"),
                ("5", "⚙️ Фоновые службы и логи", "Учёт трафика, синхронизация и системные журналы"),
                ("0", "↩ Назад", ""),
            ],
            "МОНИТОРИНГ",
        )
        if choice == "0":
            return
        if choice == "1":
            _show_traffic_combined(state, app)
        elif choice == "2":
            _show_connections(state, app)
        elif choice == "3":
            _show_realtime_sys_monitor(app)
        elif choice == "4":
            _show_devices(state, app)
        elif choice == "5":
            _menu_service_settings(state, app)


def _menu_service_settings(
    state: AppState,
    app: ApplicationService | None = None,
):
    app = _application(app)
    while True:
        state = app.admin.load_state()
        clear()
        sync_active = _unit_active("hydra-sync-agent.timer", app)
        clash_enabled = bool(getattr(state.network, "clash_api_enabled", False))
        traffic_active = _unit_active("hydra-traffic-daemon.service", app)
        panel("Фоновые службы", [
            kv("Sync Agent:", f"{GREEN}активно 🟢{NC}" if sync_active else f"{DIM}неактивно ⚪{NC}"),
            kv("Clash API:", (
                f"{GREEN}активно 🟢{NC}" if clash_enabled and traffic_active
                else f"{YELLOW}ошибка службы 🟡{NC}" if clash_enabled
                else f"{DIM}неактивно ⚪{NC}"
            )),
        ])
        choice = menu([
            ("1", "📋 Просмотр системных логов", "Sing-Box, Sync-Agent, Fail2ban и др."),
            ("2", "🔄 Sync Agent", "Проверка лимитов, сроков действия и обновление WARP-списков"),
            ("3", "📊 Clash API", "Локальный API Sing-Box и демон статистики трафика"),
            ("0", "↩ Назад", ""),
        ], "СЕРВИСНЫЕ НАСТРОЙКИ")

        if choice == "0":
            break
        if choice == "1":
            _menu_logs(state, app)
        elif choice == "2":
            _menu_sync_agent(state, app)
        elif choice == "3":
            _menu_clash_api(state, app)
