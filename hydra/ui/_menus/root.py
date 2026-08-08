"""Root dashboard controller for the interactive TUI."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from hydra.core.state_models import AppState
from hydra.plugins.base import PluginCategory
from hydra.services.application import ApplicationService
from hydra.ui.tui import (
    BANNER,
    CYAN,
    DIM,
    GREEN,
    NC,
    YELLOW,
    _bytes_auto,
    _ok,
    clear,
    kv,
    menu,
    panel,
)


@dataclass(frozen=True)
class RootMenuDependencies:
    """Navigation callbacks supplied by the public UI adapter."""

    core: Callable[[AppState, ApplicationService], None]
    protocols: Callable[[AppState, ApplicationService], None]
    users: Callable[[AppState, ApplicationService], None]
    telegram: Callable[[AppState, ApplicationService], None]
    monitoring: Callable[[AppState, ApplicationService], None]
    security: Callable[[AppState, ApplicationService], None]
    network_services: Callable[[AppState, ApplicationService], None]
    diagnostics: Callable[[AppState, ApplicationService], None]
    headless_creator: Callable[[AppState, ApplicationService], None]


def _sys_info(state: AppState, app: ApplicationService) -> list[str]:
    """Render the host projection exposed by the administration port."""
    overview = app.admin.system_overview(state)
    lines: list[str] = []
    if overview.cpu_percent is not None:
        lines.append(kv("CPU:", f"{overview.cpu_percent:.0f}%"))
    if overview.load_averages is not None:
        first, fifth = overview.load_averages
        lines.append(kv("Load Avg:", f"{first:.2f}, {fifth:.2f}"))
    if overview.memory_percent is not None:
        lines.append(
            kv(
                "RAM:",
                f"{overview.memory_percent:.0f}%  "
                f"({_bytes_auto(overview.memory_used)} / "
                f"{_bytes_auto(overview.memory_total)})",
            ),
        )
    if overview.disk_percent is not None:
        lines.append(
            kv(
                "Диск:",
                f"{overview.disk_percent:.0f}%  "
                f"({_bytes_auto(overview.disk_used)} / "
                f"{_bytes_auto(overview.disk_total)})",
            ),
        )
    if overview.uptime_seconds is not None:
        days, remainder = divmod(overview.uptime_seconds, 86400)
        hours, remainder = divmod(remainder, 3600)
        lines.append(
            kv("Uptime:", f"{days}д {hours:02d}:{remainder // 60:02d}"),
        )

    flag = f" {overview.country_flag}" if overview.country_flag else ""
    if overview.public_ip == overview.local_ip:
        lines.append(kv("IP (Public):", f"{CYAN}{overview.public_ip}{NC}{flag}"))
    else:
        lines.append(
            kv(
                "IP (Pub/Loc):",
                f"{CYAN}{overview.public_ip}{NC}{flag} / "
                f"{DIM}{overview.local_ip}{NC}",
            ),
        )

    dns = overview.dns
    if overview.dnscrypt_active:
        suffix = (
            ", ".join(overview.dnscrypt_servers)
            if overview.dnscrypt_servers
            else "активен"
        )
        dns = f"{GREEN}DNSCrypt ({suffix}){NC}"
    lines.append(kv("DNS:", dns))
    return lines


def run_main_menu(
    state: AppState,
    app: ApplicationService,
    deps: RootMenuDependencies,
) -> None:
    """Run the root navigation loop using only application-level ports."""
    while True:
        state = app.admin.load_state()
        clear()
        print(BANNER)

        singbox = app.admin.singbox_diagnostics()
        statuses = app.protocols.statuses(state)
        counts: dict[PluginCategory, tuple[int, int]] = {}
        for category in (
            PluginCategory.TRANSPORT,
            PluginCategory.ENHANCEMENT,
            PluginCategory.SECURITY,
        ):
            plugins = app.protocols.list(category)
            counts[category] = (
                sum(
                    1
                    for plugin in plugins
                    if statuses.get(plugin.meta.name, {}).get("running")
                ),
                len(plugins),
            )

        active_users = sum(
            1 for user in app.users.list(state) if app.users.access_status(user)[0]
        )
        active_t, total_t = counts[PluginCategory.TRANSPORT]
        active_e, total_e = counts[PluginCategory.ENHANCEMENT]
        active_s, total_s = counts[PluginCategory.SECURITY]
        lines = [
            kv(
                "Sing-Box:",
                f"{_ok(singbox.installed and singbox.running)}  "
                f"{singbox.version or 'не установлен'}",
            ),
            kv("Протоколы:", f"{GREEN}{active_t}{NC}/{total_t} активны"),
            kv("Сетевые службы:", f"{GREEN}{active_e}{NC}/{total_e} активны"),
            kv("Безопасность:", f"{GREEN}{active_s}{NC}/{total_s} активны"),
            kv(
                "Пользователи:",
                f"{GREEN if active_users else YELLOW}{active_users}{NC} "
                f"из {len(state.users)}",
            ),
            *_sys_info(state, app),
        ]
        panel("Состояние", lines)

        choice = menu(
            [
                ("1", "📦 Ядро и система", "Sing-Box, зависимости и конфиг"),
                (
                    "2",
                    "🧩 Протоколы",
                    f"Транспортные протоколы  [{active_t}/{total_t}]",
                ),
                (
                    "3",
                    "👥 Пользователи",
                    f"Лимиты, TTL и подписки  [{active_users} активно]",
                ),
                ("4", "🤖 Telegram-боты", "Admin-панель и клиентский бот"),
                ("5", "📊 Мониторинг", "Трафик, статус, sync-агент и логи"),
                (
                    "6",
                    "🔒 Безопасность",
                    f"Fail2ban, Honeypot, IPBan  [{active_s}/{total_s}]",
                ),
                (
                    "7",
                    "🌐 Сетевые службы",
                    f"DNSCrypt и WARP  [{active_e}/{total_e}]",
                ),
                ("8", "🛠️  Тестирование и отладка", "Диагностика VPS"),
                ("9", "🎬 Headless Creator", "Общие room creators: VK, позже WB Stream"),
                ("0", "🚪 Выход", ""),
            ],
            "HYDRA MULTI-PROXY MANAGER",
        )
        if choice == "0":
            print(f"\n{GREEN}До свидания! 👋{NC}")
            return
        callback = {
            "1": deps.core,
            "2": deps.protocols,
            "3": deps.users,
            "4": deps.telegram,
            "5": deps.monitoring,
            "6": deps.security,
            "7": deps.network_services,
            "8": deps.diagnostics,
            "9": deps.headless_creator,
        }.get(choice)
        if callback is not None:
            callback(state, app)


__all__ = ["RootMenuDependencies", "_sys_info", "run_main_menu"]
