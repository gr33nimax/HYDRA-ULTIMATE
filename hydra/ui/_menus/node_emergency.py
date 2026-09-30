"""The only surface the interactive TUI offers when it runs on a node.

Normal management (users, subscriptions, protocol settings) belongs to the base
server. Local access exists to answer "what is broken" and nothing else, so this
module is deliberately read-only: it must never apply configuration, change
desired state or touch the host.
"""

from __future__ import annotations

from hydra.core.node_identity import load_node_identity
from hydra.core.state_models import AppState
from hydra.plugins.base import PluginCategory
from hydra.services.application import ApplicationService
from hydra.ui.tui import (
    CYAN,
    GREEN,
    NC,
    RED,
    YELLOW,
    clear,
    error,
    kv,
    menu,
    panel,
    prompt,
    title,
)


def _identity_lines() -> list[str]:
    """Describe how this node is registered, including a broken identity."""
    try:
        identity = load_node_identity()
    except ValueError as exc:
        return [
            kv("Удостоверение:", f"{RED}повреждено{NC}"),
            kv("Причина:", str(exc)),
        ]
    if identity is None:
        return [kv("Удостоверение:", f"{YELLOW}отсутствует{NC}")]
    return [
        kv("Нода:", f"{CYAN}{identity.node_id}{NC}"),
        kv("Основа:", identity.base_url),
    ]


def _runtime_lines(state: AppState, app: ApplicationService) -> list[str]:
    lines: list[str] = []
    kernel = app.kernel.status(state).runtime
    lines.append(
        kv(
            "Ядро:",
            f"{GREEN}запущено{NC}" if kernel.running else f"{RED}не запущено{NC}",
        ),
    )
    statuses = app.protocols.statuses(state)
    for plugin in app.protocols.list(PluginCategory.TRANSPORT):
        status = statuses.get(plugin.meta.name, {})
        if not status.get("enabled"):
            continue
        marker = f"{GREEN}работает{NC}" if status.get("running") else f"{RED}остановлен{NC}"
        lines.append(kv(f"  {plugin.meta.display_name}:", marker))
    if len(lines) == 1:
        lines.append(kv("Протоколы:", f"{YELLOW}не включены{NC}"))
    return lines


def _show_last_error(app: ApplicationService) -> None:
    clear()
    title("Последняя ошибка применения")
    message = app.last_apply_error()
    if message:
        error(message)
    else:
        print(f"{GREEN}Ошибок применения не зафиксировано.{NC}")
    journal = app.apply_journal()
    print(f"\nЖурнал применения: {journal}")
    prompt("Нажмите Enter")


def run_node_emergency_menu(
    state: AppState,
    app: ApplicationService,
) -> None:
    """Read-only local access on a node; no desired state or host changes."""
    while True:
        state = app.admin.load_state()
        clear()
        title("РЕЖИМ НОДЫ · аварийный доступ")
        panel("УДОСТОВЕРЕНИЕ", _identity_lines())
        print()
        panel("СОСТОЯНИЕ", _runtime_lines(state, app), wrap=True)
        print(f"Управление пользователями и настройками выполняет основной сервер.")
        choice = menu(
            [
                ("1", "📄 Последняя ошибка применения", "только чтение"),
                ("0", "🚪 Выход", ""),
            ],
            "АВАРИЙНЫЙ ДОСТУП",
        )
        if choice == "0":
            return
        if choice == "1":
            _show_last_error(app)


__all__ = ["run_node_emergency_menu"]
