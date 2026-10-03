"""Read-only local diagnostics shown only on a managed node."""

from __future__ import annotations

from hydra.core.state_models import AppState
from hydra.plugins.base import PluginCategory
from hydra.services.application import ApplicationService
from hydra.ui.protocol_ui import protocol_label
from hydra.ui.tui import CYAN, GREEN, NC, RED, YELLOW, clear, error, kv, menu, panel, prompt, title


def _identity_lines(app: ApplicationService) -> list[str]:
    try:
        identity = app.nodes.local_identity()
    except Exception as exc:
        return [kv("Удостоверение:", f"{RED}недоступно{NC}"), kv("Причина:", _reason(exc))]
    if identity is None:
        return [kv("Удостоверение:", f"{YELLOW}отсутствует{NC}")]
    return [
        kv("Нода:", f"{CYAN}{identity.node_id}{NC}"),
        kv("Адрес:", identity.address),
        kv("Control-порт:", str(identity.control_port)),
    ]


def _runtime_lines(state: AppState, app: ApplicationService) -> list[str]:
    lines: list[str] = []
    kernel = app.kernel.status(state).runtime
    lines.append(kv("Ядро:", f"{GREEN}запущено{NC}" if kernel.running else f"{RED}не запущено{NC}"))
    try:
        control_running = app.admin.unit_active("hydra-managed-node.service")
    except Exception:
        control_running = None
    lines.append(kv(
        "Management service:",
        f"{GREEN}работает{NC}" if control_running is True
        else f"{RED}остановлен{NC}" if control_running is False
        else f"{YELLOW}нет данных{NC}",
    ))
    apply_error = app.apply_error()
    if apply_error:
        lines.append(kv("Ошибка применения:", str(apply_error)[:256]))
    statuses = app.protocols.statuses(state)
    enabled_count = 0
    for plugin in app.protocols.list(PluginCategory.TRANSPORT):
        status = statuses.get(plugin.meta.name, {})
        if not status.get("enabled"):
            continue
        enabled_count += 1
        label = protocol_label(plugin.meta.name, getattr(plugin.meta, "display_name", ""))
        result = f"{GREEN}работает{NC}" if status.get("running") else f"{RED}остановлен{NC}"
        lines.append(kv(f"{label}:", result))
    if not enabled_count:
        lines.append(kv("Протоколы:", f"{YELLOW}не включены{NC}"))
    return lines


def run_node_emergency_menu(state: AppState, app: ApplicationService) -> None:
    """Expose local facts without opening base user, subscription or protocol management."""
    while True:
        state = app.admin.load_state()
        clear()
        title("РЕЖИМ НОДЫ · локальная диагностика")
        panel("УПРАВЛЕНИЕ", _identity_lines(app))
        print()
        panel("СОСТОЯНИЕ", _runtime_lines(state, app), wrap=True)
        print("Настройки и пользователями управляет основа; этот экран только для чтения.")
        choice = menu([("1", "Последняя ошибка применения", "только чтение"), ("0", "Выход", "")], "ДИАГНОСТИКА НОДЫ")
        if choice == "0":
            return
        if choice == "1":
            clear()
            title("Последняя ошибка применения")
            message = app.last_apply_error()
            if message:
                error(str(message)[:256])
            else:
                print("Ошибок применения не зафиксировано.")
            prompt("Нажмите Enter")


def _reason(exc: Exception) -> str:
    return str(exc) if str(exc) else type(exc).__name__


__all__ = ["run_node_emergency_menu"]
