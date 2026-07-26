"""Protocol status and realtime host metric adapters."""
from __future__ import annotations

from hydra.services.application import ApplicationService
from hydra.services.system_monitoring_compatibility import (
    legacy_system_monitoring,
    monitoring_from_application,
)
from hydra.ui import system_monitor
from hydra.ui._menus.monitoring_support import _application, _is_enter_pressed
from hydra.ui.tui import (
    BOLD,
    DIM,
    GREEN,
    NC,
    YELLOW,
    _bytes_auto,
    clear,
    prompt,
    title,
)


def _show_status(app: ApplicationService | None = None):
    app = _application(app)
    clear()
    title("🚦 Статус протоколов")
    print()
    statuses = app.protocols.statuses()
    print(
        f"  {BOLD}{'Протокол':<15} {'Порт':<7} {'Состояние':<12} "
        f"{'Автозапуск':<12}{NC}",
    )
    print(f"  {DIM}{'─' * 55}{NC}")
    for name, status in statuses.items():
        state_text = (
            f"{GREEN}запущен{NC}" if status["running"]
            else f"{YELLOW}остановлен{NC}" if status["installed"]
            else f"{DIM}не уст.{NC}"
        )
        port = str(status["port"]) if status["port"] else "—"
        autostart = "вкл" if status.get("enabled", False) else "выкл"
        print(
            f"  {name:<15} {port:<7} {state_text:<12} {autostart:<12}",
        )
    print()
    prompt("Нажмите Enter для возврата")


def _monitoring(app: ApplicationService | None):
    return (
        monitoring_from_application(app)
        if app is not None
        else legacy_system_monitoring()
    )


def _read_proc_cpu(
    app: ApplicationService | None = None,
) -> tuple[float, float]:
    return _monitoring(app).cpu_counters()


def _read_proc_mem(
    app: ApplicationService | None = None,
) -> tuple[int, int, float]:
    return _monitoring(app).memory_usage()


def _read_proc_net(
    app: ApplicationService | None = None,
) -> tuple[int, int]:
    return _monitoring(app).network_counters()


def _show_realtime_sys_monitor(
    app: ApplicationService | None = None,
):
    system_monitor.show_realtime(
        enter_pressed=_is_enter_pressed,
        bytes_auto=_bytes_auto,
        monitoring=_monitoring(app),
    )
