"""Realtime system metrics presentation over an injected monitoring port."""
from __future__ import annotations

from typing import Callable

from hydra.services.system_monitoring import SystemMonitoring
from hydra.services.system_monitoring_compatibility import (
    legacy_system_monitoring,
)
from hydra.ui.tui import (
    BOLD,
    CYAN,
    DIM,
    GREEN,
    NC,
    PANEL_W,
    clear,
    error,
    kv,
    panel,
    title,
)


def read_proc_cpu(stat_path: object | None = None) -> tuple[float, float]:
    """Compatibility wrapper for the host monitoring adapter."""

    return legacy_system_monitoring().cpu_counters(stat_path)


def read_proc_mem(
    meminfo_path: object | None = None,
) -> tuple[int, int, float]:
    """Compatibility wrapper for the host monitoring adapter."""

    return legacy_system_monitoring().memory_usage(meminfo_path)


def read_proc_net(
    route_path: object | None = None,
    dev_path: object | None = None,
) -> tuple[int, int]:
    """Compatibility wrapper for the host monitoring adapter."""

    return legacy_system_monitoring().network_counters(route_path, dev_path)


def show_realtime(
    *,
    enter_pressed: Callable[[], bool],
    bytes_auto: Callable[[int], str],
    monitoring: SystemMonitoring | None = None,
    read_cpu: Callable[[], tuple[float, float]] | None = None,
    read_mem: Callable[[], tuple[int, int, float]] | None = None,
    read_net: Callable[[], tuple[int, int]] | None = None,
) -> None:
    """Render realtime host metrics until Enter is pressed."""

    operations = monitoring or legacy_system_monitoring()
    cpu_reader = read_cpu or operations.cpu_counters
    memory_reader = read_mem or operations.memory_usage
    network_reader = read_net or operations.network_counters

    clear()
    print(f"\n  {BOLD}{CYAN}▸ Запуск живого мониторинга...{NC}")
    print(f"  {DIM}Нажмите [Enter] для возврата в меню.{NC}\n")
    operations.sleep(0.5)

    previous_network = network_reader()
    previous_idle, previous_total = cpu_reader()
    previous_time = operations.now()

    while True:
        try:
            if enter_pressed():
                return

            clear()
            title("📈 Живой мониторинг системы")
            print(
                f"  {DIM}Нажмите [Enter] для возврата в меню. "
                f"Обновление каждую секунду.{NC}",
            )
            print()

            sample = operations.snapshot()
            cpu_percent = sample.cpu_percent
            if cpu_percent is None:
                current_idle, current_total = cpu_reader()
                total_delta = current_total - previous_total
                idle_delta = current_idle - previous_idle
                cpu_percent = (
                    (total_delta - idle_delta) / total_delta * 100
                    if total_delta > 0
                    else 0.0
                )
                previous_idle, previous_total = current_idle, current_total

            memory_used, memory_total, memory_percent = memory_reader()
            if sample.memory_total:
                memory_used = sample.memory_used
                memory_total = sample.memory_total
                memory_percent = sample.memory_percent

            if sample.disk_total:
                disk_text = (
                    f"{sample.disk_percent:.1f}%  "
                    f"({bytes_auto(sample.disk_used)} / "
                    f"{bytes_auto(sample.disk_total)})"
                )
            else:
                disk_text = "н/д"

            current_network = network_reader()
            current_time = operations.now()
            elapsed = max(current_time - previous_time, 1.0)
            receive_speed = max(
                0.0,
                (current_network[0] - previous_network[0]) / elapsed,
            )
            transmit_speed = max(
                0.0,
                (current_network[1] - previous_network[1]) / elapsed,
            )
            previous_network = current_network
            previous_time = current_time

            panel(
                "Текущие параметры",
                [
                    kv("Загрузка CPU:", f"{cpu_percent:.1f}%"),
                    kv(
                        "Использование RAM:",
                        f"{memory_percent:.1f}%  "
                        f"({bytes_auto(memory_used)} / "
                        f"{bytes_auto(memory_total)})",
                    ),
                    kv("Дисковое пространство:", disk_text),
                    f"  {DIM}{'─' * (PANEL_W - 2)}{NC}",
                    kv(
                        "Сетевой вход (Rx):",
                        f"{GREEN}{bytes_auto(int(receive_speed))}/s{NC}",
                    ),
                    kv(
                        "Сетевой выход (Tx):",
                        f"{CYAN}{bytes_auto(int(transmit_speed))}/s{NC}",
                    ),
                ],
            )
            operations.sleep(1)
        except (KeyboardInterrupt, SystemExit):
            return
        except Exception as exc:
            error(f"Ошибка мониторинга: {exc}")
            operations.sleep(2)
