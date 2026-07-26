"""TUI rendering and dispatch for diagnostic collectors."""
from __future__ import annotations

from hydra.core.state_models import AppState
from hydra.services.application import ApplicationService
from hydra.services.system_monitoring_compatibility import (
    monitoring_from_application,
)
from hydra.ui.tui import clear, error, kv, menu, panel, prompt, title
from hydra.ui._diagnostics.collectors import (
    run_function_with_spinner,
    test_bench_speedtest,
    test_censorcheck,
    test_cpu_sysbench,
    test_ip_region,
    test_iperf3_ru,
)
from hydra.ui._diagnostics.report import run_diagnostics_report


def show_live_report(app: ApplicationService):
    """Run the runtime report, display it, then return to the menu."""
    clear()
    title("Диагностика HYDRA")
    print()
    try:
        report = run_function_with_spinner("Опрос состояния HYDRA и сервисов", run_diagnostics_report, app)
        print(report)
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        error(f"Не удалось получить диагностику: {exc}")
    prompt("Нажмите Enter для возврата в меню...")


# Keep the existing symbol used by callers/tests, but change its behavior from
# file export to an in-place runtime report.
test_generate_report = show_live_report


def menu_diagnostics(state: AppState, app: ApplicationService):
    """Меню раздела «Тестирование и диагностика VPS»"""
    monitoring = monitoring_from_application(app)
    while True:
        clear()
        
        load_str = "—"
        averages = monitoring.load_averages()
        if averages is not None:
            load_str = f"{averages[0]:.2f}, {averages[1]:.2f}"
                
        panel("🛠️  Тестирование и диагностика VPS", [
            kv("Загрузка CPU (LA):", load_str),
            kv("Текущее время:", monitoring.local_time("%Y-%m-%d %H:%M:%S")),
        ])
        
        choice = menu([
            ("1", "🌍 Сетевая идентификация (GeoIP)", "Анализ IP-адресов, ASN и геолокации"),
            ("2", "🛡️ Доступ к медиа-сервисам (Geoblocks)", "Тест ограничений OTT и ИИ-платформ"),
            ("3", "🛡️ Исходящая доступность с VPS (DPI)", "Проверка DNS, HTTP, TLS и возможных блокировок"),
            ("4", "🌐 Тест пропускной способности (Global)", "Замер скорости до мировых узлов"),
            ("5", "⚡ Тест пропускной способности (iPerf3 RU)", "Замер скорости до серверов в РФ"),
            ("6", "💻 Производительность процессора (Sysbench)", "Бенчмарк вычислительной мощности CPU"),
            ("7", "🔎 Диагностика HYDRA", "Сервисы, плагины, state и последнее применение"),
            ("0", "↩ Назад", "Возврат в главное меню")
        ], "ВЫБОР ДИАГНОСТИЧЕСКОГО ТЕСТА")
        
        if choice == "0":
            break
        elif choice == "1":
            test_ip_region()
        elif choice == "2":
            test_censorcheck("geoblock")
        elif choice == "3":
            test_censorcheck("dpi")
        elif choice == "4":
            test_bench_speedtest(app)
        elif choice == "5":
            test_iperf3_ru(app)
        elif choice == "6":
            test_cpu_sysbench(app)
        elif choice == "7":
            test_generate_report(app)
