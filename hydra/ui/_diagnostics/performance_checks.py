"""Network and CPU performance benchmarks for diagnostics."""
from __future__ import annotations

import concurrent.futures
import json
import re
import sys

from hydra.services.application import ApplicationService
from hydra.services.diagnostic_compatibility import (
    current_diagnostic_operations,
    operations_from_application,
)
from hydra.ui._diagnostics.system_checks import (
    ensure_packages,
    run_function_with_spinner,
    run_with_spinner,
)
from hydra.ui.tui import (
    BOLD,
    CYAN,
    DIM,
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


def test_iperf3_ru(app: ApplicationService):
    """Тест 4. Тест скорости до российских серверов через iPerf3"""
    clear()
    title("Тест скорости iPerf3 до серверов в РФ")
    print()

    if not ensure_packages(["iperf3", "ping"], app):
        return

    SERVERS = {
        "Москва": {"host": "spd-rudp.hostkey.ru", "fallback": "st.tver.ertelecom.ru"},
        "Санкт-Петербург": {"host": "st.spb.ertelecom.ru", "fallback": "st.yar.ertelecom.ru"},
        "Нижний Новгород": {"host": "st.nn.ertelecom.ru", "fallback": "speed-nn.vtt.net"},
        "Челябинск": {"host": "st.chel.ertelecom.ru", "fallback": "st.mgn.ertelecom.ru"},
        "Тюмень": {"host": "st.tmn.ertelecom.ru", "fallback": "st.krsk.ertelecom.ru"},
    }

    ports = [5201, 5202, 5203, 5204, 5205, 5206, 5207, 5208, 5209]

    operations = operations_from_application(app)

    def check_port(host, port):
        return port if operations.tcp_connect(host, port, 0.4) else None

    def find_active_port(host):
        with concurrent.futures.ThreadPoolExecutor(max_workers=9) as executor:
            futures = [executor.submit(check_port, host, p) for p in ports]
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res is not None:
                    return res
        return None

    def run_speed(host, port, reverse=False):
        cmd = ["iperf3", "-c", host, "-p", str(port), "-t", "4", "-P", "4", "-J"]
        if reverse:
            cmd.append("-R")
        try:
            r = app.admin.run_command(cmd, capture_output=True, text=True, timeout=6)
            if r.returncode != 0:
                return 0.0
            res_data = json.loads(r.stdout)
            sent = res_data.get("end", {}).get("sum_sent", {}).get("bits_per_second", 0)
            recv = res_data.get("end", {}).get("sum_received", {}).get("bits_per_second", 0)
            return max(sent, recv) / 1_000_000
        except Exception:
            return 0.0

    def get_ping(host):
        try:
            r = app.admin.run_command(["ping", "-c", "2", "-W", "1.5", host], capture_output=True, text=True, timeout=3.0)
            match = re.search(r"rtt min/avg/max/mdev = [\d\.]+/(?P<avg>[\d\.]+)/[\d\.]+/[\d\.]+", r.stdout)
            if match:
                return f"{float(match.group('avg')):.1f} ms"
        except Exception:
            pass
        return "N/A"

    def print_row(city, down_tuple, up_tuple, ping_tuple, end_char="\n"):
        val_down, col_down = down_tuple
        val_up, col_up = up_tuple
        val_ping, col_ping = ping_tuple

        p_down = f"{val_down:<16}"
        p_up = f"{val_up:<16}"
        p_ping = f"{val_ping:<12}"

        c_down = f"{col_down}{p_down}{NC}"
        c_up = f"{col_up}{p_up}{NC}"
        c_ping = f"{col_ping}{p_ping}{NC}"

        line = f"  {city:<20} │ {c_down} │ {c_up} │ {c_ping} "
        sys.stdout.write(f"  {CYAN}║{NC}{line}{CYAN}║{NC}{end_char}")
        sys.stdout.flush()

    print(f"  {CYAN}╔{'═' * 76}╗{NC}")
    print_row("Сервер", ("↓ Download", BOLD), ("↑ Upload", BOLD), ("Ping", BOLD))
    print(f"  {CYAN}╠{'═' * 76}╣{NC}")

    try:
        for city, cfg in SERVERS.items():
            print_row(city, ("Connecting...", YELLOW), ("", ""), ("—", ""), end_char="\r")

            def try_host(host):
                target_port = find_active_port(host)
                if not target_port:
                    return None

                ping_val = get_ping(host)
                print_row(city, ("Download...", CYAN), ("", ""), (ping_val, ""), end_char="\r")
                down_speed = run_speed(host, target_port, reverse=True)

                if down_speed == 0.0:
                    return None

                print_row(city, (f"{down_speed:.1f} Mbps", GREEN), ("Upload...", CYAN), (ping_val, ""), end_char="\r")
                up_speed = run_speed(host, target_port, reverse=False)

                return down_speed, up_speed, ping_val

            res = try_host(cfg["host"])
            if res is None:
                print_row(city, ("Fallback...", YELLOW), ("", ""), ("—", ""), end_char="\r")
                res = try_host(cfg["fallback"])

            if res is not None:
                down_speed, up_speed, ping_val = res
                print_row(city, (f"{down_speed:.1f} Mbps", GREEN), (f"{up_speed:.1f} Mbps", GREEN), (ping_val, ""), end_char="\n")
            else:
                print_row(city, ("Unavailable", RED), ("Unavailable", RED), ("—", RED), end_char="\n")

        print(f"  {CYAN}╚{'═' * 76}╝{NC}")

    except KeyboardInterrupt:
        sys.stdout.write("\r" + " " * 80 + "\r")
        print(f"  {CYAN}╚{'═' * 76}╝{NC}")
        print(f"\n\n  {RED}[!] Тест скорости прерван.{NC}")

    print()
    prompt("Нажмите Enter для возврата...")


def test_cpu_sysbench(app: ApplicationService):
    """Тест 6. Тест производительности процессора с помощью sysbench"""
    clear()
    title("Тестирование производительности процессора (sysbench)")
    print()

    if not ensure_packages(["sysbench"], app):
        return

    try:
        stdout = run_with_spinner("Вычисление производительности CPU", "sysbench cpu run --threads=1", app)

        events_per_sec = re.search(r"events per second:\s+([\d\.]+)", stdout)
        total_time = re.search(r"total time:\s+([\d\.]+s?)", stdout)
        total_events = re.search(r"total number of events:\s+(\d+)", stdout)
        min_lat = re.search(r"min:\s+([\d\.]+)", stdout)
        avg_lat = re.search(r"avg:\s+([\d\.]+)", stdout)
        max_lat = re.search(r"max:\s+([\d\.]+)", stdout)

        lines = []
        if events_per_sec:
            lines.append(kv("Производительность:", f"{GREEN}{events_per_sec.group(1)} событий/сек (однопоток){NC}"))
        if total_events:
            lines.append(kv("Всего событий:", total_events.group(1)))
        if total_time:
            lines.append(kv("Время теста:", total_time.group(1)))
        if avg_lat:
            lines.append(kv("Средний пинг (avg):", f"{avg_lat.group(1)} ms"))
        if min_lat:
            lines.append(kv("Миним. пинг (min):", f"{min_lat.group(1)} ms"))
        if max_lat:
            lines.append(kv("Максим. пинг (max):", f"{max_lat.group(1)} ms"))

        panel("💻  Результаты теста CPU (sysbench)", lines)

    except KeyboardInterrupt:
        pass
    except Exception as e:
        error(f"Не удалось выполнить тест: {e}")

    prompt("Нажмите Enter для возврата...")


def run_parallel_pings(nodes, app: ApplicationService):
    """Выполняет быстрый ICMP-пинг до всех серверов в пуле параллельно."""
    operations = operations_from_application(app)

    def get_ping_ms(host):
        try:
            r = app.admin.run_command(["ping", "-c", "2", "-W", "1.5", host], capture_output=True, text=True, timeout=3.0)
            match = re.search(r"rtt min/avg/max/mdev = [\d\.]+/(?P<avg>[\d\.]+)/[\d\.]+/[\d\.]+", r.stdout)
            if match:
                return f"{float(match.group('avg')):.1f} ms", float(match.group('avg'))
        except Exception:
            pass
        return "N/A", float('inf')

    results = {}
    def worker(node):
        host = operations.url_hostname(node["url"])
        ping_str, ping_val = get_ping_ms(host)
        return node["url"], (ping_str, ping_val)

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(worker, node): node for node in nodes}
        for future in concurrent.futures.as_completed(futures):
            url, res = future.result()
            results[url] = res
    return results


def run_http_speed(url):
    """Измеряет скорость скачивания HTTP-файла в течение 4 секунд."""
    return current_diagnostic_operations().download_speed_mbps(url)


def test_bench_speedtest(app: ApplicationService):
    """Тест 5. Тест скорости до зарубежных серверов (Global Speedtest с оптимизацией по пингу)"""
    clear()
    title("Тест скорости до зарубежных серверов (Global)")
    print()

    if not ensure_packages(["ping"], app):
        return

    choice = menu([
        ("1", "Быстрый тест (замер для 5 серверов с лучшим пингом)", "Экономит время"),
        ("2", "Полный тест (замер для всех доступных серверов)", "Занимает около 1 минуты"),
        ("0", "↩ Назад", "")
    ], "ВЫБОР РЕЖИМА ТЕСТА СКОРОСТИ")

    if choice == "0":
        return

    clear()
    title("Тест скорости до зарубежных серверов (Global)")
    print()

    NODES = [
        {"city": "Atlanta, GA, US", "provider": "Linode", "url": "http://speedtest.atlanta.linode.com/100MB-atlanta.bin"},
        {"city": "Dallas, TX, US", "provider": "Enzu", "url": "https://speedtest.dfw1.enzu.com/100MB.bin"},
        {"city": "Seattle, WA, US", "provider": "Datapacket", "url": "http://sea.download.datapacket.com/100mb.bin"},
        {"city": "San Francisco, CA, US", "provider": "HelioHost", "url": "http://heliohost.org/speedtest/100MB.bin"},
        {"city": "Washington, DC, US", "provider": "Leaseweb", "url": "http://speedtest.was1.us.leaseweb.net/100mb.bin"},
        {"city": "Sao Paulo, Brazil", "provider": "Linode", "url": "http://speedtest.sao-paulo.linode.com/100MB-sao-paulo.bin"},
        {"city": "Serangoon, Singapore", "provider": "Leaseweb", "url": "http://speedtest.sin1.sg.leaseweb.net/100mb.bin"},
        {"city": "Taipei, Taiwan", "provider": "Hinet", "url": "http://tpdb.speed2.hinet.net/test_100m.zip"},
        {"city": "Tokyo, Japan", "provider": "Linode", "url": "http://speedtest.tokyo2.linode.com/100MB-tokyo2.bin"},
        {"city": "Nuremberg, Germany", "provider": "Hetzner", "url": "https://nbg1-speed.hetzner.com/100MB.bin"},
        {"city": "Helsinki, Finland", "provider": "Hetzner", "url": "https://hel1-speed.hetzner.com/100MB.bin"},
        {"city": "Amsterdam, Netherlands", "provider": "Leaseweb", "url": "http://speedtest.ams1.nl.leaseweb.net/100mb.bin"},
        {"city": "Milan, Italy", "provider": "Linode", "url": "http://speedtest.milan.linode.com/100MB-milan.bin"},
        {"city": "Sydney, AU", "provider": "Datapacket", "url": "https://syd.download.datapacket.com/100mb.bin"},
    ]

    def print_row(loc, prov, speed_tuple, ping_tuple, end_char="\n"):
        val_speed, col_speed = speed_tuple
        val_ping, col_ping = ping_tuple

        p_speed = f"{val_speed:<14}"
        p_ping = f"{val_ping:<11}"

        c_speed = f"{col_speed}{p_speed}{NC}"
        c_ping = f"{col_ping}{p_ping}{NC}"

        line = f" {loc:<25} │ {prov:<14} │ {c_speed} │ {c_ping}  "
        sys.stdout.write(f"  {CYAN}║{NC}{line}{CYAN}║{NC}{end_char}")
        sys.stdout.flush()

    try:
        ping_results = run_function_with_spinner(
            "Измерение пинга до мировых серверов",
            run_parallel_pings,
            NODES,
            app,
        )

        # Сортируем ноды по пингу
        sorted_nodes = []
        for node in NODES:
            ping_str, ping_val = ping_results.get(node["url"], ("N/A", float('inf')))
            sorted_nodes.append((node, ping_str, ping_val))
        sorted_nodes.sort(key=lambda x: x[2])

        # В зависимости от выбора пользователя определяем список нод для замера скорости
        if choice == "1":
            active_urls = {item[0]["url"] for item in sorted_nodes[:5]}
        else:
            active_urls = {item[0]["url"] for item in sorted_nodes if item[2] != float('inf')}

        print(f"  {CYAN}╔{'═' * 76}╗{NC}")
        print_row("Локация", "Провайдер", ("↓ Speed", BOLD), ("Ping", BOLD))
        print(f"  {CYAN}╠{'═' * 76}╣{NC}")

        for node in NODES:
            loc = node["city"]
            prov = node["provider"]
            url = node["url"]
            ping_str, ping_val = ping_results.get(url, ("N/A", float('inf')))

            if url in active_urls and ping_val != float('inf'):
                print_row(loc, prov, ("Download...", CYAN), (ping_str, ""), end_char="\r")
                speed_mbps = run_http_speed(url)

                if speed_mbps > 0.0:
                    if speed_mbps >= 1000:
                        speed_str = f"{speed_mbps/1000:.1f} Gbps"
                    else:
                        speed_str = f"{speed_mbps:.1f} Mbps"
                    print_row(loc, prov, (speed_str, GREEN), (ping_str, ""), end_char="\n")
                else:
                    print_row(loc, prov, ("Unavailable", RED), (ping_str, RED), end_char="\n")
            else:
                # Нода пропущена
                speed_str = "—" if ping_val == float('inf') else "Skipped"
                print_row(loc, prov, (speed_str, DIM), (ping_str, ""), end_char="\n")

        print(f"  {CYAN}╚{'═' * 76}╝{NC}")

    except KeyboardInterrupt:
        sys.stdout.write("\r" + " " * 80 + "\r")
        print(f"  {CYAN}╚{'═' * 76}╝{NC}")
        print(f"\n  {RED}[!] Тест скорости прерван.{NC}")

    print()
    prompt("Нажмите Enter для возврата...")
