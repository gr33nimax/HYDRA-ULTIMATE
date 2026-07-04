import sys
import os
import time
import json
import shutil
import subprocess
import re
import socket
from pathlib import Path

from hydra.core.state import AppState
from hydra.ui.tui import (
    clear, title, info, success, warn, error, menu, prompt, panel, kv,
    confirm, _bytes_auto, _bar, _ok,
    GREEN, CYAN, YELLOW, RED, BOLD, DIM, WHITE, NC, PANEL_W
)

# ═════════════════════════════════════════════════════════════════════════════
#  Утилиты запуска и зависимостей
# ═════════════════════════════════════════════════════════════════════════════

def ensure_packages(pkgs: list[str]) -> bool:
    """Проверяет наличие бинарников в системе и при необходимости предлагает установить."""
    missing = []
    # Сопоставляем имя пакета с именем исполняемого бинарного файла
    pkg_to_binary = {
        "dnsutils": "dig",
        "netcat-openbsd": "nc",
        "netcat": "nc",
    }
    for pkg in pkgs:
        binary = pkg_to_binary.get(pkg, pkg)
        if not shutil.which(binary):
            missing.append(pkg)
            
    if not missing:
        return True
        
    warn(f"Для выполнения этого теста требуются утилиты: {', '.join(missing)}")
    if confirm("Установить их сейчас?", default=True):
        info("Обновляю список пакетов и устанавливаю зависимости...")
        # Так как менеджер запускается от root (проверено в main.py), sudo не требуется
        r = subprocess.run(f"apt-get update && apt-get install -y {' '.join(missing)}", shell=True)
        if r.returncode == 0:
            success("Зависимости успешно установлены")
            return True
        else:
            error("Не удалось установить зависимости")
            prompt("Нажмите Enter для продолжения...")
            return False
    return False


def run_with_spinner(title_text: str, cmd: str) -> str:
    """Запускает команду с плавной TUI-анимацией загрузки (spinner) и возвращает stdout."""
    process = subprocess.Popen(
        cmd,
        shell=True,
        executable="/bin/bash",
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, # Предотвращает deadlock при переполнении буфера stderr
        text=True,
    )
    
    spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    idx = 0
    try:
        while process.poll() is None:
            sys.stdout.write(f"\r  {CYAN}[{spinner[idx]}]{NC} {title_text}...")
            sys.stdout.flush()
            idx = (idx + 1) % len(spinner)
            time.sleep(0.1)
    except KeyboardInterrupt:
        process.terminate()
        process.wait()
        sys.stdout.write(f"\r  {RED}✗{NC} {title_text}: выполнение прервано.\n")
        sys.stdout.flush()
        raise KeyboardInterrupt

    stdout, _ = process.communicate()
    sys.stdout.write("\r" + " " * 80 + "\r")  # Очистка строки
    sys.stdout.flush()
    
    if process.returncode != 0:
        raise Exception(f"Команда завершилась с ошибкой ({process.returncode})")
        
    return stdout


def run_streaming_cmd(title_text: str, cmd: str):
    """Стримит вывод команды в реальном времени, фильтруя шум и оборачивая вывод в рамки HYDRA."""
    print(f"\n  {CYAN}╔{'═' * 76}╗{NC}")
    print(f"  {CYAN}║{NC} {BOLD}{title_text:<74}{NC} {CYAN}║{NC}")
    print(f"  {CYAN}╠{'═' * 76}╣{NC}")
    
    process = subprocess.Popen(
        cmd,
        shell=True,
        executable="/bin/bash",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    
    # Шумовые строки, которые лучше скрыть для чистоты интерфейса
    skip_patterns = [
        r"Performing IPv\d iperf3",
        r"Preparing system for disk tests",
        r"Generating fio test file",
        r"Running fio random mixed",
        r"yet-another-bench-script",
        r"masonr/yet-another-bench-script",
        r"# ## ## ## ## ## ## ##",
        r"wget -qO- bench.sh",
        r"Speedtest by Ookla"
    ]
    
    try:
        for line in process.stdout:
            cleaned = line.strip()
            if not cleaned:
                # Рисуем пустую строку внутри рамки
                sys.stdout.write(f"  {CYAN}║{NC}{' ' * 76}{CYAN}║{NC}\n")
                sys.stdout.flush()
                continue
                
            # Пропускаем шум
            should_skip = False
            for pat in skip_patterns:
                if re.search(pat, cleaned):
                    should_skip = True
                    break
            if should_skip:
                continue
                
            # Заменяем разделители на ровную линию рамки
            if all(c in "- ─" for c in cleaned) and len(cleaned) > 10:
                sys.stdout.write(f"  {CYAN}║{NC}{DIM}{'─' * 76}{NC}{CYAN}║{NC}\n")
                sys.stdout.flush()
                continue
                
            # Убираем перевод строки, заменяем табы на пробелы
            line_val = line.rstrip("\r\n").replace("\t", "    ")
            
            # Считаем видимую ширину без учета ANSI-последовательностей
            plain = re.sub(r"\033\[[0-9;]*m", "", line_val)
            visible_w = len(plain)
            
            if visible_w > 76:
                padded_line = line_val[:76]
            else:
                padded_line = line_val + " " * (76 - visible_w)
                
            sys.stdout.write(f"  {CYAN}║{NC}{padded_line}{CYAN}║{NC}\n")
            sys.stdout.flush()
            
    except KeyboardInterrupt:
        process.terminate()
        process.wait()
        sys.stdout.write("\r" + " " * 80 + "\r")
        print(f"  {CYAN}╚{'═' * 76}╝{NC}")
        print(f"\n  {RED}[!] Выполнение прервано.{NC}")
        raise KeyboardInterrupt
        
    process.wait()
    print(f"  {CYAN}╚{'═' * 76}╝{NC}")
    print()
    success("Тест завершен.")


def run_direct_cmd(title_text: str, cmd: str):
    """Очищает экран, выводит заголовок HYDRA и запускает команду напрямую (для поддержки интерактивных TUI-меню)."""
    clear()
    print(f"\n  {CYAN}╔{'═' * 76}╗{NC}")
    print(f"  {CYAN}║{NC} {BOLD}{title_text:<74}{NC} {CYAN}║{NC}")
    print(f"  {CYAN}╚{'═' * 76}╝{NC}\n")
    
    try:
        subprocess.run(cmd, shell=True, executable="/bin/bash")
    except KeyboardInterrupt:
        print(f"\n  {RED}[!] Выполнение прервано.{NC}")


# ═════════════════════════════════════════════════════════════════════════════
#  Реализация диагностических тестов
# ═════════════════════════════════════════════════════════════════════════════

def test_ip_region():
    """Тест 1. IP region (проверка региона IP через GeoIP и внешние сервисы)"""
    clear()
    title("Тестирование: IP region")
    print()
    
    if not ensure_packages(["wget", "curl", "jq"]):
        return
        
    try:
        stdout = run_with_spinner("Запрос геоданных IP", "bash <(wget -qO- https://ipregion.vrnt.xyz) -j")
        data = json.loads(stdout)
        
        lines = [
            f"  {BOLD}Основная информация:{NC}",
            "────────────────────────────────────────────────────────"
        ]
        if data.get("ipv4"):
            lines.append(kv("IPv4-адрес:", data["ipv4"]))
        if data.get("ipv6"):
            lines.append(kv("IPv6-адрес:", data["ipv6"]))
            
        res = data.get("results", {})
        
        if res.get("custom"):
            lines.append("")
            lines.append(f"  {BOLD}Доступ к популярным сервисам:{NC}")
            lines.append("────────────────────────────────────────────────────────")
            for item in res["custom"]:
                service = item.get("service", "")
                v4 = item.get("ipv4") or "—"
                v6 = item.get("ipv6") or "—"
                
                # Форматируем красивый статус
                v4_str = f"{GREEN}{v4}{NC}" if v4 not in ("—", "No", "N/A") else f"{RED}{v4}{NC}"
                v6_str = f"{GREEN}{v6}{NC}" if v6 not in ("—", "No", "N/A") else f"{RED}{v6}{NC}"
                lines.append(kv(f"{service}:", f"v4: {v4_str:<18} │ v6: {v6_str}"))
                
        if res.get("primary"):
            lines.append("")
            lines.append(f"  {BOLD}Базы GeoIP:{NC}")
            lines.append("────────────────────────────────────────────────────────")
            for item in res["primary"]:
                service = item.get("service", "")
                v4 = item.get("ipv4") or "—"
                v6 = item.get("ipv6") or "—"
                v4_str = f"{GREEN}{v4}{NC}" if v4 != "—" else f"{DIM}N/A{NC}"
                v6_str = f"{GREEN}{v6}{NC}" if v6 != "—" else f"{DIM}N/A{NC}"
                lines.append(kv(f"{service}:", f"v4: {v4_str:<18} │ v6: {v6_str}"))
                
        panel("🌍  Результаты IP Region", lines)
        
    except KeyboardInterrupt:
        pass
    except Exception as e:
        error(f"Не удалось выполнить тест: {e}")
        
    prompt("Нажмите Enter для возврата...")


def test_censorcheck(mode: str):
    """Тест 2 и 3. Censorcheck (geoblock или dpi) с нативным TUI"""
    clear()
    mode_title = "Гео-блокировки" if mode == "geoblock" else "DPI РФ"
    title(f"Тестирование: {mode_title}")
    print()
    
    if not ensure_packages(["wget", "curl", "jq", "dig"]):
        return
        
    try:
        stdout = run_with_spinner(
            "Анализ доступности ресурсов",
            f"bash <(wget -qO- https://github.com/vernette/censorcheck/raw/master/censorcheck.sh) --mode {mode} -j"
        )
        data = json.loads(stdout)
        results = data.get("results", [])
        
        lines = []
        for item in results:
            domain = item.get("service", "")
            http = item.get("http", {})
            https = item.get("https", {})
            
            http_v4 = http.get("ipv4") or {}
            https_v4 = https.get("ipv4") or {}
            
            def get_status_str(res_obj):
                if not res_obj or res_obj == "null":
                    return f"{DIM}N/A{NC}"
                status = res_obj.get("status")
                if status is None or str(status).lower() == "null":
                    return f"{DIM}N/A{NC}"
                
                try:
                    status_int = int(status)
                except ValueError:
                    return f"{YELLOW}{status}{NC}"
                    
                if status_int == 200:
                    return f"{GREEN}Доступен (200){NC}"
                elif status_int == -1:
                    return f"{RED}Блок (Порт){NC}"
                elif status_int == 0:
                    return f"{RED}Блок (Таймаут){NC}"
                elif 300 <= status_int < 400:
                    return f"{GREEN}Редирект ({status_int}){NC}"
                elif status_int == 403:
                    return f"{RED}Отказ (403){NC}"
                else:
                    return f"{YELLOW}Код {status_int}{NC}"
                    
            h_res = get_status_str(http_v4)
            s_res = get_status_str(https_v4)
            lines.append(kv(f"{domain}:", f"HTTP: {h_res:<25} │ HTTPS: {s_res}"))
            
        panel(f"🛡️  Результаты проверки: {mode_title}", lines)
        
    except KeyboardInterrupt:
        pass
    except Exception as e:
        error(f"Не удалось выполнить тест: {e}")
        
    prompt("Нажмите Enter для возврата...")


def test_iperf3_ru():
    """Тест 4. Нативный Python тест скорости до российских серверов через iPerf3"""
    clear()
    title("Тест скорости iPerf3 до серверов в РФ")
    print()
    
    if not ensure_packages(["iperf3", "ping"]):
        return
        
    SERVERS = {
        "Москва": {"host": "spd-rudp.hostkey.ru", "fallback": "st.tver.ertelecom.ru"},
        "Санкт-Петербург": {"host": "st.spb.ertelecom.ru", "fallback": "st.yar.ertelecom.ru"},
        "Нижний Новгород": {"host": "st.nn.ertelecom.ru", "fallback": "speed-nn.vtt.net"},
        "Челябинск": {"host": "st.chel.ertelecom.ru", "fallback": "st.mgn.ertelecom.ru"},
        "Тюмень": {"host": "st.tmn.ertelecom.ru", "fallback": "st.krsk.ertelecom.ru"},
    }
    
    ports = [5201, 5202, 5203, 5204, 5205, 5206, 5207, 5208, 5209]
    
    def check_port(host, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.8)
            s.connect((host, port))
            s.close()
            return True
        except Exception:
            return False
            
    def run_speed(host, port, reverse=False):
        # -R для тестирования скачивания (server to client)
        cmd = ["iperf3", "-c", host, "-p", str(port), "-t", "4", "-P", "4", "-J"]
        if reverse:
            cmd.append("-R")
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=6)
            if r.returncode != 0:
                return 0.0
            res_data = json.loads(r.stdout)
            sent = res_data.get("end", {}).get("sum_sent", {}).get("bits_per_second", 0)
            recv = res_data.get("end", {}).get("sum_received", {}).get("bits_per_second", 0)
            return max(sent, recv) / 1_000_000 # В Mbps
        except (subprocess.TimeoutExpired, Exception):
            return 0.0
            
    def get_ping(host):
        try:
            r = subprocess.run(["ping", "-c", "3", "-W", "2", host], capture_output=True, text=True, timeout=4)
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
                target_port = None
                for p in ports:
                    if check_port(host, p):
                        target_port = p
                        break
                if not target_port:
                    return None
                    
                ping_val = get_ping(host)
                
                print_row(city, ("Download...", CYAN), ("", ""), (ping_val, ""), end_char="\r")
                down_speed = run_speed(host, target_port, reverse=True)
                
                # Если тест скачивания выдал 0.0 (занят или ошибка), пробуем резервный
                if down_speed == 0.0:
                    return None
                    
                print_row(city, (f"{down_speed:.1f} Mbps", GREEN), ("Upload...", CYAN), (ping_val, ""), end_char="\r")
                up_speed = run_speed(host, target_port, reverse=False)
                
                return down_speed, up_speed, ping_val

            # Пробуем основной
            res = try_host(cfg["host"])
            
            # Если не вышло, пробуем резервный
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


# test_ip_quality удален


def test_cpu_sysbench():
    """Тест 8. Нативный тест CPU с помощью sysbench"""
    clear()
    title("Тестирование производительности процессора (sysbench)")
    print()
    
    if not ensure_packages(["sysbench"]):
        return
        
    try:
        stdout = run_with_spinner("Вычисление производительности CPU", "sysbench cpu run --threads=1")
        
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


def test_bench_speedtest():
    """Тест 5. Тест скорости до зарубежных серверов (вместо Bench.sh)"""
    clear()
    title("Тест скорости до зарубежных серверов (Global)")
    print()
    
    if not ensure_packages(["ping"]):
        return
        
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
        {"city": "Rotterdam, Netherlands", "provider": "id3.net", "url": "http://mirror.i3d.net/100mb.bin"},
        {"city": "Amsterdam, Netherlands", "provider": "Leaseweb", "url": "http://speedtest.ams1.nl.leaseweb.net/100mb.bin"},
        {"city": "Milan, Italy", "provider": "Linode", "url": "http://speedtest.milan.linode.com/100MB-milan.bin"},
        {"city": "Sydney, AU", "provider": "Datapacket", "url": "https://syd.download.datapacket.com/100mb.bin"},
    ]
    
    import urllib.request
    from urllib.parse import urlparse
    
    def get_ping(host):
        try:
            r = subprocess.run(["ping", "-c", "3", "-W", "2", host], capture_output=True, text=True, timeout=4)
            match = re.search(r"rtt min/avg/max/mdev = [\d\.]+/(?P<avg>[\d\.]+)/[\d\.]+/[\d\.]+", r.stdout)
            if match:
                return f"{float(match.group('avg')):.1f} ms"
        except Exception:
            pass
        return "N/A"

    def run_http_speed(url):
        try:
            start_time = time.time()
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=3.0) as response:
                bytes_downloaded = 0
                while True:
                    chunk = response.read(65536)
                    if not chunk:
                        break
                    bytes_downloaded += len(chunk)
                    elapsed = time.time() - start_time
                    if elapsed >= 4.0:
                        break
                if elapsed == 0:
                    return 0.0
                speed_bps = (bytes_downloaded * 8) / elapsed
                return speed_bps / 1_000_000 # В Mbps
        except Exception:
            return 0.0

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

    print(f"  {CYAN}╔{'═' * 76}╗{NC}")
    print_row("Локация", "Провайдер", ("↓ Speed", BOLD), ("Ping", BOLD))
    print(f"  {CYAN}╠{'═' * 76}╣{NC}")
    
    try:
        for node in NODES:
            loc = node["city"]
            prov = node["provider"]
            url = node["url"]
            
            print_row(loc, prov, ("Connecting...", YELLOW), ("—", ""), end_char="\r")
            
            host = urlparse(url).hostname
            ping_val = get_ping(host)
            
            print_row(loc, prov, ("Download...", CYAN), (ping_val, ""), end_char="\r")
            speed_mbps = run_http_speed(url)
            
            if speed_mbps > 0.0:
                if speed_mbps >= 1000:
                    speed_str = f"{speed_mbps/1000:.1f} Gbps"
                else:
                    speed_str = f"{speed_mbps:.1f} Mbps"
                print_row(loc, prov, (speed_str, GREEN), (ping_val, ""), end_char="\n")
            else:
                print_row(loc, prov, ("Unavailable", RED), (ping_val, RED), end_char="\n")
                
        print(f"  {CYAN}╚{'═' * 76}╝{NC}")
        
    except KeyboardInterrupt:
        sys.stdout.write("\r" + " " * 80 + "\r")
        print(f"  {CYAN}╚{'═' * 76}╝{NC}")
        print(f"\n  {RED}[!] Тест скорости прерван.{NC}")
        
    print()
    prompt("Нажмите Enter для возврата...")


# ═════════════════════════════════════════════════════════════════════════════
#  Главное меню раздела диагностики
# ═════════════════════════════════════════════════════════════════════════════

def menu_diagnostics(state: AppState):
    """Меню раздела «Тестирование и отладка»"""
    while True:
        clear()
        
        # Быстрая системная панель для диагностики
        load_str = "—"
        if os.name != "nt":
            try:
                avg1, avg5, _ = os.getloadavg()
                load_str = f"{avg1:.2f}, {avg5:.2f}"
            except Exception:
                pass
                
        panel("🛠️  Тестирование и диагностика VPS", [
            kv("Загрузка CPU (LA):", load_str),
            kv("Текущее время:", time.strftime("%Y-%m-%d %H:%M:%S")),
        ])
        
        choice = menu([
            ("1", "🌍 Геолокация и провайдер (GeoIP)", "Определение страны, города, провайдера и ASN"),
            ("2", "🛡️ Доступность ресурсов (Censorcheck)", "Проверка блокировок популярных зарубежных сайтов"),
            ("3", "🛡️ Обход DPI-фильтров (Censorcheck DPI)", "Тест прохождения трафика через цензуру провайдеров РФ"),
            ("4", "⚡ Тест скорости до РФ (iPerf3)", "Замер пропускной способности (Download/Upload) до узлов РФ"),
            ("5", "🌐 Тест скорости: Мир (Global)", "Тест скорости загрузки и Ping до мировых серверов"),
            ("6", "💻 Производительность CPU (Sysbench)", "Оценка вычислительной мощности процессора VPS в один поток"),
            ("0", "↩ Возврат в главное меню", "")
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
            test_iperf3_ru()
        elif choice == "5":
            test_bench_speedtest()
        elif choice == "6":
            test_cpu_sysbench()
