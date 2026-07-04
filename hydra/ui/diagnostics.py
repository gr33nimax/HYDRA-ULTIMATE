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
    for pkg in pkgs:
        if not shutil.which(pkg):
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
        stderr=subprocess.PIPE,
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

    stdout, stderr = process.communicate()
    sys.stdout.write("\r" + " " * 80 + "\r")  # Очистка строки
    sys.stdout.flush()
    
    if process.returncode != 0:
        raise Exception(f"Команда завершилась с ошибкой ({process.returncode}): {stderr.strip()}")
        
    return stdout


def run_streaming_cmd(title_text: str, cmd: str):
    """Стримит вывод команды в реальном времени с отступом для TUI HYDRA."""
    print(f"\n  {CYAN}╔══════════════════════════════════════════════════════════════════════════════╗{NC}")
    print(f"  {CYAN}║{NC} {BOLD}{title_text:<76}{NC} {CYAN}║{NC}")
    print(f"  {CYAN}╚══════════════════════════════════════════════════════════════════════════════╝{NC}\n")
    
    process = subprocess.Popen(
        cmd,
        shell=True,
        executable="/bin/bash",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    
    try:
        # Стримим построчно
        for line in process.stdout:
            sys.stdout.write(f"  {line}")
            sys.stdout.flush()
    except KeyboardInterrupt:
        process.terminate()
        process.wait()
        print(f"\n  {RED}[!] Выполнение прервано пользователем.{NC}")
        raise KeyboardInterrupt
        
    process.wait()
    print()
    success("Тест завершен.")


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
    mode_title = "геоблоков" if mode == "geoblock" else "DPI"
    title(f"Тестирование: Censorcheck ({mode_title})")
    print()
    
    if not ensure_packages(["wget", "curl", "jq", "dig"]):
        return
        
    try:
        stdout = run_with_spinner(
            f"Проверка {mode_title}",
            f"bash <(wget -qO- https://github.com/vernette/censorcheck/raw/master/censorcheck.sh) --mode {mode} -j"
        )
        data = json.loads(stdout)
        results = data.get("results", [])
        
        lines = []
        for item in results:
            domain = item.get("domain", "")
            http = item.get("http", {})
            https = item.get("https", {})
            
            h_status = http.get("status", "N/A")
            h_code = http.get("code")
            s_status = https.get("status", "N/A")
            s_code = https.get("code")
            
            def get_status_str(status, code):
                if "Available" in status:
                    c = f" (code {code})" if code else ""
                    return f"{GREEN}Доступен{c}{NC}"
                elif "Blocked" in status:
                    return f"{RED}Заблокирован{NC}"
                else:
                    return f"{YELLOW}{status}{NC}"
                    
            h_res = get_status_str(h_status, h_code)
            s_res = get_status_str(s_status, s_code)
            lines.append(kv(f"{domain}:", f"HTTP: {h_res:<25} │ HTTPS: {s_res}"))
            
        panel(f"🛡️  Результаты Censorcheck ({mode.upper()})", lines)
        
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
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            return 0.0
        try:
            res_data = json.loads(r.stdout)
            sent = res_data.get("end", {}).get("sum_sent", {}).get("bits_per_second", 0)
            recv = res_data.get("end", {}).get("sum_received", {}).get("bits_per_second", 0)
            return max(sent, recv) / 1_000_000 # В Mbps
        except Exception:
            return 0.0
            
    def get_ping(host):
        r = subprocess.run(["ping", "-c", "3", "-W", "2", host], capture_output=True, text=True)
        match = re.search(r"rtt min/avg/max/mdev = [\d\.]+/(?P<avg>[\d\.]+)/[\d\.]+/[\d\.]+", r.stdout)
        if match:
            return f"{float(match.group('avg')):.1f} ms"
        return "N/A"

    print(f"  {BOLD}{'Сервер':<18} │ {'Скачивание':<14} │ {'Выгрузка':<14} │ {'Пинг':<10}{NC}")
    print(f"  {DIM}{'─' * 65}{NC}")
    
    try:
        for city, cfg in SERVERS.items():
            sys.stdout.write(f"  {city:<18} │ {YELLOW}Подключение...{NC}\r")
            sys.stdout.flush()
            
            # Ищем порт на основном сервере, если нет — на резервном
            target_host = cfg["host"]
            target_port = None
            for p in ports:
                if check_port(target_host, p):
                    target_port = p
                    break
            
            if not target_port:
                # Пробуем fallback
                target_host = cfg["fallback"]
                for p in ports:
                    if check_port(target_host, p):
                        target_port = p
                        break
            
            if not target_port:
                sys.stdout.write(f"  {city:<18} │ {RED}{'Недоступен':<14}{NC} │ {RED}{'—':<14}{NC} │ {RED}{'—':<10}{NC}\n")
                sys.stdout.flush()
                continue
                
            # Замеряем пинг
            ping_val = get_ping(target_host)
            
            # Тест скачивания
            sys.stdout.write(f"  {city:<18} │ {CYAN}{'Тест Down...':<14}{NC} │ {'':<14} │ {ping_val:<10}\r")
            sys.stdout.flush()
            down_speed = run_speed(target_host, target_port, reverse=True)
            
            # Тест выгрузки
            sys.stdout.write(f"  {city:<18} │ {GREEN}{down_speed:.1f} Mbps{NC:<14} │ {CYAN}{'Тест Up...':<14}{NC} │ {ping_val:<10}\r")
            sys.stdout.flush()
            up_speed = run_speed(target_host, target_port, reverse=False)
            
            sys.stdout.write(f"  {city:<18} │ {GREEN}{down_speed:.1f} Mbps{NC:<14} │ {GREEN}{up_speed:.1f} Mbps{NC:<14} │ {ping_val:<10}\n")
            sys.stdout.flush()
            
    except KeyboardInterrupt:
        print(f"\n\n  {RED}[!] Тест скорости прерван.{NC}")
        
    print()
    prompt("Нажмите Enter для возврата...")


def test_ip_quality(interactive: bool = False):
    """Тест 5 и 7. Проверка IP на блокировки и IPQuality (Check.Place) с парсингом в HYDRA TUI"""
    clear()
    test_title = "IPQuality (Check.Place -EI)" if interactive else "Блокировки зарубежными сервисами (IP.Check.Place)"
    title(f"Тестирование: {test_title}")
    print()
    
    if not ensure_packages(["curl", "jq"]):
        return
        
    cmd_args = "-j -l en -n"
    if interactive:
        # Для IPQuality добавляем флаг -EI
        cmd_args = "-j -l en -n -E"
        
    try:
        stdout = run_with_spinner("Анализ репутации IP", f"bash <(curl -Ls https://Check.Place) {cmd_args}")
        data = json.loads(stdout)
        
        # Парсим JSON и выводим
        lines = []
        
        # 1. Сводная инфа
        head = data.get("Head", {})
        info_sec = data.get("Info", {})
        
        lines.append(f"  {BOLD}Информация об IP:{NC}")
        lines.append("────────────────────────────────────────────────────────")
        lines.append(kv("IP-адрес:", head.get("IP", "N/A")))
        lines.append(kv("Тип IP:", info_sec.get("Type", "N/A")))
        lines.append(kv("Организация:", info_sec.get("Organization", "N/A")))
        
        region = info_sec.get("Region", {})
        if region:
            lines.append(kv("Регион:", f"{region.get('Name', 'N/A')} ({region.get('Code', 'N/A')})"))
        lines.append(kv("Временная зона:", info_sec.get("TimeZone", "N/A")))
        
        # 2. Оценки фрода / Risk Scores
        score = data.get("Score", {})
        if score:
            lines.append("")
            lines.append(f"  {BOLD}Оценки рисков фрода (Risk Scores):{NC}")
            lines.append("────────────────────────────────────────────────────────")
            for db, val in score.items():
                if val is not None and str(val).lower() != "null":
                    try:
                        clean_val = str(val).replace("%", "").strip()
                        val_num = float(clean_val)
                        if val_num > 50:
                            val_str = f"{RED}{val}{NC}"
                        elif val_num > 20:
                            val_str = f"{YELLOW}{val}{NC}"
                        else:
                            val_str = f"{GREEN}{val}{NC}"
                    except ValueError:
                        val_str = f"{GREEN}{val}{NC}" if str(val).lower() in ("0", "clean", "low") else f"{YELLOW}{val}{NC}"
                    lines.append(kv(f"{db}:", val_str))
                    
        # 3. Факторы угроз (Proxy, VPN, Tor)
        factor = data.get("Factor", {})
        if factor:
            lines.append("")
            lines.append(f"  {BOLD}Угрозы и классификация IP (Threat Factors):{NC}")
            lines.append("────────────────────────────────────────────────────────")
            for k, v in factor.items():
                if v is not None and str(v).lower() != "null":
                    v_str = str(v).lower()
                    if v_str in ("yes", "true", "1"):
                        v_colored = f"{RED}Да (Обнаружено){NC}"
                    elif v_str in ("no", "false", "0"):
                        v_colored = f"{GREEN}Нет (Чисто){NC}"
                    else:
                        v_colored = f"{YELLOW}{v}{NC}"
                    lines.append(kv(f"{k}:", v_colored))
                    
        # 4. Стриминг и ИИ (Media)
        media = data.get("Media", {})
        if media:
            lines.append("")
            lines.append(f"  {BOLD}Доступ к медиаресурсам:{NC}")
            lines.append("────────────────────────────────────────────────────────")
            for k, v in media.items():
                if v is not None and str(v).lower() != "null":
                    v_str = str(v).lower()
                    if v_str in ("yes", "true", "available", "original"):
                        v_colored = f"{GREEN}Доступен / Разблокирован{NC}"
                    elif v_str in ("no", "false", "blocked"):
                        v_colored = f"{RED}Заблокирован{NC}"
                    else:
                        v_colored = f"{YELLOW}{v}{NC}"
                    lines.append(kv(f"{k}:", v_colored))
                    
        panel("🛡️  Репутация и Качество IP", lines)
        
    except KeyboardInterrupt:
        pass
    except Exception as e:
        error(f"Не удалось выполнить тест: {e}")
        
    prompt("Нажмите Enter для возврата...")


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
            ("1", "🌍 IP region", "Проверка региона IP (ipregion.vrnt.xyz)"),
            ("2", "🛡️ Censorcheck (геоблок)", "Проверка геоблока сайтов и сервисов"),
            ("3", "🛡️ Censorcheck (DPI РФ)", "Проверка DPI блокировок на серверах РФ"),
            ("4", "⚡ Тест скорости до РФ (iPerf3)", "Нативный замер скорости скачивания и выгрузки"),
            ("5", "🚀 YABS (Yet Another Bench Script)", "Комплексный бенчмарк (стриминг fio, cpu, iperf)"),
            ("6", "🔒 Блокировки зарубежными сервисами", "Проверка IP сервера на зарубежные блокировки"),
            ("7", "📊 Bench.sh (Параметры сервера)", "Замер скорости к зарубежным провайдерам"),
            ("8", "🛡️ IPQuality (Check.Place -EI)", "Детальная проверка качества IP и VPN/Proxy детекта"),
            ("9", "💻 Тест процессора (sysbench)", "Нативный тест производительности CPU"),
            ("0", "↩ Назад", "")
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
            try:
                # YABS запускаем стримингом
                run_streaming_cmd("YABS Benchmark", "curl -sL yabs.sh | bash -s -- -4")
            except KeyboardInterrupt:
                pass
            prompt("Нажмите Enter...")
        elif choice == "6":
            test_ip_quality(interactive=False)
        elif choice == "7":
            try:
                # Bench.sh запускаем стримингом
                run_streaming_cmd("Bench.sh Benchmark", "wget -qO- bench.sh | bash")
            except KeyboardInterrupt:
                pass
            prompt("Нажмите Enter...")
        elif choice == "8":
            test_ip_quality(interactive=True)
        elif choice == "9":
            test_cpu_sysbench()
