import sys
import os
import time
import json
import shutil
import subprocess
import re
import socket
import ssl
import urllib.request
import urllib.error
import concurrent.futures
import threading
from urllib.parse import urlparse
from pathlib import Path

from hydra.core.state import AppState
from hydra.ui.tui import (
    clear, title, info, success, warn, error, menu, prompt, panel, kv,
    confirm, _bytes_auto, _bar, _ok,
    GREEN, CYAN, YELLOW, RED, BOLD, DIM, WHITE, NC, PANEL_W
)

# ═════════════════════════════════════════════════════════════════════════════
#  Глобальные хуки и многопоточность для IP-версий
# ═════════════════════════════════════════════════════════════════════════════

_thread_local = threading.local()

# Переопределяем socket.getaddrinfo для поддержки принудительной фильтрации по семейству (IPv4/IPv6)
original_getaddrinfo = socket.getaddrinfo

def filtered_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    version = getattr(_thread_local, "ip_version", None)
    if version == 4:
        family = socket.AF_INET
    elif version == 6:
        family = socket.AF_INET6
    return original_getaddrinfo(host, port, family, type, proto, flags)

socket.getaddrinfo = filtered_getaddrinfo

def check_system_ipv6() -> bool:
    """Быстрая проверка доступности IPv6 на уровне операционной системы."""
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(1.0)
        s.connect(("2001:4860:4860::8888", 53))
        s.close()
        return True
    except Exception:
        return False

# Списки доменов для проверок блокировок
DPI_BLOCKED_SITES = [
    "youtube.com",
    "redirector.googlevideo.com",
    "discord.com",
    "instagram.com",
    "facebook.com",
    "x.com",
    "linkedin.com",
    "rutracker.org",
    "digitalocean.com",
    "amnezia.org",
    "getoutline.org",
    "mailfence.com",
    "flibusta.is",
    "rezka.ag",
    "api.telegram.org",
    "play.google.com"
]

GEO_BLOCKED_SITES = [
    "spotify.com",
    "netflix.com",
    "patreon.com",
    "swagger.io",
    "snyk.io",
    "mongodb.com",
    "autodesk.com",
    "graylog.org",
    "redis.io",
    "copilot.microsoft.com"
]

# ═════════════════════════════════════════════════════════════════════════════
#  Утилиты запуска и зависимостей
# ═════════════════════════════════════════════════════════════════════════════

def ensure_packages(pkgs: list[str]) -> bool:
    """Проверяет наличие бинарников в системе и при необходимости предлагает установить."""
    missing = []
    pkg_to_binary = {
        "dnsutils": "dig",
        "netcat-openbsd": "nc",
        "netcat": "nc",
        "bsdmainutils": "column",
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
    """Запускает системную команду с плавной TUI-анимацией загрузки (spinner) и возвращает stdout."""
    process = subprocess.Popen(
        cmd,
        shell=True,
        executable="/bin/bash",
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
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


def run_function_with_spinner(title_text: str, func, *args, **kwargs):
    """Запускает Python-функцию в фоновом потоке и показывает красивый спиннер в TUI."""
    result = []
    error_container = []
    
    def target():
        try:
            result.append(func(*args, **kwargs))
        except Exception as e:
            error_container.append(e)
            
    t = threading.Thread(target=target)
    t.start()
    
    spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    idx = 0
    try:
        while t.is_alive():
            sys.stdout.write(f"\r  {CYAN}[{spinner[idx]}]{NC} {title_text}...")
            sys.stdout.flush()
            idx = (idx + 1) % len(spinner)
            time.sleep(0.1)
    except KeyboardInterrupt:
        sys.stdout.write(f"\r  {RED}✗{NC} {title_text}: выполнение прервано.\n")
        sys.stdout.flush()
        raise KeyboardInterrupt
        
    sys.stdout.write("\r" + " " * 80 + "\r")  # Очистка строки
    sys.stdout.flush()
    
    if error_container:
        raise error_container[0]
        
    return result[0]


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
                sys.stdout.write(f"  {CYAN}║{NC}{' ' * 76}{CYAN}║{NC}\n")
                sys.stdout.flush()
                continue
                
            should_skip = False
            for pat in skip_patterns:
                if re.search(pat, cleaned):
                    should_skip = True
                    break
            if should_skip:
                continue
                
            if all(c in "- ─" for c in cleaned) and len(cleaned) > 10:
                sys.stdout.write(f"  {CYAN}║{NC}{DIM}{'─' * 76}{NC}{CYAN}║{NC}\n")
                sys.stdout.flush()
                continue
                
            line_val = line.rstrip("\r\n").replace("\t", "    ")
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
#  Нативные сетевые функции на Python (Взамен bash-скриптов)
# ═════════════════════════════════════════════════════════════════════════════

def make_http_request(url: str, method: str = "GET", headers: dict = None, body: str = None, timeout: float = 2.0) -> str:
    """Выполняет HTTP/HTTPS запрос с гибкими заголовками и отключенной валидацией SSL (для обхода перехватов)."""
    if headers is None:
        headers = {}
    if "User-Agent" not in headers:
        headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        
    req = urllib.request.Request(url, headers=headers, method=method)
    if body:
        req.data = body.encode("utf-8")
        if "Content-Type" not in headers:
            headers["Content-Type"] = "application/json"
            
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        try:
            return e.read().decode("utf-8", errors="ignore")
        except Exception:
            return ""
    except Exception:
        return ""


def get_ip_address(version: int = 4) -> str:
    """Нативно получает внешний IP-адрес для указанной версии протокола (IPv4/IPv6)."""
    _thread_local.ip_version = version
    try:
        urls = {
            4: ["https://v4.ident.me", "https://ipv4.icanhazip.com", "https://api4.ipify.org"],
            6: ["https://v6.ident.me", "https://ipv6.icanhazip.com", "https://api6.ipify.org"]
        }
        for url in urls[version]:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "curl/7.81.0"})
                with urllib.request.urlopen(req, timeout=2.0) as resp:
                    ip = resp.read().decode("utf-8").strip()
                    if ip and ("." in ip or ":" in ip):
                        return ip
            except Exception:
                continue
        return ""
    finally:
        _thread_local.ip_version = None


def query_primary_geoip(ip: str, service: str) -> str:
    """Запрашивает код страны IP-адреса из выбранной базы GeoIP."""
    if not ip or ip == "—":
        return "—"
        
    # Определяем версию IP для подключения к сервису
    is_target_ipv6 = ":" in ip
    if is_target_ipv6 and service in ("MAXMIND", "CLOUDFLARE"):
        conn_ip_version = 6
    else:
        conn_ip_version = 4

    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0"}
    if service == "IPREGISTRY":
        headers["Origin"] = "https://ipregistry.co"
    elif service == "MAXMIND":
        headers["Referer"] = "https://www.maxmind.com"
    elif service == "IPAPI_COM":
        headers["Origin"] = "https://ip-api.com"
    elif service == "CLOUDFLARE":
        headers["Referer"] = "https://speed.cloudflare.com"

    urls = {
        "MAXMIND": "https://geoip.maxmind.com/geoip/v2.1/city/me",
        "IPINFO_IO": f"https://ipinfo.io/widget/demo/{ip}",
        "IPREGISTRY": f"https://api.ipregistry.co/{ip}?hostname=true&key=sb69ksjcajfs4c",
        "IPAPI_CO": f"https://ipapi.co/{ip}/json/",
        "CLOUDFLARE": "https://speed.cloudflare.com/meta",
        "IFCONFIG_CO": f"https://ifconfig.co/country-iso?ip={ip}",
        "IPAPI_COM": f"http://ip-api.com/json/{ip}?fields=countryCode",
        "IPWHO_IS": f"https://ipwho.is/{ip}",
        "IP2LOCATION_IO": f"https://api.ip2location.io/?ip={ip}"
    }
    
    url = urls.get(service)
    if not url:
        return "—"
        
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    _thread_local.ip_version = conn_ip_version
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, context=ctx, timeout=2.0) as resp:
            data = resp.read().decode("utf-8", errors="ignore")
            if service == "MAXMIND":
                val = json.loads(data).get("country", {}).get("iso_code")
                return val.upper() if val else "—"
            elif service == "IPINFO_IO":
                val = json.loads(data).get("data", {}).get("country")
                return val.upper() if val else "—"
            elif service == "IPREGISTRY":
                val = json.loads(data).get("location", {}).get("country", {}).get("code")
                return val.upper() if val else "—"
            elif service == "IPAPI_CO":
                val = json.loads(data).get("country")
                return val.upper() if val else "—"
            elif service == "CLOUDFLARE":
                val = json.loads(data).get("country")
                return val.upper() if val else "—"
            elif service == "IFCONFIG_CO":
                return data.strip().upper()
            elif service == "IPAPI_COM":
                val = json.loads(data).get("countryCode")
                return val.upper() if val else "—"
            elif service == "IPWHO_IS":
                val = json.loads(data).get("country_code")
                return val.upper() if val else "—"
            elif service == "IP2LOCATION_IO":
                val = json.loads(data).get("country_code")
                return val.upper() if val else "—"
    except Exception:
        pass
    finally:
        _thread_local.ip_version = None
        
    # Fallback to ip-api.com (which is IPv4-only) to avoid N/A on rate-limits/blocks/ssl errors
    _thread_local.ip_version = 4
    try:
        fallback_url = f"http://ip-api.com/json/{ip}?fields=countryCode"
        req = urllib.request.Request(fallback_url, headers=headers)
        with urllib.request.urlopen(req, context=ctx, timeout=1.5) as resp:
            res_data = json.loads(resp.read().decode("utf-8"))
            val = res_data.get("countryCode")
            return val.upper() if val else "—"
    except Exception:
        pass
    finally:
        _thread_local.ip_version = None
        
    return "—"


def check_custom_service(service_name: str, ip_version: int, system_has_ipv6: bool) -> str:
    """Тестирует геоблокировку популярных стримингов и сервисов через указанную версию IP."""
    _thread_local.ip_version = ip_version
    if ip_version == 6 and not system_has_ipv6:
        return "—"
        
    try:
        if service_name == "Google":
            response = make_http_request("https://accounts.google.com/v3/signin/identifier?flowName=GlifSetupAndroid")
            match = re.search(r'name="region"\s+value="([^"]*)"', response)
            return match.group(1).upper() if match else "No"
        elif service_name == "YouTube":
            response = make_http_request("https://www.youtube.com/sw.js_data")
            if response.startswith(")]}'"):
                response = response[4:].strip()
            data = json.loads(response)
            return data[0][2][0][0][1].upper()
        elif service_name == "Twitch":
            body = '[{"operationName":"VerifyEmail_CurrentUser","variables":{},"extensions":{"persistedQuery":{"version":1,"sha256Hash":"f9e7dcdf7e99c314c82d8f7f725fab5f99d1df3d7359b53c9ae122deec590198"}}}]'
            headers = {"Client-Id": "kimne78kx3ncx6brgo4mv6wki5h1ko"}
            response = make_http_request("https://gql.twitch.tv/gql", method="POST", headers=headers, body=body)
            data = json.loads(response)
            return data[0]["data"]["requestInfo"]["countryCode"].upper()
        elif service_name == "ChatGPT":
            headers = {"Statsig-Api-Key": "client-zUdXdSTygXJdzoE0sWTkP8GKTVsUMF2IRM7ShVO2JAG"}
            response = make_http_request("https://ab.chatgpt.com/v1/initialize", method="POST", headers=headers, body="{}")
            data = json.loads(response)
            return data["derived_fields"]["country"].upper()
        elif service_name == "Netflix":
            response = make_http_request("https://api.fast.com/netflix/speedtest/v2?https=true&token=YXNkZmFzZGxmbnNkYWZoYXNkZmhrYWxm&urlCount=1")
            data = json.loads(response)
            return data["client"]["location"]["country"].upper()
        elif service_name == "Spotify":
            headers = {"X-Client-Id": "9a8d2f0ce77a4e248bb71fefcb557637"}
            response = make_http_request("https://spclient.wg.spotify.com/signup/public/v1/account/?validate=1&key=142b583129b2df829de3656f9eb484e6", headers=headers)
            data = json.loads(response)
            return data.get("country", "").upper()
    except Exception:
        pass
    finally:
        _thread_local.ip_version = None
    return "No"


def check_domain_censor(domain: str, secure: bool = True) -> int:
    """Выполняет проверку доступности конкретного домена по HTTP/HTTPS (возвращает статус-код или код ошибки)."""
    url = f"{'https' if secure else 'http'}://{domain}"
    ctx = None
    if secure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=2.0) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except urllib.error.URLError as e:
        reason = str(e.reason).lower()
        if "timed out" in reason or "timeout" in reason:
            return 0
        elif "reset" in reason or "connection reset" in reason:
            return -2
        elif "refused" in reason:
            return -1
        elif "not known" in reason or "resolve" in reason:
            return -3
        else:
            return 0
    except (socket.timeout, TimeoutError):
        return 0
    except ConnectionResetError:
        return -2
    except ConnectionRefusedError:
        return -1
    except Exception:
        return 0


def run_censorcheck_python(mode: str) -> dict:
    """Запускает параллельные проверки доступности доменов в зависимости от выбранного режима."""
    domains = GEO_BLOCKED_SITES if mode == "geoblock" else DPI_BLOCKED_SITES
    results = []
    
    def worker(domain):
        http_status = check_domain_censor(domain, secure=False)
        https_status = check_domain_censor(domain, secure=True)
        return {
            "service": domain,
            "http": {
                "ipv4": {"status": http_status}
            },
            "https": {
                "ipv4": {"status": https_status}
            }
        }
        
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(worker, d): d for d in domains}
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
            
    # Сортируем результаты по алфавиту для красоты
    results.sort(key=lambda x: x["service"])
    return {"results": results}


# ═════════════════════════════════════════════════════════════════════════════
#  Реализация диагностических тестов (Вызываются из TUI)
# ═════════════════════════════════════════════════════════════════════════════

def test_ip_region():
    """Тест 1. IP region (определение геопозиции по базам GeoIP и стримингам)"""
    clear()
    title("Тестирование: IP region")
    print()
    
    system_has_ipv6 = check_system_ipv6()
    
    def fetch_data():
        ipv4 = get_ip_address(4) or "—"
        ipv6 = get_ip_address(6) or "—"
        
        # Получаем детальную инфу для IPv4
        v4_detail = {"isp": "—", "asn": "—", "location": "—"}
        if ipv4 and ipv4 != "—":
            try:
                headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0"}
                req = urllib.request.Request(f"http://ip-api.com/json/{ipv4}", headers=headers)
                with urllib.request.urlopen(req, timeout=2.0) as resp:
                    res_data = json.loads(resp.read().decode("utf-8"))
                    if res_data.get("status") == "success":
                        v4_detail["isp"] = res_data.get("isp") or res_data.get("org") or "—"
                        as_val = res_data.get("as", "—")
                        v4_detail["asn"] = as_val.split()[0] if as_val and as_val != "—" else "—"
                        
                        loc_parts = []
                        if res_data.get("country"):
                            loc_parts.append(res_data["country"])
                        if res_data.get("city"):
                            loc_parts.append(res_data["city"])
                        v4_detail["location"] = ", ".join(loc_parts) if loc_parts else "—"
            except Exception:
                pass

        # Получаем детальную инфу для IPv6
        v6_detail = {"isp": "—", "asn": "—", "location": "—"}
        if ipv6 and ipv6 != "—":
            try:
                headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0"}
                req = urllib.request.Request(f"http://ip-api.com/json/{ipv6}", headers=headers)
                with urllib.request.urlopen(req, timeout=2.0) as resp:
                    res_data = json.loads(resp.read().decode("utf-8"))
                    if res_data.get("status") == "success":
                        v6_detail["isp"] = res_data.get("isp") or res_data.get("org") or "—"
                        as_val = res_data.get("as", "—")
                        v6_detail["asn"] = as_val.split()[0] if as_val and as_val != "—" else "—"
                        
                        loc_parts = []
                        if res_data.get("country"):
                            loc_parts.append(res_data["country"])
                        if res_data.get("city"):
                            loc_parts.append(res_data["city"])
                        v6_detail["location"] = ", ".join(loc_parts) if loc_parts else "—"
            except Exception:
                pass
        
        primary_services = ["MAXMIND", "IPINFO_IO", "CLOUDFLARE", "IPREGISTRY", "IPAPI_CO", "IPAPI_COM", "IPWHO_IS", "IP2LOCATION_IO"]
        custom_services = ["Google", "YouTube", "Twitch", "ChatGPT", "Netflix", "Spotify"]
        
        primary_results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            v4_futures = {executor.submit(query_primary_geoip, ipv4, s): s for s in primary_services}
            v6_futures = {executor.submit(query_primary_geoip, ipv6, s): s for s in primary_services}
            
            v4_res = {v4_futures[f]: f.result() for f in concurrent.futures.as_completed(v4_futures)}
            v6_res = {v6_futures[f]: f.result() for f in concurrent.futures.as_completed(v6_futures)}
            
            for s in primary_services:
                primary_results.append({
                    "service": s,
                    "ipv4": v4_res.get(s, "—"),
                    "ipv6": v6_res.get(s, "—")
                })
        
        custom_results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
            v4_futures = {executor.submit(check_custom_service, s, 4, system_has_ipv6): s for s in custom_services}
            v6_futures = {executor.submit(check_custom_service, s, 6, system_has_ipv6): s for s in custom_services}
            
            v4_res = {v4_futures[f]: f.result() for f in concurrent.futures.as_completed(v4_futures)}
            v6_res = {v6_futures[f]: f.result() for f in concurrent.futures.as_completed(v6_futures)}
            
            for s in custom_services:
                custom_results.append({
                    "service": s,
                    "ipv4": v4_res.get(s, "No"),
                    "ipv6": v6_res.get(s, "No")
                })
                
        return {
            "ipv4": ipv4,
            "ipv6": ipv6,
            "v4_detail": v4_detail,
            "v6_detail": v6_detail,
            "results": {
                "primary": primary_results,
                "custom": custom_results
            }
        }
        
    try:
        data = run_function_with_spinner("Запрос геоданных IP", fetch_data)
        
        lines = [
            f"  {BOLD}Основная информация:{NC}",
            "────────────────────────────────────────────────────────"
        ]
        if data.get("ipv4") and data["ipv4"] != "—":
            lines.append(kv("IPv4-адрес:", data["ipv4"]))
            lines.append(kv("  Провайдер/ISP:", data["v4_detail"]["isp"]))
            lines.append(kv("  ASN:", data["v4_detail"]["asn"]))
            lines.append(kv("  Геолокация:", data["v4_detail"]["location"]))
            
        if data.get("ipv6") and data["ipv6"] != "—":
            if data.get("ipv4") and data["ipv4"] != "—":
                lines.append("")
            lines.append(kv("IPv6-адрес:", data["ipv6"]))
            lines.append(kv("  Провайдер/ISP:", data["v6_detail"]["isp"]))
            lines.append(kv("  ASN:", data["v6_detail"]["asn"]))
            lines.append(kv("  Геолокация:", data["v6_detail"]["location"]))
            
        res = data.get("results", {})
        
        if res.get("custom"):
            lines.append("")
            lines.append(f"  {BOLD}Доступ к популярным сервисам:{NC}")
            lines.append("────────────────────────────────────────────────────────")
            for item in res["custom"]:
                service = item.get("service", "")
                v4 = item.get("ipv4") or "—"
                v6 = item.get("ipv6") or "—"
                
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
    """Тест 2 и 3. Censorcheck (проверка гео-блокировок или обхода DPI)"""
    clear()
    mode_title = "Гео-блокировки" if mode == "geoblock" else "DPI РФ"
    title(f"Тестирование: {mode_title}")
    print()
    
    try:
        data = run_function_with_spinner("Анализ доступности ресурсов", run_censorcheck_python, mode)
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
                elif status_int == -2:
                    return f"{RED}Блок (Сброс){NC}"
                elif status_int == -3:
                    return f"{RED}Блок (DNS){NC}"
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
    """Тест 4. Тест скорости до российских серверов через iPerf3"""
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
            s.settimeout(0.4)
            s.connect((host, port))
            s.close()
            return port
        except Exception:
            return None

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
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=6)
            if r.returncode != 0:
                return 0.0
            res_data = json.loads(r.stdout)
            sent = res_data.get("end", {}).get("sum_sent", {}).get("bits_per_second", 0)
            recv = res_data.get("end", {}).get("sum_received", {}).get("bits_per_second", 0)
            return max(sent, recv) / 1_000_000
        except (subprocess.TimeoutExpired, Exception):
            return 0.0
            
    def get_ping(host):
        try:
            r = subprocess.run(["ping", "-c", "2", "-W", "1.5", host], capture_output=True, text=True, timeout=3.0)
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


def test_cpu_sysbench():
    """Тест 6. Тест производительности процессора с помощью sysbench"""
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


def run_parallel_pings(nodes):
    """Выполняет быстрый ICMP-пинг до всех серверов в пуле параллельно."""
    def get_ping_ms(host):
        try:
            r = subprocess.run(["ping", "-c", "2", "-W", "1.5", host], capture_output=True, text=True, timeout=3.0)
            match = re.search(r"rtt min/avg/max/mdev = [\d\.]+/(?P<avg>[\d\.]+)/[\d\.]+/[\d\.]+", r.stdout)
            if match:
                return f"{float(match.group('avg')):.1f} ms", float(match.group('avg'))
        except Exception:
            pass
        return "N/A", float('inf')
        
    results = {}
    def worker(node):
        host = urlparse(node["url"]).hostname
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
    import urllib.request
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
            return speed_bps / 1_000_000
    except Exception:
        return 0.0


def test_bench_speedtest():
    """Тест 5. Тест скорости до зарубежных серверов (Global Speedtest с оптимизацией по пингу)"""
    clear()
    title("Тест скорости до зарубежных серверов (Global)")
    print()
    
    if not ensure_packages(["ping"]):
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
        ping_results = run_function_with_spinner("Измерение пинга до мировых серверов", run_parallel_pings, NODES)
        
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


# ═════════════════════════════════════════════════════════════════════════════
#  Генератор полного отчета диагностики
# ═════════════════════════════════════════════════════════════════════════════

def run_diagnostics_report() -> str:
    """Фоновый сборщик полного Markdown-отчета."""
    import platform
    
    # 1. Сбор системных данных
    os_info = platform.platform()
    cpu_model = "—"
    if os.path.exists("/proc/cpuinfo"):
        try:
            with open("/proc/cpuinfo", "r") as f:
                for line in f:
                    if "model name" in line:
                        cpu_model = line.split(":", 1)[1].strip()
                        break
        except Exception:
            pass
            
    ram_total = "—"
    ram_free = "—"
    if os.path.exists("/proc/meminfo"):
        try:
            with open("/proc/meminfo", "r") as f:
                for line in f:
                    if "MemTotal" in line:
                        ram_total = line.split(":", 1)[1].strip()
                    elif "MemAvailable" in line or "MemFree" in line:
                        ram_free = line.split(":", 1)[1].strip()
        except Exception:
            pass
            
    load_avg = "—"
    try:
        avg1, avg5, avg15 = os.getloadavg()
        load_avg = f"{avg1:.2f}, {avg5:.2f}, {avg15:.2f}"
    except Exception:
        pass
        
    report = []
    report.append("# HYDRA Diagnostics Report")
    report.append(f"Сгенерировано: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    report.append("")
    report.append("## 1. Информация о системе")
    report.append(f"- **ОС/Платформа**: {os_info}")
    report.append(f"- **Процессор (CPU)**: {cpu_model}")
    report.append(f"- **Оперативная память (RAM)**: Всего: {ram_total} | Доступно: {ram_free}")
    report.append(f"- **Загрузка системы (LA)**: {load_avg}")
    report.append(f"- **Версия Python**: {platform.python_version()}")
    report.append("")
    
    # 2. Сетевое геоопределение
    report.append("## 2. Сетевое геоопределение (IP Geolocation)")
    ipv4 = get_ip_address(4) or "—"
    ipv6 = get_ip_address(6) or "—"

    # Получаем детальную инфу для IPv4
    v4_detail = {"isp": "—", "asn": "—", "location": "—"}
    if ipv4 and ipv4 != "—":
        try:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0"}
            req = urllib.request.Request(f"http://ip-api.com/json/{ipv4}", headers=headers)
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                res_data = json.loads(resp.read().decode("utf-8"))
                if res_data.get("status") == "success":
                    v4_detail["isp"] = res_data.get("isp") or res_data.get("org") or "—"
                    as_val = res_data.get("as", "—")
                    v4_detail["asn"] = as_val.split()[0] if as_val and as_val != "—" else "—"
                    
                    loc_parts = []
                    if res_data.get("country"):
                        loc_parts.append(res_data["country"])
                    if res_data.get("city"):
                        loc_parts.append(res_data["city"])
                    v4_detail["location"] = ", ".join(loc_parts) if loc_parts else "—"
        except Exception:
            pass

    # Получаем детальную инфу для IPv6
    v6_detail = {"isp": "—", "asn": "—", "location": "—"}
    if ipv6 and ipv6 != "—":
        try:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0"}
            req = urllib.request.Request(f"http://ip-api.com/json/{ipv6}", headers=headers)
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                res_data = json.loads(resp.read().decode("utf-8"))
                if res_data.get("status") == "success":
                    v6_detail["isp"] = res_data.get("isp") or res_data.get("org") or "—"
                    as_val = res_data.get("as", "—")
                    v6_detail["asn"] = as_val.split()[0] if as_val and as_val != "—" else "—"
                    
                    loc_parts = []
                    if res_data.get("country"):
                        loc_parts.append(res_data["country"])
                    if res_data.get("city"):
                        loc_parts.append(res_data["city"])
                    v6_detail["location"] = ", ".join(loc_parts) if loc_parts else "—"
        except Exception:
            pass

    report.append(f"- **Внешний IPv4**: `{ipv4}`")
    if ipv4 and ipv4 != "—":
        report.append(f"  - **Провайдер/ISP**: `{v4_detail['isp']}`")
        report.append(f"  - **ASN**: `{v4_detail['asn']}`")
        report.append(f"  - **Геолокация**: `{v4_detail['location']}`")
        
    report.append(f"- **Внешний IPv6**: `{ipv6}`")
    if ipv6 and ipv6 != "—":
        report.append(f"  - **Провайдер/ISP**: `{v6_detail['isp']}`")
        report.append(f"  - **ASN**: `{v6_detail['asn']}`")
        report.append(f"  - **Геолокация**: `{v6_detail['location']}`")
        
    report.append("")
    
    system_has_ipv6 = check_system_ipv6()
    primary_services = ["MAXMIND", "IPINFO_IO", "CLOUDFLARE", "IPREGISTRY", "IPAPI_CO", "IPAPI_COM", "IPWHO_IS", "IP2LOCATION_IO"]
    custom_services = ["Google", "YouTube", "Twitch", "ChatGPT", "Netflix", "Spotify"]
    
    report.append("### Детекция баз GeoIP")
    report.append("| База | Страна (IPv4) | Страна (IPv6) |")
    report.append("| --- | --- | --- |")
    for s in primary_services:
        cc_v4 = query_primary_geoip(ipv4, s)
        cc_v6 = query_primary_geoip(ipv6, s) if system_has_ipv6 else "—"
        report.append(f"| {s} | {cc_v4} | {cc_v6} |")
    report.append("")
    
    report.append("### Статус доступа к стримингам и ИИ")
    report.append("| Сервис | Статус (IPv4) | Статус (IPv6) |")
    report.append("| --- | --- | --- |")
    for s in custom_services:
        status_v4 = check_custom_service(s, 4, system_has_ipv6)
        status_v6 = check_custom_service(s, 6, system_has_ipv6) if system_has_ipv6 else "—"
        report.append(f"| {s} | {status_v4} | {status_v6} |")
    report.append("")
    
    # 3. Блокировки доменов
    report.append("## 3. Проверка блокировок и цензуры (Censorcheck)")
    report.append("### Гео-ограничения")
    report.append("| Домен | Статус HTTP | Статус HTTPS |")
    report.append("| --- | --- | --- |")
    for domain in GEO_BLOCKED_SITES:
        http_s = check_domain_censor(domain, secure=False)
        https_s = check_domain_censor(domain, secure=True)
        report.append(f"| {domain} | {http_s} | {https_s} |")
    report.append("")
    
    report.append("### Цензура и DPI (Ресурсы, блокируемые в РФ)")
    report.append("| Домен | Статус HTTP | Статус HTTPS |")
    report.append("| --- | --- | --- |")
    for domain in DPI_BLOCKED_SITES:
        http_s = check_domain_censor(domain, secure=False)
        https_s = check_domain_censor(domain, secure=True)
        report.append(f"| {domain} | {http_s} | {https_s} |")
    report.append("")
    
    # 4. Статус сервисов
    report.append("## 4. Состояние служб HYDRA")
    services = ["sing-box", "caddy", "dnscrypt-proxy", "fail2ban", "hydra-traffic-daemon"]
    report.append("| Служба | Активность (systemd) |")
    report.append("| --- | --- |")
    for s in services:
        status_str = "Unknown"
        try:
            r = subprocess.run(["systemctl", "is-active", s], capture_output=True, text=True, timeout=2.0)
            status_str = r.stdout.strip()
        except Exception:
            pass
        report.append(f"| {s} | {status_str} |")
    report.append("")
    
    # Запись в лог
    os.makedirs("/var/log/hydra", exist_ok=True)
    report_path = "/var/log/hydra/diagnostics_report.md"
    try:
        with open(report_path, "w", encoding="utf-8") as f:
            f.write("\n".join(report))
        return report_path
    except Exception as e:
        raise Exception(f"Не удалось записать файл отчета: {e}")


def test_generate_report():
    """Тест 7. Запуск сборщика отчета в TUI"""
    clear()
    title("Генерация полного отчета диагностики")
    print()
    
    try:
        report_path = run_function_with_spinner("Сбор системных данных и проведение сетевых тестов", run_diagnostics_report)
        success(f"Отчет успешно создан!")
        print()
        panel("📁 Путь к файлу отчета", [
            f"Вы можете скопировать или передать файл:",
            f"{BOLD}{report_path}{NC}",
            "",
            f"Чтобы просмотреть его содержимое, выполните:",
            f"{CYAN}cat {report_path}{NC}"
        ])
    except KeyboardInterrupt:
        pass
    except Exception as e:
        error(f"Не удалось сгенерировать отчет: {e}")
        
    prompt("Нажмите Enter для возврата...")


# ═════════════════════════════════════════════════════════════════════════════
#  Главное меню раздела диагностики
# ═════════════════════════════════════════════════════════════════════════════

def menu_diagnostics(state: AppState):
    """Меню раздела «Тестирование и диагностика VPS»"""
    while True:
        clear()
        
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
            ("1", "🌍 Геолокация и провайдер (GeoIP)", "Нативная Python-детекция"),
            ("2", "🛡️ Доступность ресурсов (Geoblocks)", "Тестирование гео-ограничений стримингов"),
            ("3", "🛡️ Обход DPI-фильтров (DPI РФ)", "Тест блокировок провайдеров РФ"),
            ("4", "⚡ Тест скорости до РФ (iPerf3)", "Замер пропускной способности до серверов РФ"),
            ("5", "🌐 Тест скорости: Мир (Global)", "Тест 5 самых быстрых мировых локаций по пингу"),
            ("6", "💻 Производительность CPU (Sysbench)", "Оценка мощности процессора VPS"),
            ("7", "📝 Сгенерировать полный отчет диагностики", "Markdown-отчет в /var/log/hydra/"),
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
        elif choice == "7":
            test_generate_report()
