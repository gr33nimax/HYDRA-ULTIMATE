from hydra.core.host import HOST
import sys
import os
import time
import json
import ipaddress
import shutil
import subprocess
import re
import socket
import ssl
import urllib.request
import urllib.error
import concurrent.futures
import threading
import shlex
from urllib.parse import urlparse
from pathlib import Path

from hydra.core.state import AppState
from hydra.utils.commands import CommandError, DEFAULT_TIMEOUT, run as run_command
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
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            s.connect(("2001:4860:4860::8888", 53))
        return True
    except Exception:
        return False

# Списки доменов для проверок блокировок
DPI_BLOCKED_SITES = [
    "amnezia.org",
    "api.telegram.org",
    "bbc.com",
    "digitalocean.com",
    "discord.com",
    "dw.com",
    "facebook.com",
    "flibusta.is",
    "getoutline.org",
    "instagram.com",
    "linkedin.com",
    "mailfence.com",
    "medium.com",
    "mullvad.net",
    "nordvpn.com",
    "play.google.com",
    "pornhub.com",
    "proton.me",
    "redirector.googlevideo.com",
    "rezka.ag",
    "rutracker.org",
    "surfshark.com",
    "tailscale.com",
    "torproject.org",
    "windscribe.com",
    "x.com",
    "youtube.com"
]

GEO_BLOCKED_SITES = [
    "adobe.com",
    "amd.com",
    "autodesk.com",
    "canva.com",
    "cisco.com",
    "claude.ai",
    "copilot.microsoft.com",
    "coursera.org",
    "dell.com",
    "figma.com",
    "graylog.org",
    "hub.docker.com",
    "huggingface.co",
    "intel.com",
    "mongodb.com",
    "netflix.com",
    "notion.so",
    "nvidia.com",
    "openai.com",
    "oracle.com",
    "patreon.com",
    "redis.io",
    "slack.com",
    "snyk.io",
    "spotify.com",
    "supercell.com",
    "swagger.io",
    "zoom.us"
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
        try:
            update = run_command(["apt-get", "update"], timeout=300)
            install = run_command(["apt-get", "install", "-y", *missing], timeout=300)
        except CommandError:
            error("Не удалось запустить менеджер пакетов")
            prompt("Нажмите Enter для продолжения...")
            return False
        if update.returncode == 0 and install.returncode == 0:
            success("Зависимости успешно установлены")
            return True
        else:
            error("Не удалось установить зависимости")
            prompt("Нажмите Enter для продолжения...")
            return False
    return False


def _command_argv(cmd: str | list[str] | tuple[str, ...]) -> list[str]:
    """Convert legacy command strings to argv without invoking a shell."""
    argv = [str(item) for item in cmd] if not isinstance(cmd, str) else shlex.split(cmd)
    if not argv:
        raise ValueError("Пустая системная команда")
    return argv


def run_with_spinner(title_text: str, cmd: str | list[str] | tuple[str, ...]) -> str:
    """Запускает системную команду с плавной TUI-анимацией загрузки (spinner) и возвращает stdout."""
    process = HOST.popen(
        _command_argv(cmd),
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    
    spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    idx = 0
    deadline = time.monotonic() + DEFAULT_TIMEOUT
    try:
        while process.poll() is None:
            if time.monotonic() >= deadline:
                process.kill()
                process.wait()
                raise TimeoutError(f"Команда превысила таймаут {DEFAULT_TIMEOUT} секунд")
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


def run_streaming_cmd(title_text: str, cmd: str | list[str] | tuple[str, ...]):
    """Стримит вывод команды в реальном времени, фильтруя шум и оборачивая вывод в рамки HYDRA."""
    print(f"\n  {CYAN}╔{'═' * 76}╗{NC}")
    print(f"  {CYAN}║{NC} {BOLD}{title_text:<74}{NC} {CYAN}║{NC}")
    print(f"  {CYAN}╠{'═' * 76}╣{NC}")
    
    process = HOST.popen(
        _command_argv(cmd),
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
        
    process.wait(timeout=DEFAULT_TIMEOUT)
    print(f"  {CYAN}╚{'═' * 76}╝{NC}")
    print()
    success("Тест завершен.")


def run_direct_cmd(title_text: str, cmd: str | list[str] | tuple[str, ...]):
    """Очищает экран, выводит заголовок HYDRA и запускает команду напрямую (для поддержки интерактивных TUI-меню)."""
    clear()
    print(f"\n  {CYAN}╔{'═' * 76}╗{NC}")
    print(f"  {CYAN}║{NC} {BOLD}{title_text:<74}{NC} {CYAN}║{NC}")
    print(f"  {CYAN}╚{'═' * 76}╝{NC}\n")
    
    try:
        HOST.run(_command_argv(cmd), timeout=DEFAULT_TIMEOUT, check=False)
    except KeyboardInterrupt:
        print(f"\n  {RED}[!] Выполнение прервано.{NC}")


# ═════════════════════════════════════════════════════════════════════════════
#  Нативные сетевые функции на Python (Взамен bash-скриптов)
# ═════════════════════════════════════════════════════════════════════════════

def make_http_request(url: str, method: str = "GET", headers: dict = None, body: str = None, timeout: float = 2.0) -> str:
    """Выполняет HTTP/HTTPS-запрос с проверкой подлинности TLS-сертификата."""
    headers = dict(headers or {})
    if "User-Agent" not in headers:
        headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

    data = None
    if body:
        data = body.encode("utf-8")
        if "Content-Type" not in headers:
            headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, headers=headers, data=data, method=method)
            
    ctx = ssl.create_default_context()
    
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
                    parsed_ip = ipaddress.ip_address(ip)
                    if parsed_ip.version == version:
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
        "IP2LOCATION_IO": f"https://api.ip2location.io/?ip={ip}",
        "RIPE": f"https://stat.ripe.net/data/rir-geo/data.json?resource={ip}"
    }
    
    url = urls.get(service)
    if not url:
        return "—"
        
    ctx = ssl.create_default_context()

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
            elif service == "RIPE":
                resources = json.loads(data).get("data", {}).get("located_resources", [])
                if resources:
                    val = resources[0].get("location")
                    return val.upper() if val else "—"
                return "—"
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
    if ip_version == 6 and not system_has_ipv6:
        return "—"
    _thread_local.ip_version = ip_version
        
    def find_key_nested(d, target_key):
        if isinstance(d, dict):
            for k, v in d.items():
                if k == target_key:
                    return v
                res = find_key_nested(v, target_key)
                if res is not None:
                    return res
        elif isinstance(d, list):
            for item in d:
                res = find_key_nested(item, target_key)
                if res is not None:
                    return res
        return None

    ctx = ssl.create_default_context()
        
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
        elif service_name == "Disney+":
            # 1. Register Device
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Content-Type": "application/json",
                "Authorization": "Bearer ZGlzbmV5JmJyb3dzZXImMS4wLjA.Cu56AgSfBTDag5NiRA81oLHkDZfu5L3CKadnefEAY84"
            }
            url1 = "https://disney.api.edge.bamgrid.com/devices"
            body1 = json.dumps({
                "deviceFamily": "browser",
                "applicationRuntime": "chrome",
                "deviceProfile": "windows",
                "attributes": {}
            }).encode()
            
            req1 = urllib.request.Request(url1, headers=headers, data=body1, method="POST")
            with urllib.request.urlopen(req1, context=ctx, timeout=3.0) as resp1:
                res1 = json.loads(resp1.read().decode("utf-8"))
                assertion = res1.get("assertion")
                if not assertion:
                    return "No"
                    
            # 2. Get Token (Exchange)
            url2 = "https://disney.api.edge.bamgrid.com/token"
            headers2 = headers.copy()
            headers2["Content-Type"] = "application/x-www-form-urlencoded"
            body2 = f"grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&latitude=0&longitude=0&platform=browser&subject_token={assertion}&subject_token_type=urn%3Abamtech%3Aparams%3Aoauth%3Atoken-type%3Adevice".encode()
            
            req2 = urllib.request.Request(url2, headers=headers2, data=body2, method="POST")
            with urllib.request.urlopen(req2, context=ctx, timeout=3.0) as resp2:
                res2 = json.loads(resp2.read().decode("utf-8"))
                refresh_token = res2.get("refresh_token")
                access_token = res2.get("access_token")
                if not refresh_token or not access_token:
                    return "No"
                
            # 3. GraphQL Query
            url3 = "https://disney.api.edge.bamgrid.com/graph/v1/device/graphql"
            headers3 = headers.copy()
            headers3["Content-Type"] = "application/json"
            headers3["Authorization"] = f"Bearer {access_token}"
            body3 = json.dumps({
                "query": """mutation refreshToken($input: RefreshTokenInput!) {
                    refreshToken(refreshToken: $input) {
                        activeSession {
                            sessionId
                        }
                    }
                }""",
                "variables": {"input": {"refreshToken": refresh_token}}
            }).encode()
            
            req3 = urllib.request.Request(url3, headers=headers3, data=body3, method="POST")
            with urllib.request.urlopen(req3, context=ctx, timeout=3.0) as resp3:
                res3 = json.loads(resp3.read().decode("utf-8"))
                region = find_key_nested(res3, "countryCode")
                if region:
                    return region.upper()
                return "Yes"
        elif service_name == "Steam":
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
            req = urllib.request.Request("https://store.steampowered.com/app/761830", headers=headers)
            with urllib.request.urlopen(req, context=ctx, timeout=3.0) as resp:
                html = resp.read().decode("utf-8", errors="ignore")
                match = re.search(r'itemprop="priceCurrency"\s+content="([^"]*)"', html)
                if not match:
                    match = re.search(r'"priceCurrency"\s*:\s*"([^"]*)"', html)
                if match:
                    return match.group(1).upper()
                return "Yes"
        elif service_name == "Claude":
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
            req = urllib.request.Request("https://claude.ai/login", headers=headers)
            with urllib.request.urlopen(req, context=ctx, timeout=3.0) as resp:
                if resp.status == 200:
                    return "Yes"
                return "No"
    except Exception:
        pass
    finally:
        _thread_local.ip_version = None
    return "No"


GEOBLOCK_INSPECT_DOMAINS = {
    "openai.com", "chatgpt.com", "claude.ai",
    "copilot.microsoft.com", "netflix.com", "spotify.com",
    "disneyplus.com", "disney.api.edge.bamgrid.com"
}

RKN_STUB_IPS = {
    "195.208.4.1", "195.208.5.1", "188.186.157.35",
    "80.93.183.168", "213.87.154.141", "92.101.255.255"
}

def check_domain_censor(domain: str, secure: bool = True) -> int:
    """Выполняет проверку доступности конкретного домена по HTTP/HTTPS (возвращает статус-код или код ошибки)."""
    # 1. DNS check & RKN stub check
    try:
        ips = socket.getaddrinfo(domain, None)
        resolved_ips = {ip[4][0] for ip in ips}
        if resolved_ips.intersection(RKN_STUB_IPS):
            return -4  # DNS spoof
    except Exception:
        return -3  # DNS resolve error
        
    url = f"{'https' if secure else 'http'}://{domain}"
    ctx = None
    if secure:
        ctx = ssl.create_default_context()
        
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive"
    })
    
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=3.0) as resp:
            # Check regional block in body only for geoblocked services
            if domain in GEOBLOCK_INSPECT_DOMAINS:
                content_type = resp.headers.get("Content-Type", "")
                if "text/html" in content_type:
                    body = resp.read().decode("utf-8", errors="ignore").lower()
                    if any(x in body for x in [
                        "sorry, you have been blocked", "you are unable to access",
                        "not available in your region", "restricted in your country",
                        "access denied due to location", "blocked in your area",
                        "forbidden-location", "not available in your country"
                    ]):
                        return -5  # Regional block
            return resp.status
    except urllib.error.HTTPError as e:
        if domain in GEOBLOCK_INSPECT_DOMAINS:
            # Check body of 403/451 errors for geoblock messages
            try:
                body = e.read().decode("utf-8", errors="ignore").lower()
                if any(x in body for x in [
                    "sorry, you have been blocked", "you are unable to access",
                    "not available in your region", "restricted in your country",
                    "access denied due to location", "blocked in your area",
                    "forbidden-location", "not available in your country"
                ]):
                    return -5
            except Exception:
                pass
        return e.code
    except urllib.error.URLError as e:
        reason = str(e.reason).lower()
        if "timed out" in reason or "timeout" in reason:
            return 0  # Timeout
        elif "reset" in reason or "connection reset" in reason:
            return -2  # Reset
        elif "refused" in reason:
            return -1  # Refused
        elif "not known" in reason or "resolve" in reason:
            return -3  # DNS error
        else:
            return 0
    except (socket.timeout, TimeoutError):
        return 0
    except ConnectionResetError:
        return -2
    except ConnectionRefusedError:
        return -1
    except ssl.SSLError:
        return -6  # TLS/SSL error
    except Exception:
        return 0


def run_censorcheck_python(mode: str) -> dict:
    """Запускает параллельные проверки доступности доменов в зависимости от выбранного режима."""
    domains = GEO_BLOCKED_SITES if mode == "geoblock" else DPI_BLOCKED_SITES
    results = []
    
    def fetch_asn():
        try:
            req = urllib.request.Request("http://ip-api.com/json/", headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                res_data = json.loads(resp.read().decode("utf-8"))
                if res_data.get("status") == "success":
                    asn = res_data.get("as", "")
                    return asn.split()[0] if asn else "—"
        except Exception:
            pass
        return "—"
        
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
        
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
        asn_future = executor.submit(fetch_asn)
        futures = {executor.submit(worker, d): d for d in domains}
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
            
        asn = asn_future.result()
            
    # Сортируем результаты по алфавиту для красоты
    results.sort(key=lambda x: x["service"])
    return {"results": results, "asn": asn}


def classify_censor_status(http_status: int, https_status: int) -> tuple[str, str]:
    """Классифицирует результат проверки без привязки к оформлению TUI."""
    if 100 <= https_status < 400:
        return "ok", "TLS"

    error_labels = {
        -6: "TLS/SSL",
        -5: "REGIONAL",
        -4: "DNS-SPOOF",
        -3: "DNS",
        -2: "DPI/RESET",
        -1: "TCP/REFUSED",
    }
    if https_status in error_labels:
        return "blocked", error_labels[https_status]

    if https_status in (403, 451):
        return "blocked", f"HTTP {https_status}"

    http_available = 100 <= http_status < 400
    if https_status == 0:
        if http_available:
            return "partial", "HTTPS TIMEOUT; HTTP OK"
        return "blocked", "TIMEOUT"

    if http_available:
        return "partial", f"HTTPS {https_status}; HTTP OK"
    return "blocked", f"HTTP {https_status}"


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
        
        primary_services = ["RIPE", "MAXMIND", "IPINFO_IO", "CLOUDFLARE", "IPREGISTRY", "IPAPI_CO", "IPAPI_COM", "IPWHO_IS", "IP2LOCATION_IO"]
        custom_services = ["Google", "YouTube", "Twitch", "ChatGPT", "Netflix", "Spotify", "Disney+", "Steam", "Claude"]
        
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


def is_port_listening(port: int) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            s.bind(("127.0.0.1", port))
        return False
    except OSError:
        return True

def get_reality_sni() -> str:
    """Пытается распарсить SNI из конфигурации sing-box, либо возвращает fallback."""
    config_path = "/etc/sing-box/config.json"
    if os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
                def find_sni(data):
                    if isinstance(data, dict):
                        for k in ("server_name", "server_names", "dest", "server"):
                            if k in data and isinstance(data[k], str) and "." in data[k]:
                                return data[k]
                            elif k in data and isinstance(data[k], list):
                                for item in data[k]:
                                    if isinstance(item, str) and "." in item:
                                        return item
                        for v in data.values():
                            res = find_sni(v)
                            if res:
                                return res
                    elif isinstance(data, list):
                        for item in data:
                            res = find_sni(item)
                            if res:
                                return res
                    return None
                sni = find_sni(cfg)
                if sni:
                    return sni
        except Exception:
            pass
    return "dl.google.com"  # fallback

def run_tspu_radar(target_ip: str, sni: str) -> dict:
    """Выполняет проверку ТСПУ с использованием API RIPE Atlas."""
    api_key = "dbfb4e08-e6fe-4d8c-a180-3a416688e7dc"
    url = "https://atlas.ripe.net/api/v2/measurements/"
    
    data = {
        "definitions": [{
            "target": target_ip, 
            "description": "Reality TLS Handshake",
            "type": "sslcert",
            "port": 443,
            "hostname": sni,
            "af": 4
        }],
        "probes": [
            {"requested": 3, "type": "asn", "value": 12389, "tags": {"include": ["system-ipv4-works"]}},
            {"requested": 5, "type": "asn", "value": 8402,  "tags": {"include": ["system-ipv4-works"]}},
            {"requested": 5, "type": "asn", "value": 25513, "tags": {"include": ["system-ipv4-works"]}},
            {"requested": 3, "type": "asn", "value": 8359,  "tags": {"include": ["system-ipv4-works"]}},
            {"requested": 3, "type": "asn", "value": 3216,  "tags": {"include": ["system-ipv4-works"]}},
            {"requested": 2, "type": "asn", "value": 20485, "tags": {"include": ["system-ipv4-works"]}},
            {"requested": 1, "type": "asn", "value": 25490, "tags": {"include": ["system-ipv4-works"]}},
            {"requested": 1, "type": "asn", "value": 43727, "tags": {"include": ["system-ipv4-works"]}},
            {"requested": 4, "type": "asn", "value": 12714, "tags": {"include": ["system-ipv4-works"]}},
            {"requested": 2, "type": "asn", "value": 34757, "tags": {"include": ["system-ipv4-works"]}},
            {"requested": 2, "type": "asn", "value": 29124, "tags": {"include": ["system-ipv4-works"]}},
            {"requested": 2, "type": "asn", "value": 12768, "tags": {"include": ["system-ipv4-works"]}}
        ],
        "is_oneoff": True
    }
    
    ctx = ssl.create_default_context()
    
    try:
        req = urllib.request.Request(url, data=json.dumps(data).encode("utf-8"), 
                                     headers={"Content-Type": "application/json", "Authorization": f"Key {api_key}"})
        with urllib.request.urlopen(req, context=ctx, timeout=5.0) as response:
            resp_data = json.loads(response.read().decode("utf-8"))
            msm_id = resp_data["measurements"][0]
    except Exception as e:
        return {"status": "error", "message": f"API create error: {e}"}
        
    results_url = f"https://atlas.ripe.net/api/v2/measurements/{msm_id}/results/"
    results = []
    
    last_count = 0
    stagnant_attempts = 0
    
    for attempt in range(15):
        time.sleep(2.0)
        try:
            req_res = urllib.request.Request(results_url)
            with urllib.request.urlopen(req_res, context=ctx, timeout=3.0) as response:
                results = json.loads(response.read().decode("utf-8"))
                current_count = len(results)
                if current_count >= 33:
                    break
                if current_count > 0 and current_count == last_count:
                    stagnant_attempts += 1
                else:
                    stagnant_attempts = 0
                last_count = current_count
                
                if stagnant_attempts >= 3 and current_count >= 10:
                    break
        except Exception:
            pass
            
    if not results:
        return {"status": "error", "message": "No data received from RIPE probes"}
        
    blocked = 0
    blocked_prb_ids = []
    for probe in results:
        if "cert" in probe or "method" in probe or "alert" in probe:
            pass
        else:
            blocked += 1
            prb_id = probe.get("prb_id")
            if prb_id:
                blocked_prb_ids.append(prb_id)
                
    total = len(results)
    success = total - blocked
    
    blocked_asns = {}
    if blocked_prb_ids:
        try:
            ids_str = ",".join(str(p) for p in blocked_prb_ids)
            probes_url = f"https://atlas.ripe.net/api/v2/probes/?id__in={ids_str}&fields=id,asn_v4"
            req_prb = urllib.request.Request(probes_url)
            with urllib.request.urlopen(req_prb, context=ctx, timeout=5.0) as response:
                probe_info = json.loads(response.read().decode("utf-8"))
                for p in probe_info.get("results", []):
                    asn = p.get("asn_v4")
                    if asn:
                        blocked_asns[asn] = blocked_asns.get(asn, 0) + 1
        except Exception:
            pass
            
    return {
        "status": "success",
        "total": total,
        "success": success,
        "blocked": blocked,
        "blocked_asns": blocked_asns
    }

def test_censorcheck(mode: str):
    """Тест 2 и 3. Censorcheck (проверка гео-блокировок или обхода DPI)"""
    clear()
    mode_title = "Гео-блокировки с VPS" if mode == "geoblock" else "Исходящая доступность с VPS"
    title(f"Тестирование: {mode_title}")
    print()
    
    try:
        data = run_function_with_spinner("Анализ доступности ресурсов", run_censorcheck_python, mode)
        results = data.get("results", [])
        asn = data.get("asn", "—")
        
        def pad_ansi(s, width):
            clean_len = len(re.sub(r'\x1b\[[0-9;]*m', '', s))
            if clean_len >= width:
                return s
            return s + " " * (width - clean_len)
            
        print(f"  {BOLD}{'Domain':<28} │ {'Status':<14} │ Block Type{NC}")
        print("  " + "─" * 74)
        
        ok_count = 0
        blocked_count = 0
        partial_count = 0
        
        for item in results:
            domain = item.get("service", "")
            http = item.get("http", {})
            https = item.get("https", {})
            
            http_status = http.get("ipv4", {}).get("status", 0)
            https_status = https.get("ipv4", {}).get("status", 0)
            
            classification, reason = classify_censor_status(http_status, https_status)
            if classification == "ok":
                status_str = f"{GREEN}OK{NC}"
                block_type_str = f"{GREEN}✓{reason}{NC}"
                ok_count += 1
            elif classification == "partial":
                status_str = f"{YELLOW}PARTIAL{NC}"
                block_type_str = f"{YELLOW}({reason}){NC}"
                partial_count += 1
            else:
                status_str = f"{RED}BLOCKED{NC}"
                block_type_str = f"{RED}({reason}){NC}"
                blocked_count += 1
                    
            print(f"  {domain:<28} │ {pad_ansi(status_str, 14)} │ {block_type_str}")
            
        print("  " + "─" * 74)
        summary = f"{GREEN}OK:{ok_count}{NC}  {RED}BLOCKED:{blocked_count}{NC}  {YELLOW}PARTIAL:{partial_count}{NC}  {DIM}Total:{len(results)}{NC}"
        if asn != "—":
            summary += f" {DIM}|{NC} {CYAN}{asn}{NC}"
        print(f"  {summary}")
        print("  " + "─" * 74)
        
        if mode == "dpi":
            if not is_port_listening(443):
                print()
                print(f"  {DIM}Радар ТСПУ отменен: порт 443 не активен (убедитесь, что VPN запущен){NC}")
                print()
            else:
                print()
                print(f"  {CYAN}Опрос сетей РФ: РТК, МТС, МГТС, Билайн, ТТК, РТК-Юг, Мегафон...{NC}")
                target_ip = get_ip_address(4)
                sni = get_reality_sni()
                
                radar_res = run_function_with_spinner("Запуск радара ТСПУ", run_tspu_radar, target_ip, sni)
                print()
                if radar_res.get("status") == "success":
                    total = radar_res["total"]
                    success_prbs = radar_res["success"]
                    blocked_prbs = radar_res["blocked"]
                    
                    percent = (success_prbs * 100 // total) if total > 0 else 0
                    if percent == 100:
                        color = GREEN
                        text = "ПОЛНЫЙ ДОСТУП ИЗ РФ"
                    elif percent > 50:
                        color = YELLOW
                        text = "ЧАСТИЧНАЯ БЛОКИРОВКА IP (Дропы у части провайдеров)"
                    else:
                        color = RED
                        text = "КРИТИЧНАЯ БЛОКИРОВКА ТСПУ (IP недоступен)"
                        
                    print(f"  Зондов ответило: {CYAN}{total}{NC} | Пробились: {GREEN}{success_prbs}{NC} | Заблокированы: {RED}{blocked_prbs}{NC}")
                    print(f"  ТСПУ Статус: {color}{percent}% {text}{NC}")
                    
                    blocked_asns = radar_res.get("blocked_asns", {})
                    if blocked_asns:
                        asn_names = {
                            12389: "Ростелеком",
                            8402: "Билайн",
                            25513: "МГТС",
                            8359: "МТС",
                            3216: "Билайн",
                            20485: "ТТК",
                            25490: "РТК-Юг",
                            43727: "Мегафон",
                            12714: "Мегафон",
                            34757: "Сибсети",
                            29124: "Искрателеком",
                            12768: "Дом.ру"
                        }
                        blocking_list = []
                        for b_asn, count in blocked_asns.items():
                            name = asn_names.get(int(b_asn), f"AS{b_asn}")
                            blocking_list.append(f"{RED}{name}{NC} ({count})")
                        print(f"  {RED}Блокируют:{NC} {', '.join(blocking_list)}")
                    print()
                else:
                    print(f"  {YELLOW}Не удалось запустить радар ТСПУ: {radar_res.get('message')}{NC}")
                    print()
                    
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
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.4)
                s.connect((host, port))
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
            r = HOST.run(cmd, capture_output=True, text=True, timeout=6)
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
            r = HOST.run(["ping", "-c", "2", "-W", "1.5", host], capture_output=True, text=True, timeout=3.0)
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
            r = HOST.run(["ping", "-c", "2", "-W", "1.5", host], capture_output=True, text=True, timeout=3.0)
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
            elapsed = 0.0
            while True:
                chunk = response.read(65536)
                if not chunk:
                    break
                bytes_downloaded += len(chunk)
                elapsed = time.time() - start_time
                if elapsed >= 4.0:
                    break
            if bytes_downloaded and elapsed == 0.0:
                elapsed = time.time() - start_time
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
#  Генератор диагностического отчета
# ═════════════════════════════════════════════════════════════════════════════

def run_diagnostics_report() -> str:
    """Collect a live HYDRA runtime report for immediate display in the TUI.

    This intentionally does not run network benchmarks, censor checks or
    export files. Those remain separate diagnostics menu actions.
    """
    from hydra.core import orchestrator, singbox
    from hydra.core.state import load_state

    width = 74
    report: list[str] = [
        "╭" + "─" * width + "╮",
        "│" + "HYDRA — диагностика".center(width) + "│",
        "│" + f"Проверка: {time.strftime('%Y-%m-%d %H:%M:%S')}".center(width) + "│",
        "╰" + "─" * width + "╯",
    ]
    errors = 0

    def section(name: str) -> None:
        report.extend(["", f"┌─ {name} " + "─" * max(1, width - len(name) - 4)])

    def item(marker: str, text: str) -> None:
        report.append(f"│ {marker:<7} {text}")

    section("СОСТОЯНИЕ HYDRA")
    try:
        state = load_state()
        enabled = [name for name, value in state.protocols.items() if value.enabled]
        item("[OK]", f"state.json       корректен, schema {state.version}")
        item("[OK]", f"Пользователи      {len(state.users)}")
        item("[OK]", f"Протоколы         {', '.join(enabled) if enabled else 'нет'}")
    except Exception as exc:
        errors += 1
        item("[ERROR]", f"state.json        {exc}")

    section("ЯДРО SING-BOX")
    if singbox.is_installed():
        item("[OK]", f"Sing-Box          установлен, {singbox.get_version() or 'версия не определена'}")
    else:
        errors += 1
        item("[ERROR]", "Sing-Box          не установлен")
    config_exists = singbox.SINGBOX_CONFIG.exists()
    if config_exists:
        item("[OK]", "Конфигурация      существует")
    else:
        item("[WARNING]", "Конфигурация      ещё не создана")
    binary = singbox._find_singbox()
    if binary and config_exists:
        try:
            checked = singbox._run([str(binary), "check", "-c", str(singbox.SINGBOX_CONFIG)])
            if checked.returncode == 0:
                item("[OK]", "Проверка конфига  синтаксис корректен")
            else:
                errors += 1
                detail = (checked.stderr or checked.stdout or "неизвестная ошибка").strip().splitlines()[-1]
                item("[ERROR]", f"Проверка конфига  {detail[:300]}")
        except (OSError, subprocess.SubprocessError) as exc:
            item("[WARNING]", f"Проверка конфига  недоступна: {exc}")
    item("[INFO]", f"Ошибка применения  {orchestrator.last_apply_error() or 'нет'}")

    section("СЕРВИСЫ")
    services = ["sing-box", "caddy-l4", "dnscrypt-proxy", "fail2ban", "hydra-traffic-daemon"]
    if os.name == "nt":
        item("[INFO]", "systemd            недоступен в Windows-окружении")
    else:
        shown_services = 0
        for service in services:
            try:
                loaded = HOST.run(
                    ["systemctl", "show", service, "--property=LoadState", "--value"],
                    capture_output=True, text=True, timeout=2.0,
                )
                if loaded.returncode != 0 or loaded.stdout.strip() != "loaded":
                    continue
                shown_services += 1
                active = HOST.run(
                    ["systemctl", "is-active", service],
                    capture_output=True, text=True, timeout=2.0,
                )
                enabled = HOST.run(
                    ["systemctl", "is-enabled", service],
                    capture_output=True, text=True, timeout=2.0,
                )
                active_state = active.stdout.strip() or "не установлен"
                enabled_state = enabled.stdout.strip() or "не включён"
                marker = "OK" if active.returncode == 0 else "WARNING"
                if active.returncode != 0:
                    errors += 1 if enabled.returncode == 0 else 0
                item(f"[{marker}]", f"{service:<20} {active_state}, автозапуск: {enabled_state}")
            except (OSError, subprocess.SubprocessError) as exc:
                item("[WARNING]", f"{service:<20} проверка недоступна: {exc}")
        if not shown_services:
            item("[INFO]", "Сервисы            управляемые systemd-сервисы не установлены")

    section("ПЛАГИНЫ")
    if os.name == "nt":
        item("[INFO]", "Runtime-статусы    доступны только на Linux")
    else:
        try:
            from hydra.plugins.registry import status_all
            statuses = status_all()
            installed = 0
            active_plugins = []
            disabled_plugins = []
            for name, status in statuses.items():
                if not status.get("installed"):
                    continue
                installed += 1
                if status.get("enabled"):
                    active_plugins.append((name, status))
                else:
                    disabled_plugins.append((name, status))
            if active_plugins:
                report.append("│ АКТИВНЫЕ")
                for name, status in active_plugins:
                    marker = "[OK]" if status.get("running") else "[ERROR]"
                    if not status.get("running"):
                        errors += 1
                    port = str(status.get("port") or "—")
                    item(marker, f"{name:<18} {'запущен' if status.get('running') else 'не запущен':<11} порт: {port}")
            if disabled_plugins:
                report.append("│ ОТКЛЮЧЕНЫ (установлены, но не участвуют в работе)")
                for name, status in disabled_plugins:
                    item("[INFO]", f"{name:<18} отключён" + (f", порт: {status.get('port')}" if status.get("port") else ""))
            if not installed:
                item("[INFO]", "Установленные     плагины отсутствуют")
        except Exception as exc:
            errors += 1
            item("[ERROR]", f"Статусы плагинов   не удалось получить: {exc}")

    section("ПОСЛЕДНЕЕ ПРИМЕНЕНИЕ")
    journal = getattr(orchestrator, "APPLY_JOURNAL", Path("/var/log/hydra/apply.jsonl"))
    if journal.exists():
        try:
            entries = [line.strip() for line in journal.read_text(encoding="utf-8").splitlines() if line.strip()]
            item("[OK]", f"Журнал             {len(entries)} событий")
            if entries:
                latest = json.loads(entries[-1])
                event = str(latest.get("event", "unknown"))
                event_names = {
                    "started": "применение начато",
                    "fragments_collected": "конфигурация плагинов собрана",
                    "nft_applied": "сетевые правила применены",
                    "plugins_applied": "плагины применены",
                    "committed": "применение успешно завершено",
                    "rolled_back": "изменения отменены",
                    "failed": "применение завершилось ошибкой",
                    "rejected": "применение отклонено",
                }
                marker = "OK" if event == "committed" else "WARNING"
                if event in {"rolled_back", "failed", "rejected"}:
                    errors += 1
                item(f"[{marker}]", f"Результат          {event_names.get(event, event)}")
                if latest.get("ts"):
                    item("[INFO]", f"Время              {latest['ts']}")
                if latest.get("stage"):
                    item("[INFO]", f"Этап               {latest['stage']}")
                if latest.get("error"):
                    item("[ERROR]", f"Причина            {str(latest['error'])[:500]}")
        except (OSError, ValueError, TypeError) as exc:
            item("[WARNING]", f"Журнал             недоступен: {exc}")
    else:
        item("[INFO]", "Журнал             применений ещё не зарегистрировано")

    result = "ERROR" if errors else "OK"
    report.extend(["", "└─ ИТОГ: " + ("ОБНАРУЖЕНЫ ОШИБКИ" if errors else "СИСТЕМА В НОРМЕ") + f" [{result}]"])
    return "\n".join(report)


# ═════════════════════════════════════════════════════════════════════════════
#  Главное меню раздела диагностики
# ═════════════════════════════════════════════════════════════════════════════

def show_live_report():
    """Run the runtime report, display it, then return to the menu."""
    clear()
    title("Диагностика HYDRA")
    print()
    try:
        report = run_function_with_spinner("Опрос состояния HYDRA и сервисов", run_diagnostics_report)
        print(report)
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        error(f"Не удалось получить диагностику: {exc}")
    prompt("Нажмите Enter для возврата в меню...")


# Keep the existing symbol used by callers/tests, but change its behavior from
# file export to an in-place runtime report.
test_generate_report = show_live_report


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
            test_bench_speedtest()
        elif choice == "5":
            test_iperf3_ru()
        elif choice == "6":
            test_cpu_sysbench()
        elif choice == "7":
            test_generate_report()
