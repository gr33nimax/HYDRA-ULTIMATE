"""Censorship probes, classification and interactive diagnostics."""
from __future__ import annotations

import concurrent.futures
import json
import re

from hydra.services.diagnostic_compatibility import (
    current_diagnostic_operations,
)
from hydra.ui._diagnostics import censorship_radar as _radar
from hydra.ui._diagnostics.network_checks import get_ip_address
from hydra.ui._diagnostics.system_checks import run_function_with_spinner
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
    prompt,
    title,
)


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
    operations = current_diagnostic_operations()
    try:
        resolved_ips = set(operations.resolve_addresses(domain))
        if resolved_ips.intersection(RKN_STUB_IPS):
            return -4  # DNS spoof
    except Exception:
        return -3  # DNS resolve error

    url = f"{'https' if secure else 'http'}://{domain}"
    result = operations.request(
        url,
        headers={
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": (
                "text/html,application/xhtml+xml,"
                "application/xml;q=0.9,*/*;q=0.8"
            ),
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
        },
        timeout=3.0,
        verify_tls=secure,
    )

    if domain in GEOBLOCK_INSPECT_DOMAINS:
        content_type = result.headers.get("Content-Type", "")
        body = result.text().lower()
        regional_markers = (
            "sorry, you have been blocked",
            "you are unable to access",
            "not available in your region",
            "restricted in your country",
            "access denied due to location",
            "blocked in your area",
            "forbidden-location",
            "not available in your country",
        )
        if (
            result.error_kind == "http"
            or "text/html" in content_type
        ) and any(marker in body for marker in regional_markers):
            return -5

    if not result.error_kind:
        return result.status
    if result.error_kind == "http":
        return result.status
    return {
        "reset": -2,
        "refused": -1,
        "dns": -3,
        "tls": -6,
    }.get(result.error_kind, 0)


def run_censorcheck_python(mode: str) -> dict:
    """Запускает параллельные проверки доступности доменов в зависимости от выбранного режима."""
    domains = GEO_BLOCKED_SITES if mode == "geoblock" else DPI_BLOCKED_SITES
    results = []

    def fetch_asn():
        try:
            response = current_diagnostic_operations().request(
                "http://ip-api.com/json/",
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=1.5,
            )
            res_data = json.loads(response.text())
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

def is_port_listening(port: int) -> bool:
    return current_diagnostic_operations().port_listening(port)

def get_reality_sni() -> str:
    """Пытается распарсить SNI из конфигурации sing-box, либо возвращает fallback."""
    config_path = "/etc/sing-box/config.json"
    operations = current_diagnostic_operations()
    if operations.path_exists(config_path):
        try:
            cfg = operations.read_json_file(config_path)

            def find_sni(data):
                if isinstance(data, dict):
                    for k in ("server_name", "server_names", "dest", "server"):
                        if k in data and isinstance(data[k], str) and "." in data[k]:
                            return data[k]
                        if k in data and isinstance(data[k], list):
                            for item in data[k]:
                                if isinstance(item, str) and "." in item:
                                    return item
                    for value in data.values():
                        result = find_sni(value)
                        if result:
                            return result
                elif isinstance(data, list):
                    for item in data:
                        result = find_sni(item)
                        if result:
                            return result
                return None

            sni = find_sni(cfg)
            if sni:
                return sni
        except Exception:
            pass
    return "dl.google.com"  # fallback

def run_tspu_radar(target_ip: str, sni: str) -> dict:
    """Выполняет проверку ТСПУ с использованием API RIPE Atlas."""
    return _radar.run_tspu_radar(target_ip, sni)

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
