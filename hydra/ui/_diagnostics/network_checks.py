"""Network identity, GeoIP and service availability diagnostics."""
from __future__ import annotations

import ipaddress
import json
import re

from hydra.services.diagnostic_compatibility import (
    current_diagnostic_operations,
)
from hydra.ui._diagnostics.system_checks import (
    _thread_local,
    check_system_ipv6,
    run_function_with_spinner,
)
from hydra.ui._diagnostics.network_region_data import collect_region_data
from hydra.ui._diagnostics.network_service_exchanges import disney_region
from hydra.ui.tui import BOLD, DIM, GREEN, NC, RED, clear, error, kv, panel, prompt, title


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

    result = current_diagnostic_operations().request(
        url,
        method=method,
        headers=headers,
        data=data,
        timeout=timeout,
    )
    if not result.error_kind or result.error_kind == "http":
        return result.text()
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
                result = current_diagnostic_operations().request(
                    url,
                    headers={"User-Agent": "curl/7.81.0"},
                    timeout=2.0,
                )
                ip = result.text().strip()
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

    _thread_local.ip_version = conn_ip_version
    try:
        response = current_diagnostic_operations().request(
            url,
            headers=headers,
            timeout=2.0,
        )
        if not response.error_kind:
            data = response.text()
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
        response = current_diagnostic_operations().request(
            fallback_url,
            headers=headers,
            timeout=1.5,
        )
        res_data = json.loads(response.text())
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
            return disney_region()
        elif service_name == "Steam":
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
            response = current_diagnostic_operations().request(
                "https://store.steampowered.com/app/761830",
                headers=headers,
                timeout=3.0,
            )
            html = response.text()
            match = re.search(r'itemprop="priceCurrency"\s+content="([^"]*)"', html)
            if not match:
                match = re.search(r'"priceCurrency"\s*:\s*"([^"]*)"', html)
            if match:
                return match.group(1).upper()
            return "Yes"
        elif service_name == "Claude":
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
            response = current_diagnostic_operations().request(
                "https://claude.ai/login",
                headers=headers,
                timeout=3.0,
            )
            return "Yes" if response.status == 200 else "No"
    except Exception:
        pass
    finally:
        _thread_local.ip_version = None
    return "No"

def test_ip_region():
    """Тест 1. IP region (определение геопозиции по базам GeoIP и стримингам)"""
    clear()
    title("Тестирование: IP region")
    print()

    system_has_ipv6 = check_system_ipv6()

    try:
        data = run_function_with_spinner(
            "Запрос геоданных IP",
            collect_region_data,
            system_has_ipv6,
            get_ip_address=get_ip_address,
            query_primary_geoip=query_primary_geoip,
            check_custom_service=check_custom_service,
        )

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
