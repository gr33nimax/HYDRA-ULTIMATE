"""Data collection for the interactive IP-region diagnostic."""
from __future__ import annotations

import concurrent.futures
import json
from collections.abc import Callable

from hydra.services.diagnostic_compatibility import (
    current_diagnostic_operations,
)


PRIMARY_SERVICES = (
    "RIPE",
    "MAXMIND",
    "IPINFO_IO",
    "CLOUDFLARE",
    "IPREGISTRY",
    "IPAPI_CO",
    "IPAPI_COM",
    "IPWHO_IS",
    "IP2LOCATION_IO",
)
CUSTOM_SERVICES = (
    "Google",
    "YouTube",
    "Twitch",
    "ChatGPT",
    "Netflix",
    "Spotify",
    "Disney+",
    "Steam",
    "Claude",
)
_UNKNOWN = "—"
_DETAIL_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) "
        "Gecko/20100101 Firefox/140.0"
    ),
}


def _ip_details(ip: str) -> dict[str, str]:
    details = {"isp": _UNKNOWN, "asn": _UNKNOWN, "location": _UNKNOWN}
    if not ip or ip == _UNKNOWN:
        return details
    try:
        response = current_diagnostic_operations().request(
            f"http://ip-api.com/json/{ip}",
            headers=_DETAIL_HEADERS,
            timeout=2.0,
        )
        payload = json.loads(response.text())
        if payload.get("status") != "success":
            return details
        details["isp"] = payload.get("isp") or payload.get("org") or _UNKNOWN
        as_value = payload.get("as", _UNKNOWN)
        if as_value and as_value != _UNKNOWN:
            details["asn"] = as_value.split()[0]
        location = [
            value
            for value in (payload.get("country"), payload.get("city"))
            if value
        ]
        details["location"] = ", ".join(location) if location else _UNKNOWN
    except Exception:
        pass
    return details


def _parallel_results(
    services: tuple[str, ...],
    lookup: Callable[[str, int], str],
    *,
    workers: int,
    fallback: str,
) -> list[dict[str, str]]:
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        v4_futures = {executor.submit(lookup, name, 4): name for name in services}
        v6_futures = {executor.submit(lookup, name, 6): name for name in services}
        v4 = {
            v4_futures[future]: future.result()
            for future in concurrent.futures.as_completed(v4_futures)
        }
        v6 = {
            v6_futures[future]: future.result()
            for future in concurrent.futures.as_completed(v6_futures)
        }
    return [
        {
            "service": name,
            "ipv4": v4.get(name, fallback),
            "ipv6": v6.get(name, fallback),
        }
        for name in services
    ]


def collect_region_data(
    system_has_ipv6: bool,
    *,
    get_ip_address: Callable[[int], str],
    query_primary_geoip: Callable[[str, str], str],
    check_custom_service: Callable[[str, int, bool], str],
) -> dict[str, object]:
    """Collect address metadata, GeoIP votes, and service-region results."""
    ipv4 = get_ip_address(4) or _UNKNOWN
    ipv6 = get_ip_address(6) or _UNKNOWN

    primary = _parallel_results(
        PRIMARY_SERVICES,
        lambda service, version: query_primary_geoip(
            ipv4 if version == 4 else ipv6,
            service,
        ),
        workers=8,
        fallback=_UNKNOWN,
    )
    custom = _parallel_results(
        CUSTOM_SERVICES,
        lambda service, version: check_custom_service(
            service,
            version,
            system_has_ipv6,
        ),
        workers=6,
        fallback="No",
    )
    return {
        "ipv4": ipv4,
        "ipv6": ipv6,
        "v4_detail": _ip_details(ipv4),
        "v6_detail": _ip_details(ipv6),
        "results": {"primary": primary, "custom": custom},
    }


__all__ = ["collect_region_data"]
