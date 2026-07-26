"""Shared pure helpers for Telegram security dashboards."""
from __future__ import annotations

import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor
from collections.abc import Mapping
from typing import Any

def _mapping_projection(value: object) -> dict[str, Any]:
    """Copy one plugin-owned mapping before rendering it."""
    return dict(value) if isinstance(value, Mapping) else {}

def _format_period(seconds: object) -> str:
    try:
        value = max(0, int(float(seconds)))
    except (TypeError, ValueError):
        return "—"
    if value < 60:
        return f"{value}с"
    if value < 3600:
        return f"{value // 60}м"
    if value < 86400:
        return f"{value // 3600}ч"
    return f"{value // 86400}д"

def _format_security_timestamp(value: object) -> str:
    raw = str(value or "").strip().replace("T", " ")
    match = re.match(
        r"(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})",
        raw,
    )
    if match:
        year, month, day, hour, minute = match.groups()
        return f"{day}.{month}.{year} {hour}:{minute}"
    return raw[:16] or "—"

def _parse_fail2ban_ban_lines(
    lines: list[str],
    limit: int = 5,
) -> list[dict[str, str]]:
    pattern = re.compile(
        r"^(?P<when>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}).*?"
        r"NOTICE\s+\[(?P<jail>[^]]+)]\s+Ban\s+(?P<ip>\S+)",
    )
    result = []
    seen = set()
    for line in reversed(lines):
        match = pattern.search(str(line))
        if not match:
            continue
        try:
            address = ipaddress.ip_address(
                match.group("ip").strip("[]"),
            ).compressed
        except ValueError:
            continue
        if address in seen:
            continue
        seen.add(address)
        result.append(
            {
                "ip": address,
                "jail": match.group("jail"),
                "when": match.group("when"),
            },
        )
        if len(result) >= max(0, int(limit)):
            break
    return result

def _lookup_security_intel(
    addresses: list[str],
) -> dict[str, dict[str, str]]:
    from hydra.services.security_intel import lookup_ip

    unique = list(dict.fromkeys(addresses))[:5]
    if not unique:
        return {}
    with ThreadPoolExecutor(max_workers=len(unique)) as executor:
        return dict(zip(unique, executor.map(lookup_ip, unique)))

def _network_label(intel: dict[str, str]) -> str:
    return " ".join(
        value
        for value in (
            str(intel.get("asn", "")),
            str(intel.get("owner", "")),
        )
        if value and value != "N/A"
    ).strip()
