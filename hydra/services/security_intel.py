"""Fail-open, cached IP country and network ownership enrichment."""

from __future__ import annotations

import ipaddress
import json
import os
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path

CACHE_FILE = Path("/var/lib/hydra/ip-intel-cache.json")
POSITIVE_TTL = 7 * 86400
NEGATIVE_TTL = 3600
LOOKUP_TIMEOUT = 1.5
_lock = threading.Lock()


def country_flag(code: str) -> str:
    normalized = str(code or "").strip().upper()
    if len(normalized) != 2 or any(letter < "A" or letter > "Z" for letter in normalized):
        return "🌐"
    return "".join(chr(0x1F1E6 + ord(letter) - ord("A")) for letter in normalized)


def _fallback() -> dict[str, str]:
    return {"country_code": "", "flag": "🌐", "owner": "N/A", "asn": ""}


def _load_cache(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, TypeError, ValueError):
        return {}


def _save_cache(path: Path, data: dict) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        pending = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
        pending.write_text(json.dumps(data, separators=(",", ":")), encoding="utf-8")
        pending.chmod(0o600)
        pending.replace(path)
    except OSError:
        pass


def _coordinate(value: object) -> str:
    """Format a coordinate so the cached value stays a string like the rest."""
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return ""
    try:
        return f"{float(value):.6f}"
    except (TypeError, ValueError):
        return ""


def _text(value: object, limit: int) -> str:
    return str(value if value is not None else "")[:limit]


def _region_from(payload: dict, code: str) -> dict[str, str]:
    """Region facts the provider returns in the same response, kept as strings.

    The site shows where the server actually is, so the city is the headline while
    the capital stays available as a separate fact. Time zones are not taken from
    here: they only have to be consistent with the name, and that is checked
    locally against the IANA database when the page is built.
    """
    timezone = payload.get("timezone")
    zone = _text(timezone.get("id"), 64) if isinstance(timezone, dict) else ""
    return {
        "country": _text(payload.get("country"), 80),
        "country_code": code,
        "city": _text(payload.get("city"), 80),
        "region": _text(payload.get("region"), 80),
        "capital": _text(payload.get("capital"), 80),
        "latitude": _coordinate(payload.get("latitude")),
        "longitude": _coordinate(payload.get("longitude")),
        "timezone": zone,
    }


def _address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        address = ipaddress.ip_address(str(value).strip("[]"))
    except ValueError:
        return None
    return address if address.is_global else None


def _fresh(cached: object, timestamp: float) -> bool:
    if not isinstance(cached, dict):
        return False
    ttl = POSITIVE_TTL if cached.get("ok") else NEGATIVE_TTL
    try:
        stored = float(cached.get("at", 0) or 0)
    except (TypeError, ValueError):
        return False
    return timestamp - stored < ttl


def _entry_timestamp(item: tuple[str, object]) -> float:
    entry = item[1]
    raw = entry.get("at", 0) if isinstance(entry, dict) else 0
    try:
        return float(raw or 0)
    except (TypeError, ValueError):
        return 0.0


def _fetch_remote(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> tuple[dict, dict, bool]:
    """One request for both the notification subset and the region facts."""
    value = _fallback()
    region: dict[str, str] = {}
    ok = False
    try:
        encoded = urllib.parse.quote(address.compressed, safe=":")
        request = urllib.request.Request(
            f"https://ipwho.is/{encoded}",
            headers={"Accept": "application/json", "User-Agent": "HYDRA-ULTIMATE/AntiDPI"},
        )
        with urllib.request.urlopen(request, timeout=LOOKUP_TIMEOUT) as response:
            payload = json.loads(response.read(262144))
        if isinstance(payload, dict) and payload.get("success", True):
            raw_connection = payload.get("connection")
            connection: dict = raw_connection if isinstance(raw_connection, dict) else {}
            code = str(payload.get("country_code", "")).upper()
            raw_asn = connection.get("asn", "")
            asn = f"AS{raw_asn}" if raw_asn and not str(raw_asn).upper().startswith("AS") else str(raw_asn)
            owner = str(connection.get("org") or connection.get("isp") or "N/A")[:160]
            value = {"country_code": code, "flag": country_flag(code), "owner": owner, "asn": asn}
            region = _region_from(payload, code)
            ok = bool(code or owner != "N/A" or asn)
    except Exception:
        pass
    return value, region, ok


def _entry(address, timestamp: float, path: Path) -> dict:
    with _lock:
        cache = _load_cache(path)
        cached = cache.get(address.compressed)
        if isinstance(cached, dict) and _fresh(cached, timestamp):
            return dict(cached)

    value, region, ok = _fetch_remote(address)
    entry = {"at": timestamp, "ok": ok, "value": value, "region": region}
    with _lock:
        cache = _load_cache(path)
        cache[address.compressed] = entry
        if len(cache) > 4096:
            ordered = sorted(cache.items(), key=_entry_timestamp)
            cache = dict(ordered[-3072:])
        _save_cache(path, cache)
    return dict(entry)


def lookup_ip(ip: str, *, now: float | None = None, cache_file: Path | None = None) -> dict[str, str]:
    """Return flag/ASN/owner; network and cache failures never propagate."""
    address = _address(ip)
    if address is None:
        return _fallback()
    timestamp = time.time() if now is None else now
    entry = _entry(address, timestamp, cache_file or CACHE_FILE)
    value = entry.get("value")
    return dict(value) if isinstance(value, dict) else _fallback()


def lookup_region(ip: str, *, now: float | None = None, cache_file: Path | None = None) -> dict[str, str]:
    """Return where the address is: country, city, coordinates and IANA zone.

    Uses the same provider, the same cache file and the same single request as
    `lookup_ip`, so the flag in the menu and the region on the site cannot disagree.
    An unknown or private address yields an empty mapping and never raises.
    """
    address = _address(ip)
    if address is None:
        return {}
    timestamp = time.time() if now is None else now
    entry = _entry(address, timestamp, cache_file or CACHE_FILE)
    region = entry.get("region")
    return dict(region) if isinstance(region, dict) else {}


def notification_fields(ip: str) -> list[tuple[str, str]]:
    intel = lookup_ip(ip)
    network = " ".join(value for value in (intel["asn"], intel["owner"]) if value).strip()
    return [("Geo", intel["flag"]), ("Owner", network or "N/A")]


__all__ = [
    "CACHE_FILE",
    "NEGATIVE_TTL",
    "POSITIVE_TTL",
    "country_flag",
    "lookup_ip",
    "lookup_region",
    "notification_fields",
]
