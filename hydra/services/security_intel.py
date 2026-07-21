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


def lookup_ip(ip: str, *, now: float | None = None, cache_file: Path | None = None) -> dict[str, str]:
    """Return flag/ASN/owner; network and cache failures never propagate."""
    try:
        address = ipaddress.ip_address(str(ip).strip("[]"))
    except ValueError:
        return _fallback()
    if not address.is_global:
        return _fallback()
    timestamp = time.time() if now is None else now
    path = cache_file or CACHE_FILE
    with _lock:
        cache = _load_cache(path)
        cached = cache.get(address.compressed)
        if isinstance(cached, dict):
            ttl = POSITIVE_TTL if cached.get("ok") else NEGATIVE_TTL
            if timestamp - float(cached.get("at", 0) or 0) < ttl:
                return dict(cached.get("value") or _fallback())

    value = _fallback()
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
            connection = payload.get("connection") if isinstance(payload.get("connection"), dict) else {}
            code = str(payload.get("country_code", "")).upper()
            raw_asn = connection.get("asn", "")
            asn = f"AS{raw_asn}" if raw_asn and not str(raw_asn).upper().startswith("AS") else str(raw_asn)
            owner = str(connection.get("org") or connection.get("isp") or "N/A")[:160]
            value = {"country_code": code, "flag": country_flag(code), "owner": owner, "asn": asn}
            ok = bool(code or owner != "N/A" or asn)
    except Exception:
        pass

    with _lock:
        cache = _load_cache(path)
        cache[address.compressed] = {"at": timestamp, "ok": ok, "value": value}
        if len(cache) > 4096:
            ordered = sorted(cache.items(), key=lambda item: float((item[1] or {}).get("at", 0)))
            cache = dict(ordered[-3072:])
        _save_cache(path, cache)
    return value


def notification_fields(ip: str) -> list[tuple[str, str]]:
    intel = lookup_ip(ip)
    network = " ".join(value for value in (intel["asn"], intel["owner"]) if value).strip()
    return [("Geo", intel["flag"]), ("Owner", network or "N/A")]
