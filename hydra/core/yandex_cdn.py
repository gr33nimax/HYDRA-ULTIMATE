"""Validated runtime cache for Yandex CDN origin source prefixes."""

from __future__ import annotations

import ipaddress
import json
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from hydra.core.host import HOST

PREFIX_URL = "https://tech.cdn.yandex.net/prefixes/yc.json"
CACHE_FILE = Path("/var/lib/hydra/yandex-cdn-prefixes.json")
CACHE_TTL = 24 * 3600
TIMEOUT = 5.0
MAX_PREFIXES = 4096


@dataclass(frozen=True)
class PrefixRefresh:
    ok: bool
    count: int
    error: str = ""


def _fetch() -> bytes:
    request = urllib.request.Request(PREFIX_URL, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        return response.read(262144)


def _load(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _prefixes(payload: object) -> list[str]:
    values = payload.get("prefixes") if isinstance(payload, dict) else None
    if not isinstance(values, list) or not 0 < len(values) <= MAX_PREFIXES:
        raise ValueError("invalid prefix list")
    networks = [ipaddress.ip_network(str(value), strict=True).with_prefixlen for value in values]
    return sorted(set(networks))


def _store(path: Path, data: dict) -> None:
    HOST.atomic_write(path, json.dumps(data, separators=(",", ":")), mode=0o600)


def refresh_prefixes(
    *,
    cache_file: Path = CACHE_FILE,
    now: float | None = None,
    fetch: Callable[[], bytes] = _fetch,
) -> PrefixRefresh:
    """Refresh the provider list; a bad response keeps the prior snapshot."""
    timestamp = time.time() if now is None else now
    current = _load(cache_file)
    try:
        payload = json.loads(fetch())
        prefixes = _prefixes(payload)
    except (OSError, TypeError, ValueError) as exc:
        current.update({"checked_at": timestamp, "error": str(exc)[:160] or "fetch failed"})
        _store(cache_file, current)
        return PrefixRefresh(False, len(current.get("prefixes", [])), current["error"])
    current.update({"prefixes": prefixes, "fetched_at": timestamp, "checked_at": timestamp, "error": ""})
    _store(cache_file, current)
    return PrefixRefresh(True, len(prefixes))


def contains_peer(
    address: object,
    *,
    cache_file: Path = CACHE_FILE,
    now: float | None = None,
) -> bool:
    """Return true only for a peer in a fresh, previously validated snapshot."""
    try:
        peer = ipaddress.ip_address(str(address))
        data = _load(cache_file)
        fetched_at = float(data.get("fetched_at", 0))
        if (time.time() if now is None else now) - fetched_at > CACHE_TTL:
            return False
        return any(peer in ipaddress.ip_network(prefix, strict=True) for prefix in _prefixes(data))
    except (TypeError, ValueError):
        return False


__all__ = ["CACHE_FILE", "CACHE_TTL", "PREFIX_URL", "PrefixRefresh", "contains_peer", "refresh_prefixes"]
