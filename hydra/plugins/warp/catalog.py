"""Dynamic rule-source catalogue published by Geo-Aggregator.

The catalogue is data, not code: HYDRA caches ``db/catalog.json`` and rebuilds
the operator's menu from it, so a service added upstream appears without a
release. Every source is one line-per-entry text list, which is exactly what
:func:`hydra.plugins.warp.rules.parse_rule_list` consumes.
"""

from __future__ import annotations

from datetime import datetime, timedelta
import json
from pathlib import Path
from typing import Any
import urllib.request

from hydra.plugins.warp.constants import (
    CATALOG_URL,
    EXTERNAL_LISTS,
    EXTRA_SOURCES,
    RU_TLD_SOURCE,
    is_granular_source,
)

CATALOG_TTL = timedelta(hours=24)
_REQUEST_TIMEOUT = 30
_HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}


def _copy(sources: dict[str, dict[str, str]]) -> dict[str, dict[str, str]]:
    return {key: dict(value) for key, value in sources.items() if is_granular_source(key)}


def fetch_sources(*, timeout: int = _REQUEST_TIMEOUT) -> dict[str, dict[str, str]]:
    """Download the upstream catalogue and normalise it into source records."""
    request = urllib.request.Request(CATALOG_URL, headers=_HEADERS)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = response.read().decode("utf-8", errors="replace")
    try:
        document = json.loads(payload)
    except ValueError as exc:
        raise ValueError(f"catalogue is not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise ValueError("catalogue is not a JSON object")
    base = str(document.get("base") or "").strip()
    if not base:
        raise ValueError("catalogue has no base url")
    labels = {
        str(category.get("id")): str(category.get("name") or category.get("id"))
        for category in document.get("categories") or []
        if isinstance(category, dict)
    }
    sources = _copy(EXTRA_SOURCES)
    # category-ru is an umbrella: it physically aggregates every Russian
    # `category-*-ru` list, so selecting it routes all of them. itDog-* and
    # single services (mosmetro) are intentionally left out of the union.
    russian_urls: list[str] = []
    for service in document.get("services") or []:
        if not isinstance(service, dict):
            continue
        key = str(service.get("id") or "").strip()
        path = str(service.get("src") or "").strip()
        group = str(service.get("cat") or "other")
        if key and path and group == "ru" and key.lower().startswith("category-"):
            russian_urls.append(base + path)
        if not key or not path or not is_granular_source(key):
            continue
        sources[key] = {
            "name": str(service.get("name") or key),
            "url": base + path,
            "desc": labels.get(group, group),
            "group": group,
        }
    if not sources:
        raise ValueError("catalogue carries no services")
    if RU_TLD_SOURCE in sources and russian_urls:
        own = sources[RU_TLD_SOURCE]["url"]
        sources[RU_TLD_SOURCE]["urls"] = "\n".join(dict.fromkeys([own, *russian_urls]))
    return sources


def load_sources(
    cache: Path,
    fallback: dict[str, dict[str, str]] | None = None,
) -> dict[str, dict[str, str]]:
    """Return the cached catalogue, or the builtin fallback when unusable."""
    builtin = EXTERNAL_LISTS if fallback is None else fallback
    try:
        document = json.loads(cache.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return _copy(builtin)
    stored = document.get("sources") if isinstance(document, dict) else None
    if not isinstance(stored, dict) or not stored:
        return _copy(builtin)
    return {
        **_copy(builtin),
        **{
            str(key): dict(value)
            for key, value in stored.items()
            if isinstance(value, dict) and is_granular_source(str(key))
        },
    }


def refresh_due(cache: Path, *, max_age: timedelta = CATALOG_TTL) -> bool:
    """Treat a missing, stale, or malformed catalogue cache as due for refresh."""
    try:
        document = json.loads(cache.read_text(encoding="utf-8"))
        updated_at = datetime.fromisoformat(str(document["updated_at"]))
        if not isinstance(document["sources"], dict) or not any(
            is_granular_source(str(key)) for key in document["sources"]
        ):
            return True
    except (OSError, ValueError, KeyError, TypeError):
        return True
    return datetime.now() - updated_at >= max_age


def refresh_sources(
    cache: Path,
    *,
    host: Any,
    timeout: int = _REQUEST_TIMEOUT,
) -> tuple[bool, str]:
    """Fetch and persist the catalogue; report why it could not be refreshed."""
    try:
        sources = fetch_sources(timeout=timeout)
    except Exception as exc:
        return False, f"Не удалось обновить каталог списков: {exc}"
    try:
        host.atomic_write(
            cache,
            json.dumps(
                {
                    "updated_at": datetime.now().isoformat(),
                    "sources": sources,
                },
                indent=2,
                ensure_ascii=False,
            ),
            mode=0o600,
        )
    except Exception as exc:
        return False, f"Не удалось сохранить каталог списков: {exc}"
    return True, f"Каталог списков обновлён: {len(sources)} источников."


__all__ = [
    "CATALOG_TTL",
    "fetch_sources",
    "load_sources",
    "refresh_due",
    "refresh_sources",
]
