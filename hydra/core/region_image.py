"""Изображение региона для страницы-прикрытия.

Источник — Викисклад: свободные лицензии, ключ не нужен, и в ответе есть не только файл,
но и требуемая атрибуция. Картинка скачивается один раз и обновляется раз в двенадцать
часов; при неудаче остаётся прошлая копия, а при первом запуске — локальный запасной файл,
поэтому страница никогда не остаётся без изображения и никогда не ссылается на чужой хост.
"""
from __future__ import annotations

import html
import json
import re
import time
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

SEARCH_URL = "https://commons.wikimedia.org/w/api.php"
ASSETS_DIR = "assets"
IMAGE_NAME = "region.jpg"
PLACEHOLDER_NAME = "region.svg"
IMAGE_SRC = f"/{ASSETS_DIR}/{IMAGE_NAME}"
PLACEHOLDER_SRC = f"/{ASSETS_DIR}/{PLACEHOLDER_NAME}"
REFRESH_SECONDS = 12 * 3600
TIMEOUT = 8.0
MIN_BYTES = 4096
MAX_BYTES = 6 * 1024 * 1024
USER_AGENT = "HYDRA-ULTIMATE/decoy-site"
_TAGS = re.compile(r"<[^>]+>")


@dataclass(frozen=True)
class RegionImage:
    """Что показывать на странице и откуда это взялось."""

    src: str
    attribution: str = ""
    source: str = ""
    refreshed: bool = False


def placeholder_svg() -> str:
    """Запасное изображение: локальное, без ссылок наружу и без бинарников в репозитории."""
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" width="1600" height="900" '
        'viewBox="0 0 1600 900" role="img" aria-label="region placeholder">'
        '<defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1">'
        '<stop offset="0" stop-color="#1b2430"/>'
        '<stop offset="0.6" stop-color="#243347"/>'
        '<stop offset="1" stop-color="#1b2430"/>'
        "</linearGradient></defs>"
        '<rect width="1600" height="900" fill="url(#g)"/>'
        '<circle cx="1180" cy="300" r="90" fill="#2f4257" opacity="0.8"/>'
        '<path d="M0 700 L360 520 L700 660 L1040 470 L1600 700 L1600 900 L0 900 Z" '
        'fill="#141b24"/>'
        "</svg>"
    )


def _text(value: object, limit: int = 200) -> str:
    return html.unescape(_TAGS.sub("", str(value or ""))).strip()[:limit]


def _first(pages: dict) -> dict | None:
    for page in pages.values():
        if isinstance(page, dict):
            return page
    return None


def parse_search(payload: object) -> RegionImage | None:
    """Разобрать ответ Викисклада: адрес файла плюс обязательная атрибуция."""
    if not isinstance(payload, dict):
        return None
    query = payload.get("query")
    pages = query.get("pages") if isinstance(query, dict) else None
    page = _first(pages) if isinstance(pages, dict) else None
    if page is None:
        return None

    infos = page.get("imageinfo")
    info = infos[0] if isinstance(infos, list) and infos and isinstance(infos[0], dict) else None
    if info is None:
        return None
    url = str(info.get("thumburl") or info.get("url") or "").strip()
    if not url.startswith("https://"):
        return None

    meta = info.get("extmetadata")
    metadata = meta if isinstance(meta, dict) else {}

    def field(name: str) -> str:
        entry = metadata.get(name)
        value = entry.get("value") if isinstance(entry, dict) else ""
        return _text(value)

    artist = field("Artist") or field("Credit")
    licence = field("LicenseShortName")
    attribution = ", ".join(part for part in (artist, licence) if part)
    title = _text(page.get("title"), 160)

    return RegionImage(src=url, attribution=attribution, source=title)


def _search(query: str) -> RegionImage | None:
    parameters = urllib.parse.urlencode(
        {
            "action": "query",
            "format": "json",
            "generator": "search",
            "gsrsearch": f"filetype:bitmap {query}".strip(),
            "gsrnamespace": "6",
            "gsrlimit": "1",
            "prop": "imageinfo",
            "iiprop": "url|extmetadata|size",
            "iiurlwidth": "1600",
        },
    )
    request = urllib.request.Request(
        f"{SEARCH_URL}?{parameters}",
        headers={"Accept": "application/json", "User-Agent": USER_AGENT},
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            payload = json.loads(response.read(524288))
    except Exception:
        return None
    return parse_search(payload)


def _download(url: str) -> bytes | None:
    """Скачать байты; проверку размера делает тот, кто пишет файл."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            return response.read(MAX_BYTES + 1)
    except Exception:
        return None


def _size_is_sane(data: bytes) -> bool:
    return MIN_BYTES <= len(data) <= MAX_BYTES


def assets_directory(directory: str | Path) -> Path:
    assets = Path(directory) / ASSETS_DIR
    assets.mkdir(parents=True, exist_ok=True)
    return assets


def write_placeholder(directory: str | Path) -> Path:
    """Положить запасное изображение рядом: страница отдаёт его локально."""
    target = assets_directory(directory) / PLACEHOLDER_NAME
    if not target.exists():
        target.write_text(placeholder_svg(), encoding="utf-8")
    return target


def _stored(directory: str | Path) -> Path:
    return assets_directory(directory) / IMAGE_NAME


def as_timestamp(value: object) -> float:
    """Привести сохранённую отметку времени к числу, не доверяя её типу."""
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def refresh_region_image(
    directory: str | Path,
    *,
    query: str,
    last_updated: float = 0.0,
    now: float | None = None,
    force: bool = False,
    search: Callable[[str], RegionImage | None] = _search,
    download: Callable[[str], bytes | None] = _download,
) -> RegionImage:
    """Обновить изображение, если прошло двенадцать часов, и никогда не ломать страницу."""
    timestamp = time.time() if now is None else now
    write_placeholder(directory)
    target = _stored(directory)
    found = target.exists()

    fresh = found and not force and (timestamp - as_timestamp(last_updated)) < REFRESH_SECONDS
    if fresh:
        return RegionImage(src=IMAGE_SRC)

    candidate = search(str(query or "").strip()) if str(query or "").strip() else None
    if candidate is None:
        # Нечего качать: остаётся прошлая копия, иначе — запасной файл.
        return RegionImage(src=IMAGE_SRC if found else PLACEHOLDER_SRC)

    data = download(candidate.src)
    if data is None or not _size_is_sane(data):
        # Мусор и огрызки не должны заменять рабочую картинку.
        return RegionImage(src=IMAGE_SRC if found else PLACEHOLDER_SRC)

    pending = target.with_suffix(target.suffix + ".tmp")
    try:
        pending.write_bytes(data)
        pending.replace(target)
    except OSError:
        return RegionImage(src=IMAGE_SRC if found else PLACEHOLDER_SRC)

    return RegionImage(
        src=IMAGE_SRC,
        attribution=candidate.attribution,
        source=candidate.source,
        refreshed=True,
    )


__all__ = [
    "IMAGE_NAME",
    "IMAGE_SRC",
    "PLACEHOLDER_NAME",
    "PLACEHOLDER_SRC",
    "REFRESH_SECONDS",
    "RegionImage",
    "assets_directory",
    "parse_search",
    "placeholder_svg",
    "refresh_region_image",
    "as_timestamp",
    "write_placeholder",
]
