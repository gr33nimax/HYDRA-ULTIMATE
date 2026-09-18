"""Погода для страницы-прикрытия: один провайдер, кеш и честный отказ.

Провайдер — Open-Meteo: ключ не нужен, ответ маленький. Внешний сбой никогда не ломает
страницу: при неудаче отдаётся последний удачный ответ, а если его нет — состояние
«недоступно», и страница просто не показывает погоду.
"""
from __future__ import annotations

import json
import os
import threading
import time
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

FORECAST_URL = "https://api.open-meteo.com/v1/forecast"
CACHE_FILE = Path("/var/lib/hydra/weather-cache.json")
CACHE_TTL = 12 * 60
LOOKUP_TIMEOUT = 3.0
CURRENT_FIELDS = "temperature_2m,weather_code,wind_speed_10m,relative_humidity_2m"
_lock = threading.Lock()

# Коды WMO: показываем человеческий текст, а не число.
CONDITIONS: dict[int, str] = {
    0: "Clear sky",
    1: "Mainly clear",
    2: "Partly cloudy",
    3: "Overcast",
    45: "Fog",
    48: "Depositing rime fog",
    51: "Light drizzle",
    53: "Drizzle",
    55: "Dense drizzle",
    56: "Light freezing drizzle",
    57: "Freezing drizzle",
    61: "Light rain",
    63: "Rain",
    65: "Heavy rain",
    66: "Light freezing rain",
    67: "Freezing rain",
    71: "Light snow",
    73: "Snow",
    75: "Heavy snow",
    77: "Snow grains",
    80: "Light showers",
    81: "Showers",
    82: "Violent showers",
    85: "Snow showers",
    86: "Heavy snow showers",
    95: "Thunderstorm",
    96: "Thunderstorm with hail",
    99: "Thunderstorm with heavy hail",
}


@dataclass(frozen=True)
class WeatherView:
    """Погода в городе сервера; поля могут быть пустыми, если провайдер молчит."""

    temperature: str = ""
    condition: str = ""
    wind: str = ""
    humidity: str = ""
    updated: str = ""
    available: bool = True


@dataclass(frozen=True)
class WeatherQuery:
    latitude: str
    longitude: str
    cache_file: Path = field(default=CACHE_FILE)


def _condition(code: object) -> str:
    if isinstance(code, bool) or not isinstance(code, (int, float, str)):
        return ""
    try:
        number = int(code)
    except (TypeError, ValueError):
        return ""
    return CONDITIONS.get(number, f"Code {number}")


def _number(value: object, pattern: str) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return ""
    try:
        return pattern.format(float(value))
    except (TypeError, ValueError):
        return ""


def _measured_at(value: object) -> str:
    text = str(value or "").strip()
    if len(text) >= 16 and text[10] == "T":
        return f"{text[11:16]} UTC"
    return ""


def _view(current: dict[str, Any]) -> WeatherView:
    temperature = _number(current.get("temperature_2m"), "{:+.0f}")
    if temperature:
        temperature = f"{temperature} °C"
    return WeatherView(
        temperature=temperature,
        condition=_condition(current.get("weather_code")),
        wind=(
            f"{_number(current.get('wind_speed_10m'), '{:.1f}')} m/s"
            if _number(current.get("wind_speed_10m"), "{:.1f}")
            else ""
        ),
        humidity=(
            f"{_number(current.get('relative_humidity_2m'), '{:.0f}')}%"
            if _number(current.get("relative_humidity_2m"), "{:.0f}")
            else ""
        ),
        updated=_measured_at(current.get("time")),
        available=True,
    )


def _load(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, TypeError, ValueError):
        return {}


def _save(path: Path, data: dict) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        pending = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
        pending.write_text(json.dumps(data, separators=(",", ":")), encoding="utf-8")
        pending.chmod(0o600)
        pending.replace(path)
    except OSError:
        pass


def _key(latitude: str, longitude: str) -> str:
    return f"{latitude},{longitude}"


def _fetch(latitude: str, longitude: str) -> dict[str, Any] | None:
    parameters = urllib.parse.urlencode(
        {
            "latitude": latitude,
            "longitude": longitude,
            "current": CURRENT_FIELDS,
            "wind_speed_unit": "ms",
        },
    )
    request = urllib.request.Request(
        f"{FORECAST_URL}?{parameters}",
        headers={"Accept": "application/json", "User-Agent": "HYDRA-ULTIMATE/decoy-site"},
    )
    try:
        with urllib.request.urlopen(request, timeout=LOOKUP_TIMEOUT) as response:
            payload = json.loads(response.read(131072))
    except Exception:
        return None
    current = payload.get("current") if isinstance(payload, dict) else None
    return current if isinstance(current, dict) else None


def weather_view(
    latitude: object,
    longitude: object,
    *,
    now: float | None = None,
    cache_file: Path | None = None,
    fetcher: Callable[[str, str], dict[str, Any] | None] = _fetch,
) -> WeatherView:
    """Погода по координатам: из кеша, из провайдера или последняя удачная."""
    lat = str(latitude or "").strip()
    lon = str(longitude or "").strip()
    if not lat or not lon:
        return WeatherView(available=False)

    timestamp = time.time() if now is None else now
    path = cache_file or CACHE_FILE
    key = _key(lat, lon)
    with _lock:
        cached = _load(path).get(key)
    entry: dict[str, Any] = cached if isinstance(cached, dict) else {}
    stored = entry.get("value")
    value: dict[str, Any] | None = stored if isinstance(stored, dict) else None
    if value is not None and timestamp - _stamp(entry) < CACHE_TTL:
        return _view(value)

    try:
        current = fetcher(lat, lon)
    except Exception:
        # Любая ошибка провайдера — это просто отсутствие свежих данных.
        current = None
    if current is None:
        # Внешний отказ: показываем последний удачный ответ, если он был.
        return _view(value) if value is not None else WeatherView(available=False)

    view = _view(current)
    with _lock:
        cache = _load(path)
        cache[key] = {"at": timestamp, "value": current}
        if len(cache) > 256:
            ordered = sorted(cache.items(), key=lambda item: _stamp(item[1]))
            cache = dict(ordered[-192:])
        _save(path, cache)
    return view


def _stamp(entry: object) -> float:
    raw = entry.get("at", 0) if isinstance(entry, dict) else 0
    try:
        return float(raw or 0)
    except (TypeError, ValueError):
        return 0.0


__all__ = [
    "CACHE_FILE",
    "CACHE_TTL",
    "CONDITIONS",
    "FORECAST_URL",
    "LOOKUP_TIMEOUT",
    "WeatherQuery",
    "WeatherView",
    "weather_view",
]
