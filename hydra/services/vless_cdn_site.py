"""Страница-прикрытие: данные о регионе и запись файла, который отдаёт web backend.

Регион берётся из состояния, а если он там ещё не заполнен — из того же источника, что и
флаг в меню (`security_intel.lookup_region`), и сохраняется: страница не должна ходить в
чужой API на каждый показ.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from hydra.contracts.vless_cdn import DECOY_ROOT, PROTOCOL_NAME
from hydra.core import systemd
from hydra.core.host import HOST
from hydra.core.install_layout import project_root as _project_root
from hydra.core.install_layout import python_executable
from hydra.core.state_models import AppState, PluginState
from hydra.core.vless_cdn_page import (
    ImageView,
    SiteData,
    render_page,
)
from hydra.core.weather import WeatherView, weather_view
from hydra.services.security_intel import lookup_region

TIMER_NAME = "hydra-vless-cdn-site"
TIMER_CALENDAR = "*:0/10"
PAGE_NAME = "index.html"

# Соответствие между ответом провайдера и полями состояния.
REGION_KEYS: dict[str, str] = {
    "country_code": "region_country_code",
    "country": "region_country_name",
    "city": "region_city",
    "capital": "region_capital",
    "latitude": "region_latitude",
    "longitude": "region_longitude",
    "timezone": "region_timezone",
}

RegionLookup = Callable[..., dict[str, str]]


def _known_zone(zone: str) -> bool:
    """Зона существует в локальной базе IANA: иначе часы покажут пустоту."""
    try:
        ZoneInfo(zone)
    except (ZoneInfoNotFoundError, ValueError, OSError):
        return False
    return True


def extra_zones(value: object) -> tuple[tuple[str, str], ...]:
    """Разобрать список `Подпись=Зона, …`, отбрасывая всё, что не является зоной.

    Неизвестная зона — это испорченная строка часов, а не повод не отдать страницу.
    """
    entries: list[tuple[str, str]] = []
    for item in str(value or "").split(","):
        label, separator, zone = item.partition("=")
        zone = zone.strip() if separator else ""
        if not zone or not _known_zone(zone):
            continue
        entries.append((label.strip() or zone, zone))
    return tuple(entries)


def _region_of(protocol: PluginState) -> dict[str, str]:
    return {key: str(protocol.config.get(stored, "") or "").strip() for key, stored in REGION_KEYS.items()}


def ensure_region(
    state: AppState,
    *,
    protocol: PluginState | None = None,
    lookup: RegionLookup = lookup_region,
    address: str = "",
) -> bool:
    """Заполнить регион, если его ещё нет. Уже сохранённые значения не трогаем."""
    current = protocol or state.protocols.get(PROTOCOL_NAME)
    if current is None:
        return False
    if all(_region_of(current).values()):
        return False

    target = address or str(state.network.server_ip or "").strip()
    if not target:
        from hydra.utils.net import public_ip

        try:
            target = str(public_ip() or "").strip()
        except Exception:
            return False
    if not target:
        return False

    region = lookup(target)
    if not region:
        return False

    for key, stored in REGION_KEYS.items():
        value = str(region.get(key, "") or "").strip()
        if value and not str(current.config.get(stored, "") or "").strip():
            current.config[stored] = value
    code = str(region.get("country_code", "") or "").strip()
    if code and not str(current.config.get("region_flag", "") or "").strip():
        from hydra.services.security_intel import country_flag

        current.config["region_flag"] = country_flag(code)
    return True


def build_site_data(
    state: AppState,
    *,
    protocol: PluginState | None = None,
    now: datetime | None = None,
    weather: WeatherView | None = None,
    image: ImageView | None = None,
) -> SiteData:
    """Собрать данные страницы: регион, зоны, отметка времени, погода и картинка."""
    current = protocol or state.protocols.get(PROTOCOL_NAME)
    config = current.config if current else {}
    stamp = now or datetime.now(timezone.utc)
    return SiteData(
        country=str(config.get("region_country_name", "") or ""),
        country_code=str(config.get("region_country_code", "") or ""),
        flag=str(config.get("region_flag", "") or ""),
        city=str(config.get("region_city", "") or ""),
        capital=str(config.get("region_capital", "") or ""),
        timezone=str(config.get("region_timezone", "") or ""),
        extra_zones=extra_zones(config.get("region_extra_timezones", "")),
        updated=stamp.strftime("%Y-%m-%d %H:%M UTC"),
        status="operational",
        weather=weather or WeatherView(available=False),
        image=image or ImageView(),
    )


def refresh_site(
    state: AppState,
    *,
    directory: str | Path | None = None,
    now: datetime | None = None,
    weather: WeatherView | None = None,
    image: ImageView | None = None,
    lookup: RegionLookup = lookup_region,
) -> Path:
    """Обновить страницу в каталоге, который отдаёт web backend."""
    current = state.protocols.get(PROTOCOL_NAME)
    if current is None:
        raise LookupError("протокол VLESS через CDN не настроен")

    ensure_region(state, protocol=current, lookup=lookup)
    current_weather = weather if weather is not None else weather_view(
        current.config.get("region_latitude", ""),
        current.config.get("region_longitude", ""),
    )
    data = build_site_data(
        state,
        protocol=current,
        now=now,
        weather=current_weather,
        image=image,
    )

    target_dir = Path(str(directory or DECOY_ROOT))
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / PAGE_NAME
    HOST.atomic_write(target, render_page(data), mode=0o644)
    return target


def site_units(
    root: Path | None = None,
    interpreter: Path | None = None,
    *,
    calendar: str = TIMER_CALENDAR,
) -> tuple[str, str]:
    """Содержимое сервиса и таймера — той же формы, что у остальных задач HYDRA."""
    project = root or _project_root()
    python = interpreter or python_executable(project)
    service = f"""[Unit]
Description=HYDRA VLESS CDN decoy site refresh
After=network.target
[Service]
Type=oneshot
User=root
WorkingDirectory={project}
Environment=PYTHONPATH={project}
ExecStart={python} -m hydra.entrypoints.vless_cdn_site
"""
    timer = f"""[Unit]
Description=HYDRA VLESS CDN decoy site timer
[Timer]
OnCalendar={calendar}
Persistent=true
[Install]
WantedBy=timers.target
"""
    return service, timer


def install_site_timer(root: Path | None = None) -> bool:
    """Поставить таймер обновления страницы через общий установщик юнитов."""
    service, timer = site_units(root)
    return systemd.install_timer(TIMER_NAME, service, timer)


def remove_site_timer() -> bool:
    return systemd.remove_unit(TIMER_NAME)


__all__ = [
    "PAGE_NAME",
    "REGION_KEYS",
    "TIMER_CALENDAR",
    "TIMER_NAME",
    "build_site_data",
    "ensure_region",
    "extra_zones",
    "install_site_timer",
    "refresh_site",
    "remove_site_timer",
    "site_units",
]
