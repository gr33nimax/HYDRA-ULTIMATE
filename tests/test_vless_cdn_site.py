"""TSK-006: страница-прикрытие — генератор, данные региона и таймер."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from hydra.contracts import JsonValue
from hydra.contracts.vless_cdn import PROTOCOL_NAME
from hydra.core.state import AppState
from hydra.core.state_models import PluginState
from hydra.core.vless_cdn_page import (
    ImageView,
    SiteData,
    WeatherView,
    render_page,
)
from hydra.services import vless_cdn_site as site

CITY = "Frankfurt am Main"
COUNTRY = "Germany"
CAPITAL = "Berlin"
STAMP = datetime(2026, 9, 19, 0, 30, tzinfo=timezone.utc)

REGION = {
    "country": COUNTRY,
    "country_code": "DE",
    "city": CITY,
    "region": "Hesse",
    "capital": CAPITAL,
    "latitude": "50.110900",
    "longitude": "8.682100",
    "timezone": "Europe/Berlin",
}


def _data(**overrides) -> SiteData:
    values = {
        "country": COUNTRY,
        "country_code": "DE",
        "flag": "🇩🇪",
        "city": CITY,
        "capital": CAPITAL,
        "timezone": "Europe/Berlin",
        "extra_zones": (("London", "Europe/London"), ("Tokyo", "Asia/Tokyo")),
        "updated": "2026-09-19 00:30 UTC",
        "weather": WeatherView(
            temperature="+12 °C",
            condition="Cloudy",
            wind="4.2 m/s",
            humidity="58%",
            updated="00:20 UTC",
        ),
        "image": ImageView(
            src="/assets/region.jpg",
            attribution="Wikimedia Commons, CC BY-SA",
            source="Frankfurt am Main",
        ),
    }
    values.update(overrides)
    return SiteData(**values)


def _state(**config) -> AppState:
    values: dict[str, JsonValue] = {
        "region_country_name": COUNTRY,
        "region_country_code": "DE",
        "region_flag": "🇩🇪",
        "region_city": CITY,
        "region_capital": CAPITAL,
        "region_timezone": "Europe/Berlin",
        "region_latitude": "50.110900",
        "region_longitude": "8.682100",
        "region_extra_timezones": "London=Europe/London,Tokyo=Asia/Tokyo",
    }
    values.update(config)
    state = AppState()
    state.network.server_ip = "203.0.113.10"
    state.protocols[PROTOCOL_NAME] = PluginState(enabled=True, config=values)
    return state


def test_page_describes_the_server_itself():
    page = render_page(_data())

    for fragment in (CITY, COUNTRY, CAPITAL, "🇩🇪", "+12 °C", "Cloudy", "4.2 m/s", "58%"):
        assert fragment in page
    assert "/assets/region.jpg" in page
    assert "Wikimedia Commons" in page
    assert "<title>" in page and CITY in page.split("<title>")[1].split("</title>")[0]


def test_clocks_are_rendered_from_iana_zones_in_the_browser():
    page = render_page(_data())

    assert 'data-zone="Europe/Berlin"' in page
    assert 'data-zone="Europe/London"' in page
    assert 'data-zone="Asia/Tokyo"' in page
    assert "Intl.DateTimeFormat" in page, "часы считает браузер по зоне"
    assert "setInterval" in page, "часы должны идти, а не стоять"


def test_page_needs_no_third_party_hosts():
    page = render_page(_data())

    assert "http://" not in page
    assert "https://" not in page, "никаких внешних зависимостей на странице"


def test_missing_weather_keeps_the_page_usable():
    page = render_page(_data(weather=WeatherView(available=False)))

    assert "temporarily unavailable" in page
    assert CITY in page
    assert 'data-zone="Europe/Berlin"' in page


def test_missing_image_falls_back_to_a_local_placeholder():
    page = render_page(_data(image=ImageView()))

    assert "hero placeholder" in page
    assert "<img" not in page


def test_primary_zone_comes_first_and_is_not_repeated():
    data = _data(extra_zones=(("Berlin", "Europe/Berlin"), ("Tokyo", "Asia/Tokyo")))

    assert data.zones == ((CITY, "Europe/Berlin"), ("Tokyo", "Asia/Tokyo"))


def test_unknown_zones_are_dropped_not_fatal():
    assert site.extra_zones("London=Europe/London, Bad=Not/AZone, Tokyo=Asia/Tokyo") == (
        ("London", "Europe/London"),
        ("Tokyo", "Asia/Tokyo"),
    )
    assert site.extra_zones("Europe/London") == ()
    assert site.extra_zones("") == ()


def test_site_data_is_built_from_state_and_a_stamp():
    data = site.build_site_data(_state(), now=STAMP)

    assert data.city == CITY
    assert data.country == COUNTRY
    assert data.capital == CAPITAL
    assert data.flag == "🇩🇪"
    assert data.timezone == "Europe/Berlin"
    assert data.extra_zones == (("London", "Europe/London"), ("Tokyo", "Asia/Tokyo"))
    assert data.updated == "2026-09-19 00:30 UTC"
    assert data.weather.available is False, "погода появится отдельной задачей"
    assert data.image.src == "", "изображение появится отдельной задачей"


def test_region_is_filled_once_and_never_overwritten():
    state = _state(region_city="", region_capital="", region_timezone="")
    calls: list[str] = []

    def lookup(address: str) -> dict[str, str]:
        calls.append(address)
        return dict(REGION)

    assert site.ensure_region(state, lookup=lookup) is True
    config = state.protocols[PROTOCOL_NAME].config

    assert calls == ["203.0.113.10"]
    assert config["region_city"] == CITY
    assert config["region_capital"] == CAPITAL
    assert config["region_timezone"] == "Europe/Berlin"
    assert config["region_flag"] == "🇩🇪"

    # Второй проход ничего не делает: значения уже есть.
    assert site.ensure_region(state, lookup=lookup) is False
    assert calls == ["203.0.113.10"]


def test_page_is_written_to_the_directory_the_backend_serves(tmp_path):
    state = _state(region_city="", region_capital="")
    calls: list[str] = []

    def lookup(address: str) -> dict[str, str]:
        calls.append(address)
        return dict(REGION)

    target = site.refresh_site(state, directory=tmp_path, now=STAMP, lookup=lookup)

    assert target.name == "index.html"
    page = Path(target).read_text(encoding="utf-8")
    assert CITY in page
    assert "2026-09-19 00:30 UTC" in page

    site.refresh_site(state, directory=tmp_path, now=STAMP, lookup=lookup)
    assert calls == ["203.0.113.10"], "провайдера спрашиваем один раз"


def test_refresh_refuses_an_unconfigured_protocol(tmp_path):
    with pytest.raises(LookupError):
        site.refresh_site(AppState(), directory=tmp_path)


@pytest.fixture(autouse=True)
def _no_provider_calls(monkeypatch):
    """Ни один тест этой страницы не должен случайно пойти в сеть за погодой."""
    monkeypatch.setattr(
        site,
        "weather_view",
        lambda *args, **kwargs: WeatherView(available=False),
    )


def test_page_takes_weather_from_the_region_coordinates(tmp_path, monkeypatch):
    seen: dict[str, str] = {}

    def fake_weather(latitude: object, longitude: object, **kwargs) -> WeatherView:
        seen.update({"lat": str(latitude), "lon": str(longitude)})
        return WeatherView(temperature="+12 °C", condition="Cloudy", wind="4.2 m/s")

    monkeypatch.setattr(site, "weather_view", fake_weather)
    target = site.refresh_site(_state(), directory=tmp_path, now=STAMP)

    assert seen == {"lat": "50.110900", "lon": "8.682100"}
    page = Path(target).read_text(encoding="utf-8")
    assert "+12 °C" in page
    assert "Cloudy" in page
    assert "4.2 m/s" in page


def test_page_survives_a_silent_weather_provider(tmp_path):
    target = site.refresh_site(_state(), directory=tmp_path, now=STAMP)

    page = Path(target).read_text(encoding="utf-8")
    assert "temporarily unavailable" in page
    assert CITY in page
    assert 'data-zone="Europe/Berlin"' in page


def test_timer_units_follow_the_house_pattern(tmp_path):
    root = tmp_path / "hydra"
    interpreter = root / ".venv" / "bin" / "python"

    service, timer = site.site_units(root, interpreter)

    assert f"ExecStart={interpreter} -m hydra.entrypoints.vless_cdn_site" in service
    assert f"PYTHONPATH={root}" in service
    assert f"WorkingDirectory={root}" in service
    assert "Type=oneshot" in service
    assert "OnCalendar=*:0/10" in timer
    assert "Persistent=true" in timer
    assert "WantedBy=timers.target" in timer


def test_installing_the_timer_uses_the_shared_installer(monkeypatch, tmp_path):
    captured: dict[str, str] = {}

    def fake_install(name: str, service: str, timer: str) -> bool:
        captured.update({"name": name, "service": service, "timer": timer})
        return True

    monkeypatch.setattr(site.systemd, "install_timer", fake_install)

    assert site.install_site_timer(tmp_path) is True
    assert captured["name"] == site.TIMER_NAME == "hydra-vless-cdn-site"
    assert "vless_cdn_site" in captured["service"]
