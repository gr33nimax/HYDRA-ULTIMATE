"""TSK-006: страница-прикрытие — генератор, данные региона и таймер."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from hydra.contracts import JsonValue
from hydra.contracts.vless_cdn import MEDIA_PLAYLIST_PATH, PROTOCOL_NAME
from hydra.core.state import AppState
from hydra.core.state_models import PluginState
from hydra.core.region_image import RegionImage
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


def test_page_plays_the_live_stream_from_the_media_family():
    page = render_page(_data())

    assert '<video id="live-stream"' in page
    assert f'src="{MEDIA_PLAYLIST_PATH}"' in page, "плеер смотрит на медиа-семейство туннеля"
    assert "street camera" in page
    assert 'class="live-tag"' in page
    assert ">LIVE<" in page


def test_player_uses_the_local_hls_library_and_the_handwriting_headers():
    page = render_page(_data())

    assert 'src="/assets/hls.min.js"' in page, "библиотека HLS — со своего origin, не с третьей стороны"
    assert "xhrSetup" in page
    assert "X-Upload-Token" in page, "сессия плеера — та же рука, что у туннеля"
    assert "X-Client-Version" in page, "padding-заголовок совпадает с транспортом"


def test_player_poster_is_the_region_image():
    page = render_page(_data())
    assert 'poster="/assets/region.jpg"' in page


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
    """Ни один тест этой страницы не должен случайно пойти в сеть."""
    monkeypatch.setattr(
        site,
        "weather_view",
        lambda *args, **kwargs: WeatherView(available=False),
    )
    monkeypatch.setattr(
        site,
        "refresh_region_image",
        lambda *args, **kwargs: RegionImage(src="/assets/region.svg"),
    )


def test_attribution_of_a_refreshed_image_reaches_the_page(tmp_path, monkeypatch):
    def fake_refresh(directory: object, **kwargs) -> RegionImage:
        return RegionImage(
            src="/assets/region.jpg",
            attribution="Christian Wolf, CC BY-SA 3.0 de",
            source="File:Skyline Frankfurt am Main 2015.jpg",
            refreshed=True,
        )

    monkeypatch.setattr(site, "refresh_region_image", fake_refresh)
    state = _state()
    target = site.refresh_site(state, directory=tmp_path, now=STAMP)

    page = Path(target).read_text(encoding="utf-8")
    assert 'src="/assets/region.jpg"' in page
    assert "CC BY-SA 3.0 de" in page

    config = state.protocols[PROTOCOL_NAME].config
    assert config["image_attribution"] == "Christian Wolf, CC BY-SA 3.0 de"
    assert config["image_source"] == "File:Skyline Frankfurt am Main 2015.jpg"
    assert config["image_updated_at"] == STAMP.timestamp()


def test_failed_due_image_refresh_stays_due_and_records_the_error(tmp_path):
    state = _state(image_updated_at=100.0)

    image = site.image_for_site(
        protocol=state.protocols[PROTOCOL_NAME],
        directory=tmp_path,
        now=100.0 + 86401,
        refresh=lambda *_args, **_kwargs: RegionImage(src="/assets/region.jpg", error="download failed"),
    )

    config = state.protocols[PROTOCOL_NAME].config
    assert image.src == "/assets/region.jpg"
    assert config["image_updated_at"] == 100.0
    assert config["image_refresh_error"] == "download failed"
    assert config["image_last_attempt_at"] == 86501.0


def test_query_for_the_image_names_the_city_and_the_country(tmp_path, monkeypatch):
    seen: dict[str, str] = {}

    def fake_refresh(directory: object, **kwargs) -> RegionImage:
        seen["query"] = str(kwargs.get("query"))
        seen["last_updated"] = str(kwargs.get("last_updated"))
        return RegionImage(src="/assets/region.svg")

    monkeypatch.setattr(site, "refresh_region_image", fake_refresh)
    site.refresh_site(_state(), directory=tmp_path, now=STAMP)

    assert seen["query"] == f"{CITY} {COUNTRY}"
    assert seen["last_updated"] == "0.0", "без сохранённой отметки окно не действует"


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


def test_timer_entrypoint_updates_state_and_refreshes_prefixes(monkeypatch, tmp_path):
    from hydra.core import state as state_module
    from hydra.core import yandex_cdn
    from hydra.entrypoints import vless_cdn_site

    calls: list[object] = []
    monkeypatch.setattr(yandex_cdn, "refresh_prefixes", lambda: yandex_cdn.PrefixRefresh(True, 1))
    monkeypatch.setattr(
        state_module,
        "update_state",
        lambda mutator: (calls.append(mutator) or AppState(), tmp_path / "index.html"),
    )

    assert vless_cdn_site.main() == 0
    assert len(calls) == 1


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
    stream = MagicMock(return_value=True)
    monkeypatch.setattr(site, "install_stream_service", stream)

    assert site.install_site_timer(tmp_path) is True
    assert captured["name"] == site.TIMER_NAME == "hydra-vless-cdn-site"
    assert "vless_cdn_site" in captured["service"]
    stream.assert_called_once_with(tmp_path)


def test_the_site_stack_installs_the_live_stream_first(monkeypatch, tmp_path):
    """Страница ссылается на плейлист: без потока она указывала бы в пустоту."""
    order: list[str] = []
    monkeypatch.setattr(site, "install_stream_service", lambda root=None: order.append("stream") or True)
    monkeypatch.setattr(
        site.systemd,
        "install_timer",
        lambda *_args: order.append("timer") or True,
    )

    assert site.install_site_timer(tmp_path) is True
    assert order == ["stream", "timer"]


def test_a_missing_ffmpeg_stops_the_site_stack_before_the_timer(monkeypatch, tmp_path):
    """Без ffmpeg потока не будет: лучше явный отказ, чем страница с мёртвым плеером."""
    timer = MagicMock(return_value=True)
    monkeypatch.setattr(site, "install_stream_service", lambda root=None: False)
    monkeypatch.setattr(site.systemd, "install_timer", timer)

    assert site.install_site_timer(tmp_path) is False
    timer.assert_not_called()


def test_a_failed_timer_rolls_back_the_stream_service(monkeypatch, tmp_path):
    cleanup = MagicMock(return_value=True)
    monkeypatch.setattr(site, "install_stream_service", lambda root=None: True)
    monkeypatch.setattr(site.systemd, "install_timer", lambda *_args: False)
    monkeypatch.setattr(site, "remove_stream_service", cleanup)

    assert site.install_site_timer(tmp_path) is False
    cleanup.assert_called_once_with()


def test_removing_the_site_stack_removes_the_stream_too(monkeypatch):
    stream = MagicMock(return_value=True)
    timer = MagicMock(return_value=True)
    monkeypatch.setattr(site, "remove_stream_service", stream)
    monkeypatch.setattr(site.systemd, "remove_unit", timer)

    assert site.remove_site_timer() is True
    stream.assert_called_once_with()
    timer.assert_called_once_with(site.TIMER_NAME)
