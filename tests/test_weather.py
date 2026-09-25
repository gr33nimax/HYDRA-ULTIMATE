"""TSK-007: погода — один провайдер, кеш и честный отказ."""

from __future__ import annotations

from pathlib import Path

from hydra.core.weather import CACHE_TTL, weather_view

PAYLOAD = {
    "temperature_2m": 12.34,
    "weather_code": 3,
    "wind_speed_10m": 4.2,
    "relative_humidity_2m": 58,
    "time": "2026-09-19T21:43",
}


def _fetcher(payload: dict | None = PAYLOAD, calls: list | None = None, error: bool = False):
    log = calls if calls is not None else []

    def fetch(latitude: str, longitude: str) -> dict | None:
        log.append((latitude, longitude))
        if error:
            raise RuntimeError("провайдер упал")
        return payload

    return fetch, log


def test_reading_is_formatted_for_the_page(tmp_path):
    fetch, _ = _fetcher()

    view = weather_view("60.169517", "24.935449", now=100, cache_file=tmp_path / "w.json", fetcher=fetch)

    assert view.available is True
    assert view.temperature == "+12 °C"
    assert view.condition == "Overcast"
    assert view.wind == "4.2 m/s"
    assert view.humidity == "58%"
    assert view.updated == "21:43 UTC"


def test_repeat_views_inside_the_window_do_not_call_the_provider(tmp_path):
    fetch, calls = _fetcher()
    cache = tmp_path / "w.json"

    first = weather_view("60.0", "24.0", now=100, cache_file=cache, fetcher=fetch)
    second = weather_view("60.0", "24.0", now=100 + CACHE_TTL - 1, cache_file=cache, fetcher=fetch)

    assert first == second
    assert len(calls) == 1


def test_expired_window_is_refreshed(tmp_path):
    fetch, calls = _fetcher()
    cache = tmp_path / "w.json"

    weather_view("60.0", "24.0", now=100, cache_file=cache, fetcher=fetch)
    weather_view("60.0", "24.0", now=100 + CACHE_TTL + 1, cache_file=cache, fetcher=fetch)

    assert len(calls) == 2


def test_failure_keeps_the_last_good_reading(tmp_path):
    cache = tmp_path / "w.json"
    good, _ = _fetcher()
    weather_view("60.0", "24.0", now=100, cache_file=cache, fetcher=good)

    broken, _ = _fetcher(payload=None)
    view = weather_view("60.0", "24.0", now=100 + CACHE_TTL + 1, cache_file=cache, fetcher=broken)

    assert view.available is True, "последнее удачное значение лучше пустоты"
    assert view.temperature == "+12 °C"


def test_an_exception_from_the_provider_is_not_fatal(tmp_path):
    cache = tmp_path / "w.json"
    good, _ = _fetcher()
    weather_view("60.0", "24.0", now=100, cache_file=cache, fetcher=good)

    broken, _ = _fetcher(error=True)
    view = weather_view("60.0", "24.0", now=100 + CACHE_TTL + 1, cache_file=cache, fetcher=broken)

    assert view.temperature == "+12 °C"


def test_without_a_cache_a_failure_is_reported_honestly(tmp_path):
    broken, _ = _fetcher(payload=None)

    view = weather_view("60.0", "24.0", now=100, cache_file=tmp_path / "w.json", fetcher=broken)

    assert view.available is False
    assert view.temperature == ""
    assert view.condition == ""


def test_missing_coordinates_are_never_a_request(tmp_path):
    fetch, calls = _fetcher()

    for latitude, longitude in (("", "24.0"), ("60.0", ""), (None, None)):
        view = weather_view(latitude, longitude, now=100, cache_file=tmp_path / "w.json", fetcher=fetch)
        assert view.available is False

    assert calls == []


def test_an_unknown_code_is_shown_as_a_code_not_invented(tmp_path):
    fetch, _ = _fetcher(payload={**PAYLOAD, "weather_code": 1234})

    view = weather_view("60.0", "24.0", now=100, cache_file=tmp_path / "w.json", fetcher=fetch)

    assert view.condition == "Code 1234"


def test_partial_payload_keeps_the_fields_it_has(tmp_path):
    fetch, _ = _fetcher(payload={"temperature_2m": 5.0})

    view = weather_view("60.0", "24.0", now=100, cache_file=tmp_path / "w.json", fetcher=fetch)

    assert view.temperature == "+5 °C"
    assert view.condition == ""
    assert view.wind == ""
    assert view.available is True


def test_cache_file_is_created_next_to_the_target(tmp_path):
    cache = tmp_path / "nested" / "w.json"
    fetch, _ = _fetcher()

    weather_view("60.0", "24.0", now=100, cache_file=cache, fetcher=fetch)

    assert Path(cache).exists()
