import json
from unittest.mock import patch

from hydra.services.security_intel import (
    country_flag,
    lookup_ip,
    lookup_region,
    notification_fields,
)


class _Response:
    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def read(self, _limit):
        return json.dumps({
            "success": True,
            "country": "Germany",
            "country_code": "DE",
            "region": "Hesse",
            "city": "Frankfurt am Main",
            "capital": "Berlin",
            "latitude": 50.1109,
            "longitude": 8.6821,
            "timezone": {"id": "Europe/Berlin"},
            "connection": {"asn": 24940, "org": "Hetzner Online GmbH"},
        }).encode()


def test_country_code_is_rendered_as_flag():
    assert country_flag("DE") == "🇩🇪"
    assert country_flag("") == "🌐"


def test_lookup_is_cached_and_formats_owner(tmp_path):
    cache = tmp_path / "intel.json"
    with patch("hydra.services.security_intel.urllib.request.urlopen", return_value=_Response()) as request:
        first = lookup_ip("8.8.8.8", now=100, cache_file=cache)
        second = lookup_ip("8.8.8.8", now=101, cache_file=cache)
    assert request.call_count == 1
    assert first == second == {
        "country_code": "DE", "flag": "🇩🇪",
        "owner": "Hetzner Online GmbH", "asn": "AS24940",
    }


def test_lookup_failure_is_fail_open(tmp_path):
    with patch("hydra.services.security_intel.urllib.request.urlopen", side_effect=OSError("offline")):
        value = lookup_ip("8.8.4.4", now=100, cache_file=tmp_path / "cache.json")
    assert value["flag"] == "🌐"
    assert value["owner"] == "N/A"


def test_notification_fields_include_flag_and_network(tmp_path):
    with patch("hydra.services.security_intel.CACHE_FILE", tmp_path / "cache.json"), \
         patch("hydra.services.security_intel.urllib.request.urlopen", return_value=_Response()):
        assert notification_fields("8.8.8.8") == [
            ("Geo", "🇩🇪"), ("Owner", "AS24940 Hetzner Online GmbH"),
        ]


def test_region_comes_from_the_same_single_request(tmp_path):
    cache = tmp_path / "intel.json"
    with patch("hydra.services.security_intel.urllib.request.urlopen", return_value=_Response()) as request:
        region = lookup_region("8.8.8.8", now=100, cache_file=cache)
        again = lookup_region("8.8.8.8", now=101, cache_file=cache)

    assert request.call_count == 1, "регион не должен стоить второго запроса"
    assert region == again == {
        "country": "Germany",
        "country_code": "DE",
        "city": "Frankfurt am Main",
        "region": "Hesse",
        "capital": "Berlin",
        "latitude": "50.110900",
        "longitude": "8.682100",
        "timezone": "Europe/Berlin",
    }


def test_region_and_notification_share_one_lookup(tmp_path):
    cache = tmp_path / "intel.json"
    with patch("hydra.services.security_intel.urllib.request.urlopen", return_value=_Response()) as request:
        intel = lookup_ip("8.8.8.8", now=100, cache_file=cache)
        region = lookup_region("8.8.8.8", now=100, cache_file=cache)

    assert request.call_count == 1
    assert intel["flag"] == "🇩🇪"
    assert region["country_code"] == intel["country_code"]


def test_region_is_empty_for_private_or_broken_addresses(tmp_path):
    with patch("hydra.services.security_intel.urllib.request.urlopen") as request:
        assert lookup_region("127.0.0.1", cache_file=tmp_path / "c.json") == {}
        assert lookup_region("не-адрес", cache_file=tmp_path / "c.json") == {}

    assert request.call_count == 0, "локальные адреса не спрашиваем у провайдера"


def test_region_is_fail_open_when_the_provider_is_silent(tmp_path):
    with patch(
        "hydra.services.security_intel.urllib.request.urlopen",
        side_effect=OSError("offline"),
    ):
        region = lookup_region("8.8.4.4", now=100, cache_file=tmp_path / "cache.json")

    assert region == {}


def test_region_survives_a_provider_without_the_fields(tmp_path):
    class _Bare(_Response):
        def read(self, _limit):
            return json.dumps({"success": True, "country_code": "FI"}).encode()

    with patch("hydra.services.security_intel.urllib.request.urlopen", return_value=_Bare()):
        region = lookup_region("8.8.8.8", now=100, cache_file=tmp_path / "cache.json")

    assert region["country_code"] == "FI"
    assert region["city"] == ""
    assert region["latitude"] == ""
    assert region["timezone"] == ""
