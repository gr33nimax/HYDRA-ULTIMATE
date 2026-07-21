import json
from unittest.mock import patch

from hydra.services.security_intel import country_flag, lookup_ip, notification_fields


class _Response:
    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def read(self, _limit):
        return json.dumps({
            "success": True,
            "country_code": "DE",
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
