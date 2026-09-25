"""Transport details survive Shadowrocket URI conversion."""

import base64
import json
from urllib.parse import parse_qs, urlsplit

import pytest

import hydra.services.subscriptions.shadowrocket as shadowrocket

from hydra.services.subscriptions.shadowrocket import (
    build_shadowrocket_naive_links,
    build_shadowrocket_snell_link,
)


@pytest.mark.parametrize(("relay", "expected_udp"), [("false", "0"), ("true", "1"), ("2", "1")])
@pytest.mark.parametrize(
    ("mode", "expected_plugin"),
    [
        ("http", "obfs-local;obfs=http;obfs-host=cdn.example.com;obfs-uri=/"),
        ("tls", 'obfs-local;obfs=tls;obfs-host={"Host":"cdn.example.com"};obfs-uri=/'),
    ],
)
def test_snell_obfuscation_uses_shadowrocket_plugin_uri(mode, expected_plugin, relay, expected_udp):
    link = build_shadowrocket_snell_link(
        f"snell://p%40ss@[2001:db8::1]:32000?version=4&udp-relay={relay}"
        f"&obfs-mode={mode}&obfs-host=cdn.example.com#Example",
    )
    parsed = urlsplit(link)

    assert base64.b64decode(parsed.username or "").decode() == "chacha20-ietf-poly1305:p@ss"
    assert parsed.hostname == "2001:db8::1"
    assert parsed.port == 32000
    assert parse_qs(parsed.query) == {
        "plugin": [expected_plugin],
        "version": ["4"],
        "udp": [expected_udp],
    }
    assert parsed.fragment == "Example"


def test_snell_none_uses_shadowrockets_udp_form():
    link = build_shadowrocket_snell_link(
        "snell://p%40ss@[2001:db8::1]:32000?version=4&udp-relay=true#Example",
    )
    parsed = urlsplit(link)

    assert base64.b64decode(parsed.netloc).decode() == "chacha20-ietf-poly1305:p@ss@[2001:db8::1]:32000"
    assert parse_qs(parsed.query) == {"version": ["4"], "udp": ["1"]}
    assert parsed.fragment == "Example"


def test_awg_uses_shadowrockets_obfs_param_and_preserves_base64_plus():
    link = (
        "wg://203.0.113.10:52017?private_key=private+key/=&local_address=10.67.67.11/32"
        "&enable_amnezia=true&jc=2&jmin=27&jmax=39&s1=9&s2=6&s3=0&s4=0"
        "&h1=101&h2=102&h3=103&h4=104&i1=feedface"
        "&header_protection_key=header+key/=&content_padding_addition=50-100"
        "&rekey_after_time=100-140&rekey_timeout=4-6&reject_after_time=160-200"
        "&keepalive_timeout=8-12&max_handshake_attempts=7&random_trailers=true"
        "&disable_cookies=false&public_key=public+key/=&pre_shared_key=shared+key/="
        "&persistent_keepalive_interval=25#Example"
    )
    converted = shadowrocket.build_shadowrocket_awg_link(link)
    parsed = urlsplit(converted)
    query = parse_qs(parsed.query)

    assert parsed.hostname == "203.0.113.10"
    assert parsed.port == 52017
    assert query["publicKey"] == ["public+key/="]
    assert query["privateKey"] == ["private+key/="]
    assert query["presharedKey"] == ["shared+key/="]
    assert query["ip"] == ["10.67.67.11/32"]
    assert query["keepalive"] == ["25"]
    assert query["udp"] == ["1"]
    assert query["obfs"] == ["amneziawg"]
    assert "privateKey=private%2Bkey%2F%3D" in converted
    assert json.loads(query["obfsParam"][0]) == {
        "jc": "2",
        "jmin": "27",
        "jmax": "39",
        "s1": "9",
        "s2": "6",
        "s3": "0",
        "s4": "0",
        "h1": "101",
        "h2": "102",
        "h3": "103",
        "h4": "104",
        "i1": "feedface",
        "header_protection_key": "header+key/=",
        "content_padding_addition": "50-100",
        "rekey_after_time": "100-140",
        "rekey_timeout": "4-6",
        "reject_after_time": "160-200",
        "keepalive_timeout": "8-12",
        "max_handshake_attempts": "7",
        "random_trailers": "true",
        "disable_cookies": "false",
    }
    assert parsed.fragment == "Example"


def test_awg_shadowrocket_defaults_boolean_obfs_fields_to_false():
    converted = shadowrocket.build_shadowrocket_awg_link(
        "wg://203.0.113.10:52017?private_key=private&local_address=10.67.67.11/32"
        "&jc=2&public_key=public&persistent_keepalive_interval=25#Example",
    )

    obfs_param = json.loads(parse_qs(urlsplit(converted).query)["obfsParam"][0])
    assert obfs_param["jc"] == "2"
    assert obfs_param["random_trailers"] == "false"
    assert obfs_param["disable_cookies"] == "false"


def test_naive_http3_keeps_custom_tls_name_and_unicode_credentials():
    links = build_shadowrocket_naive_links(
        "naive+quic://user:%D0%BF%D0%B0%D1%80%D0%BE%D0%BB%D1%8C@[2001:db8::1]:8443?sni=proxy.example.com#QUIC",
    )
    assert len(links) == 1
    parsed = urlsplit(links[0])
    assert parsed.scheme == "http3"
    assert parse_qs(parsed.query) == {
        "remarks": ["QUIC"],
        "padding": ["1"],
    }
    assert base64.urlsafe_b64decode(parsed.netloc + "=" * (-len(parsed.netloc) % 4)).decode() == (
        "user:пароль@[2001:db8::1]:8443"
    )


def test_naive_tcp_variants_drop_uot_when_the_server_does_not_serve_it():
    links = build_shadowrocket_naive_links(
        "naive+https://user:password@example.com:443?security=tls&sni=example.com#Naive",
        uot=False,
    )

    assert [urlsplit(link).scheme for link in links] == ["https", "http2"]
    for link in links:
        query = parse_qs(urlsplit(link).query)
        assert "uot" not in query
        assert query["tfo"] == ["1"]
        assert query["padding"] == ["1"]


def test_naive_tcp_variants_keep_uot_by_default():
    links = build_shadowrocket_naive_links(
        "naive+https://user:password@example.com:443?security=tls&sni=example.com#Naive",
    )

    for link in links:
        query = parse_qs(urlsplit(link).query)
        assert query["uot"] == ["2"]
        assert query["tfo"] == ["1"]
