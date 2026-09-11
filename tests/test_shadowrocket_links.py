"""Transport details survive Shadowrocket URI conversion."""
import base64
from urllib.parse import parse_qs, urlsplit

import pytest

from hydra.services.subscriptions.shadowrocket import (
    build_shadowrocket_naive_links,
    build_shadowrocket_snell_link,
)


@pytest.mark.parametrize("relay", ["0", "1", "2"])
def test_snell_keeps_obfuscation_and_numeric_udp_mode(relay):
    link = build_shadowrocket_snell_link(
        f"snell://p%40ss@[2001:db8::1]:32000?version=4&udp-relay={relay}"
        "&obfs-mode=http&obfs-host=cdn.example.com#Example",
    )
    parsed = urlsplit(link)
    assert base64.b64decode(parsed.netloc).decode() == (
        "chacha20-ietf-poly1305:p@ss@[2001:db8::1]:32000"
    )
    assert parse_qs(parsed.query) == {
        "version": ["4"], "udp-relay": [relay],
        "obfs-mode": ["http"], "obfs-host": ["cdn.example.com"],
    }
    assert parsed.fragment == "Example"


def test_naive_http3_keeps_custom_tls_name_and_unicode_credentials():
    links = build_shadowrocket_naive_links(
        "naive+quic://user:%D0%BF%D0%B0%D1%80%D0%BE%D0%BB%D1%8C"
        "@[2001:db8::1]:8443?sni=proxy.example.com#QUIC",
    )
    assert len(links) == 1
    parsed = urlsplit(links[0])
    assert parsed.scheme == "http3"
    assert parse_qs(parsed.query) == {
        "peer": ["proxy.example.com"], "alpn": ["h3"], "remarks": ["QUIC"],
        "padding": ["1"],
    }
    assert base64.urlsafe_b64decode(parsed.netloc + "=" * (-len(parsed.netloc) % 4)).decode() == (
        "user:пароль@[2001:db8::1]:8443"
    )
