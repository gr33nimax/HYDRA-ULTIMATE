"""TSK-005: клиентский профиль и share-данные на публичный CDN-домен."""

from __future__ import annotations

import json
import urllib.parse

import pytest

from hydra.contracts.vless_cdn import (
    DEFAULT_XHTTP_PATH,
    client_encryption_value,
    generate_encryption_keypair,
)
from hydra.core.state_models import User
from hydra.plugins.vless_cdn.client import (
    PUBLIC_PORT,
    SHARE_LINK_NOTE,
    client_view,
    outbound,
    profile,
    share_link,
)
from hydra.plugins.vless_cdn.profile import MODE, UPLINK_METHOD, link_extra, xhttp_transport

CDN = "cdn.example.com"
ORIGIN = "origin.example.com"
USER = User(email="reader@example.com", uuid="5f0d6b7a-6f4e-4a5b-9d3c-52c11f0a9b21")


def _config() -> dict[str, object]:
    private_key, public_key = generate_encryption_keypair()
    return {
        "cdn_domain": CDN,
        "origin_host": ORIGIN,
        "xhttp_path": DEFAULT_XHTTP_PATH,
        "core_port": 20449,
        "encryption_mode": "native",
        "encryption_private_key": private_key,
        "encryption_public_key": public_key,
    }


def test_profile_dials_the_cdn_and_never_the_origin():
    config = _config()

    document = json.loads(profile(USER, config))
    connection = document["outbounds"][0]

    assert connection["server"] == CDN
    assert connection["server_port"] == PUBLIC_PORT == 443
    assert connection["uuid"] == USER.uuid
    assert "tls" in connection and connection["tls"]["server_name"] == CDN

    text = json.dumps(document)
    assert ORIGIN not in text, "адрес origin не должен попадать в клиентский профиль"
    assert str(config["encryption_private_key"]) not in text, "приватный ключ остаётся на сервере"


def test_client_and_server_agree_on_every_shared_setting():
    server = xhttp_transport(DEFAULT_XHTTP_PATH, ORIGIN, client=False)
    client = xhttp_transport(DEFAULT_XHTTP_PATH, CDN, client=True)

    # Различаться обязаны только host (у клиента — публичное имя) и поля своей стороны.
    differing = {
        "host",
        "uplink_http_method",
        "xmux",
        "no_sse_header",
        "sc_max_buffered_posts",
        "sc_min_posts_interval_ms",
        "server_max_header_bytes",
    }
    shared_server = {key: value for key, value in server.items() if key not in differing}
    shared_client = {key: value for key, value in client.items() if key not in differing}

    assert shared_server == shared_client, "общие настройки сервера и клиента разъехались"
    assert client["host"] == CDN
    assert client["uplink_http_method"] == UPLINK_METHOD == "GET"


def test_share_link_carries_every_setting_it_claims():
    config = _config()

    link = share_link(USER, config)
    parsed = urllib.parse.urlparse(link)
    query = dict(urllib.parse.parse_qsl(parsed.query))

    assert parsed.scheme == "vless"
    assert parsed.hostname == CDN
    assert parsed.port == PUBLIC_PORT
    assert parsed.username == USER.uuid

    assert query["type"] == "xhttp"
    assert query["mode"] == MODE == "packet-up"
    assert query["path"] == DEFAULT_XHTTP_PATH
    assert query["host"] == CDN
    assert query["sni"] == CDN
    assert query["alpn"] == "h2"
    assert query["security"] == "tls"
    assert query["encryption"] == client_encryption_value(str(config["encryption_public_key"]))

    extra = json.loads(query["extra"])
    assert extra == link_extra()
    assert extra["uplinkHTTPMethod"] == "GET"
    assert extra["xPaddingBytes"] == "100-1000"
    assert extra["sessionIDKey"] == "X-Upload-Token"
    assert extra["seqKey"] == "chunk_id"
    assert extra["xmux"]["maxConcurrency"] == "16-32"
    assert "hKeepAlivePeriod" not in json.dumps(extra), (
        "поле не задаём: в этом ядре это секунды, а не миллисекунды референса"
    )


def test_share_link_does_not_leak_the_origin_or_the_private_key():
    config = _config()

    link = share_link(USER, config)

    assert ORIGIN not in link
    assert str(config["encryption_private_key"]) not in link


def test_client_side_artifacts_require_a_public_key():
    config = _config()
    config["encryption_public_key"] = ""

    for build in (lambda: profile(USER, config), lambda: share_link(USER, config)):
        with pytest.raises(ValueError):
            build()


def test_client_view_is_honest_about_what_the_link_cannot_do():
    view = client_view(USER, _config())

    assert view["server"] == CDN
    assert view["port"] == PUBLIC_PORT
    assert view["path"] == DEFAULT_XHTTP_PATH
    assert view["mode"] == MODE
    assert view["share_note"] == SHARE_LINK_NOTE
    assert "extra" in view["share_note"]


def test_outbound_tag_is_personal_and_stable():
    first = outbound(USER, _config())
    second = outbound(USER, _config())

    assert first["tag"] == second["tag"]
    assert USER.email in str(first["tag"])
