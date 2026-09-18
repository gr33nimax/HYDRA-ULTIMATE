"""TSK-004: inbound VLESS с XHTTP packet-up и VLESS Encryption."""
from __future__ import annotations

import base64
import re

import pytest

from hydra.contracts import JsonValue
from hydra.contracts.vless_cdn import (
    DEFAULT_XHTTP_PATH,
    ENCRYPTION_SCHEME,
    PROTOCOL_NAME,
    client_encryption_value,
    generate_encryption_keypair,
    server_encryption_value,
)
from hydra.core.state import AppState
from hydra.core.state_models import PluginState, User
from hydra.plugins.vless_cdn.plugin import VlessCdnPlugin
from hydra.plugins.vless_cdn.profile import MODE, UPLINK_METHOD, xhttp_transport

ORIGIN = "origin.example.com"
CORE_PORT = 20449
USER_UUID = "5f0d6b7a-6f4e-4a5b-9d3c-52c11f0a9b21"


def _state(**overrides) -> AppState:
    config: dict[str, JsonValue] = {
        "origin_host": ORIGIN,
        "xhttp_path": DEFAULT_XHTTP_PATH,
        "core_port": CORE_PORT,
        "encryption_private_key": generate_encryption_keypair()[0],
        "encryption_mode": "native",
    }
    config.update(overrides)
    return AppState(
        protocols={PROTOCOL_NAME: PluginState(enabled=True, config=config)},
        users=[User(email="reader@example.com", uuid=USER_UUID)],
    )


def _inbound(state: AppState | None = None) -> dict:
    fragment = VlessCdnPlugin().configure(state or _state())
    assert len(fragment.inbounds) == 1, "inbound должен быть ровно один"
    return dict(fragment.inbounds[0])


def test_keypair_is_two_distinct_keys_without_padding():
    private_key, public_key = generate_encryption_keypair()

    assert private_key != public_key
    for key in (private_key, public_key):
        assert "=" not in key, "base64url без выравнивания"
        assert len(base64.urlsafe_b64decode(key + "=" * (-len(key) % 4))) == 32


def test_encryption_values_have_the_shape_the_core_parses():
    private_key, public_key = generate_encryption_keypair()

    server = server_encryption_value(private_key)
    client = client_encryption_value(public_key)

    assert server == f"{ENCRYPTION_SCHEME}.native.300-600s.{private_key}"
    assert client == f"{ENCRYPTION_SCHEME}.native.1rtt.{public_key}"
    assert client.split(".")[2] == "1rtt", "0-RTT не используем"


def test_encryption_refuses_values_it_cannot_express():
    with pytest.raises(ValueError):
        server_encryption_value("", mode="native")
    with pytest.raises(ValueError):
        server_encryption_value("key", mode="нет-такого")
    with pytest.raises(ValueError):
        client_encryption_value("", mode="native")


def test_inbound_carries_the_profile_the_core_expects():
    inbound = _inbound()
    transport = inbound["transport"]

    assert inbound["type"] == "vless"
    assert inbound["listen"] == "127.0.0.1", "слушаем только localhost"
    assert inbound["listen_port"] == CORE_PORT
    assert str(inbound["decryption"]).startswith(f"{ENCRYPTION_SCHEME}.native.")
    assert "tls" not in inbound, "TLS завершает web backend"
    assert [user["uuid"] for user in inbound["users"]] == [USER_UUID]

    assert transport["type"] == "xhttp"
    assert transport["mode"] == MODE == "packet-up"
    assert transport["path"] == DEFAULT_XHTTP_PATH
    assert transport["host"] == ORIGIN

    assert transport["x_padding_bytes"] == "100-1000", "ядро не умеет выключать padding"
    assert transport["x_padding_obfs_mode"] is True
    assert transport["x_padding_key"] == "hash"
    assert transport["x_padding_header"] == "X-Client-Version"
    assert transport["x_padding_placement"] == "queryInHeader"
    assert transport["x_padding_method"] == "tokenish"
    assert transport["session_placement"] == "header"
    assert transport["session_key"] == "X-Upload-Token"
    assert transport["session_id_table"] == "Base62"
    assert transport["session_id_length"] == "16-32"
    assert transport["seq_placement"] == "query"
    assert transport["seq_key"] == "chunk_id"
    assert transport["uplink_data_placement"] == "body"
    assert transport["sc_max_each_post_bytes"] == "131072-1048576"
    assert transport["sc_max_buffered_posts"] == 30
    assert transport["sc_min_posts_interval_ms"] == "50-150"
    assert transport["server_max_header_bytes"] == 8192
    assert transport["no_sse_header"] is False
    assert transport["no_grpc_header"] is False


def test_values_that_do_not_belong_here_are_not_copied():
    transport = _inbound()["transport"]

    # В этом ядре h_keep_alive_period читается в секундах и зажимается в 5 с – 5 мин,
    # значение из референса переносить нельзя; поле не задаётся вовсе.
    assert "xmux" not in transport, "мультиплексирование — сторона клиента"
    assert "uplink_http_method" not in transport, "метод выгрузки выбирает клиент"
    assert "sc_stream_up_server_secs" not in transport, "это поле stream-up, а мы packet-up"
    assert "congestion_controller" not in transport, "только HTTP/3"
    assert "cwnd" not in transport, "только HTTP/3"

    assert "h_keep_alive_period" not in str(transport)


def test_client_side_differs_only_by_its_own_fields():
    server = xhttp_transport(DEFAULT_XHTTP_PATH, ORIGIN, client=False)
    client = xhttp_transport(DEFAULT_XHTTP_PATH, ORIGIN, client=True)

    assert client["uplink_http_method"] == UPLINK_METHOD == "GET"
    assert client["xmux"]["max_concurrency"] == "16-32"
    assert client["xmux"]["h_max_reusable_secs"] == 100
    assert "h_keep_alive_period" not in str(client["xmux"]), (
        "поле не задаём: в этом ядре это секунды и диапазон 5 с – 5 мин"
    )

    shared = {key for key in server if key in client}
    for key in ("mode", "path", "host", "x_padding_bytes", "session_key", "seq_key"):
        assert key in shared
        assert server[key] == client[key], f"{key} не должен различаться по сторонам"


@pytest.mark.parametrize(
    "missing",
    [
        {"origin_host": ""},
        {"xhttp_path": ""},
        {"core_port": 0},
        {"encryption_private_key": ""},
        {"encryption_mode": "нет-такого"},
    ],
)
def test_inbound_is_not_emitted_until_everything_is_known(missing):
    fragment = VlessCdnPlugin().configure(_state(**missing))

    assert fragment.is_empty()


def test_inbound_waits_for_a_user():
    state = _state()
    state.users = []

    assert VlessCdnPlugin().configure(state).is_empty()


def test_blocked_users_are_left_out():
    state = _state()
    state.users.append(User(email="blocked@example.com", uuid="blocked", blocked=True))

    inbound = _inbound(state)

    assert [user["uuid"] for user in inbound["users"]] == [USER_UUID]
    assert not re.search("blocked", str(inbound))
