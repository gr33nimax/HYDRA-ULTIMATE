"""tests/test_awg_endpoint_projection.py — the server endpoint the core serves.

Every field comes from desired state: the endpoint *is* the server side of the tunnel, so a peer exists
exactly when HYDRA has issued it an address, and the generation material is what the profile carries.
These tests pin that contract per generation.
"""

import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from hydra.core.state import AppState, PluginState, User  # noqa: E402
from hydra.plugins.amneziawg.endpoints import (  # noqa: E402
    GENERATION_FIELDS_30,
    GENERATION_FIELDS_31,
    generate_generation_material,
)
from hydra.plugins.amneziawg.plugin import AmneziaWGPlugin  # noqa: E402

OBFUSCATION_2X = {
    "Jc": "4",
    "Jmin": "50",
    "Jmax": "1000",
    "S1": "62",
    "S2": "86",
    "S3": "45",
    "S4": "21",
    "H1": "6664925-106664924",
    "H2": "944259910-1044259909",
    "H3": "1459921639-1559921638",
    "H4": "1858653411-1958653410",
    "I1": "aae1e32da608adb221fe63c98a7f1f923e0ee35c5112330784c755c1a3c8d3",
}

GENERATION_31 = {
    "HeaderProtectionKey": "4GPZHbocITJ/d48RQnZcqEsRKjL7SdK1I7PbkSOhGFk=",
    "ContentPaddingAddition": "10-100",
    "RekeyAfterTime": "100-120",
    "RekeyTimeout": "3-7",
    "RejectAfterTime": "150-180",
    "KeepaliveTimeout": "5-15",
    "RandomTrailers": True,
    "DisableCookies": True,
}

PEER_OCTET = "3"


def _project(
    _tmp_path=None,
    *,
    mode: str = "2.0",
    blocked: bool = False,
    with_server_key: bool = True,
    generation: bool = True,
) -> list[dict]:
    profile: dict = {
        "port": 50494,
        "network": "10.67.67.0/24",
        "mtu": "1376",
        "obfuscation": dict(OBFUSCATION_2X),
    }
    if with_server_key:
        profile["server_private_key"] = "server-private"
    if generation and mode != "2.0":
        profile["generation"] = dict(GENERATION_31)
    user = User(email="alice@example.com", uuid="u1", blocked=blocked)
    user.credentials["amneziawg"] = {
        "private_key": "private-d",
        "public_key": "public-d",
        "preshared_key": "psk-d",
        "address_octet": PEER_OCTET,
    }
    state = AppState(
        protocols={
            "amneziawg": PluginState(
                installed=True,
                config={"protocol_mode": mode, "profiles": {"desktop": profile}},
            )
        },
        users=[user],
    )
    return AmneziaWGPlugin().server_endpoints(state)


def test_endpoint_carries_the_served_fields_and_the_issued_peer(tmp_path):
    endpoints = _project(tmp_path)

    assert len(endpoints) == 1
    endpoint = endpoints[0]
    assert endpoint["type"] == "wireguard"
    assert endpoint["tag"] == "awg-desktop"
    assert endpoint["address"] == ["10.67.67.1/24"]
    assert endpoint["private_key"] == "server-private"
    assert endpoint["listen_port"] == 50494
    assert endpoint["mtu"] == 1376
    assert endpoint["peers"] == [
        {
            "public_key": "public-d",
            "pre_shared_key": "psk-d",
            "allowed_ips": ["10.67.67.3/32"],
        }
    ]


def test_2x_endpoint_carries_the_classic_set_and_no_generation_field(tmp_path):
    amnezia = _project(tmp_path)[0]["amnezia"]

    assert amnezia["jc"] == 4
    assert amnezia["s1"] == 62 and amnezia["s4"] == 21
    assert amnezia["h1"] == "6664925-106664924"
    assert amnezia["i1"] == "aae1e32da608adb221fe63c98a7f1f923e0ee35c5112330784c755c1a3c8d3"
    assert "header_protection_key" not in amnezia
    assert "random_trailers" not in amnezia


def test_31_endpoint_carries_the_generation_material_from_state(tmp_path):
    amnezia = _project(tmp_path, mode="3.1")[0]["amnezia"]

    assert amnezia["header_protection_key"] == "4GPZHbocITJ/d48RQnZcqEsRKjL7SdK1I7PbkSOhGFk="
    assert amnezia["content_padding_addition"] == "10-100"
    assert amnezia["rekey_timeout"] == "3-7"
    assert amnezia["random_trailers"] is True
    assert amnezia["disable_cookies"] is True
    assert "i1" not in amnezia


def test_a_blocked_user_has_no_peer(tmp_path):
    assert _project(tmp_path, blocked=True)[0]["peers"] == []


def test_a_profile_without_a_server_key_is_not_invented(tmp_path):
    assert _project(tmp_path, with_server_key=False) == []


def test_generated_material_fills_a_31_profile():
    material = generate_generation_material("3.1")

    assert len(material["HeaderProtectionKey"]) == 44  # 32 bytes, base64
    assert material["ContentPaddingAddition"] == "10-100"
    assert material["RandomTrailers"] is True
    # 3.1 *is* this pair — random trailers on, cookies off — so the material carries it and every
    # link of this generation says the same thing.
    assert material["DisableCookies"] is True
    assert generate_generation_material("2.0") == {}


def _served_state(mode: str = "2.0", *, material: dict | None = None) -> AppState:
    profile: dict = {"server_private_key": "server-private", "port": 50494, "network": "10.67.67.0/24"}
    if material is not None:
        profile["generation"] = material
    return AppState(
        protocols={
            "amneziawg": PluginState(
                installed=True,
                config={
                    "protocol_mode": mode,
                    "profiles": {"desktop": profile},
                },
            )
        },
        users=[],
    )


def test_switching_a_served_host_into_31_generates_the_material():
    state = _served_state()

    assert AmneziaWGPlugin().set_protocol_mode(state, "3.1") is True

    material = state.protocols["amneziawg"].config["profiles"]["desktop"]["generation"]
    assert len(material["HeaderProtectionKey"]) == 44
    assert material["RandomTrailers"] is True
    assert state.protocols["amneziawg"].config["protocol_mode"] == "3.1"


def test_switching_never_replaces_the_material_it_finds():
    given = {"HeaderProtectionKey": "keep-me", "RandomTrailers": True, "DisableCookies": True}
    state = _served_state("3.1", material=given)

    assert AmneziaWGPlugin().set_protocol_mode(state, "3.0") is True

    material = state.protocols["amneziawg"].config["profiles"]["desktop"]["generation"]
    assert material["HeaderProtectionKey"] == "keep-me"
    assert state.protocols["amneziawg"].config["protocol_mode"] == "3.0"


def test_switching_back_to_2x_keeps_the_material_for_a_return():
    state = _served_state("3.1", material={"HeaderProtectionKey": "keep-me", "RandomTrailers": True})

    assert AmneziaWGPlugin().set_protocol_mode(state, "2.0") is True

    config = state.protocols["amneziawg"].config
    assert config["protocol_mode"] == "2.0"
    assert config["profiles"]["desktop"]["generation"]["HeaderProtectionKey"] == "keep-me"


def test_a_switch_that_changes_nothing_reports_no_change():
    state = _served_state(
        "3.1", material={"HeaderProtectionKey": "keep-me", "RandomTrailers": True, "DisableCookies": True}
    )

    assert AmneziaWGPlugin().set_protocol_mode(state, "3.1") is False


def _served_31_fixture(tmp_path) -> tuple[AmneziaWGPlugin, AppState, User]:
    """A host the core serves with no interface file at all: state carries every field."""
    obfuscation = {
        "Jc": "4",
        "Jmin": "50",
        "Jmax": "1000",
        "S1": "62",
        "S2": "86",
        "S3": "45",
        "S4": "21",
        "H1": "6664925-106664924",
        "H2": "944259910-1044259909",
        "H3": "1459921639-1559921638",
        "H4": "1858653411-1958653410",
    }
    profile = {
        "server_private_key": "server-private",
        "server_public_key": "server-public",
        "port": 50494,
        "network": "10.67.67.0/24",
        "mtu": "1376",
        "obfuscation": obfuscation,
        "generation": generate_generation_material("3.1"),
    }
    user = User(email="alice@example.com", uuid="u1")
    user.credentials["amneziawg"] = {
        "private_key": "private-d",
        "public_key": "public-d",
        "preshared_key": "psk-d",
        "address_octet": "2",
    }
    state = AppState(
        protocols={
            "amneziawg": PluginState(
                installed=True,
                config={
                    "protocol_mode": "3.1",
                    "profiles": {"desktop": profile},
                },
            )
        },
        users=[user],
    )
    state.network.server_ip = "203.0.113.10"
    return AmneziaWGPlugin(), state, user


def test_client_artifacts_carry_exactly_the_served_fields(tmp_path):
    plugin, state, user = _served_31_fixture(tmp_path)
    with patch("hydra.plugins.amneziawg.client_links.kernel_supports_awg31", return_value=True):
        endpoint = plugin.server_endpoints(state)[0]
        native = plugin.generate_client_config(user, state)
        link = plugin.client_link(user, state)

    assert endpoint["amnezia"]
    assert native and link.startswith("wg://")
    interface_names = {target: source for source, target in (*GENERATION_FIELDS_30, *GENERATION_FIELDS_31)}
    for key, value in endpoint["amnezia"].items():
        name = interface_names.get(key, key.capitalize())
        if isinstance(value, bool):
            token = "true" if value else "false"
            assert f"{name} = {token}" in native, (name, native)
            assert f"{key}={token}" in link, (key, link)
            continue
        assert f"{name} = {value}" in native, (name, native)
        assert f"{key}={value}" in link, (key, link)


def _mobile_state():
    profile = {
        "port": 51821,
        "network": "10.68.68.0/24",
        "mtu": "1280",
        "obfuscation": dict(OBFUSCATION_2X),
        "server_private_key": "mobile-server",
    }
    user = User(email="bob@example.com", uuid="u2")
    user.credentials["amneziawg_mobile"] = {
        "private_key": "private-m",
        "public_key": "public-m",
        "preshared_key": "psk-m",
        "address_octet": "5",
    }
    return AppState(
        protocols={
            "amneziawg": PluginState(
                installed=True,
                config={"protocol_mode": "2.0", "profiles": {"mobile": profile}},
            )
        },
        users=[user],
    )


def test_a_mobile_profile_is_served_on_its_own_network():
    endpoints = AmneziaWGPlugin().server_endpoints(_mobile_state())

    assert len(endpoints) == 1
    endpoint = endpoints[0]
    assert endpoint["tag"] == "awg-mobile"
    assert endpoint["address"] == ["10.68.68.1/24"]
    assert endpoint["listen_port"] == 51821
    assert endpoint["peers"][0]["allowed_ips"] == ["10.68.68.5/32"]
