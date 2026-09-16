"""tests/test_awg_endpoint_builder.py — the server endpoint projection for a core-served AWG.

The core serves AmneziaWG itself, so the server side is configuration, not an interface file. The
2.0 golden here is the exact field set that carried traffic through a real tunnel between two core
instances (TSK-001 evidence), so a regression in the projection shows up as a diff against a shape
that is known to work.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from hydra.plugins.amneziawg.endpoints import (  # noqa: E402
    amnezia_block,
    build_endpoint,
    build_peer,
    generation_block,
    obfuscation_block,
)

# The set two core instances actually exchanged traffic with, fields as the state stores them.
TRAFFIC_PROVEN_2X = {
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

EXPECTED_2X = {
    "jc": 4,
    "jmin": 50,
    "jmax": 1000,
    "s1": 62,
    "s2": 86,
    "s3": 45,
    "s4": 21,
    "h1": "6664925-106664924",
    "h2": "944259910-1044259909",
    "h3": "1459921639-1559921638",
    "h4": "1858653411-1958653410",
    "i1": "aae1e32da608adb221fe63c98a7f1f923e0ee35c5112330784c755c1a3c8d3",
}

GENERATION_30 = {
    "HeaderProtectionKey": "WH8rAUX7V8pE2zlO44P/0bkFv6gRqTblw1bk5QTXKVU=",
    "ContentPaddingAddition": "10-100",
    "RekeyAfterTime": "100-120",
    "RekeyTimeout": "3-7",
    "RejectAfterTime": "150-180",
    "KeepaliveTimeout": "5-15",
}

GENERATION_31 = {
    **GENERATION_30,
    "RandomTrailers": True,
    "DisableCookies": True,
}

GENERATION_TARGETS_30 = (
    "header_protection_key",
    "content_padding_addition",
    "rekey_after_time",
    "rekey_timeout",
    "reject_after_time",
    "keepalive_timeout",
)


def test_2x_block_is_the_shape_that_carried_traffic():
    # A diff here means the projection stopped matching the configuration that was proven live.
    assert amnezia_block(TRAFFIC_PROVEN_2X, None, "2.0") == EXPECTED_2X


def test_2x_block_carries_no_generation_field():
    block = amnezia_block(TRAFFIC_PROVEN_2X, GENERATION_31, "2.0")

    assert not set(block).intersection(GENERATION_TARGETS_30)
    assert "random_trailers" not in block
    assert "disable_cookies" not in block


def test_30_carries_the_generation_fields_and_drops_the_legacy_injection():
    block = amnezia_block(TRAFFIC_PROVEN_2X, GENERATION_30, "3.0")

    for target in GENERATION_TARGETS_30:
        assert target in block, target
    assert block["header_protection_key"] == GENERATION_30["HeaderProtectionKey"]
    # `i1` is the classic-era injection; a 3.x profile does not carry it.
    assert "i1" not in block
    assert "random_trailers" not in block
    assert "disable_cookies" not in block


def test_31_carries_both_booleans_as_json_booleans():
    block = amnezia_block(TRAFFIC_PROVEN_2X, GENERATION_31, "3.1")

    assert block["random_trailers"] is True
    assert block["disable_cookies"] is True
    assert isinstance(block["random_trailers"], bool)


def test_31_booleans_follow_the_stored_value():
    generation = {**GENERATION_30, "RandomTrailers": False, "DisableCookies": False}

    block = amnezia_block(TRAFFIC_PROVEN_2X, generation, "3.1")

    assert block["random_trailers"] is False
    assert block["disable_cookies"] is False


def test_an_optional_handshake_attempt_limit_is_carried_when_present():
    generation = {**GENERATION_30, "MaxHandshakeAttempts": "7"}

    block = amnezia_block(TRAFFIC_PROVEN_2X, generation, "3.0")

    assert block["max_handshake_attempts"] == "7"
    assert "max_handshake_attempts" not in amnezia_block(TRAFFIC_PROVEN_2X, GENERATION_30, "3.0")


@pytest.mark.parametrize("missing", sorted(GENERATION_30))
def test_missing_generation_material_is_refused_by_name(missing):
    generation = {key: value for key, value in GENERATION_30.items() if key != missing}

    with pytest.raises(ValueError, match=missing):
        generation_block(generation, "3.0")


def test_31_refuses_when_the_two_extra_fields_are_absent():
    with pytest.raises(ValueError, match="RandomTrailers"):
        generation_block(GENERATION_30, "3.1")


def test_padding_below_the_header_protection_nonce_is_refused():
    # 3.x needs each padding to carry the nonce; the validator owns that rule, so the projection
    # must not quietly pass a set it cannot serve.
    obfuscation = {**TRAFFIC_PROVEN_2X, "S3": "0"}

    with pytest.raises(ValueError, match="S3"):
        amnezia_block(obfuscation, GENERATION_30, "3.0")

    # The same set stays legal for 2.0, which has no header protection.
    assert amnezia_block(obfuscation, None, "2.0")["s3"] == 0


def test_obfuscation_block_keeps_single_values_and_ranges_apart():
    block = obfuscation_block(TRAFFIC_PROVEN_2X, include_i1=True)

    assert block["h1"] == "6664925-106664924"
    assert obfuscation_block({"H1": "12345"}, include_i1=False)["h1"] == 12345


def test_a_peer_carries_its_address_and_optional_pre_shared_key():
    peer = build_peer(public_key="pub", preshared_key="psk", address="10.67.67.3/32")

    assert peer == {
        "public_key": "pub",
        "pre_shared_key": "psk",
        "allowed_ips": ["10.67.67.3/32"],
    }
    assert "pre_shared_key" not in build_peer(public_key="pub", preshared_key="", address="10.67.67.4/32")


def test_an_endpoint_is_the_shape_the_core_serves():
    endpoint = build_endpoint(
        tag="awg-desktop",
        address="10.67.67.1/24",
        private_key="server-private",
        port="50494",
        mtu="1376",
        peers=[build_peer(public_key="pub", preshared_key="psk", address="10.67.67.3/32")],
        amnezia=EXPECTED_2X,
    )

    assert endpoint == {
        "type": "wireguard",
        "tag": "awg-desktop",
        "address": ["10.67.67.1/24"],
        "private_key": "server-private",
        "listen_port": 50494,
        "mtu": 1376,
        "peers": [{"public_key": "pub", "pre_shared_key": "psk", "allowed_ips": ["10.67.67.3/32"]}],
        "amnezia": EXPECTED_2X,
    }
