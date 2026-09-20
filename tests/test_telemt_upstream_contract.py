"""Pinned upstream compatibility checks for Telemt."""

import pytest

from hydra.core.state import AppState, PluginState, User
from hydra.plugins.telemt.profiles import client_links
from hydra.plugins.telemt.upstream_contract import (
    RELEASE_ARCHIVES,
    RELEASE_TAG,
    release_archive,
    unsupported_toml_paths,
)


def test_release_contract_pins_telemt_357_assets():
    assert RELEASE_TAG == "3.5.7"
    assert release_archive("x86_64") == "telemt-x86_64-linux-gnu.tar.gz"
    assert release_archive("x86_64", supports_v3=True) == "telemt-x86_64-v3-linux-gnu.tar.gz"
    assert release_archive("aarch64", libc="musl") == "telemt-aarch64-linux-musl.tar.gz"
    assert set(RELEASE_ARCHIVES) == {"aarch64", "x86_64", "x86_64_v3"}


def test_release_contract_rejects_unknown_target():
    with pytest.raises(ValueError, match="unsupported Telemt target"):
        release_archive("riscv64")


def test_config_contract_rejects_stale_fields():
    assert unsupported_toml_paths({"censorship.tls_domain", "access.users"}) == set()
    assert unsupported_toml_paths({"censorship.fake_cert_len"}) == {"censorship.fake_cert_len"}


def test_existing_fake_tls_state_keeps_its_client_artifact():
    state = AppState()
    state.network.server_ip = "203.0.113.9"
    state.protocols["telemt"] = PluginState(
        enabled=True,
        config={"port": 8443, "tls_domain": "legacy.example"},
    )
    user = User(email="user@example.com", uuid="legacy-user")

    links = client_links(
        user,
        state,
        resolve_public_ip=lambda: "unused",
        ios_status=lambda: {"enabled": False},
    )

    assert links == [
        "tg://proxy?server=203.0.113.9&port=8443&secret=eef07a591c36e2d25aea8efc8a00df3eb36c65676163792e6578616d706c65"
    ]
