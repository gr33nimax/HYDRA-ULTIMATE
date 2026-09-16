"""Generation switching for a host the core serves.

The installer-era migration commands are gone: a mode change is desired state plus the material the
endpoint carries, and the observed value is read back from the core's own configuration.
"""

import json

from typing import Any, cast

from unittest.mock import patch

from hydra.core.state import AppState, PluginState
from hydra.plugins.amneziawg.plugin import AmneziaWGPlugin
from hydra.plugins.amneziawg.protocol_mode import served_generation


def _state(mode="2.0", *, with_profile=True):
    profiles = (
        {
            "desktop": {
                "port": 51820,
                "network": "10.67.67.0/24",
                "server_private_key": "cHJpdmF0ZS1rZXk=",
                "obfuscation": {"Jc": "5"},
            }
        }
        if with_profile
        else {}
    )
    return AppState(
        protocols={
            "amneziawg": PluginState(
                installed=True,
                config=cast(Any, {"protocol_mode": mode, "profiles": profiles}),
            )
        }
    )


def test_protocol_mode_status_reports_the_served_generation():
    plugin = AmneziaWGPlugin()
    state = _state("3.1")

    with patch("hydra.plugins.amneziawg.protocol_mode.served_generation", return_value="3.1"):
        status = plugin.protocol_mode_status(state)

    assert status["desired"] == "3.1"
    assert status["observed"] == "3.1"
    assert status["exports"]["native_conf"] == "ready"


def test_protocol_mode_status_keeps_awg31_exports_closed_on_an_old_core():
    plugin = AmneziaWGPlugin()
    state = _state("3.1")

    with (
        patch("hydra.plugins.amneziawg.protocol_mode.served_generation", return_value="3.1"),
        patch("hydra.plugins.amneziawg.client_links.kernel_supports_awg31", return_value=False),
    ):
        exports = plugin.protocol_mode_status(state)["exports"]

    assert exports["native_conf"] == "ready"
    for key in ("singbox", "hydrabox_subscription"):
        assert exports[key].startswith("unsupported: AWG 3.1 requires a HydraCore")


def test_protocol_mode_status_allows_only_source_proven_awg30_sbe_exports():
    plugin = AmneziaWGPlugin()
    state = _state("3.0")

    with patch("hydra.plugins.amneziawg.protocol_mode.served_generation", return_value="3.0"):
        exports = plugin.protocol_mode_status(state)["exports"]

    assert exports["singbox"] == "ready"
    assert exports["hydrabox_subscription"] == "ready"
    assert exports["sn_awg"] == "unsupported: AWG 3.0 importer compatibility is unverified"


def test_awg31_core_gate_compares_real_version_strings():
    from hydra.plugins.amneziawg.client_links import kernel_supports_awg31

    def with_version(version):
        with patch("hydra.core.singbox.get_version", return_value=version):
            return kernel_supports_awg31()

    assert with_version("v1.14.0-extended-2.7.1-hydracore.12") is True
    assert with_version("v1.14.0-extended-2.7.1-hydracore.12-debug.2") is True
    assert with_version("v1.14.0-extended-2.7.1-hydracore.11") is False
    assert with_version(None) is False


def test_served_generation_reads_the_core_configuration(tmp_path):
    """The observed generation is what the core actually runs, not what state wishes for."""
    config = tmp_path / "config.json"

    def write(amnezia):
        config.write_text(
            json.dumps({"endpoints": [{"type": "wireguard", "tag": "awg-desktop", "amnezia": amnezia}]}),
            encoding="utf-8",
        )
        return served_generation(config)

    assert write({"jc": 5, "jmin": 50}) == "2.0"
    assert write({"header_protection_key": "k"}) == "3.0"
    assert write({"header_protection_key": "k", "random_trailers": True}) == "3.1"
    assert write({}) == "unavailable"
    config.unlink()
    assert served_generation(config) == "unavailable"


def test_set_protocol_mode_switches_the_served_generation_without_the_installer():
    """Entering 3.x fills the material a profile lacks; leaving it back keeps that material."""
    plugin = AmneziaWGPlugin()
    state = _state("2.0")
    profiles = state.protocols["amneziawg"].config["profiles"]

    assert plugin.set_protocol_mode(state, "3.1") is True
    generation = profiles["desktop"]["generation"]
    assert "HeaderProtectionKey" in generation
    assert generation["RandomTrailers"] is True
    assert state.protocols["amneziawg"].config["protocol_mode"] == "3.1"

    operator_value = generation["HeaderProtectionKey"]
    assert plugin.set_protocol_mode(state, "3.1") is False
    assert profiles["desktop"]["generation"]["HeaderProtectionKey"] == operator_value

    assert plugin.set_protocol_mode(state, "2.0") is True
    assert profiles["desktop"]["generation"] == generation


def test_set_protocol_mode_refuses_a_profile_less_protocol():
    plugin = AmneziaWGPlugin()
    state = _state("2.0", with_profile=False)

    try:
        plugin.set_protocol_mode(state, "3.0")
    except RuntimeError as exc:
        assert "no profile" in str(exc)
    else:
        raise AssertionError("switching without a profile must be refused")
