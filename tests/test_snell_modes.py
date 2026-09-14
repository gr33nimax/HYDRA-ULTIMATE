"""tests/test_snell_modes.py — Snell 5/6 rendering for the migrated HydraCore.

The regression this file fences off: the plugin used to emit a server-side
`version: 4` and a nested `obfs` object, both of which the upstream Snell
implementation inside HydraCore refuses, so enabling Snell took the core down.
"""

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from hydra.core.state import AppState, PluginState, User
from hydra.plugins.snell.plugin import SnellPlugin
from hydra.services.subscriptions.shadowrocket import build_shadowrocket_snell_link

CORE_WITH_SNELL = "v1.14.0-extended-2.7.1-hydracore.12"
CORE_WITHOUT_SNELL = "v1.13.16-extended-hydracore.11-debug.61"


def _state(config: dict | None = None) -> AppState:
    state = AppState()
    state.users = [User(email="reader@example.com", uuid="u1")]
    state.network.server_ip = "203.0.113.10"
    state.protocols["snell"] = PluginState(
        installed=True,
        enabled=True,
        config={"version": 5, **(config or {})},
    )
    return state


def _supported():
    return patch("hydra.plugins.snell.plugin.kernel_supports_snell", return_value=True)


@pytest.mark.parametrize("obfs_mode", ["none", "http", "tls"])
def test_snell5_server_uses_the_flat_obfs_field(obfs_mode):
    state = _state({"version": 5, "obfs_mode": obfs_mode})

    with _supported():
        inbound = SnellPlugin().configure(state).inbounds[0]

    assert inbound["version"] == 5
    assert "obfs" not in inbound
    if obfs_mode == "none":
        assert "obfs_mode" not in inbound
    else:
        assert inbound["obfs_mode"] == obfs_mode


@pytest.mark.parametrize("mode", ["default", "unshaped", "unsafe-raw"])
def test_snell6_server_uses_its_own_mode(mode):
    state = _state({"version": 6, "mode": mode})

    with _supported():
        inbound = SnellPlugin().configure(state).inbounds[0]

    assert inbound["version"] == 6
    assert inbound["mode"] == mode
    assert "obfs" not in inbound
    assert "obfs_mode" not in inbound


def test_snell5_client_outbound_is_the_classic_pair():
    state = _state({"version": 5, "obfs_mode": "tls"})
    plugin = SnellPlugin()

    with _supported():
        outbound = json.loads(plugin.generate_client_config(state.users[0], state))["outbounds"][0]

    # A version 5 server has no version 5 client in the core's library: the pair is
    # negotiated as a client-side 4 with the obfuscation settings.
    assert outbound["version"] == 4
    assert outbound["obfs_mode"] == "tls"
    assert outbound["obfs_host"] == "www.bing.com"
    assert "obfs" not in outbound


def test_snell6_client_outbound_matches_its_server():
    state = _state({"version": 6, "mode": "unshaped"})
    plugin = SnellPlugin()

    with _supported():
        outbound = json.loads(plugin.generate_client_config(state.users[0], state))["outbounds"][0]

    assert outbound["version"] == 6
    assert outbound["mode"] == "unshaped"
    assert "obfs_mode" not in outbound


def test_snell_share_link_carries_the_client_side_version():
    plugin = SnellPlugin()
    classic = _state({"version": 5, "obfs_mode": "http"})
    modern = _state({"version": 6, "mode": "unsafe-raw"})

    with _supported():
        classic_link = plugin.client_link(classic.users[0], classic)
        modern_link = plugin.client_link(modern.users[0], modern)

    assert "version=4" in classic_link
    assert "obfs-mode=http" in classic_link
    assert "obfs-host=www.bing.com" in classic_link
    assert "version=6" in modern_link
    assert "mode=unsafe-raw" in modern_link


def test_shadowrocket_keeps_the_classic_pair_and_skips_generation_six():
    classic = build_shadowrocket_snell_link(
        "snell://secret@example.com:32000?version=4&obfs-mode=tls&obfs-host=www.bing.com#tag"
    )
    assert "version=4" in classic
    assert "obfs-mode=tls" in classic
    assert "obfs-host=www.bing.com" in classic

    modern = "snell://secret@example.com:32000?version=6&mode=unshaped#tag"
    assert build_shadowrocket_snell_link(modern) == modern


def test_snell_settings_validation_and_migration():
    state = _state()
    plugin = SnellPlugin()

    assert plugin.set_settings(state, version=5, obfs_mode="tls") is True
    assert state.protocols["snell"].config["obfs_mode"] == "tls"
    assert plugin.set_settings(state, version=6, obfs_mode="none", mode="unshaped") is True
    assert state.protocols["snell"].config == {
        "version": 6,
        "obfs_mode": "none",
        "obfs_host": "www.bing.com",
        "mode": "unshaped",
    }

    with pytest.raises(ValueError):
        plugin.set_settings(state, version=7, obfs_mode="none")
    with pytest.raises(ValueError):
        plugin.set_settings(state, version=5, obfs_mode="quic")
    with pytest.raises(ValueError):
        plugin.set_settings(state, version=6, obfs_mode="http")
    with pytest.raises(ValueError):
        plugin.set_settings(state, version=5, obfs_mode="tls", mode="unshaped")
    with pytest.raises(ValueError):
        plugin.set_settings(state, version=5, obfs_mode="tls", obfs_host="")

    # The previous core's server-side version 4 is the classic generation.
    state.protocols["snell"].config["version"] = 4
    assert SnellPlugin._version(state) == 5


def test_snell_gate_reads_the_installed_core_version():
    from hydra.plugins.snell.plugin import kernel_supports_snell

    def with_version(version):
        with patch("hydra.core.singbox.get_version", return_value=version):
            return kernel_supports_snell()

    assert with_version(CORE_WITH_SNELL) is True
    assert with_version("v1.14.0-extended-2.7.1-hydracore.12-debug.2") is True
    assert with_version(CORE_WITHOUT_SNELL) is False
    assert with_version("") is False
    with patch("hydra.core.singbox.get_version", side_effect=RuntimeError("no core")):
        assert kernel_supports_snell() is False


def test_snell_refuses_to_render_on_an_old_core():
    state = _state({"version": 5})
    plugin = SnellPlugin()

    with patch("hydra.plugins.snell.plugin.kernel_supports_snell", return_value=False):
        with pytest.raises(ValueError, match="upstream Snell"):
            plugin.configure(state)
        with pytest.raises(ValueError, match="upstream Snell"):
            plugin.on_enable(state)


def test_snell_status_names_the_generation_and_its_clients():
    plugin = SnellPlugin()

    with _supported():
        modern = plugin.status(_state({"version": 6, "mode": "unshaped"}))
        classic = plugin.status(_state({"version": 5, "obfs_mode": "tls"}))

    assert modern.info["Версия"] == "v6"
    assert modern.info["Клиенты"] == "только v6"
    assert modern.info["Obfs"] == "не применимо"
    assert classic.info["Версия"] == "v5"
    assert classic.info["Obfs"] == "TLS · www.bing.com"
    assert "Клиенты" not in classic.info
