from __future__ import annotations

import json
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlsplit

import pytest

from hydra.core.state import AppState, PluginState, User
from hydra.plugins.vless_xhttp import presets, tuning
from hydra.plugins.vless_xhttp.plugin import ROUTE_CONFIG_KEY, VlessXhttpPlugin
from hydra.services.protocol_setup import normalize_protocol_config
from hydra.ui._menus import vless_xhttp_settings, vless_xhttp_tuning


LEGACY_TRANSPORT = {
    "type": "xhttp",
    "mode": "stream-up",
    "host": "",
    "path": "/xhttp",
    "headers": {},
    "x_padding_bytes": "100-1000",
    "no_sse_header": False,
    "sc_max_each_post_bytes": 1_000_000,
    "sc_max_buffered_posts": 30,
    "sc_stream_up_server_secs": "20-80",
    "server_max_header_bytes": 8192,
    "trusted_x_forwarded_for": [],
}


def _state(**config: object) -> AppState:
    state = AppState()
    state.network.server_ip = "203.0.113.10"
    state.protocols["vless"] = PluginState(
        enabled=True,
        installed=True,
        config={
            "domain": "xhttp.example.com",
            "cert_file": "/cert.pem",
            "key_file": "/key.pem",
            "xhttp_mode": "stream-up",
            "xhttp_path": "/xhttp",
            ROUTE_CONFIG_KEY: VlessXhttpPlugin.route_config(),
            **config,
        },
    )
    state.users = [User("active@example.com", "uuid-active")]
    return state


def _config(state: AppState) -> dict:
    return state.protocols["vless"].config


def test_defaults_keep_the_previously_hardcoded_transport():
    plugin = VlessXhttpPlugin()
    state = _state()

    inbound = plugin.configure(state).inbounds[0]

    assert inbound["transport"] == LEGACY_TRANSPORT


def test_meta_defaults_cover_every_tuning_field():
    defaults = dict(VlessXhttpPlugin.meta.config_defaults)

    for field in tuning.FIELDS:
        assert defaults[field.key] == field.default
    assert "set_tuning" in VlessXhttpPlugin.meta.commands
    assert "set_preset" in VlessXhttpPlugin.meta.commands
    assert "get_tuning" in VlessXhttpPlugin.meta.queries


def test_tuning_defaults_are_copied_per_protocol_state():
    defaults = VlessXhttpPlugin.meta.config_defaults
    first = normalize_protocol_config({}, defaults)
    second = normalize_protocol_config({}, defaults)

    first["xhttp_headers"]["X-Probe"] = "1"

    assert second["xhttp_headers"] == {}


def test_set_tuning_updates_transport_and_client_config():
    plugin = VlessXhttpPlugin()
    state = _state()

    assert plugin.set_tuning(
        state,
        padding="0",
        max_post_bytes=262_144,
        max_buffered_posts=8,
        stream_up_secs="10-30",
        max_header_bytes=16384,
        no_sse_header=True,
        headers={"X-Requested-With": "XMLHttpRequest"},
    )

    transport = plugin.configure(state).inbounds[0]["transport"]
    client = json.loads(
        plugin.generate_client_config(state.users[0], state),
    )["outbounds"][0]["transport"]

    assert transport["x_padding_bytes"] == "0"
    assert transport["sc_max_each_post_bytes"] == 262_144
    assert transport["sc_max_buffered_posts"] == 8
    assert transport["sc_stream_up_server_secs"] == "10-30"
    assert transport["server_max_header_bytes"] == 16384
    assert transport["no_sse_header"] is True
    assert transport["headers"] == {"X-Requested-With": "XMLHttpRequest"}
    assert client["headers"] == {"X-Requested-With": "XMLHttpRequest"}
    assert client["host"] == "xhttp.example.com"


def test_set_tuning_accepts_json_string_scalars_from_cli():
    plugin = VlessXhttpPlugin()
    state = _state()

    assert plugin.set_tuning(state, max_post_bytes="8192", no_sse_header="true")

    assert _config(state)["xhttp_max_post_bytes"] == 8192
    assert _config(state)["xhttp_no_sse_header"] is True


@pytest.mark.parametrize(
    ("parameters", "message"),
    [
        ({"padding": "1000-100"}, "ascending range"),
        ({"padding": "abc"}, "must be 'N' or 'N-M'"),
        ({"padding": "70000"}, "ascending range"),
        ({"stream_up_secs": "10-5000"}, "ascending range"),
        ({"max_post_bytes": 1024}, "must be within"),
        ({"max_post_bytes": True}, "must be an integer"),
        ({"max_buffered_posts": 0}, "must be within"),
        ({"max_header_bytes": 512}, "must be within"),
        ({"no_sse_header": "maybe"}, "must be a boolean"),
        ({"headers": ["X-Test: 1"]}, "must be a JSON object"),
        ({"headers": {"Host": "example.com"}}, "managed by the transport"),
        ({"headers": {"Bad Name": "1"}}, "header name is invalid"),
        ({"headers": {"X-Test": "line\nbreak"}}, "header value is invalid"),
        ({"headers": {"X-Test": ""}}, "header value is invalid"),
        ({"unknown": 1}, "unsupported XHTTP tuning parameters"),
        ({}, "no XHTTP tuning parameters"),
    ],
)
def test_invalid_tuning_does_not_mutate_state(parameters: dict, message: str):
    plugin = VlessXhttpPlugin()
    state = _state()
    before = dict(_config(state))

    with pytest.raises(ValueError, match=message):
        plugin.set_tuning(state, **parameters)

    assert _config(state) == before


def test_headers_are_capped_and_sorted():
    plugin = VlessXhttpPlugin()
    state = _state()
    too_many = {f"X-H{index}": "1" for index in range(17)}

    with pytest.raises(ValueError, match="must not exceed"):
        plugin.set_tuning(state, headers=too_many)

    assert plugin.set_tuning(state, headers={"X-B": "2", "X-A": "1"})
    assert list(_config(state)["xhttp_headers"]) == ["X-A", "X-B"]


def test_preset_replaces_mode_and_tuning_as_a_group():
    plugin = VlessXhttpPlugin()
    state = _state()

    assert plugin.set_preset(state, "low-latency")

    config = _config(state)
    assert config["xhttp_mode"] == "stream-one"
    assert config["xhttp_max_buffered_posts"] == 10
    assert presets.current_preset(config) == "low_latency"
    assert plugin.configure(state).inbounds[0]["transport"]["mode"] == "stream-one"


def test_unknown_preset_does_not_mutate_state():
    plugin = VlessXhttpPlugin()
    state = _state()
    before = dict(_config(state))

    with pytest.raises(ValueError, match="XHTTP preset must be one of"):
        plugin.set_preset(state, "turbo")

    assert _config(state) == before


def test_default_config_matches_the_balanced_preset():
    assert presets.current_preset(_config(_state())) == "balanced"


def test_custom_tuning_is_reported_as_custom_preset():
    plugin = VlessXhttpPlugin()
    state = _state()

    plugin.set_tuning(state, padding="7-9")

    assert presets.current_preset(_config(state)) == presets.CUSTOM_PRESET
    assert presets.preset_label(presets.CUSTOM_PRESET) == "🛠 Пользовательский"


def test_headers_do_not_break_preset_detection():
    plugin = VlessXhttpPlugin()
    state = _state()

    plugin.set_tuning(state, headers={"X-Trace": "1"})

    assert presets.current_preset(_config(state)) == "balanced"


def test_share_link_stays_unchanged_for_default_tuning():
    plugin = VlessXhttpPlugin()
    state = _state()

    query = parse_qs(urlsplit(plugin.client_link(state.users[0], state)).query)

    assert "extra" not in query


def test_share_link_carries_only_client_visible_overrides():
    plugin = VlessXhttpPlugin()
    state = _state()
    plugin.set_tuning(
        state,
        padding="0",
        max_header_bytes=16384,
        headers={"X-Trace": "1"},
    )

    query = parse_qs(urlsplit(plugin.client_link(state.users[0], state)).query)
    extra = json.loads(query["extra"][0])

    assert extra == {"xPaddingBytes": "0", "headers": {"X-Trace": "1"}}
    assert "server_max_header_bytes" not in extra


def test_get_tuning_projects_effective_settings():
    plugin = VlessXhttpPlugin()
    state = _state()
    plugin.set_preset(state, "stealth")

    assert plugin.get_tuning(state) == {
        "security": "tls",
        "preset": "stealth",
        "mode": "stream-up",
        "path": "/xhttp",
        "headers": {},
        "padding": "500-2000",
        "no_sse_header": False,
        "max_post_bytes": 1_000_000,
        "max_buffered_posts": 30,
        "stream_up_secs": "30-120",
        "max_header_bytes": 16384,
        "utls_fingerprint": "none",
    }


def test_enable_rejects_invalid_persisted_tuning_before_firewall_changes():
    plugin = VlessXhttpPlugin()
    state = _state(xhttp_padding="oops")

    with patch("hydra.utils.firewall.open_tcp") as open_tcp:
        with pytest.raises(ValueError, match="XHTTP padding"):
            plugin.on_enable(state)

    open_tcp.assert_not_called()


def test_status_reports_preset_and_tuning_summary():
    plugin = VlessXhttpPlugin()
    state = _state()

    with patch("hydra.core.singbox.is_installed", return_value=True), \
         patch("hydra.core.singbox.is_running", return_value=True), \
         patch("hydra.core.sni_router.is_active", return_value=True):
        info = plugin.status(state).info

    assert info["XHTTP preset"] == "balanced"
    assert "padding 100-1000" in info["XHTTP tuning"]


def test_status_survives_an_invalid_stored_tuning_value():
    plugin = VlessXhttpPlugin()
    state = _state(xhttp_max_buffered_posts=0)

    with patch("hydra.core.singbox.is_installed", return_value=True), \
         patch("hydra.core.singbox.is_running", return_value=False), \
         patch("hydra.core.sni_router.is_active", return_value=False):
        info = plugin.status(state).info

    assert info["XHTTP preset"] == "invalid"
    assert "max_buffered_posts" in info["XHTTP tuning"]


def _app(state: AppState) -> MagicMock:
    app = MagicMock()
    app.admin.load_state.return_value = state
    app.plugin_command.return_value = True
    return app


def test_settings_menu_opens_the_tuning_submenu():
    state = _state()
    app = _app(state)

    with patch.object(
        vless_xhttp_settings,
        "menu",
        side_effect=["5", "0"],
    ), patch.object(
        vless_xhttp_settings,
        "open_tuning_menu",
    ) as open_tuning:
        vless_xhttp_settings.open_menu(state, MagicMock(), app)

    open_tuning.assert_called_once_with(state, app)
    app.plugin_command.assert_not_called()


def test_tuning_menu_edits_a_scalar_knob():
    state = _state()
    app = _app(state)
    index = str(
        next(
            position
            for position, field in enumerate(tuning.FIELDS, start=1)
            if field.param == "padding"
        ),
    )

    with patch.object(
        vless_xhttp_tuning,
        "menu",
        side_effect=[index, "0"],
    ), patch.object(
        vless_xhttp_tuning,
        "prompt",
        side_effect=["300-900", ""],
    ):
        vless_xhttp_tuning.open_menu(state, app)

    app.plugin_command.assert_called_once_with(
        state,
        "vless",
        "set_tuning",
        padding="300-900",
    )


def test_tuning_menu_toggles_a_boolean_knob():
    state = _state()
    app = _app(state)
    index = str(
        next(
            position
            for position, field in enumerate(tuning.FIELDS, start=1)
            if field.param == "no_sse_header"
        ),
    )

    with patch.object(
        vless_xhttp_tuning,
        "menu",
        side_effect=[index, "0"],
    ), patch.object(vless_xhttp_tuning, "prompt", return_value=""):
        vless_xhttp_tuning.open_menu(state, app)

    app.plugin_command.assert_called_once_with(
        state,
        "vless",
        "set_tuning",
        no_sse_header=True,
    )


def test_tuning_menu_removes_a_header():
    state = _state(xhttp_headers={"X-Trace": "1"})
    app = _app(state)
    index = str(
        next(
            position
            for position, field in enumerate(tuning.FIELDS, start=1)
            if field.param == "headers"
        ),
    )

    with patch.object(
        vless_xhttp_tuning,
        "menu",
        side_effect=[index, "2", "0"],
    ), patch.object(
        vless_xhttp_tuning,
        "prompt",
        side_effect=["X-Trace", ""],
    ):
        vless_xhttp_tuning.open_menu(state, app)

    app.plugin_command.assert_called_once_with(
        state,
        "vless",
        "set_tuning",
        headers={},
    )


def test_default_client_profile_carries_no_utls_hint():
    plugin = VlessXhttpPlugin()
    state = _state()

    client = json.loads(
        plugin.generate_client_config(state.users[0], state),
    )["outbounds"][0]
    query = parse_qs(urlsplit(plugin.client_link(state.users[0], state)).query)

    assert "utls" not in client["tls"]
    assert "fp" not in query


def test_utls_fingerprint_reaches_the_client_profile_and_link():
    plugin = VlessXhttpPlugin()
    state = _state()

    assert plugin.set_tuning(state, utls_fingerprint="Firefox")

    client = json.loads(
        plugin.generate_client_config(state.users[0], state),
    )["outbounds"][0]
    query = parse_qs(urlsplit(plugin.client_link(state.users[0], state)).query)

    assert _config(state)["utls_fingerprint"] == "firefox"
    assert client["tls"]["utls"] == {"enabled": True, "fingerprint": "firefox"}
    assert query["fp"] == ["firefox"]
    assert "extra" not in query


def test_utls_fingerprint_never_reaches_the_server_inbound():
    plugin = VlessXhttpPlugin()
    state = _state()
    plugin.set_tuning(state, utls_fingerprint="chrome")

    inbound = plugin.configure(state).inbounds[0]

    assert "utls" not in inbound["tls"]
    assert "utls_fingerprint" not in inbound["transport"]
    assert "fp" not in inbound["transport"]


def test_unknown_fingerprint_does_not_mutate_state():
    plugin = VlessXhttpPlugin()
    state = _state()
    before = dict(_config(state))

    with pytest.raises(ValueError, match="utls_fingerprint must be one of"):
        plugin.set_tuning(state, utls_fingerprint="netscape")

    assert _config(state) == before


def test_settings_menu_changes_the_fingerprint():
    state = _state()
    app = _app(state)

    with patch.object(
        vless_xhttp_settings,
        "menu",
        side_effect=["6", "2", "0"],
    ), patch.object(vless_xhttp_settings, "prompt", return_value=""):
        vless_xhttp_settings.open_menu(state, MagicMock(), app)

    app.plugin_command.assert_called_once_with(
        state,
        "vless",
        "set_tuning",
        utls_fingerprint=tuning.UTLS_FINGERPRINTS[1],
    )
