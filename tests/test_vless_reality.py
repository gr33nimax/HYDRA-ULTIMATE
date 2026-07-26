"""VLESS Reality over XHTTP: configuration, routing, links and health."""
from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlsplit

import pytest

from hydra.core.sni_router import _collect_backends, _generate_config, needs_mux
from hydra.core.state import AppState, PluginState, User
from hydra.plugins.vless_xhttp.plugin import (
    INTERNAL_PORT,
    ROUTE_CONFIG_KEY,
    VlessXhttpPlugin,
)
from hydra.plugins.vless_xhttp.security import (
    MODE_REALITY,
    MODE_TLS,
    PASSTHROUGH_ROUTE_KEY,
    is_reality,
)
from hydra.services.protocol_setup import ProtocolSetupService
from hydra.ui._menus import vless_xhttp_settings


HANDSHAKE = "www.samsung.com"
KEYPAIR = ("private-key-value", "public-key-value")


def _state(*, users: bool = True) -> AppState:
    state = AppState()
    state.network.server_ip = "203.0.113.10"
    state.protocols["vless"] = PluginState(
        enabled=True,
        installed=True,
        config={
            "xhttp_mode": "stream-up",
            "xhttp_path": "/xhttp",
            ROUTE_CONFIG_KEY: VlessXhttpPlugin.route_config(),
        },
    )
    if users:
        state.users = [User("active@example.com", "uuid-active")]
    return state


def _reality_state(**config: object) -> AppState:
    state = _state()
    plugin = VlessXhttpPlugin()
    with patch(
        "hydra.core.singbox_keys.generate_reality_keypair",
        return_value=KEYPAIR,
    ):
        plugin.set_security(state, MODE_REALITY, handshake=HANDSHAKE)
    state.protocols["vless"].config.update(config)
    return state


def _config(state: AppState) -> dict:
    return state.protocols["vless"].config


def test_switching_to_reality_replaces_the_certificate_contract():
    state = _reality_state()
    config = _config(state)

    assert is_reality(config)
    assert config["reality_handshake"] == HANDSHAKE
    assert config["reality_private_key"] == KEYPAIR[0]
    assert config["reality_public_key"] == KEYPAIR[1]
    assert len(config["reality_short_id"]) == 8
    assert ROUTE_CONFIG_KEY not in config
    assert config[PASSTHROUGH_ROUTE_KEY] == {
        "kind": "tls_passthrough",
        "internal_port": INTERNAL_PORT,
        "sni_config": "reality_handshake",
    }
    assert "domain" not in config


def test_switching_back_to_tls_restores_the_decoy_route():
    state = _reality_state()
    plugin = VlessXhttpPlugin()

    assert plugin.set_security(state, MODE_TLS)

    config = _config(state)
    assert not is_reality(config)
    assert PASSTHROUGH_ROUTE_KEY not in config
    assert config[ROUTE_CONFIG_KEY]["kind"] == "http_path_proxy"
    # Keys survive the round trip so switching back needs no new handshake.
    assert config["reality_public_key"] == KEYPAIR[1]


def test_existing_keys_are_reused_instead_of_regenerated():
    state = _reality_state()
    plugin = VlessXhttpPlugin()

    with patch(
        "hydra.core.singbox_keys.generate_reality_keypair",
    ) as generate:
        plugin.set_security(state, MODE_REALITY, handshake="www.icloud.com")

    generate.assert_not_called()
    assert _config(state)["reality_handshake"] == "www.icloud.com"


@pytest.mark.parametrize(
    ("mode", "handshake", "message"),
    [
        ("quantum", HANDSHAKE, "security must be one of"),
        (MODE_REALITY, "not a host", "Reality handshake must be"),
        (MODE_REALITY, "localhost", "Reality handshake must be"),
    ],
)
def test_invalid_security_input_does_not_mutate_state(mode, handshake, message):
    state = _state()
    plugin = VlessXhttpPlugin()
    before = dict(_config(state))

    with pytest.raises(ValueError, match=message):
        plugin.set_security(state, mode, handshake=handshake)

    assert _config(state) == before


def test_reality_inbound_borrows_the_handshake_and_keeps_xhttp():
    state = _reality_state()

    with patch("hydra.core.sni_router.needs_mux", return_value=False):
        inbound = VlessXhttpPlugin().configure(state).inbounds[0]

    assert inbound["listen"] == "::"
    assert inbound["listen_port"] == 443
    assert inbound["tls"] == {
        "enabled": True,
        "server_name": HANDSHAKE,
        "reality": {
            "enabled": True,
            "handshake": {"server": HANDSHAKE, "server_port": 443},
            "private_key": KEYPAIR[0],
            "short_id": [_config(state)["reality_short_id"]],
        },
    }
    assert inbound["transport"]["type"] == "xhttp"
    assert inbound["transport"]["path"] == "/xhttp"
    assert "certificate_path" not in inbound["tls"]


def test_reality_listens_on_loopback_when_the_multiplexer_is_required():
    state = _reality_state()
    state.protocols["anytls"] = PluginState(
        enabled=True,
        config={"domain": "anytls.example.com"},
    )

    inbound = VlessXhttpPlugin().configure(state).inbounds[0]

    assert needs_mux(state) is True
    assert inbound["listen"] == "127.0.0.1"
    assert inbound["listen_port"] == INTERNAL_PORT


def test_reality_alone_does_not_require_the_multiplexer():
    assert needs_mux(_reality_state()) is False


def test_multiplexer_routes_the_borrowed_sni_without_terminating_tls():
    state = _reality_state()
    state.protocols["anytls"] = PluginState(
        enabled=True,
        config={
            "domain": "anytls.example.com",
            "cert_file": "/cert.pem",
            "key_file": "/key.pem",
        },
    )
    backends = _collect_backends(state)

    vless = next(item for item in backends if item["name"] == "vless")
    assert vless["domain"] == HANDSHAKE
    assert vless["route_kind"] == "tls_passthrough"
    assert vless["cert_file"] == ""

    config = _generate_config(backends, state)
    routes = config["apps"]["layer4"]["servers"]["tls_mux"]["routes"]
    route = next(
        item
        for item in routes
        if item["match"] == [{"tls": {"sni": [HANDSHAKE]}}]
    )
    assert [handler["handler"] for handler in route["handle"]] == ["proxy"]
    assert route["handle"][0]["upstreams"][0]["dial"] == [
        f"127.0.0.1:{INTERNAL_PORT}",
    ]
    loaded = config["apps"].get("tls", {}).get("certificates", {})
    assert HANDSHAKE not in json.dumps(loaded)


def test_reality_route_rejects_an_unusable_handshake():
    state = _reality_state()
    _config(state)["reality_handshake"] = "not-a-host"

    with pytest.raises(ValueError, match="is not a valid SNI"):
        _collect_backends(state)


def test_reality_link_and_profile_carry_the_public_key():
    state = _reality_state()
    plugin = VlessXhttpPlugin()
    user = state.users[0]

    link = plugin.client_link(user, state)
    query = parse_qs(urlsplit(link).query)
    outbound = json.loads(plugin.generate_client_config(user, state))[
        "outbounds"
    ][0]

    assert urlsplit(link).hostname == "203.0.113.10"
    assert urlsplit(link).port == 443
    assert query["security"] == ["reality"]
    assert query["sni"] == [HANDSHAKE]
    assert query["pbk"] == [KEYPAIR[1]]
    assert query["sid"] == [_config(state)["reality_short_id"]]
    assert query["fp"] == ["chrome"]
    assert query["type"] == ["xhttp"]
    assert query["host"] == [HANDSHAKE]
    assert "alpn" not in query
    assert outbound["server"] == "203.0.113.10"
    assert outbound["tls"]["reality"] == {
        "enabled": True,
        "public_key": KEYPAIR[1],
        "short_id": _config(state)["reality_short_id"],
    }
    assert outbound["tls"]["utls"]["fingerprint"] == "chrome"
    assert outbound["transport"]["host"] == HANDSHAKE


def test_configured_fingerprint_wins_over_the_reality_default():
    state = _reality_state()
    VlessXhttpPlugin().set_tuning(state, utls_fingerprint="firefox")

    query = parse_qs(
        urlsplit(
            VlessXhttpPlugin().client_link(state.users[0], state),
        ).query,
    )

    assert query["fp"] == ["firefox"]


def test_reality_never_publishes_the_private_key():
    state = _reality_state()
    plugin = VlessXhttpPlugin()
    user = state.users[0]

    with patch("hydra.core.singbox.is_installed", return_value=True), \
         patch("hydra.core.singbox.is_running", return_value=True), \
         patch("hydra.core.sni_router.is_active", return_value=True):
        info = plugin.status(state).info

    assert KEYPAIR[0] not in json.dumps(info)
    assert KEYPAIR[0] not in plugin.client_link(user, state)
    assert KEYPAIR[0] not in plugin.generate_client_config(user, state)
    assert info["Security"] == MODE_REALITY


def test_enabling_reality_needs_no_certificate_but_needs_a_public_ip():
    state = _reality_state()
    plugin = VlessXhttpPlugin()

    with patch("hydra.utils.firewall.open_tcp") as open_tcp:
        plugin.on_enable(state)
    assert open_tcp.call_args_list == [((443, "vless-xhttp"),)]

    state.network.server_ip = ""
    with patch("hydra.utils.firewall.open_tcp") as open_tcp:
        with pytest.raises(ValueError, match="Публичный IP"):
            plugin.on_enable(state)
    open_tcp.assert_not_called()


def test_certificate_preflight_skips_a_reality_endpoint():
    state = _reality_state()
    plugin = VlessXhttpPlugin()
    certificates = MagicMock()
    setup = ProtocolSetupService(certificates, lambda _name: plugin)

    setup.prepare_enable(state, "vless")

    certificates.ensure.assert_not_called()
    assert "cert_file" not in _config(state)


def test_certificate_preflight_still_runs_in_tls_mode():
    state = _state()
    _config(state)["domain"] = "xhttp.example.com"
    plugin = VlessXhttpPlugin()
    certificates = MagicMock()
    certificates.ensure.return_value = ("/cert.pem", "/key.pem")
    setup = ProtocolSetupService(certificates, lambda _name: plugin)

    setup.prepare_enable(state, "vless")

    certificates.ensure.assert_called_once()
    assert _config(state)["cert_file"] == "/cert.pem"


def test_setting_a_domain_in_reality_mode_is_rejected():
    state = _reality_state()

    with pytest.raises(ValueError, match="режиме Reality домен не используется"):
        VlessXhttpPlugin().set_domain(state, "xhttp.example.com")


def test_health_reports_a_reality_endpoint_without_a_tls_probe():
    state = _reality_state()
    plugin = VlessXhttpPlugin()

    with patch("hydra.core.singbox.is_running", return_value=True), \
         patch("hydra.core.singbox.has_configured_inbound", return_value=True), \
         patch("hydra.core.sni_router.needs_mux", return_value=False), \
         patch("hydra.core.sni_router.probe_tls_route") as probe:
        result = plugin.healthcheck_for_state(state)

    assert result.healthy is True
    assert result.checks["reality_keys"] is True
    assert "caddy_route" not in result.checks
    probe.assert_not_called()


def test_health_requires_the_mux_route_when_the_mux_is_active():
    state = _reality_state()
    report = SimpleNamespace(ok=True, actual=("other.example.com",))

    with patch("hydra.core.singbox.is_running", return_value=True), \
         patch("hydra.core.singbox.has_configured_inbound", return_value=True), \
         patch("hydra.core.sni_router.needs_mux", return_value=True), \
         patch("hydra.core.sni_router.is_active", return_value=True), \
         patch("hydra.core.sni_router.audit_routes", return_value=report):
        result = VlessXhttpPlugin().healthcheck_for_state(state)

    assert result.healthy is False
    assert result.detail == (
        f"Caddy does not route SNI {HANDSHAKE} to VLESS Reality"
    )


def test_reality_endpoint_is_not_audited_for_certificate_expiry():
    from hydra.services.certificate_audit import collect_domains

    state = _reality_state()
    state.network.domain = "naive.example.com"

    assert collect_domains(state) == []


def test_settings_menu_switches_to_reality_with_a_chosen_handshake():
    state = _reality_state()
    app = MagicMock()
    app.admin.load_state.return_value = state
    app.plugin_command.return_value = True

    with patch.object(
        vless_xhttp_settings,
        "menu",
        side_effect=["1", "2", "0"],
    ), patch.object(
        vless_xhttp_settings,
        "prompt",
        side_effect=["www.icloud.com", ""],
    ):
        vless_xhttp_settings.open_menu(state, MagicMock(), app)

    app.plugin_command.assert_called_once_with(
        state,
        "vless",
        "set_security",
        mode=MODE_REALITY,
        handshake="www.icloud.com",
    )
