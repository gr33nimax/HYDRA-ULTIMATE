"""Server projections must revoke a single user's old credentials."""

from unittest.mock import patch

from hydra.contracts.vless_cdn import generate_encryption_keypair
from hydra.core.state_models import AppState, PluginState, User
from hydra.plugins.amneziawg.plugin import AmneziaWGPlugin
from hydra.plugins.anytls.plugin import AnyTLSPlugin
from hydra.plugins.calls.plugin import CallsPlugin
from hydra.plugins.catalog import PluginCatalog
from hydra.plugins.executor import PluginExecutor
from hydra.plugins.invoker import PluginInvoker
from hydra.plugins.snell.plugin import SnellPlugin
from hydra.plugins.vless_cdn.plugin import VlessCdnPlugin


def test_cdn_inbound_excludes_only_the_disabled_user():
    user = User(email="alice", uuid="00000000-0000-4000-8000-000000000001", disabled_protocols=["vless_cdn"])
    other = User(email="bob", uuid="00000000-0000-4000-8000-000000000002")
    state = AppState(
        users=[user, other],
        protocols={
            "vless_cdn": PluginState(
                enabled=True,
                config={
                    "cdn_domain": "cdn.example.test",
                    "origin_host": "origin.example.test",
                    "xhttp_path": "/xhttp",
                    "core_port": 20449,
                    "encryption_private_key": generate_encryption_keypair()[0],
                },
            )
        },
    )
    inbound = PluginInvoker().configure(VlessCdnPlugin(), state).inbounds[0]
    assert inbound["users"] == [{"name": "bob", "uuid": other.uuid}]


def test_snell_keeps_reserved_ports_when_one_user_is_disabled():
    enabled = User(email="bob", uuid="bob")
    solo = AppState(users=[enabled])
    reserved_port = SnellPlugin._port_map(solo)[enabled.uuid]
    disabled = User(email="alice", uuid="alice", disabled_protocols=["snell"])
    disabled.credentials["snell"] = {"port": reserved_port}
    state = AppState(users=[disabled, enabled], protocols={"snell": PluginState()})
    expected_port = SnellPlugin._port_map(state)[enabled.uuid]
    assert expected_port != reserved_port

    with (
        patch.object(SnellPlugin, "_require_generation_support"),
        patch.object(SnellPlugin, "_version", return_value=5),
    ):
        inbounds = PluginInvoker().configure(SnellPlugin(), state).inbounds
    assert len(inbounds) == 1
    assert inbounds[0]["listen_port"] == expected_port


def test_last_revocation_keeps_empty_calls_server_valid():
    user = User(email="alice", uuid="alice", disabled_protocols=["calls"])
    state = AppState(users=[user], protocols={"calls": PluginState(enabled=True)})
    plugin = CallsPlugin()
    assert PluginInvoker().configure(plugin, state).inbounds == []
    assert PluginInvoker().apply(plugin, state) is True


def test_empty_authorized_transport_does_not_fail_health_check():
    user = User(email="alice", uuid="alice", disabled_protocols=["anytls"])
    state = AppState(users=[user], protocols={"anytls": PluginState(enabled=True)})
    assert PluginExecutor(PluginCatalog([AnyTLSPlugin()])).health_all(state) == {}


def test_amneziawg_endpoint_drops_revoked_peer_but_preserves_keys():
    user = User(email="alice", uuid="alice", disabled_protocols=["amneziawg"])
    user.credentials["amneziawg"] = {
        "private_key": "client-private",
        "public_key": "client-public",
        "preshared_key": "client-psk",
        "address_octet": "3",
    }
    state = AppState(
        users=[user],
        protocols={
            "amneziawg": PluginState(
                config={
                    "protocol_mode": "2.0",
                    "profiles": {
                        "desktop": {
                            "server_private_key": "server-private",
                            "port": 50494,
                            "network": "10.67.67.0/24",
                            "mtu": "1376",
                            "obfuscation": {
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
                            },
                        }
                    },
                }
            )
        },
    )
    endpoints = PluginInvoker().configure(AmneziaWGPlugin(), state).endpoints
    assert len(endpoints) == 1
    assert endpoints[0]["peers"] == []
    assert user.credentials["amneziawg"]["public_key"] == "client-public"
