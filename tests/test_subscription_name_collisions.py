import base64
import json
from urllib.parse import urlsplit

from hydra.core.state_models import AppState, PluginState, User
from hydra.plugins.anytls.plugin import AnyTLSPlugin
from hydra.plugins.shadowtls.plugin import ShadowTLSPlugin
from hydra.plugins.trusttunnel.plugin import TrustTunnelPlugin
from hydra.services.subscriptions.access import SubscriptionPluginService
from hydra.services.subscriptions.client_configs import generate_singbox_config, generate_throne_sub
from hydra.services.subscriptions.hydrabox import generate_hydrabox_subscription


def test_equal_display_names_keep_both_protocols_and_detours():
    user = User(email="alice@example.com", uuid="one")
    state = AppState(users=[user], protocols={
        "anytls": PluginState(enabled=True, config={"domain": "any.example"}),
        "shadowtls": PluginState(enabled=True, config={"handshake_sni": "www.example.com"}),
    }, configuration_names={"anytls": "Дом", "shadowtls": "Дом"})
    state.network.server_ip = "203.0.113.10"
    transports = [AnyTLSPlugin(), ShadowTLSPlugin()]
    plugins = SubscriptionPluginService(
        enabled_plugins=lambda *_args: transports,
        get_plugin=lambda name: next((p for p in transports if p.meta.name == name), None),
    )
    combined = generate_singbox_config(user, state, plugins=plugins)
    tags = [outbound["tag"] for outbound in combined["outbounds"]]
    assert len(tags) == len(set(tags))
    anytls = next(outbound for outbound in combined["outbounds"] if outbound["type"] == "anytls")
    trojan = next(outbound for outbound in combined["outbounds"] if outbound["type"] == "trojan")
    assert anytls["tag"] == "Дом"
    assert trojan["tag"] == "Дом (2)"
    assert trojan["detour"] in tags
    assert trojan["password"] == ShadowTLSPlugin._derive_trojan_password(user.uuid)
    assert combined["route"]["final"] == "Дом"

    lines = base64.b64decode(generate_throne_sub(user, state, plugins=plugins)).decode().splitlines()
    wrapper_link = next(link for link in lines if link.startswith("json://shadowtls#"))
    encoded = urlsplit(wrapper_link).fragment
    wrapper = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    assert wrapper["name"] == "Дом"
    assert json.loads(wrapper["config"])["route"]["final"] == "Дом"

    user.created_at = "2026-09-10T00:00:00Z"
    envelope = generate_hydrabox_subscription(user, state, plugins=plugins)
    assert {profile["name"] for profile in envelope["profiles"]} == {"Дом"}


def test_trusttunnel_menu_key_names_both_transports_and_avoids_reserved_tags():
    user = User(email="alice@example.com", uuid="one")
    state = AppState(users=[user], protocols={
        "trusttunnel": PluginState(enabled=True, config={"domain": "tt.example", "transport": "both"}),
    }, configuration_names={"trusttunnel": "Общее"})
    plugin = TrustTunnelPlugin()
    plugins = SubscriptionPluginService(enabled_plugins=lambda *_: [plugin], get_plugin=lambda _: plugin)
    config = json.loads(plugins.client_config(plugin, user, state))
    assert [outbound["tag"] for outbound in config["outbounds"]] == ["Общее", "Общее QUIC", "direct"]
    state.configuration_names["trusttunnel:quic"] = "Общее отдельное"
    user.configuration_name_overrides["trusttunnel"] = "Личное"
    config = json.loads(plugins.client_config(plugin, user, state))
    assert [outbound["tag"] for outbound in config["outbounds"]] == ["Личное", "Личное QUIC", "direct"]
    for link, name in zip(plugins.client_links(plugin, user, state), ("Личное", "Личное QUIC")):
        encoded = link.removeprefix("tt://?")
        assert name.encode() in base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    assert user.configuration_name_overrides == {"trusttunnel": "Личное"}
    for reserved in ("direct", "select", "__hydra.test"):
        user.configuration_name_overrides["trusttunnel"] = reserved
        config = json.loads(plugins.client_config(plugin, user, state))
        tags = [outbound["tag"] for outbound in config["outbounds"]]
        assert len(tags) == len(set(tags))
        assert config["route"]["final"] != reserved
        assert not config["route"]["final"].startswith("__hydra.")
