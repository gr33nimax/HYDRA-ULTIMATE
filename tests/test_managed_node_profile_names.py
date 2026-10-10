"""Node profile identities stay distinct from alternative import formats."""
import base64
from copy import deepcopy
import json
import struct
from types import SimpleNamespace
from unittest.mock import MagicMock
import zlib

import pytest

from hydra.contracts.managed_node_models import ApplyReceipt, NodeDefinition, canonical_digest
from hydra.contracts.managed_node_observations import ConfirmedProfiles
from hydra.core.state_models import AppState, PluginState, User
from hydra.plugins.amneziawg.plugin import AmneziaWGPlugin
from hydra.services.configuration_names import ConfigurationNameService
from hydra.services.managed_nodes.profiles import ManagedNodeProfileBuilder
from hydra.services.protocols import ProtocolService
from hydra.services.subscriptions.hydrabox import generate_hydrabox_subscription
from hydra.services.subscriptions.links import generate_base64_sub
from hydra.services.subscriptions.node_exports import _profiles_for_bundle, _tag_link, node_profile_name_key
from hydra.ui._menus.users_links import _artifact_name_key, _client_artifacts, _render_inline_artifact
from hydra.ui._menus.users_names import edit_configuration_name


@pytest.fixture
def exported_node(monkeypatch):
    monkeypatch.setattr("hydra.services.subscriptions.node_exports.cached_country_flag", lambda ip: "🇬🇧")
    state = AppState(users=[User("alice", "user-1")], protocols={
        "amneziawg": PluginState(enabled=True, installed=True, port=443, config={"protocol_mode": "2.0"}),
    })
    state.network.server_ip = "203.0.113.4"
    state.network.sub_domain = "sub.example.test"
    plugin = AmneziaWGPlugin()
    plugin.prepare_configuration(state)
    assert plugin.add_profile("mobile", "mobile", state)
    plugin.on_user_add(state.users[0], state)
    protocols = ProtocolService(operations=MagicMock(), catalog=SimpleNamespace(get=lambda name: plugin))
    profiles = ManagedNodeProfileBuilder(protocols=protocols).build(state, "uk-1")
    assert len(profiles) == 2
    digest = canonical_digest([profile.to_document() for profile in profiles])
    receipt = ApplyReceipt("apply-1", 1, "b" * 64, "runtime-1", "c" * 64, digest)
    bundle = ConfirmedProfiles("uk-1", receipt, profiles, digest)
    definition = NodeDefinition("uk-1", "Великобритания", "203.0.113.4", "root", "dev", "a" * 40,
                                24443, [], "managed-node/uk-1")
    return state, definition, bundle


def _vpn_document(link):
    encoded = link.removeprefix("vpn://")
    raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    payload = zlib.decompress(raw[4:])
    assert struct.unpack(">I", raw[:4])[0] == len(payload)
    return json.loads(payload)


def test_one_awg_variant_per_subscription_entry_and_matching_embedded_names(exported_node):
    state, definition, bundle = exported_node
    before = deepcopy(bundle)
    profiles = _profiles_for_bundle(state.users[0], state, definition, bundle)
    reader = SimpleNamespace(profiles_for_user=lambda user, state: tuple(profiles))
    plugins = SimpleNamespace(enabled_transports=lambda state: [], get=lambda name: None)
    links = base64.b64decode(generate_base64_sub(state.users[0], state, plugins=plugins, node_exports=reader)).decode().splitlines()
    assert len(links) == 2 and all(link.startswith("wg://") for link in links)
    names = ["🇬🇧 Великобритания · AWG · Desktop", "🇬🇧 Великобритания · AWG · Mobile"]
    assert [profile.name for profile in profiles] == names
    for profile in profiles:
        assert len(profile.singbox) == 1
        assert len(profile.singbox[0]["endpoints"]) == 1
        vpn = next(link for link in profile.links if link.startswith("vpn://"))
        assert _vpn_document(vpn)["description"] == profile.name
    envelope = generate_hydrabox_subscription(state.users[0], state, plugins=plugins, node_exports=reader)
    assert [profile["name"] for profile in envelope["profiles"]] == names
    assert len(envelope["resources"]) == 2
    assert bundle == before


def test_global_and_personal_names_apply_to_all_node_import_formats(exported_node):
    state, definition, bundle = exported_node
    key = node_profile_name_key("uk-1", "amneziawg", "desktop")
    state.configuration_names[key] = "🇬🇧 Мой VPN"
    user = state.users[0]
    user.configuration_name_overrides[key] = "🇬🇧 Личный VPN"
    desktop, mobile = _profiles_for_bundle(user, state, definition, bundle)
    assert desktop.name == "🇬🇧 Личный VPN"
    assert mobile.name.endswith("Mobile")
    assert _vpn_document(next(link for link in desktop.links if link.startswith("vpn://")))["description"] == desktop.name
    endpoint = desktop.singbox[0]["endpoints"][0]
    assert endpoint["tag"] == desktop.name
    assert desktop.singbox[0]["route"]["final"] == endpoint["tag"]
    # Display-only edits never rotate credentials, alter membership or need remote apply.
    assert len(bundle.profiles) == 2


def test_node_profiles_are_editable_with_stable_keys_and_node_scoped_menu(exported_node, monkeypatch):
    state, definition, bundle = exported_node
    profiles = tuple(_profiles_for_bundle(state.users[0], state, definition, bundle))
    protocols = MagicMock()
    protocols.enabled_subscription_names.return_value = []
    protocols.manual_client_artifacts.return_value = []
    app = SimpleNamespace(protocols=protocols, nodes=SimpleNamespace(profiles_for_user=lambda user, state: profiles),
                          configuration_names=ConfigurationNameService(), admin=MagicMock())
    artifacts = _client_artifacts(state, state.users[0], app)
    assert [_artifact_name_key(item) for item in artifacts] == [profile.name_key for profile in profiles]
    choices = []
    monkeypatch.setattr("hydra.ui._menus.users_names.menu", lambda options, title: choices.extend(options) or "1")
    monkeypatch.setattr("hydra.ui._menus.users_names.prompt", lambda *args, **kwargs: "🇬🇧 UK VPN")
    monkeypatch.setattr("hydra.ui._menus.users_names.success", lambda *args: None)
    edit_configuration_name(state, state.users[0], app, global_scope=True, node_id="uk-1")
    assert len(choices) == 3
    assert state.configuration_names == {profiles[0].name_key: "🇬🇧 UK VPN"}
    app.admin.save_state.assert_called_once_with(state)


@pytest.mark.parametrize("link", ["vpn://bad", "vpn://AAAA", "vpn://" + "A" * 131073])
def test_invalid_or_oversized_amnezia_container_is_not_rewritten(link):
    assert _tag_link(link, "name") == link


def test_subscription_retains_amnezia_fallback_when_wg_import_is_unavailable(exported_node):
    from dataclasses import replace
    state, definition, bundle = exported_node
    profile = _profiles_for_bundle(state.users[0], state, definition, bundle)[0]
    profile = replace(profile, links=tuple(link for link in profile.links if link.startswith("vpn://")))
    reader = SimpleNamespace(profiles_for_user=lambda user, state: (profile,))
    plugins = SimpleNamespace(enabled_transports=lambda state: [], get=lambda name: None)
    links = base64.b64decode(generate_base64_sub(state.users[0], state, plugins=plugins, node_exports=reader)).decode().splitlines()
    assert len(links) == 1 and links[0].startswith("vpn://")


def test_manual_node_links_keep_node_names_instead_of_base_names(exported_node, capsys):
    state, definition, bundle = exported_node
    profiles = tuple(_profiles_for_bundle(state.users[0], state, definition, bundle))
    protocols = MagicMock()
    protocols.enabled_subscription_names.return_value = []
    protocols.manual_client_artifacts.return_value = []
    state.configuration_names["amneziawg:desktop"] = "Основа"
    app = SimpleNamespace(protocols=protocols, nodes=SimpleNamespace(profiles_for_user=lambda user, state: profiles),
                          configuration_names=ConfigurationNameService())
    artifact = _client_artifacts(state, state.users[0], app)[0]
    _render_inline_artifact(artifact, state, state.users[0], app)
    output = capsys.readouterr().out
    assert all(link in output for link in artifact.links)
    assert "Основа" not in output


def test_protocol_name_editor_excludes_other_protocols_on_the_same_node(exported_node, monkeypatch):
    from dataclasses import replace
    state, definition, bundle = exported_node
    awg = tuple(_profiles_for_bundle(state.users[0], state, definition, bundle))
    other = replace(awg[0], protocol="anytls", name="UK AnyTLS",
                    name_key=node_profile_name_key("uk-1", "anytls", "direct"))
    protocols = MagicMock()
    protocols.enabled_subscription_names.return_value = []
    protocols.manual_client_artifacts.return_value = []
    app = SimpleNamespace(protocols=protocols, nodes=SimpleNamespace(profiles_for_user=lambda user, state: (*awg, other)),
                          configuration_names=ConfigurationNameService(), admin=MagicMock())
    shown = []
    monkeypatch.setattr("hydra.ui._menus.users_names.menu", lambda options, title: shown.extend(options) or "0")
    edit_configuration_name(state, state.users[0], app, global_scope=True, node_id="uk-1", protocol_name="amneziawg")
    assert len(shown) == 3
    assert "UK AnyTLS" not in str(shown)
    app.admin.save_state.assert_not_called()
