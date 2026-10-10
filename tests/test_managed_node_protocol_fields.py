from __future__ import annotations

from unittest.mock import patch

import pytest

from hydra.contracts.managed_node_models import ProtocolAssignment
from hydra.core.state_models import AppState, PluginState
from hydra.plugins.base import PluginCategory
from hydra.plugins.defaults import default_plugins
from hydra.ui._menus import node_protocol_fields as fields


def test_offered_transports_have_specific_public_parameter_definitions():
    offered = {
        plugin.meta.name
        for plugin in default_plugins()
        if plugin.meta.category == PluginCategory.TRANSPORT
        and (plugin.meta.capabilities.subscription_enabled or plugin.meta.capabilities.hydra_v2_subscription_enabled)
    }
    assert offered
    assert offered <= set(fields.PROTOCOL_FIELDS)
    assert all(fields.protocol_field_labels(name) for name in offered)


def test_required_fields_cancel_and_vless_security_preflight_are_explicit():
    assert fields.missing_required("anytls", {})
    assert fields.preflight_protocol("vless", {"security": "tls"})
    assert not fields.preflight_protocol("vless", {"security": "reality"})
    with patch.object(fields, "prompt", return_value="0"):
        assert fields.collect_protocol_config("anytls", {}) is None


def test_form_removes_stale_conditional_parameters_and_contract_rejects_secrets():
    with (
        patch.object(fields, "prompt", return_value="cover.example.test"),
        patch.object(fields, "menu", return_value="0"),
    ):
        config = fields.collect_protocol_config(
            "mtproto_zig",
            {"domain": "cover.example.test", "web_mode": "off", "web_domain": "stale.example.test"},
        )
    assert config == {"domain": "cover.example.test", "web_mode": "off"}
    with pytest.raises(ValueError, match="secret"):
        ProtocolAssignment("vless", {"port": 443, "private_key": "must-not-cross"}).validate()


def test_numeric_fields_reask_invalid_values_and_accept_only_the_range():
    item = fields.NodeField("port", "Port", kind="int", minimum=1, maximum=65535)
    with patch.object(fields, "prompt", side_effect=["bad", "70000", "24443"]), patch.object(fields, "error") as report:
        accepted, value = fields._ask(item, None)
    assert accepted and value == 24443
    assert report.call_count == 2


def test_registry_choices_and_collected_values_are_usable_by_node_plugins():
    for plugin in default_plugins():
        if plugin.meta.category != PluginCategory.TRANSPORT:
            continue
        name = plugin.meta.name
        if name not in fields.PROTOCOL_FIELDS:
            continue
        config = {}
        for item in fields.PROTOCOL_FIELDS[name]:
            if item.default not in (None, ""):
                config[item.key] = item.default
            elif item.required:
                config[item.key] = "node.example.test"
        with (
            patch.object(fields, "prompt", side_effect=lambda _label, default="": str(default)),
            patch.object(fields, "menu", return_value="0"),
            patch.object(fields, "confirm", return_value=True),
        ):
            collected = fields.collect_protocol_config(name, config)
        assert collected is not None, name
        assert not fields.protocol_config_changed(name, config, collected), name
        state = AppState(protocols={name: PluginState(installed=True, enabled=True, config={})})
        try:
            result = plugin.prepare_node_config(state, collected)
        except ValueError as exc:
            assert str(exc).strip(), name
        else:
            assert result is True, name


@pytest.mark.parametrize("name, previous, collected, changed", [
    ("amneziawg", {}, {"protocol_mode": "2.0", "port": 443}, False),
    ("amneziawg", {"protocol_mode": "2.0"}, {"protocol_mode": "3.1"}, True),
    ("naive", {"domain": "node.test"}, {"domain": "node.test", "network": "tcp", "uot": True}, False),
    ("naive", {"domain": "node.test"}, {"domain": "node.test", "uot": False}, True),
    ("mtproto_zig", {"domain": "node.test", "web_mode": "off", "web_domain": "unused.test"},
     {"domain": "node.test", "web_mode": "off"}, False),
    ("mtproto_zig", {"domain": "node.test", "web_mode": "hybrid", "web_domain": "relay.test"},
     {"domain": "node.test", "web_mode": "off"}, True),
    ("hysteria2", {"domain": "node.test", "congestion_mode": "bbr"},
     {"domain": "node.test", "congestion_mode": "bbr", "port": 8443}, False),
])
def test_effective_changes_distinguish_defaults_from_real_edits(name, previous, collected, changed):
    assert fields.protocol_config_changed(name, previous, collected) is changed
