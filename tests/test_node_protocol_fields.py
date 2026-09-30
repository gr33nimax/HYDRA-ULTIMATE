from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from hydra.contracts.node_snapshot import NodeProtocolSpec, is_node_local_secret_key
from hydra.plugins.base import PluginCategory
from hydra.plugins.defaults import default_plugins
from hydra.ui._menus import node_protocol_fields as fields
from hydra.ui._menus import nodes_setup


def _transport_plugins():
    return [plugin for plugin in default_plugins() if plugin.meta.category == PluginCategory.TRANSPORT]


def _app(names):
    app = Mock()
    app.protocols.list.return_value = [
        SimpleNamespace(
            meta=SimpleNamespace(
                name=name,
                display_name="",
                capabilities=SimpleNamespace(subscription_enabled=True, hydra_v2_subscription_enabled=False),
            )
        )
        for name in names
    ]
    return app


def _answers(values):
    """Answer each field by label prefix, so field order cannot break the test."""

    def answer(label, default=""):
        for prefix, value in values.items():
            if label.startswith(prefix):
                return value
        return default

    return answer


def test_every_publishable_transport_has_its_own_parameter_set():
    publishable = [
        plugin.meta.name
        for plugin in _transport_plugins()
        if (plugin.meta.capabilities.subscription_enabled or plugin.meta.capabilities.hydra_v2_subscription_enabled)
    ]
    assert publishable
    assert set(publishable) <= set(fields.PROTOCOL_FIELDS)
    assert "calls" in fields.PROTOCOL_FIELDS


def test_protocol_choices_cover_every_transport_with_readable_labels():
    app = _app([plugin.meta.name for plugin in _transport_plugins()])
    choices = nodes_setup.protocol_choices(app)
    assert len(choices) == len(_transport_plugins())
    assert all(label.strip() for _, label in choices.values())
    assert all("{}" not in label and "<" not in label for _, label in choices.values())


@pytest.mark.parametrize(
    ("provider", "field_key"),
    [("hydra.plugins.anytls.presets", "padding_preset"), ("hydra.plugins.mieru.presets", "traffic_preset")],
)
def test_dynamic_preset_choices_come_from_the_plugin_registry(provider, field_key):
    item = next(field for field in fields.PROTOCOL_FIELDS[provider.split(".")[2]] if field.key == field_key)
    choices = fields._choices(item)
    assert len(choices) >= 2
    assert all(value and label for value, label in choices)


@pytest.mark.parametrize("name", ["anytls", "hysteria2", "naive", "shadowtls", "trusttunnel", "mtproto_zig"])
def test_domain_based_protocols_still_require_a_domain(name):
    assert fields.missing_required(name, {})


def test_zero_cancels_the_whole_parameter_set():
    with patch.object(fields, "prompt", return_value="0"):
        assert fields.collect_protocol_config("anytls", {}) is None


def test_enter_keeps_previous_values_and_adds_nothing_empty():
    with (
        patch.object(fields, "prompt", return_value=""),
        patch.object(fields, "menu", return_value="0"),
    ):
        collected = fields.collect_protocol_config("shadowtls", {"domain": "node.example.com"})
    assert collected == {"domain": "node.example.com"}


def test_enum_is_chosen_by_number_and_zero_keeps_the_current_value():
    with patch.object(fields, "menu", return_value="2"), patch.object(fields, "prompt", return_value=""):
        collected = fields.collect_protocol_config("hysteria2", {"domain": "n.example.com"})
    assert collected is not None and collected["congestion_mode"] == "brutal"
    with patch.object(fields, "menu", return_value="0"), patch.object(fields, "prompt", return_value=""):
        kept = fields.collect_protocol_config("hysteria2", {"domain": "n.example.com", "congestion_mode": "brutal"})
    assert kept is not None and kept["congestion_mode"] == "brutal"


def test_integer_field_reasks_until_the_value_is_usable():
    item = fields.NodeField("up_mbps", "Upload", kind="int", default=100, minimum=1, maximum=100000)
    with (
        patch.object(fields, "prompt", side_effect=["abc", "999999", "250"]),
        patch.object(fields, "error") as report,
    ):
        accepted, value = fields._ask(item, None)
    assert accepted and value == 250
    assert report.call_count == 2


def test_boolean_field_is_confirmed_not_typed():
    item = fields.NodeField("uot", "UDP over TCP", kind="bool", default=True)
    with patch.object(fields, "confirm", return_value=False) as ask:
        accepted, value = fields._ask(item, None)
    assert accepted and value is False
    ask.assert_called_once()


def test_registry_and_collected_config_never_contain_node_local_secrets():
    for name, items in fields.PROTOCOL_FIELDS.items():
        assert all(not is_node_local_secret_key(item.key) for item in items), name
    with (
        patch.object(fields, "prompt", return_value="node.example.com"),
        patch.object(fields, "menu", return_value="0"),
        patch.object(fields, "confirm", return_value=True),
    ):
        collected = fields.collect_protocol_config("shadowtls", {})
    assert collected is not None
    assert set(collected) <= set(fields.protocol_field_names("shadowtls"))
    assert not any(is_node_local_secret_key(key) for key in collected)


def test_collect_answers_every_registry_protocol_without_looping_forever():
    for name in fields.PROTOCOL_FIELDS:
        values = _answers({"Домен": "node.example.com", "CDN-домен": "cdn.example.com", "Origin": "origin.example.com"})
        with (
            patch.object(
                fields, "prompt", side_effect=lambda label, default="", v=values: v(label, default) or default or "100"
            ),
            patch.object(fields, "menu", return_value="0"),
            patch.object(fields, "confirm", return_value=True),
        ):
            collected = fields.collect_protocol_config(name, {})
        assert collected is not None, name


def test_read_protocol_asks_protocol_parameters_instead_of_raw_json():
    app = _app(["anytls"])
    with (
        patch.object(nodes_setup, "menu", side_effect=["1"]),
        patch.object(fields, "prompt", return_value="node.example.com"),
        patch.object(fields, "menu", return_value="0"),
        patch.object(nodes_setup, "panel") as panel,
    ):
        spec = nodes_setup.read_protocol("anytls", app, NodeProtocolSpec())
    assert spec is not None and spec.enabled and spec.port == 0
    assert spec.config["domain"] == "node.example.com"
    rendered = " ".join(str(part) for call in panel.call_args_list for part in call.args)
    assert "JSON" not in rendered


def test_required_domain_is_refused_before_any_state_change():
    app = _app(["anytls"])
    with (
        patch.object(nodes_setup, "menu", side_effect=["1"]),
        patch.object(fields, "prompt", return_value=""),
        patch.object(fields, "menu", return_value="0"),
        patch.object(fields, "error") as report,
        patch.object(nodes_setup, "panel"),
    ):
        assert nodes_setup.read_protocol("anytls", app, NodeProtocolSpec()) is None
    assert report.called
    app.nodes.change_protocol.assert_not_called()


def test_vless_reality_needs_no_domain_but_tls_does():
    app = _app(["vless"])
    with (
        patch.object(nodes_setup, "menu", side_effect=["1"]),
        patch.object(fields, "menu", side_effect=["2", "0", "0"]),
        patch.object(fields, "prompt", return_value=""),
        patch.object(nodes_setup, "panel"),
    ):
        spec = nodes_setup.read_protocol("vless", app, NodeProtocolSpec())
    assert spec is not None and spec.config["security"] == "reality"
    assert not spec.config.get("domain")

    with (
        patch.object(nodes_setup, "menu", side_effect=["1"]),
        patch.object(fields, "menu", side_effect=["1", "0", "0"]),
        patch.object(fields, "prompt", return_value=""),
        patch.object(fields, "error") as report,
        patch.object(nodes_setup, "panel"),
    ):
        assert nodes_setup.read_protocol("vless", app, NodeProtocolSpec()) is None
    assert not report.called  # the required domain is refused before asking more fields
    assert not fields.missing_required("nonexistent", {})


def test_disabling_a_protocol_keeps_previous_public_parameters():
    app = _app(["anytls"])
    previous = NodeProtocolSpec(enabled=True, port=8443, config={"domain": "node.example.com"})
    with patch.object(nodes_setup, "menu", return_value="2"), patch.object(nodes_setup, "panel"):
        spec = nodes_setup.read_protocol("anytls", app, previous)
    assert spec is not None and not spec.enabled and spec.port == 8443
    assert spec.config == {"domain": "node.example.com"}


def test_unrecognized_enum_input_keeps_the_current_value_after_bounded_attempts():
    item = fields.NodeField(
        "security",
        "Защита",
        kind="enum",
        default="tls",
        choices=(("tls", "TLS"), ("reality", "Reality")),
    )
    with patch.object(fields, "menu", return_value="zz"), patch.object(fields, "error") as report:
        accepted, value = fields._ask(item, None)
    assert accepted and value == "tls"
    assert report.called


def test_read_protocol_never_asks_for_a_port_of_a_routed_tls_protocol():
    app = _app(["anytls"])
    with (
        patch.object(nodes_setup, "menu", side_effect=["1"]),
        patch.object(fields, "menu", return_value="0"),
        patch.object(fields, "prompt", return_value="node.example.com"),
        patch.object(nodes_setup, "prompt") as port_prompt,
        patch.object(nodes_setup, "panel") as panel,
    ):
        spec = nodes_setup.read_protocol("anytls", app, NodeProtocolSpec())
    assert spec is not None and spec.enabled and spec.port == 0
    port_prompt.assert_not_called()
    assert "ПОРТ" not in " ".join(str(call.args[1]) for call in panel.call_args_list)
    assert "Порт" not in " ".join(str(call.args[1]) for call in panel.call_args_list)


def _wizard_defaults(name):
    """The public settings the wizard collects when the operator accepts every default."""
    config = {}
    for item in fields.PROTOCOL_FIELDS.get(name, ()):
        if item.kind in ("int", "bool"):
            config[item.key] = item.default
        elif item.kind == "enum":
            config[item.key] = item.default or (item.choices[0][0] if item.choices else "")
        else:
            config[item.key] = item.default or ("node.example.com" if item.required else "")
    return config


def test_every_offered_transport_prepares_its_node_config_or_names_what_is_missing():
    """A node must never store a command-owned setting and call it applied.

    Preparation is the plugin's own step, so this guard fails when a transport gains a
    command-owned key that nobody prepares — the defect that left a node storing
    ``protocol_mode=3.1`` without the material it means.
    """
    from hydra.core.state_models import AppState, PluginState

    failures = []
    for plugin in _transport_plugins():
        capabilities = plugin.meta.capabilities
        if not (capabilities.subscription_enabled or capabilities.hydra_v2_subscription_enabled):
            continue
        name = plugin.meta.name
        state = AppState(protocols={name: PluginState(installed=True, enabled=True, config={})})
        try:
            result = plugin.prepare_node_config(state, _wizard_defaults(name))
        except ValueError as exc:
            if not str(exc).strip():
                failures.append(f"{name}: ValueError without a reason")
            continue
        except Exception as exc:  # noqa: BLE001 - the point is the exception type
            failures.append(f"{name}: {type(exc).__name__}: {exc}")
            continue
        if result is not True:
            failures.append(f"{name}: prepare_node_config returned {result!r}")

    assert failures == []


def test_conditional_fields_are_not_asked_when_they_cannot_apply():
    """Brutal needs explicit Mbps; BBR estimates them, so the question is noise."""
    def brute_answers(values):
        def answer(label, default=""):
            for prefix, value in values.items():
                if label.startswith(prefix):
                    return value
            return default

        return answer

    with (
        patch.object(fields, "prompt", side_effect=brute_answers({"Домен": "hy.example.com"})) as prompt,
        patch.object(fields, "menu", side_effect=["1"]),  # BBR
    ):
        config = fields.collect_protocol_config("hysteria2", {})

    assert config is not None
    assert config["congestion_mode"] == "bbr"
    assert "up_mbps" not in config and "down_mbps" not in config
    assert all("Mbps" not in str(call) for call in prompt.call_args_list)

    with (
        patch.object(
            fields,
            "prompt",
            side_effect=brute_answers({"Домен": "hy.example.com", "Upload": "250", "Download": "250"}),
        ),
        patch.object(fields, "menu", side_effect=["2"]),  # Brutal
    ):
        config = fields.collect_protocol_config("hysteria2", {})

    assert config is not None
    assert config["up_mbps"] == 250 and config["down_mbps"] == 250


def test_a_value_that_no_longer_applies_is_dropped_not_kept():
    """Switching the WEB relay off must not leave its domain behind for the node."""
    previous = {"domain": "cover.example.com", "web_mode": "hybrid", "web_domain": "web.example.com"}

    def keep_cover(label, default=""):
        return "cover.example.com" if label.startswith("Домен FakeTLS") else default

    with (
        patch.object(fields, "prompt", side_effect=keep_cover),
        patch.object(fields, "menu", side_effect=["1"]),  # off
    ):
        config = fields.collect_protocol_config("mtproto_zig", previous)

    assert config is not None
    assert config["web_mode"] == "off"
    assert "web_domain" not in config
    assert config["domain"] == "cover.example.com"


def test_preflight_rejects_impossible_combinations_before_the_vps_is_touched():
    assert fields.preflight_protocol("vless", {"security": "tls"}) == "VLESS в режиме TLS требует свой домен"
    assert fields.preflight_protocol("vless", {"security": "reality"}) == ""
    assert fields.preflight_protocol("mtproto_zig", {"web_mode": "hybrid", "domain": "cover.example.com"})
    assert fields.preflight_protocol(
        "mtproto_zig",
        {"web_mode": "hybrid", "domain": "same.example.com", "web_domain": "same.example.com"},
    )
    assert fields.preflight_protocol(
        "mtproto_zig",
        {"web_mode": "hybrid", "domain": "cover.example.com", "web_domain": "web.example.com"},
    ) == ""
    assert fields.preflight_protocol("mtproto_zig", {"web_mode": "off", "domain": "cover.example.com"}) == ""
