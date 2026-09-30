from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from hydra.contracts.node_snapshot import NodeProtocolSpec
from hydra.plugins.base import PluginCategory
from hydra.plugins.defaults import default_plugins
from hydra.ui._menus import node_protocol_fields as fields
from hydra.ui._menus import nodes_setup


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


DOMAIN_PROTOCOLS = ("anytls", "trusttunnel", "shadowtls", "naive", "hysteria2", "vless_cdn", "mtproto_zig")
TLS_ROUTED_PROTOCOLS = ("anytls", "trusttunnel", "shadowtls", "naive", "vless", "mtproto_zig", "vless_cdn")


@pytest.mark.parametrize("name", TLS_ROUTED_PROTOCOLS)
def test_tls_routed_protocols_never_ask_the_operator_for_a_port(name):
    """The node owns TCP/443; the SNI multiplexer or the frontend decides the port."""
    assert "port" not in fields.protocol_field_names(name)


@pytest.mark.parametrize("name", ["hysteria2", "calls", "wdtt"])
def test_protocols_with_a_real_config_port_ask_for_that_port(name):
    assert "port" in fields.protocol_field_names(name) or name in fields.PROTOCOL_FIELDS
    item = next(
        (field for field in fields.PROTOCOL_FIELDS[name] if field.key in {"port", "listen_port", "dtls_port"}),
        None,
    )
    assert item is not None, name
    assert item.kind == "int"
    assert (item.minimum, item.maximum) == (1, 65535)
    assert 1 <= int(str(item.default)) <= 65535


def test_read_protocol_keeps_the_node_port_untouched_for_routed_tls():
    app = _app(["anytls"])
    with (
        patch.object(nodes_setup, "menu", side_effect=["1"]),
        patch.object(fields, "prompt", return_value="node.example.com"),
        patch.object(fields, "menu", return_value="0"),
        patch.object(nodes_setup, "panel"),
    ):
        spec = nodes_setup.read_protocol("anytls", app, NodeProtocolSpec())
    assert spec is not None and spec.enabled
    assert spec.port == 0
    assert spec.config["domain"] == "node.example.com"


def test_hysteria2_collects_the_udp_port_the_plugin_actually_reads():
    app = _app(["hysteria2"])
    answers = {"Домен": "node-hy.example.com"}
    with (
        patch.object(nodes_setup, "menu", side_effect=["1"]),
        patch.object(fields, "menu", return_value="0"),
        patch.object(
            fields,
            "prompt",
            side_effect=lambda label, default="": answers.get(label.split()[0], default),
        ),
        patch.object(nodes_setup, "panel"),
    ):
        spec = nodes_setup.read_protocol("hysteria2", app, NodeProtocolSpec())
    assert spec is not None
    assert spec.config.get("port") == 8443
    assert spec.config.get("domain") == "node-hy.example.com"


def test_anytls_is_never_offered_a_port_even_when_one_was_stored_before():
    app = _app(["anytls"])
    previous = NodeProtocolSpec(enabled=True, port=9999, config={"domain": "old.example.com"})
    with (
        patch.object(nodes_setup, "menu", side_effect=["1"]),
        patch.object(fields, "prompt", return_value="node.example.com"),
        patch.object(fields, "menu", return_value="0"),
        patch.object(nodes_setup, "panel"),
    ):
        spec = nodes_setup.read_protocol("anytls", app, previous)
    assert spec is not None and spec.port == 9999
    assert spec.config["domain"] == "node.example.com"
