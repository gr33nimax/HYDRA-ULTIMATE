from types import SimpleNamespace

from hydra.ui.protocol_menu import (
    enhancement_options,
    enhancement_summary_lines,
    menu_footer,
    transport_options,
    transport_summary_lines,
)
import hydra.ui.protocol_menu as protocol_menu


def _plugin(name: str, description: str = "description"):
    return SimpleNamespace(meta=SimpleNamespace(name=name, description=description))


def test_transport_rows_keep_registry_order_and_status_details():
    plugins = [_plugin("vless"), _plugin("hysteria2")]
    statuses = {
        "vless": {"running": True, "enabled": True, "installed": True, "port": 443},
        "hysteria2": {"running": False, "enabled": True, "installed": True, "port": None, "error": "broken"},
    }

    lines = transport_summary_lines(plugins, statuses)
    options = transport_options(plugins, statuses)

    assert "vless" in lines[0] and "443" in lines[0]
    assert [row[0] for row in options] == ["1", "2"]
    assert options[1][2] == "broken"


def test_enhancement_rows_are_safe_for_missing_optional_status_fields():
    plugins = [_plugin("dnscrypt")]
    statuses = {"dnscrypt": {"installed": True, "running": False, "enabled": False}}

    lines = enhancement_summary_lines(plugins, statuses)
    options = enhancement_options(plugins, statuses)

    assert "dnscrypt" in lines[0]
    assert options[0][0] == "1"
    assert "dnscrypt" in options[0][1]


def test_menu_footer_is_stable_and_does_not_share_mutable_state():
    first = menu_footer()
    first.append(("x", "", ""))
    assert menu_footer() == [("-", "", ""), ("0", "↩ Назад", "")]


def test_render_protocol_status_falls_back_to_persisted_state_on_probe_error(monkeypatch):
    plugin = SimpleNamespace(
        meta=SimpleNamespace(name="vless"),
        status=lambda: (_ for _ in ()).throw(RuntimeError("probe failed")),
    )
    persisted = SimpleNamespace(installed=True, enabled=True, running=True, port=443)
    captured = {}
    monkeypatch.setattr(protocol_menu, "protocol_status_panel", lambda *args, **kwargs: captured.update(kwargs))

    protocol_menu.render_protocol_status(plugin, persisted)

    assert captured == {
        "installed": True,
        "enabled": True,
        "running": False,
        "port": 443,
        "error": "probe failed",
    }
