"""A node protocol has separate settings, naming and confirmed removal actions."""
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from hydra.contracts.managed_node_models import NodeDefinition, ProtocolAssignment
from hydra.contracts.managed_node_observations import NodeView, SyncReport
from hydra.ui._menus import node_protocols


def _view(assignment):
    return NodeView(NodeDefinition("uk-1", "Великобритания", "203.0.113.4", "root", "dev", "a" * 40,
                                   24443, [assignment], "node/uk-1"))


def _menu(monkeypatch, choices):
    iterator = iter(choices)
    shown = []
    def select(options, title):
        shown.append((options, title))
        return next(iterator)
    monkeypatch.setattr(node_protocols, "menu", select)
    return shown


@pytest.mark.parametrize("parameters", [{"protocol_mode": "2.0", "port": 443}, {"port": 443}])
def test_opening_settings_without_edits_never_asks_for_apply(monkeypatch, parameters):
    assignment = ProtocolAssignment("amneziawg", parameters)
    _menu(monkeypatch, ["1", "1", "0", "0"])
    monkeypatch.setattr(node_protocols, "collect_protocol_config", lambda name, previous: {**previous, "protocol_mode": "2.0"})
    confirm = MagicMock()
    monkeypatch.setattr(node_protocols, "confirm", confirm)
    app = MagicMock()
    node_protocols.manage_node_protocols(_view(assignment), app, MagicMock())
    confirm.assert_not_called()
    app.nodes.configure_protocol.assert_not_called()
    app.nodes.sync.assert_not_called()


@pytest.mark.parametrize("accepted", [False, True])
def test_protocol_removal_has_confirmation_and_reports_actual_sync_result(monkeypatch, accepted):
    assignment = ProtocolAssignment("anytls", {"domain": "uk.example.test", "port": 443})
    choices = ["1", "3"] if accepted else ["1", "3", "0", "0"]
    shown = _menu(monkeypatch, choices)
    monkeypatch.setattr(node_protocols, "confirm", lambda *args, **kwargs: accepted)
    report = SyncReport({"uk-1": {"status": "failed", "error": "remote apply failed"}})
    app = MagicMock()
    app.nodes.remove_protocol.return_value = report
    render = MagicMock()
    node_protocols.manage_node_protocols(_view(assignment), app, render)
    assert "Добавить протокол" in [label for key, label, hint in shown[0][0]]
    assert "только реализованные формы" not in str(shown)
    if accepted:
        app.nodes.remove_protocol.assert_called_once_with("uk-1", "anytls", confirmed=True)
        render.assert_called_once_with("УДАЛЕНИЕ ПРОТОКОЛА", report)
    else:
        app.nodes.remove_protocol.assert_not_called()


def test_naming_is_inside_protocol_settings_and_scoped_to_that_protocol(monkeypatch):
    assignment = ProtocolAssignment("amneziawg", {"port": 443})
    _menu(monkeypatch, ["1", "2", "0", "0"])
    edit_names = MagicMock()
    monkeypatch.setattr(node_protocols, "edit_global_configuration_names", edit_names)
    app = MagicMock()
    node_protocols.manage_node_protocols(_view(assignment), app, MagicMock())
    edit_names.assert_called_once_with(app.admin.load_state.return_value, app, node_id="uk-1", protocol_name="amneziawg")
    app.nodes.configure_protocol.assert_not_called()


@pytest.mark.parametrize("accepted", [True, False])
def test_actual_setting_change_is_applied_only_after_confirmation(monkeypatch, accepted):
    assignment = ProtocolAssignment("anytls", {"domain": "uk.example.test", "port": 443})
    _menu(monkeypatch, ["1", "1"] if accepted else ["1", "1", "0", "0"])
    parameters = {"domain": "new.example.test", "port": 443}
    monkeypatch.setattr(node_protocols, "collect_protocol_config", lambda name, previous: parameters)
    monkeypatch.setattr(node_protocols, "confirm", lambda *args, **kwargs: accepted)
    app = MagicMock()
    app.nodes.configure_protocol.return_value = SyncReport({"uk-1": {"status": "pending"}})
    render = MagicMock()
    node_protocols.manage_node_protocols(_view(assignment), app, render)
    if accepted:
        app.nodes.configure_protocol.assert_called_once_with("uk-1", ProtocolAssignment("anytls", parameters), confirmed=True)
        render.assert_called_once_with("НАСТРОЙКИ ПРОТОКОЛА", app.nodes.configure_protocol.return_value)
    else:
        app.nodes.configure_protocol.assert_not_called()


def test_new_protocol_with_only_default_settings_is_still_added(monkeypatch):
    view = _view(ProtocolAssignment("anytls", {"domain": "uk.example.test", "port": 443}))
    _menu(monkeypatch, ["2", "1"])
    plugin = SimpleNamespace(meta=SimpleNamespace(name="amneziawg", display_name="AmneziaWG",
                              capabilities=SimpleNamespace(subscription_enabled=True)))
    app = MagicMock()
    app.protocols.list.return_value = [plugin]
    monkeypatch.setattr(node_protocols, "collect_protocol_config", lambda name, previous: {"protocol_mode": "2.0"})
    monkeypatch.setattr(node_protocols, "confirm", lambda *args, **kwargs: True)
    node_protocols.manage_node_protocols(view, app, MagicMock())
    app.nodes.configure_protocol.assert_called_once_with("uk-1", ProtocolAssignment("amneziawg", {
        "protocol_mode": "2.0", "port": 443,
    }), confirmed=True)
