from unittest.mock import Mock

from hydra.core.state import AppState
from hydra.plugins.base import BasePlugin, PluginCategory, PluginMeta
from hydra.services.protocols import ProtocolService


def _plugin(name: str, category: PluginCategory):
    plugin = Mock(spec=BasePlugin)
    plugin.meta = PluginMeta(name=name, description=name, category=category)
    return plugin


def _fixture():
    operations = Mock()
    catalog = Mock()
    catalog.transports.return_value = [_plugin("transport", PluginCategory.TRANSPORT)]
    catalog.enhancements.return_value = [_plugin("enhancement", PluginCategory.ENHANCEMENT)]
    catalog.security.return_value = [_plugin("security", PluginCategory.SECURITY)]
    return ProtocolService(operations, catalog), operations, catalog


def test_list_filters_protocol_categories():
    service, _, _ = _fixture()

    assert [p.meta.name for p in service.list(PluginCategory.TRANSPORT)] == ["transport"]
    assert [p.meta.name for p in service.list(PluginCategory.ENHANCEMENT)] == ["enhancement"]
    assert [p.meta.name for p in service.list(PluginCategory.SECURITY)] == ["security"]
    assert len(service.list()) == 3


def test_get_and_statuses_delegate_to_catalog():
    service, _, catalog = _fixture()
    catalog.get.return_value = catalog.transports.return_value[0]
    catalog.status_all.return_value = {"transport": {"running": True}}

    assert service.get("transport").meta.name == "transport"
    assert service.statuses()["transport"]["running"] is True


def test_lifecycle_delegates_to_orchestrator():
    service, operations, _ = _fixture()
    state = AppState()
    operations.install_plugin.return_value = True
    operations.reinstall_plugin.return_value = True
    operations.uninstall_plugin.return_value = True
    operations.enable.return_value = True
    operations.disable.return_value = True

    assert service.install(state, "transport") is True
    assert service.reinstall(state, "transport") is True
    assert service.uninstall(state, "transport") is True
    assert service.enable(state, "transport") is True
    assert service.disable(state, "transport") is True

    operations.install_plugin.assert_called_once_with(state, "transport")
    operations.reinstall_plugin.assert_called_once_with(state, "transport")
    operations.uninstall_plugin.assert_called_once_with(state, "transport")
    operations.enable.assert_called_once_with(state, "transport")
    operations.disable.assert_called_once_with(state, "transport")
