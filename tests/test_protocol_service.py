from unittest.mock import Mock

from hydra.core.state import AppState, PluginState
from hydra.plugins.base import BasePlugin, PluginCategory, PluginMeta
from hydra.plugins.invoker import PluginInvoker
from hydra.services.protocols import ManualClientArtifact, ProtocolService


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


def test_inventory_is_json_safe_and_filters_by_public_category():
    service, _, catalog = _fixture()
    state = AppState()
    catalog.status_all.return_value = {
        "transport": {
            "installed": True,
            "enabled": False,
            "running": False,
        },
    }

    inventory = service.inventory(state, category="transport")

    assert inventory == [
        {
            "name": "transport",
            "display_name": "transport",
            "description": "transport",
            "category": "transport",
            "version": "1.0.0",
            "contract_version": 1,
            "capabilities": {
                "central_apply": True,
                "required_commands": (),
                "required_services": (),
                "conflicts_with": (),
                "commands": (),
                "persist_only_commands": (),
                "queries": (),
                "actions": (),
                "tls_domain_source": "",
                "config_defaults": (),
                "subscription_profile_query": "",
                "subscription_enabled": True,
                "hydra_v2_subscription_enabled": True,
                "manual_artifacts_query": "",
                "connection_source": "plugin",
                "maintenance_tasks": (),
                "backup_resources": (),
            },
            "status": {
                "installed": True,
                "enabled": False,
                "running": False,
            },
        },
    ]
    catalog.status_all.assert_called_once_with(state)


def test_status_queries_receive_state_from_the_injected_reader():
    state = AppState()
    plugin = _plugin("transport", PluginCategory.TRANSPORT)
    plugin.status.return_value.running = True
    operations = Mock()
    catalog = Mock()
    catalog.get.return_value = plugin
    catalog.status_all.return_value = {"transport": {"running": True}}
    service = ProtocolService(
        operations,
        catalog,
        state_reader=lambda: state,
    )

    assert service.status("transport").running is True
    assert service.statuses()["transport"]["running"] is True

    plugin.status.assert_called_once_with(state)
    catalog.status_all.assert_called_once_with(state)


def test_lifecycle_delegates_to_orchestrator():
    service, operations, _ = _fixture()
    state = AppState()
    operations.install_plugin.return_value = True
    operations.activate_plugin.return_value = True
    operations.reinstall_plugin.return_value = True
    operations.uninstall_plugin.return_value = True
    operations.enable.return_value = True
    operations.disable.return_value = True

    assert service.install(state, "transport") is True
    assert service.activate(state, "transport", domain="vpn.example.com") is True
    assert service.reinstall(state, "transport") is True
    assert service.uninstall(state, "transport") is True
    assert service.enable(state, "transport") is True
    assert service.disable(state, "transport") is True

    operations.install_plugin.assert_called_once_with(state, "transport")
    operations.activate_plugin.assert_called_once_with(
        state,
        "transport",
        domain="vpn.example.com",
    )
    operations.reinstall_plugin.assert_called_once_with(state, "transport")
    operations.uninstall_plugin.assert_called_once_with(state, "transport")
    operations.enable.assert_called_once_with(state, "transport")
    operations.disable.assert_called_once_with(state, "transport")


def test_connection_activity_uses_the_declared_plugin_projection():
    plugin = _plugin("transport", PluginCategory.TRANSPORT)
    plugin.meta = PluginMeta(
        name="transport",
        description="transport",
        queries=("recent_activity",),
        connection_source="recent_activity",
    )
    catalog = Mock()
    catalog.get.return_value = plugin
    invoker = Mock(spec=PluginInvoker)
    invoker.query.return_value = [{"email": "a@example.com"}]
    service = ProtocolService(Mock(), catalog, invoker=invoker)
    state = AppState()

    assert service.connection_activity(state, "transport") == [
        {"email": "a@example.com"},
    ]
    invoker.query.assert_called_once_with(
        plugin,
        "recent_activity",
        state=state,
    )


def test_tracked_connection_source_does_not_duplicate_plugin_rows():
    plugin = _plugin("transport", PluginCategory.TRANSPORT)
    plugin.meta = PluginMeta(
        name="transport",
        description="transport",
        connection_source="tracked",
    )
    catalog = Mock()
    catalog.get.return_value = plugin
    invoker = Mock(spec=PluginInvoker)
    service = ProtocolService(Mock(), catalog, invoker=invoker)

    assert service.connection_activity(AppState(), "transport") == []
    invoker.connected_clients.assert_not_called()
    invoker.query.assert_not_called()


def test_client_profiles_and_subscription_names_are_descriptor_driven():
    profiled = _plugin("profiled", PluginCategory.TRANSPORT)
    profiled.meta = PluginMeta(
        name="profiled",
        description="profiled",
        queries=("profiles",),
        subscription_profile_query="profiles",
    )
    aggregate_only = _plugin("aggregate", PluginCategory.TRANSPORT)
    aggregate_only.meta = PluginMeta(
        name="aggregate",
        description="aggregate",
        subscription_enabled=False,
    )
    catalog = Mock()
    catalog.get.return_value = profiled
    catalog.transports.return_value = [profiled, aggregate_only]
    catalog.enhancements.return_value = []
    catalog.security.return_value = []
    invoker = Mock(spec=PluginInvoker)
    invoker.query.return_value = [{"name": "mobile", "label": "Mobile"}]
    service = ProtocolService(Mock(), catalog, invoker=invoker)
    state = AppState(
        protocols={
            "profiled": PluginState(enabled=True),
            "aggregate": PluginState(enabled=True),
        },
    )

    assert service.enabled_subscription_names(state) == {"profiled"}
    assert service.client_profiles(state, "profiled") == [
        {"name": "mobile", "label": "Mobile"},
    ]


def test_manual_artifacts_are_descriptor_driven_and_not_subscriptions():
    plugin = _plugin("global", PluginCategory.TRANSPORT)
    plugin.meta = PluginMeta(
        name="global",
        description="global",
        display_name="Global transport",
        queries=("manual_artifacts",),
        manual_artifacts_query="manual_artifacts",
        subscription_enabled=False,
    )
    catalog = Mock()
    catalog.transports.return_value = [plugin]
    catalog.enhancements.return_value = []
    catalog.security.return_value = []
    invoker = Mock(spec=PluginInvoker)
    invoker.query.return_value = [
        {
            "profile_name": "master",
            "profile_label": "Shared master",
            "links": ["qwdtt://master", "qwdtt://master"],
        },
    ]
    service = ProtocolService(Mock(), catalog, invoker=invoker)
    state = AppState(protocols={"global": PluginState(enabled=True)})

    assert service.enabled_subscription_names(state) == set()
    assert service.manual_client_artifacts(state) == [
        ManualClientArtifact(
            plugin_name="global",
            display_name="Global transport",
            profile_name="master",
            profile_label="Shared master",
            config="",
            links=("qwdtt://master",),
        ),
    ]
    invoker.query.assert_called_once_with(
        plugin,
        "manual_artifacts",
        state=state,
    )
