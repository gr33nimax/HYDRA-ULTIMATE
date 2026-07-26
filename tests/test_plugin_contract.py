import pytest

from hydra.plugins import registry
from hydra.core.state import AppState
from hydra.plugins.base import BasePlugin, ConfigFragment, HealthResult, LifecycleResult, PluginMeta, PluginStatus
from hydra.plugins.context import PluginStateAccess
from hydra.plugins.invoker import PluginInvoker


class LegacyPlugin(BasePlugin):
    meta = PluginMeta("legacy", "test")
    status_state = None

    def install(self) -> bool:
        return True

    def uninstall(self) -> bool:
        return True

    def status(
        self,
        state: PluginStateAccess | None = None,
    ) -> PluginStatus:
        self.status_state = state
        return PluginStatus(True, True, True)

    def configure(self, state: AppState) -> ConfigFragment:
        return ConfigFragment()

    def healthcheck(self):
        return True, "legacy healthy"


def test_registered_plugins_satisfy_static_contract():
    registry.validate_contracts()
    assert all(not registry.contract_errors(plugin) for plugin in registry.all_plugins())


def test_capabilities_are_typed_and_serializable():
    plugin = registry.all_plugins()[0]
    capabilities = plugin.meta.capabilities
    assert isinstance(capabilities.central_apply, bool)
    assert isinstance(capabilities.as_dict(), dict)


def test_legacy_lifecycle_and_health_are_normalized():
    plugin = LegacyPlugin()
    assert isinstance(plugin.install_result(), LifecycleResult)
    assert isinstance(plugin.enable_result(AppState()), LifecycleResult)
    result = plugin.health_result()
    assert isinstance(result, HealthResult)
    assert result.healthy is True


def test_app_state_satisfies_the_narrow_plugin_state_port():
    assert isinstance(AppState(), PluginStateAccess)


def test_invoker_rejects_an_unknown_contract_version_explicitly():
    plugin = LegacyPlugin()
    plugin.meta = PluginMeta("future", "test", contract_version=2)

    with pytest.raises(ValueError, match="unsupported plugin contract v2"):
        PluginInvoker().configure(plugin, AppState())


def test_invoker_passes_explicit_state_to_status_contract():
    plugin = LegacyPlugin()
    state = AppState()

    PluginInvoker().status(plugin, state)

    assert plugin.status_state is state
