"""tests/test_plugins.py — Тесты для плагинной системы."""
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from hydra.plugins.base import BasePlugin, PluginMeta, PluginStatus, PluginCategory, ConfigFragment
from hydra.core.state import AppState, PluginState


class MockPlugin(BasePlugin):
    """Тестовый плагин для проверки интерфейса."""
    meta = PluginMeta(
        name="mock",
        description="Mock plugin for testing",
        category=PluginCategory.ENHANCEMENT,
        version="0.0.1",
    )

    def install(self) -> bool:
        return True

    def uninstall(self) -> bool:
        return True

    def configure(self, state: AppState) -> ConfigFragment:
        return ConfigFragment(
            inbounds=[{"type": "http", "tag": "mock-in", "listen": "127.0.0.1", "listen_port": 9999}],
        )

    def status(self) -> PluginStatus:
        return PluginStatus(
            installed=True,
            enabled=True,
            running=True,
            port=9999,
        )

    def traffic(self, state: AppState) -> dict[str, int]:
        return {"test@example.com": 1024}


def test_plugin_meta():
    """Метаданные плагина."""
    plugin = MockPlugin()
    assert plugin.meta.name == "mock"
    assert plugin.meta.version == "0.0.1"


def test_plugin_install():
    """Установка плагина."""
    plugin = MockPlugin()
    assert plugin.install() is True


def test_plugin_configure():
    """Конфигурация плагина возвращает фрагмент."""
    plugin = MockPlugin()
    state = AppState()
    frag = plugin.configure(state)
    assert len(frag.inbounds) == 1
    assert frag.inbounds[0]["type"] == "http"
    assert frag.inbounds[0]["listen_port"] == 9999


def test_plugin_status():
    """Статус плагина."""
    plugin = MockPlugin()
    status = plugin.status()
    assert status.installed is True
    assert status.running is True
    assert status.port == 9999


def test_plugin_traffic():
    """Трафик плагина."""
    plugin = MockPlugin()
    state = AppState()
    traffic = plugin.traffic(state)
    assert traffic["test@example.com"] == 1024


def test_plugin_on_enable_disable():
    """Включение/выключение плагина."""
    plugin = MockPlugin()
    state = AppState()
    # Эти методы не должны падать
    plugin.on_enable(state)
    plugin.on_disable(state)


def test_status_all_returns_all_plugins():
    """status_all возвращает статусы всех зарегистрированных плагинов."""
    from hydra.plugins.registry import status_all
    with patch("hydra.plugins.registry._PLUGINS", [MockPlugin()]):
        result = status_all()
    assert isinstance(result, dict)
    assert "mock" in result
    assert result["mock"]["running"] is True
    assert result["mock"]["installed"] is True


def test_status_all_isolates_broken_plugin():
    """Ошибка одного status() не должна скрывать остальные протоколы."""
    from hydra.plugins import registry

    healthy = MockPlugin()
    broken = MockPlugin()
    broken.meta = PluginMeta(name="broken", description="broken")
    broken.status = MagicMock(side_effect=RuntimeError("service unavailable"))

    with patch.object(registry, "_PLUGINS", [broken, healthy]):
        result = registry.status_all()

    assert result["broken"]["running"] is False
    assert result["broken"]["error"] == "service unavailable"
    assert result["mock"]["running"] is True


def test_config_fragment_empty():
    """Пустой фрагмент конфига."""
    frag = ConfigFragment()
    assert frag.inbounds == []
    assert frag.outbounds == []
    assert frag.route_rules == []


def test_collect_fragments_fails_closed_for_enabled_plugin():
    from hydra.plugins import registry
    plugin = MockPlugin()
    plugin.configure = MagicMock(side_effect=ValueError("invalid config"))
    state = AppState(protocols={"mock": PluginState(enabled=True)})

    with patch("hydra.plugins.registry._PLUGINS", [plugin]), \
         pytest.raises(registry.PluginConfigurationError, match="mock"):
        registry.collect_fragments(state)


def test_collect_fragments_keeps_endpoint_only_fragment():
    from hydra.plugins import registry
    plugin = MockPlugin()
    plugin.configure = MagicMock(
        return_value=ConfigFragment(endpoints=[{"type": "wireguard", "tag": "ep"}])
    )
    state = AppState(protocols={"mock": PluginState(enabled=True)})

    with patch("hydra.plugins.registry._PLUGINS", [plugin]):
        fragments = registry.collect_fragments(state)

    assert "mock" in fragments
    assert fragments["mock"].endpoints[0]["tag"] == "ep"


@pytest.mark.parametrize(
    "fragment",
    [
        ConfigFragment(inbounds=["not-an-object"]),
        ConfigFragment(nft_tproxy_ports=[0]),
        ConfigFragment(nft_tproxy_ports=[True]),
        ConfigFragment(nft_tproxy_ifaces=[""]),
    ],
)
def test_collect_fragments_rejects_invalid_plugin_output(fragment):
    from hydra.plugins import registry

    state = AppState(protocols={"mock": PluginState(enabled=True)})
    plugin = MockPlugin()

    with patch.object(registry, "_PLUGINS", [plugin]), \
         patch.object(plugin, "configure", return_value=fragment), \
         pytest.raises(registry.PluginConfigurationError, match="mock"):
        registry.collect_fragments(state)


def test_central_apply_preserves_wdtt_legacy_lifecycle():
    from hydra.plugins import registry
    plugin = MockPlugin()
    plugin.meta = PluginMeta(name="wdtt", description="legacy")
    plugin.apply = MagicMock(return_value=True)
    state = AppState(protocols={"wdtt": PluginState(enabled=True)})

    with patch("hydra.plugins.registry._PLUGINS", [plugin]):
        registry.apply_enabled(state)

    plugin.apply.assert_not_called()


def test_central_apply_rolls_back_previous_plugins_on_failure():
    from hydra.plugins import registry

    first = MockPlugin()
    first.meta = PluginMeta(name="first", description="first")
    first.snapshot = MagicMock(return_value={"old": 1})
    first.rollback = MagicMock(return_value=True)
    second = MockPlugin()
    second.meta = PluginMeta(name="second", description="second")
    second.snapshot = MagicMock(return_value={"old": 2})
    second.apply = MagicMock(side_effect=RuntimeError("boom"))
    second.rollback = MagicMock(return_value=True)
    state = AppState(protocols={"first": PluginState(enabled=True), "second": PluginState(enabled=True)})

    with patch("hydra.plugins.registry._PLUGINS", [first, second]), pytest.raises(RuntimeError):
        registry.apply_enabled(state)

    first.rollback.assert_called_once_with(state, {"old": 1})
    second.rollback.assert_called_once_with(state, {"old": 2})


def test_central_apply_rolls_back_current_plugin_on_false_result():
    from hydra.plugins import registry

    plugin = MockPlugin()
    plugin.meta = PluginMeta(name="broken", description="broken")
    plugin.snapshot = MagicMock(return_value={"old": True})
    plugin.apply = MagicMock(return_value=False)
    plugin.rollback = MagicMock(return_value=True)
    state = AppState(protocols={"broken": PluginState(enabled=True)})

    with patch("hydra.plugins.registry._PLUGINS", [plugin]), pytest.raises(RuntimeError):
        registry.apply_enabled(state)

    plugin.rollback.assert_called_once_with(state, {"old": True})


def test_central_apply_does_not_reuse_previous_snapshot_when_snapshot_fails():
    from hydra.plugins import registry

    first = MockPlugin()
    first.meta = PluginMeta(name="first", description="first")
    first.snapshot = MagicMock(return_value={"first": True})
    first.rollback = MagicMock(return_value=True)
    second = MockPlugin()
    second.meta = PluginMeta(name="second", description="second")
    second.snapshot = MagicMock(side_effect=RuntimeError("snapshot failed"))
    second.rollback = MagicMock(return_value=True)
    state = AppState(protocols={"first": PluginState(enabled=True), "second": PluginState(enabled=True)})

    with patch("hydra.plugins.registry._PLUGINS", [first, second]), pytest.raises(RuntimeError):
        registry.apply_enabled(state)

    first.rollback.assert_called_once_with(state, {"first": True})
    second.rollback.assert_not_called()


def test_health_all_reports_only_unhealthy_enabled_plugins():
    from hydra.plugins import registry

    healthy = MockPlugin()
    healthy.meta = PluginMeta(name="healthy", description="healthy")
    healthy.healthcheck = MagicMock(return_value=(True, ""))
    broken = MockPlugin()
    broken.meta = PluginMeta(name="broken", description="broken")
    broken.healthcheck = MagicMock(return_value=(False, "порт недоступен"))
    state = AppState(protocols={"healthy": PluginState(enabled=True), "broken": PluginState(enabled=True)})

    with patch("hydra.plugins.registry._PLUGINS", [healthy, broken]):
        assert registry.health_all(state) == {"broken": "порт недоступен"}
