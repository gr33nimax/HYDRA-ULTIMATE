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

    assert fragments["mock"].endpoints[0]["tag"] == "ep"


def test_central_apply_preserves_wdtt_legacy_lifecycle():
    from hydra.plugins import registry
    plugin = MockPlugin()
    plugin.meta = PluginMeta(name="wdtt", description="legacy")
    plugin.apply = MagicMock(return_value=True)
    state = AppState(protocols={"wdtt": PluginState(enabled=True)})

    with patch("hydra.plugins.registry._PLUGINS", [plugin]):
        registry.apply_enabled(state)

    plugin.apply.assert_not_called()
