"""tests/test_porthopping_plugin.py — Тесты для Port Hopping plugin v2."""
from pathlib import Path
from unittest.mock import patch, MagicMock, ANY
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from hydra.plugins.porthopping.plugin import PortHoppingPlugin, NFT_TABLE
from hydra.plugins.base import PluginCategory, ConfigFragment
from hydra.core.state import AppState, PluginState


def _make_state(enabled: bool = True) -> AppState:
    state = AppState()
    state.protocols["porthopping"] = PluginState(
        enabled=True, config={
            "enabled": enabled,
            "range_start": 10000,
            "range_end": 20000,
            "real_port": 443,
            "proto": "tcp",
        },
    )
    return state


def test_plugin_meta():
    p = PortHoppingPlugin()
    assert p.meta.name == "porthopping"
    assert p.meta.category == PluginCategory.ENHANCEMENT


def test_configure_returns_empty_fragment():
    """configure возвращает пустой ConfigFragment (нет вклада в sing-box)."""
    p = PortHoppingPlugin()
    frag = p.configure(_make_state())
    assert isinstance(frag, ConfigFragment)
    assert frag.nft_tproxy_ports == []
    assert frag.inbounds == []
    assert frag.outbounds == []
    assert frag.route_rules == []


def test_apply_calls_nft_when_enabled():
    """apply вызывает nft -f - при включённом плагине."""
    p = PortHoppingPlugin()
    state = _make_state(enabled=True)

    with patch.object(p, "_clear_rules") as mock_clear, \
         patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        result = p.apply(state)

    assert result is True
    mock_clear.assert_called_once()
    assert mock_run.call_count >= 2


def test_apply_clears_rules_when_disabled():
    """apply очищает правила при отключённом плагине."""
    p = PortHoppingPlugin()
    state = _make_state(enabled=False)

    with patch.object(p, "_clear_rules") as mock_clear:
        result = p.apply(state)

    assert result is True
    mock_clear.assert_called_once()


def test_status_returns_plugin_status():
    """status возвращает PluginStatus без ошибок."""
    p = PortHoppingPlugin()
    with patch.object(PortHoppingPlugin, "_nft_available", return_value=True), \
         patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0, stdout=f"table inet {NFT_TABLE} {{ ... }}",
        )
        s = p.status()
        assert s.installed is True
        assert s.running is True


def test_install_checks_nft_availability():
    """install возвращает True если nft доступен, иначе False."""
    p = PortHoppingPlugin()
    with patch.object(PortHoppingPlugin, "_nft_available", return_value=True):
        assert p.install() is True
    with patch.object(PortHoppingPlugin, "_nft_available", return_value=False):
        assert p.install() is False


def test_uninstall_clears_rules():
    """uninstall очищает nftables правила."""
    p = PortHoppingPlugin()
    with patch.object(p, "_clear_rules") as mock_clear:
        assert p.uninstall() is True
        mock_clear.assert_called_once()


def test_clear_rules_calls_nft_delete():
    """_clear_rules пытается удалить nft-таблицу."""
    p = PortHoppingPlugin()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        p._clear_rules()
        mock_run.assert_called_once_with(
            ["nft", "delete", "table", "inet", NFT_TABLE],
            capture_output=True,
        )


def test_traffic_returns_empty():
    """traffic возвращает пустой словарь."""
    p = PortHoppingPlugin()
    assert p.traffic(_make_state()) == {}
