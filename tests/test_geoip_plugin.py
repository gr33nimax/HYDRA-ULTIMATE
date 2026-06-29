"""tests/test_geoip_plugin.py — Тесты для GeoIPPlugin."""
from pathlib import Path
from unittest.mock import patch, MagicMock, ANY
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from hydra.plugins.geoip.plugin import GeoIPPlugin
from hydra.plugins.base import PluginCategory, ConfigFragment
from hydra.core.state import AppState, PluginState


def _make_state() -> AppState:
    state = AppState()
    state.protocols["geoip"] = PluginState(enabled=True)
    return state


def test_plugin_meta():
    p = GeoIPPlugin()
    assert p.meta.name == "geoip"
    assert p.meta.category == PluginCategory.SECURITY
    assert p.meta.version == "2.0.0"


def test_configure_returns_empty_fragment():
    p = GeoIPPlugin()
    frag = p.configure(_make_state())
    assert isinstance(frag, ConfigFragment)
    assert frag.inbounds == []


def test_status_returns_plugin_status():
    p = GeoIPPlugin()
    with patch.object(GeoIPPlugin, "_installed", return_value=True), \
         patch("subprocess.run") as mock_run, \
         patch.object(GeoIPPlugin, "_load_state", return_value={"enabled": True, "cidrs_v4": 5000}):
        mock_run.return_value = MagicMock(returncode=0, stdout="Members:\n1.1.1.0/24\n2.2.0.0/16\n")
        s = p.status()
        assert s.installed is True
        assert s.enabled is True


def test_status_not_installed():
    p = GeoIPPlugin()
    with patch.object(GeoIPPlugin, "_installed", return_value=False):
        s = p.status()
        assert s.installed is False


def test_traffic_returns_empty():
    p = GeoIPPlugin()
    assert p.traffic(_make_state()) == {}


def test_install_already_installed():
    p = GeoIPPlugin()
    with patch.object(GeoIPPlugin, "_installed", return_value=True):
        assert p.install() is True


def test_install_with_success():
    p = GeoIPPlugin()
    with patch.object(GeoIPPlugin, "_installed", side_effect=[False, True]), \
         patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        assert p.install() is True


def test_apply_fetches_and_adds_cidrs():
    p = GeoIPPlugin()
    with patch.object(GeoIPPlugin, "_ensure_sets") as mock_sets, \
         patch.object(GeoIPPlugin, "_ensure_iptables_rules") as mock_ipt, \
         patch.object(GeoIPPlugin, "_fetch_ru_subnets", return_value=(["1.0.0.0/8"], ["::/0"])), \
         patch.object(GeoIPPlugin, "_ipset_add_batch") as mock_add, \
         patch.object(GeoIPPlugin, "_save_state") as mock_save:
        assert p.apply(_make_state()) is True
        mock_add.assert_called_once_with(["1.0.0.0/8"], ["::/0"])


def test_on_enable():
    p = GeoIPPlugin()
    with patch.object(GeoIPPlugin, "_ensure_sets") as mock_sets, \
         patch.object(GeoIPPlugin, "_ensure_iptables_rules") as mock_ipt, \
         patch.object(GeoIPPlugin, "_fetch_ru_subnets", return_value=(["1.0.0.0/8"], [])), \
         patch.object(GeoIPPlugin, "_ipset_add_batch") as mock_add, \
         patch.object(GeoIPPlugin, "_save_state") as mock_save:
        p.on_enable(_make_state())
        mock_add.assert_called_once()


def test_on_disable():
    p = GeoIPPlugin()
    with patch.object(GeoIPPlugin, "_remove_rules") as mock_rm, \
         patch("pathlib.Path.unlink") as mock_unlink:
        p.on_disable(_make_state())
        mock_rm.assert_called_once()
