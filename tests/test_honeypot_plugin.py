"""tests/test_honeypot_plugin.py — Тесты для HoneypotPlugin."""
from pathlib import Path
from unittest.mock import patch, MagicMock, ANY
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from hydra.plugins.honeypot.plugin import HoneypotPlugin, HONEYPOT_PORT, HONEYPOT_SCRIPT
from hydra.plugins.base import PluginCategory, ConfigFragment
from hydra.core.state import AppState, PluginState


def _make_state() -> AppState:
    state = AppState()
    state.protocols["honeypot"] = PluginState(enabled=True)
    return state


def test_plugin_meta():
    p = HoneypotPlugin()
    assert p.meta.name == "honeypot"
    assert p.meta.category == PluginCategory.SECURITY
    assert p.meta.version == "2.0.0"


def test_configure_returns_empty_fragment():
    p = HoneypotPlugin()
    frag = p.configure(_make_state())
    assert isinstance(frag, ConfigFragment)
    assert frag.inbounds == []


def test_status_returns_plugin_status():
    p = HoneypotPlugin()
    with patch("subprocess.run") as mock_run, \
         patch.object(HoneypotPlugin, "_load_state", return_value={"banned": {"1.1.1.1": {}}, "port": 9999}):
        mock_run.return_value = MagicMock(returncode=0, stdout="active")
        s = p.status()
        assert s.running is True
        assert s.info.get("banned_ips") == 1


def test_status_not_installed():
    p = HoneypotPlugin()
    with patch("pathlib.Path.exists", return_value=False), \
         patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1, stdout="inactive")
        s = p.status()
        assert s.installed is False


def test_traffic_returns_empty():
    p = HoneypotPlugin()
    assert p.traffic(_make_state()) == {}


def test_install_always_true():
    p = HoneypotPlugin()
    assert p.install() is True


def test_on_enable():
    p = HoneypotPlugin()
    with patch.object(HoneypotPlugin, "_load_state", return_value={"port": 9999, "whitelist": ["127.0.0.1"]}), \
         patch.object(HoneypotPlugin, "_install_service") as mock_install:
        p.on_enable(_make_state())
        mock_install.assert_called_once_with(9999, ["127.0.0.1"])


def test_on_disable():
    p = HoneypotPlugin()
    with patch.object(HoneypotPlugin, "_remove_service") as mock_rm:
        p.on_disable(_make_state())
        mock_rm.assert_called_once()
