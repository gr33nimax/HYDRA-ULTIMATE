"""tests/test_fail2ban_plugin.py — Тесты для Fail2banPlugin."""
from pathlib import Path
from unittest.mock import patch, MagicMock, ANY
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from hydra.plugins.fail2ban.plugin import Fail2banPlugin
from hydra.plugins.base import PluginCategory, ConfigFragment
from hydra.core.state import AppState, PluginState


def _make_state() -> AppState:
    state = AppState()
    state.protocols["fail2ban"] = PluginState(enabled=True)
    return state


def test_plugin_meta():
    p = Fail2banPlugin()
    assert p.meta.name == "fail2ban"
    assert p.meta.category == PluginCategory.SECURITY
    assert p.meta.version == "2.0.0"


def test_configure_returns_empty_fragment():
    p = Fail2banPlugin()
    frag = p.configure(_make_state())
    assert isinstance(frag, ConfigFragment)
    assert frag.inbounds == []
    assert frag.outbounds == []


def test_status_returns_plugin_status():
    p = Fail2banPlugin()
    with patch("pathlib.Path.exists", return_value=True), \
         patch("subprocess.run") as mock_run:
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="active"),                    # is-active
            MagicMock(returncode=0, stdout="Jail list: sshd, nginx"),    # client status
            MagicMock(returncode=0, stdout="  Currently banned: 3\n  Total banned: 5\n  Banned IP list: 1.1.1.1 2.2.2.2 3.3.3.3\n"),  # sshd
            MagicMock(returncode=0, stdout="  Currently banned: 1\n  Total banned: 2\n  Banned IP list: 4.4.4.4\n"),  # nginx
        ]
        s = p.status()
        assert s.installed is True
        assert s.running is True
        assert s.info.get("banned_ips") == 4  # 3 + 1


def test_status_not_installed():
    p = Fail2banPlugin()
    with patch("pathlib.Path.exists", return_value=False):
        s = p.status()
        assert s.installed is False


def test_traffic_returns_empty():
    p = Fail2banPlugin()
    assert p.traffic(_make_state()) == {}


def test_install_already_installed():
    p = Fail2banPlugin()
    with patch.object(Fail2banPlugin, "_installed", return_value=True):
        assert p.install() is True


def test_install_with_success():
    p = Fail2banPlugin()
    with patch("pathlib.Path.exists", side_effect=[False, True]), \
         patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        assert p.install() is True
        assert mock_run.call_count >= 2


def test_uninstall():
    p = Fail2banPlugin()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        assert p.uninstall() is True
