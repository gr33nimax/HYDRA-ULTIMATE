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
    assert p.meta.version == "2.1.0"


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
    with patch.object(Fail2banPlugin, "_installed", return_value=False):
        s = p.status()
        assert s.installed is False


def test_traffic_returns_empty():
    p = Fail2banPlugin()
    assert p.traffic(_make_state()) == {}


def test_install_already_installed():
    p = Fail2banPlugin()
    with patch.object(Fail2banPlugin, "_installed", return_value=True), \
         patch.object(Fail2banPlugin, "_write_jails", return_value=True), \
         patch.object(Fail2banPlugin, "status", return_value=MagicMock(running=True)), \
         patch("hydra.plugins.fail2ban.plugin._run", return_value=MagicMock(returncode=0)):
        assert p.install() is True


def test_install_with_success():
    p = Fail2banPlugin()
    with patch.object(Fail2banPlugin, "_installed", side_effect=[False, True]), \
         patch.object(Fail2banPlugin, "_write_jails", return_value=True), \
         patch.object(Fail2banPlugin, "status", return_value=MagicMock(running=True)), \
         patch("hydra.plugins.fail2ban.plugin._run", return_value=MagicMock(returncode=0)) as mock_run:
        assert p.install() is True
        assert mock_run.call_count >= 2


def test_uninstall():
    p = Fail2banPlugin()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        assert p.uninstall() is True


def test_write_jails_with_whitelist():
    p = Fail2banPlugin()
    state = _make_state()
    state.protocols["fail2ban"].config["whitelist"] = ["192.168.1.100", "10.0.0.0/24"]
    
    written_files = {}
    def mock_atomic_write(path, text):
        written_files[path.name] = text

    with patch("pathlib.Path.mkdir"), \
         patch("hydra.plugins.fail2ban.plugin._atomic_write", side_effect=mock_atomic_write), \
         patch("hydra.plugins.fail2ban.plugin._run", return_value=MagicMock(returncode=0, stdout="", stderr="")), \
         patch("pathlib.Path.unlink"):
        assert p._write_jails(state) is True
        
    assert "00-hydra-defaults.local" in written_files
    content = written_files["00-hydra-defaults.local"]
    assert "ignoreip = 127.0.0.1/8 ::1 192.168.1.100 10.0.0.0/24" in content


def test_proxy_filters_only_match_authentication_failures():
    filters = Fail2banPlugin._filters()
    assert "unknown user password" in filters["hydra-anytls"]
    assert "authorization failed" in filters["hydra-trusttunnel"]
    assert '"status"\\s*:\\s*407' in filters["hydra-naive"]
    assert "401|403" not in filters["hydra-naive"]


def test_jail_overrides_persist_but_cannot_enable_disabled_protocol():
    p = Fail2banPlugin()
    state = _make_state()
    state.protocols["anytls"] = PluginState(enabled=True, port=443)
    state.protocols["fail2ban"].config["jails"] = {
        "hydra-anytls": {"bantime": "9000", "enabled": False},
        "hydra-trusttunnel": {"enabled": True},
    }
    jails = p.jail_options(state)
    assert jails["hydra-anytls"]["bantime"] == "9000"
    assert jails["hydra-anytls"]["enabled"] == "false"
    assert jails["hydra-trusttunnel"]["enabled"] == "false"


def test_invalid_generated_configuration_is_rolled_back(tmp_path):
    p = Fail2banPlugin()
    jail_dir = tmp_path / "jail.d"
    filter_dir = tmp_path / "filter.d"
    jail_dir.mkdir()
    filter_dir.mkdir()
    defaults = jail_dir / "00-hydra-defaults.local"
    defaults.write_text("original", encoding="utf-8")

    with patch("hydra.plugins.fail2ban.plugin.JAIL_DIR", jail_dir), \
         patch("hydra.plugins.fail2ban.plugin.FILTER_DIR", filter_dir), \
         patch("hydra.plugins.fail2ban.plugin.F2B_LOG", tmp_path / "fail2ban.log"), \
         patch("hydra.plugins.fail2ban.plugin._run", return_value=MagicMock(returncode=1, stdout="", stderr="bad config")):
        assert p._write_jails(_make_state()) is False

    assert defaults.read_text(encoding="utf-8") == "original"
    assert list(filter_dir.iterdir()) == []


def test_current_ssh_client_is_persisted_in_whitelist():
    state = _make_state()
    with patch.dict("os.environ", {"SSH_CONNECTION": "203.0.113.7 50000 192.0.2.1 22"}):
        Fail2banPlugin._remember_ssh_client(state)
    assert state.protocols["fail2ban"].config["whitelist"] == ["203.0.113.7"]


def test_portscan_rule_is_idempotent():
    with patch("shutil.which", return_value="/usr/sbin/iptables"), \
         patch("hydra.plugins.fail2ban.plugin._run", return_value=MagicMock(returncode=0)) as run:
        assert Fail2banPlugin._sync_portscan_rule(True) is True
    assert run.call_count == 1
    assert "-C" in run.call_args.args[0]
