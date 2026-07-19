"""tests/test_honeypot_plugin.py — Тесты для HoneypotPlugin."""
from pathlib import Path
from unittest.mock import patch, MagicMock, ANY
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from hydra.plugins.honeypot.plugin import HoneypotPlugin, HONEYPOT_PORT, HONEYPOT_SCRIPT
import hydra.plugins.honeypot.plugin as honeypot_module
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
    assert p.meta.version == "2.1.0"


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


def test_install_checks_dependencies():
    p = HoneypotPlugin()
    with patch("shutil.which", return_value="/usr/bin/tool"):
        assert p.install() is True


def test_on_enable():
    p = HoneypotPlugin()
    with patch.object(HoneypotPlugin, "_load_state", return_value={"port": 9999, "whitelist": ["127.0.0.1"]}), \
         patch.object(HoneypotPlugin, "_install_service") as mock_install:
        p.on_enable(_make_state())
        mock_install.assert_called_once_with(9999, ["127.0.0.1"])


def test_on_disable():
    p = HoneypotPlugin()
    with patch.object(HoneypotPlugin, "_remove_service", return_value=True) as mock_rm:
        p.on_disable(_make_state())
        mock_rm.assert_called_once_with(close_port=True)


def test_on_enable_reports_service_diagnostics():
    p = HoneypotPlugin()
    p.last_error = "Address already in use"
    with patch.object(HoneypotPlugin, "_load_state", return_value={"port": 9999, "whitelist": []}), \
         patch.object(HoneypotPlugin, "_install_service", return_value=False):
        try:
            p.on_enable(_make_state())
        except RuntimeError as exc:
            assert "Address already in use" in str(exc)
        else:
            raise AssertionError("on_enable must fail when the service is not stable")


def test_whitelist_is_normalized_and_invalid_values_are_ignored():
    result = HoneypotPlugin._normalize_whitelist([
        "127.0.0.1/8", "192.168.1.42", "10.0.0.99/24", "bad-value",
    ])
    assert "127.0.0.0/8" in result
    assert "127.0.0.1/8" not in result
    assert "192.168.1.42/32" in result
    assert "10.0.0.0/24" in result
    assert "bad-value" not in result


def test_generated_script_records_only_verified_firewall_bans():
    p = HoneypotPlugin()
    with patch("pathlib.Path.mkdir"), \
         patch("pathlib.Path.write_text") as write_text, \
         patch("pathlib.Path.chmod"):
        p._write_script(9999, ["127.0.0.1/8"])
    script = write_text.call_args.args[0]
    compile(script, "hydra-honeypot.py", "exec")
    assert "ipaddress.ip_network(item, strict=False)" in script
    assert "if not ok:\n        return False" in script
    assert '"-C", "INPUT"' in script
    assert '"-I", "INPUT", "1"' in script


def test_apply_does_not_restart_healthy_honeypot_when_script_is_unchanged(tmp_path, monkeypatch):
    script = tmp_path / "hydra-honeypot.py"
    script.write_bytes(b"stable-script")
    monkeypatch.setattr(honeypot_module, "HONEYPOT_SCRIPT", script)
    plugin = HoneypotPlugin()
    with patch.object(plugin, "_load_state", return_value={"port": 9999, "whitelist": []}), \
         patch.object(plugin, "status", return_value=MagicMock(running=True)), \
         patch.object(plugin, "_write_script") as write_script, \
         patch.object(honeypot_module, "_run") as run:
        assert plugin.apply(_make_state()) is True
    write_script.assert_called_once_with(9999, [])
    run.assert_not_called()
