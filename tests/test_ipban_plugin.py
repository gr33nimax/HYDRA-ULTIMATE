"""tests/test_ipban_plugin.py — Тесты для IPBanPlugin."""
from pathlib import Path
from unittest.mock import patch, MagicMock, ANY
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from hydra.plugins.ipban.plugin import IPBanPlugin
from hydra.plugins.base import PluginCategory, ConfigFragment
from hydra.core.state import AppState, PluginState


def _make_state() -> AppState:
    state = AppState()
    state.protocols["ipban"] = PluginState(enabled=True)
    return state


def test_plugin_meta():
    p = IPBanPlugin()
    assert p.meta.name == "ipban"
    assert p.meta.category == PluginCategory.SECURITY
    assert p.meta.version == "2.1.0"


def test_configure_returns_empty_fragment():
    p = IPBanPlugin()
    frag = p.configure(_make_state())
    assert isinstance(frag, ConfigFragment)
    assert frag.inbounds == []


def test_ban_ip_single():
    p = IPBanPlugin()
    with patch.object(IPBanPlugin, "_ensure_sets") as mock_s, \
         patch.object(IPBanPlugin, "_ensure_iptables_rules") as mock_i, \
         patch("subprocess.run") as mock_run, \
         patch.object(IPBanPlugin, "_state_add_entry") as mock_add:
        mock_run.return_value = MagicMock(returncode=0)
        result = p.ban_ip("1.2.3.4")
        assert result is True
        mock_add.assert_called_once_with("1.2.3.4", ["1.2.3.4/32"], "ip", "")


def test_ban_ip_cidr():
    p = IPBanPlugin()
    with patch.object(IPBanPlugin, "_ensure_sets") as mock_s, \
         patch.object(IPBanPlugin, "_ensure_iptables_rules") as mock_i, \
         patch("subprocess.run") as mock_run, \
         patch.object(IPBanPlugin, "_state_add_entry") as mock_add:
        mock_run.return_value = MagicMock(returncode=0)
        result = p.ban_ip("10.0.0.0/8")
        assert result is True
        mock_add.assert_called_once_with("10.0.0.0/8", ["10.0.0.0/8"], "cidr", "")


def test_unban_ip_not_found():
    p = IPBanPlugin()
    with patch.object(IPBanPlugin, "_load_state", return_value={"entries": []}):
        assert p.unban_ip("nonexistent") is False


def test_unban_ip_success():
    p = IPBanPlugin()
    with patch.object(IPBanPlugin, "_load_state", return_value={
        "entries": [{"display": "1.2.3.4", "cidrs": ["1.2.3.4/32"], "kind": "ip"}]
    }), patch.object(IPBanPlugin, "_installed", return_value=True), \
         patch("subprocess.run") as mock_run, \
         patch.object(IPBanPlugin, "_save_state") as mock_save:
        mock_run.return_value = MagicMock(returncode=0)
        assert p.unban_ip("1.2.3.4") is True


def test_list_banned():
    p = IPBanPlugin()
    with patch.object(IPBanPlugin, "_load_state", return_value={
        "entries": [{"display": "1.2.3.4", "kind": "ip"}]
    }):
        result = p.list_banned()
        assert len(result) == 1
        assert result[0]["display"] == "1.2.3.4"


def test_status():
    p = IPBanPlugin()
    with patch.object(IPBanPlugin, "_installed", return_value=True), \
         patch.object(IPBanPlugin, "_load_state", return_value={"entries": [{"display": "1.2.3.4"}]}), \
         patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="Members:\n1.2.3.4/32\n")
        s = p.status()
        assert s.installed is True
        assert s.info.get("entries") == 1


def test_traffic_returns_empty():
    p = IPBanPlugin()
    assert p.traffic(_make_state()) == {}


def test_iptables_rules_are_exact_ordered_and_family_specific():
    p = IPBanPlugin()
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        if "-C" in command and len([c for c in calls if "-C" in c]) <= 2:
            return MagicMock(returncode=1)
        return MagicMock(returncode=0)

    with patch("hydra.plugins.ipban.plugin._run", side_effect=fake_run):
        assert p._ensure_iptables_rules() is True

    inserts = [call for call in calls if "-I" in call]
    assert inserts[0][:5] == ["iptables", "-I", "INPUT", "1", "-m"]
    assert inserts[1][:5] == ["ip6tables", "-I", "INPUT", "1", "-m"]
    assert all("hydra-ipban" in call for call in inserts)
    assert not any(call[0] == "iptables" and "hydra_manual_ban6" in call for call in calls)


def test_failed_ipset_add_is_not_saved():
    p = IPBanPlugin()
    with patch.object(IPBanPlugin, "_ensure_sets", return_value=True), \
         patch.object(IPBanPlugin, "_ensure_iptables_rules", return_value=True), \
         patch("hydra.plugins.ipban.plugin._run", return_value=MagicMock(returncode=1, stderr=b"full")), \
         patch.object(IPBanPlugin, "_state_add_entry") as save:
        assert p.ban_ip("1.2.3.4") is False
    save.assert_not_called()


def test_unban_keeps_shared_cidr_until_last_reference():
    p = IPBanPlugin()
    state = {
        "entries": [
            {"display": "AS1", "cidrs": ["1.2.3.0/24"]},
            {"display": "1.2.3.0/24", "cidrs": ["1.2.3.0/24"]},
        ]
    }
    with patch.object(IPBanPlugin, "_installed", return_value=True), \
         patch.object(IPBanPlugin, "_load_state", return_value=state), \
         patch.object(IPBanPlugin, "_save_state") as save, \
         patch("hydra.plugins.ipban.plugin._run") as run:
        assert p.unban_ip("AS1") is True
    run.assert_not_called()
    assert save.call_args.args[0]["entries"][0]["display"] == "1.2.3.0/24"
