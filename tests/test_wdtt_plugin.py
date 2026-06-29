"""tests/test_wdtt_plugin.py — Тесты для qWDTT plugin v2."""
import json
from pathlib import Path
from unittest.mock import patch, MagicMock, ANY
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from hydra.plugins.wdtt.plugin import (
    WdttPlugin, BIN_PATH, SERVICE_FILE, CONFIG_DIR, CONFIG_FILE, PASSWORDS_FILE,
    DEFAULT_DTLS_PORT, DEFAULT_WG_PORT, DEFAULT_WG_SUBNET, SYSTEM_PASSWORD,
)
from hydra.plugins.base import PluginCategory, ConfigFragment
from hydra.core.state import AppState, User, PluginState


def _make_state(users: list | None = None, server_ip: str = "1.2.3.4",
                dtls_port: int = DEFAULT_DTLS_PORT, wg_port: int = DEFAULT_WG_PORT) -> AppState:
    state = AppState()
    state.network.server_ip = server_ip
    state.protocols["wdtt"] = PluginState(
        enabled=True,
        port=dtls_port,
        config={"dtls_port": dtls_port, "wg_port": wg_port},
    )
    if users:
        state.users = users
    return state


def _make_user(email: str, uuid: str = "u1", blocked: bool = False) -> User:
    return User(email=email, uuid=uuid, blocked=blocked)


def test_plugin_meta():
    p = WdttPlugin()
    assert p.meta.name == "wdtt"
    assert p.meta.category == PluginCategory.TRANSPORT
    assert p.meta.needs_domain is False


def test_configure_returns_fragment_with_port():
    p = WdttPlugin()
    user = _make_user("a@x.com", uuid="uuid-a")
    state = _make_state([user])
    frag = p.configure(state)

    assert isinstance(frag, ConfigFragment)
    assert frag.nft_tproxy_ports == [DEFAULT_DTLS_PORT]
    assert frag.inbounds == []
    assert frag.outbounds == []


def test_configure_uses_defaults_without_state():
    p = WdttPlugin()
    state = AppState()
    state.network.server_ip = "1.2.3.4"
    frag = p.configure(state)
    assert frag.nft_tproxy_ports == [DEFAULT_DTLS_PORT]


def test_configure_with_custom_ports():
    p = WdttPlugin()
    state = _make_state(dtls_port=56001, wg_port=56002)
    p.configure(state)
    assert p._pending_cfg["dtls_port"] == 56001
    assert p._pending_cfg["wg_port"] == 56002


def test_configure_generates_passwords_from_users():
    p = WdttPlugin()
    users = [
        _make_user("a@x.com", uuid="uuid-a"),
        _make_user("b@x.com", uuid="uuid-b"),
    ]
    state = _make_state(users)
    p.configure(state)
    assert len(p._pending_cfg["passwords"]) == 2


def test_configure_skips_blocked_users():
    p = WdttPlugin()
    users = [
        _make_user("active@x.com", uuid="uuid-a"),
        _make_user("blocked@x.com", uuid="uuid-b", blocked=True),
    ]
    state = _make_state(users)
    p.configure(state)
    assert len(p._pending_cfg["passwords"]) == 1


def test_configure_uses_empty_passwords_without_users():
    p = WdttPlugin()
    state = _make_state([])
    p.configure(state)
    assert p._pending_cfg["passwords"] == {}


def test_apply_writes_configs_and_restarts():
    p = WdttPlugin()
    users = [_make_user("a@x.com", uuid="uuid-a")]
    state = _make_state(users)
    p.configure(state)

    with (
        patch.object(Path, "mkdir"),
        patch.object(Path, "write_text") as mock_write,
        patch.object(Path, "chmod"),
        patch.object(WdttPlugin, "_install_service") as mock_svc,
        patch("subprocess.run") as mock_run,
    ):
        result = p.apply(state)

    assert result is True

    write_calls = [c for c in mock_write.call_args_list if c.args]
    passwords_text = write_calls[0].args[0]
    pw_data = json.loads(passwords_text)
    assert pw_data["main_password"] == SYSTEM_PASSWORD
    assert len(pw_data["passwords"]) == 1
    assert pw_data["admin_id"] == ""
    assert pw_data["bot_token"] == ""

    config_text = write_calls[1].args[0]
    cfg_data = json.loads(config_text)
    assert cfg_data["dtls_port"] == DEFAULT_DTLS_PORT
    assert cfg_data["wg_port"] == DEFAULT_WG_PORT

    assert mock_svc.called
    reload_calls = [c for c in mock_run.call_args_list
                    if "reload-or-restart" in str(c.args)]
    assert len(reload_calls) >= 1


def test_apply_returns_false_without_pending():
    p = WdttPlugin()
    assert p.apply(_make_state()) is False


def test_on_user_add_sets_credentials():
    p = WdttPlugin()
    user = _make_user("a@x.com", uuid="uuid-a")
    state = _make_state([user])

    with patch.object(p, "apply", return_value=True):
        p.on_user_add(user, state)

    assert "wdtt" in user.credentials
    assert "password" in user.credentials["wdtt"]
    assert len(user.credentials["wdtt"]["password"]) > 8


def test_on_user_remove_calls_configure_apply():
    p = WdttPlugin()
    state = _make_state([])
    with patch.object(p, "configure") as mock_cfg, \
         patch.object(p, "apply", return_value=True):
        p.on_user_remove(_make_user("a@x.com"), state)
        assert mock_cfg.called


def test_on_user_block_calls_configure_apply():
    p = WdttPlugin()
    state = _make_state([])
    with patch.object(p, "configure") as mock_cfg, \
         patch.object(p, "apply", return_value=True):
        p.on_user_block(_make_user("a@x.com"), state)
        assert mock_cfg.called


def test_deterministic_password():
    uuid = "same-uuid-123"
    p1 = WdttPlugin._derive_password(uuid)
    p2 = WdttPlugin._derive_password(uuid)
    assert p1 == p2

    p3 = WdttPlugin._derive_password("different-uuid")
    assert p1 != p3


def test_client_link_returns_qwdtt_uri():
    p = WdttPlugin()
    state = _make_state()
    user = _make_user("a@x.com", uuid="uuid-a")
    link = p.client_link(user, state)

    assert link.startswith("qwdtt://config?name=")
    assert "1.2.3.4:56000" in link
    assert "hashes=VK_HASH" in link
    assert "pass=" in link
    assert "workers=16" in link
    assert "port=9000" in link


def test_client_link_with_custom_port():
    p = WdttPlugin()
    state = _make_state(dtls_port=56001)
    user = _make_user("a@x.com", uuid="uuid-a")
    link = p.client_link(user, state)
    assert "1.2.3.4:56001" in link


def test_generate_client_config_returns_json():
    p = WdttPlugin()
    state = _make_state()
    user = _make_user("a@x.com", uuid="uuid-a")
    cfg = p.generate_client_config(user, state)
    parsed = json.loads(cfg)
    assert parsed["protocol"] == "wdtt"
    assert parsed["link"].startswith("qwdtt://")


def test_status_returns_plugin_status():
    p = WdttPlugin()
    with (
        patch.object(WdttPlugin, "_installed", return_value=True),
        patch("hydra.plugins.wdtt.plugin.CONFIG_FILE") as mock_cfg,
        patch("subprocess.run") as mock_run,
    ):
        mock_cfg.exists.return_value = True
        mock_cfg.read_text.return_value = json.dumps({"dtls_port": 56000})
        mock_run.return_value = MagicMock(stdout="active\n", returncode=0)
        s = p.status()
        assert s.installed is True
        assert s.running is True
        assert s.port == 56000


def test_status_returns_not_installed():
    p = WdttPlugin()
    s = p.status()
    assert s.installed is False


def test_traffic_returns_empty():
    p = WdttPlugin()
    state = _make_state()
    assert p.traffic(state) == {}


def test_connected_clients_returns_empty():
    p = WdttPlugin()
    assert p.connected_clients() == []


def test_install_service_generates_correct_unit():
    mock_path = MagicMock(spec=Path)
    with patch("hydra.plugins.wdtt.plugin.SERVICE_FILE", mock_path), \
         patch("subprocess.run"):
        WdttPlugin._install_service(DEFAULT_DTLS_PORT, DEFAULT_WG_PORT)
        written = mock_path.write_text.call_args[0][0]
        assert f"-listen 0.0.0.0:{DEFAULT_DTLS_PORT}" in written
        assert f"-wg-port {DEFAULT_WG_PORT}" in written
        assert f"-password {SYSTEM_PASSWORD}" in written
        assert f"-config-dir {CONFIG_DIR}" in written
        assert "ExecStart=" in written
        assert "Restart=always" in written


def test_install_service_with_custom_ports():
    mock_path = MagicMock(spec=Path)
    with patch("hydra.plugins.wdtt.plugin.SERVICE_FILE", mock_path), \
         patch("subprocess.run"):
        WdttPlugin._install_service(56001, 56002)
        written = mock_path.write_text.call_args[0][0]
        assert "-listen 0.0.0.0:56001" in written
        assert "-wg-port 56002" in written


def test_on_enable_starts_service_if_inactive():
    p = WdttPlugin()
    state = _make_state([_make_user("a@x.com", uuid="uuid-a")])
    with (
        patch.object(p, "configure"),
        patch.object(p, "apply"),
        patch("subprocess.run", return_value=MagicMock(stdout="inactive\n",
                                                        text=True, returncode=0)) as mock_run,
    ):
        p.on_enable(state)
        enable_calls = [c for c in mock_run.call_args_list
                        if "enable" in str(c.args)]
        assert len(enable_calls) >= 1


def test_on_disable_stops_service():
    p = WdttPlugin()
    with patch("subprocess.run") as mock_run:
        p.on_disable(_make_state())
        stop_calls = [c for c in mock_run.call_args_list if "stop" in str(c.args)]
        assert len(stop_calls) >= 1


def test_uninstall_removes_service_and_binary():
    p = WdttPlugin()
    mock_svc = MagicMock(spec=Path)
    mock_svc.exists.return_value = True
    mock_bin = MagicMock(spec=Path)
    mock_bin.exists.return_value = True
    mock_cfg_dir = MagicMock(spec=Path)
    mock_cfg_dir.exists.return_value = True
    with (
        patch("subprocess.run") as mock_run,
        patch("hydra.plugins.wdtt.plugin.SERVICE_FILE", mock_svc),
        patch("hydra.plugins.wdtt.plugin.BIN_PATH", mock_bin),
        patch("hydra.plugins.wdtt.plugin.CONFIG_DIR", mock_cfg_dir),
        patch("shutil.rmtree") as mock_rmtree,
    ):
        result = p.uninstall()
        assert result is True
        assert mock_svc.unlink.called
        assert mock_bin.unlink.called
        assert mock_rmtree.called
