"""tests/test_olcrtc_plugin.py — Тесты для olcRTC plugin v2."""
import json
from pathlib import Path
from unittest.mock import patch, MagicMock
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from hydra.plugins.olcrtc.plugin import (
    OlcrtcPlugin, OLC_BIN, OLC_UNIT_FILE, OLC_LINKS_DIR, OLC_VAR_DIR,
    DEFAULT_CARRIER, DEFAULT_TRANSPORT, DEFAULT_SOCKS_START,
    UNIT_CONTENT,
)
from hydra.plugins.base import PluginCategory, ConfigFragment
from hydra.core.state import AppState, User, PluginState


def _make_state(users: list | None = None, server_ip: str = "1.2.3.4",
                carrier: str = "", transport: str = "") -> AppState:
    state = AppState()
    state.network.server_ip = server_ip
    cfg = {}
    if carrier:
        cfg["carrier"] = carrier
    if transport:
        cfg["transport"] = transport
    state.protocols["olcrtc"] = PluginState(enabled=True, port=0, config=cfg)
    if users:
        state.users = users
    return state


def _make_user(email: str, uuid: str = "u1", blocked: bool = False) -> User:
    return User(email=email, uuid=uuid, blocked=blocked)


def _user_with_creds(email: str = "a@x.com", uuid: str = "uuid-a") -> User:
    u = _make_user(email, uuid)
    u.credentials["olcrtc"] = {
        "carrier": "jitsi",
        "transport": "datachannel",
        "room_id": "https://meet.example.com/olc-room",
        "key": "ab" * 32,
        "socks_port": 8808,
        "link_name": "uuid-a",
    }
    return u


def test_plugin_meta():
    p = OlcrtcPlugin()
    assert p.meta.name == "olcrtc"
    assert p.meta.category == PluginCategory.TRANSPORT
    assert p.meta.needs_domain is False


def test_configure_returns_empty_fragment():
    p = OlcrtcPlugin()
    state = _make_state()
    frag = p.configure(state)
    assert isinstance(frag, ConfigFragment)
    assert frag.nft_tproxy_ports == []
    assert frag.inbounds == []
    assert frag.outbounds == []


def test_configure_uses_defaults():
    p = OlcrtcPlugin()
    state = AppState()
    p.configure(state)
    assert p._pending_cfg["carrier"] == DEFAULT_CARRIER
    assert p._pending_cfg["transport"] == DEFAULT_TRANSPORT


def test_configure_with_custom_config():
    p = OlcrtcPlugin()
    state = _make_state(carrier="telemost", transport="vp8channel")
    p.configure(state)
    assert p._pending_cfg["carrier"] == "telemost"
    assert p._pending_cfg["transport"] == "vp8channel"


def test_generate_client_config_returns_json():
    p = OlcrtcPlugin()
    user = _user_with_creds()
    state = _make_state()
    cfg = p.generate_client_config(user, state)
    parsed = json.loads(cfg)
    assert parsed["protocol"] == "olcrtc"
    assert "client_yaml" in parsed
    assert "mode: cnc" in parsed["client_yaml"]
    assert parsed["socks_port"] == 8808
    assert "instructions" in parsed


def test_generate_client_config_empty_without_creds():
    p = OlcrtcPlugin()
    user = _make_user("a@x.com", uuid="no-creds")
    state = _make_state()
    assert p.generate_client_config(user, state) == ""


def test_client_link_returns_yaml():
    p = OlcrtcPlugin()
    user = _user_with_creds()
    state = _make_state()
    yaml = p.client_link(user, state)
    assert "mode: cnc" in yaml
    assert "provider: jitsi" in yaml
    assert "port: 8808" in yaml


def test_client_link_empty_without_creds():
    p = OlcrtcPlugin()
    user = _make_user("a@x.com")
    state = _make_state()
    assert p.client_link(user, state) == ""


def test_sanitize_name():
    assert OlcrtcPlugin._sanitize_name("Hello-World_123") == "hello-world_123"
    assert OlcrtcPlugin._sanitize_name("  UPPER  ") == "upper"
    assert OlcrtcPlugin._sanitize_name("a" * 50) == "a" * 32


def test_server_yaml_contains_mode_srv():
    yaml = OlcrtcPlugin._server_yaml(
        "jitsi", "https://meet.example.com/room", "key123",
        "datachannel", "/var/lib/olcrtc/test/data",
    )
    assert "mode: srv" in yaml
    assert 'id: "https://meet.example.com/room"' in yaml
    assert 'key: "key123"' in yaml


def test_server_yaml_vp8channel():
    yaml = OlcrtcPlugin._server_yaml(
        "jitsi", "room", "k", "vp8channel", "/data",
    )
    assert "vp8:" in yaml
    assert "fps: 60" in yaml


def test_server_yaml_videochannel():
    yaml = OlcrtcPlugin._server_yaml(
        "jitsi", "room", "k", "videochannel", "/data",
    )
    assert "video:" in yaml
    assert "width: 1080" in yaml


def test_client_yaml_contains_mode_cnc():
    yaml = OlcrtcPlugin._client_yaml(
        "jitsi", "https://meet.example.com/room", "key123",
        "datachannel", 8808,
    )
    assert "mode: cnc" in yaml
    assert "port: 8808" in yaml
    assert 'host: "127.0.0.1"' in yaml


def test_on_user_add_creates_link():
    p = OlcrtcPlugin()
    user = _make_user("a@x.com", uuid="uuid-a")
    state = _make_state()

    with (
        patch.object(OlcrtcPlugin, "_installed", return_value=True),
        patch.object(Path, "mkdir"),
        patch.object(Path, "write_text"),
        patch.object(OlcrtcPlugin, "_ensure_unit_file"),
        patch("subprocess.run") as mock_run,
    ):
        p.on_user_add(user, state)

    assert "olcrtc" in user.credentials
    c = user.credentials["olcrtc"]
    assert c["carrier"] == "jitsi"
    assert c["transport"] == "datachannel"
    assert c["key"]
    assert c["socks_port"] == DEFAULT_SOCKS_START
    assert c["link_name"] == "uuid-a"
    enable_calls = [a for a in mock_run.call_args_list
                    if "enable" in str(a.args)]
    assert len(enable_calls) >= 1


def test_on_user_remove_deletes_link():
    p = OlcrtcPlugin()
    user = _make_user("a@x.com", uuid="uuid-a")
    user.credentials["olcrtc"] = {"link_name": "uuid-a"}

    with (
        patch("subprocess.run"),
        patch.object(Path, "unlink"),
        patch("shutil.rmtree"),
    ):
        p.on_user_remove(user, MagicMock())

    assert "olcrtc" not in user.credentials


def test_on_user_block_stops_service():
    p = OlcrtcPlugin()
    user = _make_user("a@x.com", uuid="uuid-a")
    user.credentials["olcrtc"] = {"link_name": "uuid-a"}

    with patch("subprocess.run") as mock_run:
        p.on_user_block(user, MagicMock())
        stop_calls = [a for a in mock_run.call_args_list
                      if "stop" in str(a.args)]
        assert len(stop_calls) >= 1


def test_on_user_block_noop_without_creds():
    p = OlcrtcPlugin()
    user = _make_user("a@x.com", uuid="uuid-a")
    # No olcrtc credentials — should not crash
    p.on_user_block(user, MagicMock())


def test_traffic_returns_empty():
    p = OlcrtcPlugin()
    assert p.traffic(_make_state()) == {}


def test_connected_clients_returns_list():
    p = OlcrtcPlugin()
    with (
        patch.object(OlcrtcPlugin, "_load_links", return_value={"lnk1": {}, "lnk2": {}}),
        patch("subprocess.run", return_value=MagicMock(
            stdout="active\n", text=True, returncode=0)),
    ):
        clients = p.connected_clients()
        assert len(clients) == 2
        assert clients[0]["name"] == "lnk1"
        assert clients[0]["active"] is True


def test_status_with_active_links():
    p = OlcrtcPlugin()
    with (
        patch.object(OlcrtcPlugin, "_installed", return_value=True),
        patch.object(OlcrtcPlugin, "_load_links", return_value={"lnk": {}}),
        patch("subprocess.run", return_value=MagicMock(
            stdout="active\n", text=True, returncode=0)),
    ):
        s = p.status()
        assert s.installed is True
        assert s.running is True
        assert s.info["links"] == 1
        assert s.info["active"] == 1


def test_status_not_installed():
    p = OlcrtcPlugin()
    s = p.status()
    assert s.installed is False
    assert s.running is False


def test_ensure_unit_file_writes_content():
    mock_path = MagicMock(spec=Path)
    with (
        patch("hydra.plugins.olcrtc.plugin.OLC_UNIT_FILE", mock_path),
        patch("subprocess.run"),
    ):
        p = OlcrtcPlugin()
        p._ensure_unit_file()
        written = mock_path.write_text.call_args[0][0]
        assert "ExecStart=/usr/local/bin/olcrtc" in written
        assert "olcrtc@%i" not in written  # unit is a template
        assert "Restart=on-failure" in written
        assert written == UNIT_CONTENT


def test_on_enable_starts_all_links():
    p = OlcrtcPlugin()
    with (
        patch.object(OlcrtcPlugin, "_load_links", return_value={"lnk1": {}, "lnk2": {}}),
        patch("subprocess.run") as mock_run,
    ):
        p.on_enable(MagicMock())
        enable_calls = [a for a in mock_run.call_args_list
                        if "enable" in str(a.args)]
        assert len(enable_calls) == 2


def test_on_disable_stops_all_links():
    p = OlcrtcPlugin()
    with (
        patch.object(OlcrtcPlugin, "_load_links", return_value={"lnk1": {}}),
        patch("subprocess.run") as mock_run,
    ):
        p.on_disable(MagicMock())
        disable_calls = [a for a in mock_run.call_args_list
                         if "disable" in str(a.args)]
        assert len(disable_calls) == 1


def test_apply_is_noop():
    p = OlcrtcPlugin()
    with patch.object(OlcrtcPlugin, "configure") as mock_cfg:
        result = p.apply(MagicMock())
        assert result is True
        assert not mock_cfg.called
