"""tests/test_vkturn_plugin.py — Тесты для VK Turn Proxy plugin v2."""
import json
from pathlib import Path
from unittest.mock import patch, MagicMock
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from hydra.plugins.vkturn.plugin import VkTurnPlugin, SERVICE_FILE, BIN_PATH
from hydra.plugins.base import PluginCategory, ConfigFragment
from hydra.core.state import AppState, User, PluginState


def _make_state(users: list | None = None, server_ip: str = "1.2.3.4",
                listen_port: int = 56000, target_port: int = 51820) -> AppState:
    state = AppState()
    state.network.server_ip = server_ip
    state.protocols["vkturn"] = PluginState(
        enabled=True,
        port=listen_port,
        config={"listen_port": listen_port, "target_port": target_port},
    )
    if users:
        state.users = users
    return state


def _make_user(email: str, uuid: str = "u1", blocked: bool = False) -> User:
    return User(email=email, uuid=uuid, blocked=blocked)


def test_plugin_meta():
    p = VkTurnPlugin()
    assert p.meta.name == "vkturn"
    assert p.meta.category == PluginCategory.TRANSPORT
    assert p.meta.needs_domain is False


def test_configure_returns_fragment_with_port():
    """configure() возвращает ConfigFragment с nft_tproxy_ports=[56000]."""
    p = VkTurnPlugin()
    state = _make_state()
    frag = p.configure(state)

    assert isinstance(frag, ConfigFragment)
    assert frag.nft_tproxy_ports == [56000]
    assert frag.inbounds == []
    assert frag.outbounds == []


def test_configure_returns_defaults_without_state():
    """Без PluginState configure использует дефолтные порты."""
    p = VkTurnPlugin()
    state = AppState()
    state.network.server_ip = "1.2.3.4"
    frag = p.configure(state)

    assert frag.nft_tproxy_ports == [56000]
    assert p._pending_cfg["listen_port"] == 56000
    assert p._pending_cfg["target_port"] == 51820


def test_configure_with_custom_ports():
    """Кастомные порты из state.protocols."""
    p = VkTurnPlugin()
    state = _make_state(listen_port=56001, target_port=51920)
    p.configure(state)

    assert p._pending_cfg["listen_port"] == 56001
    assert p._pending_cfg["target_port"] == 51920
    assert p._pending_cfg["target_type"] == "wireguard"


def test_client_link_returns_freeturn_uri():
    """client_link() возвращает freeturn:// URI."""
    p = VkTurnPlugin()
    state = _make_state()
    user = _make_user("a@x.com")
    link = p.client_link(user, state)

    assert link.startswith("freeturn://")
    assert "1.2.3.4:56000" in link


def test_generate_client_config_returns_json():
    """generate_client_config возвращает JSON с инструкцией."""
    p = VkTurnPlugin()
    state = _make_state()
    user = _make_user("a@x.com")

    cfg = p.generate_client_config(user, state)
    parsed = json.loads(cfg)
    assert parsed["protocol"] == "vkturn"
    assert parsed["server"] == "1.2.3.4"
    assert parsed["port"] == 56000
    assert "FreeTurn" in parsed["instructions"]


def test_per_user_methods_are_noop():
    """on_user_* методы ничего не делают."""
    p = VkTurnPlugin()
    state = _make_state()
    user = _make_user("a@x.com")
    # Никаких исключений
    p.on_user_add(user, state)
    p.on_user_remove(user, state)
    p.on_user_block(user, state)


def test_status_returns_plugin_status():
    """status() возвращает PluginStatus без ошибок."""
    p = VkTurnPlugin()
    with patch.object(VkTurnPlugin, "_installed", return_value=True), \
         patch("hydra.plugins.vkturn.plugin.SERVICE_FILE") as mock_svc, \
         patch("subprocess.run") as mock_run:
        mock_svc.exists.return_value = True
        mock_run.return_value = MagicMock(stdout="active\n", returncode=0)
        s = p.status()
        assert s.installed is True
        assert s.port == 56000


def test_traffic_returns_empty():
    """traffic() для vkturn всегда пустой (не per-user)."""
    p = VkTurnPlugin()
    state = _make_state()
    assert p.traffic(state) == {}


def test_connected_clients_returns_empty():
    """connected_clients() для vkturn всегда пустой."""
    p = VkTurnPlugin()
    assert p.connected_clients() == []


def test_write_service_generates_correct_command():
    """_write_service создаёт корректный systemd unit."""
    mock_path = MagicMock(spec=Path)
    with patch("hydra.plugins.vkturn.plugin.SERVICE_FILE", mock_path):
        VkTurnPlugin._write_service(56000, 51820)
        written = mock_path.write_text.call_args[0][0]
        assert "-listen 0.0.0.0:56000" in written
        assert "-connect 127.0.0.1:51820" in written
        assert "ExecStart=" in written
        assert "Restart=always" in written
