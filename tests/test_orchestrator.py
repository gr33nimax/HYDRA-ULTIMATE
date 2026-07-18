"""Тесты orchestrator: pipeline, fan-out, моки."""
from __future__ import annotations

from unittest.mock import patch, MagicMock

from hydra.core.state import AppState, NetworkConfig, PluginState, User
from hydra.plugins.base import ConfigFragment, PluginCategory, PluginMeta, PluginStatus
from hydra.plugins.base import BasePlugin


class _MockTransport(BasePlugin):
    meta = PluginMeta(
        name="mock_transport",
        description="Mock transport для тестов",
        category=PluginCategory.TRANSPORT,
    )

    def __init__(self):
        self.added_users: list[str] = []
        self.blocked_users: list[str] = []
        self.removed_users: list[str] = []

    def install(self) -> bool: return True
    def uninstall(self) -> bool: return True
    def status(self) -> PluginStatus:
        return PluginStatus(installed=True, enabled=True, running=True)

    def configure(self, state: AppState) -> ConfigFragment:
        return ConfigFragment(nft_tproxy_ports=[9999])

    def on_user_add(self, user, state) -> None:
        self.added_users.append(user.email)

    def on_user_block(self, user, state) -> None:
        self.blocked_users.append(user.email)

    def on_user_remove(self, user, state) -> None:
        self.removed_users.append(user.email)


def _state_with_mock_transport() -> tuple[AppState, _MockTransport]:
    state = AppState()
    state.network = NetworkConfig(tproxy_enabled=False)
    mock = _MockTransport()
    state.protocols["mock_transport"] = PluginState(enabled=True, installed=True)
    return state, mock


def test_apply_config_pipeline():
    state = AppState()
    state.network = NetworkConfig(tproxy_enabled=False)
    frag = ConfigFragment(nft_tproxy_ports=[1234])

    with (
        patch("hydra.core.orchestrator.registry.collect_fragments", return_value={"p": frag}),
        patch("hydra.core.orchestrator.singbox.generate_config", return_value={}) as mock_gen,
        patch("hydra.core.orchestrator.singbox.write_config", return_value=True) as mock_write,
        patch("hydra.core.orchestrator.singbox.reload", return_value=True) as mock_reload,
        patch("hydra.core.orchestrator.nft.apply_tproxy"),
        patch("hydra.core.orchestrator.save_state"),
    ):
        from hydra.core import orchestrator
        result = orchestrator.apply_config(state)

    assert result is True
    mock_write.assert_called_once()
    mock_reload.assert_called_once()


def test_apply_config_returns_false_on_write_error():
    state = AppState()
    state.network = NetworkConfig()

    with (
        patch("hydra.core.orchestrator.registry.collect_fragments", return_value={}),
        patch("hydra.core.orchestrator.singbox.generate_config", return_value={}),
        patch("hydra.core.orchestrator.singbox.write_config", return_value=False),
        patch("hydra.core.orchestrator.singbox.reload") as mock_reload,
        patch("hydra.core.orchestrator.nft.apply_tproxy"),
        patch("hydra.core.orchestrator.save_state"),
    ):
        from hydra.core import orchestrator
        result = orchestrator.apply_config(state)

    assert result is False
    mock_reload.assert_not_called()


def test_add_user_fanout():
    state, mock = _state_with_mock_transport()
    user = User(email="alice@test", uuid="uuid-1")

    with (
        patch("hydra.core.orchestrator.registry.transports", return_value=[mock]),
        patch("hydra.core.orchestrator.registry.collect_fragments", return_value={}),
        patch("hydra.core.orchestrator.singbox.generate_config", return_value={}),
        patch("hydra.core.orchestrator.singbox.write_config", return_value=True),
        patch("hydra.core.orchestrator.singbox.reload", return_value=True),
        patch("hydra.core.orchestrator.nft.apply_tproxy"),
        patch("hydra.core.orchestrator.save_state"),
    ):
        from hydra.core import orchestrator
        orchestrator.add_user(state, user)

    assert "alice@test" in mock.added_users
    assert user in state.users


def test_block_user_calls_on_user_block():
    state, mock = _state_with_mock_transport()
    user = User(email="bob@test", uuid="uuid-2")
    state.users.append(user)

    with (
        patch("hydra.core.orchestrator.registry.transports", return_value=[mock]),
        patch("hydra.core.orchestrator.registry.collect_fragments", return_value={}),
        patch("hydra.core.orchestrator.singbox.generate_config", return_value={}),
        patch("hydra.core.orchestrator.singbox.write_config", return_value=True),
        patch("hydra.core.orchestrator.singbox.reload", return_value=True),
        patch("hydra.core.orchestrator.nft.apply_tproxy"),
        patch("hydra.core.orchestrator.save_state"),
    ):
        from hydra.core import orchestrator
        orchestrator.block_user(state, "bob@test")

    assert "bob@test" in mock.blocked_users
    assert user.blocked is True


def test_remove_user_calls_on_user_remove():
    state, mock = _state_with_mock_transport()
    user = User(email="charlie@test", uuid="uuid-3")
    state.users.append(user)

    with (
        patch("hydra.core.orchestrator.registry.transports", return_value=[mock]),
        patch("hydra.core.orchestrator.registry.collect_fragments", return_value={}),
        patch("hydra.core.orchestrator.singbox.generate_config", return_value={}),
        patch("hydra.core.orchestrator.singbox.write_config", return_value=True),
        patch("hydra.core.orchestrator.singbox.reload", return_value=True),
        patch("hydra.core.orchestrator.nft.apply_tproxy"),
        patch("hydra.core.orchestrator.save_state"),
    ):
        from hydra.core import orchestrator
        orchestrator.remove_user(state, "charlie@test")

    assert "charlie@test" in mock.removed_users
    assert not any(u.email == "charlie@test" for u in state.users)


def test_add_user_skips_disabled_transport():
    state = AppState()
    state.network = NetworkConfig()
    mock = _MockTransport()
    user = User(email="dave@test", uuid="uuid-4")

    with (
        patch("hydra.core.orchestrator.registry.transports", return_value=[mock]),
        patch("hydra.core.orchestrator.registry.collect_fragments", return_value={}),
        patch("hydra.core.orchestrator.singbox.generate_config", return_value={}),
        patch("hydra.core.orchestrator.singbox.write_config", return_value=True),
        patch("hydra.core.orchestrator.singbox.reload", return_value=True),
        patch("hydra.core.orchestrator.nft.apply_tproxy"),
        patch("hydra.core.orchestrator.save_state"),
    ):
        from hydra.core import orchestrator
        orchestrator.add_user(state, user)

    assert mock.added_users == []


def test_unblock_user_reenables():
    state, mock = _state_with_mock_transport()
    user = User(email="bob@test", uuid="uuid-2")
    state.users.append(user)
    user.blocked = True

    with (
        patch("hydra.core.orchestrator.registry.transports", return_value=[mock]),
        patch("hydra.core.orchestrator.registry.collect_fragments", return_value={}),
        patch("hydra.core.orchestrator.singbox.generate_config", return_value={}),
        patch("hydra.core.orchestrator.singbox.write_config", return_value=True),
        patch("hydra.core.orchestrator.singbox.reload", return_value=True),
        patch("hydra.core.orchestrator.nft.apply_tproxy"),
        patch("hydra.core.orchestrator.save_state"),
    ):
        from hydra.core import orchestrator
        orchestrator.unblock_user(state, "bob@test")

    assert user.blocked is False
    assert "bob@test" in mock.added_users


def test_apply_config_calls_tproxy_when_enabled():
    state = AppState()
    state.network = NetworkConfig(tproxy_enabled=True, tproxy_port=1081)

    with (
        patch("hydra.core.orchestrator.registry.collect_fragments", return_value={}),
        patch("hydra.core.orchestrator.singbox.generate_config", return_value={}),
        patch("hydra.core.orchestrator.singbox.write_config", return_value=True),
        patch("hydra.core.orchestrator.singbox.reload", return_value=True),
        patch("hydra.core.orchestrator.nft.apply_tproxy") as mock_tproxy,
        patch("hydra.core.orchestrator.save_state"),
    ):
        from hydra.core import orchestrator
        orchestrator.apply_config(state)

    mock_tproxy.assert_called_once_with({}, 1081)


def test_enable_trusttunnel_rolls_back_plugin_state_on_apply_failure():
    from hydra.core import orchestrator

    state = AppState()
    state.protocols["trusttunnel"] = PluginState(
        enabled=False, installed=True, config={"domain": "old.example", "transport": "tcp"},
    )
    plugin = MagicMock()

    def mutate_on_enable(current_state):
        current_state.protocols["trusttunnel"].config["transport"] = "quic"

    plugin.on_enable.side_effect = mutate_on_enable

    with patch("hydra.core.orchestrator.registry.get", return_value=plugin), \
         patch("hydra.core.orchestrator.apply_config", side_effect=[False, True]) as apply, \
         patch("hydra.core.orchestrator.save_state"):
        result = orchestrator.enable(state, "trusttunnel")

    assert result is False
    restored = state.protocols["trusttunnel"]
    assert restored.enabled is False
    assert restored.config == {"domain": "old.example", "transport": "tcp"}
    assert apply.call_count == 2


def test_apply_config_returns_false_when_caddy_rebuild_fails():
    from hydra.core import orchestrator

    state = AppState()
    fake_socket = MagicMock()
    fake_socket.__enter__.return_value.connect_ex.return_value = 1

    with patch("hydra.core.orchestrator.registry.collect_fragments", return_value={}), \
         patch("hydra.core.orchestrator.singbox.generate_config", return_value={}), \
         patch("hydra.core.orchestrator.singbox.write_config", return_value=True), \
         patch("hydra.core.orchestrator.singbox.reload", return_value=True), \
         patch("hydra.core.orchestrator.nft.apply_tproxy"), \
         patch("hydra.core.orchestrator.save_state"), \
         patch("hydra.core.sni_router.needs_mux", return_value=True), \
         patch("hydra.core.sni_router.rebuild", return_value=False), \
         patch("socket.socket", return_value=fake_socket):
        assert orchestrator.apply_config(state) is False


def test_install_plugin_rolls_back_state_when_apply_fails():
    from hydra.core import orchestrator

    state = AppState()
    state.protocols["mock_transport"] = PluginState(enabled=True, installed=False)
    plugin = _MockTransport()

    with patch("hydra.core.orchestrator.registry.get", return_value=plugin), \
         patch("hydra.core.orchestrator.apply_config", side_effect=[False, True]) as apply, \
         patch("hydra.core.orchestrator.save_state") as save:
        result = orchestrator.install_plugin(state, "mock_transport")

    assert result is False
    assert state.protocols["mock_transport"].installed is False
    assert state.protocols["mock_transport"].enabled is True
    assert apply.call_count == 2
    assert save.call_count == 2
