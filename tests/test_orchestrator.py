"""Тесты orchestrator: pipeline, fan-out, моки."""
from __future__ import annotations

from unittest.mock import patch, MagicMock
from contextlib import contextmanager
import pytest

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


def test_active_traffic_daemon_is_not_restarted_when_unit_is_unchanged(tmp_path):
    from hydra.core import orchestrator

    state = AppState()
    state.network.clash_api_enabled = True
    service_file = tmp_path / "hydra-traffic-daemon.service"
    completed = MagicMock(returncode=0)

    with patch.object(orchestrator, "TRAFFIC_DAEMON_SERVICE", service_file), \
         patch("hydra.core.orchestrator.subprocess.run", return_value=completed) as run:
        orchestrator._manage_traffic_daemon(state)
        run.reset_mock()
        orchestrator._manage_traffic_daemon(state)

    commands = [call.args[0] for call in run.call_args_list]
    assert ["systemctl", "restart", "hydra-traffic-daemon"] not in commands
    assert ["systemctl", "start", "hydra-traffic-daemon"] not in commands


def test_inactive_traffic_daemon_is_started_without_forced_restart(tmp_path):
    from hydra.core import orchestrator

    state = AppState()
    state.network.clash_api_enabled = True
    service_file = tmp_path / "hydra-traffic-daemon.service"

    with patch.object(orchestrator, "TRAFFIC_DAEMON_SERVICE", service_file), \
         patch("hydra.core.orchestrator.subprocess.run", return_value=MagicMock(returncode=0)):
        orchestrator._manage_traffic_daemon(state)

    def result_for(command, **kwargs):
        return MagicMock(returncode=1 if "is-active" in command else 0)

    with patch.object(orchestrator, "TRAFFIC_DAEMON_SERVICE", service_file), \
         patch("hydra.core.orchestrator.subprocess.run", side_effect=result_for) as run:
        orchestrator._manage_traffic_daemon(state)

    commands = [call.args[0] for call in run.call_args_list]
    assert ["systemctl", "start", "hydra-traffic-daemon"] in commands
    assert ["systemctl", "restart", "hydra-traffic-daemon"] not in commands


def test_reinstall_plugin_preserves_configuration_and_enabled_state():
    state, mock = _state_with_mock_transport()
    state.protocols["mock_transport"].port = 9443
    state.protocols["mock_transport"].config = {
        "domain": "vpn.example",
        "transport": "quic",
    }

    with (
        patch("hydra.core.orchestrator.registry.get", return_value=mock),
        patch("hydra.core.orchestrator.apply_config", return_value=True),
        patch("hydra.core.orchestrator.save_state"),
    ):
        from hydra.core import orchestrator
        result = orchestrator.reinstall_plugin(state, "mock_transport")

    protocol = state.protocols["mock_transport"]
    assert result is True
    assert protocol.installed is True
    assert protocol.enabled is True
    assert protocol.port == 9443
    assert protocol.config == {
        "domain": "vpn.example",
        "transport": "quic",
    }


def test_reinstall_plugin_restores_original_install_when_repair_fails():
    from hydra.core import orchestrator

    state = AppState(
        protocols={
            "mock": PluginState(
                enabled=True,
                installed=True,
                port=9443,
                config={"domain": "vpn.example"},
            )
        }
    )
    plugin = MagicMock()
    plugin.uninstall.return_value = True
    plugin.install.side_effect = [False, True]

    with patch("hydra.core.orchestrator.registry.get", return_value=plugin), \
         patch("hydra.core.orchestrator.apply_config", return_value=True), \
         patch("hydra.core.orchestrator.save_state"):
        assert orchestrator.reinstall_plugin(state, "mock") is False

    assert plugin.install.call_count == 2
    plugin.on_enable.assert_called_once_with(state)
    restored = state.protocols["mock"]
    assert restored.installed is True
    assert restored.enabled is True
    assert restored.port == 9443
    assert restored.config == {"domain": "vpn.example"}


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


def test_add_user_rolls_back_plugin_hooks_and_state_when_apply_fails():
    from hydra.core import orchestrator

    state, mock = _state_with_mock_transport()
    user = User(email="rollback@test", uuid="uuid-rollback")

    with (
        patch("hydra.core.orchestrator.registry.transports", return_value=[mock]),
        patch("hydra.core.orchestrator.apply_config", side_effect=[False, True]),
        patch("hydra.core.orchestrator.save_state"),
        pytest.raises(RuntimeError, match="user change"),
    ):
        orchestrator.add_user(state, user)

    assert not any(existing.email == user.email for existing in state.users)
    assert mock.added_users == [user.email]
    assert mock.removed_users == [user.email]


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


def test_disable_rolls_back_hook_and_state_on_apply_failure():
    from hydra.core import orchestrator

    state = AppState()
    state.protocols["mock"] = PluginState(enabled=True, installed=True)
    plugin = MagicMock()
    plugin.meta.name = "mock"

    with patch("hydra.core.orchestrator.registry.get", return_value=plugin), \
         patch("hydra.core.orchestrator.apply_config", side_effect=[False, True]) as apply, \
         patch("hydra.core.orchestrator.save_state"):
        result = orchestrator.disable(state, "mock")

    assert result is False
    assert state.protocols["mock"].enabled is True
    plugin.on_disable.assert_called_once_with(state)
    plugin.on_enable.assert_called_once_with(state)
    assert apply.call_count == 2


def test_apply_config_returns_false_when_caddy_rebuild_fails():
    from hydra.core import orchestrator

    state = AppState()
    fake_socket = MagicMock()
    fake_socket.__enter__.return_value.connect_ex.return_value = 1

    snapshot = MagicMock()
    plugin = MagicMock()
    plugin.meta.name = "mock"
    plugin_snapshot = {"old": True}
    with patch("hydra.core.orchestrator.registry.collect_fragments", return_value={}), \
         patch("hydra.core.orchestrator.registry.apply_enabled", return_value=[(plugin, plugin_snapshot)]), \
         patch("hydra.core.orchestrator.singbox.generate_config", return_value={}), \
         patch("hydra.core.orchestrator.singbox.write_config", return_value=True), \
         patch("hydra.core.orchestrator.singbox.reload", return_value=True), \
         patch("hydra.core.orchestrator.nft.apply_tproxy"), \
         patch("hydra.core.orchestrator.nft.snapshot_tproxy", return_value=snapshot), \
         patch("hydra.core.orchestrator.nft.restore_tproxy") as restore_nft, \
         patch("hydra.core.orchestrator.save_state"), \
         patch("hydra.core.sni_router.needs_mux", return_value=True), \
         patch("hydra.core.sni_router.rebuild", return_value=False), \
         patch("socket.socket", return_value=fake_socket):
        assert orchestrator.apply_config(state) is False
    restore_nft.assert_called_once_with(snapshot)
    plugin.rollback.assert_called_once_with(state, plugin_snapshot)


def test_apply_config_rejects_parallel_transaction():
    from hydra.core import orchestrator

    state = AppState()
    orchestrator._apply_lock.acquire()
    try:
        assert orchestrator.apply_config(state) is False
        assert orchestrator.last_apply_error() == "Применение конфигурации уже выполняется"
    finally:
        orchestrator._apply_lock.release()


def test_apply_config_rejects_other_process_transaction():
    from hydra.core import orchestrator

    @contextmanager
    def busy_guard():
        yield False

    with patch.object(orchestrator, "_process_apply_guard", busy_guard):
        assert orchestrator.apply_config(AppState()) is False
    assert "другом процессе" in orchestrator.last_apply_error()


def test_traffic_daemon_failure_fails_apply_and_rolls_back():
    from hydra.core import orchestrator

    state = AppState()
    state.network.clash_api_enabled = True
    plugin = MagicMock()
    plugin.meta.name = "mock"
    fake_socket = MagicMock()
    fake_socket.__enter__.return_value.connect_ex.return_value = 1
    with patch("hydra.core.orchestrator.registry.collect_fragments", return_value={}), \
         patch("hydra.core.orchestrator.registry.apply_enabled", return_value=[(plugin, {"old": True})]), \
         patch("hydra.core.orchestrator.singbox.generate_config", return_value={}), \
         patch("hydra.core.orchestrator.singbox.write_config", return_value=True), \
         patch("hydra.core.orchestrator.singbox.reload", return_value=True), \
         patch("hydra.core.orchestrator.nft.snapshot_tproxy", return_value=MagicMock()), \
         patch("hydra.core.orchestrator.nft.apply_tproxy"), \
         patch("hydra.core.orchestrator.nft.restore_tproxy"), \
         patch("hydra.core.orchestrator._manage_traffic_daemon", side_effect=RuntimeError("boom")), \
         patch("hydra.core.orchestrator.save_state"), \
         patch("hydra.core.sni_router.needs_mux", return_value=False), \
         patch("hydra.core.sni_router.stop"), \
         patch("socket.socket", return_value=fake_socket):
        assert orchestrator.apply_config(state) is False
    plugin.rollback.assert_called_once_with(state, {"old": True})
    assert "учёта трафика" in orchestrator.last_apply_error()


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


def test_install_plugin_removes_new_install_when_apply_fails():
    from hydra.core import orchestrator

    state = AppState(protocols={"mock": PluginState(enabled=True, installed=False)})
    plugin = MagicMock()
    plugin.install.return_value = True
    plugin.uninstall.return_value = True

    with patch("hydra.core.orchestrator.registry.get", return_value=plugin), \
         patch("hydra.core.orchestrator.apply_config", side_effect=[False, True]), \
         patch("hydra.core.orchestrator.save_state"):
        assert orchestrator.install_plugin(state, "mock") is False

    plugin.uninstall.assert_called_once_with()
    assert state.protocols["mock"].installed is False


def test_uninstall_plugin_reinstalls_and_restores_state_when_apply_fails():
    from hydra.core import orchestrator

    state = AppState(
        protocols={
            "mock": PluginState(
                enabled=True,
                installed=True,
                port=9443,
                config={"domain": "vpn.example"},
            )
        }
    )
    plugin = MagicMock()
    plugin.uninstall.return_value = True
    plugin.install.return_value = True

    with patch("hydra.core.orchestrator.registry.get", return_value=plugin), \
         patch("hydra.core.orchestrator.apply_config", side_effect=[False, True]), \
         patch("hydra.core.orchestrator.save_state"):
        assert orchestrator.uninstall_plugin(state, "mock") is False

    plugin.install.assert_called_once_with()
    plugin.on_enable.assert_called_once_with(state)
    restored = state.protocols["mock"]
    assert restored.installed is True
    assert restored.enabled is True
    assert restored.port == 9443
    assert restored.config == {"domain": "vpn.example"}
