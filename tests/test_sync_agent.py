from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

from hydra.core import orchestrator
from hydra.core.state import AppState, User, get_protocol
from hydra.plugins import registry
from hydra.plugins.warp.observation import external_rules_update_due
from hydra.services.protocols import ProtocolService
from hydra.services import sync_agent
from hydra.services.plugin_actions import PluginActionService
from hydra.services.plugin_queries import PluginQueryService
from hydra.services.sync_ports import default_sync_operations


def _state_updater(state: AppState):
    def update(mutator):
        result = mutator(state)
        return state, result
    return update


def _run_sync(*, traffic_check=None, **kwargs):
    protocols = ProtocolService(orchestrator, registry)
    operations = default_sync_operations(
        protocols=protocols,
        apply_config=lambda state: orchestrator.apply_config(state),
        check_traffic_limits=traffic_check or (lambda state: []),
        plugin_actions=PluginActionService(get_plugin=protocols.get),
        plugin_queries=PluginQueryService(get_plugin=protocols.get),
    )
    return sync_agent.run_sync(operations=operations, **kwargs)


def test_failed_config_apply_is_retried_on_next_sync():
    user = User(email="alice@example.com", uuid="token")
    state = AppState(users=[user])
    warp_status = MagicMock(enabled=False)
    check_limits = MagicMock(side_effect=[[user.email], []])

    with patch.object(sync_agent, "update_state", side_effect=_state_updater(state)), \
         patch.object(sync_agent, "_log"), \
         patch("hydra.core.orchestrator.apply_config", side_effect=[False, True]) as apply, \
         patch("hydra.plugins.warp.plugin.WarpPlugin.status", return_value=warp_status):
        _run_sync(traffic_check=check_limits)
        assert user.blocked is True
        assert state.install["sync_config_pending"] is True

        _run_sync(traffic_check=check_limits)

    assert "sync_config_pending" not in state.install
    assert apply.call_count == 2


def test_expired_user_is_blocked_and_config_is_applied():
    user = User(
        email="expired@example.com",
        uuid="token",
        expiry_date="2000-01-01T00:00:00Z",
    )
    state = AppState(users=[user])
    warp_status = MagicMock(enabled=False)

    with patch.object(sync_agent, "update_state", side_effect=_state_updater(state)), \
         patch.object(sync_agent, "_log"), \
         patch("hydra.core.orchestrator.apply_config", return_value=True) as apply, \
         patch("hydra.plugins.warp.plugin.WarpPlugin.status", return_value=warp_status):
        _run_sync()

    assert user.blocked is True
    assert "sync_config_pending" not in state.install
    apply.assert_called_once()


def test_failed_warp_apply_is_queued_for_retry():
    state = AppState()
    get_protocol(state, "warp").enabled = True

    with patch.object(sync_agent, "update_state", side_effect=_state_updater(state)), \
         patch.object(sync_agent, "_log"), \
         patch("hydra.core.orchestrator.apply_config", return_value=False), \
         patch("hydra.plugins.warp.plugin.WarpPlugin.update_external_rules", return_value=(True, "ok")):
        _run_sync()

    assert state.install["sync_config_pending"] is True


def test_pending_config_is_retried_when_limit_checks_are_disabled():
    state = AppState()
    state.install["sync_limits_enabled"] = False
    state.install["sync_warp_enabled"] = False
    state.install["sync_updates_enabled"] = False
    state.install["sync_config_pending"] = True
    check_limits = MagicMock()

    with patch("hydra.core.state.load_state", return_value=state), \
         patch.object(sync_agent, "update_state", side_effect=_state_updater(state)), \
         patch.object(sync_agent, "_log"), \
         patch("hydra.core.orchestrator.apply_config", return_value=True) as apply:
        ok, _ = _run_sync(traffic_check=check_limits)

    assert ok is True
    assert "sync_config_pending" not in state.install
    check_limits.assert_not_called()
    apply.assert_called_once_with(state)


def test_manual_full_check_ignores_automatic_check_toggles():
    state = AppState()
    state.install.update({
        "sync_limits_enabled": False,
        "sync_warp_enabled": False,
        "sync_updates_enabled": False,
    })
    get_protocol(state, "warp").enabled = True
    check_limits = MagicMock(return_value=[])

    with patch("hydra.core.state.load_state", return_value=state), \
         patch.object(sync_agent, "update_state", side_effect=_state_updater(state)), \
         patch.object(sync_agent, "_log"), \
         patch("hydra.plugins.warp.plugin.WarpPlugin.update_external_rules", return_value=(True, "ok")) as warp_update, \
         patch("hydra.core.orchestrator.apply_config", return_value=True), \
         patch("hydra.utils.downloader.latest_release", return_value="v1.13.11-extended-2.1.0") as latest, \
         patch("hydra.core.singbox.get_version", return_value="1.13.11-extended-2.1.0"):
        ok, _ = _run_sync(
            traffic_check=check_limits,
            force_all_checks=True,
            force_update_check=True,
        )

    assert ok is True
    check_limits.assert_called_once_with(state)
    warp_update.assert_called_once()
    latest.assert_called_once()


def test_manual_run_reports_update_check_failure():
    state = AppState()
    state.install["sync_warp_enabled"] = False

    with patch("hydra.core.state.load_state", return_value=state), \
         patch.object(sync_agent, "update_state", side_effect=_state_updater(state)), \
         patch.object(sync_agent, "_log"), \
         patch("hydra.utils.downloader.latest_release", return_value="unknown"):
        ok, message = _run_sync(force_update_check=True)

    assert ok is False
    assert "Sing-Box" in message


def test_stale_warp_cache_is_refreshed(tmp_path):
    cache = tmp_path / "warp.json"
    cache.write_text(
        '{"updated_at": "'
        + (datetime.now() - timedelta(days=2)).isoformat()
        + '"}',
        encoding="utf-8",
    )

    assert external_rules_update_due(cache) is True


def test_fresh_warp_cache_is_not_refreshed(tmp_path):
    cache = tmp_path / "warp.json"
    cache.write_text(
        '{"updated_at": "' + datetime.now().isoformat() + '"}',
        encoding="utf-8",
    )

    assert external_rules_update_due(cache) is False


def test_invalid_warp_cache_is_treated_as_stale(tmp_path):
    cache = tmp_path / "warp.json"
    cache.write_text("{broken", encoding="utf-8")

    assert external_rules_update_due(cache) is True
