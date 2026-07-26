from unittest.mock import MagicMock, patch

from hydra.entrypoints import sync_agent


def test_main_composes_every_sync_dependency():
    application = MagicMock()
    operations = MagicMock()

    with patch.object(
        sync_agent,
        "production_application",
        return_value=application,
    ), patch.object(
        sync_agent,
        "default_sync_operations",
        return_value=operations,
    ) as compose, patch.object(
        sync_agent,
        "run_sync",
        return_value=(True, "ok"),
    ) as run:
        assert sync_agent.main() == 0

    compose.assert_called_once_with(
        protocols=application.protocols,
        plugin_actions=application.plugin_actions,
        plugin_queries=application.plugin_queries,
        apply_config=application.apply,
        check_traffic_limits=application.traffic.check_limits,
    )
    run.assert_called_once_with(operations=operations)
