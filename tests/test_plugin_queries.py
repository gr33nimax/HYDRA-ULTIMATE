from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from hydra.services.application import ApplicationService
from hydra.services.plugin_queries import PluginQueryService


class _Plugin:
    meta = SimpleNamespace(
        name="antidpi",
        contract_version=1,
        capabilities=SimpleNamespace(
            queries=("management_snapshot",),
        ),
    )

    def management_snapshot(self):
        return {"events": 7}

    def _private_state(self):
        return {"secret": True}


def test_plugin_query_service_exposes_only_allowlisted_public_queries():
    service = PluginQueryService(
        get_plugin=lambda name: _Plugin() if name == "antidpi" else None,
    )

    assert service.execute(
        "antidpi",
        "management_snapshot",
    ) == {"events": 7}

    with pytest.raises(ValueError, match="unsupported plugin query"):
        service.execute("antidpi", "_private_state")


def test_plugin_query_service_rejects_unknown_plugins():
    service = PluginQueryService(get_plugin=lambda name: None)

    with pytest.raises(ValueError, match="unknown plugin"):
        service.execute("antidpi", "management_snapshot")


def test_application_service_delegates_plugin_queries_to_injected_port():
    queries = Mock()
    queries.execute.return_value = {"events": 4}
    app = ApplicationService(
        users=SimpleNamespace(),
        protocols=SimpleNamespace(),
        apply_config=lambda state: True,
        last_apply_error=lambda: "",
        plugin_statuses=lambda state: {},
        plugin_queries=queries,
    )

    assert app.plugin_query(
        "antidpi",
        "management_snapshot",
    ) == {"events": 4}
    queries.execute.assert_called_once_with(
        "antidpi",
        "management_snapshot",
    )
