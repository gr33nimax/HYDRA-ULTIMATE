from unittest.mock import patch

from hydra.core.state import AppState, PluginState
from hydra.plugins.base import PluginCategory, PluginMeta
from hydra.plugins import registry


class RequirementPlugin:
    meta = PluginMeta(
        name="mock",
        description="mock",
        category=PluginCategory.TRANSPORT,
        required_commands=("missing-tool",),
        conflicts_with=("other",),
    )


def test_requirements_reports_missing_commands_and_conflicts():
    state = AppState(protocols={
        "mock": PluginState(enabled=True),
        "other": PluginState(enabled=True),
    })
    other = RequirementPlugin()
    other.meta = PluginMeta(name="other", description="other")
    with patch.object(registry, "_PLUGINS", [RequirementPlugin(), other]), \
         patch.object(registry.HOST, "which", return_value=None):
        result = registry.requirements(state)
    assert result["mock"]["missing_commands"] == ["missing-tool"]
    assert result["mock"]["conflicts"] == ["other"]
